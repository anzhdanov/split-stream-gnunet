/*
  This file is part of GNUnet.
  (C) 

  GNUnet is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published
  by the Free Software Foundation; either version 3, or (at your
  option) any later version.

  GNUnet is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
  General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with GNUnet; see the file COPYING.  If not, write to the
  Free Software Foundation, Inc., 59 Temple Place - Suite 330,
  Boston, MA 02111-1307, USA.
*/

/**
 * @file scrb/gnunet-service-scrb.c
 * @brief scrb service implementation
 * @author Xi
 */
#include <gnunet/platform.h>
#include <gnunet/gnunet_util_lib.h>
#include <gnunet/gnunet_protocols.h>
#include "gnunet_protocols_scrb.h"
#include <gnunet/gnunet_core_service.h>
#include <gnunet/gnunet_statistics_service.h>
#include "gnunet/gnunet_common.h"
#include <gnunet/gnunet_mq_lib.h>
#include <gnunet/gnunet_cadet_service.h>
#include <gnunet/gnunet_applications.h>
#include "scrb.h"
#include "gnunet/gnunet_dht_service.h"
#include <gcrypt.h>
#include "scrb_block_lib.h"
#include "scrb_map.h"
#include "scrb_policy.h"

/**
 * A structure to hold a subscribing peer (node).
 * It contains the peer identity, peer identity hash,
 * channel and a flag which shows that the peer has been
 * already acked.
 */
struct NodeHandle
{  
  /**
   * Identity of the peer 
   */
  struct GNUNET_PeerIdentity peer;
  /**
   * Peer hash
   */
  struct GNUNET_HashCode peer_hash;
  /**
   * The channel associated with the peer
   */
  struct Channel* chn;
  /**
   * The flag shows if the peer has been acknowledged
   * already
   */
  int is_acked;
  
  /**
   * A pointer to previous
   */
  struct NodeHandle* prev;
  
  /**
   * A pointer to next
   */
  struct NodeHandle* next;
};

struct ClientList
{
  struct GNUNET_SERVER_Client* client;
  struct ClientList* prev;
  struct ClientList* next;
};

struct Group
{
  /**
   * a list of clients
   */ 
  struct ClientList* cl_head;
  struct ClientList* cl_tail;
	
  /**
   * a list of peers (children)
   */
  struct NodeHandle* nl_head;
  struct NodeHandle* nl_tail;
  
  /**
   * group notification context.
   */
  struct GNUNET_SERVER_NotificationContext* nc;

  struct GNUNET_SCRB_RoutePath path_to_root;

  struct GNUNET_CRYPTO_EddsaPublicKey pub_key;

  struct GNUNET_HashCode pub_key_hash;

  /**
   * channel to the parent node
   */
  struct NodeHandle* parent;

  /**
   * channel to the root node
   */
  struct NodeHandle* root;
  
  /**
   * if we are the root node for the group
   */
  uint8_t is_root;
  /**
   * if we are acked
   */
  uint8_t is_acked;

  uint8_t disconnected;
};

struct GroupList
{
  struct Group* group;
  struct GroupList* prev;
  struct GroupList* next;
};

/**
 * Structure necessary to store data for put join requests
 */
struct PutJoin
{
  enum GNUNET_DHT_RouteOption options;
  void* data;
  struct GNUNET_SCRB_RoutePath path;
};

/**
 * The client entry on the server
 */
struct Client
{
  /**
   * this is a list of groups the client is subscribed to
   * for now, api does not allow to make multiple subsriptions
   * nevertheless, requestes can come sequentially
   */
  struct GroupList* gl_head;
  struct GroupList* gl_tail;
  /**
   * Public key of the client
   */
  struct GNUNET_CRYPTO_EddsaPublicKey pub_key;
  /**
   * Hash of the public key
   */
  struct GNUNET_HashCode pub_key_hash;
  /**
   * Private key of the client
   */
  struct GNUNET_CRYPTO_EddsaPrivateKey priv_key;
};

/**
 * Context for a cadet channel
 */
struct Channel
{
  /**
   * Group the channel belongs to
   */
  struct Group* grp;
	
  struct GNUNET_CRYPTO_EddsaPublicKey group_key;

  struct GNUNET_HashCode group_key_hash; 

  /**
   * CADET channel
   */ 
  struct GNUNET_CADET_Channel* channel;

  /**
   * CADET transmission handle
   */
  struct GNUNET_CADET_TransmitHandle *tmit_handle;
	
  /**
   * Remote peer identity
   */
  struct GNUNET_PeerIdentity peer;
	
  /**
   * Channel direction
   * @see enum ChannelDirection
   */
  uint8_t direction;
};

/**
 * Operation result of the forwarding function
 */
enum FOpResult
{
  FOPR_CHECK_FAIL,
  FOPR_SUBSCRIBE_ACK,
  FOPR_SUBSCRIBE_FAIL,
  FOPR_WAIT_ACK,
  FOPR_ANYCAST,
  FOPR_ANYCAST_FAIL,
  FOPR_ERR
};

/**
 * A CADET handle
 */
static struct GNUNET_CADET_Handle *cadet;

/**
 * Scribe policy
 */
static struct GNUNET_SCRB_Policy *policy;

/**
 * Scribe map view
 */
static struct GNUNET_SCRB_RouteMap *route_map;

/**
 * Our configuration.
 */
static const struct GNUNET_CONFIGURATION_Handle *cfg;

/**
 * Handle to CORE.
 */
static struct GNUNET_CORE_Handle *core_api;

/**
 * Identity of this peer.
 */
static struct GNUNET_PeerIdentity my_identity;

/**
 * Hash of the identity of this peer.
 */
static struct GNUNET_HashCode my_identity_hash;

/**
 * Handle for the statistics service.
 */
struct GNUNET_STATISTICS_Handle *scrb_stats;

/**
 * Handle to our server.
 */
static struct GNUNET_SERVER_Handle *server;

/**
 * Handle to DHT
 */
static struct GNUNET_DHT_Handle *dht_handle;

/**
 * Handle to DHT PUT
 */
static struct GNUNET_DHT_PutHandle *put_dht_handle;

/**
 * Handle to DHT monitor
 */
static struct GNUNET_DHT_MonitorHandle *monitor_handle;

/**
 * Group map
 */
static struct GNUNET_CONTAINER_MultiHashMap *groups;


/**
 * Checks if the @a path contains @a node
 * @param path        Path of DHT message
 * @param path_length The length of the path
 * @param node        Identity of the peer to be checked
 * @return 0 in case the node is not on the path, 1 otherwise
 */
int
check_path_contains(const struct GNUNET_PeerIdentity *path,
                    unsigned int path_length,
                    const struct GNUNET_PeerIdentity *node)
{
  int i;
  for(i = 0; i < path_length; i++)
	if(0 == memcmp(&path[i], node, sizeof(struct GNUNET_HashCode)))
	  return 1;
  return 0;
}

/**
 * Add child to group
 * @param grp        Group the child to be added
 * @param node       The child to be added
 * @return 1 on success, 0 otherwise
 */
static int
group_children_add(struct Group *grp, struct NodeHandle *node)
{
  GNUNET_CONTAINER_DLL_insert (grp->nl_head, grp->nl_tail, node);
  return 1;
}


/**
 * Clear the group children and free
 * @param grp    The group
 */
static void
group_children_clear(struct Group *grp)
{
  struct NodeHandle *nl;
  while(NULL != (nl = grp->nl_head))
  {
	GNUNET_CONTAINER_DLL_remove (grp->nl_head,
								 grp->nl_tail,
								 nl);
	GNUNET_free(nl->chn);
	GNUNET_free(nl);
  }
}


/**
 * Clear the group children and free
 * @param grp    The group
 */
static void
group_clients_clear(struct Group *grp)
{
  struct ClientList *cl;
  while(NULL != (cl = grp->cl_head))
  {
	GNUNET_CONTAINER_DLL_remove (grp->cl_head,
								 grp->cl_tail,
								 cl);
	GNUNET_free (cl);
  }
}


/**
 * Check if the group contains the child
 * @param grp     The group to be checked
 * @param child   The peer identity of the child
 * @return 1 on success, 0 otherwise
 */
static int
group_children_contain(struct Group *grp, const struct GNUNET_PeerIdentity *child)
{
  struct NodeHandle *nl = grp->nl_head;
  while(NULL != nl)
  {
	if(0 == memcmp(&nl->peer, child, sizeof(*child)))
	  return 1;
	nl = nl->next;
  }
  return 0;
}

/**
 * Get node by its peer identity
 * @param grp           The group
 * @param child         Peer identity of the child
 * @return NodeHandle, NULL if none
 */
static
struct NodeHandle*
group_children_get(struct Group *grp, struct GNUNET_PeerIdentity *child)
{
  struct NodeHandle *node = grp->nl_head;
  while(NULL != node)
  {
	if(0 == memcmp(&node->peer, child, sizeof(*child)))
	{
	  break;
	}
	node = node->next;
  }
  return node;
}

/**
 * Remove a child by its peer identity
 * @param grp           The group
 * @param child         Peer identity of the child
 * @return NodeHandle, NULL if none
 */
static
struct NodeHandle*
group_children_remove(struct Group *grp, struct GNUNET_PeerIdentity *child)
{
  struct NodeHandle *nl = grp->nl_head;
  struct NodeHandle *node = NULL;
  while(NULL != nl)
  {
	if(0 == memcmp(&nl->peer, child, sizeof(*child)))
	{
	  GNUNET_CONTAINER_DLL_remove (grp->nl_head, grp->nl_tail, nl);
	  node = nl;
	  break;
	}
	nl = nl->next;
  }
  return node;
}

/**
 * Size of the group children
 * @param nl           Pointer to the children list
 * @return size of the children
 */
static int 
group_children_size(struct NodeHandle *nl)
{
  if(NULL == nl)
	return 0;
  else
	return 1 + group_children_size(nl->next);
}

/**
 * Check if the children list is empty
 * @param grp The group to be checked
 * @return 1 if the children list is empty
 * 0 otherwise
 */
static int 
group_children_is_empty(struct Group *grp)
{
  return grp->nl_head == NULL;
}

/**
 * Add the group @a grp children to anycast message @a msg.
 */
static void
group_children_add_to_anycast(struct Group *grp,
                              struct GNUNET_SCRB_AnycastMessage *msg)
{
  size_t size = 0;
  struct NodeHandle *node = grp->nl_head;
  while(NULL != node)
  {
	if(1 == node->is_acked)
	  size++;
	node = node->next;
  }
  struct GNUNET_PeerIdentity **children = GNUNET_malloc(size * sizeof(struct GNUNET_PeerIdentity*));
  node = grp->nl_head;
  //gathering group children
  while(NULL != node)
  {
	if(1 == node->is_acked)
	  *children++ = &node->peer;
	node = node->next;
  }
  if(NULL != policy->direct_anycst_cb)
	policy->direct_anycst_cb(policy, msg, &grp->parent->peer, children, size, NULL);
}

/**
 * Send message to all clients connected to the group
 */
static
void group_client_send_message(const struct Group *grp,
                               const struct GNUNET_MessageHeader *msg)
{
  GNUNET_log(GNUNET_ERROR_TYPE_WARNING,
			 "%p Sending message to clients. \n", grp);
  struct ClientList *cl = grp->cl_head;
  while(NULL != cl)
  {
	GNUNET_SERVER_notification_context_add(grp->nc, cl->client);
	GNUNET_SERVER_notification_context_unicast(grp->nc, cl->client, msg, GNUNET_NO);
	cl = cl->next;
  }
}

/**
 * Creates a CADET channel for the provided @a peer.
 *
 * @param grp        The group channel belongs to
 * @param peer       Peer
 * @return           struct Channel
 */
static struct Channel*
cadet_channel_create(struct Group *grp, struct GNUNET_PeerIdentity *peer)
{
  struct Channel *chn = GNUNET_malloc (sizeof(*chn));
  chn->grp = grp;
  chn->group_key = grp->pub_key;
  chn->group_key_hash = grp->pub_key_hash;
  chn->peer = *peer;
  chn->channel = GNUNET_CADET_channel_create( cadet, chn, &chn->peer,
											  GNUNET_APPLICATION_TYPE_MULTICAST,
											  GNUNET_CADET_OPTION_RELIABLE);
  return chn;
}

/**
 * CADET is ready to transmit a message
 */
size_t
cadet_notify_transmit_ready(void* cls, size_t buf_size, void* buf)
{
  if(0 == buf_size)
  {
	return 0;
  }
  const struct GNUNET_MessageHeader* msg = cls;
  uint16_t msg_size = ntohs(msg->size);
  GNUNET_assert (msg_size <= buf_size);
  memcpy(buf, msg, msg_size);
  return msg_size;
}

/**
 * Send a message to CADET channel
 * @param chn Channel
 * @param msg Message
 */
static void
cadet_send_msg(struct Channel* chn, const struct GNUNET_MessageHeader *msg)
{
  chn->tmit_handle
	= GNUNET_CADET_notify_transmit_ready (chn->channel, GNUNET_NO,
										  GNUNET_TIME_UNIT_FOREVER_REL,
										  ntohs(msg->size),
										  &cadet_notify_transmit_ready,
										  (void*) msg);
}

/**
 * Creates a node handle
 */
static
struct NodeHandle*
create_node_handle(struct Group *grp,
                   const struct GNUNET_PeerIdentity *peer)
{
  struct GNUNET_HashCode *p_hash = GNUNET_malloc(sizeof(*p_hash));
  GNUNET_CRYPTO_hash (peer, sizeof(*peer), p_hash);
	
  //create a handle for the node
  struct NodeHandle *node = GNUNET_new (struct NodeHandle);
  node->peer = *peer;
  node->peer_hash = *p_hash;
  node->chn = cadet_channel_create(grp, &node->peer);
  return node;
}

/**
 * A helper method for adding @a child to a group with
 * @a grp_key.
 * @param grp_key
 * @param grp_key_hash
 * @param child
 * @return 1 if we need to subscribe to the group, implicitly
 * subscribing
 */
static struct Group*
group_child_add_helper(const struct GNUNET_SCRB_Policy *policy, 
                       const struct GNUNET_CRYPTO_EddsaPublicKey *grp_pub_key, 
                       const struct GNUNET_HashCode *grp_pub_key_hash,
                       const struct GNUNET_PeerIdentity *peer)
{
  struct Group *ret = NULL;
  struct GNUNET_HashCode ph;
  GNUNET_CRYPTO_hash(peer, sizeof(*peer), &ph);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
			  "add child %s to group %s.\n",
			  GNUNET_h2s (grp_pub_key_hash),
			  GNUNET_h2s (&ph));
  struct Group*
	grp = GNUNET_CONTAINER_multihashmap_get (groups, grp_pub_key_hash);
	
  if(NULL == grp)
  {
	grp = GNUNET_new(struct Group);
	grp->pub_key = *grp_pub_key;
	grp->pub_key_hash = *grp_pub_key_hash;
	grp->is_acked = 0;
	GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
				"implicitly subscribing to group %s.\n",
				GNUNET_h2s (grp_pub_key_hash));
  }
	
  ret = grp;

  struct NodeHandle *child = create_node_handle(grp, peer);	

  group_children_add(grp, child);
	
  if(NULL != policy->child_added_cb)
	policy->child_added_cb(policy, grp_pub_key, &child->peer, NULL);
	
  return ret;
}

/**
 * Sending a message to all children using cadet
 */
static void
group_children_send_message(const struct Group *grp,
							const struct GNUNET_MessageHeader *msg)
{
  GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
			  "%p Sending message to children. \n", grp);
	
  struct NodeHandle *nl = grp->nl_head;
  while(NULL != nl)
  {
	cadet_send_msg(nl->chn, msg);
	nl = nl->next;
  }
}

/**
 * Extracts the next on the path for the downstream message
 */
static
struct NodeHandle*
dstrm_msg_get_next(struct GNUNET_SCRB_DownStreamMessage *msg)
{
  struct GNUNET_CRYPTO_EddsaPublicKey *group_key;
  struct GNUNET_HashCode *group_key_hash = NULL;
  group_key = &msg->grp_key;
  GNUNET_CRYPTO_hash(group_key, sizeof(*group_key), group_key_hash);
  
  struct Group* 
	grp = GNUNET_CONTAINER_multihashmap_get (groups, group_key_hash);
  if(NULL == grp)
	return NULL;
  struct GNUNET_PeerIdentity *path = NULL;
  unsigned int path_length = 0;
  if(NULL != route_map->map_get_path_cb)
	route_map->map_get_path_cb(route_map,
							   &grp->pub_key_hash,
							   &msg->dst, &msg->src, path, &path_length, NULL);
  if(NULL == path)
	return NULL;
  struct GNUNET_PeerIdentity *end = &path[path_length - 1];
  if(0 != memcmp(&msg->src, end, sizeof(*end)))
	return NULL;
  struct GNUNET_PeerIdentity *start = &path[0];
  if(0 != memcpy(&msg->dst, start, sizeof(*start)))
	return NULL;
  struct GNUNET_PeerIdentity *next = &path[path_length - 2];
  struct NodeHandle* child = NULL;
  if(NULL == (child = group_children_get(grp, next)))
  {
	//create a handle for the next peer
	child = create_node_handle(grp, next);	
  }
  return child;
}


/**
 * Creates a put join from the provided data
 */
static
struct PutJoin*
create_put_join(enum GNUNET_DHT_RouteOption options,
                const void *data,
                const struct GNUNET_PeerIdentity *path,
                unsigned int path_length)
{
  struct PutJoin *pj = GNUNET_malloc(sizeof(*pj));
  pj->options = options;
  pj->data = GNUNET_malloc(sizeof(*data));
  memcpy(&pj->data, data, sizeof(*data));
  pj->path.path = GNUNET_malloc(path_length * sizeof(*path));
  memcpy(pj->path.path, path, path_length * sizeof(*path));
  pj->path.path_length = path_length;
  return pj;
}

/**
 * Sends a subscribe child added message to all the clients subscribed to the group
 *
 * @param grp         The group which clients need to be updated
 * @param peer        Identity of the child
 */
static void
client_send_child_change_event (const struct Group *grp,
                                const struct GNUNET_PeerIdentity *peer,
                                uint16_t type)
{	
  struct GNUNET_SCRB_ChildChangeEventMessage*
	msg = GNUNET_malloc (sizeof(*msg));

  msg->header.header.type = htons(type);
  msg->header.header.size = htons(sizeof(*msg));
  msg->grp_key = grp->pub_key;
  msg->child = *peer;
  group_client_send_message(grp, &msg->header.header);
}

/**
 * Sends a downstream message to the recipient
 *
 * @param node        Node
 * @param src         Source of the subscribe message
 * @param path        Path to the peer where the message is processed
 * @param path_length Length of the path
 */
static void
cadet_send_downstream_msg (const struct GNUNET_CRYPTO_EddsaPublicKey *grp_key,
						   struct GNUNET_SCRB_MessageHeader *m,
						   enum GNUNET_SCRB_ContentType ct, 
						   const struct GNUNET_PeerIdentity *src,
						   const struct GNUNET_PeerIdentity *dst)
{
  //FIXME: put the information into the scribe header
  struct GNUNET_SCRB_DownStreamMessage*
	msg = GNUNET_malloc (sizeof(*msg));
  struct GNUNET_HashCode gkh;
  GNUNET_CRYPTO_hash(&msg->grp_key, sizeof(msg->grp_key), &gkh);
  struct Group*
	grp = GNUNET_CONTAINER_multihashmap_get (groups, &gkh);
  if(NULL == grp)
  {
	GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
				"There is no group %s.\n",
				GNUNET_h2s (&gkh));
	return;
  }

  msg->header.header.type = htons(GNUNET_MESSAGE_TYPE_SCRB_DWNSTRM_MSG);
  msg->header.header.size = htons(sizeof(*msg));
  //encapsulate a message
  memcpy(msg->content.app_data, m, sizeof(*m));
  msg->content.data_size = sizeof(*m);
  msg->content.type = ct;
  msg->grp_key = *grp_key;
  msg->src = *src;
  msg->dst = *dst;
  GNUNET_CRYPTO_hash_create_random(GNUNET_CRYPTO_QUALITY_WEAK, &msg->id);
  struct NodeHandle* next = dstrm_msg_get_next(msg);
  if(next != NULL)
  {	
	cadet_send_msg(next->chn, &msg->header.header);
  }else
  {
	//we do not see the path, send to parent
	struct GNUNET_HashCode sh;
	struct GNUNET_HashCode dh;
	GNUNET_CRYPTO_hash(src, sizeof(*src), &sh);
	GNUNET_CRYPTO_hash(dst, sizeof(*dst), &dh);
	GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
				  "The local node do not see the path %s to %s for group %s.\n",
				GNUNET_h2s (&sh),
				GNUNET_h2s (&dh),
				GNUNET_h2s (&grp->pub_key_hash));
	GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
				"Sending the message %p to parent %s.\n",
				msg,
				GNUNET_h2s (&grp->parent->peer_hash));
	cadet_send_msg(grp->parent->chn, &msg->header.header);
  }
}

/**
 * Sends a subscribe ack message to the provided @a dst
 * for the given @a grp
 *
 * @param grp          Group the message is sent
 * @param src          Source of the subscribe message
 * @param dst          Destination of the message
 * @param path_to_root Path to the group root node
 * @param ptr_lenght   Length of the path to root
 */
static void
cadet_send_subscribe_ack (struct Group* grp,
                          const struct GNUNET_PeerIdentity* src,
                          const struct GNUNET_PeerIdentity* dst,
                          const struct GNUNET_PeerIdentity* path_to_root,
                          const unsigned int ptr_length)
{	
  struct GNUNET_SCRB_SubscribeAckMessage*
	msg = GNUNET_malloc (sizeof(*msg));
  msg->header.header.type = htons(GNUNET_MESSAGE_TYPE_SCRB_SUBSCRIBE_ACK);
  msg->header.header.size = htons(sizeof(*msg));
  msg->requestor = *dst;
  msg->path_to_root.path = GNUNET_malloc (ptr_length * sizeof(struct GNUNET_PeerIdentity));
  memcpy(msg->path_to_root.path, path_to_root, ptr_length * sizeof(*path_to_root));
  msg->path_to_root.path_length = ptr_length;
  msg->grp_key = grp->pub_key;
  msg->grp_key_hash = grp->pub_key_hash;
  cadet_send_downstream_msg(&grp->pub_key, &msg->header, MSG, src, dst);
}

/**
 * Sends an anycast failure message to the provided @a dst
 *
 * @param src         Source of the subscribe message
 * @param dst         Destination of the message
 */
static void
cadet_send_anycast_fail(struct Group* grp,
						const struct GNUNET_SCRB_Content* content,
						const struct GNUNET_PeerIdentity* src,
						const struct GNUNET_PeerIdentity* dst)
{	
  struct GNUNET_SCRB_AnycastFailMessage*
	msg = GNUNET_malloc (sizeof(*msg));
  msg->header.header.type = htons(GNUNET_MESSAGE_TYPE_SCRB_ANYCAST_FAIL);
  msg->header.header.size = htons(sizeof(*msg));
  msg->src = *dst;
  msg->group_key = grp->pub_key;
  msg->content = *content;
  cadet_send_downstream_msg (&grp->pub_key, &msg->header, MSG, src, dst);
}

/**
 * Sends a subscribe fail message for the given node
 * @param node        The next node on the path
 * @param src         Source of the subscribe message
 * @param dst         Destination of the message
 */
static void
cadet_send_subscribe_fail (const struct Group* grp, 
						   const struct GNUNET_PeerIdentity* src,
						   const struct GNUNET_PeerIdentity* dst)
{	
  struct GNUNET_SCRB_SubscribeFailMessage*
	msg = GNUNET_malloc (sizeof(*msg));
  msg->header.header.type = htons(GNUNET_MESSAGE_TYPE_SCRB_SUBSCRIBE_FAIL);
  msg->header.header.size = htons(sizeof(*msg));
  msg->requestor = *dst;
  msg->grp_key = grp->pub_key;
  msg->grp_key_hash = grp->pub_key_hash;
  cadet_send_downstream_msg (&grp->pub_key, &msg->header, MSG, src, dst);
}

/**
 * Sends an anycast message to the provided @a dst
 *
 * @param grp_key     Public key of the group
 * @param m           Message encapsulated inside anycast
 * @param src         Source of the subscribe message
 * @param dst         Destination of the message
 */
static void
cadet_send_direct_anycast(const struct GNUNET_CRYPTO_EddsaPublicKey* grp_key,
						  struct GNUNET_SCRB_MessageHeader* m,
						  const struct GNUNET_PeerIdentity* src,
						  const struct GNUNET_PeerIdentity* dst)
{
  struct GNUNET_SCRB_AnycastMessage*
	msg = (struct GNUNET_SCRB_AnycastMessage*)m;
  msg->header.header.type = htons(GNUNET_MESSAGE_TYPE_SCRB_ANYCAST);
  msg->header.header.size = htons(sizeof(*msg));
  cadet_send_downstream_msg (grp_key, &msg->header, ANYCAST_MSG, src, dst);
}

/**
 * Sends a subscribe parent message to the given peer
 * @param grp      Group the node is taken into
 * @param peer     Peer
 */
static void
cadet_send_parent (struct Group* grp,
				   const struct GNUNET_PeerIdentity* peer)
{	
  struct GNUNET_SCRB_SubscribeParentMessage*
	msg = GNUNET_malloc (sizeof(*msg));
  msg->header.header.type = htons(GNUNET_MESSAGE_TYPE_SCRB_SUBSCRIBE_SEND_PARENT);
  msg->header.header.size = htons(sizeof(*msg));
  msg->parent = *peer;
  msg->grp_key = grp->pub_key;
  msg->grp_key_hash = grp->pub_key_hash;
     //create a handle for the node
  struct NodeHandle* node = create_node_handle(grp, peer);	
  cadet_send_msg(node->chn, &msg->header.header);
}

/**
 * Sends a subscribe ack message to all the clients subscribed to the group
 *
 * @param grp         The group which clients need to be updated
 */
static void
client_send_subscribe_ack (struct Group* grp)
{	
  struct GNUNET_SCRB_SubscribeFailMessage*
	msg = GNUNET_malloc (sizeof(*msg));

  msg->header.header.type = htons(GNUNET_MESSAGE_TYPE_SCRB_SUBSCRIBE_ACK);
  msg->header.header.size = htons(sizeof(*msg));
  msg->grp_key = grp->pub_key;
  group_client_send_message(grp, &msg->header.header);
}

/**
 * Sends a subscribe fail message to all the clients subscribed to the group
 *
 * @param grp         The group which clients need to be updated
 */
static void
client_send_subscribe_fail (struct Group* grp)
{	
  struct GNUNET_SCRB_SubscribeFailMessage*
	msg = GNUNET_malloc (sizeof(*msg));

  msg->header.header.type = htons(GNUNET_MESSAGE_TYPE_SCRB_SUBSCRIBE_FAIL);
  msg->header.header.size = htons(sizeof(*msg));
  msg->grp_key = grp->pub_key;
  group_client_send_message(grp, &msg->header.header);
}

/**
 * Sends an anycast message to all the clients subscribed to the group
 *
 * @param grp         The group which clients need to be updated
 */
static void
client_send_anycast (struct Group* grp,
					 struct GNUNET_SCRB_Content* content)
{	
  struct GNUNET_SCRB_ClientAnycastMessage
	*cam = GNUNET_malloc(sizeof(*cam));
  cam->header.header.type = htons(GNUNET_MESSAGE_TYPE_SCRB_ANYCAST);
  cam->header.header.size = htons(sizeof(*cam));
  cam->group_key = grp->pub_key;
  cam->content = *content;
  group_client_send_message(grp, &cam->header.header);
}

/**
 * Free resources occupied by the @a node.
 *
 * @param group to free
 */
static void
free_channel(struct Channel *channel)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
			  "Cleaning up channel. \n");
  GNUNET_CADET_channel_destroy(channel->channel);
  GNUNET_free (channel);
}

/**
 * Free resources occupied by the @a node.
 *
 * @param group to free
 */
static void
free_node(struct NodeHandle *node)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
			  "Cleaning up node handle. \n");
  free_channel(node->chn);
}

/**
 * Free resources occupied by the @a group.
 *
 * @param group to free
 */
static void
free_group(struct Group *grp)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
			  "Cleaning up group entry. \n");
  GNUNET_SERVER_notification_context_destroy (grp->nc);
  grp->nc = NULL;
  struct NodeHandle* nl;
  while(NULL != (nl = grp->nl_head))
  {
	GNUNET_CONTAINER_DLL_remove (grp->nl_head,
								 grp->nl_tail,
								 nl);
	GNUNET_free(nl);
  }
  struct ClientList* cl;
  while(NULL != (cl = grp->cl_head))
  {
	GNUNET_CONTAINER_DLL_remove (grp->cl_head,
								 grp->cl_tail,
								 cl);
	GNUNET_free(cl);
  }
  free_node(grp->parent);
  free_node(grp->root); //FIXME: add root identity handling
  GNUNET_free (grp);
}

/**
 * The function is invoked on applications when the underlying
 * peer receives an incoming dht put. Applications can admit
 * a requestor to the group or send fail or ack replies to the
 * subscriber. Applications cannot stop the message propagation
 * nor change the message content.
 *
 *
 * f.1 group is created
 *   f.1.1 check if the source node is already on the path
 *   f.1.2 check if we already have the child
 *     f.1.2.1 update global view
 *   f.1.3 check if any of the children are on the path
 *   f.1.4 if policy accepts
 *     f.1.4.1 add child
 *     f.1.4.2 update global view
 *     f.1.4.3 if group is ack
 *       f.1.4.3.1 send ack to node
 *       f.1.4.3.2 update clients
 *   f.1.5 policy does not accept
 *     f.1.5.1 if group is ack
 *       f.1.5.2 send anycast to children
 * f.2 group is not created 
 *   f.2.1 create group
 *   f.2.2 if policy accepts node
 *     f.2.2.1 add child
 *     f.2.2.2 send parent
 *     f.2.2.3 update global view
 *   f.2.3 policy does not accept
 *     f.2.3.1 send fail
 */
uint8_t
forward(enum GNUNET_DHT_RouteOption options,
		const void *data,
		const struct GNUNET_PeerIdentity *path,
		unsigned int path_length,
		struct GNUNET_CONTAINER_MultiHashMap *groups) 
{
  struct GNUNET_BLOCK_SCRB_Join *
	join_block = (struct GNUNET_BLOCK_SCRB_Join *) data;
  //FIXME: do all the necessary security checks

  //check if this is our subscribe message then ignore it
  if(0 == memcmp(&join_block->src, &my_identity, sizeof(struct GNUNET_HashCode)))
  {
	GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
				"Bypassing forward logic of subscribe message for group %s because local node is the subscriber's source.\n",
				GNUNET_h2s (&join_block->gr_pub_key_hash));
	return FOPR_CHECK_FAIL;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
			  "Handle forward subscribe message for group %s.\n",
			  GNUNET_h2s (&join_block->gr_pub_key_hash));
	
  //take the last peer on the path
  const struct GNUNET_PeerIdentity *lp = &path[path_length - 1];
  struct GNUNET_HashCode lp_hash;
  GNUNET_CRYPTO_hash(lp, sizeof(*lp), &lp_hash);

  //source
  const struct GNUNET_PeerIdentity *source = &join_block->src;
	
  const struct GNUNET_CRYPTO_EddsaPublicKey *grp_pub_key = &join_block->gr_pub_key;
  const struct GNUNET_HashCode *grp_pub_key_hash = &join_block->gr_pub_key_hash;
	
  struct Group *
	grp =GNUNET_CONTAINER_multihashmap_get (groups, grp_pub_key_hash);
	
  if(NULL != grp)//f.1
  {
	//f.1.1. check if the source node is already on the path
	struct GNUNET_SCRB_RoutePath *path_to_root = &grp->path_to_root;
	if(1 == check_path_contains(path_to_root->path, path_to_root->path_length, lp))
	{
	  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
				  "Rejecting subsribe message for group %s, the node %s is already on the path.\n",
				  GNUNET_h2s (&grp->pub_key_hash),
				  GNUNET_h2s (&lp_hash));
	  return FOPR_CHECK_FAIL;
	}
		
	//f.1.2. Check if we already have the child
	if(1 == group_children_contain(grp, lp))
	{
	  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
				  "The node %s is already in group %s.\n",
				  GNUNET_h2s (&lp_hash),
				  GNUNET_h2s (&grp->pub_key_hash));
	  //f.1.2.1 update map
	  if(NULL != route_map->map_put_path_cb)
		route_map->map_put_path_cb(route_map, &grp->pub_key_hash, path, path_length, NULL);
	  return FOPR_CHECK_FAIL;
	}
	//f.1.3 check if any of the children are on the path
	struct NodeHandle *nl = grp->nl_head;
	while(NULL != nl)
	{
	  if(1 == check_path_contains(path, path_length, &nl->peer))
	  {
		GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
					"Rejecting subsribe message for group %s, the child %s is already on the path.\n",
					GNUNET_h2s (&grp->pub_key_hash),
					GNUNET_h2s (&nl->peer_hash));
		return FOPR_CHECK_FAIL;
	  }
	  nl = nl->next;
	}
	//f.1.4  check if our policy allows to take on the node
	if(NULL != policy->allow_subs_cb &&
	   1 == policy->allow_subs_cb(policy, lp, grp_pub_key, groups, &join_block->content, NULL))
	{
	  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
				  "Hijacking subscribe message from %s to group %s.\n",
				  GNUNET_h2s (&lp_hash),
				  GNUNET_h2s (&grp->pub_key_hash));
	  //f.1.4.1
	  //here, provide the last on the path to build the group
	  group_child_add_helper(policy, grp_pub_key, grp_pub_key_hash, lp);
	  //f.1.4.2 update global view
	  if(NULL != route_map->map_put_path_cb)
		route_map->map_put_path_cb(route_map, &grp->pub_key_hash, path, path_length, NULL);
	  // f.1.4.3 if group is ack
	  if(grp->is_acked)
	  {
		//f.1.4.3.1 send ack to node
		cadet_send_subscribe_ack(grp, &my_identity,
								 &join_block->src,
								 path_to_root->path,
								 path_to_root->path_length);
		//f.1.4.3.2 send child add to clients
		client_send_child_change_event (grp, lp, 1);

		return FOPR_SUBSCRIBE_ACK;
	  }
	  
	  return FOPR_WAIT_ACK;

	}else if(1 == grp->is_acked)//f.1.5.(1) policy does not accept (group is acked)
	{
	  //f.1.5.2 send anycast to children
	  struct GNUNET_SCRB_AnycastMessage *msg = GNUNET_malloc(sizeof(*msg));
	  memcpy(&msg->group_key, &grp->pub_key, sizeof(grp->pub_key));
	  msg->pth_to_rq.path = GNUNET_malloc(path_length * sizeof(struct GNUNET_PeerIdentity));
	  memcpy(msg->pth_to_rq.path, path, path_length * sizeof(*path));
	  msg->pth_to_rq.path_length = path_length;
	  //send only to those that have been acked already
	  group_children_add_to_anycast(grp, msg);
	  struct GNUNET_PeerIdentity *next = NULL;
	  if(NULL != policy->get_next_anycst_cb)
		next = policy->get_next_anycst_cb(policy, msg, NULL);
	  if(NULL == next)
	  {
		GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
					"Anycast fail to group %s.\n",
					GNUNET_h2s (&grp->pub_key_hash));
		//send back subscribe fail
		GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
					"Sending subsribe fail message to %s for group %s.\n",
					GNUNET_h2s (&lp_hash),
					GNUNET_h2s (&grp->pub_key_hash));

		cadet_send_subscribe_fail (grp, &my_identity,
								   source);
		return FOPR_SUBSCRIBE_FAIL;

	  }else
	  {
		GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
					"handle forward subscribe: routing message to peer %s for group %s.\n",
					GNUNET_h2s (&lp_hash),
					GNUNET_h2s (&grp->pub_key_hash));
	
		memcpy(&msg->ssrc, &join_block->src, sizeof(struct GNUNET_PeerIdentity));
		memcpy(&msg->iasrc, &my_identity, sizeof(struct GNUNET_PeerIdentity));
		memcpy(&msg->asrc, &my_identity, sizeof(struct GNUNET_PeerIdentity));
		//we create a new PutJoin to send with anycast messages
		struct PutJoin *put = create_put_join(options, data, path, path_length);
		msg->content.app_data = GNUNET_malloc(sizeof(*put));
		memcpy(msg->content.app_data, put, sizeof(*put));
		msg->content.data_size = sizeof(*put);
		msg->content.type = DHT_PUT;
		cadet_send_direct_anycast(&grp->pub_key, &msg->header, &my_identity, next);
		return FOPR_ANYCAST;
	  }
	}
  }else
  { //f.2 group is not created
	
	//f.2.1 if policy accepts the node
	if(NULL != policy->allow_subs_cb && 1 == policy->allow_subs_cb(policy, lp, grp_pub_key, groups, &join_block->content, NULL))
	{
	  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
				  "Hijacking subscribe message from %s to group %s.\n",
				  GNUNET_h2s (&lp_hash),
				  GNUNET_h2s (&grp->pub_key_hash));
	  //f.2.2.1 add child
	  //here, provide the last on the path to build the group
	  if(NULL != (grp = group_child_add_helper(policy, grp_pub_key, grp_pub_key_hash, lp)))
	  {
		//the group was implicitly created
		//f.2.2.2 send parent
		cadet_send_parent (grp, lp);
		//f.2.2.3 update global view
		if(NULL != route_map->map_put_path_cb)
		  route_map->map_put_path_cb(route_map, &grp->pub_key_hash, path, path_length, NULL);		
		
		return FOPR_WAIT_ACK;
	  }
		
	}else //f.2.3 policy does not accept
	{
	  //f.2.3.1 send fail
	  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
				  "Anycast fail to group %s.\n",
				  GNUNET_h2s (&grp->pub_key_hash));
		
	  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
				  "Sending subsribe fail message to %s for group %s.\n",
				  GNUNET_h2s (&lp_hash),
				  GNUNET_h2s (&grp->pub_key_hash));

	  cadet_send_subscribe_fail (grp, &my_identity,
								 source);
	  return FOPR_SUBSCRIBE_FAIL;
	}
  }
}

/**
 * The function is called on the application at the destination peer
 * for an icoming dht put.
 *
 * d.1 call forward on the node
 * d.2 if result of forwarding wait ack
 *   d.2.1 set group acked
 *   d.2.2 set root
 *   d.2.3 set path root
 *   d.2.4 if message is ours
 *     d.2.4.1 update clients
 *   d.2.5 else
 *     d.2.5.1 send subscribe ack
 *
 * @a options          routing options for DHT
 * @a data             data which comes together with put
 * @a path             path
 * @a path_length      path length
 * @a groups           a hash map with groups
 * 
 */
void
deliver(enum GNUNET_DHT_RouteOption options,
		const void *data,
		const struct GNUNET_PeerIdentity *path,
		unsigned int path_length,
		struct GNUNET_CONTAINER_MultiHashMap *groups) 
{
  //d.1 call forward on the message content
  enum FOpResult fres = forward(options, data, path, path_length, groups);
  struct GNUNET_BLOCK_SCRB_Join *
	join_block = (struct GNUNET_BLOCK_SCRB_Join *) data;
  struct GNUNET_HashCode srch;
  GNUNET_CRYPTO_hash(&join_block->src, sizeof(join_block->src), &srch);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
			  "Deliver is called subsribing peer %s for group %s.\n",GNUNET_h2s (&srch),
			  GNUNET_h2s (&join_block->gr_pub_key_hash));
  struct Group*
	grp = GNUNET_CONTAINER_multihashmap_get (groups, &join_block->gr_pub_key_hash);
  
  if(NULL != grp)
  {
	// d.2
	if(FOPR_WAIT_ACK == fres)
	{
	  grp->is_acked = 1;
	  grp->is_root = 1;
	  grp->path_to_root.path = GNUNET_malloc(path_length * sizeof(*path));
	  memcpy(grp->path_to_root.path, path, path_length * sizeof(*path));
	  grp->path_to_root.path_length = path_length;
		  
	  //d.2.4 message is ours
	  if(0 == memcmp(&join_block->src, &my_identity, sizeof(my_identity)))
		client_send_subscribe_ack(grp);//d.2.4.1 update clients
	  else//d.2.5
		cadet_send_subscribe_ack (grp, //d.2.5.1
								  &my_identity,
								  &join_block->src,
								  path, path_length);
	}
  }
}
 
/**
 * Incoming subscribe fail message
 *
 * s.f.1 group is not created
 *   s.f.1.1 return err ?
 * s.f.2 group is created
 *   s.f.2.1 if we get fail for our request
 *     s.f.2.1.1 send subscribe fail to clients
 *   s.f.2.2 if group is empty
 *     s.f.2.2.1 destroy group
 */ 
static int
recv_subscribe_fail_handler(void *cls, 
							const struct GNUNET_MessageHeader *m)
{
  uint16_t size = ntohs(m->size);
  if(size < sizeof(*m))
  {
	GNUNET_break_op(0);
	return GNUNET_SYSERR;
  }
  const struct GNUNET_SCRB_SubscribeFailMessage*
	msg = (struct GNUNET_SCRB_SubscribeFailMessage*)m;
	
  struct Group*
	grp = GNUNET_CONTAINER_multihashmap_get(groups, &msg->grp_key_hash);

  if(NULL != grp)
  {  
	//s.f.2 group is created
	//s.f.2.1 check if we are the source
	if(0 == memcmp(&my_identity, &msg->requestor, sizeof(struct GNUNET_PeerIdentity)))
	{
	  //s.f.2.1.1 we are the source, send subscribe fail message to clients
	  client_send_subscribe_fail (grp);		
	}

	//s.f.2.3. if the group is empty, remove it and do the cleanup
	if(1 == group_children_is_empty(grp))
	{
	  //FIXME: do it in a separate function
	  //cleanup the group
	  GNUNET_CONTAINER_multihashmap_remove (groups, &grp->pub_key_hash, grp);
	  free_group(grp);
	}
  }
}


/**
 * Incoming subscribe ack message
 * s.a.1 if group is not created
 *   s.a.1.1 return err
 * s.a.2 if group is created
 *   s.a.2.1 if message is ours
 *     s.a.2.1.1 ack the group
 *     s.a.2.1.2 set path to root
 *     s.a.2.1.3 update all clients 
 *  
 */ 
static int
recv_subscribe_ack_handler(void* cls, 
						   const struct GNUNET_MessageHeader* m)
{
  uint16_t size = ntohs(m->size);
  if(size < sizeof(*m))
  {
	GNUNET_break_op(0);
	return GNUNET_SYSERR;
  }
  const struct GNUNET_SCRB_SubscribeAckMessage*
	msg = (struct GNUNET_SCRB_SubscribeAckMessage*)m;
	
  struct Group*
	grp = GNUNET_CONTAINER_multihashmap_get(groups, &msg->grp_key_hash);
  
  if(NULL != grp)
  {
	//s.a.2 if group is created
	//s.a.2.1 if message is ours
	if(0 == memcmp(&my_identity, &msg->requestor, sizeof(struct GNUNET_PeerIdentity)))
	{
	  //s.a.2.1.1
	  grp->is_acked = 1;
	  //s.a.2.1.2
	  memcpy(&grp->path_to_root, &msg->path_to_root, sizeof(msg->path_to_root));
	  //s.a.2.1.2 we are the source, send subscribe ack message to clients
	  client_send_subscribe_ack (grp);
		
	}
  }	 
}

/**
 * Handle an incoming anycast message.
 * 
 * a.1 group is not created
 *   a.1.1 return ERR
 * a.2 group is created
 *   a.2.1 if content is dht put
 *     a.2.1.1 call put dht handler on the anycast message content
 *   a.2.2 else
 *     a.2.2.1 send anycast content to clients
 *     a.2.2.2 add local node to the visited list
 *     a.2.2.3 add children to message
 *     a.2.2.4 set local node as source
 *     a.2.2.5 get next destination
 *       a.2.2.5.1 if destination is null
 *         a.2.2.5.1.1 send anycast failure to the initial requestor
 *       a.2.2.5.2 else
 *         a.2.2.5.2.1 send anycast to the next
 */
static void
recv_direct_anycast_handler(void *cls,
							const struct GNUNET_MessageHeader *m)
{
  const struct GNUNET_SCRB_AnycastMessage*
	msg = (struct GNUNET_SCRB_AnycastMessage*)m;

  struct GNUNET_CRYPTO_EddsaPublicKey group_key;
  memcpy(&group_key, &msg->group_key, sizeof(group_key));
  struct GNUNET_HashCode group_key_hash;
  GNUNET_CRYPTO_hash (&group_key, sizeof(group_key), &group_key_hash);
	
  struct Group*
	grp = GNUNET_CONTAINER_multihashmap_get (groups, &group_key_hash);
  if(NULL == grp)// a.1 group is not created
  {
	// a.1.1 return err
	return;
  }
  // a.2 group is created
  struct GNUNET_SCRB_Content content;
  memcpy(&content, &msg->content, sizeof(msg->content));
  // a.2.1 if content is dht put
  if(DHT_PUT == content.type)
  {
	//we have received the join put
	//   a.2.1.1 call put dht handler on the anycast message content
	struct PutJoin* put = (struct PutJoin*)content.app_data;
	forward(put->options, put->data, put->path.path, put->path. path_length, groups);
  }else // a.2.2 else
  {
	// a.2.2.1 send anycast content to clients
	client_send_anycast (grp, &content);
	struct GNUNET_SCRB_AnycastMessage *new_msg = GNUNET_malloc(sizeof(*msg));
	memcpy(new_msg, msg, sizeof(*msg));
	// a.2.2.2 add local node to the visited list
	GNUNET_realloc(new_msg->visited.path, new_msg->visited.path_length + 1);
	new_msg->visited.path_length++;
	memcpy((new_msg->visited.path + new_msg->visited.path_length), &my_identity, sizeof(my_identity));
	// a.2.2.3 add children to message
	group_children_add_to_anycast(grp, new_msg);
	// a.2.2.4 set local node as source
	memcpy(&new_msg->asrc, &my_identity, sizeof(struct GNUNET_PeerIdentity));
	// a.2.2.5 get next destination
	struct GNUNET_PeerIdentity *next = NULL;
	if(NULL != policy->get_next_anycst_cb)
	  next = policy->get_next_anycst_cb(policy, new_msg, NULL);
	if(NULL == next) //  a.2.2.5.1 if destination is null
	{
	  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
				  "Anycast fail to group %s.\n",
				  GNUNET_h2s (&grp->pub_key_hash));
	  
	  cadet_send_anycast_fail(grp, &content,
							  &my_identity,
							  &msg->iasrc);
	  return;

	}else // a.2.2.5.2 else
	{
	  //   a.2.2.5.2.1 send anycast to the next
	  struct GNUNET_HashCode nh;
	  GNUNET_CRYPTO_hash(next, sizeof(*next), &nh);
	  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
				  "anycast handler: send anycast message to peer %s for group %s.\n",
				  GNUNET_h2s (&nh),
				  GNUNET_h2s (&grp->pub_key_hash));
	 
	  cadet_send_direct_anycast(&grp->pub_key, &new_msg->header, &my_identity, next);
	  return;
	}
  }
}

/**
******************************************************
*                 Monitor handlers                   *
******************************************************
*/

static void
get_dht_resp_callback (void *cls,
					   enum GNUNET_BLOCK_Type type,
					   const struct GNUNET_PeerIdentity *get_path,
					   unsigned int get_path_length,
					   const struct GNUNET_PeerIdentity *put_path,
					   unsigned int put_path_length,
					   struct GNUNET_TIME_Absolute exp,
					   const struct GNUNET_HashCode *key,
					   const void *data,
					   size_t size)
{
  GNUNET_log(GNUNET_ERROR_TYPE_WARNING,"I got get resp event! \n");
}

/**
 * A handler for the dht put callback
 */
static void
put_dht_handler(enum GNUNET_DHT_RouteOption options,
				const void* data,
				const struct GNUNET_PeerIdentity* path,
				unsigned int path_length,
				struct GNUNET_CONTAINER_MultiHashMap* groups)
{
  if (0 != (options & GNUNET_DHT_RO_LAST_HOP))
	deliver(options, data, path, path_length, groups); 
  else
	forward(options, data, path, path_length, groups);
}


static void
put_dht_callback (void *cls,
				  enum GNUNET_DHT_RouteOption options,
				  enum GNUNET_BLOCK_Type type,
				  uint32_t hop_count,
				  uint32_t desired_replication_level,
				  unsigned int path_length,
				  const struct GNUNET_PeerIdentity *path,
				  struct GNUNET_TIME_Absolute exp,
				  const struct GNUNET_HashCode *key,
				  const void *data,
				  size_t size)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "DHT PUT received\n");
  put_dht_handler(options, data, path, path_length, groups); 
}


/**
******************************************************
*                     Cleanup                        *
******************************************************
*/

/**
 * Free resources occupied by @a client.
 *
 * @param client to free
 */
static void
free_client (struct Client *client)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
			  "Free client. \n");
  struct GroupList* gl;
  while(NULL != (gl = client->gl_head))
  {
	GNUNET_CONTAINER_DLL_remove (client->gl_head,
								 client->gl_tail,
								 gl);
	GNUNET_free(gl);
  }
  GNUNET_free (client);
}

/**
 * Free memory occupied by an entry in the group map.
 *
 * @param cls unused
 * @param key unused
 * @param value a `struct  GNUNET_SCRB_Group*`
 * @return #GNUNET_OK (continue to iterate)
 */
static int
cleanup_group (void *cls,
			   const struct GNUNET_HashCode *key,
			   void *value)
{
  struct Group *group = value;

  free_group (group);
  return GNUNET_OK;
}

/**
 * Task run during shutdown.
 *
 * @param cls unused
 * @param tc unused
 */
static void
shutdown_task (void *cls,
			   const struct GNUNET_SCHEDULER_TaskContext *tc)
{

  if (NULL != groups)
  {
	GNUNET_CONTAINER_multihashmap_iterate (groups,
										   &cleanup_group,
										   NULL);
	GNUNET_CONTAINER_multihashmap_destroy (groups);
	groups = NULL;
  }
	
  GNUNET_DHT_monitor_stop (monitor_handle);
  GNUNET_DHT_disconnect (dht_handle);
  dht_handle = NULL;
	
  if (core_api != NULL)
  {
	GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Disconnecting core.\n");
	GNUNET_CORE_disconnect (core_api);
	core_api = NULL;
  }

  if (NULL != scrb_stats)
  {
	GNUNET_STATISTICS_destroy (scrb_stats, GNUNET_NO);
	scrb_stats = NULL;
  }
}

/**
 * Sends a group modification event message to the given node
 * @param grp      Group the node is taken into
 * @param node     Node
 * @param child    Child
 * @param op       Add/Rem -> 1/0
 */
static void
cadet_send_child_event (struct Group* grp,
						struct NodeHandle* node,
						struct GNUNET_PeerIdentity* child,
						uint8_t op)
{	
  struct GNUNET_SCRB_ChildChangeEventMessage*
	msg = GNUNET_malloc (sizeof(*msg));
  if(1 == op)
	msg->header.header.type = htons(GNUNET_MESSAGE_TYPE_SCRB_CHILD_ADD);
  else
	msg->header.header.type = htons(GNUNET_MESSAGE_TYPE_SCRB_CHILD_REM);
  msg->header.header.size = htons(sizeof(*msg));
  memcpy(&msg->grp_key, &grp->pub_key, sizeof(grp->pub_key));
  memcpy(&msg->child, child, sizeof(*child));	
  cadet_send_msg(node->chn, &msg->header.header);
}

/**
 * Sends a group modification event message to all children of the given
 * group
 *
 * @param grp      Group the node is taken into
 * @param op       Add/Rem -> 1/0
 */
static void
cadet_send_child_event_all (const struct Group* grp,
							const struct GNUNET_PeerIdentity* child,
							uint8_t op)
{	
  struct GNUNET_SCRB_ChildChangeEventMessage*
	msg = GNUNET_malloc (sizeof(*msg));
  if(1 == op)
	msg->header.header.type = htons(GNUNET_MESSAGE_TYPE_SCRB_CHILD_ADD);
  else
	msg->header.header.type = htons(GNUNET_MESSAGE_TYPE_SCRB_CHILD_REM);
  msg->header.header.size = htons(sizeof(*msg));
  memcpy(&msg->grp_key, &grp->pub_key, sizeof(grp->pub_key));
  memcpy(&msg->child, child, sizeof(*child));	
  group_children_send_message(grp, &msg->header.header);
}

/**
 * Handler for an incoming child change message.
 */
int
cadet_recv_child_change_event(void* cls, 
							  struct GNUNET_CADET_Channel* channel,
							  void** ctx,
							  const struct GNUNET_MessageHeader* m)
{
  uint16_t size = ntohs(m->size);
  if(size < sizeof(*m))
  {
	GNUNET_break_op(0);
	return GNUNET_SYSERR;
  }
  const struct GNUNET_SCRB_ChildChangeEventMessage*
	msg = (struct GNUNET_SCRB_ChildChangeEventMessage*)m;
  
  if(NULL != *ctx)
  {
	GNUNET_break_op(0);
	return GNUNET_SYSERR;
  }
  //FIXME: here should be some necessary security checks
  struct GNUNET_HashCode grp_key_hash;
  GNUNET_CRYPTO_hash(&msg->grp_key, sizeof(msg->grp_key), &grp_key_hash);
  struct Group*
	grp = GNUNET_CONTAINER_multihashmap_get (groups, &grp_key_hash);
  if(NULL != grp)
  {
	
	//just copy the message content and send to all clients
	//and children that have been acked
	struct GNUNET_SCRB_ChildChangeEventMessage*
	  new_msg = GNUNET_malloc(sizeof(*new_msg));
	memcpy(new_msg, msg, sizeof(*msg));
	struct NodeHandle *nl = grp->nl_head;
	while(NULL != nl)
	{
	  if(1 == nl->is_acked)
		cadet_send_msg(nl->chn, &msg->header.header);
	  nl = nl->next;
	}
	group_client_send_message(grp, &new_msg->header.header);
  }
  return GNUNET_OK;
}

/**
 * Handler for an incoming anycast fail message.
 */
int
cadet_recv_anycast_fail(void* cls, 
						struct GNUNET_CADET_Channel* channel,
						void** ctx,
						const struct GNUNET_MessageHeader* m)
{
  uint16_t size = ntohs(m->size);
  if(size < sizeof(*m))
  {
	GNUNET_break_op(0);
	return GNUNET_SYSERR;
  }
  const struct GNUNET_SCRB_AnycastFailMessage*
	msg = (struct GNUNET_SCRB_AnycastFailMessage*)m;
  if(NULL != *ctx)
  {
	GNUNET_break_op(0);
	return GNUNET_SYSERR;
  }
  //FIXME: here should be some necessary security checks
  struct GNUNET_HashCode grp_key_hash;
  GNUNET_CRYPTO_hash(&msg->group_key, sizeof(msg->group_key), &grp_key_hash);
  struct Group*
	grp = GNUNET_CONTAINER_multihashmap_get (groups, &grp_key_hash);
  if(NULL != grp)
  {
	struct GNUNET_HashCode srch;
	GNUNET_CRYPTO_hash(&msg->src, sizeof(&msg->src), &srch);
	GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
				"Receive anycast fail from %s for group %s.\n",
				GNUNET_h2s (&srch),
				GNUNET_h2s (&grp->pub_key_hash));
	
	if(NULL != policy->recv_anycst_fail_cb)
	  policy->recv_anycst_fail_cb(policy,
								   &msg->group_key,
								   &msg->src,
								  &msg->content, NULL);
  }
  return GNUNET_OK;
}

/**
 * Incoming subscribe parent message
 */ 
int
cadet_recv_subscribe_parent(void* cls, 
                            struct GNUNET_CADET_Channel* channel, 
                            void** ctx,
                            const struct GNUNET_MessageHeader* m)
{
  uint16_t size = ntohs(m->size);
  if(size < sizeof(*m))
  {
	GNUNET_break_op(0);
	return GNUNET_SYSERR;
  }
  const struct GNUNET_SCRB_SubscribeParentMessage*
	msg = (struct GNUNET_SCRB_SubscribeParentMessage*)m;
  
  if(NULL != *ctx)
  {
	GNUNET_break_op(0);
	return GNUNET_SYSERR;
  }
  //FIXME: here should be some necessary security checks
  struct Group*
	grp = GNUNET_CONTAINER_multihashmap_get (groups, &msg->grp_key_hash);
  if(NULL != grp)
  {
	struct NodeHandle* parent = GNUNET_new (struct NodeHandle);
	parent->peer = msg->parent;
	GNUNET_CRYPTO_hash (&parent->peer, sizeof(parent->peer), &parent->peer_hash);
	//create a channel for parent
	struct Channel* chn = GNUNET_malloc(sizeof (*chn));
	chn->grp = grp;
	chn->channel = channel;
	chn->group_key = msg->grp_key;
	chn->group_key_hash = msg->grp_key_hash;
	chn->peer = msg->parent;
	parent->chn = chn;
	//save the channel as parent channel in group
	grp->parent = parent;
  }
  return GNUNET_OK;
}

/**
 * Receives a downstream message.
 * 
 * D.S.M.1 if we are not recipients
 *   D.S.M.1.1 send the message down the stream 
 * D.S.M 2 extract contents
 *   D.S.M 2.1 if the content is message
 *     D.S.M 2.1.1 if subscribe fail message
 *       D.S.M 2.1.1.1 call a handler for subscribe fail
 *     D.S.M 2.1.2 if subscribe ack message
 *       D.S.M 2.1.2.1 call a handler for subscribe ack
 *   D.S.M 2.2 if the content is anycast message
 *     D.S.M 2.2.1 call the anycast message handler
 */
int
cadet_recv_downstream_msg(void* cls,
						  struct GNUNET_CADET_Channel* channel,
						  void** ctx,
						  const struct GNUNET_MessageHeader* m)
{
  uint16_t size = ntohs(m->size);
  if(size < sizeof(*m))
  {
	GNUNET_break_op(0);
	return GNUNET_SYSERR;
  }
  const struct GNUNET_SCRB_DownStreamMessage*
	msg = (struct GNUNET_SCRB_DownStreamMessage*)m;
  
  if(NULL != *ctx)
  {
	GNUNET_break_op(0);
	return GNUNET_SYSERR;
  }
  
  if(0 == memcmp(&my_identity, &msg->dst, sizeof(struct GNUNET_PeerIdentity)))
  {
	//D.S.M.1.1 send the message down the stream
	struct GNUNET_SCRB_MessageHeader* m = (struct GNUNET_SCRB_MessageHeader*)msg->content.app_data;
	  //set our identity as the source
	cadet_send_downstream_msg(&msg->grp_key, m, msg->content.type, &my_identity, &msg->dst);
		
  }
  //D.S.M 2 extract contents
  struct GNUNET_SCRB_Content content;
  memcpy(&content, &msg->content, sizeof(msg->content));
  //	D.S.M 2.1 if the content is message
  if(MSG == content.type)
  {
	struct GNUNET_MessageHeader* m = (struct GNUNET_MessageHeader*)content.app_data;
   		
	if(GNUNET_MESSAGE_TYPE_SCRB_SUBSCRIBE_FAIL == ntohs(m->type))
	{
	  // D.S.M 2.1.1 if subscribe fail message
	  recv_subscribe_fail_handler(cls, m);
			
	}else if(GNUNET_MESSAGE_TYPE_SCRB_SUBSCRIBE_ACK == ntohs(m->type))
	{
	  // D.S.M 2.1.2 if subscribe ack message
	  recv_subscribe_ack_handler(cls, m);
	}
  }else if(ANYCAST_MSG == content.type)
  {
	  recv_direct_anycast_handler(cls, m);
		
  }else if(MULTICAST_MSG == content.type)
  {
		
  }

  return GNUNET_OK;
}


/**
 * A subscribe request from the client
 * 
 * c.s.1 group is not created
 *   c.s.1.1 create group
 *   c.s.1.3 send subscribe request via dht
 * c.s.2 add client to clients
 */
void
client_recv_subscribe (void *cls, struct GNUNET_SERVER_Client *client,
					   const struct GNUNET_MessageHeader *message)
{
  uint16_t size = ntohs(message->size);
  if(size < sizeof(*message))
  {
	GNUNET_break_op(0);
	return;
  }
  //create all the necessary structures on our side
  const struct GNUNET_SCRB_SubscribeMessage* sm =
	(const struct GNUNET_SCRB_SubscribeMessage*) message;
  //hashing public key of group
  struct GNUNET_CRYPTO_EddsaPublicKey group_key;
  struct GNUNET_HashCode group_key_hash;
  memcpy(&group_key, &sm->group_key, sizeof(group_key));
  GNUNET_CRYPTO_hash (&group_key, sizeof(group_key), &group_key_hash);

  //take client's public key and make a hash
  struct GNUNET_CRYPTO_EddsaPrivateKey client_priv_key;
  struct GNUNET_CRYPTO_EddsaPublicKey client_pub_key;
  struct GNUNET_HashCode client_pub_key_hash;
  memcpy(&client_priv_key, &sm->client_key, sizeof(client_priv_key));
  GNUNET_CRYPTO_eddsa_key_get_public(&client_priv_key, &client_pub_key);
  GNUNET_CRYPTO_hash (&client_pub_key, sizeof(client_pub_key), &client_pub_key_hash);
  //copy the content
  struct GNUNET_SCRB_Content content;
  memcpy(&content, &sm->content, sizeof(content));
  //take client context or create
  struct Client* 
	sclient = GNUNET_SERVER_client_get_user_context(client, struct Client); 
	
  if(NULL == sclient)
  {
	sclient = GNUNET_new(struct Client);
	sclient->priv_key = client_priv_key;
	sclient->pub_key = client_pub_key;
	sclient->pub_key_hash = client_pub_key_hash;
	GNUNET_SERVER_client_set_user_context (client, sclient);
  }
  //take group or create
  struct Group*
	grp = GNUNET_CONTAINER_multihashmap_get (groups, &group_key_hash);
  
  if(NULL == grp)//c.s.1 group is created
  {
	//c.s.1.1 create group
	grp = GNUNET_new(struct Group);
	grp->pub_key = group_key;
	grp->pub_key_hash = group_key_hash;
	grp->nc = GNUNET_SERVER_notification_context_create (server, 1);
	//c.s.1.2 send subscribe message via dht
	struct GNUNET_BLOCK_SCRB_Join *
	  join_block = GNUNET_new(struct GNUNET_BLOCK_SCRB_Join);

	join_block->gr_pub_key = group_key;
	join_block->gr_pub_key_hash = group_key_hash;
	join_block->cl_pr_key = client_priv_key;
	join_block->cl_pub_key = client_pub_key;
	join_block->cl_pub_key_hash = client_pub_key_hash;
	join_block->src = my_identity;
	join_block->src_hash = my_identity_hash;
	join_block->content = content;
	//send message via DHT
	put_dht_handle = GNUNET_DHT_put (dht_handle, &group_key_hash, 1,
									 GNUNET_DHT_RO_RECORD_ROUTE |
									 GNUNET_DHT_RO_DEMULTIPLEX_EVERYWHERE | GNUNET_DHT_RO_LAST_HOP,
									 GNUNET_BLOCK_SCRB_TYPE_JOIN,
									 sizeof (join_block), join_block,
									 GNUNET_TIME_UNIT_FOREVER_ABS,
									 GNUNET_TIME_UNIT_FOREVER_REL,
									 NULL, NULL);

	if(NULL == put_dht_handle)
	  GNUNET_break(0);
  }
	
  //c.s.2 add client to group client list 
  struct ClientList *cl = GNUNET_new (struct ClientList);
  cl->client = client;
  GNUNET_CONTAINER_DLL_insert (grp->cl_head, grp->cl_tail, cl);
	
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
			  "%p Client connected to group %s. \n",
			  sclient, GNUNET_h2s (&grp->pub_key_hash));
	
  //operation is done on our side
	
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
}

/**
 * Message handlers for server
 */
static const struct GNUNET_SERVER_MessageHandler server_handlers[] = {
  {&client_recv_subscribe, NULL,
   GNUNET_MESSAGE_TYPE_SCRB_SUBSCRIBE, 0},
  {NULL, NULL, 0, 0}
};

/**
 * CADET handlers
 */
static const struct GNUNET_CADET_MessageHandler cadet_handlers[] = {
  {&cadet_recv_downstream_msg, GNUNET_MESSAGE_TYPE_SCRB_DWNSTRM_MSG, 0},
  {&cadet_recv_subscribe_parent, GNUNET_MESSAGE_TYPE_SCRB_SUBSCRIBE_SEND_PARENT, 0},
  {&cadet_recv_anycast_fail, GNUNET_MESSAGE_TYPE_SCRB_ANYCAST_FAIL, 0},
  {&cadet_recv_child_change_event, GNUNET_MESSAGE_TYPE_SCRB_CHILD_ADD, 0},
  {&cadet_recv_child_change_event, GNUNET_MESSAGE_TYPE_SCRB_CHILD_REM, 0},
  {NULL, 0, 0}
};
/**
 * Listening ports for cadet
 */
static const uint32_t cadet_ports[] = {GNUNET_APPLICATION_TYPE_MULTICAST, 0};
//FIXME: add scribe application type

static void
client_notify_connect(void* cls, struct GNUNET_SERVER_Client* client)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "%p Client connected\n", client);
  /*FIXME: send connect ACK*/
}

static void*
cadet_notify_channel_new(void* cls,
						 struct GNUNET_CADET_Channel* channel,
						 const struct GNUNET_PeerIdentity* initiator,
						 uint32_t port,
						 enum GNUNET_CADET_ChannelOption options)
{
  return NULL;
}

static void
cadet_notify_channel_end(void* cls,
						 const struct GNUNET_CADET_Channel* channel,
						 void* ctx)
{
  if(NULL == ctx)
	return;
	
  struct Channel *chn = ctx;
  if(NULL != chn->grp)
  {
	struct Group* grp = chn->grp;
	struct NodeHandle* nl;
	nl = grp->nl_head;
	while(NULL != nl)
	{
	  if(chn == nl->chn)
	  {
		GNUNET_free(nl);
		break;
	  }else
		nl = nl->next;
	}
		
	if(chn == grp->parent->chn)
	  GNUNET_free(grp->parent);
	else if(chn == grp->root->chn)
	  GNUNET_free(grp->root);
  }
  GNUNET_free(chn);
}

static void
client_notify_disconnect(void* cls,
						 struct GNUNET_SERVER_Client* client)
{
  if(NULL == client)
	return;
  struct Client*
	sclient = GNUNET_SERVER_client_get_user_context (client, struct Client);
	  
  if(NULL == sclient)
  {
	GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
				"%p User context is NULL in client_disconnect()\n", client);
	GNUNET_assert(0);
	return;
  }
  
  struct GroupList* gl;
  struct Group* grp;
  struct ClientList* cl;

  gl = sclient->gl_head;
  while(NULL != gl)
  {
	grp = gl->group;
	cl = grp->cl_head;
	while(NULL != cl)
	{
	  if(cl->client == client)
	  {
		GNUNET_CONTAINER_DLL_remove (grp->cl_head,
									 grp->cl_tail,
									 cl);
		GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
					"%p Client is disconnected from group %s\n",
					client,
					GNUNET_h2s(&grp->pub_key_hash));
		if(NULL == grp->cl_head && group_children_is_empty(grp))
		{
		  //do cleanup
		  GNUNET_CONTAINER_multihashmap_remove (groups, &grp->pub_key_hash, grp);
		  free_group(grp);
		}
				
	  }
	  cl = cl->next;
	}
	gl = gl->next;
  }
  free_client(sclient);
}

static void
core_connected_cb(void* cls, const struct GNUNET_PeerIdentity *identity)
{
  my_identity = *identity;
  GNUNET_CRYPTO_hash (identity,
					  sizeof (struct GNUNET_PeerIdentity),
					  &my_identity_hash);

  scrb_stats = GNUNET_STATISTICS_create("scrb", cfg);
  groups = GNUNET_CONTAINER_multihashmap_create(1, GNUNET_YES);
	
  cadet = GNUNET_CADET_connect (cfg, NULL, 
								&cadet_notify_channel_new,
								&cadet_notify_channel_end,
								cadet_handlers, cadet_ports);
  GNUNET_SERVER_add_handlers(server, server_handlers);
  GNUNET_SERVER_disconnect_notify (server, &client_notify_disconnect, NULL);
	
  dht_handle = GNUNET_DHT_connect (cfg, 100);
  monitor_handle = GNUNET_DHT_monitor_start (dht_handle,
											 GNUNET_BLOCK_TYPE_ANY,
											 NULL,
											 NULL,
											 &get_dht_resp_callback,
											 &put_dht_callback,
											 cls);

  policy = GNUNET_SCRB_create_default_policy();
  route_map = GNUNET_SCRB_create_route_map_def();

  GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_FOREVER_REL, &shutdown_task,
								NULL);
}

static void
run (void *cls,
	 struct GNUNET_SERVER_Handle *srv,
	 const struct GNUNET_CONFIGURATION_Handle *c)
{
  cfg = c;
  server = srv;
  GNUNET_SERVER_connect_notify(server, &client_notify_connect, NULL);
  core_api = GNUNET_CORE_connect (cfg, NULL, &core_connected_cb, NULL, NULL,
								  NULL, GNUNET_NO, NULL, GNUNET_NO, NULL);	
}


/**
 * The main function for the scrb service.
 *
 * @param argc number of arguments from the command line
 * @param argv command line arguments
 * @return 0 ok, 1 on error
 */
int
main (int argc, char *const *argv)
{
  return (GNUNET_OK ==
		  GNUNET_SERVICE_run (argc, argv,"scrb",
							  GNUNET_SERVICE_OPTION_NONE, &run, NULL)) ? 0 : 1;
}

/* end of gnunet-service-scrb.c */
