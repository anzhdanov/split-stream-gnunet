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
#include "scrb.h"
#include "gnunet/gnunet_dht_service.h"
#include <gcrypt.h>
#include "scrb_block_lib.h"
#include "scrb_map.h"
#include "scrb_policy.h"

struct NodeHandle
{  
  struct GNUNET_PeerIdentity* peer;
  struct GNUNET_HashCode* peer_hash;
  struct Channel* chn;
  uint8_t is_acked;
};

struct ClientList
{
  struct GNUNET_SERVER_Client* client;
  struct ClientList* prev;
  struct ClientList* next;
};

struct NodeList
{
  struct NodeHandle* node;
  struct NodeList* prev;
  struct NodeList* next;
};


struct Group
{
  //a list of clients
  struct ClientList* cl_head;
  struct ClientList* cl_tail;
	
  //a list of peers (children)
  struct NodeList* nl_head;
  struct NodeList* nl_tail;
	
  struct GNUNET_SCRB_RoutePath path_to_root;

  struct GNUNET_CRYPTO_EddsaPublicKey pub_key;

  struct GNUNET_HashCode pub_key_hash;

  //channel to the parent node
  struct NodeHandle* parent;

  //channel to the root node
  struct NodeHandle* root;
  //if we are the root node for the group
  uint8_t is_root;
  //if we are acked
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
  const void* data;
  const struct GNUNET_SCRB_RoutePath path;
};

struct Client
{
  //a list of groups
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
	
  struct GNUNET_CRYPTO_PublicKey* group_key;

  struct GNUNET_HashCode* group_key_hash; 

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
  struct GNUNET_PeerIdentity* peer;
	
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
  CHECK_FAIL, SUBSCRIBE_ACK, SUBSCRIBE_FAIL, WAIT_ACK, ANYCAST, ANYCAST_FAIL, ERR
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
 * Our notification context.
 */
static struct GNUNET_SERVER_NotificationContext *nc;

/**
 * Handle to DHT
 */
static struct GNUNET_DHT_Handle *dht_handle;

/**
 * Handle to DHT PUT
 */
static struct GNUNET_DHT_PutHandle *put_dht_handle;

/**
 * Handle to DHT GET
 */
static struct GNUNET_DHT_GetHandle *get_dht_handle;

static struct GNUNET_DHT_MonitorHandle *monitor_handle;

static struct GNUNET_CONTAINER_MultiHashMap *groups;

/**
******************************************************
*                 Monitor handlers                   *
******************************************************
*/

void
get_dht_resp_callback (void *cls,
					   enum GNUNET_BLOCK_Type type,
					   const struct GNUNET_PeerIdentity *get_path,
					   unsigned int get_path_length,
					   const struct GNUNET_PeerIdentity *put_path,
					   unsigned int put_path_length,
					   struct GNUNET_TIME_Absolute exp,
					   const struct GNUNET_HashCode *key,
					   const void *data,
					   size_t size);
void
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
				  size_t size);
/**
 * A handler for the dht put callback
 */
void
put_dht_handler(enum GNUNET_DHT_RouteOption options,
				const void* data,
				const struct GNUNET_PeerIdentity* path,
				unsigned int path_length,
				struct GNUNET_CONTAINER_MultiHashMap* groups);


/**
******************************************************
*                                                    *
******************************************************
*/

/**
 * The function is called on the application at the destination peer
 * for an icoming dht put.
 */
void
deliver(enum GNUNET_DHT_RouteOption options,
		const void* data,
		const struct GNUNET_PeerIdentity* path,
		unsigned int path_length,
		struct GNUNET_CONTAINER_MultiHashMap* groups); 
/**
 * The function is invoked on applications when the underlying
 * peer receives an incoming dht put. Applications can admit
 * a requestor to the group or send fail or ack replies to the
 * subscriber. Applications cannot stop the message propagation
 * nor change the message content.
 *
 * @a options          routing options for DHT
 * @a data             data which comes together with put
 * @a path             path
 * @a path_length      path length
 * @a groups           a hash map with groups
 * @return results of the forwarding operation, @see enum FOpResult
 */
uint8_t
forward(enum GNUNET_DHT_RouteOption options,
		const void* data,
		const struct GNUNET_PeerIdentity* path,
		unsigned int path_length,
		struct GNUNET_CONTAINER_MultiHashMap* groups);

/**
******************************************************
*               Helper methods                       *
******************************************************
*/

/**
 * Checks if the @a path contains @a node
 * @param path        Path of DHT message
 * @param path_length The length of the path
 * @param node        Identity of the peer to be checked
 * @return 0 in case the node is not on the path, 1 otherwise
 */
int
check_path_contains(const struct GNUNET_PeerIdentity* path,
					unsigned int path_length,
					const struct GNUNET_PeerIdentity* node);
/**
 * Add child to group
 * @param grp        Group the child to be added
 * @param node       The child to be added
 * @return 1 on success, 0 otherwise
 */
static int
group_children_add(struct Group* grp,
				   struct NodeHandle*  node);

/**
 * Clear the group children and free
 * @param grp    The group
 */
static void
group_children_clear(struct Group* grp);

/**
 * Clear the group children and free
 * @param grp    The group
 */
static void
group_clients_clear(struct Group* grp);

/**
 * Check if the group contains the child
 * @param grp     The group to be checked
 * @param child   The peer identity of the child
 * @return 1 on success, 0 otherwise
 */
static int
group_children_contain(struct Group* grp,
					   const struct GNUNET_PeerIdentity* child);

/**
 * Get node by its peer identity
 * @param grp           The group
 * @param child         Peer identity of the child
 * @return NodeHandle, NULL if none
 */
static struct NodeHandle*
group_children_get(struct Group* grp,
				   struct GNUNET_PeerIdentity* child);

/**
 * Remove a child by its peer identity
 * @param grp           The group
 * @param child         Peer identity of the child
 * @return NodeHandle, NULL if none
 */
static struct NodeHandle*
group_children_remove(struct Group* grp,
					  struct GNUNET_PeerIdentity* child);

/**
 * Size of the group children
 * @param nl           Pointer to the children list
 * @return size of the children
 */
static int 
group_children_size(struct NodeList* nl);

/**
 * Check if the children list is empty
 * @param grp The group to be checked
 * @return 1 if the children list is empty
 * 0 otherwise
 */
static int
group_children_is_empty(struct Group* grp);

/**
 * Add the group @a grp children to anycast message @a msg.
 */
static void
group_children_add_to_anycast(struct Group* grp,
							  struct GNUNET_SCRB_AnycastMessage* msg);


/**
 * Send message to all clients connected to the group
 */
static void
group_client_send_message(const struct Group* grp,
						  const struct GNUNET_MessageHeader* msg);

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
group_child_add_helper(const struct GNUNET_SCRB_Policy* policy,
					   const struct GNUNET_CRYPTO_EddsaPublicKey* grp_key,
					   const struct GNUNET_HashCode* grp_key_hash,
					   struct NodeHandle* child);
/**
 * Extracts the next on the path for the downstream message
 */
struct NodeHandle*
dstrm_msg_get_next(struct GNUNET_SCRB_DownStreamMessage* msg);

/**
 * Creates a put join from the provided data
 */
struct PutJoin*
create_put_join(enum GNUNET_DHT_RouteOption options,
				const void* data,
				const struct GNUNET_PeerIdentity* path,
				unsigned int path_length);
/**
 * Creates a node handle
 */
struct NodeHandle*
create_node_handle(const struct GNUNET_PeerIdentity* peer);

/**
******************************************************
*               Client communication                 *
******************************************************
*/

/**
 * Sends a subscribe ack message to all the clients subscribed to the group
 *
 * @param grp         The group which clients need to be updated
 */
static void
client_send_subscribe_ack (struct Group* grp);

/**
 * Sends a subscribe child added message to all the clients subscribed to the group
 *
 * @param grp         The group which clients need to be updated
 * @param peer        Identity of the child
 */
static void
client_send_child_change_event (const struct Group* grp, 
								const struct GNUNET_PeerIdentity* peer,
								uint16_t type);
/**
******************************************************
*                Cadet communication                 *
******************************************************
*/

/**
 * Sends a subscribe ack message to the given node
 *
 * @param node         Node
 * @param src          Source of the subscribe message
 * @param dst          Destination of the message
 * @param path_to_root Path to the group root node
 * @param ptr_lenght   Length of the path to root
 */
static void
cadet_send_subscribe_ack (const struct NodeHandle* node,
						  const struct GNUNET_PeerIdentity* src,
						  const struct GNUNET_PeerIdentity* dst,
						  const struct GNUNET_PeerIdentity* path_to_root,
						  const unsigned int ptr_length);

/**
 * Sends a subscribe fail message for the given node
 * @param node        The next node on the path
 * @param src         Source of the subscribe message
 * @param dst         Destination of the message
 */
static void
cadet_send_subscribe_fail (struct NodeHandle* node, 
						   struct GNUNET_PeerIdentity* src,
						   struct GNUNET_PeerIdentity* dst);
/**
 * Sends a subscribe parent message for the given node
 * @param grp      Group the node is taken into
 * @param node     Node
 */
static void
cadet_send_parent (struct Group* grp, struct NodeHandle* node);

/**
 * 
 */
static void
cadet_send_direct_anycast(const struct NodeHandle* handle,
						  struct GNUNET_SCRB_MessageHeader* m,
						  const struct GNUNET_PeerIdentity* src,
						  const struct GNUNET_PeerIdentity* dst)

void
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
  printf("I got get resp event! \n");
}
void
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

void
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

/**
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
 */
void
deliver(enum GNUNET_DHT_RouteOption options,
		const void* data,
		const struct GNUNET_PeerIdentity* path,
		unsigned int path_length,
		struct GNUNET_CONTAINER_MultiHashMap* groups) 
{
  //d.1 call forward on the message content
  enum FOpResult fres = forward(options, data, path, path_length, groups);
  struct GNUNET_BLOCK_SCRB_Join*
	join_block = (struct GNUNET_BLOCK_SCRB_Join*) data;
  struct GNUNET_HashCode srch;
  GNUNET_CRYPTO_hash(&join_block->src, sizeof(join_block->src), &srch);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
			  "Deliver is called subsribing peer %s for group %s.\n",GNUNET_h2s (&srch),
			  GNUNET_h2s (&join_block->gr_pub_key_hash));
  struct Group*
	grp = GNUNET_CONTAINER_multihashmap_get (groups, &join_block->gr_pub_key_hash);
  
  if(NULL != grp)
  {
	struct NodeHandle* node = create_node_handle(&path[path_length-1]);
	// d.2
	if(WAIT_ACK == fres)
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
		cadet_send_subscribe_ack (node, //d.2.5.1
								  &my_identity,
								  &join_block->src,
								  path, path_length);
	}
  }
}

/**
 * Processes a join block which comes via DHT.
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
		const void* data,
		const struct GNUNET_PeerIdentity* path,
		unsigned int path_length,
		struct GNUNET_CONTAINER_MultiHashMap* groups) 
{
  struct GNUNET_BLOCK_SCRB_Join*
	join_block = (struct GNUNET_BLOCK_SCRB_Join*) data;
  //FIXME: do all the necessary security checks

  //check if this is our subscribe message then ignore it
  if(0 == memcmp(&join_block->src, &my_identity, sizeof(struct GNUNET_HashCode)))
  {
	GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
				"Bypassing forward logic of subscribe message for group %s because local node is the subscriber's source.\n",
				GNUNET_h2s (&join_block->gr_pub_key_hash));
	return CHECK_FAIL;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
			  "Handle forward subscribe message for group %s.\n",
			  GNUNET_h2s (&join_block->gr_pub_key_hash));
	
  //take the last peer on the path
  const struct GNUNET_PeerIdentity* lp = &path[path_length - 1];
  
  //create a handle for the node
  struct NodeHandle* node = create_node_handle(lp);
	
  //source
  struct GNUNET_PeerIdentity source;
  memcpy(&source, &join_block->src, sizeof(source));
	
  struct GNUNET_CRYPTO_EddsaPublicKey grp_pub_key;
  struct GNUNET_HashCode grp_pub_key_hash;
  memcpy(&grp_pub_key, &join_block->gr_pub_key, sizeof(grp_pub_key));
  memcpy(&grp_pub_key_hash, &join_block->gr_pub_key_hash, sizeof(grp_pub_key_hash));
	
  struct Group*
	grp =GNUNET_CONTAINER_multihashmap_get (groups, &grp_pub_key_hash);
	
  if(NULL != grp)//f.1
  {
	//f.1.1. check if the source node is already on the path
	struct GNUNET_SCRB_RoutePath* path_to_root = &grp->path_to_root;
	if(1 == check_path_contains(path_to_root->path, path_to_root->path_length, lp))
	{
	  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
				  "Rejecting subsribe message for group %s, the node %s is already on the path.\n",
				  GNUNET_h2s (&grp->pub_key_hash),
				  GNUNET_h2s (node->peer_hash));
	  return CHECK_FAIL;
	}
		
	//f.1.2. Check if we already have the child
	if(1 == group_children_contain(grp, lp))
	{
	  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
				  "The node %s is already in group %s.\n",
				  GNUNET_h2s (node->peer_hash),
				  GNUNET_h2s (&grp->pub_key_hash));
	  //f.1.2.1 update map
	  if(NULL != route_map->map_put_path_cb)
		route_map->map_put_path_cb(route_map, &grp->pub_key_hash, path, path_length, NULL);
	  return CHECK_FAIL;
	}
	//f.1.3 check if any of the children are on the path
	struct NodeList* nl = grp->nl_head;
	while(NULL != nl)
	{
	  if(1 == check_path_contains(path, path_length, nl->node->peer))
	  {
		GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
					"Rejecting subsribe message for group %s, the child %s is already on the path.\n",
					GNUNET_h2s (&grp->pub_key_hash),
					GNUNET_h2s (node->peer_hash));
		return CHECK_FAIL;
	  }
	  nl = nl->next;
	}
	//f.1.4  check if our policy allows to take on the node
	if(NULL != policy->allow_subs_cb &&
	   1 == policy->allow_subs_cb(policy, lp, &grp_pub_key, groups, &join_block->content, NULL))
	{
	  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
				  "Hijacking subscribe message from %s to group %s.\n",
				  GNUNET_h2s (node->peer_hash),
				  GNUNET_h2s (&grp->pub_key_hash));
	  //f.1.4.1
	  //here, provide the last on the path to build the group
	  group_child_add_helper(policy, &grp_pub_key, &grp_pub_key_hash, node);
	  //f.1.4.2 update global view
	  if(NULL != route_map->map_put_path_cb)
		route_map->map_put_path_cb(route_map, &grp->pub_key_hash, path, path_length, NULL);
	  // f.1.4.3 if group is ack
	  if(grp->is_acked)
	  {
		//f.1.4.3.1 send ack to node
		cadet_send_subscribe_ack(node,
								 &my_identity,
								 &join_block->src,
								 path_to_root->path,
								 path_to_root->path_length);
		//f.1.4.3.2 send child add to clients
		client_send_child_change_event (grp, node->peer, 1);

		return SUBSCRIBE_ACK;
	  }
	  
	  return WAIT_ACK;

	}else if(1 == grp->is_acked)//f.1.5.(1) policy does not accept (group is acked)
	{
	  //f.1.5.2 send anycast to children
	  struct GNUNET_SCRB_AnycastMessage* msg = GNUNET_malloc(sizeof(*msg));
	  memcpy(&msg->group_key, &grp->pub_key, sizeof(grp->pub_key));
	  msg->pth_to_rq.path = GNUNET_malloc(path_length * sizeof(struct GNUNET_PeerIdentity));
	  memcpy(msg->pth_to_rq.path, path, path_length * sizeof(*path));
	  msg->pth_to_rq.path_length = path_length;
	  //send only to those that have been acked already
	  group_children_add_to_anycast(grp, msg);
	  struct GNUNET_PeerIdentity* next = NULL;
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
					GNUNET_h2s (node->peer_hash),
					GNUNET_h2s (&grp->pub_key_hash));

		cadet_send_subscribe_fail (node,
								   &my_identity,
								   &source);
		return SUBSCRIBE_FAIL;

	  }else
	  {
		GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
					"handle forward subscribe: routing message to peer %s for group %s.\n",
					GNUNET_h2s (node->peer_hash),
					GNUNET_h2s (&grp->pub_key_hash));
		struct NodeHandle* handle = NULL;
		if(NULL == (handle = group_children_get(grp, next)))
		{
		  //create a handle for the next peer
		  handle = create_node_handle(next);	
		}
		memcpy(&msg->ssrc, &join_block->src, sizeof(struct GNUNET_PeerIdentity));
		memcpy(&msg->iasrc, &my_identity, sizeof(struct GNUNET_PeerIdentity));
		memcpy(&msg->asrc, &my_identity, sizeof(struct GNUNET_PeerIdentity));
		//we create a new PutJoin to send with anycast messages
		struct PutJoin* put = create_put_join(options, data, path, path_length);
		msg->content.data = GNUNET_malloc(sizeof(*put));
		memcpy(msg->content.data, put, sizeof(*put));
		msg->content.data_size = sizeof(*put);
		msg->content.type = DHT_PUT;
		cadet_send_direct_anycast(handle, msg, &my_identity, next);
		return ANYCAST;
	  }
	}
  }else
  { //f.2 group is not created
	
	//f.2.1 if policy accepts the node
	if(NULL != policy->allow_subs_cb && 1 == policy->allow_subs_cb(policy, lp, &grp_pub_key, groups, &join_block->content, NULL))
	{
	  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
				  "Hijacking subscribe message from %s to group %s.\n",
				  GNUNET_h2s (node->peer_hash),
				  GNUNET_h2s (&grp->pub_key_hash));
	  //f.2.2.1 add child
	  //here, provide the last on the path to build the group
	  if(NULL != (grp = group_child_add_helper(policy, &grp_pub_key, &grp_pub_key_hash, node)))
	  {
		//the group was implicitly created
		//f.2.2.2 send parent
		cadet_send_parent (grp, node);
		//f.2.2.3 update global view
		if(NULL != route_map->map_put_path_cb)
		  route_map->map_put_path_cb(route_map, &grp->pub_key_hash, path, path_length, NULL);		
		
		return WAIT_ACK;
	  }
		
	}else //f.2.3 policy does not accept
	{
	  //f.2.3.1 send fail
	  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
				  "Anycast fail to group %s.\n",
				  GNUNET_h2s (&grp->pub_key_hash));
		
	  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
				  "Sending subsribe fail message to %s for group %s.\n",
				  GNUNET_h2s (node->peer_hash),
				  GNUNET_h2s (&grp->pub_key_hash));

	  cadet_send_subscribe_fail (node,
								 &my_identity,
								 &source);
	}
  }
}

/**
 * Checks if the @a path contains @a node
 * @param path        Path of DHT message
 * @param path_length The length of the path
 * @param node        Identity of the peer to be checked
 * @return 0 in case the node is not on the path, 1 otherwise
 */
int
check_path_contains(const struct GNUNET_PeerIdentity* path,
					unsigned int path_length,
					const struct GNUNET_PeerIdentity* node)
{
  int i;
  for(i = 0; i < path_length; i++)
	if(0 == memcmp(&path[i], node, sizeof(struct GNUNET_HashCode)))
	  return 1;
  return 0;
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
 * Sends a subscribe child added message to all the clients subscribed to the group
 *
 * @param grp         The group which clients need to be updated
 * @param peer        Identity of the child
 */
static void
client_send_child_change_event (const struct Group* grp, 
								const struct GNUNET_PeerIdentity* peer,
								uint16_t type)
{	
  struct GNUNET_SCRB_ChildChangeEventMessage*
	msg = GNUNET_malloc (sizeof(*msg));

  msg->header.header.type = htons(type);
  msg->header.header.size = htons(sizeof(*msg));
  memcpy(&msg->grp_key, &grp->pub_key, sizeof(grp->pub_key));
  memcpy(&msg->child, peer, sizeof(*peer));
  group_client_send_message(grp, &msg->header.header);
}

/**
 * Sends an anycast message to all the clients subscribed to the group
 *
 * @param grp         The group which clients need to be updated
 */
static void
client_send_anycast (struct GNUNET_CRYPTO_EddsaPublicKey* group_key,
					 struct GNUNET_SCRB_Content* content)
{	
  struct GNUNET_SCRB_ClientAnycastMessage
	*cam = GNUNET_malloc(sizeof(*cam));
  cam->header.header.type = htons(GNUNET_MESSAGE_TYPE_SCRB_ANYCAST);
  cam->header.header.size = htons(sizeof(*msg));
  memcpy(&cam->group_key, group_key, sizeof(*group_key));
  memcpy(&cam->content, content, sizeof(*content));
  group_client_send_message(grp, cam->header.header);
}


static struct Channel*
cadet_channel_create(struct Group* grp, struct GNUNET_PeerIdentity *peer)
{
  struct Channel *chn = GNUNET_malloc (sizeof(*chn));
  chn->grp = grp;
  chn->group_key = grp->pub_key;
  chn->group_key_hash = grp->pub_key_hash;
  chn->peer = *peer;
  chn->direction = DIR_OUTGOING;
  chn->channel = GNUNET_CADET_channel_create( cadet, chn, &chn->peer,
											  GNUNET_APPLICATION_TYPE_SCRB,
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
 * Sends a subscribe parent message for the given node
 * @param grp      Group the node is taken into
 * @param node     Node
 */
static void
cadet_send_parent (struct Group* grp, struct NodeHandle* node)
{	
  struct GNUNET_SCRB_SubscribeParentMessage*
	msg = GNUNET_malloc (sizeof(*msg));
  msg->header.header.type = htons(GNUNET_MESSAGE_TYPE_SCRB_SUBSCRIBE_SEND_PARENT);
  msg->header.header.size = htons(sizeof(*msg));
  msg->parent = node->chn->peer;
  msg->grp_key = node->chn->group_key;
  msg->grp_key_hash = node->chn->group_key_hash;
  cadet_send_msg(node->chn, msg->header.header);
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
  memcpy(&msg->grp_key, grp->pub_key, sizeof(*grp->pub_key));
  memcpy(&msg->child, child, sizeof(*node->peer));	
  cadet_send_msg(node->chn, msg->header.header);
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
  memcpy(&msg->grp_key, grp->pub_key, sizeof(*grp->pub_key));
  memcpy(&msg->child, child, sizeof(*child));	
  group_children_send_message(node->chn, msg->header.header);
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
cadet_send_downstream_msg (struct NodeHandle* node,
						   struct GNUNET_SCRB_MessageHeader* m,
						   enum GNUNET_SCRB_ContentType ct, 
						   struct GNUNET_PeerIdentity* src,
						   struct GNUNET_PeerIdentity* dst)
{	
  struct GNUNET_SCRB_DownStreamMessage*
	msg = GNUNET_malloc (sizeof(*msg));
  msg->header.header.type = htons(GNUNET_MESSAGE_TYPE_SCRB_DWNSTRM_MSG);
  msg->header.header.size = htons(sizeof(*msg));
  //encapsulate a message
  msg->content.data = m;
  msg->content.data_size = sizeof(*m);
  msg->content.type = ct;
  memcpy(&msg->src, src, sizeof(*src));
  memcpy(&msg->dst, dst, sizeof(*dst));
  GNUNET_CRYPTO_hash_create_random(GNUNET_CRYPTO_QUALITY_WEAK, &msg->id);
  cadet_send_msg(node->chn, msg->header.header);
}


/**
 * Sends a subscribe fail message for the given node
 * @param node        The next node on the path
 * @param src         Source of the subscribe message
 * @param dst         Destination of the message
 */
static void
cadet_send_subscribe_fail (struct NodeHandle* node, 
						   struct GNUNET_PeerIdentity* src,
						   struct GNUNET_PeerIdentity* dst)
{	
  struct GNUNET_SCRB_SubscribeFailMessage*
	msg = GNUNET_malloc (sizeof(*msg));
  msg->header.header.type = htons(GNUNET_MESSAGE_TYPE_SCRB_SUBSCRIBE_FAIL);
  msg->header.header.size = htons(sizeof(*msg));
  memcpy(&msg->requestor, dst, sizeof(*dst));
  memcpy(&msg->grp_key, node->chn->group_key, sizeof(msg->grp_key));
  memcpy(&msg->grp_key_hash, node->chn->group_key_hash, sizeof(msg->grp_key_hash));
  cadet_send_downstream_msg (node,msg, MSG, src, dst);
}

/**
 * Sends a subscribe ack message to the given node
 *
 * @param node         Node
 * @param src          Source of the subscribe message
 * @param dst          Destination of the message
 * @param path_to_root Path to the group root node
 * @param ptr_lenght   Length of the path to root
 */
static void
cadet_send_subscribe_ack (const struct NodeHandle* node,
						  const struct GNUNET_PeerIdentity* src,
						  const struct GNUNET_PeerIdentity* dst,
						  const struct GNUNET_PeerIdentity* path_to_root,
						  const unsigned int ptr_length)
{	
  struct GNUNET_SCRB_SubscribeAckMessage*
	msg = GNUNET_malloc (sizeof(*msg));
  msg->header.header.type = htons(GNUNET_MESSAGE_TYPE_SCRB_SUBSCRIBE_ACK);
  msg->header.header.size = htons(sizeof(*msg));
  memcpy(&msg->requestor, dst, sizeof(*dst));
  msg->path_to_root->path = GNUNET_malloc (ptr_length * sizeof(struct GNUNET_PeerIdentity));
  memcpy(msg->path_to_root->path, path_to_root, ptr_length * sizeof(*path_to_root));
  msg->path_to_root->path_length = ptr_length;
  memcpy(&msg->grp_key, node->chn->group_key, sizeof(msg->grp_key));
  memcpy(&msg->grp_key_hash, node->chn->group_key_hash, sizeof(msg->grp_key_hash));
  cadet_send_downstream_msg(node, msg, MSG, src, dst);
}

/**
 * Sends an anycast failure message to the given node
 * @param node        The next node on the path
 * @param src         Source of the subscribe message
 * @param dst         Destination of the message
 */
static void
cadet_send_anycast_fail(struct NodeHandle* node,
						struct GNUNET_SCRB_Content* content,
						struct GNUNET_PeerIdentity* src,
						struct GNUNET_PeerIdentity* dst)
{	
  struct GNUNET_SCRB_AnycastFailMessage*
	msg = GNUNET_malloc (sizeof(*msg));
  msg->header.header.type = htons(GNUNET_MESSAGE_TYPE_SCRB_ANYCAST_FAIL);
  msg->header.header.size = htons(sizeof(*msg));
  memcpy(&msg->src, dst, sizeof(*dst));
  memcpy(&msg->group_key, node->chn->group_key, sizeof(msg->group_key));
  memcpy(&msg->content, content, sizeof(*content));
  cadet_send_downstream_msg (node,msg, MSG, src, dst);
}


static void
cadet_send_direct_anycast(const struct NodeHandle* handle,
						  struct GNUNET_SCRB_MessageHeader* m,
						  const struct GNUNET_PeerIdentity* src,
						  const struct GNUNET_PeerIdentity* dst)
{
  struct GNUNET_SCRB_AnycastMessage*
	msg = (struct GNUNET_SCRB_AnycastMessage*)m;
  msg->header.header.type = htons(GNUNET_MESSAGE_TYPE_SCRB_ANYCAST);
  msg->header.header.size = htons(sizeof(*msg));
  cadet_send_downstream_msg (handle, msg, ANYCAST_MSG, src, dst);
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
void
recv_direct_anycast_handler(void* cls,
							const struct GNUNET_MessageHeader* m)
{
  const struct GNUNET_SCRB_AnycastMessage*
	msg = (struct GNUNET_SCRB_AnycastMessage*)m;

  struct GNUNET_CRYPTO_EddsaPublicKey group_key;
  memcpy(&group_key, &msg->group_key, sizeof(group_key));
  struct GNUNET_HashCode group_key_hash;
  GNUNET_CRYPTO_Hash (&group_key, sizeof(group_key), &group_key_hash);
	
  struct Group*
	grp = GNUNET_CONTAINER_multihashmap_get (groups, &grp_key_hash);
  if(NULL == grp)// a.1 group is not created
  {
	// a.1.1 return err
	return ERR;
  }
  // a.2 group is created
  struct GNUNET_SCRB_Content* content;
  memcpy(content, &msg->content, sizeof(&msg->content));
  // a.2.1 if content is dht put
  if(DHT_PUT == content->type)
  {
	//we have received the join put
	//   a.2.1.1 call put dht handler on the anycast message content
	struct PutJoin* put = (struct PutJoin*)content->data;
	forward(put->options, put->data, put->path.path, put->path. path_length, groups);
  }else // a.2.2 else
  {
	// a.2.2.1 send anycast content to clients
	client_send_anycast (grp->pub_key, &msg->content);
	  
	// a.2.2.2 add local node to the visited list
	GNUNET_realloc(msg->visited.path, msg->visited.path + 1);
	mempcy((msg->visited.path + path_length), &my_identity, sizeof(my_identity));
	// a.2.2.3 add children to message
	group_children_add_to_anycast(grp, msg);
	// a.2.2.4 set local node as source
	memcpy(&msg->asrc, &my_identity, sizeof(struct GNUNET_PeerIdentity));
	// a.2.2.5 get next destination
	struct GNUNET_PeerIdentity* next = NULL;
	if(NULL != policy->get_next_anycst_cb)
	  next = policy->get_next_anycst_cb(policy, msg, NULL);
	if(NULL == next) //  a.2.2.5.1 if destination is null
	{
	  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
				  "Anycast fail to group %s.\n",
				  GNUNET_h2s (grp->pub_key_hash));

	  cadet_send_anycast_fail(node,
							  &msg->content,
							  &my_identity,
							  &msg->iasrc);
	  return ANYCAST_FAIL;

	}else // a.2.2.5.2 else
	{
	  //   a.2.2.5.2.1 send anycast to the next
	  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
				  "anycast handler: send anycast message to peer %s for group %s.\n",
				  GNUNET_h2s (node->peer_hash),
				  GNUNET_h2s (grp->pub_key_hash));
	  struct NodeHandle* handle = NULL;
	  if(NULL == (handle = group_children_get(grp, next)))
	  {
		//create a handle for the next peer
		handle = GNUNET_new (struct NodeHandle);
		handle->peer = GNUNET_new (struct GNUNET_PeerIdentity);
		handle->peer_hash = GNUNET_new (struct GNUNET_HashCode);
		GNUNET_CRYPTO_Hash (next, sizeof(*next), handle->peer_hash);		
		memcpy(handle->peer, next, sizeof(*next));
		handle->ch = cadet_channel_create(grp, handle->peer);	
	  }
	  cadet_send_direct_anycast(handle, msg, &my_identity, next);
	  return ANYCAST;
	}
  }
}


int
cadet_recv_child_change_event(void* cls, 
							  struct GNUNET_CADET_Channel* channel,
							  void** ctx,
							  const struct GNUNET_MessageHeader* m)
{
  const struct GNUNET_SCRB_ChildChangeMessage*
	msg = (struct GNUNET_SCRB_ChildChangeMessage*)m;
  uint16_t size = ntohs(m->size);
  if(size < sizeof(*msg))
  {
	GNUNET_break_op(0);
	return GNUNET_SYSERR;
  }
  if(NULL != *ctx)
  {
	GNUNET_break_op(0);
	return GNUNET_SYSERR;
  }
  //FIXME: here should be some necessary security checks
  struct Group*
	grp = GNUNET_CONTAINER_multihashmap_get (groups, &msg->grp_key_hash);
  if(NULL == grp)
  {
	return GNUNET_SYSERR;
  }
  //just copy the message content and send to all clients
  //and children that have been acked
  struct GNUNET_SCRB_ChildChangeEventMessage*
	new_msg = GNUNET_malloc(sizeof(*new_msg));
  memcpy(new_msg, msg, sizeof(*msg));
  struct NodeList *nl = grp->nl_head;
  while(NULL != nl)
  {
	if(1 == nl->node->is_acked)
	  cadet_send_msg(nl->node->chn, msg->header.header);
	nl = nl->next;
  }
  group_client_send_message(grp, new_msg->header.header);
}

/**
 * 
 */
int
cadet_recv_anycast_fail(void* cls, 
						struct GNUNET_CADET_Channel* channel,
						void** ctx,
						const struct GNUNET_MessageHeader* m)
{
  const struct GNUNET_SCRB_AnycastFailMessage*
	msg = (struct GNUNET_SCRB_AnycastFailMessage*)m;
  uint16_t size = ntohs(m->size);
  if(size < sizeof(*msg))
  {
	GNUNET_break_op(0);
	return GNUNET_SYSERR;
  }
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
	struct GNUNET_HashCode srch;
	GNUNET_CRYPTO_hash(&msg->src, sizeof(&msg->src), &srch);
	GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
				"Receive anycast fail from %s for group %s.\n",
				GNUNET_h2s (&srch),
				GNUNET_h2s (grp->pub_key_hash));
	
	if(NULL != policy->recv_anycast_fail_cb)
	  policy->recv_anycast_fail_cb(policy,
								   &msg->group_key,
								   &msg->src,
								   &msg->content);
  }
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
  const struct GNUNET_SCRB_SubscribeParentMessage*
	msg = (struct GNUNET_SCRB_SubscribeParentMessage*)m;
  uint16_t size = ntohs(m->size);
  if(size < sizeof(*msg))
  {
	GNUNET_break_op(0);
	return GNUNET_SYSERR;
  }
  if(NULL != *ctx)
  {
	GNUNET_break_op(0);
	return GNUNET_SYSERR;
  }
  //FIXME: here should be some necessary security checks
  struct Group*
	grp = GNUNET_CONTAINER_multihashmap_get (groups, &msg->grp_key_hash);
  if(NULL == grp)
  {
	return GNUNET_SYSERR;
  }
  struct NodeHandle* parent = GNUNET_new (struct NodeHandle);
  node->peer = GNUNET_new (struct GNUNET_PeerIdentity);
  memcpy(node->peer, &msg->parent, sizeof(*node->peer));
  node->peer_hash = GNUNET_new (struct GNUNET_HashCode);
  GNUNET_CRYPTO_Hash (node->peer, sizeof(*node->peer), node->peer_hash);
  //create a channel for parent
  struct Channel* chn = GNUNET_malloc(sizeof (*node->chn));
  chn->grp = grp;
  chn->channel = channel;
  memcpy(chn->group_key, &msg->grp_key, sizeof(*chn->group_key));
  memcpy(chn->group_key_hash, &msg->grp_key_hash, sizeof(*chn->group_key_hash));
  memcpy(chn->peer, &msg->parent, sizeof(*chn->peer));
  chn->direction = DIR_INCOMING;
  node->chn = chn;
  //save the channel as parent channel in group
  grp->parent = parent;
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
  const struct GNUNET_SCRB_DownStreamMessage*
	msg = (struct GNUNET_SCRB_DownStreamMessage*)m;
  uint16_t size = ntohs(m->size);
  if(size < sizeof(*msg))
  {
	GNUNET_break_op(0);
	return GNUNET_SYSERR;
  }
  if(NULL != *ctx)
  {
	GNUNET_break_op(0);
	return GNUNET_SYSERR;
  }
  struct NodeHandle* next = NULL;
  if(0 == memcmp(&my_identity, &msg->dst, sizeof(struct GNUNET_PeerIdentity)))
  {
	//D.S.M.1 we are not recipients
	next = dstrm_msg_get_next(msg);
	if(NULL == next)
	{
	  //we are not recipients, we cannot send further
	  //for now do not handle, just drop
	  //TO-DO: add msg fail handler
			
	}else
	{
	  //D.S.M.1.1 send the message down the stream
	  struct NodeHandle* next = dstrm_msg_get_next (msg);
	  if(NULL != next)
	  {
		struct GNUNET_MessageHeader* m = (struct GNUNET_MessageHeader*)msg->content.data
		  //set our identity as the source
		  cadet_send_downstream_msg(next, m, msg->content.type, &my_identity, &msg->dst);
	  }
	}
		
  }
  //D.S.M 2 extract contents
  const struct GNUNET_SCRB_Content content;
  memcpy(&content, &msg->content, sizeof(msg->content));
  //	D.S.M 2.1 if the content is message
  if(MSG == content.type)
  {
	const struct GNUNET_MessageHeader m;
	memcpy(&m, content.data, content.data_size);
   		
	if(GNUNET_MESSAGE_TYPE_SCRB_SUBSCRIBE_FAIL = ntohs(m.type))
	{
	  // D.S.M 2.1.1 if subscribe fail message
	  recv_subscribe_fail_handler(cls, m);
			
	}else if(GNUNET_MESSAGE_TYPE_SCRB_SUBSCRIBE_ACK = ntohs(m.type))
	{
	  // D.S.M 2.1.2 if subscribe ack message
	  recv_subscribe_ack_handler(cls, m);
	}
  }else if(ANYCAST_MSG == content.type)
  {
		
  }else if(MULTICAST_MSG == content.type)
  {
		
  }	
}

/**
 * Incoming subscribe fail message
 * s.f.1 group is not created
 *   s.f.1.1 return err ?
 * s.f.2 group is created
 *   s.f.2.1 if we get fail for our request
 *     s.f.2.1.1 send subscribe fail to clients
 *   s.f.2.2 if group is empty
 *     s.f.2.2.1 destroy group
 */ 
int
recv_subscribe_fail_handler(void* cls, 
							const struct GNUNET_MessageHeader* m)
{
  const struct GNUNET_SCRB_SubscribeFailMessage*
	msg = (struct GNUNET_SCRB_SubscribeFailMessage*)m;
	
  struct Group*
	grp = GNUNET_CONTAINER_multihashmap_get(groups, &msg->grp_key_hash);
  //s.f.1 if group is not created
  if(NULL == grp)
  {
	return 0;
  }
  //s.f.2 group is created
  //s.f.2.1 check if we are the source
  if(0 == memcmp(&my_identity, &msg->source, sizeof(struct GNUNET_PeerIdentity)))
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
  return GNUNET_OK;
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
int
recv_subscribe_ack_handler(void* cls, 
						   const struct GNUNET_MessageHeader* m)
{
  const struct GNUNET_SCRB_SubscribeAckMessage*
	msg = (struct GNUNET_SCRB_SubscribeAckMessage*)m;
	
  struct Group*
	grp = GNUNET_CONTAINER_multihashmap_get(groups, &msg->grp_key_hash);
  //s.a.1 if group is not created
  if(NULL == grp)
  {
	return 0;
  }
  //s.a.2 if group is created
  //s.a.2.1 if message is ours
  if(0 == memcmp(&my_identity, &msg->requestor, sizeof(struct GNUNET_PeerIdentity)))
  {
	//s.a.2.1.1
	grp->is_acked = 1;
	//s.a.2.1.2
	memcpy(grp->path_to_root, &msg->path_to_root, sizeof(msg->path_to_root));
	//s.a.2.1.2 we are the source, send subscribe ack message to clients
	client_send_subscribe_ack (grp);
		
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
static void
client_recv_subscribe (void *cls, struct GNUNET_SERVER_Client *client,
					   const struct GNUNET_MessageHeader *message)
{
  //create all the necessary structures on our side
  const struct GNUNET_SCRB_SubscribeMessage* sm =
	(const struct GNUNET_SCRB_SubscribeMessage*) msg;
  //hashing public key of group
  struct GNUNET_CRYPTO_EddsaPublicKey group_key;
  struct GNUNET_HashCode group_key_hash;
  memcpy(&group_key, sizeof(group_key), &sm->group_key);
  GNUNET_CRYPTO_Hash (&group_key, sizeof(group_key), &group_key_hash);

  //take client's public key and make a hash
  struct GNUNET_CRYPTO_EddsaPrivateKey client_priv_key;
  struct GNUNET_CRYPTO_EddsaPublicKey client_pub_key;
  struct GNUNET_HashCode client_pub_key_hash;
  memcpy(&client_priv_key, sizeof(client_priv_key), &sm->client_key);
  GNUNET_CRYPTO_eddsa_key_get_public(&client_priv_key, &client_pub_key);
  GNUNET_CRYPTO_Hash (&client_pub_key, sizeof(client_pub_key), &client_pub_key_hash);
  //copy the content
  struct GNUNET_SCRB_Content content;
  memcpy(&content, sizeof(content), &sm->content);
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
  struct Group* grp =
	client = GNUNET_CONTAINER_multihashmap_get (groups, &pub_key_hash);
  if(NULL == grp)//c.s.1 group is created
  {
	//c.s.1.1 create group
	grp = GNUNET_new(struct Group);
	grp->pub_key = group_key;
	grp->pub_key_hash = group_key_hash;
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
			  cl_ctx, GNUNET_h2s (&grp->pub_key_hash));
	
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
 *
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
static const uint32_t cadet_ports[] = {GNUNET_APPLICATION_TYPE_SCRB, 0};

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
	
  nc = GNUNET_SERVER_notification_context_create (server, 1);
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
	GNUNET_CONTAINER_DLL_remove (client->nl_head,
								 client->nl_tail,
								 gl);
	GNUNET_free(gl);
  }
  GNUNET_free (client);
}

/**
 * Free resources occupied by the @a group.
 *
 * @param group to free
 */
static void
free_group(struct Group *group)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
			  "Cleaning up group entry. \n");
  struct NodeList* nl;
  while(NULL != (nl = grp->nl_head))
  {
	GNUNET_CONTAINER_DLL_remove (grp->nl_head,
								 grp->nl_tail,
								 nl);
	GNUNET_free(nl->node);
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
  GNUNET_free (group);
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
  GNUNET_free (node->peer);
  GNUNET_free (node);
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
  GNUNET_CADET_channel_destroy(channel);
  GNUNET_free (channel);
}

/**
 * Free memory occupied by an entry in the client map.
 *
 * @param cls unused
 * @param key unused
 * @param value a `struct  GNUNET_SCRB_Group*`
 * @return #GNUNET_OK (continue to iterate)
 */
static int
cleanup_client (void *cls,
				const struct GNUNET_HashCode *key,
				void *value)
{
  struct Client *client = value;
  free_client_entry (client);
  return GNUNET_OK;
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
  if (NULL == nc)
	return;

  GNUNET_SERVER_notification_context_destroy (nc);
  nc = NULL;

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
 * Helper methods
 */
static int
group_children_add(struct Group* grp, struct NodeHandle*  node)
{
  struct NodeList* nl = GNUNET_new(sizeof(*nl));
  nl->node = node;
  GNUNET_CONTAINER_DLL_insert (grp->nl_head, grp->nl_tail, nl);
  return 1;
}

static void
group_children_clear(struct Group* grp)
{
  struct NodeList* nl;
  while(NULL != (nl = grp->nl_head))
  {
	GNUNET_CONTAINER_DLL_remove (grp->nl_head,
								 grp->nl_tail,
								 nl);
	GNUNET_free(nl->node->chn);
	GNUNET_free(nl->node);
	GNUNET_free (nl);
  }
}

static int
group_children_contain(struct Group* grp, const struct GNUNET_PeerIdentity* child)
{
  struct NodeList* nl = grp->nl_head;
  while(NULL != nl)
  {
	if(0 == memcmp(nl->node->peer, child, sizeof(*child)))
	  return 1;
	nl = nl->next;
  }
  return 0;
}

static struct NodeHandle*
group_children_get(struct Group* grp, struct GNUNET_PeerIdentity* child)
{
  struct NodeList* nl = grp->nl_head;
  struct NodeHandle* node = NULL;
  while(NULL != nl)
  {
	if(0 == memcmp(nl->node->peer, child, sizeof(*child)))
	{
	  node = nl->node;
	  break;
	}
	nl = nl->next;
  }
  return node;
}

static struct NodeHandle*
group_children_remove(struct Group* grp, struct GNUNET_PeerIdentity* child)
{
  struct NodeList* nl = grp->nl_head;
  struct NodeHandle* node = NULL;
  while(NULL != nl)
  {
	if(0 == memcmp(nl->node->peer, child, sizeof(*child)))
	{
	  GNUNET_CONTAINER_DLL_remove (grp->nl_head, grp->nl_tail, nl);
	  node = nl->node;
	  GNUNET_free (nl);
	  break;
	}
	nl = nl->next;
  }
  return node;
}

static int 
group_children_size(struct NodeList* nl)
{
  if(NULL == nl)
	return 0;
  else
	return 1 + group_children_size(nl->next);
}

static int 
group_children_is_empty(struct Group* grp)
{
  return grp->nl_head == NULL;
}

static void
group_children_clear(struct Group* grp)
{
  struct NodeList* nl;
  while(NULL != (nl = grp->nl_head))
  {
	GNUNET_CONTAINER_DLL_remove (grp->nl_head,
								 grp->nl_tail,
								 nl);
	GNUNET_free(nl);
  }
}


static void
client_notify_disconnect(void* cls,
						 struct GNUNET_SERVER_Client* client)
{
  if(NULL == client)
	return;
  struct Client*
	sclient = GNUNET_SEVER_client_get_user_context (client, struct Client);
	  
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
}

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
	struct NodeList* nl;
	nl = grp->nl_head;
	while(NULL != nl)
	{
	  if(chn == nl->node->chn)
	  {
		GNUNET_free(nl->node);
		GNUNET_free(nl);
		break;
	  }else
		nl = nl->next;
	}
		
	if(chn == parent->chn)
	  GNUNET_free(parent);
	else if(chn == root->chn)
	  GNUNET_free(root);
  }
  GNUNET_free(chn);
}


/**
 * Sending a message to all children using cadet
 */
static void
group_children_send_message(const struct Group* grp,
							const struct GNUNET_MessageHeader* msg)
{
  GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
			  "%p Sending message to children. \n", grp);
	
  struct NodeList *nl = grp->nl_head;
  while(NULL != nl)
  {
	cadet_send_msg(nl->node->chn, msg->header.header);
	nl = nl->next;
  }
}


/**
 * Helper to add children to a group with the provided @a grp_pub_key
 * @return grp or NULL on failure
 */
static struct Group*
group_child_add_helper(const struct GNUNET_SCRB_Policy* policy,
					   const struct GNUNET_CRYPTO_PublicKey* grp_pub_key,
					   const struct GNUNET_HashCode* grp_pub_key_hash, 
					   struct NodeHandle* child)
{
  struct Group* ret = NULL;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
			  "add child %s to group %s.\n",
			  GNUNET_h2s (grp_pub_key_hash),
			  GNUNET_h2s (child->peer_hash));
  struct Group*
	grp = GNUNET_CONTAINER_multihashmap_get (groups, &join_block->gr_pub_key_hash);
	
  if(NULL == grp)
  {
	grp = GNUNET_new(struct Group);
	grp->pub_key = group_key;
	grp->pub_key_hash = group_key_hash;
	grp->is_acked = 0;
	GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
				"implicitly subscribing to group %s.\n",
				GNUNET_h2s (grp_key_hash));
  }
	
  ret = grp;
	
  group_children_add(grp, child);
	
  if(NULL != policy->child_added_cb)
	policy->child_added_cb(policy, child);
	
  return ret;
}

struct NodeHandle*
dstrm_msg_get_next(struct GNUNET_SCRB_DownStreamMessage* msg)
{
  struct GNUNET_CRYPTO_EddsaPublicKey group_key;
  struct GNUNET_HashCode group_key_hash;
  memcpy(&group_key, sizeof(group_key), &sm->group_key);
  GNUNET_CRYPTO_Hash (&group_key, sizeof(group_key), &group_key_hash);
  struct Group* grp =
	client = GNUNET_CONTAINER_multihashmap_get (groups, &pub_key_hash);
  if(NULL == grp)
	return NULL;
  struct GNUNET_PeerIdentity* path = NULL;
  unsigned int path_length = 0;
  if(NULL != route_map->map_get_path_cb)
	route_map->map_get_path_cb(route_map,
							   grp->pub_key_hash,
							   msg->dst, msg->src, path, &path_length);
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
  child = group_children_get(grp, next);
  return child;
}

static void
group_children_add_to_anycast(struct Group* grp,
							  struct GNUNET_SCRB_AnycastMessage* msg,
							  struct GNUNET_SCRB_Policy* policy)
{
  size_t size = 0;
  struct NodeList* nl = grp->nl_head;
  while(NULL != nl)
  {
	if(1 == nl->node->is_acked)
	  size++;
	nl = nl->next;
  }
  struct GNUNET_PeerIdentity** children = GNUNET_malloc(size * sizeof(struct GNUNET_PeerIdentity*));
  nl = grp->nl_head;
  //gathering group children
  while(NULL != nl)
  {
	if(1 == nl->node->is_acked)
	  *children++ = nl->node->peer;
	nl = nl->next;
  }
  if(NULL != policy->direct_anycst_cb)
	policy->direct_anycst_cb(msg, grp->parent->peer, children, size, NULL);
}

struct PutJoin*
create_put_join(enum GNUNET_DHT_RouteOption options,
				const void* data,
				const struct GNUNET_PeerIdentity* path,
				unsigned int path_length)
{
  struct PutJoin* pj = GNUNET_malloc(pj);
  pj->options = options;
  pj->data = GNUNET_malloc(sizeof(*data));
  memcpy(&pj->data, data, sizeof(*data));
  pj->path->path = GNUNET_malloc(path_length * sizeof(*path));
  memcpy(pj->path->path, path, path_length * sizeof(*path));
  pj->path->path_length = path_length;
  return pj;
}

struct NodeHandle*
create_node_handle(const struct GNUNET_PeerIdentity* peer)
{
  struct GNUNET_HashCode* p_hash = GNUNET_malloc(sizeof(*p_hash));
  GNUNET_CRYPTO_Hash (peer, sizeof(*peer), p_hash);
	
  //create a handle for the node
  struct NodeHandle* node = GNUNET_new (struct NodeHandle);
  node->peer = GNUNET_new (struct GNUNET_PeerIdentity);
  node->peer_hash = p_hash;
  memcpy(node->peer, peer, sizeof(*peer));
  node->ch = cadet_channel_create(grp, node->peer);
  return node;
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
 * The main function for the ext service.
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
