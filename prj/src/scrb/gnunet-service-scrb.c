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
#include "scrb_group.h"
#include "scrb_publisher.h"
#include "scrb_subscriber.h"

/**
 * A CADET handle
 */
static struct GNUNET_CADET_Handle *cadet;

/**
 * Scribe policy
 */
static struct GNUNET_SCRB_Policy *policy;

#define CHUNK 1024
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
static struct GNUNET_SERVER_Handle *srv;

/**
 * Our notification context.
 */
static struct GNUNET_SERVER_NotificationContext *nc;

/**
 * How many buckets will we allow total.
 */
#define MAX_BUCKETS sizeof (struct GNUNET_HashCode) * 8

#define NUM_MSG 10

unsigned int num_received;

int result;


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

/**
 * How often do we run the PUTs?
 */
#define PUT_FREQUENCY GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 10)


static struct GNUNET_DHT_MonitorHandle *monitor_handle;
/*****************************************methods*******************************************/
/*************************************monitor handlers**************************************/
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

/*******************************************************************************************/

size_t
service_confirm_creation
(struct GNUNET_SCRB_Group *group);

void send_subscribe_confirmation(struct GNUNET_SCRB_ServiceSubscriber* sub,
		struct GNUNET_CONTAINER_MultiHashMap* clients);

void forward_join(
		const struct GNUNET_HashCode* key,
		const void* data,
		const struct GNUNET_PeerIdentity* path,
		unsigned int path_length,
		struct GNUNET_STATISTICS_Handle* scrb_stats,
		struct GNUNET_CONTAINER_MultiHashMap* groups);

void deliver_join(
		const struct GNUNET_PeerIdentity* path,
		unsigned int path_length,
		const struct GNUNET_PeerIdentity* my_identity,
		const struct GNUNET_HashCode* key,
		const void* data,
		struct GNUNET_STATISTICS_Handle* scrb_stats,
		struct GNUNET_CONTAINER_MultiHashMap* groups);
/****************************************************************************************/
static unsigned int id_counter = 0;

static struct GNUNET_CONTAINER_MultiHashMap *clients;

struct NodeHandle
{
	struct GNUNET_PeerIdentity* peer;
	struct CNUNET_HashCode* peer_hash;
	struct Channel* chn;
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
	
	uint8_t is_root;
	
	uint8_t disconnected;
};

/**
 ******************************************************
 *                 Helper methods                     *
 ******************************************************
 */

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
						struct GNUNET_PeerIdentity* child);

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
 * Check if the @a policy allows to take on the @a child
 * @param policy        Scribe policy
 * @param child         Identity of the child
 * @param grp_key_hash  Hash code of the group public key
 * @param content       The content of the message to be checked
 * @return 1 if the child is allowed to be added, 0 otherwise
 */
static int
check_policy(struct GNUNET_SCRB_Policy* policy,
			 struct GNUNET_SCRB_PeerIdentity* child,
			 struct GNUNET_HashCode* grp_key_hash,
			 struct GNUNET_SCRB_Content* content);

/**
 * Notifies @a policy that @a child is added
 * @param policy  Scribe policy
 * @param child   Child
 *
 */
static void
policy_child_added(struct GNUNET_SCRB_Policy* policy, 
				   struct NodeHandle* child);

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
static int
group_child_add_helper(const struct GNUNET_CRYPTO_PublicKey* grp_key,
	const struct GNUNET_HashCode* grp_key_hash,
	struct NodeHandle* child);

struct Client
{
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
	 *
	 * Only set for outgoing channels
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
	struct GNUNET_PeerIdentity peer;
	
	/**
	 * Channel direction
	 * @see enum ChannelDirection
	 */
	uint8_t direction;
};

static struct GNUNET_CONTAINER_MultiHashMap *groups;

static struct GNUNET_CONTAINER_MultiHashMap *publishers;

static struct GNUNET_CONTAINER_MultiHashMap *subscribers;

static struct GNUNET_CONTAINER_MultiHashMap *parents;

struct GNUNET_MQ_Handle* mq;

/****************************************************************************************/
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
	if (0 != (options & GNUNET_DHT_RO_LAST_HOP))
		deliver(cls, type, path_length, path, key, data, size);
	else
		forward(cls, type, path_length, path, key, data, size);
}

size_t
service_confirm_leave
(struct GNUNET_SCRB_GroupSubscriber *group_subscriber)
{
	struct GNUNET_SCRB_ServiceReplyLeave* my_msg;
	size_t msg_size = sizeof(struct GNUNET_SCRB_ServiceReplyLeave);

	struct GNUNET_MQ_Envelope* ev = GNUNET_MQ_msg(my_msg, GNUNET_MESSAGE_TYPE_SCRB_LEAVE_REPLY);

	my_msg->header.size = htons((uint16_t) msg_size);
	my_msg->header.type = htons(GNUNET_MESSAGE_TYPE_SCRB_LEAVE_REPLY);
	my_msg->cid = group_subscriber->cid;
	my_msg->group_id = group_subscriber->group_id;

	GNUNET_MQ_send (group_subscriber->mq_o, ev);
	return GNUNET_OK;
}

size_t
service_send_parent
(struct GNUNET_SCRB_GroupSubscriber *group_subscriber)
{
	struct GNUNET_SCRB_SendParent2Child* my_msg;
	size_t msg_size = sizeof(struct GNUNET_SCRB_SendParent2Child);

	struct GNUNET_MQ_Envelope* ev = GNUNET_MQ_msg(my_msg, GNUNET_MESSAGE_TYPE_SCRB_SUBSCRIBE_SEND_PARENT);

	my_msg->header.size = htons((uint16_t) msg_size);
	my_msg->header.type = htons(GNUNET_MESSAGE_TYPE_SCRB_SUBSCRIBE_SEND_PARENT);
	my_msg->parent = my_identity;
	my_msg->group_id = group_subscriber->group_id;
	my_msg->cid = group_subscriber->cid;

	GNUNET_MQ_send (group_subscriber->mq_l, ev);
	return GNUNET_OK;
}

size_t
service_send_leave_to_parent
(struct GNUNET_SCRB_GroupParent* parent)
{

	struct GNUNET_SCRB_SendLeaveToParent* my_msg;
	size_t msg_size = sizeof(struct GNUNET_SCRB_SendLeaveToParent);

	struct GNUNET_MQ_Envelope* ev = GNUNET_MQ_msg(my_msg, GNUNET_MESSAGE_TYPE_SCRB_SEND_LEAVE_TO_PARENT);

	my_msg->header.size = htons((uint16_t) msg_size);
	my_msg->header.type = htons(GNUNET_MESSAGE_TYPE_SCRB_SEND_LEAVE_TO_PARENT);
	my_msg->group_id = parent->group_id;
	my_msg->sid = my_identity_hash;

	GNUNET_MQ_send (parent->mq, ev);
	return GNUNET_OK;
}

size_t
service_send_multicast_to_parent
(const struct GNUNET_SCRB_GroupParent* parent, const struct GNUNET_SCRB_UpdateSubscriber* cl_msg)
{
	struct GNUNET_SCRB_UpdateSubscriber* my_msg;
	size_t msg_size = sizeof(struct GNUNET_SCRB_UpdateSubscriber);

	struct GNUNET_MQ_Envelope* ev = GNUNET_MQ_msg(my_msg, GNUNET_MESSAGE_TYPE_SCRB_MULTICAST);

	my_msg->header.size = htons((uint16_t) msg_size);
	my_msg->header.type = htons(GNUNET_MESSAGE_TYPE_SCRB_MULTICAST);
	my_msg->group_id = cl_msg->group_id;
	my_msg->data = cl_msg->data;
	my_msg->last = cl_msg->last;

	GNUNET_MQ_send (parent->mq, ev);
	return GNUNET_OK;
}


/**
 * Sends confirmation to service which requests subscription
 */
size_t
service_confirm_creation
(struct GNUNET_SCRB_Group *group)
{
	struct GNUNET_SCRB_ServiceReplyCreate* my_msg;
	size_t msg_size = sizeof(struct GNUNET_SCRB_ServiceReplyCreate);

	struct GNUNET_MQ_Envelope* ev = GNUNET_MQ_msg(my_msg, GNUNET_MESSAGE_TYPE_SCRB_CREATE_REPLY);

	my_msg->header.size = htons((uint16_t) msg_size);
	my_msg->header.type = htons(GNUNET_MESSAGE_TYPE_SCRB_CREATE_REPLY);
	my_msg->rp = my_identity;
	my_msg->cid = group->group_id;
	my_msg->status = GNUNET_OK;

	GNUNET_MQ_send (group->mq, ev);
	return GNUNET_OK;
}

size_t
service_confirm_subscription
(struct GNUNET_SCRB_GroupSubscriber *grp_sbscrbr)
{
	struct GNUNET_SCRB_ServiceReplySubscribe* my_msg;
	size_t msg_size = sizeof(struct GNUNET_SCRB_ServiceReplySubscribe);

	struct GNUNET_MQ_Envelope* ev = GNUNET_MQ_msg(my_msg, GNUNET_MESSAGE_TYPE_SCRB_SUBSCRIBE_REPLY);

	my_msg->header.size = htons((uint16_t) msg_size);
	my_msg->header.type = htons(GNUNET_MESSAGE_TYPE_SCRB_SUBSCRIBE_REPLY);
	my_msg->group_id = grp_sbscrbr->group_id;
	my_msg->cid = grp_sbscrbr->cid;
	my_msg->status = GNUNET_OK;

	if(0==memcmp(&grp_sbscrbr->sid, &grp_sbscrbr->oid , sizeof(struct GNUNET_PeerIdentity)))
		GNUNET_MQ_send (grp_sbscrbr->mq_l, ev);
	else
		GNUNET_MQ_send (grp_sbscrbr->mq_o, ev);
	return GNUNET_OK;
}
/**
 * Code for the group creation
 */
struct GNUNET_SCRB_Group* createGroup(
		const struct GNUNET_HashCode *key,
		const void* data,
		struct GNUNET_CONTAINER_MultiHashMap* groups) {
	struct GNUNET_SCRB_Group* group;
	group = GNUNET_new(struct GNUNET_SCRB_Group);
	struct GNUNET_BLOCK_SCRB_Create* create_block;
	create_block = (struct GNUNET_BLOCK_SCRB_Create*) data;
	group->group_id = *key;
	group->sid = create_block->sid;
	group->mq = GNUNET_CORE_mq_create (core_api, &create_block->sid);
	GNUNET_CONTAINER_multihashmap_put(groups, &group->group_id, group,
			GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY);
	return group;
}

struct GNUNET_SCRB_GroupSubscriber* createGroupSubscriber(
		const struct GNUNET_HashCode* key,
		const void* data,
		const struct GNUNET_PeerIdentity src,
		struct GNUNET_CONTAINER_MultiHashMap* groups) {
	struct GNUNET_SCRB_GroupSubscriber* group_subscriber;
	group_subscriber = GNUNET_new(struct GNUNET_SCRB_GroupSubscriber);
	struct GNUNET_BLOCK_SCRB_Join* join_block;
	join_block = (struct GNUNET_BLOCK_SCRB_Join*) data;
	group_subscriber->cid = join_block->cid;
	//here we add id of the origin
	group_subscriber->oid = join_block->sid;
	//here we add the last on the path
	group_subscriber->sid = src;
	group_subscriber->group_id = *key;
	//create a message queue for the last in the path
	group_subscriber->mq_l = GNUNET_CORE_mq_create (core_api, &group_subscriber->sid);
	//create a message queue for the originator
	group_subscriber->mq_o = GNUNET_CORE_mq_create (core_api, &group_subscriber->oid);
	GNUNET_CRYPTO_hash (&group_subscriber->sid,
			sizeof (struct GNUNET_PeerIdentity),
			&group_subscriber->sidh);
	struct GNUNET_SCRB_Group* group = GNUNET_CONTAINER_multihashmap_get(groups,
			key);
	GNUNET_CONTAINER_DLL_insert(group->group_head, group->group_tail,
			group_subscriber);
	return group_subscriber;
}

void leaveGroup(const struct GNUNET_HashCode* key, struct GNUNET_HashCode* sid,
		struct GNUNET_CONTAINER_MultiHashMap* groups,
		struct GNUNET_CONTAINER_MultiHashMap* parents) {
	struct GNUNET_SCRB_Group* group = GNUNET_CONTAINER_multihashmap_get(groups,
			key);
	struct GNUNET_SCRB_GroupSubscriber* gs = group->group_head;
	while (NULL != gs) {
		if (0 == memcmp(&sid, &gs->sid, sizeof(struct GNUNET_HashCode))) {
			GNUNET_CONTAINER_DLL_remove(group->group_head, group->group_tail,
					gs);
			service_confirm_leave(gs);
			GNUNET_free(gs);
		}
		gs = gs->next;
	}
	if (NULL == group->group_head)
	{
		struct GNUNET_SCRB_GroupParent* parent =
				GNUNET_CONTAINER_multihashmap_get(parents, key);
		if(NULL != parent)
		{
			service_send_leave_to_parent(parent);
		}
		GNUNET_free(group);
	}
}

void update_stats(
		const char* msg,
		const struct GNUNET_PeerIdentity* src,
		const struct GNUNET_PeerIdentity* my_identity,
		const struct GNUNET_HashCode* group_id	,
		struct GNUNET_STATISTICS_Handle* scrb_stats) {
	char str[100];
	strcpy(str, msg);
	strcat(str, GNUNET_i2s(src));
	strcat(str, " to: ");
	strcat(str, GNUNET_i2s(&*my_identity));
	strcat(str, " for the group id: ");
	strcat(str, GNUNET_h2s(group_id));
	GNUNET_STATISTICS_update(scrb_stats, gettext_noop(str), 1, GNUNET_NO);
}

void receive_multicast(const struct GNUNET_HashCode* key,
		const struct GNUNET_PeerIdentity* my_identity,
		const struct GNUNET_PeerIdentity* stop_peer,
		const struct GNUNET_CONTAINER_MultiHashMap* groups,
		const struct GNUNET_BLOCK_SCRB_Multicast* multicast_block,
		const struct GNUNET_CONTAINER_MultiHashMap* subscribers,
		const struct GNUNET_CONTAINER_MultiHashMap* clients) {
	struct GNUNET_SCRB_Group* group = GNUNET_CONTAINER_multihashmap_get(groups,
			key);
	if (NULL != group) {
		struct GNUNET_SCRB_GroupSubscriber* gs = group->group_head;
		while (NULL != gs) {
			if ((0	!= memcmp(&gs->sid, &my_identity,	sizeof(struct GNUNET_PeerIdentity))) &&
					(stop_peer == NULL || (0 != memcmp(&gs->sid, stop_peer,	sizeof(struct GNUNET_PeerIdentity))))) {
				const char* msgu = "# receive MC: message is sent from: ";
				update_stats(msgu, my_identity, &gs->sid, key, scrb_stats);

				struct GNUNET_SCRB_UpdateSubscriber *msg;
				size_t msg_size = sizeof(struct GNUNET_SCRB_UpdateSubscriber);
				struct GNUNET_MQ_Envelope* ev = GNUNET_MQ_msg(msg, 	GNUNET_MESSAGE_TYPE_SCRB_MULTICAST);

				msg->header.size = htons((uint16_t) msg_size);
				msg->header.type = htons(GNUNET_MESSAGE_TYPE_SCRB_MULTICAST);
				msg->data = multicast_block->data;
				msg->group_id = multicast_block->group_id;
				msg->last = multicast_block->last;

				GNUNET_MQ_send(gs->mq_l, ev);
			}
			gs = gs->next;
		}
	}
	struct GNUNET_SCRB_ServiceSubscription* subs =
			GNUNET_CONTAINER_multihashmap_get(subscribers, key);
	if (NULL != subs) {
		struct GNUNET_SCRB_ServiceSubscriber* sub = subs->sub_head;
		while (NULL != sub) {
			struct GNUNET_SCRB_UpdateSubscriber *msg;
			size_t msg_size = sizeof(struct GNUNET_SCRB_UpdateSubscriber);
			struct GNUNET_MQ_Envelope* ev = GNUNET_MQ_msg(msg,
					GNUNET_MESSAGE_TYPE_SCRB_MULTICAST);

			msg->header.size = htons((uint16_t) msg_size);
			msg->header.type = htons(GNUNET_MESSAGE_TYPE_SCRB_MULTICAST);
			msg->data = multicast_block->data;
			msg->group_id = multicast_block->group_id;
			msg->last = multicast_block->last;

			struct ClientEntry* ce = GNUNET_CONTAINER_multihashmap_get(clients,
					&sub->cid);
			if(NULL != ce)
				GNUNET_MQ_send(ce->mq, ev);

			sub = sub->next;
		}
	}
}

void deliver_join(const struct GNUNET_PeerIdentity* path,
				  unsigned int path_length,
				  const struct GNUNET_PeerIdentity* my_identity,
				  const struct GNUNET_HashCode* key,
				  const void* data,
				  struct GNUNET_STATISTICS_Handle* scrb_stats,
				  struct GNUNET_CONTAINER_MultiHashMap* groups) 
{
	//FIXME: check if our policy allows to take on the node
	//if it does not, send SubscribeFail message to the source

	//here we do the same operation as with forward
	struct GNUNET_BLOCK_SCRB_Join*
		join_block = (struct GNUNET_BLOCK_SCRB_Join*) data;
	GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
				"Deliver is called subsribing client %s for group %s.\n",
				GNUNET_h2s (&join_block->cl_pub_key_hash),
				GNUNET_h2s (&join_block->gr_pub_key_hash));
	//first check for necessary data structures
	struct Group*
		grp = GNUNET_CONTAINER_multihashmap_get (groups, &pub_key_hash);
	if(NULL == grp)
	{
		grp = GNUNET_new(struct Group);
		grp->pub_key = group_key;
		grp->pub_key_hash = group_key_hash;
	}
	//take the last peer on the path
	struct GNUNET_PeerIdentity* lp = &path[path_length - 1];
	//check if the previous peer is already in the
	//children list
	char hv_chld = 0;
	struct NodeList* nl = grp->pnl_head;
	while (NULL != nl)
	{
		if(0 == memcmp(nl->node->peer, lp , sizeof(struct GNUNET_PeerIdentity)))
		{
			hv_chld = 1;
			break;
		};
		nl = nl->next;
	}
	
	if(0 == hv_chld)
	{
		//create CADET channel to the previous peer on the path and
		//send parent notification to the previous peer
		cadet_send_parent (grp, &path[path_length - 1]);
	}	
}

void
deliver (void *cls,
		enum GNUNET_BLOCK_Type type,
		unsigned int path_length,
		const struct GNUNET_PeerIdentity *path,
		const struct GNUNET_HashCode *key,
		const void *data,
		size_t size)
{
	switch (type) {
	case GNUNET_BLOCK_SCRB_TYPE_CREATE:
	{
		const char* msg = "# deliver: CREATE messages received from: ";
		update_stats(msg, &path[0], &my_identity, key, scrb_stats);
		GNUNET_STATISTICS_update (scrb_stats,
				gettext_noop ("# deliver: overall CREATE messages received"),
				1, GNUNET_NO);
		struct GNUNET_SCRB_Group* group = createGroup(key, data, groups);
		service_confirm_creation(group);
		break;
	}
	case GNUNET_BLOCK_SCRB_TYPE_JOIN:
	{
		forward_join(key, data, path, path_length, scrb_stats, groups);
		//		deliver_join(path, path_length, &my_identity, key, data, scrb_stats,
		//				groups);
		break;
	}
	case GNUNET_BLOCK_SCRB_TYPE_MULTICAST:
	{
		const char* msg = "# deliver: MULTICAST messages received from: ";
		update_stats(msg, &path[path_length - 1], &my_identity, key, scrb_stats);
		GNUNET_STATISTICS_update (scrb_stats,
				gettext_noop ("# deliver: overall MULTICAST messages received"),
				1, GNUNET_NO);
		struct GNUNET_BLOCK_SCRB_Multicast* multicast_block;
		multicast_block = (struct GNUNET_BLOCK_SCRB_Multicast*) data;
		receive_multicast(key, &my_identity, NULL, groups, multicast_block, subscribers, clients);
		break;
	}
	case GNUNET_BLOCK_SCRB_TYPE_LEAVE:
	{
		struct GNUNET_BLOCK_SCRB_Leave* leave_block;
		leave_block = (struct GNUNET_BLOCK_SCRB_Leave*) data;
		struct GNUNET_HashCode sid = leave_block->sid;
		leaveGroup(key, &sid, groups, parents);
		const char* msg = "# deliver: LEAVE messages received from: ";
		update_stats(msg, &path[path_length - 1], &my_identity, key, scrb_stats);
		GNUNET_STATISTICS_update (scrb_stats,
				gettext_noop ("# deliver: overall LEAVE messages received"),
				1, GNUNET_NO);
		break;
	}
	default:
		break;
	}
}

void forward_join(const struct GNUNET_HashCode* key,
				  const void* data,
				  const struct GNUNET_PeerIdentity* path,
				  unsigned int path_length,
				  struct GNUNET_STATISTICS_Handle* scrb_stats,
				  struct GNUNET_CONTAINER_MultiHashMap* groups) 
{
	struct GNUNET_BLOCK_SCRB_Join*
		join_block = (struct GNUNET_BLOCK_SCRB_Join*) data;
	//FIXME: do all the necessary security checks

	//1. check if this is our subscribe message then ignore it
	if(0 == memcmp(&join_block->src, &my_identity, sizeof(struct GNUNET_HashCode)))
	{
		GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
				"Bypassing forward logic of subscribe message for group %s because local node is the subscriber's source.\n",
				GNUNET_h2s (&join_bloch->gr_pub_key_hash));
		return;
	}
	GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
				"Handle forward subscribe message for group %s.\n",
				GNUNET_h2s (&join_bloch->gr_pub_key_hash));
	
    //take the last peer on the path
	struct GNUNET_PeerIdentity* lp = &path[path_length - 1];
	struct GNUNET_HashCode* lp_hash = GNUNET_malloc(sizeof(*lp_hash));
	//hash of the  last peer
	GNUNET_CRYPTO_Hash (lp, sizeof(*lp), lp_hash);

	//create a handle for the node
	struct NodeHandle* node = GNUNET_new (struct NodeHandle);
	node->peer = GNUNET_new (struct GNUNET_PeerIdentity);
	node->peer_hash = lp_hash;
	memcpy(node->peer, lp, sizeof(*lp));
	node->ch = cadet_channel_create(grp, node->peer);
	
	//content of the message
	struct GNUNET_SCRB_Content *content = &join_block->content;
	
    //source
	struct GNUNET_PeerIdentity* source = &join_block->src;
	
	struct Group*
		grp = GNUNET_CONTAINER_multihashmap_get (groups, &join_block->gr_pub_key_hash);
	
	if(NULL != grp)
	{
		//2. check if the source node is already on the path
		//so we do not create loops
		struct GNUNET_SCRB_RoutePath path_to_root = grp->path_to_root;
		if(1 == check_path_contains(path_to_root->path, path_to_root->path_length, lp))
		{
			GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
						"Rejecting subsribe message for group %s, the node %s is already on the path.\n",
						GNUNET_h2s (grp->pub_key_hash),
						GNUNET_h2s (lp_hash));
			return;
		}
		
		//3. Check if we already have the child
		if(1 == group_children_contain(grp, lp)
		{
			GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
						"The node %s is already in group %s.\n",
						GNUNET_h2s (lp_hash),
						GNUNET_h2s (grp->pub_key_hash));
			return;
		}
	}
	
	//4. check if our policy allows to take on the node
	// as the source provide the last on the path
	if(NULL != policy->allow_subs_cb && 1 == policy->allow_subs_cb(policy, lp, grp->pub_key, content))
	{
		GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
				   "Hijacking subscribe message from %s to group %s.\n",
				    GNUNET_h2s (lp_hash),
					GNUNET_h2s (grp->pub_key_hash));
	
		if(1 == group_child_add_helper(grp->pub_key))
		{
			//send parent, do not send ack since the full
			//path is not created
			cadet_send_parent (grp, lp);		
		}
	
	}else
	{
		size_t size = group_children_size(grp->nl_head);
		struct GNUNET_PeerIdentity** children = GNUNET_malloc(size * sizeof(struct GNUNET_PeerIdentity*));
		struct NodeList* nl = grp->nl_head;
		//gathering group children
		while(NULL != nl)
		{
			*children++ = nl->node->peer;
			nl = nl->next;
		}
		if(NULL != policy->direct_anycst_cb)
			policy->direct_anycst_cb(msg, grp->parent->peer, children, size, NULL);
		struct GNUNET_PeerIdentity* next = NULL;
		if(NULL != policy->get_next_anycst_cb)
			next = policy->get_next_anycst_cb(policy, msg, NULL);
		if(NULL == next)
		{
			GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
						"Anycast fail to group %s.\n",
						GNUNET_h2s (grp->pub_key_hash));
			//send back subscribe fail
			GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
						"Sending subsribe fail message to %s for group %s.\n",
						GNUNET_h2s (lp_hash),
						GNUNET_h2s (grp->pub_key_hash));

			cadet_send_subscribe_fail (node, &join_block->src,
									   path, path_length,
									   0);//we send, no offset
		}else
		{
			GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
						"handle forward subscribe: routing message to peer %s for group %s.\n",
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
			cadet_send_direct_anycast();
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
check_path_contains(struct GNUNET_PeerIdentity* path,
					unsigned int path_length,
					struct GNUNET_PeerIdentity* node)
{
	int i;
	for(i = 0; i < path_length; i++)
		if(0 == memcmp(&path[i], node, sizeof(struct GNUNET_HashCode)))
			return 1;
	return 0;
};

void
forward (void *cls,
		enum GNUNET_BLOCK_Type type,
		unsigned int path_length,
		const struct GNUNET_PeerIdentity *path,
		const struct GNUNET_HashCode *key,
		const void *data,
		size_t size)
{
	switch (type) {
	case GNUNET_BLOCK_SCRB_TYPE_JOIN:
	{
		forward_join(key, data, path, path_length, scrb_stats, groups);
		break;
	}
	case GNUNET_BLOCK_SCRB_TYPE_LEAVE:
	{
		GNUNET_STATISTICS_update (scrb_stats,
				gettext_noop ("# forward: LEAVE messages received"),
				1, GNUNET_NO);
		struct GNUNET_BLOCK_SCRB_Leave* leave_block;
		leave_block = (struct GNUNET_BLOCK_SCRB_Leave*) data;
		struct GNUNET_HashCode sid = leave_block->sid;
		leaveGroup(key, &sid, groups, parents);
		break;
	}
	}
}

/**
 * To be called on core init/fail.
 *
 * @param cls service closure
 * @param identity the public identity of this peer
 */
static void
core_init (void *cls,
		const struct GNUNET_PeerIdentity *identity)
{
	my_identity = *identity;
	GNUNET_CRYPTO_hash (identity,
			sizeof (struct GNUNET_PeerIdentity),
			&my_identity_hash);

	mq = GNUNET_CORE_mq_create (core_api, identity);

}

static void
handle_core_connect (void *cls, const struct GNUNET_PeerIdentity *peer)
{
	printf("handle core connect ... \n");
}

static void
handle_core_disconnect (void *cls, const struct GNUNET_PeerIdentity *peer)
{
	printf("handle core disconnect ... \n");
}

static int
handle_service_confirm_leave (void *cls,
		const struct GNUNET_PeerIdentity *other,
		const struct GNUNET_MessageHeader *message)
{
	struct GNUNET_SCRB_ServiceReplyLeave *hdr;
	hdr = (struct GNUNET_SCRB_ServiceReplyLeave *) message;

	struct GNUNET_HashCode sub_hash;
	GNUNET_CRYPTO_hkdf (&sub_hash, sizeof (struct GNUNET_HashCode),
			GCRY_MD_SHA512, GCRY_MD_SHA256,
			&hdr->cid, sizeof (struct GNUNET_HashCode),
			&hdr->group_id, sizeof (struct GNUNET_HashCode),
			NULL, 0);
	struct GNUNET_SCRB_ServiceSubscriber* sub ;
	sub = GNUNET_CONTAINER_multihashmap_get(subscribers, &sub_hash);
	GNUNET_CONTAINER_multihashmap_remove(subscribers, &sub_hash, sub);
	GNUNET_free(sub);
	return GNUNET_OK;
}

static int
handle_service_confirm_creation (void *cls,
		const struct GNUNET_PeerIdentity *other,
		const struct GNUNET_MessageHeader *message)
{
	struct GNUNET_SCRB_ServiceReplyCreate *hdr;
	hdr = (struct GNUNET_SCRB_ServiceReplyCreate *) message;

	struct ClientEntry *ce;
	ce = GNUNET_CONTAINER_multihashmap_get(clients, &hdr->cid);

	struct GNUNET_SCRB_ServicePublisher* pub = GNUNET_new(struct GNUNET_SCRB_ServicePublisher);

	pub->rp = hdr->rp;
	pub->group_id = *ce->cid;
	GNUNET_CONTAINER_multihashmap_put(publishers,
			&pub->group_id,
			pub,
			GNUNET_CONTAINER_MULTIHASHMAPOPTION_MULTIPLE );

	struct GNUNET_MQ_Envelope* ev = GNUNET_MQ_msg(hdr, GNUNET_MESSAGE_TYPE_SCRB_CREATE_REPLY);

	GNUNET_MQ_send (ce->mq, ev);

	return GNUNET_OK;
}

static int handle_service_confirm_subscription (
		void *cls,
		const struct GNUNET_PeerIdentity *other,
		const struct GNUNET_MessageHeader *message)
{
	struct GNUNET_SCRB_SendParent2Child *hdr;
	hdr = (struct GNUNET_SCRB_SendParent2Child *) message;

	struct GNUNET_SCRB_ServiceSubscription* subs = GNUNET_new (struct GNUNET_SCRB_ServiceSubscription);

	struct GNUNET_SCRB_ServiceSubscriber* sub = GNUNET_new(struct GNUNET_SCRB_ServiceSubscriber);

	subs->group_id = hdr->group_id;
	sub->group_id = hdr->group_id;
	sub->cid = hdr->cid;

	GNUNET_CONTAINER_DLL_insert(subs->sub_head, subs->sub_tail, sub);

	GNUNET_CONTAINER_multihashmap_put(subscribers,
			&subs->group_id,
			subs,
			GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY );

	send_subscribe_confirmation(sub, clients);

	return GNUNET_OK;
}

static int handle_service_multicast (
		void *cls,
		const struct GNUNET_PeerIdentity *other,
		const struct GNUNET_MessageHeader *message)
{
	struct GNUNET_SCRB_UpdateSubscriber *hdr;
	hdr = (struct GNUNET_SCRB_UpdateSubscriber *) message;

	const char* msg = "# handle: MULTICAST messages received from: ";
	update_stats(msg, other, &my_identity, &hdr->group_id, scrb_stats);
	GNUNET_STATISTICS_update (scrb_stats,
			gettext_noop ("# handle: overall MULTICAST messages received"),
			1, GNUNET_NO);

	struct GNUNET_BLOCK_SCRB_Multicast mb;

	mb.data = hdr->data;
	mb.group_id = hdr->group_id;
	mb.last = hdr->last;

	//	struct GNUNET_SCRB_GroupParent* parent = GNUNET_CONTAINER_multihashmap_get(parents, &hdr->group_id);
	//
	//	service_send_multicast_to_parent(parent, hdr);

	receive_multicast(&hdr->group_id, &my_identity, other, groups, &mb, subscribers, clients);

	return GNUNET_OK;
}


static int
handle_service_send_parent (void *cls,
		const struct GNUNET_PeerIdentity *other,
		const struct GNUNET_MessageHeader *message)
{
	struct GNUNET_SCRB_SendParent2Child *hdr;
	hdr = (struct GNUNET_SCRB_SendParent2Child *) message;

	const char* msg = "# service: SEND PARENT messages received from: ";
	update_stats(msg, other, &my_identity, &hdr->group_id, scrb_stats);

	struct GNUNET_SCRB_GroupParent* parent = GNUNET_new(struct GNUNET_SCRB_GroupParent);

	parent->group_id = hdr->group_id;

	parent->parent = hdr->parent;

	parent->mq = GNUNET_CORE_mq_create (core_api, &parent->parent);

	GNUNET_CONTAINER_multihashmap_put(parents,
			&parent->group_id,
			parent,
			GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY );

	handle_service_confirm_subscription(cls, other, message);

	return GNUNET_OK;
}

static int
handle_service_send_leave_to_parent (void *cls,
		const struct GNUNET_PeerIdentity *other,
		const struct GNUNET_MessageHeader *message)
{
	struct GNUNET_SCRB_SendLeaveToParent *hdr;
	hdr = (struct GNUNET_SCRB_SendLeaveToParent *) message;

	leaveGroup(&hdr->group_id, &hdr->sid, groups, parents);

	return GNUNET_OK;
}





/**
 * Connect to the core service
 */
int
p2p_init ()
{
	static struct GNUNET_CORE_MessageHandler core_handlers[] = {
			{&handle_service_confirm_creation, GNUNET_MESSAGE_TYPE_SCRB_CREATE_REPLY, 0},
			{&handle_service_confirm_subscription, GNUNET_MESSAGE_TYPE_SCRB_SUBSCRIBE_REPLY, 0},
			{&handle_service_confirm_leave, GNUNET_MESSAGE_TYPE_SCRB_LEAVE_REPLY, 0},
			{&handle_service_send_parent, GNUNET_MESSAGE_TYPE_SCRB_SUBSCRIBE_SEND_PARENT, 0},
			{&handle_service_send_leave_to_parent, GNUNET_MESSAGE_TYPE_SCRB_SEND_LEAVE_TO_PARENT, 0},
			{&handle_service_multicast, GNUNET_MESSAGE_TYPE_SCRB_MULTICAST, 0},
			{NULL, 0, 0}
	};

	core_api =
			GNUNET_CORE_connect (cfg,
					NULL,
					&core_init,
					&handle_core_connect,
					&handle_core_disconnect,
					NULL,
					GNUNET_NO,
					NULL,
					GNUNET_NO,
					core_handlers);
	if (core_api == NULL)
		return GNUNET_SYSERR;

	return GNUNET_OK;
}

static void
handle_cl_multicast_request (void *cls,
		struct GNUNET_SERVER_Client *client,
		const struct GNUNET_MessageHeader *message)
{

	struct ClientEntry* ce;
	if((ce = make_client_entry (client)) == NULL)
		return;

	struct GNUNET_SCRB_UpdateSubscriber *hdr;
	hdr = (struct GNUNET_SCRB_UpdateSubscriber *) message;

	struct GNUNET_BLOCK_SCRB_Multicast multicast_block;

	memcpy(&multicast_block.data, &hdr->data, sizeof(struct GNUNET_SCRB_MulticastData));
	multicast_block.group_id = ce->cid;
	multicast_block.last = hdr->last;

	//	struct GNUNET_SCRB_GroupParent* parent = GNUNET_CONTAINER_multihashmap_get(parents, &hdr->group_id);
	//
	//	service_send_multicast_to_parent(parent, hdr);
	//
	//	receive_multicast(&hdr->group_id, &my_identity_hash, NULL, groups, &multicast_block, subscribers, clients);

	put_dht_handle = GNUNET_DHT_put (dht_handle, &hdr->group_id, 1,
			GNUNET_DHT_RO_RECORD_ROUTE |
			GNUNET_DHT_RO_DEMULTIPLEX_EVERYWHERE | GNUNET_DHT_RO_LAST_HOP,
			GNUNET_BLOCK_SCRB_TYPE_MULTICAST,
			sizeof (multicast_block), &multicast_block,
			GNUNET_TIME_UNIT_FOREVER_ABS,
			GNUNET_TIME_UNIT_FOREVER_REL,
			NULL, NULL);

	if(NULL == put_dht_handle)
		GNUNET_break(0);

	GNUNET_SERVER_receive_done (client, GNUNET_OK);

}

void send_subscribe_confirmation(struct GNUNET_SCRB_ServiceSubscriber* sub,
		struct GNUNET_CONTAINER_MultiHashMap* clients) {
	struct GNUNET_SCRB_ServiceReplySubscribe *msg;
	struct GNUNET_MQ_Envelope* ev = GNUNET_MQ_msg(msg, GNUNET_MESSAGE_TYPE_SCRB_SUBSCRIBE_REPLY);
	size_t msg_size = sizeof(struct GNUNET_SCRB_ServiceReplySubscribe);
	msg->header.size = htons((uint16_t) msg_size);
	msg->header.type = htons(GNUNET_MESSAGE_TYPE_SCRB_SUBSCRIBE_REPLY);
	msg->cid = sub->cid;
	msg->group_id = sub->group_id;
	struct ClientEntry* ce = GNUNET_CONTAINER_multihashmap_get(clients,
			&sub->cid);
	if(NULL != ce)
		GNUNET_MQ_send(ce->mq, ev);
}

static void
handle_cl_subscribe_request (void *cls,
		struct GNUNET_SERVER_Client *client,
		const struct GNUNET_MessageHeader *message)
{
	struct ClientEntry* ce;
	if((ce = make_client_entry (client)) == NULL)
		return;

	struct GNUNET_SCRB_ServiceSubscription* subs;
	subs = 	GNUNET_CONTAINER_multihashmap_get(subscribers, &ce->cid);

	if(subs == NULL)
	{
		struct GNUNET_BLOCK_SCRB_Join join_block;

		join_block.cid = hdr->client_id;
		join_block.sid = my_identity;

		/* fixme: do not ignore return handles */

		put_dht_handle = GNUNET_DHT_put (dht_handle, &hdr->group_id, 1,
				GNUNET_DHT_RO_RECORD_ROUTE |
				GNUNET_DHT_RO_DEMULTIPLEX_EVERYWHERE | GNUNET_DHT_RO_LAST_HOP,
				GNUNET_BLOCK_SCRB_TYPE_JOIN,
				sizeof (join_block), &join_block,
				GNUNET_TIME_UNIT_FOREVER_ABS,
				GNUNET_TIME_UNIT_FOREVER_REL,
				NULL, NULL);

		if(NULL == put_dht_handle)
			GNUNET_break(0);
		/* code with get handle
		get_dht_handle = GNUNET_DHT_get_start (dht_handle,
		GNUNET_BLOCK_SCRB_TYPE_CREATE,
		&hdr->group_id,
		1,
		GNUNET_DHT_RO_RECORD_ROUTE |
		GNUNET_DHT_RO_DEMULTIPLEX_EVERYWHERE | GNUNET_DHT_RO_LAST_HOP,
		NULL,
		0,
		&dht_get_join_handler, NULL);
		 */

	}else
	{

		struct GNUNET_SCRB_ServiceSubscriber *sub = GNUNET_new(struct GNUNET_SCRB_ServiceSubscriber);

		sub->group_id = hdr->group_id;
		sub->cid = hdr->client_id;

		GNUNET_CONTAINER_DLL_insert(subs->sub_head, subs->sub_tail, sub);

		send_subscribe_confirmation(sub, clients);
	}
	GNUNET_SERVER_receive_done (client, GNUNET_OK);

}

static void
handle_cl_leave_request (void *cls,
		struct GNUNET_SERVER_Client *client,
		const struct GNUNET_MessageHeader *message)
{
	struct GNUNET_SCRB_ClntRqstLv *hdr;
	hdr = (struct GNUNET_SCRB_ClntRqstLv *) message;

	struct GNUNET_BLOCK_SCRB_Leave leave_block;

	leave_block.sid = my_identity_hash;
	leave_block.group_id = hdr->group_id;

	/* fixme: do not ignore return handles */
	put_dht_handle = GNUNET_DHT_put (dht_handle, &leave_block.group_id, 1,
			GNUNET_DHT_RO_RECORD_ROUTE |
			GNUNET_DHT_RO_DEMULTIPLEX_EVERYWHERE | GNUNET_DHT_RO_LAST_HOP,
			GNUNET_BLOCK_SCRB_TYPE_LEAVE,
			sizeof (struct GNUNET_BLOCK_SCRB_Leave), &leave_block,
			GNUNET_TIME_UNIT_FOREVER_ABS,
			GNUNET_TIME_UNIT_FOREVER_REL,
			NULL, NULL);

	if(NULL == put_dht_handle)
		GNUNET_break(0);

	GNUNET_SERVER_receive_done (client, GNUNET_OK);
}



static int
send_publisher (void *cls,
		const struct GNUNET_HashCode *key,
		void *value)
{
	struct ClientEntry *ce = cls;
	struct GNUNET_SCRB_SrvcRplySrvcLst *msg;
	struct GNUNET_SCRB_ServicePublisher* pub = value;
	size_t msg_size = sizeof(struct GNUNET_SCRB_SrvcRplySrvcLst);

	struct GNUNET_MQ_Envelope* ev = GNUNET_MQ_msg(msg, GNUNET_MESSAGE_TYPE_SCRB_SERVICE_LIST_REPLY);

	msg->header.size = htons((uint16_t) msg_size);
	msg->header.type = htons(GNUNET_MESSAGE_TYPE_SCRB_SERVICE_LIST_REPLY);
	msg->pub = *pub;
	msg->size = GNUNET_CONTAINER_multihashmap_size(publishers);

	GNUNET_MQ_send (ce->mq, ev);
	return GNUNET_OK;
}

static void
handle_cl_srvc_lst_request (void *cls,
		struct GNUNET_SERVER_Client *client,
		const struct GNUNET_MessageHeader *message)
{
	const struct GNUNET_SCRB_ClntRqstSrvcLst* hdr = (struct GNUNET_SCRB_ClntRqstSrvcLst*) message;
	struct ClientEntry *ce = GNUNET_CONTAINER_multihashmap_get(clients, &hdr->cid);
	GNUNET_CONTAINER_multihashmap_iterate(publishers, &send_publisher, ce);

	GNUNET_SERVER_receive_done (client, GNUNET_OK);
}


static void
handle_cl_create_request (void *cls,
		struct GNUNET_SERVER_Client *client,
		const struct GNUNET_MessageHeader *message)
{
	struct ClientEntry* ce;
	if((ce = make_client_entry (client)) == NULL)
		return;
	
	const struct GNUNET_HashCode group_id = ce->cid;

	struct GNUNET_BLOCK_SCRB_Create create_block;

	create_block.cid = group_id;
	create_block.sid = my_identity;

	/* fixme: care for the return handle as we should be able to shutdown
           later on */
	put_dht_handle = GNUNET_DHT_put (dht_handle, &group_id, 1,
			GNUNET_DHT_RO_RECORD_ROUTE |
			GNUNET_DHT_RO_DEMULTIPLEX_EVERYWHERE | GNUNET_DHT_RO_LAST_HOP,
			GNUNET_BLOCK_SCRB_TYPE_CREATE,
			sizeof (create_block), &create_block,
			GNUNET_TIME_UNIT_FOREVER_ABS,
			GNUNET_TIME_UNIT_FOREVER_REL,
			NULL, NULL);

	if(NULL == put_dht_handle)
		GNUNET_break(0);

	GNUNET_SERVER_receive_done (client, GNUNET_OK);
}

/**
 * Sends a subscribe fail message to all the clients subscribed to the group
 *
 * @param grp         The group which clients need to be updated
 */
static void
client_send_subscribe_fail (struct Group* grp)
{	
	struct GNUNET_SCRB_ClientSubscribeFailMessage*
		msg = GNUNET_malloc (sizeof(*msg));

	msg->header.header.type = htons(GNUNET_MESSAGE_TYPE_SCRB_SUBSCRIBE_FAIL);
	msg->header.header.size = htons(sizeof(*msg));
	msg->grp_key = grp->pub_key;
	group_client_send_msg(grp, msg->header.header);
}

/**
 * Sends a subscribe child added message to all the clients subscribed to the group
 *
 * @param grp         The group which clients need to be updated
 * @param peer        Identity of the child
 */
static void
	client_send_child_added (const struct Group* grp, 
							 const struct GNUNET_PeerIdentity* peer)
{	
	struct GNUNET_SCRB_ClientChildChangeEventMessage*
		msg = GNUNET_malloc (sizeof(*msg));

	msg->header.header.type = htons(GNUNET_MESSAGE_TYPE_SCRB_CHILD_ADD);
	msg->header.header.size = htons(sizeof(*msg));
	msg->grp_key = grp->pub_key;
	msg->grp_key = *peer;
	group_client_send_msg(grp, msg->header.header);
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
};

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
};

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
};

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
 * Sends a subscribe fail message for the given node
 * @param node        Node
 * @param src         Source of the subscribe message
 * @param path        Path to the peer where the message is processed
 * @param path_length Length of the path
 */
static void
cadet_send_subscribe_fail (struct NodeHandle* node, struct GNUNET_PeerIdentity* src,
						   struct GNUNET_PeerIdentity* path, unsigned int path_length,
						   unsigned int offset)
{	
	struct GNUNET_SCRB_SubscribeFailMessage*
		msg = GNUNET_malloc (sizeof(*msg));
	msg->header.header.type = htons(GNUNET_MESSAGE_TYPE_SCRB_SUBSCRIBE_FAIL);
	msg->header.header.size = htons(sizeof(*msg));
	memcpy(&msg->source, src, sizeof(*src));
	msg->path_to_failed = GNUNET_new (struct GNUNET_SCRB_RoutePath);
	//save path in the message
	msg->path_to_failed->path = GNUNET_malloc (path_length * sizeof(struct GNUNET_PeerIdentity));
	memcpy(msg->path_to_failed->path, path, path_length * sizeof(*path));
	msg->path_to_failed->path_length = path_length;
	//where we are on the path
	msg->path_to_failed->offset = offset;
	msg->grp_key = node->chn->group_key;
	msg->grp_key_hash = node->chn->group_key_hash;
	cadet_send_msg(node->chn, msg->header.header);
}

static void
	cadet_send_direct_anycast(const struct NodeHandle* handle,
							  const struct GNUNET_SCRB_Policy* policy,
							  struct GNUNET_SCRB_Content* content)
{
	struct GNUNET_SCRB_AnycastMessage*
		msg = GNUNET_malloc (sizeof(*msg));
	msg->header.header.type = htons(GNUNET_MESSAGE_TYPE_SCRB_ANYCAST);
	msg->header.header.size = htons(sizeof(*msg));
	msg->group_key = node->chn->group_key;
	memcpy(&msg->content, content, sizeof(*content));
	cadet_send_msg(node->chn, msg->header.header);
};

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
	if(NULL != *grp)
	{
		GNUNET_break_op(0);
		return GNUNET_SYSERR;
	}
	//create a channel for parent
	struct Channel* chn = GNUNET_malloc(sizeof *chn);
	chn->grp = grp;
	chn->channel = channel;
	chn->group_key = msg->grp_key;
	chn->group_key_hash = msg->grp_key_hash;
	chn->peer = msg->parent;
	chn->direction = DIR_INCOMING;
	GNUNET_CONTAINER_multihashmap_put (channels_in, chn->group_key_hash, chn,
									   GNUNET_CONTAINER_MULTIHASHMAPOPTION_MULTIPLE);
	//save the channel as parent channel in group
	grp->parent = chn;
	return GNUNET_OK;
	
};

/**
 * Incoming subscribe fail message
 */ 
int
cadet_recv_subscribe_fail(void* cls, 
							struct GNUNET_CADET_Channel* channel,
							void** ctx,
							const struct GNUNET_MessageHeader* m)
{
	const struct GNUNET_SCRB_SubscribeFailMessage*
		msg = (struct GNUNET_SCRB_SubscribeFailMessage*)m;
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
		grp = GNUNET_CONTAINER_multihashmap_get(groups, &msg->grp_key_hash);
	if(NULL != *grp)
	{
		//may be send some message back here?
		GNUNET_break_op(0);
		return GNUNET_SYSERR;
	}
	//1. check if we are the source
	if(0 == memcmp(&my_identity, &msg->source, sizeof(struct GNUNET_PeerIdentity)))
	{
		//1.1 we are the source, send subscribe fail message to clients
		client_send_subscribe_fail (grp);
		//1.2 we need to send a subscribe fail to the previous peer on the
		//path
		struct GNUNET_SCRB_RoutePath path_to_failed = msg->path_to_failed;
		struct GNUNET_PeerIdentity* path = path_to_failed->path;
		unsigned int path_length = path_to_failed->path_length;
		unsigned int offset = path_to_failed->offset;
		struct GNUNET_PeerIdentity *pi = path[path_length - 1 - offset];
		struct NodeHandle* child;
		if(NULL != (child = group_children_remove(grp, pi)))
		{			 
			//increase the step on the path before sending
			cadet_send_subscribe_fail(child, pn, path, path_length, ++offset);
			//free the child structure
			free_node (child);	
		}
        //1.3 if the group is empty, remove it and do the cleanup
		if(1 == group_children_is_empty(grp))
		{
			//FIXME: do it in a separate function
			//cleanup the group
			GNUNET_CONTAINER_multihashmap_remove (groups, &grp->pub_key_hash, grp);
			free_group(grp);
		}
	}
	return GNUNET_OK;
};

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
	//take group or create
	struct Group* grp =
		client = GNUNET_CONTAINER_multihashmap_get (groups, &pub_key_hash);
	if(NULL == grp)
	{
		grp = GNUNET_new(struct Group);
		grp->pub_key = group_key;
		grp->pub_key_hash = group_key_hash;
	}
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
	//add client to group client list 
	struct ClientList *cl = GNUNET_new (struct ClientList);
	cl->client = client;
	GNUNET_CONTAINER_DLL_insert (grp->cl_head, grp->cl_tail, cl);
	
	GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
				"%p Client connected to group %s. \n",
				cl_ctx, GNUNET_h2s (&grp->pub_key_hash));
	//operation is done on our side
	//next, we send subscribe message via dht
	//to other peers
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
	GNUNET_SERVER_receive_done (client, GNUNET_OK);
};


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
	GNUNET_free(client->priv_key);
	GNUNET_free(client->pub_key);
	GNUNET_free(client->pub_key_hash);
	GNUNET_free (client);
}

static void
free_group_sub_entry (struct GNUNET_SCRB_GroupSubscriber *gs)
{
	GNUNET_MQ_destroy(gs->mq_l);
	GNUNET_MQ_destroy(gs->mq_o);
	GNUNET_free (gs);
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
	group_children_clear(grp);
	group_clients_clear(grp);
	free_node(grp->parent);
	free_node(grp->root);
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
 * Free resources occupied by a publisher entry.
 *
 * @param pub entry to free
 */
static void
free_pub_entry (struct GNUNET_SCRB_ServicePublisher *pub)
{
	GNUNET_free (pub);
}

static void
free_subs_entry (struct GNUNET_SCRB_ServiceSubscription *subs)
{
	struct GNUNET_SCRB_ServiceSubscriber *sub;

	while (NULL != (sub = subs->sub_head))
	{
		GNUNET_CONTAINER_DLL_remove (subs->sub_head,
				subs->sub_tail,
				sub);
		GNUNET_free (sub);
	}

	GNUNET_free (subs);
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
	struct ClientEntry *ce = value;
	free_client_entry (ce);
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
	struct GNUNET_SCRB_Group *group = value;

	free_group (group);
	return GNUNET_OK;
}

/**
 * Free memory occupied by an entry in the publisher map.
 *
 * @param cls unused
 * @param key unused
 * @param value a `struct  GNUNET_SCRB_Group*`
 * @return #GNUNET_OK (continue to iterate)
 */
static int
cleanup_publisher (void *cls,
		const struct GNUNET_HashCode *key,
		void *value)
{
	struct GNUNET_SCRB_ServicePublisher *pub = value;

	free_pub_entry (pub);
	return GNUNET_OK;
}

/**
 * Free memory occupied by an entry in the publisher map.
 *
 * @param cls unused
 * @param key unused
 * @param value a `struct  GNUNET_SCRB_Subscriber*`
 * @return #GNUNET_OK (continue to iterate)
 */
static int
cleanup_subscription (void *cls,
		const struct GNUNET_HashCode *key,
		void *value)
{
	struct GNUNET_SCRB_ServiceSubscription *subs = value;
	free_subs_entry (subs);
	return GNUNET_OK;
}

static int
cleanup_parent (void *cls,
		const struct GNUNET_HashCode *key,
		void *value)
{
	struct GNUNET_SCRB_GroupParent *parent = value;
	GNUNET_MQ_destroy(parent->mq);
	GNUNET_free(parent);
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
	
	if (NULL != clients)
	{
		GNUNET_CONTAINER_multihashmap_iterate (clients,
				&cleanup_client,
				NULL);
		GNUNET_CONTAINER_multihashmap_destroy (clients);
                clients = NULL;
	}

	if (NULL != groups)
	{
		GNUNET_CONTAINER_multihashmap_iterate (groups,
				&cleanup_group,
				NULL);
		GNUNET_CONTAINER_multihashmap_destroy (groups);
		groups = NULL;
	}

	if (NULL != publishers)
	{
		GNUNET_CONTAINER_multihashmap_iterate (publishers,
				&cleanup_publisher,
				NULL);
		GNUNET_CONTAINER_multihashmap_destroy (publishers);
		publishers = NULL;
	}

	if (NULL != subscribers)
	{
		GNUNET_CONTAINER_multihashmap_iterate (subscribers,
				&cleanup_subscription,
				NULL);
		GNUNET_CONTAINER_multihashmap_destroy (subscribers);
		subscribers = NULL;
	}

	if (NULL != parents)
	{
		GNUNET_CONTAINER_multihashmap_iterate (parents,
				&cleanup_parent,
				NULL);
		GNUNET_CONTAINER_multihashmap_destroy (parents);
		parents = NULL;
	}

	GNUNET_DHT_monitor_stop (monitor_handle);

	GNUNET_DHT_disconnect (dht_handle);
	dht_handle = NULL;
	GNUNET_MQ_destroy (mq);
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
};

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
};

static int
group_children_contain(struct Group* grp, struct GNUNET_PeerIdentity* child)
{
	struct NodeList* nl = grp->nl_head;
	while(NULL != nl)
	{
		if(0 == memcmp(nl->node->peer, child, sizeof(*child)))
			return 1;
		nl = nl->next;
	};
	return 0;
};

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
	};
	return node;
};

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
};

static int 
group_children_size(struct NodeList* nl)
{
	if(NULL == nl)
		return 0;
	else
		return 1 + group_children_size(nl->next);
};

static int 
group_children_is_empty(struct Group* grp)
{
	return grp->nl_head == NULL;
}

static void
group_children_clear(struct Group* grp)
{
	struct ClientList* cl;
	while(NULL != (cl = grp->cl_head))
	{
		GNUNET_CONTAINER_DLL_remove (grp->cl_head,
				grp->cl_tail,
				cl);
		GNUNET_free(cl);
	}
};

static int
check_policy(struct GNUNET_SCRB_Policy* policy,
			 struct GNUNET_SCRB_PeerIdentity* child,
			 struct GNUNET_HashCode* grp_key_hash,
			 struct GNUNET_SCRB_Content* content)
{
	//FIXME: implement the policy check
	return 1;
};

static void
group_client_send_message(const struct Group* grp,
						  const struct GNUNET_MessageHeader* msg)
{
	GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
				"%p Sending message to clients. \n", grp);
	
	struct ClientList *cl = grp->cl_head;
	while(NULL != cl)
	{
		GNUNET_SERVER_notification_context_add (nc, cl->client);
		GNUNET_SERVER_notification_context_unicast (nc, cl->client, msg, GNUNET_NO);
		cl = cl->next;
	}
};

static int
group_child_add_helper(const struct GNUNET_CRYPTO_PublicKey* grp_pub_key,
		const struct GNUNET_HashCode* grp_pub_key_hash, 
		struct NodeHandle* child)
{
	int ret = 0;
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
		GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
						"implicitly subscribing to group %s.\n",
						GNUNET_h2s (grp_key_hash));
		ret = 1;
	}
	
	group_children_add(grp, child);
	
	policy_child_added(policy, child);
	
	client_send_child_added(grp, child->peer);
};



/**
 * A client disconnected.  Remove all of its data structure entries.
 *
 * @param cls closure, NULL
 * @param client identification of the client
 */
static void
handle_client_disconnect (void *cls,
		struct GNUNET_SERVER_Client
		* client)
{
	if(NULL == client)
		return;
	struct ClientEntry* current = cl_head;
	while(current != NULL)
	{
		if(current->client == client)
                {
                  GNUNET_CONTAINER_multihashmap_remove(clients, current->cid,
                                                       current);
                  free_client_entry (current);
                  return;
                }
		current = current->next;
	}
}


/**
 * Process statistics requests.
 *
 * @param cls closure
 * @param server the initialized server
 * @param c configuration to use
 */
static void
run (void *cls,
		struct GNUNET_SERVER_Handle *server,
		const struct GNUNET_CONFIGURATION_Handle *c)
{
	static const struct GNUNET_SERVER_MessageHandler handlers[] = {
			{&handle_cl_id_request, NULL, GNUNET_MESSAGE_TYPE_SCRB_ID_REQUEST, 0},
			{&handle_cl_create_request, NULL, GNUNET_MESSAGE_TYPE_SCRB_CREATE_REQUEST, 0},
			{&handle_cl_srvc_lst_request, NULL, GNUNET_MESSAGE_TYPE_SCRB_SERVICE_LIST_REQUEST, 0},
			{&handle_cl_subscribe_request, NULL, GNUNET_MESSAGE_TYPE_SCRB_SUBSCRIBE_REQUEST, 0},
			{&handle_cl_multicast_request, NULL, GNUNET_MESSAGE_TYPE_SCRB_MULTICAST, 0},
			{&handle_cl_leave_request, NULL, GNUNET_MESSAGE_TYPE_SCRB_LEAVE_REQUEST, 0},
			{NULL, NULL, 0, 0}
	};
	cfg = c;
	GNUNET_SERVER_add_handlers (server, handlers);
	GNUNET_SERVER_disconnect_notify (server,
			&handle_client_disconnect,
			NULL);
	GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_FOREVER_REL,
			&shutdown_task,
			NULL);

	nc = GNUNET_SERVER_notification_context_create (server, 16);

	clients = GNUNET_CONTAINER_multihashmap_create (256, GNUNET_YES);

	groups = GNUNET_CONTAINER_multihashmap_create (256, GNUNET_YES);

	publishers = GNUNET_CONTAINER_multihashmap_create (256, GNUNET_YES);

	subscribers = GNUNET_CONTAINER_multihashmap_create (256, GNUNET_YES);

	parents = GNUNET_CONTAINER_multihashmap_create (256, GNUNET_YES);

	if (GNUNET_OK != p2p_init())
	{
		shutdown_task (NULL, NULL);
		return;
	}

	dht_handle = GNUNET_DHT_connect (cfg, 100);

	monitor_handle = GNUNET_DHT_monitor_start (dht_handle,
			GNUNET_BLOCK_TYPE_ANY,
			NULL,
			NULL,
			&get_dht_resp_callback,
			&put_dht_callback,
			cls);

	scrb_stats = GNUNET_STATISTICS_create ("scrb", cfg);
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
	fprintf(stderr, "I am running !");
	return (GNUNET_OK ==
			GNUNET_SERVICE_run (argc,
					argv,
					"scrb",
					GNUNET_SERVICE_OPTION_NONE,
					&run, NULL)) ? 0 : 1;
}

/* end of gnunet-service-scrb.c */
