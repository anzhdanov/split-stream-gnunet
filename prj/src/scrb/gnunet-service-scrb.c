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
 * @brief ext service implementation
 * @author Christian Grothoff
 */
#include <gnunet/platform.h>
#include <gnunet/gnunet_util_lib.h>
#include <gnunet/gnunet_protocols.h>
#include "gnunet_protocols_scrb.h"
#include <gnunet/gnunet_core_service.h>
#include <gnunet/gnunet_statistics_service.h>
#include "gnunet/gnunet_common.h"
#include <gnunet/gnunet_mq_lib.h>
#include "scrb.h"
#include "gnunet/gnunet_dht_service.h"
#include <gcrypt.h>
#include "scrb_block_lib.h"
#include "scrb_group.h"
#include "scrb_publisher.h"
#include "scrb_subscriber.h"
#include "scrb_multicast.h"

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
 * How often do we run the PUTs?
 */
#define PUT_FREQUENCY GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 10)


static struct GNUNET_DHT_MonitorHandle *monitor_handle;
/*****************************************methods*******************************************/
/*************************************monitor handlers**************************************/
void
get_dht_callback (void *cls,
		enum GNUNET_DHT_RouteOption options,
		enum GNUNET_BLOCK_Type type,
		uint32_t hop_count,
		uint32_t desired_replication_level,
		unsigned int path_length,
		const struct GNUNET_PeerIdentity *path,
		const struct GNUNET_HashCode *key);
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
/****************************************************************************************/
	static unsigned int id_counter = 0;

	static struct GNUNET_CONTAINER_MultiHashMap *clients;

	struct ClientEntry
	{
		/**
		 * Message queue for the client
		 */
		struct GNUNET_MQ_Handle* mq;
		/**
		 * Client id
		 */
		struct GNUNET_HashCode* cid;
		/**
		 * Client
		 */
		struct GNUNET_SERVER_Client* client;
		/**
		 * Pointer to previous
		 */
		struct ClientEntry* prev;
		/**
		 * Pointer to next
		 */
		struct ClientEntry* next;
	};

	struct ClientEntry* cl_head;

	struct ClientEntry* cl_tail;

	static struct GNUNET_CONTAINER_MultiHashMap *groups;

	static struct GNUNET_CONTAINER_MultiHashMap *publishers;

	static struct GNUNET_CONTAINER_MultiHashMap *subscribers;

	static struct GNUNET_CONTAINER_MultiHashMap *parents;

	struct GNUNET_MQ_Handle* mq;

	/****************************************************************************************/
	void
	get_dht_callback (void *cls,
			enum GNUNET_DHT_RouteOption options,
			enum GNUNET_BLOCK_Type type,
			uint32_t hop_count,
			uint32_t desired_replication_level,
			unsigned int path_length,
			const struct GNUNET_PeerIdentity *path,
			const struct GNUNET_HashCode *key)
	{
		printf("I got get event! \n");
	}
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
				GNUNET_CONTAINER_MULTIHASHMAPOPTION_MULTIPLE);
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
			struct GNUNET_STATISTICS_Handle* scrb_stats) {
		char str[100];
		strcpy(str, msg);
		strcat(str, GNUNET_i2s(src));
		strcat(str, " to: ");
		strcat(str, GNUNET_i2s(&*my_identity));
		GNUNET_STATISTICS_update(scrb_stats, gettext_noop(str), 1, GNUNET_NO);
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
			update_stats(msg, &path[0], &my_identity, scrb_stats);
			GNUNET_STATISTICS_update (scrb_stats,
					gettext_noop ("# deliver: overall CREATE messages received"),
					1, GNUNET_NO);
			struct GNUNET_SCRB_Group* group = createGroup(key, data, groups);
			service_confirm_creation(group);
			break;
		}
		case GNUNET_BLOCK_SCRB_TYPE_JOIN:
		{
			const char* msg = "# deliver: JOIN messages received from: ";
			update_stats(msg, &path[path_length - 1], &my_identity, scrb_stats);
			GNUNET_STATISTICS_update (scrb_stats,
					gettext_noop ("# deliver: overall JOIN messages received"),
					1, GNUNET_NO);
			struct GNUNET_SCRB_Group* group = GNUNET_CONTAINER_multihashmap_get(groups, key);
			if (group != NULL)
			{
				struct GNUNET_SCRB_GroupSubscriber* gs = group->group_head;
				uint32_t found = 0;
				while (NULL != gs)
				{
					if(0==memcmp(&gs->sid, &path[path_length - 1] , sizeof(struct GNUNET_PeerIdentity)))
						found = 1;
					gs = gs->next;
				}
				if(found == 0)
				{
					struct GNUNET_SCRB_GroupSubscriber* group_subscriber = createGroupSubscriber(key, data, path[path_length -1], groups);
					service_send_parent(group_subscriber);
					service_confirm_subscription(group_subscriber);
				}
			}

			break;
		}
		case GNUNET_BLOCK_SCRB_TYPE_MULTICAST:
		{
			const char* msg = "# deliver: MULTICAST messages received from: ";
			update_stats(msg, &path[path_length - 1], &my_identity, scrb_stats);
			GNUNET_STATISTICS_update (scrb_stats,
					gettext_noop ("# deliver: overall MULTICAST messages received"),
					1, GNUNET_NO);
			struct GNUNET_BLOCK_SCRB_Multicast* multicast_block;
			multicast_block = (struct GNUNET_BLOCK_SCRB_Multicast*) data;
			struct GNUNET_SCRB_Group* group = GNUNET_CONTAINER_multihashmap_get(groups,
					key);
			if (NULL != group) {
				struct GNUNET_SCRB_GroupSubscriber* gs = group->group_head;
				while (NULL != gs)
				{
					if (0 != memcmp(&gs->sidh, &my_identity_hash, sizeof(struct GNUNET_HashCode)))
					{
						GNUNET_DHT_put (dht_handle, &gs->sidh, 10U,
								GNUNET_DHT_RO_RECORD_ROUTE |
								GNUNET_DHT_RO_DEMULTIPLEX_EVERYWHERE | GNUNET_DHT_RO_LAST_HOP,
								GNUNET_BLOCK_SCRB_TYPE_MULTICAST,
								sizeof (multicast_block), &multicast_block,
								GNUNET_TIME_UNIT_FOREVER_ABS,
								GNUNET_TIME_UNIT_FOREVER_REL,
								NULL, NULL);
					}
					gs = gs->next;
				}
			}

			struct GNUNET_SCRB_ServiceSubscription* subs = GNUNET_CONTAINER_multihashmap_get(subscribers,
					key);
			if (NULL != subs) {
				struct GNUNET_SCRB_ServiceSubscriber* sub = subs->sub_head;
				while (NULL != sub)
				{
					struct GNUNET_SCRB_UpdateSubscriber *msg;
					size_t msg_size = sizeof(struct GNUNET_SCRB_UpdateSubscriber);
					struct GNUNET_MQ_Envelope* ev = GNUNET_MQ_msg(msg, GNUNET_MESSAGE_TYPE_SCRB_MULTICAST);

					msg->header.size = htons((uint16_t) msg_size);
					msg->header.type = htons(GNUNET_MESSAGE_TYPE_SCRB_MULTICAST);
					msg->data = multicast_block->data;
					msg->group_id = multicast_block->group_id;
					msg->last = multicast_block->last;

					struct ClientEntry* ce = GNUNET_CONTAINER_multihashmap_get(clients, &sub->cid);

					GNUNET_MQ_send (ce->mq, ev);

					sub = sub->next;
				}
			}

			break;
		}
		case GNUNET_BLOCK_SCRB_TYPE_LEAVE:
		{
			struct GNUNET_BLOCK_SCRB_Leave* leave_block;
			leave_block = (struct GNUNET_BLOCK_SCRB_Leave*) data;
			struct GNUNET_HashCode sid = leave_block->sid;
			leaveGroup(key, &sid, groups, parents);
			const char* msg = "# deliver: LEAVE messages received from: ";
			update_stats(msg, &path[path_length - 1], &my_identity, scrb_stats);
			GNUNET_STATISTICS_update (scrb_stats,
					gettext_noop ("# deliver: overall LEAVE messages received"),
					1, GNUNET_NO);
			break;
		}
		default:
			break;
		}
	}

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
			GNUNET_STATISTICS_update (scrb_stats,
					gettext_noop ("# forward: JOIN messages received"),
					1, GNUNET_NO);
			if(!GNUNET_CONTAINER_multihashmap_contains(groups, key))
			{
				createGroup(key, data, groups);
				struct GNUNET_SCRB_GroupSubscriber* gs = createGroupSubscriber(key, data, path[path_length - 1], groups);
				service_send_parent(gs);

			}else //we check if already have the subscriber
			{
				struct GNUNET_SCRB_Group* group = GNUNET_CONTAINER_multihashmap_get(groups, key);
				struct GNUNET_SCRB_GroupSubscriber* gs = group->group_head;
				uint32_t found = 0;
				while (NULL != gs)
				{
					if(0==memcmp(&gs->sid, &path[path_length - 1] , sizeof(struct GNUNET_PeerIdentity)))
						found = 1;
					gs = gs->next;
				}
				if(found == 0)
				{
					struct GNUNET_SCRB_GroupSubscriber* gs = createGroupSubscriber(key, data, path[path_length - 1], groups);
					service_send_parent(gs);
				}
			}

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
		const char* msg = "# CONFIRM CREATE messages received from: ";
		update_stats(msg, other, &my_identity, scrb_stats);
		GNUNET_STATISTICS_update (scrb_stats,
				gettext_noop ("# overall CONFIRM CREATE messages received"),
				1, GNUNET_NO);

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
		const char* msg = "# CONFIRM JOIN messages received from: ";
		update_stats(msg, other, &my_identity, scrb_stats);
		GNUNET_STATISTICS_update (scrb_stats,
				gettext_noop ("# overall CONFIRM JOIN messages received"),
				1, GNUNET_NO);
		struct GNUNET_SCRB_ServiceReplySubscribe *hdr;
		hdr = (struct GNUNET_SCRB_ServiceReplySubscribe *) message;

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

	static int
	handle_service_send_parent (void *cls,
			const struct GNUNET_PeerIdentity *other,
			const struct GNUNET_MessageHeader *message)
	{
		const char* msg = "# SEND PARENT messages received from: ";
		update_stats(msg, other, &my_identity, scrb_stats);
		GNUNET_STATISTICS_update (scrb_stats,
				gettext_noop ("# overall SEND PARENT messages received"),
				1, GNUNET_NO);
		struct GNUNET_SCRB_SendParent2Child *hdr;
		hdr = (struct GNUNET_SCRB_SendParent2Child *) message;

		struct GNUNET_SCRB_GroupParent* parent = GNUNET_new(struct GNUNET_SCRB_GroupParent);

		parent->group_id = hdr->group_id;

		parent->parent = hdr->parent;

		parent->mq = GNUNET_CORE_mq_create (core_api, &parent->parent);

		GNUNET_CONTAINER_multihashmap_put(parents,
				&parent->group_id,
				parent,
				GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY );

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
		struct GNUNET_SCRB_UpdateSubscriber *hdr;
		hdr = (struct GNUNET_SCRB_UpdateSubscriber *) message;

		struct GNUNET_BLOCK_SCRB_Multicast multicast_block;

		memcpy(&multicast_block.data, &hdr->data, sizeof(struct GNUNET_SCRB_MulticastData));
		multicast_block.group_id = hdr->group_id;
		multicast_block.last = hdr->last;

		/* fixme: do not ignore return handles */
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
		GNUNET_MQ_send(ce->mq, ev);
	}

	static void
	handle_cl_subscribe_request (void *cls,
			struct GNUNET_SERVER_Client *client,
			const struct GNUNET_MessageHeader *message)
	{
		struct GNUNET_SCRB_ClntSbscrbRqst *hdr;
		hdr = (struct GNUNET_SCRB_ClntSbscrbRqst *) message;

		struct GNUNET_SCRB_ServiceSubscription* subs;
		subs = 	GNUNET_CONTAINER_multihashmap_get(subscribers, &hdr->group_id);

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
		struct GNUNET_SCRB_ClientRequestCreate *hdr;
		hdr = (struct GNUNET_SCRB_ClientRequestCreate *) message;

		const struct GNUNET_HashCode group_id = hdr->group_id;

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

	static void
	handle_cl_id_request (void *cls,
			struct GNUNET_SERVER_Client *client,
			const struct GNUNET_MessageHeader *message)
	{
		//increase id counter
		id_counter++;
		struct GNUNET_HashCode ego_hash;
		GNUNET_CRYPTO_hash (&id_counter,
				sizeof (id_counter),
				&ego_hash);

		//concatenate my_identity_hash together with id counter
		struct GNUNET_HashCode *client_hash = GNUNET_new(struct GNUNET_HashCode);
		GNUNET_CRYPTO_hkdf (client_hash, sizeof (struct GNUNET_HashCode),
				GCRY_MD_SHA512, GCRY_MD_SHA256,
				&ego_hash, sizeof(ego_hash),
				&my_identity_hash, sizeof (my_identity_hash),
				NULL, 0);

		struct ClientEntry* ce = GNUNET_new(struct ClientEntry);
		ce->cid = client_hash;
		ce->client = client;
		ce->mq = GNUNET_MQ_queue_for_server_client(client);

		//put the client in map
		GNUNET_CONTAINER_multihashmap_put (clients, client_hash, ce,
				GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY);
		//put the entry in list for faster search
		GNUNET_CONTAINER_DLL_insert(cl_head, cl_tail, ce);

		size_t msg_size;
		struct GNUNET_SCRB_ServiceReplyIdentity* msg;
		struct GNUNET_MQ_Envelope* ev = GNUNET_MQ_msg(msg, GNUNET_MESSAGE_TYPE_SCRB_ID_REPLY);
		msg_size = sizeof(struct GNUNET_SCRB_ServiceReplyIdentity);
		msg->header.size = htons((uint16_t) msg_size);
		msg->header.type = htons(GNUNET_MESSAGE_TYPE_SCRB_ID_REPLY);
		msg->cid = *client_hash;
		msg->sid = my_identity;

		GNUNET_MQ_send (ce->mq, ev);

		GNUNET_SERVER_receive_done (client, GNUNET_OK);
	}

	/**
	 * Free resources occupied by a client entry.
	 *
	 * @param client entry to free
	 */
	static void
	free_client_entry (struct ClientEntry *ce)
	{
		GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
				"Cleaning up client entry\n");

		GNUNET_CONTAINER_DLL_remove (cl_head, cl_tail, ce);

		GNUNET_free (ce);
	}


	/**
	 * Free resources occupied by a group entry.
	 *
	 * @param group entry to free
	 */
	static void
	free_group_entry (struct GNUNET_SCRB_Group *group)
	{
		struct GNUNET_SCRB_GroupSubscriber *gs;

		GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
				"Cleaning up group entry\n");
		while (NULL != (gs = group->group_head))
		{
			GNUNET_CONTAINER_DLL_remove (group->group_head,
					group->group_tail,
					gs);
			GNUNET_free (gs);
		}

		GNUNET_free (group);
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
	free_par_entry (struct GNUNET_HashCode* par)
	{
		GNUNET_free (par);
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

		free_group_entry (group);
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
	cleanup_subscriber (void *cls,
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
		struct GNUNET_HashCode *parent = value;

		free_par_entry (parent);
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
		if (NULL != clients)
		{
			GNUNET_CONTAINER_multihashmap_iterate (clients,
					&cleanup_client,
					NULL);
			GNUNET_CONTAINER_multihashmap_destroy (clients);
			groups = NULL;
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
					&cleanup_subscriber,
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
			subscribers = NULL;
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
		struct ClientEntry* current = cl_head;
		while(current != NULL)
		{
			if(current->client == client)
				break;
			current = current->next;
		}

		GNUNET_CONTAINER_multihashmap_remove(clients, current->cid, current);
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
				&get_dht_callback,
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
		printf("I am running !");
		return (GNUNET_OK ==
				GNUNET_SERVICE_run (argc,
						argv,
						"scrb",
						GNUNET_SERVICE_OPTION_NONE,
						&run, NULL)) ? 0 : 1;
	}

	/* end of gnunet-service-scrb.c */
