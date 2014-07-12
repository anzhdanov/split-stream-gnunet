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
 * @file ext/ext_api.c
 * @brief API for ext
 * @author 
 */
#include <gnunet/platform.h>
#include <gnunet/gnunet_util_lib.h>
#include <gnunet/gnunet_multicast_service.h>
#include <gnunet/gnunet_mq_lib.h>
#include "handle.h"
#include "scrb.h"
#include "gnunet_protocols_scrb.h"

/**
 * id requested from service
 */
static struct GNUNET_HashCode my_identity_hash;
/**
 * service id
 */
static struct GNUNET_PeerIdentity srvc_identity;
/**
 * Initialization flag
 */
static uint16_t init;

/**
 * Rendevous point
 *
 */
static struct GNUNET_PeerIdentity* rp;
/**
 * Publish status
 */
static int publish_status;

/**
 * subscribe status
 */
static int subscribe_status;

/**
 * Services available from the service
 */
static struct GNUNET_CONTAINER_MultiHashMap *services;
/**
 * group to which the client subscribes
 */
static struct GNUNET_HashCode group_id;

static void
receive_publisher_update (void *cls, const struct GNUNET_MessageHeader *msg)
{
	struct GNUNET_SCRB_Handle* eh = cls;

	struct GNUNET_SCRB_UpdateSubscriber* up = (struct GNUNET_SCRB_UpdateSubscriber*)msg;
	fprintf(stderr, "%.1024s", up->data.data);
}

/**
 * Receive reply for service list request
 */
static void
receive_service_list_reply (void *cls, const struct GNUNET_MessageHeader *msg)
{
	struct GNUNET_SCRB_Handle* eh = cls;

	struct GNUNET_SCRB_SrvcRplySrvcLst* rim = (struct GNUNET_SCRB_SrvcRplySrvcLst*)msg;
	struct GNUNET_SCRB_ServicePublisher *pub = &rim->pub;
	GNUNET_CONTAINER_multihashmap_put(services,
			&pub->group_id,
			pub,
			GNUNET_CONTAINER_MULTIHASHMAPOPTION_MULTIPLE);
	//take the last publisher in the list and send subscription
	if(GNUNET_CONTAINER_multihashmap_size(services) == rim->size)
	{
		group_id = rim->pub.group_id;
		GNUNET_SCRB_subscribe(eh, &group_id, &my_identity_hash, NULL, NULL);
	}
}

/**
 * Receive reply for create request
 */
static void
receive_create_reply (void *cls, const struct GNUNET_MessageHeader *msg)
{
	struct GNUNET_SCRB_Handle* eh = cls;

	struct GNUNET_SCRB_ServiceReplyCreate* rim = (struct GNUNET_SCRB_ServiceReplyCreate*)msg;
	rp = &rim->rp;
	publish_status = rim->status;

	if(NULL != eh->cb)
	{
		eh->cb(eh);
	}
	/**
	 * ...
	 */
//	multicast(eh);
}

/**
 * Receive reply for create request
 */
static void
receive_subscribe_reply (void *cls, const struct GNUNET_MessageHeader *msg)
{
	struct GNUNET_SCRB_Handle* eh = cls;

	const struct GNUNET_SCRB_ServiceReplySubscribe* rim = (struct GNUNET_SCRB_ServiceReplySubscribe*)msg;
	publish_status = rim->status;

	if(NULL != eh->cb)
	{
          eh->cb(eh->cb_cls, eh);
	}
	/**
	 * request leave after a few seconds
	 */
	//	leave(eh);
}


/**
 * Receive reply from the service with id
 */
static void
receive_id_reply (void *cls, const struct GNUNET_MessageHeader *msg)
{
	struct GNUNET_SCRB_Handle* eh = cls;

	const struct GNUNET_SCRB_ServiceReplyIdentity* rim = (struct GNUNET_SCRB_ServiceReplyIdentity*)msg;
	my_identity_hash = rim->cid;
	srvc_identity = rim->sid;

	init = 1;
	if(NULL != eh->cb)
	{
		eh->cid = &my_identity_hash;
		eh->cb(eh);
	}
}

static void
handle_client_scrb_error (void *cls, enum GNUNET_MQ_Error error)
{

}

/**
 * Connect to service and ask id.
 */
struct GNUNET_SCRB_Handle *
GNUNET_SCRB_connect (const struct GNUNET_CONFIGURATION_Handle *cfg)
{
	struct GNUNET_SCRB_Handle *eh;
	static const struct GNUNET_MQ_MessageHandler mq_handlers[] = {
			{receive_id_reply, GNUNET_MESSAGE_TYPE_SCRB_ID_REPLY, 0},
			{receive_create_reply, GNUNET_MESSAGE_TYPE_SCRB_CREATE_REPLY, 0},
			{receive_service_list_reply, GNUNET_MESSAGE_TYPE_SCRB_SERVICE_LIST_REPLY, 0},
			{receive_subscribe_reply, GNUNET_MESSAGE_TYPE_SCRB_SUBSCRIBE_REPLY, 0},
			{receive_publisher_update, GNUNET_MESSAGE_TYPE_SCRB_MULTICAST, 0},
			GNUNET_MQ_HANDLERS_END
	};


	eh = GNUNET_new (struct GNUNET_SCRB_Handle);
	eh->cfg = cfg;
	eh->client = GNUNET_CLIENT_connect ("scrb", cfg);
	if (NULL == eh->client)
	{
		GNUNET_free (eh);
		return NULL;
	}
	eh->mq = GNUNET_MQ_queue_for_connection_client (eh->client, mq_handlers,
			handle_client_scrb_error, eh);
	GNUNET_assert (NULL != eh->mq);
	return eh;
}

void GNUNET_SCRB_request_id(
		struct GNUNET_SCRB_Handle *eh,
		void (*cb)(void *cls, struct GNUNET_SCRB_Handle *scrb),
		void *cb_cls)
{
	eh->cb = cb;
	eh->cb_cls = cb_cls;
	struct GNUNET_MQ_Envelope *mqm;
	struct GNUNET_SCRB_ClientRequestIdentity *msg;
	mqm = GNUNET_MQ_msg (msg, GNUNET_MESSAGE_TYPE_SCRB_ID_REQUEST);
	GNUNET_MQ_send (eh->mq, mqm);
}

/**
 * Disconnect from the service
 */
void
GNUNET_SCRB_disconnect (struct GNUNET_SCRB_Handle *eh)
{
	GNUNET_SCRB_request_leave(eh, &my_identity_hash, NULL, NULL);

	if (NULL != eh->th)
	{
		GNUNET_CLIENT_notify_transmit_ready_cancel (eh->th);
		eh->th = NULL;
	}
	if (NULL != eh->client)
	{
		GNUNET_CLIENT_disconnect (eh->client);
		eh->client = NULL;
	}

	GNUNET_free (eh);
}

/**
 * Request create group from the service
 */
void GNUNET_SCRB_request_create(
		struct GNUNET_SCRB_Handle *eh,
		const struct GNUNET_HashCode* group_id,
		void (*cb)(),
		void *cb_cls)
{
	eh->cb = cb;
	eh->cb_cls = cb_cls;

	struct GNUNET_SCRB_ClientRequestCreate *msg;

	size_t msg_size = sizeof(struct GNUNET_SCRB_ClientRequestCreate);

	struct GNUNET_MQ_Envelope* ev = GNUNET_MQ_msg(msg, GNUNET_MESSAGE_TYPE_SCRB_CREATE_REQUEST);

	msg->header.size = htons((uint16_t) msg_size);
	msg->header.type = htons(GNUNET_MESSAGE_TYPE_SCRB_CREATE_REQUEST);
	msg->group_id = *group_id;

	GNUNET_MQ_send (eh->mq, ev);
}

/**
 * Request create group from the service
 */
void GNUNET_SCRB_subscribe(
		struct GNUNET_SCRB_Handle *eh,
		const struct GNUNET_HashCode* group_id,
		const struct GNUNET_HashCode* cid,
		void (*cb)(),
		void *cb_cls)
{
	eh->cb = cb;
	eh->cb_cls = cb_cls;

	struct GNUNET_SCRB_ClntSbscrbRqst *msg;

	size_t msg_size = sizeof(struct GNUNET_SCRB_ClntSbscrbRqst);

	struct GNUNET_MQ_Envelope* ev = GNUNET_MQ_msg(msg, GNUNET_MESSAGE_TYPE_SCRB_SUBSCRIBE_REQUEST);

	msg->header.size = htons((uint16_t) msg_size);
	msg->header.type = htons(GNUNET_MESSAGE_TYPE_SCRB_SUBSCRIBE_REQUEST);
	msg->group_id = *group_id;
	msg->client_id = *cid;

	GNUNET_MQ_send (eh->mq, ev);
}

void GNUNET_SCRB_request_multicast(
		struct GNUNET_SCRB_Handle *eh,
		const struct GNUNET_HashCode* group_id,
		const struct GNUNET_SCRB_MulticastData* data,
		void (*cb)(),
		void* cb_cls)
{
	eh->cb = cb;
	eh->cb_cls = cb_cls;
	struct GNUNET_SCRB_UpdateSubscriber* msg;
	struct GNUNET_MQ_Envelope* ev = GNUNET_MQ_msg(msg, GNUNET_MESSAGE_TYPE_SCRB_MULTICAST);

	size_t msg_size = sizeof(struct GNUNET_SCRB_UpdateSubscriber);
	msg->header.size = htons((uint16_t) msg_size);
	msg->header.type = htons(GNUNET_MESSAGE_TYPE_SCRB_MULTICAST);
	msg->group_id = *group_id;
	memcpy(&msg->data, data, sizeof(struct GNUNET_SCRB_MulticastData));

	GNUNET_MQ_send (eh->mq, ev);
}


/**
 * Request create group from the service
 */
void GNUNET_SCRB_request_service_list(struct GNUNET_SCRB_Handle *eh)
{
	struct GNUNET_SCRB_ClntRqstSrvcLst *msg;

	size_t msg_size = sizeof(struct GNUNET_SCRB_ClntRqstSrvcLst);

	struct GNUNET_MQ_Envelope* ev = GNUNET_MQ_msg(msg, GNUNET_MESSAGE_TYPE_SCRB_SERVICE_LIST_REQUEST);

	msg->header.size = htons((uint16_t) msg_size);
	msg->header.type = htons(GNUNET_MESSAGE_TYPE_SCRB_SERVICE_LIST_REQUEST);
	msg->cid = my_identity_hash;

	GNUNET_MQ_send (eh->mq, ev);
}

void GNUNET_SCRB_request_leave(
		struct GNUNET_SCRB_Handle *eh,
		const struct GNUNET_HashCode *group_id,
		void (*cb)(),
		void *cb_cls)
{
	eh->cb = cb;
	eh->cb_cls = cb_cls;

	struct GNUNET_SCRB_ClntRqstLv *msg;

	size_t msg_size = sizeof(struct GNUNET_SCRB_ClntRqstLv);

	struct GNUNET_MQ_Envelope* ev = GNUNET_MQ_msg(msg, GNUNET_MESSAGE_TYPE_SCRB_LEAVE_REQUEST);

	msg->header.size = htons((uint16_t) msg_size);
	msg->header.type = htons(GNUNET_MESSAGE_TYPE_SCRB_LEAVE_REQUEST);
	msg->cid = my_identity_hash;
	msg->group_id = *group_id;

	GNUNET_MQ_send (eh->mq, ev);
}

static void
leave_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
	struct GNUNET_SCRB_Handle* eh = cls;
	if(init)
		GNUNET_SCRB_request_leave(eh, &my_identity_hash, NULL, NULL);
	else
		GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_MINUTES, &leave_task,
				eh);
}

static void
publish_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
	struct GNUNET_SCRB_Handle* eh = cls;
	if(init)
		GNUNET_SCRB_request_create(eh, &my_identity_hash, NULL, NULL);
	else
		GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_SECONDS, &publish_task,
				eh);
}

static void
request_list_and_subscribe_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
	struct GNUNET_SCRB_Handle* eh = cls;
	if(init)
		GNUNET_SCRB_request_service_list(eh);
	else
		GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_SECONDS, &request_list_and_subscribe_task,
				eh);
}

static void
multicast_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
	struct GNUNET_SCRB_Handle* eh = cls;
	struct GNUNET_SCRB_MulticastData msg;

	GNUNET_SCRB_request_multicast(eh, &my_identity_hash, &msg, NULL, NULL);

	GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_MINUTES, &multicast_task,
			eh);
}

void multicast(struct GNUNET_SCRB_Handle* eh)
{
	GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_SECONDS, &multicast_task,
			eh);
}

void publish(struct GNUNET_SCRB_Handle* eh)
{
	GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_SECONDS, &publish_task,
			eh);
}

void leave(struct GNUNET_SCRB_Handle* eh)
{
	GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_SECONDS, &leave_task,
			eh);
}

void request_list_and_subscribe(struct GNUNET_SCRB_Handle* eh)
{

	services = GNUNET_CONTAINER_multihashmap_create (256, GNUNET_YES);

	GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_SECONDS, &request_list_and_subscribe_task,
			eh);
}


/* end of ext_api.c */
