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
 * @file scrb/scrb_api.c
 * @brief API for scrb
 * @author +azhdanov+
 */


#include "gnunet/platform.h"
#include "gnunet/gnunet_util_lib.h"
#include "../include/gnunet_scrb_service.h"
#include "../include/gnunet_protocols_scrb.h"
#include "scrb.h"

#define LOG(kind,...) GNUNET_log_from (kind, "scrb-api",__VA_ARGS__)

struct GNUNET_SCRB_PublishTransmitHandle
{
	GNUNET_SCRB_PublishTransmitNotify ptn_cb;
	void* notify_cls;
	struct GNUNET_SCRB_Client *client;	
};

struct GNUNET_SCRB_AnycastTransmitHandle
{
	GNUNET_SCRB_AnycastTransmitNotify atn_cb;
	void* notify_cls;
	struct GNUNET_SCRB_ClientSubscriber *sub;
};

struct GNUNET_SCRB_Client
{
	/**
	 * A configuration to use
	 */
	const struct GNUNET_CONFIGURATION_Handle* cfg;
	/**
	 * Connection client
	 */
	struct GNUNET_CLIENT_MANAGER_Connection *client;

	/**
	 * A connect message
	 */
	struct GNUNET_MessageHeader* connect_msg;

	GNUNET_SCRB_ClientAnycastCallback anycast_cb;
	GNUNET_SCRB_ClientDeliverCallback deliver_cb;
	GNUNET_SCRB_ClientChildAddedCallback child_added_cb;
	GNUNET_SCRB_ClientChildRemovedCallback child_removed_cb;
	GNUNET_SCRB_ClientSubscribeFailedCallback subs_fail_cb;
	GNUNET_SCRB_ClientSubscribeSuccessCallback subs_ack_cb;
	void* cb_cls;
								
	/**
	 * Function called after being disconnected from the service
	 */
	GNUNET_ContinuationCallback disconnect_cb;

    /**
     * closure for @a disconnect_cb
     */
	void* disconnect_cls;
	
	/**
	 * Transmit handle for publishing content
	 */
	struct GNUNET_SCRB_PublishTransmitHandle pth;
    /**
	 * Transmit handle for anycasting content
	 */
	struct GNUNET_SCRB_AnycastTransmitHandle ath;
};

/**
 * Send first message to the service after connecting.
 */
static void
client_send_connect_msg (struct GNUNET_SCRB_Client *sclient)
{
	uint16_t cmsg_size = ntohs(sclient->connect_msg->size);
	struct GNUNET_MessageHeader *cmsg = GNUNET_malloc(cmsg_size);
	memcpy(cmsg, sclient->connect_msg, cmsg_size);
	GNUNET_CLIENT_MANAGER_transmit_now(sclient->client, cmsg);

};

/**
 * Got disconnected from service. Reconnect.
 */
static void
client_recv_disconnect (void* cls,
					 struct GNUNET_CLIENT_MANAGER_Connection* client,
					 const struct GNUNET_MessageHeader* msg)
{
	struct GNUNET_SCRB_Client*
		sclient = GNUNET_CLIENT_MANAGER_get_user_context_ (client, sizeof(*sclient));
	GNUNET_CLIENT_MANAGER_reconnect (client);
	client_send_connect_msg(sclient);
}


static void
client_recv_anycast (void *cls,
					 struct GNUNET_CLIENT_MANAGER_Connection *client,
					 const struct GNUNET_MessageHeader *msg)
{
	struct GNUNET_SCRB_Client *
		sclient = GNUNET_CLIENT_MANAGER_get_user_context_ (client, sizeof(*sclient));
	struct GNUNET_SCRB_AnycastMessage* amsg = (struct GNUNET_SCRB_AnycastMessage*)msg;
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
				"Calling anycast message callback with a message of size %u.\n",
				ntohs(amsg->header.header.size));
	if(NULL != sclient->anycast_cb)
		sclient->anycast_cb(sclient->cb_cls, &amsg->group_key, &amsg->content);
}

/**
 * Receive subscribe acknowledgement
 */
static void
client_recv_subscribe_ack (void *cls,
							  struct GNUNET_CLIENT_MANAGER_Connection *client,
							  const struct GNUNET_SCRB_MessageHeader *msg)
{
	struct GNUNET_SCRB_Client *
		sclient = GNUNET_CLIENT_MANAGER_get_user_context_ (client, sizeof(*sclient));
	struct GNUNET_SCRB_SubscribeReplyMessage* sam = (struct GNUNET_SCRB_SubscribeReplyMessage*)msg;
	GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
				"Calling a subscribe ack callback with a message of size %u.\n",
				ntohs(sam->header.header.size));

	if(NULL != sclient->subs_ack_cb)
	{
		sclient->subs_ack_cb(sclient->cb_cls, &sam->grp_key);
	}
}

/**
 * Receive subscribe fail
 */
static void
client_recv_subscribe_fail (void *cls,
				struct GNUNET_CLIENT_MANAGER_Connection *client,
				const struct GNUNET_SCRB_MessageHeader *msg)
{
	struct GNUNET_SCRB_Client*
		sclient = GNUNET_CLIENT_MANAGER_get_user_context_ (client, sizeof(*sclient));
	struct GNUNET_SCRB_ClientSubscribeReplyMessage* sfm = (struct GNUNET_SCRB_ClientSubscribeReplyMessage*)msg;
	GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
				"Calling a subscribe failed callback with a message of size %u.\n",
				ntohs(sfm->header.header.size));

	if(NULL != sclient->subs_fail_cb)
	{
		sclient->subs_fail_cb(sclient->cb_cls, &sfm->grp_key);
	}
}

/**
 * Receive child add
 */
static void
client_recv_child_added (void *cls,
	struct GNUNET_CLIENT_MANAGER_Connection *client,
	const struct GNUNET_SCRB_MessageHeader *msg)
{
	struct GNUNET_SCRB_Client*
		sclient = GNUNET_CLIENT_MANAGER_get_user_context_ (client, sizeof(*sclient));
	struct GNUNET_SCRB_ChildChangeEventMessage*
		cam = (struct GNUNET_SCRB_ChildChangeEventMessage*)msg;
	GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
				"Calling a child removed callback with a message of size %u.\n",
				ntohs(cam->header.header.size));

	if(NULL != sclient->child_added_cb)
	{
		sclient->child_added_cb(sclient->cb_cls, &cam->grp_key, &cam->child);
	}
}

/**
 * Receive child removed
 */
static void
client_recv_child_removed (void *cls,
	struct GNUNET_CLIENT_MANAGER_Connection *client,
	const struct GNUNET_SCRB_MessageHeader *msg)
{
	struct GNUNET_SCRB_Client*
		sclient = GNUNET_CLIENT_MANAGER_get_user_context_ (client, sizeof(*sclient));
	struct GNUNET_SCRB_ChildChangeEventMessage*
		crm = (struct GNUNET_SCRB_ChildChangeEventMessage*)msg;
	GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
				"Calling a child added callback with a message of size %u.\n",
				ntohs(crm->header.header.size));

	if(NULL != sclient->child_removed_cb)
	{
		sclient->child_removed_cb(sclient->cb_cls, &crm->grp_key, &crm->child);
	}
}


static struct GNUNET_CLIENT_MANAGER_MessageHandler client_handlers[] =
{
	{&client_recv_disconnect, NULL, 0, 0, GNUNET_NO},
	
	{&client_recv_anycast, NULL,
	 GNUNET_MESSAGE_TYPE_SCRB_ANYCAST,
	 sizeof(struct GNUNET_SCRB_MessageHeader), GNUNET_YES},
	
	{&client_recv_subscribe_ack, NULL,
	 GNUNET_MESSAGE_TYPE_SCRB_SUBSCRIBE_ACK,
	 sizeof(struct GNUNET_SCRB_MessageHeader), GNUNET_YES},
	
	{&client_recv_subscribe_fail, NULL,
	 GNUNET_MESSAGE_TYPE_SCRB_SUBSCRIBE_FAIL,
	 sizeof(struct GNUNET_SCRB_MessageHeader), GNUNET_YES},
	
	{&client_recv_child_added, NULL,
	 GNUNET_MESSAGE_TYPE_SCRB_CHILD_ADD,
	 sizeof(struct GNUNET_SCRB_MessageHeader), GNUNET_YES},
	
	{&client_recv_child_removed, NULL,
	 GNUNET_MESSAGE_TYPE_SCRB_CHILD_REM,
	 sizeof(struct GNUNET_SCRB_MessageHeader), GNUNET_YES}
	
};

/**
 * A contract for making a subscription.
 *
 * The function subscribes a client to a group by the provided group's
 * @a pub_key. All the information published to the group is delivered to the
 * client using the @a deliver_cb. Anycast messages are received through the
 * @a anycast_cb. 
 *
 * After requesting a subscription, a service notifies the client about the
 * subscription status using acknowledgment/failure messages which are processed
 * using @a subs_ack_cb and @a subs_fail_cb accordingly.
 *
 * The client also receives group modification notifications about addition and
 * deletion of the group members using @a child_added_cb and @a child_del_cb
 * callbacks.
 *
 * The API does not have a particular create/destroy method. When a service 
 * receives a subscribe request for a group not yet created, it simply creates
 * the group and makes a subsrcription for the requestor.
 *
 * @param cfg                   Configuration handle
 * @param pub_key               Public key of the group to be subscribed
 * @param client_key            A private key of the client to sign messages
 * @param content               Content that should be included in the subscribe
 * message
 * @param anycast_cb            The function is called when the client receives
 * an anycast message
 * @param deliver_cb            The function is called when the client receives
 * a message for the topic it is interested in
 * @param child_added_cb        The function is called when the client recieves
 * a message about a new child joining the group
 * @param child_removed_cb      The function is called when the client recieves
 * a message about a child removed from the group
 * @param subs_fail_cb          The function is called when the client recieves
 * a subscription failure message
 * @param subs_ack_cb           The function is called when the client recieves
 * a subscription acknowledgement message
 * @param cont_cb               The function is called to continue the invoca-
 * tion queue
 * @param cls                   Callback closure
 * @return Handle for the client, NULL on error
 */
struct GNUNET_SCRB_Client*
GNUNET_SCRB_subscribe(const struct GNUNET_CONFIGURATION_Handle *cfg,
					  const struct GNUNET_CRYPTO_EddsaPublicKey* group_key,
					  const struct GNUNET_CRYPTO_EddsaPrivateKey* client_key,
					  const struct GNUNET_SCRB_Content* content,
					  GNUNET_SCRB_ClientAnycastCallback anycast_cb,
					  GNUNET_SCRB_ClientDeliverCallback deliver_cb,
					  GNUNET_SCRB_ClientChildAddedCallback child_added_cb,
					  GNUNET_SCRB_ClientChildRemovedCallback child_removed_cb,
					  GNUNET_SCRB_ClientSubscribeFailedCallback subs_fail_cb,
					  GNUNET_SCRB_ClientSubscribeSuccessCallback subs_ack_cb,
					  void* cb_cls,
					  GNUNET_ContinuationCallback disconnect_cb,
					  void* disconnect_cls)
{
	struct GNUNET_SCRB_Client *sclient = GNUNET_malloc(sizeof(*sclient));
	struct GNUNET_SCRB_SubscribeMessage *sm = GNUNET_malloc(sizeof(*sm));

	sm->header.header.type = htons(GNUNET_MESSAGE_TYPE_SCRB_SUBSCRIBE);
	sm->header.header.size = htons(sizeof(*sm));
	sclient->connect_msg = (struct GNUNET_MessageHeader*) sm;
	sclient->cfg = cfg;

	memcpy(&sm->client_key, client_key, sizeof(*client_key));
	memcpy(&sm->group_key, group_key, sizeof(*group_key));
	memcpy(&sm->content, content, sizeof(*content));
	
	sclient->cb_cls = cb_cls;
	sclient->anycast_cb = anycast_cb;
	sclient->deliver_cb = deliver_cb;
	sclient->child_added_cb = child_added_cb;
	sclient->child_removed_cb = child_removed_cb;
	sclient->subs_fail_cb = subs_fail_cb;
	sclient->subs_ack_cb = subs_ack_cb;

	sclient->disconnect_cb = disconnect_cb;
	sclient->disconnect_cls = disconnect_cls;

	sclient->client = GNUNET_CLIENT_MANAGER_connect(cfg, "scrb", client_handlers);
	GNUNET_CLIENT_MANAGER_set_user_context_ (sclient->client, sclient, sizeof(*sclient));
	client_send_connect_msg(sclient);
};


/* end of ext_api.c */
