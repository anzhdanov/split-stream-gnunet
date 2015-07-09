/*
      This file is part of GNUnet
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
 * @file include/gnunet_scrb_service.h
 * @brief API to the scrb service
 * @author +azhdanov+
 */
#ifndef GNUNET_SCRB_SERVICE_H
#define GNUNET_SCRB_SERVICE_H

#include "gnunet/gnunet_util_lib.h"
#include "gnunet/gnunet_crypto_lib.h"
#include "gnunet/gnunet_common.h"

#ifdef __cplusplus
extern "C"
{
#if 0                           /* keep Emacsens' auto-indent happy */
}
#endif
#endif

/**
 * Version of the GNUnet - scribe API.
 */
#define GNUNET_SCRB_VERSION 0x00000001

/**
 * Credentials of scribe entity
 */
struct GNUNET_SCRB_Credentials;

/**
 * Handle for a publisher
 */
struct GNUNET_SCRB_ClientPublisher;

/**
 * Handle for a subscriber
 */
struct GNUNET_SCRB_ClientSubscriber;

GNUNET_NETWORK_STRUCT_BEGIN

struct GNUNET_SCRB_MessageHeader
{
	/**
	 * Header for all multicast messages
	 */
	struct GNUNET_MessageHeader header;

    /**
	 * Message id
	 */
    uint64_t message_id GNUNET_PACKED;

    /**
	 * Message priority
	 */
    uint32_t message_priority GNUNET_PACKED;

	/**
	 * Source of the multicast message
	 */
	struct GNUNET_HashCode source_id;
	
	/**
	 * Destination of the multicast message
	 */
	struct GNUNET_HashCode dest_id;
	
	/**
	 * Followed by the message body
	 */
    
};

GNUNET_NETWORK_STRUCT_END

/**
 * Content of a publish (multicast) message
 */
struct GNUNET_SCRB_UnicastData
{
	/**
	 * Data of the unicast
	 */
	char* data;
	/**
	 * Size of the content
	 */
	size_t data_size;
	/**
	 * Content type
	 */
	char type;
};

/**
 * Type of group modification event
 */
enum EventType;

/**
 * Functions with the signature are called on receiving (of response to) create request.
 * In case of failure, the client should retry the request or take an appropriate action.
 * @param cls      Callback closure
 * @param cfg      Configuration handle
 * @param group_id Id of the group to subscribe to
 * @param cred     Credentials of the entity subscribing to the topic
 */
typedef void
(*GNUNET_SCRB_CreateRequestCallback)(void *cls,
				struct GNUNET_CONFIGURATION_Handle *cfg,
				const struct GNUNET_HashCode* group_id,
				const struct GNUNET_SCRB_Credentials cred);

/**
 * Functions with the signature are called whenever there is a change event in the group
 * structure
 * @param cls      Callback closure
 * @param cfg      Configuration handle
 * @param group_id Id of the group to subscribe to
 */
typedef void
(*GNUNET_SCRB_GroupChangeEventCallback)(void *cls,
				struct GNUNET_CONFIGURATION_Handle *cfg,
				const struct GNUNET_HashCode* group_id,
				EventType e);

/**
 * Functions with the signature are called on receive of publishing request response
 * @param cls      Callback closure
 * @param cfg      Configuration handle
 * @param group_id Id of the group to subscribe to
 * @param child_id Id of the child added
 */
typedef void
(*GNUNET_SCRB_PublishRequestCallback)(void *cls,
				struct GNUNET_CONFIGURATION_Handle *cfg,
				const struct GNUNET_HashCode* group_id,
				const struct GNUNET_SCRB_MulticastContent* content);

/**
 * Functions with the signature are called whenever it is necessary to test
 * that the group with given id has been created.
 * @param cls      Callback closure
 * @param eh       Configuration handle
 * @param group_id Id of the group to subscribe to
 * @param cred     Credentials of the entity subscribing to the topic
 */
typedef int
(*GNUNET_SCRB_TestGroupCreationCallback)(void *cls,
				struct GNUNET_CONFIGURATION_Handle *cfg,
				const struct GNUNET_HashCode* group_id);

/**
 * Functions with the signature are called whenever it is necessary to test
 * a subscription of client for the group_id.
 * @param cls      Callback closure
 * @param eh       Scribe configuration handle
 * @param group_id Id of the group to subscribe to
 * @param cred     Credentials of client subscribing to the group
 */
typedef int
(*GNUNET_SCRB_TestGroupSubscriptionCallback)(void *cls,
				struct GNUNET_CONFIGURATION_Handle *cfg,
			    const struct GNUNET_HashCode* group_id,
				const struct GNUNET_HashCode* client_id);


/**
 * Functions with the signature are called on receiving (of  response to) subscribe request.
 * In case of failure, the client should retry the request or take an appropriate action.
 * @param cls              Callback closure
 * @param eh               Configuration handle
 * @param group_id         Id of the group to subscribe to
 * @param cred             Credentials of client subscribing to the group
 */
typedef void
(*GNUNET_SCRB_SubscribeRequestCallback)(void *cls,
				struct GNUNET_CONFIGURATION_Handle *cfg,
				const struct GNUNET_HashCode* group_id,
				const struct GNUNET_SCRB_Credentials cred);
/**
 * Functions with the signature are called on receive (of  response to) leave request.
 * In case of failure, the client should retry the request or take an appropriate action.
 * @param cls              Callback closure
 * @param eh               Configuration handle
 * @param group_id         Id of the group to subscribe to
 * @param cred             Credentials of client subscribing to the group
 */
typedef void
(*GNUNET_SCRB_LeaveRequestCallback)(void *cls,
				struct GNUNET_CONFIGURATION_Handle *cfg,
				const struct GNUNET_HashCode* group_id,
				const struct GNUNET_SCRB_Credentials cred);

/**
 * Functions with the signature are called on receive of a unicast message from service
 * by publisher
 * @param cls              Callback closure
 * @param msg              Message from the service
 */
typedef void
(*GNUNET_SCRB_PubUnicastMessageCallback)(void *cls,
				const struct GNUNET_SCRB_UnicastMessage* msg);

/**
 * Functions with the signature are called on receive of a unicast message from service
 * by subscriber
 * @param cls              Callback closure
 * @param msg              Message from the service
 */
typedef void
(*GNUNET_SCRB_SubUnicastMessageCallback)(void *cls,
				const struct GNUNET_SCRB_UnicastMessage* msg);


/**
 * The client sends a request to service to create a group.
 * If the credentials are valid, the service gives a successfull group creation
 * response.
 * Other clients should subscribe with the group_id in order to get information.
 * @param cls                   Callback closure
 * @param cfg                   Configuration handle
 * @param group_id              Id of the group created
 * @param cred                  Credentials of the entity creating a topic
 * @param create_cb             The function can be called on receive of a group creation (response)
 * @param subscription_cb       The function can be called on receive of a group subscription (response)
 * @param leave_cb              The function can be called on receive of a group leave (response)
 * @param group_change_cb       The function can be called on receive of a group change event
 * @param pub_cb                The function can be called on receive of a publish request
 * @param pub_unicst_mes_cb     The function can be called on receive of a unicast message by publisher
 * @param sub_unicst_mes_cb     The function can be called on receive of a unicast message by subscriber
 * @param test_group_created_cb The function can be called to test the group creation
 * @param test_group_sbs_cb     The function can be called to test the group subscription
 * @param cont_cb               The function can be called to continue invocation queue
 * @return Handle for the publisher, NULL on error
 */
struct GNUNET_SCRB_Publisher*
GNUNET_SCRB_create(const struct GNUNET_CONFIGURATION_Handle *cfg,
		const struct GNUNET_HashCode* group_id,
		const struct GNUNET_SCRB_Credentials cred,
		GNUNET_SCRB_CreateCallback create_cb,
		GNUNET_SCRB_SubscribeCallback subscrb_cb,
		GNUNET_SCRB_LeaveCallback leave_cb,
		GNUNET_SCRB_GroupChangeEventCallback group_change_cb,
        GNUNET_SCRB_PublishRequestCallback pub_cb,
		GNUNET_SCRB_PubUnicastMessageCallback pub_unicst_mes_cb,
		GNUNET_SCRB_PubUnicastMessageCallback sub_unicst_mes_cb,
		GNUNET_SCRB_TestGroupCreationCallback test_group_created_cb,
		GNUNET_SCRB_TestGroupSubscriptionCallback test_group_sbs_cb,
		GNUNET_ContinuationCallback cont_cb,
		void* cls);


/**
 * Subscribe to a group.
 * @param cfg                   Configuration handle
 * @param group_id              Id of the group to subscribe to
 * @param cred                  Credentials of the entity subscribing to a topic
 * @param cont_cb               The function can be called to test the client
 * @param create_cb             The function can be called on receive of a group creation (response)
 * @param subscription_cb       The function can be called on receive of a group subscription (response)
 * @param leave_cb              The function can be called on receive of a group leave (response)
 * @param group_change_cb       The function can be called on receive of a group change event
 * @param pub_cb                The function can be called on receive of response of a publish request
 * @param unicst_mes_cb         The function can be called on receive of a unicast message
 * @param test_group_created_cb The function can be called to test the group creation
 * @param test_group_sbs_cb     The function can be called to test a client subscription
 * @param cls                   Callback closure
 * @return Handle for the subscriber, NULL on error
 */
struct GNUNET_SCRB_Subscriber*
GNUNET_SCRB_subscribe(struct GNUNET_CONFIGURATION_Handle *cfg,
		const struct GNUNET_HashCode* group_id,
		const struct GNUNET_HashCode* client_id,
		const struct GNUNET_SCRB_Credentials cred,
		GNUNET_SCRB_CreateCallback create_cb,
		GNUNET_SCRB_SubscribeCallback subscrb_cb,
		GNUNET_SCRB_LeaveCallback leave_cb,
		GNUNET_SCRB_GroupChangeEventCallback group_change_cb,
        GNUNET_SCRB_PublishRequestCallback pub_cb,
		GNUNET_SCRB_UnicastMessageCallback unicst_mes_cb,
		GNUNET_SCRB_TestGroupCreationCallback test_group_created_cb,
		GNUNET_SCRB_TestGroupSubscriptionCallback test_group_sbs_cb,
		GNUNET_ContinuationCallback cont_cb,
		void* cls);

/**
 * Unsubscribe from a group.
 * @param cfg              Configuration handle
 * @param group_id         Id of the group to unsubscribe from
 * @param cred             Credentials of the entity unsubscribing from a topic
 * @param cls              Callback closure
 * @return Handle for the subscriber, NULL on error
 */
void
GNUNET_SCRB_unsubscribe(struct GNUNET_CONFIGURATION_Handle *cfg,
		const struct GNUNET_HashCode* group_id,
		const struct GNUNET_HashCode* client_id,
		const struct GNUNET_SCRB_Credentials cred,
		GNUNET_ContinuationCallback cont_cb,
		void* cls);

/**
 * Functions with the signature are used to make transmission messages for publishers.
 * @param cls        Closure
 * @param data_size  The number of bytes initially available in @a data.
 * @param data       A buffer to write the message body with at most @a data_size bytes.
 * @return           The message size
 */
typedef size_t
(*GNUNET_SCRB_PublisherTransmitNotify)(void* cls,
									   size_t data_size, 
									   void* data);
/**
 * Functions with the signature are used to make transmission messages for subscribers.
 * @param cls        Closure
 * @param data_size  The number of bytes initially available in @a data.
 * @param data       A buffer to write the message body with at most @a data_size bytes.
 * @return           The message size
 */
typedef size_t
(*GNUNET_SCRB_SubscriberTransmitNotify)(void* cls,
									   size_t data_size, 
									   void* data);


/**
 * Handle for a request to send a message to all group members
 */
struct GNUNET_SCRB_PublisherTransmitHandle;

/**
 * Handle for a request to send a message to a group root
 */
struct GNUNET_SCRB_SubscriberTransmitHandle;

/**
 * Publish a content.
 * @param cfg              Configuration handle
 * @param group_id         Id of the group to send a content
 * @param content          Content being sent by publisher
 * @param cred             Credentials of the entity publishing a content
 * @param cont_cb          Continuation callback
 */
struct GNUNET_SCRB_PublisherTransmitHandle*
GNUNET_SCRB_publish(
		struct GNUNET_CONFIGURATION_Handle *cfg,
		const struct GNUNET_HashCode* group_id,
		const struct GNUNET_SCRB_Credentials cred,
		GNUNET_SCRB_PublisherTransmitNotify ptn_cb,
		void* notify_cls,
		GNUNET_ContinuationCallback cont_cb,
		void* cls);

#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

#endif
