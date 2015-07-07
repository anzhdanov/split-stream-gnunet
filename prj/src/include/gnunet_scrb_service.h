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
struct GNUNET_SCRB_Publisher;

/**
 * Handle for a subscriber
 */
struct GNUNET_SCRB_Subscriber;

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
    
};

GNUNET_NETWORK_STRUCT_END

/**
 * Content of a publish (multicast) message
 */
struct GNUNET_SCRB_MulticastContent
{
	/**
	 * Data of the multicast message
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
 * A function with the signature is called whenever a create request is failed.
 * The client should retry the request or take an appropriate action.
 * @param cls      Callback closure
 * @param eh       Configuration handle
 * @param group_id Id of the group to subscribe to
 * @param cred     Credentials of the entity subscribing to the topic
 */
typedef void
(*GNUNET_SCRB_CreateFailedCallback)(void *cls,
				struct GNUNET_CONFIGURATION_Handle *cfg,
				const struct GNUNET_HashCode* group_id,
				const struct GNUNET_SCRB_Credentials cred);

/**
 * A function with the signature is called whenever a create request is
 * successfull.
 * @param cls      Callback closure
 * @param eh       Configuration handle
 * @param group_id Id of the group to subscribe to
 * @param cred     Credentials of the entity subscribing to the topic
 */
typedef void
(*GNUNET_SCRB_CreateSuccessfullCallback)(void *cls,
				struct GNUNET_CONFIGURATION_Handle *cfg,
				const struct GNUNET_HashCode* group_id,
				const struct GNUNET_SCRB_Credentials cred);
/**
 * The function with the signature is called whenever it is necessary to test
 * that the group with given id has been created.
 * @param cls      Callback closure
 * @param eh       Configuration handle
 * @param group_id Id of the group to subscribe to
 * @param cred     Credentials of the entity subscribing to the topic
 */
typedef int
(*GNUNET_SCRB_TestGroupCreatedCallback)(void *cls,
				struct GNUNET_CONFIGURATION_Handle *cfg,
				const struct GNUNET_HashCode* group_id);

/**
 * The client sends a request to service to create a group.
 * If the credentials are valid, the service gives a successfull group creation
 * response.
 * Other clients should subscribe with the group_id in order to get information.
 * @param cls              Callback closure
 * @param cfg              Configuration handle
 * @param group_id         Id of the group created
 * @param cred             Credentials of the entity creating a topic
 * @param create_failed_cb The function can be called on the group creation
 * failure
 * @param create_success_cb The function can be called on the group creation
 * success
 * @param test_group_created_cb The function can be called to test the group
 * has been successfully created
 * @param cont_cb The function can be called to continue invocation queue
 * @return Handle for the publisher, NULL on error
 */
struct GNUNET_SCRB_Publisher*
GNUNET_SCRB_create(const struct GNUNET_CONFIGURATION_Handle *cfg,
		const struct GNUNET_HashCode* group_id,
		const struct GNUNET_SCRB_Credentials cred,
		GNUNET_SCRB_CreateFailedCallback create_failed_cb,
		GNUNET_SCRB_CreateSuccessfullCallback create_success_cb,
		GNUNET_SCRB_TestGroupCreatedCallback test_group_created_cb,
		GNUNET_ContinuationCallback cont_cb,
		void* cls);

/**
 * Functions with the signature are called whenever a subscribe request failed.
 * The client should retry the request or take an appropriate action.
 * @param cls              Callback closure
 * @param eh               Configuration handle
 * @param group_id         Id of the group to subscribe to
 * @param cred             Credentials of client subscribing to the group
 */
typedef void
(*GNUNET_SCRB_SubscribeFailedCallback)(void *cls,
				struct GNUNET_CONFIGURATION_Handle *cfg,
				const struct GNUNET_HashCode* group_id,
				const struct GNUNET_SCRB_Credentials cred);

/**
 * Functions with the signature are called whenever a subscirbe request is
 * successfull.
 * @param cls              Callback closure
 * @param eh               Configuration handle
 * @param group_id         Id of the group to subscribe to
 * @param cred             Credentials of client subscribing to the group
 */
typedef void
(*GNUNET_SCRB_SubscribeSuccessfullCallback)(void *cls,
				struct GNUNET_CONFIGURATION_Handle *cfg,
				const struct GNUNET_HashCode* group_id,
				const struct GNUNET_HashCode* client_id
				const struct GNUNET_SCRB_Credentials cred);

/**
 * Functions with the signature are called whenever it is necessary to test
 * a subscription.
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
 * Subscribe to a group.
 * @param cfg                Configuration handle
 * @param group_id           Id of the group to subscribe to
 * @param cred               Credentials of the entity subscribing to a topic
 * @param subscrb_failed_cb  The function can be called on the group creation
 * failure
 * @param subscrb_success_cb The function can be called on the group creation
 * success
 * @param test_group_sbs_cb  The function can be called to test the client
 * subscription  with group_id
 * @param cont_cb The function can be called to test the client
 * subscription  with group_id
 * @param cls                Callback closure
 * @return Handle for the subscriber, NULL on error
 */
 */
struct GNUNET_SCRB_Subscriber*
GNUNET_SCRB_subscribe(struct GNUNET_CONFIGURATION_Handle *cfg,
		const struct GNUNET_HashCode* group_id,
		const struct GNUNET_HashCode* client_id,
		const struct GNUNET_SCRB_Credentials cred,
		GNUNET_SCRB_SubscribeFailedCallback subscrb_failed_cb,
		GNUNET_SCRB_SubscribeSuccessfullCallback subscrb_success_cb,
		GNUNET_SCRB_TestGroupSubscriptionCallback test_group_sbs_cb,
		GNUNET_ContinuationCallback cont_cb,
		void* cls);

/**
 * Get group subscribers.
 * @param cfg              Configuration handle
 * @param group_id         Id of the group to get subscribers from
 * @param cred             Credentials of the requesting entity
 * @param cont_cb          The function can be called to continue invocation
 * queue
 * @param cls              Callback closure
 * @return                 Pointer to array of subscribers, NULL on error
 */
struct GNUNET_SCRB_Subscriber*
GNUNET_SCRB_get_subscribers(struct GNUNET_CONFIGURATION_Handle *cfg,
		const struct GNUNET_HashCode* group_id,
		const struct GNUNET_SCRB_Credentials cred,
		GNUNET_ContinuationCallback cont_cb,
		void* cls);

/**
 * Functions with the signature are called whenever an unsubscribe request 
 * failed.
 * The client should retry the request or take an appropriate action.
 * @param cls              Callback closure
 * @param eh               Configuration handle
 * @param group_id         Id of the group to subscribe to
 * @param cred             Credentials of client subscribing to the group
 */
typedef void
(*GNUNET_SCRB_UnsubscribeFailedCallback)(void *cls,
				struct GNUNET_CONFIGURATION_Handle *cfg,
				const struct GNUNET_HashCode* group_id,
				const struct GNUNET_SCRB_Credentials cred);

/**
 * Functions with the signature are called whenever an unsubscirbe request is
 * successfull.
 * @param cls              Callback closure
 * @param eh               Configuration handle
 * @param group_id         Id of the group to subscribe to
 * @param cred             Credentials of client subscribing to the group
 */
typedef void
(*GNUNET_SCRB_UnsubscribeSuccessfullCallback)(void *cls,
				struct GNUNET_CONFIGURATION_Handle *cfg,
				const struct GNUNET_HashCode* group_id,
				const struct GNUNET_HashCode* client_id
				const struct GNUNET_SCRB_Credentials cred);


/**
 * Unsubscribe from a group.
 * @param cfg              Configuration handle
 * @param group_id         Id of the group to unsubscribe from
 * @param cred             Credentials of the entity unsubscribing from a topic
 * @param create_failed_cb The function can be called on the group creation
 * failure
 * @param create_success_cb The function can be called on the group creation
 * success
 * @param test_group_sbs_cb The function can be called to test the client
 * has been successfully subscribed to group with group_id
 * @param cls              Callback closure
 * @return Handle for the subscriber, NULL on error
 */
void
GNUNET_SCRB_unsubscribe(struct GNUNET_CONFIGURATION_Handle *cfg,
		const struct GNUNET_HashCode* group_id,
		const struct GNUNET_HashCode* client_id,
		const struct GNUNET_SCRB_Credentials cred,
		GNUNET_SCRB_UnsubscribeFailedCallback subscrb_failed_cb,
		GNUNET_SCRB_UnsubscribeSuccessfullCallback subscrb_success_cb,
		GNUNET_SCRB_TestGroupSubscriptionCallback test_group_sbs_cb,
		GNUNET_ContinuationCallback cont_cb,
		void* cls);

/**
 * Handle for a request to send a message to all group members
 */
struct GNUNET_SCRB_TransmitMulticastHandle;


/**
 * Publish a content.
 * @param cfg              Configuration handle
 * @param group_id         Id of the group to send a content
 * @param content          Content being sent by publisher
 * @param cred             Credentials of the entity publishing a content
 * @param cont_cb          Continuation callback
 */
struct GNUNET_SCRB_TransmitMulticastHandle*
GNUNET_SCRB_publish(
		struct GNUNET_CONFIGURATION_Handle *cfg,
		const struct GNUNET_HashCode* group_id,
		const struct GNUNET_SCRB_MulticastContent* content,
		const struct GNUNET_SCRB_Credentials cred,
		GNUNET_ContinuationCallback cont_cb,
		void* cls);

#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

#endif
