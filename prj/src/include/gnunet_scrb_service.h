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
 * @author Xi
 */
#ifndef GNUNET_SCRB_SERVICE_H
#defineGNUNET_SCRB_SERVICE_H

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
 * Handle for a scribe client
 */
struct GNUNET_SCRB_Client;

/**
 * Handle for a scribe policy
 */
struct GNUNET_SCRB_Policy;

struct GNUNET_SCRB_MessageHeader
{
	/**
	 * Header for all multicast messages
	 */
	struct GNUNET_MessageHeader header;

    	/**
	 * Message priority
	 */
    	uint32_t message_priority GNUNET_PACKED;
	
	/**
	 * ECC signature of the message fragment
	 * Signature must match the public key of the topic
	 */
	struct GNUNET_CRYPTO_EddsaSignature signature;
	
	/**
	 * Purpose of the signature and size of the signed data
	 */
	struct GNUNET_CRYPTO_EccSignaturePurpose purpose;

    	/**
	 * Message id
	 */
    	uint64_t message_id GNUNET_PACKED;

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

enum GNUNET_SCRB_ContentType type
{
	RAW = 0;
};

/**
 * Content of a scribe message
 */
struct GNUNET_SCRB_Content
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
	enum GNUNET_SCRB_ContentType type;
};

/**
 * Route of the scribe message
 */
struct GNUNET_SCRB_RoutePath
{
	/**
	 * Path of the message
	 */
	struct GNUNET_PeerIdentity* path;
	/**
	 * Size of the path
	 */
	unsigned int path_length;
	/**
	 * Where we are on the path
	 */	
	unsigned int offset;
};


/**
 * Functions with the signature are called when an anycast is received for @a topic
 * which this client is interested in. The client should return whether or not
 * the anycast should continue.
 *
 * @param cls        The callback closure
 * @param group_key  Public key of the group the message was anycasted for
 * @param content    The content which was anycasted
 * @return           Whether the anycast should continue, true on acceptance
 */
typedef int
(*GNUNET_SCRB_ClientAnycastCallback)(void* cls,
				const struct GNUNET_CRYPTO_EddsaPublicKey* group_key,
				const struct GNUNET_SCRB_Content* content);

/**
 * Functions with the signature are called when a message is delivered for @a 
 * topic this client is interested in.
 *
 * @param group_key  Public key of the group the message was published to
 * @param content    The content which was published
 */
typedef void
(*GNUNET_SCRB_ClientDeliverCallback)(void* cls,
				const struct GNUNET_CRYPTO_EddsaPublicKey* group_key,
				const struct GNUNET_SCRB_Content* content);

/**
 * Functions with the signature are called which informs the client that
 * @a child is added to @a topic in which it is interested in.
 *
 * @param group_key  Public key of group the client is interested in
 * @param child      Identity of the child that was added
 */
typedef void
(*GNUNET_SCRB_ClientChildAddedCallback)(void* cls,
				const struct GNUNET_CRYPTO_EddsaPublicKey* group_key,
				const struct GNUNET_PeerIdentity* child);

/**
 * Functions with the signature are called which informs the client that
 * @a child has been removed from a topic with @a topic_id in which it was
 * interested in.
 *
 * @param group_key  Public key of the group the client is interested in
 * @param child      Identity of the child that was removed
 */
typedef void
(*GNUNET_SCRB_ClientChildRemovedCallback)(void* cls,
					const struct GNUNET_CRYPTO_EddsaPublicKey* group_key,
					const struct GNUNET_PeerIdentity* child);

/**
 * Functions with the signature are called when it is necessary to inform the
 * client that a subscribe operation on the given @a topic failed. The client
 * should retry the subscribe request or take an appropriate action.
 *
 * @param group_key      Public key of the group the subscribe operation failed
 */
typedef void
(*GNUNET_SCRB_ClientSubscribeFailedCallback)(void* cls,
					const struct GNUNET_CRYPTO_EddsaPublicKey* group_key);

/**
 * Functions with the signature are called which informs the client that
 * a subscribe on the given @a topic is successfull.
 *
 * @param group_key    Public key of the group the subscribe operation is successfull
 */
typedef void
(*GNUNET_SCRB_ClientSubscribeSuccessCallback)(void* cls,
					const struct GNUNET_CRYPTO_EddsaPublicKey* group_key);

/**
 * Functions with the signature are called when the client gets a response
 * for the service request
 *
 * @param cls    Operations closure
 * @param msg    Result of the request
 */
typedef void
(*GNUNET_SCRB_RequestResultCallback)(void* cls,
				const struct GNUNET_SCRB_MessageHeader* msg);

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
				GNUNET_SCRB_ClientUnicastCallback unicast_cb,
				GNUNET_SCRB_ClientDeliverCallback deliver_cb,
				GNUNET_SCRB_ClientChildAddedCallback child_added_cb,
				GNUNET_SCRB_ClientChildRemovedCallback child_removed_cb,
				GNUNET_SCRB_ClientSubscribeFailedCallback subs_fail_cb,
				GNUNET_SCRB_ClientSubscribeSuccessCallback subs_ack_cb,
				void* cb_cls,
				GNUNET_ContinuationCallback disconnect_cb,
				void* disconnect_cls);

/**
 * Unsubscribes the given @a client from the provided @a topics.
 *
 * In case the client was the last entity that has formed a subsription,
 * the topic is deleted from the root service.
 *
 * @param cfg              Configuration handle
 * @param topics           A pointer to the array of topics to unsubscribe from.
 * @param client           The client subscribing to the topics.
 * @param cls              Callback closure
 * @return Handle for the subscriber, NULL on error
 */
void
GNUNET_SCRB_unsubscribe(const struct GNUNET_CONFIGURATION_Handle *cfg,
		const struct GNUNET_SCRB_Topic** topics,
		size_t topic_num,
		const struct GNUNET_SCRB_Client* client,
		GNUNET_ContinuationCallback cont_cb,
		void* cls);

/**
 * Functions with the signature are used to make transmission messages for clients
 * publishing content to groups
 *
 * @param cls        Closure
 * @param data_size  The number of bytes initially available in @a data.
 * @param data       A buffer to write the message body with at most @a data_size bytes.
 * @return           The message size
 */
typedef size_t
(*GNUNET_SCRB_PublishTransmitNotify)(void* cls,
				size_t data_size, 
				void* data);

/**
 * Functions with the signature are used to make transmission messages for clients
 * anycasting content to group members
 *
 * @param cls        Closure
 * @param data_size  The number of bytes initially available in @a data.
 * @param data       A buffer to write the message body with at most @a data_size bytes.
 * @return           The message size
 */
typedef size_t
(*GNUNET_SCRB_AnycastTransmitNotify)(void* cls,
				size_t data_size, 
				void* data);

/**
 * Handle for a request to send a message to all group members
 */
struct GNUNET_SCRB_PublishTransmitHandle;

/**
 * Handle for a request to send anycast messages to group members
 */
struct GNUNET_SCRB_AnycastTransmitHandle;

/**
 * Publishes @a content to the given @a topic.
 *
 * @param cfg              Configuration handle
 * @param topic            The topic is content published to
 * @param content          Content to publish
 * @param notify_cb        The callback to make a publish request message
 * @param notify_cls       Closure for the notification callback
 * @param cont_cb          Continuation callback
 * @param cls              Closure for the continuation calllback
 */
struct GNUNET_SCRB_PublishTransmitHandle*
GNUNET_SCRB_publish(struct GNUNET_CONFIGURATION_Handle *cfg,
		const struct GNUNET_SCRB_Topic* topic,
		const struct GNUNET_SCRB_Content* content,
		GNUNET_SCRB_PublishTransmitNotify notify_cb,
		void* notify_cls,
		GNUNET_ContinuationCallback cont_cb,
		void* cls);

/**
 * Anycasts @a content to a member of the given @a topic.
 *
 * @param cfg              Configuration handle
 * @param topic            The topic to anycast
 * @param content          Content to anycast
 * @param notify_cb        The callback to make an anycast message
 * @param notify_cls       Closure for the notification callback
 * @param cont_cb          Continuation callback
 * @param cls              Closure for the continuation calllback
 */
struct GNUNET_SCRB_AnycastTransmitHandle*
GNUNET_SCRB_anycast(const struct GNUNET_CONFIGURATION_Handle *cfg,
		const struct GNUNET_SCRB_Topic* topic,
		const struct GNUNET_SCRB_Content* content,
		GNUNET_SCRB_AnycastTransmitNotify notify_cb,
		void* notify_cls,
		GNUNET_ContinuationCallback cont_cb,
		void* cls);

/**
 * Anycasts @a content to a member of the given @a topic.
 *
 * Hint helps to implement centralized mechanisms where the hint
 * is the cached root of the topic. It enables us to do more "effective"
 * anycast exploiting more portions of the scribe tree.
 *
 * @param cfg              Configuration handle
 * @param topic            The topic to anycast
 * @param content          Content to anycast
 * @param notify_cb        The callback to make an anycast message
 * @param notify_cls       Closure for the notification callback
 * @param cont_cb          Continuation callback
 * @param cls              Closure for the continuation calllback
 */
struct GNUNET_SCRB_AnycastTransmitHandle*
GNUNET_SCRB_anycast(const struct GNUNET_CONFIGURATION_Handle *cfg,
		const struct GNUNET_SCRB_Topic* topic,
		const struct GNUNET_SCRB_Content* content,
		const struct GNUNET_PeerIdentity* hint,
		GNUNET_SCRB_AnycastTransmitNotify notify_cb,
		void* notify_cls,
		GNUNET_ContinuationCallback cont_cb,
		void* cls);

/**
 * The function requests a root for the given @a topic
 *
 * @param cfg         Configuration
 * @param topic       Topic in question
 * @param get_root_cb A callback for the request
 */
void
GNUNET_SCRB_get_root(struct GNUNET_CONFIGURATION_Handle *cfg,
		const struct GNUNET_SCRB_Topic* topic,
		GNUNET_RequestResultCallback get_root_cb,
		void* cls);

/**
 * The function requests whether the service is a root for the given @a topic
 *
 * @param cfg        Configuration
 * @param topic      Topic in question
 * @param is_root_cb A callback for the request
 */
void
GNUNET_SCRB_is_root(struct GNUNET_CONFIGURATION_Handle *cfg,
		const struct GNUNET_SCRB_Topic* topic,
		GNUNET_RequestResultCallback is_root_cb,
		void* cls);

/**
 * The function requests children of the given @a topic
 *
 * @param cfg           Configuration
 * @param topic         Topic in question
 * @param get_chldrn_cb A callback for the request
 */
void
GNUNET_SCRB_get_children(const struct GNUNET_CONFIGURATION_Handle *cfg,
		const struct GNUNET_SCRB_Topic* topic,
		GNUNET_RequestResultCallback get_chldrn_cb,
		void* cls);

/**
 * Requests the parent node to a given @a topic
 *
 * @param cfg         Configuration
 * @param topic       Topic in question
 * @param get_prnt_cb A callback for the request
 */
void 
GNUNET_SCRB_get_parent(const struct GNUNET_CONFIGURATION_Handle *cfg,
		const struct GNUNET_SCRB_Topic* topic,
		GNUNET_RequestResultCallback get_prnt_cb,
		void* cls);

/**
 * Returns a list of topics the given @a client is subscribed to
 *
 * @param cfg    Configuration
 * @param topic  Topic in question
 */
struct GNUNET_SCRB_Topic*
GNUNET_SCRB_get_topics(const struct GNUNET_CONFIGURATION_Handle *cfg,
		const struct GNUNET_SCRB_Topic* topic,
		GNUNET_ContinuationCallback cont_cb,
		void* cls);

/**
 * Requests a number of children for the given @a topic
 *
 * @param cfg    Configuration
 * @param topic  Topic in question
 * @param cls    Closure
 */
void
GNUNET_SCRB_num_children(const struct GNUNET_CONFIGURATION_Handle *cfg,
		const struct GNUNET_SCRB_Topic* topic,
		void* cls);

/**
 * Requests clients connected to the local service
 *
 * @param cfg            Configuration
 * @param topic          Topic in question
 * @param get_clients_cb A callback for the request
 * @param cls            Closure
 */
void
GNUNET_SCRB_get_clients(const struct GNUNET_CONFIGURATION_Handle *cfg,
		const struct GNUNET_SCRB_Topic* topic,
		GNUNET_SCRB_RequestResultCallback get_clients_cb,
		void* cls);


/**
 * Requests the local service if it contains an entry for the given @a topic.
 *
 * @param cfg    Configuration
 * @param topic  Topic in question
 * @param cls    Closure
 */
void
GNUNET_SCRB_contains_topic(const struct GNUNET_CONFIGURATION_Handle *cfg,
		const struct GNUNET_SCRB_Topic* topic,
		GNUNET_SCRB_RequestResultCallback get_clients_cb,
		void* cls);


/**
 * Requests the local service if the given @a topic contains @a child
 *
 * @param cfg           Configuration
 * @param topic         Topic in question
 * @param child         Child in question
 * @param cont_child_cb The request callback
 * @param cls    Closure
 */
void
GNUNET_SCRB_contains_child(const struct GNUNET_CONFIGURATION_Handle *cfg,
		const struct GNUNET_SCRB_Topic* topic,
		const struct NodeHandle* child,
		GNUNET_SCRB_RequestResultCallback cont_child_cb,
		void* cls);

/**
 * Requests the local service for the current policy
 *
 * @param cfg           Configuration
 * @param get_plcy_cb   A callback for the request
 */
void
GNUNET_SCRB_get_policy(const struct GNUNET_CONFIGURATION_Handle *cfg,
					   GNUNET_SCRB_RequestResultCallback* get_plcy_cb,
		               void* cls);

/**
 * Sets the current policy for the scribe service
 *
 * @param cfg           Configuration
 * @param policy        A policy to be set on the service
 * @param get_plcy_cb   A callback for the request
 */
void
GNUNET_SCRB_set_policy(const struct GNUNET_CONFIGURATION_Handle *cfg,
					   const struct GNUNET_SCRB_Policy* policy,
					   GNUNET_SCRB_RequestResultCallback* set_plcy_cb,
		               void* cls);

/**
 * Requests the local service for the current environment
 *
 * @param cfg           Configuration
 * @param get_env_cb    A callback for the request
 */
void
GNUNET_SCRB_get_environment(const struct GNUNET_CONFIGURATION_Handle *cfg,
							GNUNET_SCRB_RequestResultCallback* get_env_cb,
							void* cls);


#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

#endif
