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

enum GNUNET_SCRB_ContentType
{
  MSG, ANYCAST_MSG, MULTICAST_MSG, DHT_PUT
};

/**
 * Content of a scribe message
 */
struct GNUNET_SCRB_Content
{
  /**
   * Data
   */
  char* data;
  /**
   * Size
   */
  size_t data_size;
  /**
   * Content
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
 * Functions with the signature are called when an anycast is received for the group
 * which this client is subscribed. The client should return whether or not the
 * anycast should continue.
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
 * Functions with the signature are called when a message is delivered for a group
 * the client is subscribed.
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
 * @a child is added to the @a group which the client is subscribed.
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
 * @a child has been removed from a group with @a group_key the client is
 * subscribed.
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
 * client that a subscribe operation for a group with the given @a group_key
 * failed. The client should retry the subscribe request or take an appropriate action.
 *
 * @param group_key      Public key of the group the subscribe operation failed
 */
typedef void
(*GNUNET_SCRB_ClientSubscribeFailedCallback)(void* cls,
											 const struct GNUNET_CRYPTO_EddsaPublicKey* group_key);

/**
 * Functions with the signature are called which informs the client that
 * a subscription to the group with the given @a group_key is successfull.
 *
 * @param group_key    Public key of the group the subscribe operation is successfull
 */
typedef void
(*GNUNET_SCRB_ClientSubscribeSuccessCallback)(void* cls,
											  const struct GNUNET_CRYPTO_EddsaPublicKey* group_key);

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
 * The API does not have a particular create/destroy group methods. The function-
 * ality allows to create groups implicitly.
 *
 * @param cfg                   Configuration handle
 * @param pub_key               Public key of the group to be subscribed
 * @param client_key            A private key of the client to sign messages
 * @param content               Content that should be included in the subscribe
 * message
 * @param anycast_cb            The function is called when the client receives
 * an anycast message
 * @param deliver_cb            The function is called when the client receives
 * a message for a group it is subscribed
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
					  GNUNET_SCRB_ClientAnycastCallback unicast_cb,
					  GNUNET_SCRB_ClientDeliverCallback deliver_cb,
					  GNUNET_SCRB_ClientChildAddedCallback child_added_cb,
					  GNUNET_SCRB_ClientChildRemovedCallback child_removed_cb,
					  GNUNET_SCRB_ClientSubscribeFailedCallback subs_fail_cb,
					  GNUNET_SCRB_ClientSubscribeSuccessCallback subs_ack_cb,
					  void* cb_cls,
					  GNUNET_ContinuationCallback disconnect_cb,
					  void* disconnect_cls);

/**
 * Unsubscribes the given @a client from the group with the provided @a group_key.
 *
 * @param cfg              Configuration handle
 * @param group_key        A public key of the group.
 * @param client           The client subscribing to the group.
 * @param cls              Callback closure
 * @return Handle for the subscriber, NULL on error
 */
void
GNUNET_SCRB_unsubscribe(const struct GNUNET_CONFIGURATION_Handle *cfg,
						const struct GNUNET_CRYPTO_EddsaPublicKey* group_key,
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
 * Publishes @a content to a group with the given @a group_key.
 *
 * @param cfg              Configuration handle
 * @param group_key        A public key of the group the content is published to
 * @param content          Content to publish
 * @param notify_cb        The callback to make a publish request message
 * @param notify_cls       Closure for the notification callback
 * @param cont_cb          Continuation callback
 * @param cls              Closure for the continuation calllback
 */
struct GNUNET_SCRB_PublishTransmitHandle*
GNUNET_SCRB_publish(struct GNUNET_CONFIGURATION_Handle *cfg,
					const struct GNUNET_CRYPTO_EddsaPublicKey* group_key,
					const struct GNUNET_SCRB_Content* content,
					GNUNET_SCRB_PublishTransmitNotify notify_cb,
					void* notify_cls,
					GNUNET_ContinuationCallback cont_cb,
					void* cls);

/**
 * Anycasts @a content to a member of a group with the given @a group_key.
 *
 * @param cfg              Configuration handle
 * @param group_key        A public key of the group the content is anycasted to
 * @param content          Content to anycast
 * @param notify_cb        The callback to make an anycast message
 * @param notify_cls       Closure for the notification callback
 * @param cont_cb          Continuation callback
 * @param cls              Closure for the continuation calllback
 */
struct GNUNET_SCRB_AnycastTransmitHandle*
GNUNET_SCRB_anycast(const struct GNUNET_CONFIGURATION_Handle *cfg,
					const struct GNUNET_CRYPTO_EddsaPublicKey* group_key,
					const struct GNUNET_SCRB_Content* content,
					GNUNET_SCRB_AnycastTransmitNotify notify_cb,
					void* notify_cls,
					GNUNET_ContinuationCallback cont_cb,
					void* cls);

/**
 * Anycasts @a content to a member of a group with the given @a group_key.
 *
 * In the scibe original api: "Hint helps to implement centralized mechanisms
 * where the hint is the cached root of the topic. It enables us to do more
 * "effective" anycast exploiting more portions of the scribe tree."
 *
 * @param cfg              Configuration handle
 * @param group_key        A public key of the group the content is anycasted
 * @param content          Content to anycast
 * @param notify_cb        The callback to make an anycast message
 * @param notify_cls       Closure for the notification callback
 * @param cont_cb          Continuation callback
 * @param cls              Closure for the continuation calllback
 */
struct GNUNET_SCRB_AnycastTransmitHandle*
GNUNET_SCRB_anycast_hint(const struct GNUNET_CONFIGURATION_Handle *cfg,
						 const struct GNUNET_CRYPTO_EddsaPublicKey* group_key,
						 const struct GNUNET_SCRB_Content* content,
						 const struct GNUNET_PeerIdentity* hint,
						 GNUNET_SCRB_AnycastTransmitNotify notify_cb,
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
