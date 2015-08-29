/*
  This file is part of GNUnet
  (C) 2012-2013 Christian Grothoff (and other contributing authors)

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
 * @file scrb/scrb.h
 * @brief scrb messages
 * @author Alexander Zhdanov
 */

#ifndef SCRB_H
#define SCRB_H

#include "../include/gnunet_scrb_service.h"
#include <stdint.h>
#include <gnunet/gnunet_crypto_lib.h>

GNUNET_NETWORK_STRUCT_BEGIN

/**
 * Type of the group scribe message.
 */
enum GNUNET_SCRB_GroupMessageType
{
  GRP_SUBSCRIBE,
  GRP_SUBSCRIBE_ACK,
  GRP_SUBSCRIBE_FAIL,
  GRP_ANYCAST,
  GRP_ANYCAST_FAIL,
  GRP_PUBLISH
};

/**
 * A header for all scribe messages.
 */ 
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
   * The group the message is propagated
   */
  struct GNUNET_CRYPTO_EddsaPublicKey grp_key;
    
  /**
   * The source address
   */
  struct GNUNET_PeerIdentity src;
  
  /**
   * The destination address
   */
  struct GNUNET_PeerIdentity dst;
  
  /**
   * uinque id
   */
  struct GNUNET_HashCode id;

  /**
   * Message id
   */
  uint64_t message_id GNUNET_PACKED;

  /**
   * Type of the group message
   */
  enum GNUNET_SCRB_GroupMessageType mtype;  
	
  /**
   * Followed by the message body
   */
    
};


/**
 * A subscribe message
 */
struct GNUNET_SCRB_SubscribeMessage
{
  /**
   * The message header
   */
  struct GNUNET_SCRB_MessageHeader header;
  /**
   * Public key of the group the client would like to
   * subscribe to
   */
  struct GNUNET_CRYPTO_EddsaPublicKey group_key;

  /**
   * The client's private key
   */
  struct GNUNET_CRYPTO_EddsaPrivateKey client_key;
  /**
   * Content of the subscribe message
   */
  struct GNUNET_SCRB_Content content;
};

/**
 * Parent sends its identity to child
 */
struct GNUNET_SCRB_SubscribeParentMessage
{
  /**
   * The message header
   */
  struct GNUNET_SCRB_MessageHeader header;
  /**
   * Identity of the parent
   */
  struct GNUNET_PeerIdentity parent;
  /**
   * Group key
   */
  struct GNUNET_CRYPTO_EddsaPublicKey grp_key;
  /**
   * Group key hash
   */
  struct GNUNET_HashCode grp_key_hash;
};

/**
 *  Envelope for subscribe ack/fail messages
 */
struct GNUNET_SCRB_DownStreamMessage
{
  /**
   * The message header
   */
  struct GNUNET_SCRB_MessageHeader header;
  
  /**
   * The group the message is propagated
   */
  struct GNUNET_CRYPTO_EddsaPublicKey grp_key;
    
  /**
   * The source address
   */
  struct GNUNET_PeerIdentity src;
  
  /**
   * The destination address
   */
  struct GNUNET_PeerIdentity dst; 

  /**
   * Content of the downstream message
   */	
  struct GNUNET_SCRB_Content content;
  
  /**
   * uinque id
   */
  struct GNUNET_HashCode id;
};

/**
 * Subscribe ack message
 */
struct GNUNET_SCRB_SubscribeAckMessage
{
  /**
   * Header of the message
   */
  struct GNUNET_SCRB_MessageHeader header;
  /**
   * Path to the root of the group
   */
  struct GNUNET_SCRB_RoutePath path_to_root;

  /**
   * The group for which the acknowledgement is sent
   */
  struct GNUNET_CRYPTO_EddsaPublicKey grp_key;
  
  /**
   * Public group key hash
   */	
  struct GNUNET_HashCode grp_key_hash;
	
  /**
   * Initiator of the request
   */
  struct GNUNET_PeerIdentity requestor;
};

/**
 * Subscribe fail message
 */
struct GNUNET_SCRB_SubscribeFailMessage
{
  /**
   * The message header
   */
  struct GNUNET_SCRB_MessageHeader header;
	
  /**
   * Public key of the group
   */	
  struct GNUNET_CRYPTO_EddsaPublicKey grp_key;
	
  /**
   * Public group key hash
   */	
  struct GNUNET_HashCode grp_key_hash;
  
  /**
   * Initiator of the request
   */
  struct GNUNET_PeerIdentity requestor;
	
};


struct GNUNET_SCRB_AnycastMessage
{
  /**
   * Header of the message
   */
  struct GNUNET_SCRB_MessageHeader header;
	
  /**
   * Public key of the group the message is anycasted
   */
  struct GNUNET_CRYPTO_EddsaPublicKey group_key;
	
  /**
   * Anycast message content
   */	
  struct GNUNET_SCRB_Content content;
	
  /**
   * Nodes the message has visited
   */
  struct GNUNET_SCRB_RoutePath visited;
	
  /**
   * Nodes the message is going to visit
   */
  struct GNUNET_SCRB_RoutePath to_visit;
  
  /**
   * Path to requestor
   */
  struct GNUNET_SCRB_RoutePath pth_to_rq;
  
  /**
   * Source of the subscribe request
   */
  struct GNUNET_PeerIdentity ssrc;
  
  /**
   * Source of the anycast message
   */
  struct GNUNET_PeerIdentity asrc;
  
  /**
   * Initial source of the anycast message
   */
  struct GNUNET_PeerIdentity iasrc;  	
};

struct GNUNET_SCRB_ClientAnycastMessage
{
  /**
   * Header of the message
   */
  struct GNUNET_SCRB_MessageHeader header;
	
  /**
   * Public key of the group the message is anycasted
   */
  struct GNUNET_CRYPTO_EddsaPublicKey group_key;
	
  /**
   * Anycast message content
   */	
  struct GNUNET_SCRB_Content content;
  
  /**
   * Source of the message
   */
  struct GNUNET_PeerIdentity src; 

};

struct GNUNET_SCRB_AnycastFailMessage
{
  /**
   * Header of the message
   */
  struct GNUNET_SCRB_MessageHeader header;
	
  /**
   * Public key of the group the message is anycasted
   */
  struct GNUNET_CRYPTO_EddsaPublicKey group_key;
	
  /**
   * Anycast message content
   */	
  struct GNUNET_SCRB_Content content;
  
  /**
   * Source of the message
   */
  struct GNUNET_PeerIdentity src; 
};


struct GNUNET_SCRB_ChildChangeEventMessage
{
  /**
   * The message header
   */
  struct GNUNET_SCRB_MessageHeader header;

  /**
   * Public key of the group
   */	
  struct GNUNET_CRYPTO_EddsaPublicKey grp_key;

  /**
   * Identity of the child
   */	
  struct GNUNET_PeerIdentity child;	
};



GNUNET_NETWORK_STRUCT_END
#endif
