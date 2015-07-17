/*
 * scrb_block_lib.h
 *
 *  Created on: May 24, 2014
 *      Author: root
 */

#ifndef SCRB_BLOCK_LIB_H_
#define SCRB_BLOCK_LIB_H_

#ifdef __cplusplus
extern "C"
{
#if 0
/* keep Emacsens' auto-indent happy */
}
#endif
#endif

#include <gnunet/platform.h>
#include <gnunet/gnunet_util_lib.h>
#include <gnunet/gnunet_core_service.h>
#include "gnunet/gnunet_dht_service.h"
#include "scrb_multicast.h"

enum GNUNET_BLOCK_SCRB_Type
{

	GNUNET_BLOCK_SCRB_TYPE_CREATE = 333,

	GNUNET_BLOCK_SCRB_TYPE_JOIN = 334,

	GNUNET_BLOCK_SCRB_TYPE_MULTICAST = 335,

	GNUNET_BLOCK_SCRB_TYPE_LEAVE = 336

};

GNUNET_NETWORK_STRUCT_BEGIN

struct GNUNET_BLOCK_SCRB_Create{
	/**
	 * Service id
	 */
	struct GNUNET_PeerIdentity sid;
	/**
	 * Client id
	 */
	struct GNUNET_HashCode cid;
};

/**
 * Join block for DHT messages
 */
struct GNUNET_BLOCK_SCRB_Join
{
	struct GNUNET_CRYPTO_EddsaPublicKey gr_pub_key;
	
	struct GNUNET_HashCode gr_pub_key_hash;

	struct GNUNET_CRYPTO_EddsaPrivateKey cl_pr_key;
	
	struct GNUNET_CRYPTO_EddsaPublicKey cl_pub_key;
	
	struct GNUNET_HashCode cl_pub_key_hash;

	struct GNUNET_PeerIdentity src;
	
	struct GNUNET_HashCode src_hash;
	
	struct GNUNET_SCRB_Content content;
	
};

struct GNUNET_BLOCK_SCRB_Leave{

	/**
	 * Client id
	 */
	struct GNUNET_HashCode sid;

	/**
	 * Group id
	 */
	struct GNUNET_HashCode group_id;
};


struct GNUNET_BLOCK_SCRB_Multicast{

	struct GNUNET_HashCode group_id;

	struct GNUNET_SCRB_MulticastData data;

	int last;
};

GNUNET_NETWORK_STRUCT_END

void
deliver (void *cls,
		enum GNUNET_BLOCK_Type type,
		unsigned int path_length,
		const struct GNUNET_PeerIdentity *path,
		const struct GNUNET_HashCode *key,
		const void *data,
		size_t size);

void
forward (void *cls,
		enum GNUNET_BLOCK_Type type,
		unsigned int path_length,
		const struct GNUNET_PeerIdentity *path,
		const struct GNUNET_HashCode *key,
		const void *data,
		size_t size);



#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

#endif
