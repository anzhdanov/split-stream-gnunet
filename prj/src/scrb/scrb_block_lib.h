
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

enum GNUNET_BLOCK_SCRB_Type
{
  GNUNET_BLOCK_SCRB_TYPE_JOIN = 334
};

GNUNET_NETWORK_STRUCT_BEGIN

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

GNUNET_NETWORK_STRUCT_END

#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

#endif
