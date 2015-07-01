/*
     This file is part of GNUnet
     (C) 2010 Christian Grothoff (and other contributing authors)

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
#include "gnunet/platform.h"
#include "gnunet/gnunet_constants.h"
#include "gnunet/gnunet_hello_lib.h"
#include "gnunet/gnunet_block_plugin.h"
#include "gnunet/gnunet_block_lib.h"

/**
 * Function called to validate a reply or a request.  For
 * request evaluation, simply pass "NULL" for the reply_block.
 *
 * @param cls closure
 * @param type block type
 * @param query original query (hash)
 * @param bf pointer to bloom filter associated with query; possibly updated (!)
 * @param bf_mutator mutation value for @a bf
 * @param xquery extended query data (can be NULL, depending on type)
 * @param xquery_size number of bytes in @a xquery
 * @param reply_block response to validate
 * @param reply_block_size number of bytes in @a reply_block
 * @return characterization of result
 */
static enum GNUNET_BLOCK_EvaluationResult
block_plugin_scrb_evaluate (void *cls, enum GNUNET_BLOCK_Type type,
                           const struct GNUNET_HashCode * query,
                           struct GNUNET_CONTAINER_BloomFilter **bf,
                           int32_t bf_mutator, const void *xquery,
                           size_t xquery_size, const void *reply_block,
                           size_t reply_block_size)
{
    return GNUNET_BLOCK_EVALUATION_OK_MORE;
}


/**
 * Function called to obtain the key for a block.
 *
 * @param cls closure
 * @param type block type
 * @param block block to get the key for
 * @param block_size number of bytes @a block
 * @param key set to the key (query) for the given block
 * @return #GNUNET_OK on success, #GNUNET_SYSERR if type not supported
 *         (or if extracting a key from a block of this type does not work)
 */
static int
block_plugin_scrb_get_key (void *cls, enum GNUNET_BLOCK_Type type,
                          const void *block, size_t block_size,
                          struct GNUNET_HashCode * key)
{
    return GNUNET_OK;
}


/**
 * Entry point for the plugin.
 */
void *
libgnunet_plugin_block_scrb_init (void *cls)
{
  static enum GNUNET_BLOCK_Type types[] =
  {
    GNUNET_BLOCK_TYPE_DHT_HELLO,
    GNUNET_BLOCK_TYPE_ANY       /* end of list */
  };
  struct GNUNET_BLOCK_PluginFunctions *api;

  api = GNUNET_new (struct GNUNET_BLOCK_PluginFunctions);
  api->evaluate = block_plugin_scrb_evaluate;
  api->get_key = block_plugin_scrb_get_key;
  api->types = types;
  return api;
}


/**
 * Exit point from the plugin.
 */
void *
libgnunet_plugin_block_scrb_done (void *cls)
{
  struct GNUNET_TRANSPORT_PluginFunctions *api = cls;

  GNUNET_free (api);
  return NULL;
}

/* end of plugin_block_dht.c */
