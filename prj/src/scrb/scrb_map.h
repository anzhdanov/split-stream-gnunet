
#ifndef MAP_H_
#define MAP_H_

#include <stdint.h>
#include "gnunet/platform.h"
#include "gnunet/gnunet_crypto_lib.h"
#include "gnunet/gnunet_util_lib.h"
/**
 * A handle for a service view.
 */
struct GNUNET_SCRB_RouteMap;

/**
 * Functions with the signatures are called to put path in the
 * @a route_map for a group with the provided @a grp_key_hash.
 *
 * @param route_map    View(map) of the sribe service
 * @param grp_key_hash A hash of the group public key for which the path is insert
 * @param path         A sequence of peers
 * @param path_length  The path length
 * @param cls          Closure
 * @return result of the operation
 */
typedef int
(*GNUNET_SCRB_MapPutPath) (struct GNUNET_SCRB_RouteMap* route_map,
                           const struct GNUNET_HashCode* grp_key_hash,
	                       const struct GNUNET_PeerIdentity* path,
 	                       unsigned int path_length,
	                       void* cls);

/**
 * Functions with the signatures are called to remove path from the
 * @a route_map for a group with the provided @a grp_key_hash.
 *
 * @param route_map    View(map) of the sribe service
 * @param grp_key_hash Hash of the group public key for which the path is removed.
 * @param path         A sequence of peers
 * @param path_length  The path length
 * @param cls          Closure
 * @return result of the operation
 */
typedef int
(*GNUNET_SCRB_MapRemovePath) (struct GNUNET_SCRB_RouteMap* route_map,
                              const struct GNUNET_HashCode* grp_key_hash,
	                          const struct GNUNET_PeerIdentity* path,
	                          unsigned int path_length,
	                          void* cls);
	
/**
 * Functions with the signatures are called to check if the path is
 * contained in the @a route_map for a group with the provided @a grp_key_hash.
 *
 * @param route_map    View(map) of the sribe service
 * @param grp_key_hash Hash of the group public key for which the path is checked
 * @param path         A sequence of peers
 * @param path_length  The path length
 * @param cls          Closure
 * @return result of the operation
 */
typedef int
(*GNUNET_SCRB_MapContainPath) (struct GNUNET_SCRB_RouteMap* route_map,
                               const struct GNUNET_HashCode* grp_key_hash,
	                           const struct GNUNET_PeerIdentity* path,
	                           unsigned int path_length,
	                           void* cls);
	
/**
 * Functions with the signatures are called to get a path for the provided
 * @a start and @a end nodes for a group with the provided @a grp_key.
 *
 * @param route_map    View(map) of the sribe service
 * @param grp_key_hash Hash of the group public key for which the path is built
 * @param start        Start node of the path
 * @param end          End node of the path
 * @param path         A pointer to an array to copy the path
 * @param path_length  Length of the path 
 */
typedef void
(*GNUNET_SCRB_MapGetPath) (struct GNUNET_SCRB_RouteMap* route_map,
                           const struct GNUNET_HashCode* grp_key_hash,
                           const struct GNUNET_PeerIdentity* start,
                           const struct GNUNET_PeerIdentity* end,
                           struct GNUNET_PeerIdentity* path,
                           unsigned int* path_length,
                           void* cls);

/**
 * Creates a scribe route map
 *
 * @param map_put_path_cb       The callback to put a path in the map
 * @param map_remove_path_cb    The callback for the direct anycast
 * @param map_contain_path_cb   The callback to check if the path is contained in the map
 * @param map_get_path_cb       The callback to get a path from the map
 * @param cls                 Closure 
 */
struct GNUNET_SCRB_RouteMap*
GNUNET_SCRB_create_route_map(GNUNET_SCRB_MapPutPath map_put_path_cb,
                             GNUNET_SCRB_MapRemovePath map_remove_path_cb,
                             GNUNET_SCRB_MapContainPath map_contain_path_cb,
                             GNUNET_SCRB_MapGetPath map_get_path_cb,
                             void* cls);

struct GNUNET_SCRB_RouteMap*
GNUNET_SCRB_create_route_map_def();

/**
 * Handle for the route map
 */
struct GNUNET_SCRB_RouteMap
{
  struct GNUNET_CONTAINER_MultiHashMap* map;
  
	GNUNET_SCRB_MapPutPath map_put_path_cb;
	GNUNET_SCRB_MapRemovePath map_remove_path_cb;
	GNUNET_SCRB_MapContainPath map_contain_path_cb;
	GNUNET_SCRB_MapGetPath map_get_path_cb;
	
	void* cls;
};

#endif
