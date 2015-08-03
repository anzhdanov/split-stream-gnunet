#include "scrb_map.h"
#include <gnunet/gnunet_util_lib.h>

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

struct KnotList;

struct Knot
{
  struct GNUNET_PeerIdentity* peer;
  struct GNUNET_HashCode* grp_key_hash;
  struct KnotList* kl_head;
  struct KnotList* kl_tail;
};

struct KnotList
{
  struct Knot* knot;
  struct KnotList* prev;
  struct KnotList* next;
};

struct IteratorCls
{
  struct GNUNET_HashCode grp_key_hash;
  struct Knot* res;
};

static int
map_put_path_cb(void* cls, const struct GNUNET_HashCode* ph,
                void* knot)
{
  const struct IteratorCls* ic = cls;
  struct Knot* kn = knot;
  if(0 == memcmp(kn->grp_key_hash, &ic->grp_key_hash, sizeof(kn->grp_key_hash))
  {
    ic->res = knot;
  }
  return GNUNET_YES;
}

/**
 * Default implementation of the #GNUNET_SCRB_MapPutPath
 *
 * @param route_map    View(map) of the sribe service
 * @param grp_key_hash A hash of the group public key for which the path is put
 * @param path         A sequence of peers
 * @param path_length  The path length
 * @param cls          Closure
 * @return result of the operation
 */
int
default_map_put_path (struct GNUNET_SCRB_RouteMap* route_map,
  const struct GNUNET_HashCode* grp_key_hash,
	const struct GNUNET_PeerIdentity* path,
	unsigned int path_length,
	void* cls)
{
  struct Knot* knot = NULL;
  struct Knot* prev = NULL;
  int i;
  for(i = 0; i < path_length - 1; i++)
  {
    struct GNUNET_PeerIdentity* peer = &path[i];
    struct GNUNET_HashCode* ph = GNUNET_malloc(sizeof(*ph));
    GNUNET_CRYPTO_hash(start_peer, sizeof(*start_peer), ph);
    struct IteratorCls ic;
    memcpy(&ic.grp_key_hash, grp_key_hash, sizeof(*grp_key_hash));
    ic.res = NULL;
    if(NULL != route_map->map)
      GNUNET_CONTAINER_multihashmap_get_multiple(route_map->map, ph,
                                                 map_put_path_cb,
                                                 (void*)&ic);
    struct Knot* knot = ic.res;
    if(NULL == knot)
    {
      knot = GNUNET_malloc(sizeof(*knot));
      knot->peer = GNUNET_malloc(sizeof(*start_peer));
      memcpy(knot->peer, start_peer, sizeof(*start_peer));
      knot->grp_key_hash = GNUNET_malloc(sizeof(*grp_key_hash));
      memcpy(knot->grp_key_hash, grp_key_hash, sizeof(*grp_key_hash));
      GNUNET_CONTAINER_multihashmap_put (route_map->map, ph, knot,
                                         GNUNET_CONTAINER_MULTIHASHMAPOPTION_MULTIPLE);
    }
    
    if(NULL != prev)
    {
      struct KnotList* kl = GNUNET_malloc(sizeof(*kl));
      kl->knot = knot;
      GNUNET_CONTAINER_DLL_insert(prev->kl_head, prev->kl_tail, kl);
    } 
    prev = knot;    
  }      
  return 1;
}

/**
 * Default implementation of the #GNUNET_SCRB_MapRemovePath
 *
 * @param route_map    View(map) of the sribe service
 * @param grp_key_hash A hash of the group public key for which the path is removed
 * @param path         A sequence of peers
 * @param path_length  The path length
 * @param cls          Closure
 * @return result of the operation
 */
int
default_map_remove_path (struct GNUNET_SCRB_RouteMap* route_map,
  const struct GNUNET_HashCode* grp_key_hash,
	const struct GNUNET_PeerIdentity* path,
	unsigned int path_length,
	void* cls)
{
  struct Knot* knot = NULL;
  struct Knot* prev = NULL;
  int i;
  for(i = 0; i < path_length - 1; i++)
  {
    struct GNUNET_PeerIdentity* peer = &path[i];
    struct GNUNET_HashCode* ph = GNUNET_malloc(sizeof(*ph));
    GNUNET_CRYPTO_hash(start_peer, sizeof(*start_peer), ph);
    struct IteratorCls ic;
    memcpy(&ic.grp_key_hash, grp_key_hash, sizeof(*grp_key_hash));
    ic.res = NULL;
    if(NULL != route_map->map)
      GNUNET_CONTAINER_multihashmap_get_multiple(route_map->map, ph,
                                                 map_put_path_cb,
                                                 (void*)&ic);
    struct Knot* knot = ic.res;
    
    if(NULL != knot && NULL != prev)
    {
      struct KnotList* kl = prev->kl_head;
      while(NULL != kl)
      {
        if(0 == memcmp(kl->knot, knot, sizeof(*knot))
        {
          GNUNET_CONTAINER_DLL_remove(prev->kl_head, prev->kl_tail, kl);
          break;
        }
        kl = kl->next;
      }
    }
    if(NULL == knot->kl_head)//the knot does not have children
    {
      GNUNET_CONTAINER_multihashmap_remove(route_map->map, ph, knot);
      GNUNET_free(knot->peer);
      GNUNET_free(knot->grp_key_hash);
      GNUNET_free(knot);
    }
    prev = knot;    
  }
  return 1;      
}

/**
 * Default implementation of the #GNUNET_SCRB_MapContainPath
 *
 * @param route_map    View(map) of the sribe service
 * @param grp_key_hash A hash of the group public key for which the path is checked
 * @param path         A sequence of peers
 * @param path_length  The path length
 * @param cls          Closure
 * @return result of the operation
 */
int
default_map_contain_path (struct GNUNET_SCRB_RouteMap* route_map,
  const struct GNUNET_HashCode* grp_key_hash,
	const struct GNUNET_PeerIdentity* path,
	unsigned int path_length,
	void* cls)
{
  struct Knot* knot = NULL;
  struct Knot* prev = NULL;
  int i;
  for(i = 0; i < path_length - 1; i++)
  {
    struct GNUNET_PeerIdentity* peer = &path[i];
    struct GNUNET_HashCode* ph = GNUNET_malloc(sizeof(*ph));
    GNUNET_CRYPTO_hash(start_peer, sizeof(*start_peer), ph);
    struct IteratorCls ic;
    memcpy(&ic.grp_key_hash, grp_key_hash, sizeof(*grp_key_hash));
    ic.res = NULL;
    if(NULL != route_map->map)
      GNUNET_CONTAINER_multihashmap_get_multiple(route_map->map, ph,
                                                 map_put_path_cb,
                                                 (void*)&ic);
    struct Knot* knot = ic.res;
    
    if(NULL == knot)
      return 0;
    
    prev = knot;    
  }
  return 1;      
}

/**
 * A default implementation of #GNUNET_SCRB_MapGetPath.
 *
 * @param route_map    View(map) of the sribe service
 * @param grp_key_hash Hash of the group public key for which the path is built
 * @param start        Start node of the path
 * @param end          End node of the path
 * @param path         A pointer to an array to copy the path
 * @param path_length  Length of the path 
 */
void
default_map_get_path (struct GNUNET_SCRB_RouteMap* route_map,
  const struct GNUNET_HashCode* grp_key_hash,
	const struct GNUNET_PeerIdentity* start,
	const struct GNUNET_PeerIdentity* end,
	const struct GNUNET_PeerIdentity* path,
	unsigned int* path_length,
	void* cls)
{
  struct Knot* sn;
  struct GNUNET_HashCode sph;
  GNUNET_CRYPTO_hash(start, sizeof(*start), &sph);
  struct IteratorCls ic;
  memcpy(&ic.grp_key_hash, grp_key_hash, sizeof(*grp_key_hash));
  ic.res = NULL;
  if(NULL != route_map->map)
    GNUNET_CONTAINER_multihashmap_get_multiple(route_map->map, &sph,
                                                 map_put_path_cb,
                                                 (void*)&ic);
  sn = ic.res;
  if(NULL == sn)
    return;
  
  struct Knot* en;
  struct GNUNET_HashCode eph;
  GNUNET_CRYPTO_hash(end, sizeof(*end), &eph);
  ic.res = NULL;
  if(NULL != route_map->map)
    GNUNET_CONTAINER_multihashmap_get_multiple(route_map->map, &eph,
                                                 map_put_path_cb,
                                                 (void*)&ic);
  en = ic.res;
  if(NULL == en)
    return;
  
  struct KnotList* kl_head;
  struct KnotList* kl_tail;
  
  find_path_helper(sn, en, kl_head, kl_tail);
  size_t size = 0;
  struct KnotList* kl = kl_head;
  while(NULL != kl)
  {
    size++;
    kl = kl->next;
  }
  
  path = GNUNET_malloc(size * sizeof(struct GNUNET_PeerIdentity));
  *path_length = size;
  int i = 0;
  kl = kl_head;
  while(NULL != kl)
  {
    memcpy(&path[i++], kl->knot->peer, sizeof(struct GNUNET_PeerIdentity));
    kl = kl->next;
  }  
}


/**
 * A recursive helper function to find a path
 * depth-first
 */
int
find_path_helper(const struct Knot* start,
                const struct Knot* end,
                struct KnotList* kl_head,
                struct KnotList* kl_tail)
{
  if(0 == memcmp(start, end, sizeof(struct Knot)))
    return 1;
   
  struct KnotList* kl = start->kl_head;
  while(NULL != kl)
  {
    if(1 == find_path_helper(kl->knot, end, kl_head, kl_tail)
    {
      GNUNET_CONTAINER_DLL_insert(prev->kl_head, prev->kl_tail, kl);
      return 1;
    }
    kl = kl->next;
  }
  return 0;
}



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
						  void* cls)
{
  struct GNUNET_SCRB_RouteMap *map = GNUNET_malloc(sizeof(*map));
  map->map = GNUNET_CONTAINER_multihashmap_create(1, GNUNET_YES);
  map->map_put_path_cb = map_put_path_cb;
  map->map_remove_path_cb = map_remove_path_cb;
  map->map_contain_path_cb = map_contain_path_cb;
  map->map_get_path_cb = map_get_path_cb;
  map->cls = cls;
  return map;
}

struct GNUNET_SCRB_RouteMap*
GNUNET_SCRB_create_route_map_def()
{
  return GNUNET_SCRB_create_route_map(&default_map_put_path,
	            &default_map_remove_path,
	            &default_map_contain_path,
	            &default_map_get_path,
						  NULL);  
}
