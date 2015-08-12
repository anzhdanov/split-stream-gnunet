#ifndef SCRB_POLICY_H_
#define SCRB_POLICY_H_

#include <stdint.h>
#include "gnunet/platform.h"
#include "gnunet/gnunet_crypto_lib.h"
#include "gnunet/gnunet_util_lib.h"
#include "../include/gnunet_scrb_service.h"
#include "scrb.h"

struct GNUNET_SCRB_Policy;

/**
 * Policy type
 */
enum GNUNET_SCRB_PolicyType
{
  DEFAULT, LIMITED
};

/**
 * The function is called when @a source is about to become our child
 * and the @a policy should return whether or not the child should be allow-
 * ed to become our child. If the length of clients and children is both 0,
 * allowing the child to join will have the effect of implicitly subscribing
 * the node to the group with the given @a group_key.
 *
 * @param policy       Scribe policy
 * @param source       Identity of the child
 * @param group_key    A public key of the group
 * @param content      Content that came with the message
 * @param cls          Closure
 * @return 1 if the source is accepted, 0 otherwise.
 */
typedef int 
(*GNUNET_SCRB_PolicyAllowSubscribe) (const struct GNUNET_SCRB_Policy* policy,
									 const struct GNUNET_PeerIdentity* source,
									 const struct GNUNET_CRYPTO_EddsaPublicKey* group_key,
									 const struct GNUNET_CONTAINER_MultiHashMap* groups,
									 const struct GNUNET_SCRB_Content* content,
									 void* cls);

/**
 * The method is called when an anycast received which is not satisfied
 * at the local node. This method should add both the @a parent and @a child
 * to the anycast's to-search list, but this method allows different policies
 * concerning the order of the adding as well as selectively adding nodes.
 * 
 * @param policy     Our current policy
 * @param msg        The anycast message in question
 * @param parent     Current parent of the group the message is anycasted
 * @param children   Our current children for the group
 * @param child_num  The number of children in the group
 * @param cls        Closure
 */
typedef void
(*GNUNET_SCRB_PolicyDirectAnycast) (const struct GNUNET_SCRB_Policy* policy,
									struct GNUNET_SCRB_AnycastMessage* msg,
									const struct GNUNET_PeerIdentity* parent,
									struct GNUNET_PeerIdentity** children,
									size_t child_num,
									void* cls);

/**
 * The method with the signature is called when it is necessary to get the
 * next peer to visit from the anycast message. The peer is removed from the
 * to visit list.
 * 
 * @param policy     Our current policy
 * @param msg        The anycast message in question
 * @param cls        Closure
 * @return next peer on the path according to the @a policy
 */
typedef struct GNUNET_PeerIdentity*
(*GNUNET_SCRB_PolicyGetNextAnycast) (const struct GNUNET_SCRB_Policy* policy,
									 struct GNUNET_SCRB_AnycastMessage* msg,
									 void* cls);

/**
 * Informs the @a policy that @a child was added to a group with the given
 * @a group_key. The @a policy is free to ignore the call.
 *
 * @param policy     Our current policy
 * @param group_key  A public key of the group
 * @param child      Identity of the child
 * @param cls        Closure
 */
typedef void
(*GNUNET_SCRB_PolicyChildAdded) (const struct GNUNET_SCRB_Policy* policy,
								 const struct GNUNET_CRYPTO_EddsaPublicKey* group_key,
								 const struct GNUNET_PeerIdentity* child,
								 void* cls);

/**
 * Informs the @a policy that @a child was removed from a group with the given
 * @a group_key. The @a policy is free to ignore the call.
 *
 * @param policy     Our current policy
 * @param group_key  A public key of the group
 * @param child      Identity of the child
 * @param cls        Closure
 */
typedef void
(*GNUNET_SCRB_PolicyChildRemoved) (const struct GNUNET_SCRB_Policy* policy,
								   const struct GNUNET_CRYPTO_EddsaPublicKey* group_key,
								   const struct GNUNET_PeerIdentity* child,
								   void* cls);

/**
 * Notifies the policy about a failure for an anycast
 * 
 * @param policy          Our current policy
 * @param group_key       A public key of the group
 * @param failed_at_node  Identity of the node where the anycast failed
 * @param content         Content of the message
 * @param cls             Closure   
 */
typedef void
(*GNUNET_SCRB_PolicyRecvAnycastFail) (const struct GNUNET_SCRB_Policy* policy,
									  const struct GNUNET_CRYPTO_EddsaPublicKey* group_key,	
									  const struct GNUNET_PeerIdentity* failed_at_node,
									  const struct GNUNET_SCRB_Content* content,
									  void* cls);

/**
 * Creates a scribe policy with parameters specified in the call
 *
 * @param type                The policy type @see GNUNET_SCRB_PolicyType
 * @param allows_subs_cb      The callback for allow subscription
 * @param direct_anycst_cb    The callback for the direct anycast
 * @param child_added_cb      The callback which is called on child adding
 * @param child_removed_cb    The callback which is called on child removal
 * @param recv_anycst_fail_cb The callback which is called on receive of anycast failure
 * @param cls                 Closure 
 */
struct GNUNET_SCRB_Policy*
GNUNET_SCRB_create_policy(enum GNUNET_SCRB_PolicyType type,
						  GNUNET_SCRB_PolicyAllowSubscribe allow_subs_cb,
						  GNUNET_SCRB_PolicyDirectAnycast direct_anycst_cb,
						  GNUNET_SCRB_PolicyChildAdded    child_added_cb,
						  GNUNET_SCRB_PolicyChildRemoved  child_removed_cb,
						  GNUNET_SCRB_PolicyRecvAnycastFail recv_anycst_fail_cb,
						  GNUNET_SCRB_PolicyGetNextAnycast  get_next_anycst_cb,
						  void* cls	);
/**
 * Create a default policy with default parameters
 */
struct GNUNET_SCRB_Policy*
GNUNET_SCRB_create_default_policy();

/**
 * Handle for the scribe policy
 */
struct GNUNET_SCRB_Policy
{	
	/**
	 * The policy type
	 */
	enum GNUNET_SCRB_PolicyType type;
	
	GNUNET_SCRB_PolicyAllowSubscribe allow_subs_cb;
	GNUNET_SCRB_PolicyDirectAnycast  direct_anycst_cb;
	GNUNET_SCRB_PolicyChildAdded     child_added_cb;
	GNUNET_SCRB_PolicyChildRemoved   child_removed_cb;
	GNUNET_SCRB_PolicyRecvAnycastFail recv_anycst_fail_cb;
	GNUNET_SCRB_PolicyGetNextAnycast  get_next_anycst_cb;
	void* cls;
	/**
	 * A maximum number of children
	 */
	uint64_t max_children;
		
};


#endif
