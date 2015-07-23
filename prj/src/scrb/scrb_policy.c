#include "scrb_policy.h"
#include <stdlib.h>
#include <string.h>

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
	void* cls;
	/**
	 * A maximum number of children
	 */
	uint64_t max_children;
		
};

struct PeerList
{
	struct GNUNET_PeerIdentity* peer;
	struct PeerList* prev;
	struct PeerList* next;
};

/**
 * Implementation of allow subscribe for the default policy
 *
 * @param policy       Scribe policy
 * @param source       Identity of the child
 * @param group_key    A public key of the group
 * @param content      Content that came with the message
 * @param cls          Closure
 * @return 1 if the source is accepted, 0 otherwise.
 */
 */
int
default_policy_allow_subscribe(const struct GNUNET_SCRB_Policy* policy,
	const struct GNUNET_PeerIdentity* source,
	const struct GNUNET_CRYPTO_PublicKey* group_key,
	const struct GNUNET_SCRB_Content* content,
	void* cls)
{
	//TO-DO: implement the policy
	return 1;
};

/**
 * Shuffles @a path in a random order
 */
void
shuffle(struct GNUNET_PeerIdentity* path,
	size_t path_length)
{
	int i;
	for(i = 0; i < path_length; i++)
	{
		int r = rand() % path_length;
		struct GNUNET_PeerIdentity temp = *(path + i);
		*(path + i) = *(path + r);
		*(path + r) = temp;
	}	
};

/**
 * Copies @a children to the message in a random order and appends @a parent.
 */
void
default_direct_anycast(const struct GNUNET_SCRB_Policy* policy,
	struct GNUNET_SCRB_AnycastMessage* msg,
	const struct GNUNET_PeerIdentity* parent,
	const struct GNUNET_PeerIdentity** children,
	size_t child_num,
	void* cls)
{
	
	struct GNUNET_SCRB_RoutePath* to_visit = &msg.to_visit;
	struct GNUNET_PeerIdentity*
		path = GNUNET_malloc((child_num + 1) * sizeof(struct GNUNET_PeerIdentity));
	int path_length = child_num + 1;
	struct GNUNET_PeerIdentity* p;
	for(p = path; p < path + child_num; p++)
	{
		memcpy(p,*children++, sizeof(*p));
	}
	
	shuffle(path, child_num);

	if(NULL != parent)
	{
		memcpy(++p, parent, sizeof(*p));
		memcpy(&to_visit->path[0], path, sizeof(*path));
		to_visit->path_length = path_length;
	}else
	{
		--path_length;
		memcpy(to_visit->path, path, child_num * sizeof(*p);
		to_visit->path_length = path_length;
	}
};

void
default_policy_child_added (const struct GNUNET_SCRB_Policy* policy
	const struct GNUNET_CRYPTO_PublicKey* group_key,
	const struct GNUNET_PeerIdentity* child,
	void* cls)
{
	//TO-DO: implement
};

void
default_policy_child_removed (const struct GNUNET_SCRB_Policy* policy
	const struct GNUNET_CRYPTO_PublicKey* group_key,
	const struct GNUNET_PeerIdentity* child,
	void* cls)
{
	//TO-DO: implement
};

void
default_policy_recv_anycast_fail (const struct GNUNET_SCRB_Policy* policy,
	const struct GNUNET_CRYPTO_PublicKey* group_key,	
	const struct GNUNET_PeerIdentity* failed_at_node,
	const struct GNUNET_SCRB_Content* content,
	void* cls)
{
	//TO-DO: implement
};

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
						  void* cls	)
{
	struct GNUNET_SCRB_Policy* policy = GNUNET_malloc(sizeof(*policy));
	policy->type = type;
	policy->allow_subs_cb = allow_subs_cb;
	policy->direct_anycst_cb = direct_anycst_cb;
	policy->child_added_cb = child_added_cb;
	policy->child_removed_cb = child_removed_cb;
	policy->recv_anycst_fail_cb = recv_anycst_fail_cb;
	policy->cls = cls;	
};

struct GNUNET_SCRB_Policy*
	GNUNET_SCRB_create_default_policy()
{
	return GNUNET_SCRB_create_policy(DEFAULT,
									 &default_policy_allow_subscribe,
									 &default_policy_direct_anycast,
									 &default_policy_child_added,
									 &default_policy_child_removed,
									 &default_policy_recv_anycast_fail, 
									 NULL);

};

