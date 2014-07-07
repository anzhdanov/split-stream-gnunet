/*
 * scrb_group.h
 *
 *  Created on: May 30, 2014
 *      Author: root
 */

#ifndef SCRB_GROUP_H_
#define SCRB_GROUP_H_

#include <gnunet/platform.h>
#include <gnunet/gnunet_util_lib.h>
#include <gnunet/gnunet_core_service.h>
#include "gnunet/gnunet_dht_service.h"
#include "gnunet/gnunet_crypto_lib.h"

GNUNET_NETWORK_STRUCT_BEGIN

struct GNUNET_SCRB_GroupSubscriber{
	/**
	 * id of the group the client subscribes for
	 */
	struct GNUNET_HashCode group_id;
	/**
	 * The last on the path
	 */
	struct GNUNET_PeerIdentity sid;

	/**
	 * id of the originator
	 */
	struct GNUNET_PeerIdentity oid;
	/**
	 * Service id hash
	 */
	struct GNUNET_HashCode sidh;
	/**
	 * Message queue handle
	 */
	struct GNUNET_MQ_Handle* mq_o;

	/**
	 * Message queue handle
	 */
	struct GNUNET_MQ_Handle* mq_l;
	/**
	 * Id of client which subscribes to the group
	 */
	struct GNUNET_HashCode cid;
	/**
	 *	Previous entry
	 */
	struct GNUNET_SCRB_GroupSubscriber* prev;

	/**
	 *	Next entry
	 */
	struct GNUNET_SCRB_GroupSubscriber* next;
};

struct GNUNET_SCRB_Group{
	/**
	 * Service id
	 */
	struct GNUNET_PeerIdentity sid;

	/**
	 * group id
	 */
	struct GNUNET_HashCode group_id;

	/**
	 * group id
	 */
	struct GNUNET_HashCode cid;
	/**
	 * Message queue handle
	 */
	struct GNUNET_MQ_Handle* mq;

	/**
	 * Head of group subscribers list
	 */
	struct GNUNET_SCRB_GroupSubscriber *group_head;

	/**
	 * Tail of group subscribers list
	 */
	struct GNUNET_SCRB_GroupSubscriber *group_tail;
};

struct GNUNET_SCRB_GroupParent
{
	/**
	 * Group id
	 */
	struct GNUNET_HashCode group_id;

	/**
	 * Group id
	 */
	struct GNUNET_PeerIdentity parent;

	/**
	 * Message queue handle
	 */
	struct GNUNET_MQ_Handle* mq;
};

GNUNET_NETWORK_STRUCT_END

#endif /* EXT_GROUP_H_ */
