/*
 * ext_subscriber.h
 *
 *  Created on: May 30, 2014
 *      Author: root
 */

#ifndef SCRB_SUBSCRIBER_H_
#define SCRB_SUBSCRIBER_H_

GNUNET_NETWORK_STRUCT_BEGIN

struct GNUNET_SCRB_ServiceSubscription
{
	/**
	 * group id
	 */
	struct GNUNET_HashCode group_id;

	struct GNUNET_SCRB_ServiceSubscriber* sub_head;

	struct GNUNET_SCRB_ServiceSubscriber* sub_tail;
};


struct GNUNET_SCRB_ServiceSubscriber
{
	/**
	 * Client id
	 */
	struct GNUNET_HashCode cid;

	/**
	 * group id
	 */
	struct GNUNET_HashCode group_id;


	struct GNUNET_SCRB_ServiceSubscriber *prev;

	struct GNUNET_SCRB_ServiceSubscriber *next;

};

GNUNET_NETWORK_STRUCT_END


#endif /* SCRB_SUBSCRIBER_H_ */
