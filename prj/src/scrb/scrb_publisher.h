/*
 * ext_publisher.h
 *
 *  Created on: May 30, 2014
 *      Author: root
 */

#ifndef SCRB_PUBLISHER_H_
#define SCRB_PUBLISHER_H_


GNUNET_NETWORK_STRUCT_BEGIN

struct GNUNET_SCRB_ServicePublisher
{
	struct GNUNET_HashCode group_id;
	/**
	 * rendevouz point
	 */
	struct GNUNET_PeerIdentity rp;
};


GNUNET_NETWORK_STRUCT_END


#endif /* SCRB_PUBLISHER_H_ */
