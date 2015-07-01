/*
 * multicast.h
 *
 *  Created on: Jun 6, 2014
 *      Author: azhdanov
 */

#ifndef MULTICAST_H_
#define MULTICAST_H_

struct GNUNET_SCRB_MulticastData
{
	/**
	 * Data of the multicast message
	 */
	char data[1024];
};

#endif /* MULTICAST_H_ */
