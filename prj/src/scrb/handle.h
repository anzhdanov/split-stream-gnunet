/*
 * handle.h
 *
 *  Created on: Jun 27, 2014
 *      Author: root
 */

#ifndef HANDLE_H_
#define HANDLE_H_

#include "gnunet_scrb_service.h"

struct GNUNET_SCRB_Handle
{
	const struct GNUNET_CONFIGURATION_Handle *cfg;

	struct GNUNET_CLIENT_Connection *client;

	struct GNUNET_CLIENT_TransmitHandle *th;

	struct GNUNET_MQ_Handle *mq;

	void (*cb)();

	void *cb_cls;

	struct GNUNET_HashCode* cid;
};

#endif /* HANDLE_H_ */
