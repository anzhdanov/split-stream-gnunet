/*
      This file is part of GNUnet
      (C) 2012-2013 Christian Grothoff (and other contributing authors)

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
/**
 * @file scrb/scrb.h
 * @brief example IPC messages between SCRB API and GNS service
 * @author Matthias Wachs
 */

#ifndef SCRB_H
#define SCRB_H

#include "gnunet_scrb_service.h"
#include <stdint.h>
#include "scrb_publisher.h"
#include "scrb_subscriber.h"
#include "scrb_multicast.h"

GNUNET_NETWORK_STRUCT_BEGIN


struct GNUNET_SCRB_ClientCreate
{
	struct GNUNET_SCRB_MessageHeader header;
	/**
	 * group id, hash of client
	 */
	struct GNUNET_HashCode group_id;
};


struct GNUNET_SCRB_ServiceReplyIdentity
{
	struct GNUNET_MessageHeader header;
	/**
	 * peer identity of service
	 */
	struct GNUNET_PeerIdentity sid;
	/**
	 * client hash code
	 */
	struct GNUNET_HashCode cid;
};

struct GNUNET_SCRB_ServiceReplyCreate
{
	struct GNUNET_MessageHeader header;
	/**
	 * rendevouz point
	 */
	struct GNUNET_PeerIdentity rp;
	/**
	 * client id
	 */
	struct GNUNET_HashCode cid;
	/**
	 * status
	 */
	unsigned int status;
};

struct GNUNET_SCRB_ServiceReplySubscribe
{
	struct GNUNET_PeerIdentity pid;

	struct GNUNET_MessageHeader header;
	/**
	 * group id
	 */
	struct GNUNET_HashCode group_id;
	/**
	 * client id
	 */
	struct GNUNET_HashCode cid;
	/**
	 * status
	 */
	unsigned int status;
};


struct GNUNET_SCRB_RegisterService
{
	struct GNUNET_MessageHeader header;
	/**
	 * Publisher id
	 */
	struct GNUNET_HashCode pid;
};

/**
 * Message for client requesting a service list
 */
struct GNUNET_SCRB_ClntRqstSrvcLst
{
	struct GNUNET_MessageHeader header;

	struct GNUNET_HashCode cid;
};

struct GNUNET_SCRB_SrvcRplySrvcLst
{
	struct GNUNET_MessageHeader header;

	struct GNUNET_SCRB_ServicePublisher pub;

	uint16_t size;
};

struct GNUNET_SCRB_ClntSbscrbRqst
{
	struct GNUNET_MessageHeader header;

	struct GNUNET_HashCode group_id;

	struct GNUNET_HashCode client_id;
};

struct GNUNET_SCRB_UpdateSubscriber
{
	struct GNUNET_MessageHeader header;

	struct GNUNET_HashCode group_id;

	struct GNUNET_SCRB_MulticastData data;

	int last;
};

struct GNUNET_SCRB_UnicastMessage
{
	struct GNUNET_SCRB_MessageHeader header;

	char type;

	struct GNUNET_SCRB_UnicastData data;

	struct GNUNET_HashCode group_id;

	struct GNUNET_HashCode source_id;

	int last;
};


struct GNUNET_SCRB_ClntRqstLv
{
	struct GNUNET_MessageHeader header;
	/**
	 * Client id
	 */
	struct GNUNET_HashCode cid;
	/**
	 * Group id
	 */
	struct GNUNET_HashCode group_id;
};

struct GNUNET_SCRB_ServiceReplyLeave
{
	struct GNUNET_MessageHeader header;
	/**
	 * group id
	 */
	struct GNUNET_HashCode group_id;
	/**
	 * client id
	 */
	struct GNUNET_HashCode cid;
};

struct GNUNET_SCRB_SendParent2Child
{
	struct GNUNET_MessageHeader header;
	/**
	 * group id
	 */
	struct GNUNET_HashCode group_id;
	/**
	 * client id
	 */
	struct GNUNET_PeerIdentity parent;

	struct GNUNET_HashCode cid;
};

struct GNUNET_SCRB_SendLeaveToParent
{
	struct GNUNET_MessageHeader header;
	/**
	 * group id
	 */
	struct GNUNET_HashCode group_id;
	/**
	 * client id
	 */
	struct GNUNET_HashCode sid;
};


GNUNET_NETWORK_STRUCT_END
#endif
