/*
      This file is part of GNUnet
      (C) 

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
 * @file include/gnunet_ext_service.h
 * @brief API to the ext service
 * @author Christian Grothoff
 */
#ifndef GNUNET_SCRB_SERVICE_H
#define GNUNET_SCRB_SERVICE_H

#include "gnunet/platform.h"
#include "gnunet/gnunet_arm_service.h"
#include "gnunet/gnunet_core_service.h"
#include "gnunet/gnunet_getopt_lib.h"
#include "gnunet/gnunet_os_lib.h"
#include "gnunet/gnunet_program_lib.h"
#include "gnunet/gnunet_scheduler_lib.h"
#include "gnunet/gnunet_transport_service.h"
#include "../scrb/scrb.h"


#ifdef __cplusplus
extern "C"
{
#if 0                           /* keep Emacsens' auto-indent happy */
}
#endif
#endif

/**
 * Version of the scrb API.
 */
#define GNUNET_SCRB_VERSION 0x00000000

struct GNUNET_SCRB_Handle;

struct PeerContext
{
	struct GNUNET_CONFIGURATION_Handle *cfg;
	struct GNUNET_CORE_Handle *ch;
	struct GNUNET_PeerIdentity id;
	struct GNUNET_TRANSPORT_Handle *th;
	struct GNUNET_TRANSPORT_GetHelloHandle *ghh;
	struct GNUNET_MessageHeader *hello;
	int connect_status;
	struct GNUNET_OS_Process *arm_proc;
};

/**
 * the client sends a request to service to start a group
 */
void GNUNET_SCRB_request_create(
		struct GNUNET_SCRB_Handle *eh,
		const struct GNUNET_HashCode* group_id,
		void (*cb)(),
		void* cb_cls);

/**
 * connects a client to Scribe service
 * parameters:
 * 		cfg - configuration handle
 */
struct GNUNET_SCRB_Handle *
GNUNET_SCRB_connect (const struct GNUNET_CONFIGURATION_Handle *cfg);
/**
 * disconnects a client from Scribe service
 */
void
GNUNET_SCRB_disconnect (struct GNUNET_SCRB_Handle *eh);

void
GNUNET_SCRB_request_id(
		struct GNUNET_SCRB_Handle *eh,
		void (*cb)(),
		void* cb_cls);

void
GNUNET_SCRB_subscribe(
		struct GNUNET_SCRB_Handle *eh,
		const struct GNUNET_HashCode* group_id,
		const struct GNUNET_HashCode* cid,
		void (*cb)(),
		void* cb_cls);

void
GNUNET_SCRB_request_multicast(
		struct GNUNET_SCRB_Handle *eh,
		const struct GNUNET_HashCode* group_id,
		const struct GNUNET_SCRB_UpdateSubscriber *msg,
		void (*cb)(),
		void* cb_cls);

void
GNUNET_SCRB_request_service_list(struct GNUNET_SCRB_Handle *eh);

void
GNUNET_SCRB_request_leave(
		struct GNUNET_SCRB_Handle *eh,
		const struct GNUNET_HashCode* group_id,
		void (*cb)(),
		void* cb_cls);

void multicast(struct GNUNET_SCRB_Handle* eh);

void publish(struct GNUNET_SCRB_Handle* eh);

void leave(struct GNUNET_SCRB_Handle* eh);

void request_list_and_subscribe(struct GNUNET_SCRB_Handle* eh);


#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

#endif
