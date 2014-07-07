/*
     This file is part of GNUnet.
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
 * @file include/gnunet_protocols_ext.h
 * @brief constants for network protocols
 * @author 
 */

#ifndef GNUNET_PROTOCOLS_SCRB_H
#define GNUNET_PROTOCOLS_SCRB_H

#ifdef __cplusplus
extern "C"
{
#if 0                           /* keep Emacsens' auto-indent happy */
}
#endif
#endif

/**
 * EXT message
 */
#define GNUNET_MESSAGE_TYPE_EXT 32000

#define GNUNET_MESSAGE_TYPE_EXT_P2P_GET 32001

#define GNUNET_MESSAGE_TYPE_EXT_P2P_PUT 32002

#define GNUNET_MESSAGE_TYPE_EXT_ORIGIN_START 32003

#define GNUNET_MESSAGE_TYPE_SCRB_ID_REQUEST 32004

#define GNUNET_MESSAGE_TYPE_SCRB_ID_REPLY 32005

#define GNUNET_MESSAGE_TYPE_SCRB_CREATE_REQUEST 32006

#define GNUNET_MESSAGE_TYPE_SCRB_CREATE_REPLY 32007

#define GNUNET_MESSAGE_TYPE_SCRB_SERVICE_LIST_REQUEST 32008

#define GNUNET_MESSAGE_TYPE_SCRB_SERVICE_LIST_REPLY 32009

#define GNUNET_MESSAGE_TYPE_SCRB_SUBSCRIBE_REQUEST 32011

#define GNUNET_MESSAGE_TYPE_SCRB_SUBSCRIBE_REPLY 32012

#define GNUNET_MESSAGE_TYPE_SCRB_MULTICAST 32013

#define GNUNET_MESSAGE_TYPE_SCRB_LEAVE_REQUEST 32014

#define GNUNET_MESSAGE_TYPE_SCRB_LEAVE_REPLY 32015

#define GNUNET_MESSAGE_TYPE_SCRB_SUBSCRIBE_SEND_PARENT 32016

#define GNUNET_MESSAGE_TYPE_SCRB_SEND_LEAVE_TO_PARENT 32017

#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

/* ifndef GNUNET_PROTOCOLS_H */
#endif
/* end of gnunet_protocols.h */
