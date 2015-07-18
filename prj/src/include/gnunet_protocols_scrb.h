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
 * @file include/gnunet_protocols_scrb.h
 * @brief constants for network protocols
 * @author Xi
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
 * SCRB messages
 */


#define GNUNET_MESSAGE_TYPE_SCRB_SUBSCRIBE 32009

#define GNUNET_MESSAGE_TYPE_SCRB_SUBSCRIBE_ACK 32010

#define GNUNET_MESSAGE_TYPE_SCRB_SUBSCRIBE_FAIL 32011

#define GNUNET_MESSAGE_TYPE_SCRB_PUBLISH 32013

#define GNUNET_MESSAGE_TYPE_SCRB_PUBLISH_ACK 32014

#define GNUNET_MESSAGE_TYPE_SCRB_PUBLISH_FAIL 32015

#define GNUNET_MESSAGE_TYPE_SCRB_LEAVE 32016

#define GNUNET_MESSAGE_TYPE_SCRB_LEAVE_ACK 32017

#define GNUNET_MESSAGE_TYPE_SCRB_LEAVE_FAIL 32018

#define GNUNET_MESSAGE_TYPE_SCRB_SUBSCRIBE_SEND_PARENT 32019

#define GNUNET_MESSAGE_TYPE_SCRB_SEND_LEAVE_TO_PARENT 32020

#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

/* ifndef GNUNET_PROTOCOLS_H */
#endif
/* end of gnunet_protocols.h */
