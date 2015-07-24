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
 * @file scrb/gnunet-scrb.c
 * @brief scrb tool
 * @author 
 */
#include <gnunet/platform.h>
#include <gnunet/gnunet_util_lib.h>
#include "../include/gnunet_scrb_service.h"
#include "gnunet/gnunet_dht_service.h"

static int ret;

/**
 * Main function that will be run by the scheduler.
 *
 * @param cls closure
 * @param args remaining command-line arguments
 * @param cfgfile name of the configuration file used (for saving, can be NULL!)
 * @param cfg configuration
 */
static void
run (void *cls,
		char *const *args,
		const char *cfgfile,
		const struct GNUNET_CONFIGURATION_Handle *cfg)
{
	/*main code*/
}

/**
 * The main function to ext.
 *
 * @param argc number of arguments from the command line
 * @param argv command line arguments
 * @return 0 ok, 1 on error
 */
int
main (int argc, char *const *argv)
{
	static const struct GNUNET_GETOPT_CommandLineOption options[] = {
		/* FIXME: add options here */	
	GNUNET_GETOPT_OPTION_END
	};
//	if(GNUNET_OK != GNUNET_STRINGS_get_ut8_args (argc, argv, &argc, &argv))
//		return 2;
	return (GNUNET_OK ==
			GNUNET_PROGRAM_run (argc, argv, "gnunet-scrb",
								gettext_noop ("help text"), options, &run,
								NULL)) ? ret : 1;
	GNUNET_free((void*) argv);
	return ret;
}

/* end of gnunet-scrb.c */
