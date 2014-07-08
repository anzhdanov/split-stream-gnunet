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
 * @file ext/gnunet-ext.c
 * @brief ext tool
 * @author 
 */
#include <gnunet/platform.h>
#include <gnunet/gnunet_util_lib.h>
#include "gnunet_scrb_service.h"
#include "gnunet/gnunet_dht_service.h"

static int ret;

static uint32_t source;

static uint32_t node;


/**
 * Handle to the service
 */

static struct GNUNET_SCRB_Handle *handle;


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
	//ret = 0;
	handle = GNUNET_SCRB_connect(cfg);

	if(NULL == handle)
		goto error;

	GNUNET_SCRB_request_id(handle, NULL, NULL);

	if(source != 0){
		publish(handle);
		//GNUNET_SCRB_request_create(handle, source);
	}

	if(node != 0){
		request_list_and_subscribe(handle);
		//GNUNET_SCRB_request_create(handle, source);
	}

	error:
	GNUNET_SCHEDULER_shutdown ();
	ret = 1;
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
			{'s', "source", NULL,
					gettext_noop("the flag shows that the client is a source"), 0,
					&GNUNET_GETOPT_set_one, &source},
					{'n', "node", NULL,
							gettext_noop("the flag shows that the client is a node"), 0,
							&GNUNET_GETOPT_set_one, &node},
							GNUNET_GETOPT_OPTION_END
	};
	return (GNUNET_OK ==
			GNUNET_PROGRAM_run (argc,
					argv,
					"gnunet-scrb [options [value]]",
					gettext_noop
					("scrb"),
					options, &run, NULL)) ? ret : 1;
}

/* end of gnunet-scrb.c */
