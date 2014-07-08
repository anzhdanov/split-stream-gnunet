#include <unistd.h>
#include <gnunet/platform.h>
#include <gnunet/gnunet_util_lib.h>
#include <gnunet/gnunet_testbed_service.h>
#include "handle.h"
#include "../include/gnunet_scrb_service.h"
#include "gnunet/gnunet_crypto_lib.h"
#include "gnunet/gnunet_common.h"
#include "gnunet_protocols_scrb.h"
/* Number of peers we want to start */
#define NUM_PEERS 10

static struct GNUNET_HashCode publisher;

static int publisher_init = 0;

static GNUNET_SCHEDULER_TaskIdentifier shutdown_tid;

/**
 * Global result for testcase.
 */
static int result;

/**
 *
 */
struct SCRBPeer
{
	/**
	 * Prev reference in DLL.
	 */
	struct SCRBPeer *prev;

	/**
	 * Next reference in DLL.
	 */
	struct SCRBPeer *next;

	/**
	 * Handle with testbed.
	 */
	struct GNUNET_TESTBED_Peer *guardian;

	/**
	 * Testbed operation to connect to SCRB service.
	 */
	struct GNUNET_TESTBED_Operation *scrb_op;

  struct GNUNET_SCRB_Handle *scrb;

	unsigned int id;

};

/**
 * Head of DLL of peers we monitor closely.
 */
static struct SCRBPeer *peer_head;

/**
 * Tail of DLL of peers we monitor closely.
 */
static struct SCRBPeer *peer_tail;

/**
 * Handles to all of the running peers.
 */
static struct GNUNET_TESTBED_Peer **guardians;

/**
 * Function run on CTRL-C or shutdown (i.e. success/timeout/etc.).
 * Cleans up.
 */
static void
shutdown_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct SCRBPeer *peer;

	shutdown_tid = GNUNET_SCHEDULER_NO_TASK;
        
        while (NULL != (peer = peer_head))
        {
          if (NULL != peer->scrb_op)
            GNUNET_TESTBED_operation_done (peer->scrb_op);
          peer->scrb_op = NULL;
        }
	result = GNUNET_OK;
	GNUNET_SCHEDULER_shutdown (); /* Also kills the testbed */
}

static void
join_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
	struct GNUNET_SCRB_Handle *scrb_handle = cls;
	if(publisher_init == 1)
		GNUNET_SCRB_subscribe(scrb_handle, &publisher, scrb_handle->cid, NULL, NULL);
	else
		GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 10),
				&join_task, scrb_handle);
}

static void
multicast_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
	struct GNUNET_SCRB_Handle *scrb_handle = cls;
	struct GNUNET_SCRB_MulticastData msg;

	GNUNET_SCRB_request_multicast(scrb_handle, &publisher, &msg, NULL, NULL);
	GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 10),
			&multicast_task, scrb_handle);
}

void continuation_leave_cb(struct GNUNET_SCRB_Handle* scrb_handle)
{
	//leave the the group
	GNUNET_SCRB_request_leave(scrb_handle, scrb_handle->cid, NULL, NULL);
}

void continuation_multicast_cb(struct GNUNET_SCRB_Handle* scrb_handle)
{
	GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 10),
			&multicast_task, scrb_handle);
}

void continuation_join_cb(struct GNUNET_SCRB_Handle* scrb_handle)
{
	GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 10),
			&join_task, scrb_handle);
}

void continuation_create_cb(struct GNUNET_SCRB_Handle* scrb_handle)
{
	publisher = *scrb_handle->cid;
	publisher_init = 1;
	GNUNET_SCRB_request_create(scrb_handle, scrb_handle->cid, &continuation_multicast_cb, NULL);
}

/**
 * This is where the test logic should be, at least that
 * part of it that uses the DHT of peer "0".
 *
 * @param cls closure, for the example: NULL
 * @param op should be equal to "dht_op"
 * @param ca_result result of the connect operation, the
 *        connection to the DHT service
 * @param emsg error message, if testbed somehow failed to
 *        connect to the DHT.
 */
static void
service_connect_pub (void *cls,
		struct GNUNET_TESTBED_Operation *op,
		void *ca_result,
		const char *emsg)
{
	struct SCRBPeer* peer = cls;
        peer->scrb = ca_result;
	/* Service to DHT successful; here we'd usually do something
     with the DHT (ok, if successful) */
	GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
			"Connecting to peer %s \n",
			GNUNET_i2s (peer->scrb->cid));

	if(peer->id == 0)
		GNUNET_SCRB_request_id(peer->scrb, &continuation_create_cb, peer);
	else
		GNUNET_SCRB_request_id(peer->scrb, &continuation_join_cb, peer);

	//	GNUNET_SCRB_request_create(ext_handle, peer->id);

	//	GNUNET_SCRB_subscribe(ext_handle, peer->id);

	//	GNUNET_SCRB_request_multicast(ext_handle);
	/* for now, just indiscriminately terminate after 10s */
	//	GNUNET_SCHEDULER_cancel (shutdown_tid);
	//	shutdown_tid = GNUNET_SCHEDULER_add_delayed
	//			(GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 10),
	//					&shutdown_task, NULL);
}

/**
 * Testbed has provided us with the configuration to access one
 * of the peers and it is time to do "some" connect operation to
 * "some" subsystem of the peer.  For this example, we connect
 * to the SCRB subsystem.  Testbed doesn't know which subsystem,
 * so we need these adapters to do the actual connecting (and
 * possibly pass additional options to the subsystem connect
 * function, such as the "ht_len" argument for the DHT).
 *
 * @param cls closure
 * @param cfg peer configuration (here: peer[0]
 * @return NULL on error, otherwise some handle to access the
 *         subsystem
 */
static void *
scrb_connect (void *cls, const struct GNUNET_CONFIGURATION_Handle *cfg)
{
	/* Use the provided configuration to connect to service */
  return GNUNET_SCRB_connect (cfg);
}


/**
 * Dual of 'dht_ca' to perform the 'disconnect'/cleanup operation
 * once we no longer need to access this subsystem.
 *
 * @param cls closure
 * @param op_result whatever we returned from 'dht_ca'
 */
static void
scrb_disconnect (void *cls, void *op_result)
{
  struct SCRBPeer *peer = cls;
  /* Disconnect from SCRB service */
  GNUNET_SCRB_disconnect ((struct GNUNET_SCRB_Handle *) op_result);
  peer->scrb = NULL;
}


/**
 * Main function inovked from TESTBED once all of the
 * peers are up and running.  This one then connects
 * just to the DHT service of peer 0.
 *
 * @param cls closure
 * @param h the run handle
 * @param peers started peers for the test
 * @param num_peers size of the 'peers' array
 * @param links_succeeded number of links between peers that were created
 * @param links_failed number of links testbed was unable to establish
 */
static void
test_master (void *cls,
		struct GNUNET_TESTBED_RunHandle *h,
		unsigned int num_peers,
		struct GNUNET_TESTBED_Peer **peers,
		unsigned int links_succeeded,
		unsigned int links_failed)
{
	if (NULL == peers)
	{
		GNUNET_SCHEDULER_add_now (&shutdown_task, NULL);
	}

	guardians = peers;
	struct SCRBPeer* current_peer;
	unsigned int i;
	for(i = 0; i < num_peers; i++){
		current_peer = GNUNET_new(struct SCRBPeer);
		current_peer->guardian = guardians[i];
		current_peer->id = i;
		current_peer->scrb_op = 
                    GNUNET_TESTBED_service_connect
                    (NULL,      /* Closure for operation */
                     peers[i],  /* The peer whose service to connect to */
                     "scrb",    /* The name of the service */
                     service_connect_pub, /* callback to call after a handle to
                                                service is opened */
                     current_peer, /* closure for the above callback */
                     scrb_connect, /* callback to call with peer's
                                      configuration; this should open the needed
                                      service connection */
                     scrb_disconnect, /* callback to be called when closing the
                                         opened service connection */
                     current_peer); /* closure for the above two callbacks */
		GNUNET_CONTAINER_DLL_insert (peer_head, peer_tail, current_peer);
	}
	shutdown_tid = GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_MINUTES,
			&shutdown_task, NULL);
}


int
main (int argc, char **argv)
{
	int ret;

	result = GNUNET_SYSERR;
	ret = GNUNET_TESTBED_test_run
			("scrb-test",  /* test case name */
					"test_scrb_peer1.conf", /* template configuration */
					NUM_PEERS,       /* number of peers to start */
					0LL, /* Event mask - set to 0 for no event notifications */
					NULL, /* Controller event callback */
					NULL, /* Closure for controller event callback */
					&test_master, /* continuation callback to be called when testbed setup is
                        complete */
					NULL); /* Closure for the test_master callback */
	if ( (GNUNET_OK != ret) || (GNUNET_OK != result) )
		return 1;
	return 0;
}

