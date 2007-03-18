
/*
 * ppp.h
 *
 * Written by Archie Cobbs <archie@freebsd.org>
 * Copyright (c) 1995-1999 Whistle Communications, Inc. All rights reserved.
 * See ``COPYRIGHT.whistle''
 */

#ifndef _PPP_H_
#define _PPP_H_

/* Keep source files simple */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <poll.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <sys/queue.h>
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <stddef.h>
#include <stdarg.h>
#include <string.h>
#include <signal.h>
#include <ctype.h>
#include <unistd.h>
#include <errno.h>
#include <err.h>
#include <netdb.h>
#include <fcntl.h>
#include <machine/endian.h>
#ifdef __DragonFly__
#include <net/ppp_layer/ppp_defs.h>
#else
#include <net/ppp_defs.h>
#endif
#include <netinet/in.h>
#include <arpa/inet.h>

#include <pthread.h>
#include <pdel/structs/structs.h>
#include <pdel/structs/type/array.h>
#include <pdel/util/typed_mem.h>
#include <pdel/util/pevent.h>
#include <pdel/util/paction.h>
#include <pdel/util/ghash.h>


#include "defs.h"

/*
 * DEFINITIONS
 */

  /* Do our own version of assert() so it shows up in the logs */
  #define assert(e)	((e) ? (void)0 : DoAssert(__FILE__, __LINE__, #e))

  /* Giant Mutex handling */
  #define GIANT_MUTEX_LOCK()	assert(pthread_mutex_lock(&gGiantMutex) == 0)
  #define GIANT_MUTEX_UNLOCK()	assert(pthread_mutex_unlock(&gGiantMutex) == 0)

  #define ADLG_WAN_AUTHORIZATION_FAILURE	0
  #define ADLG_WAN_CONNECTED			1
  #define ADLG_WAN_CONNECTING			2
  #define ADLG_WAN_CONNECT_FAILURE		3
  #define ADLG_WAN_DISABLED			4
  #define ADLG_WAN_MESSAGE			5
  #define ADLG_WAN_NEGOTIATION_FAILURE		6
  #define ADLG_WAN_WAIT_FOR_DEMAND		7

  /* internal 64 bit counters as workaround for the 32 bit 
   * limitation for ng_ppp_link_stat
   */
  struct linkstats {
	u_int64_t 	xmitFrames;	/* xmit frames on link */
	u_int64_t 	xmitOctets;	/* xmit octets on link */
	u_int64_t 	recvFrames;	/* recv frames on link */
	u_int64_t	recvOctets;	/* recv octets on link */
	u_int64_t 	badProtos;	/* frames rec'd with bogus protocol */
	u_int64_t 	runts;		/* Too short MP fragments */
	u_int64_t 	dupFragments;	/* MP frames with duplicate seq # */
	u_int64_t	dropFragments;	/* MP fragments we had to drop */
  };
  typedef struct linkstat *LinkStats;

#include "bund.h"
#include "link.h"
#include "rep.h"
#include "phys.h"
#include "msgdef.h"

/*
 * VARIABLES
 */

  extern PhysInfo	*gPhyses;		/* Physes */
  extern Rep		*gReps;			/* Repeaters */
  extern Bund		*gBundles;		/* Bundles */

  extern int		gNumPhyses;		/* Total number of phys */
  extern int		gNumReps;		/* Total number of repeaters */
  extern int		gNumBundles;		/* Total number of bundles */
  extern struct console	gConsole;
  extern ConsoleSession	gConsoleSession;	/* currently active console-session */
  extern struct web	gWeb;
  extern int		gBackground;
  extern int		gShutdownInProgress;
  extern pid_t		gPid;

  extern struct globalconf	gGlobalConf;	/* Global config settings */

  extern struct pevent_ctx	*gPeventCtx;
  extern pthread_mutex_t	gGiantMutex;	/* Giant Mutex */

  extern const char	*gVersion;		/* Program version string */
  extern const char	*gConfigFile;		/* Main config file */
  extern const char	*gConfDirectory;	/* Where the files are */

/*
 * FUNCTIONS
 */

  extern void		Greetings(void);
  extern void		SendSignal(int sig);
  extern void		DoExit(int code);
  extern void		DoAssert(const char *file, int line, const char *x);

#endif

