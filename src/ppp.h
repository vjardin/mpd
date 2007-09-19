
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

#ifdef __DragonFly__
#include <netgraph/ppp/ng_ppp.h>
#else
#include <netgraph/ng_ppp.h>
#endif

#include "defs.h"

/*
 * DEFINITIONS
 */

  /* Do our own version of assert() so it shows up in the logs */
  #define assert(e)	((e) ? (void)0 : DoAssert(__FILE__, __LINE__, #e))

  /* Giant Mutex handling */
  #define GIANT_MUTEX_LOCK()	assert(pthread_mutex_lock(&gGiantMutex) == 0)
  #define GIANT_MUTEX_UNLOCK()	assert(pthread_mutex_unlock(&gGiantMutex) == 0)

  #define MUTEX_LOCK(m)		assert(pthread_mutex_lock(&m) == 0)
  #define MUTEX_UNLOCK(m)	assert(pthread_mutex_unlock(&m) == 0)

  #define RWLOCK_RDLOCK(m)	assert(pthread_rwlock_rdlock(&m) == 0)
  #define RWLOCK_WRLOCK(m)	assert(pthread_rwlock_wrlock(&m) == 0)
  #define RWLOCK_UNLOCK(m)	assert(pthread_rwlock_unlock(&m) == 0)
  
  #define SETOVERLOAD(q)	do {					\
				    int t = (q);			\
				    if (t > 60) {			\
					gOverload = 100;		\
				    } else if (t > 10) {		\
					gOverload = (t - 10) * 2;	\
				    } else {				\
					gOverload = 0;			\
				    }					\
				} while (0)

  #define OVERLOAD()		(gOverload > (random() % 100))
  
  #define REF(p)		do {					\
				    (p)->refs++;			\
				} while (0)

  #define UNREF(p)		do {					\
				    if ((--(p)->refs) == 0)		\
					Freee(NULL, p);			\
				} while (0)

  #define RESETREF(v, p)	do {					\
				    if (v) UNREF(v);			\
				    (v) = (p);				\
				    if (v) REF(v);			\
				} while (0)

  #define ADLG_WAN_AUTHORIZATION_FAILURE	0
  #define ADLG_WAN_CONNECTED			1
  #define ADLG_WAN_CONNECTING			2
  #define ADLG_WAN_CONNECT_FAILURE		3
  #define ADLG_WAN_DISABLED			4
  #define ADLG_WAN_MESSAGE			5
  #define ADLG_WAN_NEGOTIATION_FAILURE		6
  #define ADLG_WAN_WAIT_FOR_DEMAND		7

#ifndef NG_PPP_STATS64
  /* internal 64 bit counters as workaround for the 32 bit 
   * limitation for ng_ppp_link_stat
   */
  struct ng_ppp_link_stat64 {
	u_int64_t 	xmitFrames;	/* xmit frames on link */
	u_int64_t 	xmitOctets;	/* xmit octets on link */
	u_int64_t 	recvFrames;	/* recv frames on link */
	u_int64_t	recvOctets;	/* recv octets on link */
	u_int64_t 	badProtos;	/* frames rec'd with bogus protocol */
	u_int64_t 	runts;		/* Too short MP fragments */
	u_int64_t 	dupFragments;	/* MP frames with duplicate seq # */
	u_int64_t	dropFragments;	/* MP fragments we had to drop */
  };
#endif

#include "bund.h"
#include "link.h"
#include "rep.h"
#include "phys.h"
#include "msgdef.h"

/*
 * VARIABLES
 */

  extern Rep		*gReps;			/* Repeaters */
  extern Link		*gLinks;		/* Links */
  extern Bund		*gBundles;		/* Bundles */

  extern int		gNumReps;		/* Total number of repeaters */
  extern int		gNumLinks;		/* Total number of links */
  extern int		gNumBundles;		/* Total number of bundles */
  extern struct console	gConsole;
  extern struct web	gWeb;
  extern int		gBackground;
  extern int		gShutdownInProgress;
  extern int		gOverload;
  extern pid_t		gPid;
  extern int		gRouteSeq;

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

