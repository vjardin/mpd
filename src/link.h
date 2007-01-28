
/*
 * link.h
 *
 * Written by Archie Cobbs <archie@freebsd.org>
 * Copyright (c) 1995-1999 Whistle Communications, Inc. All rights reserved.
 * See ``COPYRIGHT.whistle''
 */

#ifndef _LINK_H_
#define _LINK_H_

#include "defs.h"
#include "proto.h"
#include "lcp.h"
#include "ip.h"
#include "mp.h"
#include "vars.h"
#include "auth.h"
#include "fsm.h"
#include "mbuf.h"
#include "phys.h"
#include "vars.h"
#ifdef __DragonFly__
#include <netgraph/ppp/ng_ppp.h>
#else
#include <netgraph/ng_ppp.h>
#endif

/*
 * DEFINITIONS
 */

  /* Bounds */
  /* Default bundle-layer FSM retry timeout */
  #define LINK_DEFAULT_RETRY	2

  /* Default latency and bandwidth */
  #define LINK_DEFAULT_BANDWIDTH	64000		/* 64k */
  #define LINK_DEFAULT_LATENCY		2000		/* 2ms */

  /* Configuration options */
  enum {
    LINK_CONF_PAP,
    LINK_CONF_CHAPMD5,
    LINK_CONF_CHAPMSv1,
    LINK_CONF_CHAPMSv2,
    LINK_CONF_EAP,
    LINK_CONF_ACFCOMP,
    LINK_CONF_PROTOCOMP,
    LINK_CONF_MSDOMAIN,
    LINK_CONF_MAGICNUM,
    LINK_CONF_PASSIVE,
    LINK_CONF_CHECK_MAGIC,
    LINK_CONF_RINGBACK,
    LINK_CONF_NO_ORIG_AUTH,
    LINK_CONF_CALLBACK,
  };

  /* Configuration for a link */
  struct linkconf {
    int			mtu;		/* Initial MTU value */
    int			mru;		/* Initial MRU value */
    int			accmap;		/* Initial ACCMAP value */
    short		retry_timeout;	/* FSM timeout for retries */
    short		max_redial;	/* Max failed connect attempts */
    char		*ident;		/* LCP ident string */
    char		*node;		/* Netgraph node */
    char		*hook;		/* Netgraph hook */
    struct optinfo	options;	/* Configured options */
  };

  /* Per-link bandwidth mgmt info */
  #define LINK_BM_N	6		/* Number of sampling intervals */

  struct linkbm {
    u_int	traffic[2][LINK_BM_N];	/* Traffic deltas */
    u_char	wasUp[LINK_BM_N];	/* Sub-intervals link was up */
    struct ng_ppp_link_stat
		idleStats;		/* Link management stats */
  };
  typedef struct linkbm	*LinkBm;

  #define LINK_STATS_UPDATE_INTERVAL	60 * SECONDS

  /* internal 64 bit counters as workaround for the 32 bit 
   * limitation for ng_ppp_link_stat
   */
  struct linkstats {
	struct ng_ppp_link_stat
			oldStats;
	u_int64_t 	xmitFrames;	/* xmit frames on link */
	u_int64_t 	xmitOctets;	/* xmit octets on link */
	u_int64_t 	recvFrames;	/* recv frames on link */
	u_int64_t	recvOctets;	/* recv octets on link */
	u_int64_t 	badProtos;	/* frames rec'd with bogus protocol */
	u_int64_t 	runts;		/* Too short MP fragments */
	u_int64_t 	dupFragments;	/* MP frames with duplicate seq # */
	u_int64_t	dropFragments;	/* MP fragments we had to drop */
	u_int64_t	old_xmitOctets;	/* last sent to RADIUS xmitOctets */
	u_int64_t	old_recvOctets;	/* last sent to RADIUS recvOctets */
  };
  typedef struct linkstat *LinkStats;

  /* Values for link origination (must fit in 2 bits) */
  #define LINK_ORIGINATE_UNKNOWN	0
  #define LINK_ORIGINATE_LOCAL		1
  #define LINK_ORIGINATE_REMOTE		2

  #define LINK_ORIGINATION(o)	((o) == LINK_ORIGINATE_LOCAL ? "local" :    \
  				 (o) == LINK_ORIGINATE_REMOTE ? "remote" :  \
				 "unknown")

  /* Total state of a link */
  struct linkst {
    char		name[LINK_MAX_NAME];	/* Human readable name */
    char		session_id[AUTH_MAX_SESSIONID];	/* a uniq session-id */
    Bund		bund;			/* My bundle */
    int			bundleIndex;		/* Link number in bundle */
    MsgHandler		msgs;			/* Link events */

    /* State info */
    struct linkconf	conf;		/* Link configuration */
    struct lcpstate	lcp;		/* LCP state info */
    struct linkbm	bm;		/* Link bandwidth mgmt info */
    struct linkstats	stats;		/* Link statistics */
    struct pppTimer	statsUpdateTimer;	/* update Timer */
    PhysInfo		phys;		/* Physical layer info */

    /* Link properties */
    short		num_redial;	/* Counter for retry attempts */
    u_char		marked:1;	/* Used by MpAllocate() */
    u_char		alive:1;	/* Used by MpAllocate() */
    u_char		joined_bund:1;	/* Link successfully joined bundle */
    u_char		originate:2;	/* Who originated the connection */
    u_char		lastStatus;	/* Last status code */
    char		*upReason;	/* Reason for link going up */
    u_char		upReasonValid:1;
    char		*downReason;	/* Reason for link going down */
    u_char		downReasonValid:1;
    int			bandwidth;	/* Bandwidth in bits per second */
    int			latency;	/* Latency in microseconds */
    time_t		last_open;	/* Time this link last was opened */

    /* Info gleaned from negotiations */
    struct discrim	peer_discrim;
  };

  
/*
 * VARIABLES
 */

  extern const struct cmdtab	LinkSetCmds[];

/*
 * FUNCTIONS
 */

  extern void	LinkUp(Link l);
  extern void	LinkDown(Link l);
  extern void	LinkOpen(Link l);
  extern void	LinkClose(Link l);
  extern void	LinkOpenCmd(void);
  extern void	LinkCloseCmd(void);

  extern Link	LinkNew(char *name, Bund b, int bI);
  extern Link	LinkCopy(void);
  extern int	LinkNuke(Link link);
  extern int	LinkStat(int ac, char *av[], void *arg);
  extern void	LinkUpdateStats(void);
  extern void	LinkUpdateStatsTimer(void *cookie);
  extern void	LinkResetStats(void);
  extern int	LinkCommand(int ac, char *av[], void *arg);
  extern void	RecordLinkUpDownReason(Link l, int up, const char *fmt,
			  const char *arg, ...);

#endif

