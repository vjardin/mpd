
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
    LINK_CONF_INCOMING,
    LINK_CONF_ACFCOMP,
    LINK_CONF_PROTOCOMP,
    LINK_CONF_MSDOMAIN,
    LINK_CONF_MAGICNUM,
    LINK_CONF_PASSIVE,
    LINK_CONF_CHECK_MAGIC,
    LINK_CONF_RINGBACK,
    LINK_CONF_NO_ORIG_AUTH,
    LINK_CONF_CALLBACK,
    LINK_CONF_MULTILINK,	/* multi-link */
    LINK_CONF_SHORTSEQ,		/* multi-link short sequence numbers */
  };

  /* Configuration for a link */
  struct linkconf {
    u_short		mtu;		/* Initial MTU value */
    u_short		mru;		/* Initial MRU value */
    uint16_t		mrru;		/* Initial MRRU value */
    uint32_t		accmap;		/* Initial ACCMAP value */
    short		retry_timeout;	/* FSM timeout for retries */
    short		max_redial;	/* Max failed connect attempts */
    char		*ident;		/* LCP ident string */
    struct optinfo	options;	/* Configured options */
  };

  struct linkbm {
    struct ng_ppp_link_stat
		idleStats;		/* Link management stats */
  };
  typedef struct linkbm	*LinkBm;

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
    int			id;			/* Index of this link in gLinks */
    int			tmpl;			/* This is template, not an instance */
    int			stay;			/* Must not disappear */
    char		bundt[LINK_MAX_NAME];	/* Bundle template name */
    Bund		bund;			/* My bundle */
    int			bundleIndex;		/* Link number in bundle */
    int			csock;			/* Socket node control socket */
    int			dsock;			/* Socket node data socket */
    EventRef		dataEvent;		/* Socket node data event */
    ng_ID_t		nodeID;			/* ID of ppp node */
    MsgHandler		msgs;			/* Link events */
    int			die;
    int			refs;			/* Number of references */
    int			dead;			/* Dead flag */
    int			dod;			/* Link created by DoD */

    /* State info */
    struct linkconf	conf;		/* Link configuration */
    struct lcpstate	lcp;		/* LCP state info */
    struct linkbm	bm;		/* Link bandwidth mgmt info */
    struct ng_ppp_link_stat64	stats;	/* Link statistics */
#ifndef NG_PPP_STATS64
    struct ng_ppp_link_stat oldStats;	/* Previous stats for 64bit emulation */
#endif

    /* Link properties */
    short		num_redial;	/* Counter for retry attempts */
    u_char		joined_bund;	/* Link successfully joined bundle */
    u_char		originate;	/* Who originated the connection */
    char		*upReason;	/* Reason for link going up */
    char		*downReason;	/* Reason for link going down */
    u_char		upReasonValid:1;
    u_char		downReasonValid:1;
    int			bandwidth;	/* Bandwidth in bits per second */
    int			latency;	/* Latency in microseconds */
    time_t		last_open;	/* Time this link last was opened */
    char		msession_id[AUTH_MAX_SESSIONID]; /* a uniq msession-id */
    char		session_id[AUTH_MAX_SESSIONID];	/* a uniq session-id */

    /* Info gleaned from negotiations */
    struct discrim	peer_discrim;

    u_char		state;			/* Device current state */
    PhysType		type;			/* Device type descriptor */
    void		*info;			/* Type specific info */
    time_t		lastClose;		/* Time of last close */
    MsgHandler		pmsgs;			/* Message channel */
    struct pppTimer	openTimer;		/* Open retry timer */
    struct optinfo	options;
    Rep			rep;			/* Rep connected to the device */
    char		rept[LINK_MAX_NAME];	/* Repeater template for incomings */
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
  extern void	LinkOpenCmd(Context ctx);
  extern void	LinkCloseCmd(Context ctx);

  extern int	LinkCreate(Context ctx, int ac, char *av[], void *arg);
  extern Link	LinkInst(Link lt, char *name, int tmpl, int stay);
  extern void	LinkShutdown(Link l);
  extern int	LinkNgInit(Link l);
  extern int	LinkNgJoin(Link l);
  extern int	LinkNgLeave(Link l);
  extern void	LinkNgShutdown(Link l, int tee);
  extern int	LinkNuke(Link link);
  extern int	LinkStat(Context ctx, int ac, char *av[], void *arg);
  extern void	LinkUpdateStats(Link l);
  extern void	LinkResetStats(Link l);
  extern Link	LinkFind(char *name);
  extern int	LinkCommand(Context ctx, int ac, char *av[], void *arg);
  extern int	SessionCommand(Context ctx, int ac, char *av[], void *arg);
  extern void	RecordLinkUpDownReason(Bund b, Link l, int up, const char *fmt,
			  const char *arg, ...);

#endif

