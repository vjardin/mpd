
/*
 * bund.h
 *
 * Written by Archie Cobbs <archie@freebsd.org>
 * Copyright (c) 1995-1999 Whistle Communications, Inc. All rights reserved.
 * See ``COPYRIGHT.whistle''
 */

#ifndef _BUND_H_
#define _BUND_H_

#include "defs.h"
#include "ip.h"
#include "iface.h"
#include "mp.h"
#include "ipcp.h"
#include "chap.h"
#include "ccp.h"
#include "ecp.h"
#include "vars.h"
#include "msg.h"
#include "radius.h"
#include "command.h"
#include <netgraph/ng_message.h>

/*
 * DEFINITIONS
 */

  #define BUND_MAX_SCRIPT	32

  /* Configuration options */
  enum {
    BUND_CONF_MULTILINK,	/* multi-link */
    BUND_CONF_SHORTSEQ,		/* multi-link short sequence numbers */
    BUND_CONF_COMPRESSION,	/* compression */
    BUND_CONF_ENCRYPTION,	/* encryption */
    BUND_CONF_CRYPT_REQD,	/* encryption is required */
    BUND_CONF_BWMANAGE,		/* dynamic bandwidth */
    BUND_CONF_ROUNDROBIN,	/* round-robin MP scheduling */
    BUND_CONF_RADIUSAUTH,	/* enable radius auth */
    BUND_CONF_RADIUSFALLBACK,	/* enable fallback to mpd.secret */
    BUND_CONF_RADIUSACCT,	/* enable radius accounting */
    BUND_CONF_NORETRY,		/* don't retry failed links */
    BUND_CONF_TCPWRAPPER,	/* enable tcp-wrapper */
  };

  /* Default bundle-layer FSM retry timeout */
  #define BUND_DEFAULT_RETRY	2

/*

  Bundle bandwidth management

  We treat the first link as different from the rest. It connects
  immediately when there is (qualifying) outgoing traffic. The
  idle timeout applies globally, no matter how many links are up.

  Additional links are connected/disconnected according to a simple
  algorithm that uses the following constants:

  S	Sampling interval. Number of seconds over which we average traffic.

  N	Number of sub-intervals we chop the S seconds into (granularity). 

  Hi	Hi water mark: if traffic is more than H% of total available
	bandwidth, averaged over S seconds, time to add the second link.

  Lo	Low water mark: if traffic is less than L% of total available
	bandwidth during all N sub-intervals, time to hang up the second link.

  Mc	Minimum amount of time after connecting a link before
	disconnecting any link.

  Md	Minimum amount of time after disconnecting any link before
	connecting any other link.

  We treat incoming and outgoing traffic separately when comparing
  against Hi. If either quantity exceeds it, we bring up another link.
  When comparing agains Lo, we lump incoming and outgoing traffic
  totals together into a single value before making the comparison.

*/

  #define BUND_BM_DFL_S		60	/* Length of sampling interval (secs) */
  #define BUND_BM_DFL_Hi	80	/* High water mark % */
  #define BUND_BM_DFL_Lo	20	/* Low water mark % */
  #define BUND_BM_DFL_Mc	90	/* Min connected time (secs) */
  #define BUND_BM_DFL_Md	30	/* Min disconnected time (secs) */

  struct bundbm {
    short		n_up;		/* Number of links in NETWORK phase */
    short		n_open;		/* Number of links in an OPEN state */
    time_t		last_close;	/* Time we last closed any link */
    struct pppTimer	bmTimer;	/* Bandwidth mgmt timer */
    u_char		ncps_up:1;	/* NCP's have been told we're up */
    u_char		links_open:1;	/* One or more links told to open */
    u_int		total_bw;	/* Total bandwidth available */
  };
  typedef struct bundbm	*BundBm;

  /* Configuration for a bundle */
  struct bundconf {
    int			mrru;			/* Initial MRU value */
    char		authname[AUTH_MAX_AUTHNAME];
    char		password[AUTH_MAX_PASSWORD];
    u_long		max_logins;		/* max. number of concurrent logins */
    short		retry_timeout;		/* Timeout for retries */
    u_short		bm_S;			/* Bandwidth mgmt constants */
    u_short		bm_Hi;
    u_short		bm_Lo;
    u_short		bm_Mc;
    u_short		bm_Md;
    char		script[BUND_MAX_SCRIPT];/* Link change script */
    struct optinfo	options;		/* Configured options */
#ifdef IA_CUSTOM
    struct optinfo	custopt;		/* Custom options */
    char		netname[8];		/* Custom network name */
#endif
  };

  /* Total state of a bundle */
  struct bundle {
    char		name[20];		/* Name of this bundle */
    MsgHandler		msgs;			/* Bundle events */
    char		interface[10];		/* Interface I'm using */
    short		n_links;		/* Number of links in bundle */
    int			csock;			/* Socket node control socket */
    int			dsock;			/* Socket node data socket */
    EventRef		ctrlEvent;		/* Socket node control event */
    EventRef		dataEvent;		/* Socket node data event */
    ng_ID_t		nodeID;			/* ID of ppp node */
    Link		*links;			/* Real links in this bundle */
    char		peer_authname[AUTH_MAX_AUTHNAME]; /* Peer's authname */
    struct in_range	peer_allow;		/* Peer's allowed IP (if any) */
    struct discrim	peer_discrim;		/* Peer's discriminator */
    u_char		self_msChal[CHAP_MSOFTv2_CHAL_LEN]; /* MSOFT challng */
    u_char		peer_msChal[CHAP_MSOFTv2_CHAL_LEN]; /* MSOFT challng */
    u_char		self_ntResp[CHAP_MSOFTv2_RESP_LEN]; /* MSOFT response */
    u_char		peer_ntResp[CHAP_MSOFTv2_RESP_LEN]; /* MSOFT response */
    char		msPassword[AUTH_MAX_PASSWORD];	    /* For MSOFT MPPE */
    u_char		numRecordUp;		/* # links recorded up */

    /* RADIUS configuration */
    struct radiusconf	radiusconf;

    /* PPP node config */
#if NGM_PPP_COOKIE < 940897794
    struct ng_ppp_node_config	pppConfig;
#else
    struct ng_ppp_node_conf	pppConfig;
#endif

    /* Data chunks */
    struct bundbm	bm;		/* Bandwidth management state */
    struct bundconf	conf;		/* Configuration for this bundle */
    struct mpstate	mp;		/* MP state for this bundle */
    struct ifacestate	iface;		/* IP state info */
    struct ipcpstate	ipcp;		/* IPCP state info */
    struct ccpstate	ccp;		/* CCP state info */
    struct ecpstate	ecp;		/* ECP state info */

    /* Link management stuff */
    struct pppTimer	bmTimer;		/* Bandwidth mgmt timer */
    struct pppTimer	msgTimer;		/* Status message timer */
    struct pppTimer	reOpenTimer;		/* Re-open timer */

    /* Boolean variables */
    u_char		open:1;		/* In the open state */
    u_char		multilink:1;	/* Doing multi-link on this bundle */
  };

/*
 * VARIABLES
 */

  extern struct discrim		self_discrim;	/* My discriminator */
  extern const struct cmdtab	BundSetCmds[];

/*
 * FUNCTIONS
 */

  extern void	BundOpen(void);
  extern void	BundClose(void);
  extern int	BundStat(int ac, char *av[], void *arg);
  extern void	BundUpdateParams(void);
  extern int	BundCommand(int ac, char *av[], void *arg);
  extern int	BundCreateCmd(int ac, char *av[], void *arg);

  extern int	BundJoin(void);
  extern void	BundLeave(void);
  extern void	BundLinkGaveUp(void);
  extern void	BundCloseLinks(void);

#endif

