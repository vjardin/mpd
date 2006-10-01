
/*
 * ipv6cp.h
 *
 * Written by Toshiharu OHNO <tony-o@iij.ad.jp>
 * Copyright (c) 1993, Internet Initiative Japan, Inc. All rights reserved.
 * See ``COPYRIGHT.iij''
 * 
 * Rewritten by Archie Cobbs <archie@freebsd.org>
 * Copyright (c) 1995-1999 Whistle Communications, Inc. All rights reserved.
 * See ``COPYRIGHT.whistle''
 * 
 * Rewritten for IPV6CP by Alexander Motin <mav@alkar.net>
 */

#ifndef _IPV6CP_H_
#define _IPV6CP_H_

#include <sys/types.h>
#include <netinet/ip.h>
#include "phys.h"
#include "fsm.h"
#include "timer.h"

/*
 * DEFINITONS
 */
 
   /* Configuration options */
/*  enum {
    IPV6CP_CONF_VJCOMP,
    IPV6CP_CONF_REQPRIDNS,
    IPV6CP_CONF_REQSECDNS,
    IPV6CP_CONF_REQPRINBNS,
    IPV6CP_CONF_REQSECNBNS,
    IPV6CP_CONF_PRETENDIP,
  };*/

  struct ipv6cpconf {
    struct optinfo	options;	/* Configuraion options */
  };
  typedef struct ipv6cpconf	*Ipv6cpConf;

  struct ipv6cpstate {
    struct ipv6cpconf	conf;		/* Configuration */

    u_char 		myintid[8];
    u_char 		hisintid[8];

    u_long		peer_reject;	/* Request codes rejected by peer */

    struct fsm		fsm;
  };
  typedef struct ipv6cpstate	*Ipv6cpState;

/*
 * VARIABLES
 */

  extern const struct cmdtab	Ipv6cpSetCmds[];

/*
 * FUNCTIONS
 */

  extern void	Ipv6cpInit(void);
  extern void	Ipv6cpUp(void);
  extern void	Ipv6cpDown(void);
  extern void	Ipv6cpOpen(void);
  extern void	Ipv6cpClose(void);
  extern void	Ipv6cpInput(Mbuf bp, int linkNum);
  extern void	Ipv6cpDefAddress(void);
  extern int	Ipv6cpStat(int ac, char *av[], void *arg);

#endif


