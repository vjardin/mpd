
/*
 * ip.h
 *
 * Written by Toshiharu OHNO <tony-o@iij.ad.jp>
 * Copyright (c) 1993, Internet Initiative Japan, Inc. All rights reserved.
 * See ``COPYRIGHT.iij''
 * 
 * Rewritten by Archie Cobbs <archie@freebsd.org>
 * Copyright (c) 1995-1999 Whistle Communications, Inc. All rights reserved.
 * See ``COPYRIGHT.whistle''
 */

#ifndef _IP_H_
#define _IP_H_

#include <osreldate.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/ioctl.h>
#include <net/route.h>
#include <net/if.h>
#include <net/if_var.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include "mbuf.h"

/*
 * DEFINITIONS
 */

  struct in_range {
    struct in_addr	ipaddr;
    short    		width;
  };

/*
 * FUNCTIONS
 */

  extern int	IpShowRoutes(int ac, char *av[], void *arg);
  extern int	IpAddrInRange(struct in_range *range, struct in_addr ipaddr);

#endif

