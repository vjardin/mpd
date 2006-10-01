
/*
 * iface.h
 *
 * Written by Archie Cobbs <archie@freebsd.org>
 * Copyright (c) 1995-1999 Whistle Communications, Inc. All rights reserved.
 * See ``COPYRIGHT.whistle''
 */

#ifndef _IFACE_H_
#define _IFACE_H_

#include <sys/types.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <net/if_dl.h>
#include <net/bpf.h>
#include <netgraph/ng_message.h>
#ifdef __DragonFly__
#include <netgraph/ppp/ng_ppp.h>
#include <netgraph/bpf/ng_bpf.h>
#else
#include <netgraph/ng_ppp.h>
#include <netgraph/ng_bpf.h>
#endif
#include "mbuf.h"
#include "timer.h"
#include "vars.h"

/*
 * DEFINITIONS
 */

  #define IFACE_MAX_ROUTES	32
  #define IFACE_MAX_SCRIPT	128

  #define IFACE_IDLE_SPLIT	4
  
  #define IFACE_MIN_MTU		296
  #define IFACE_MAX_MTU		65536

  /* Dial-on-demand packet cache */
  struct dodcache {
    Mbuf		pkt;
    time_t		ts;
    u_short		proto;
  };

  #define MAX_DOD_CACHE_DELAY	30

  struct ifaceroute {
    struct in_addr	dest;			/* Destination of route */
    struct in_addr	netmask;		/* Zero if none specified */
    u_char		ok:1;			/* Route installed OK */
  };
  typedef struct ifaceroute	*IfaceRoute;

  struct ifacestate {
    char		ifname[IFNAMSIZ+1];	/* Name of my interface */
    u_char		traffic[IFACE_IDLE_SPLIT];	/* Mark any traffic */
    u_short		mtu;			/* Interface MTU */
    u_short		max_mtu;		/* Configured maximum MTU */
    struct optinfo	options;		/* Configuration options */
    u_int		idle_timeout;		/* Idle timeout */
    u_int		session_timeout;	/* Session timeout */
    short		n_routes;
    short		n_routes_static;
    struct ifaceroute	routes[IFACE_MAX_ROUTES];
    struct in_addr	self_addr;		/* Interface's IP address */
    struct in_addr	peer_addr;		/* Peer's IP address */
    struct in_addr	proxy_addr;		/* Proxied IP address */
    struct in6_addr	ipv6_addr;
    struct pppTimer	idleTimer;		/* Idle timer */
    struct pppTimer	sessionTimer;		/* Session timer */
    char		up_script[IFACE_MAX_SCRIPT];
    char		down_script[IFACE_MAX_SCRIPT];
    u_char		open:1;			/* In an open state */
    u_char		up:1;			/* interface is up */
    u_char		ip_up:1;		/* IP interface is up */
    u_char		ipv6_up:1;		/* IPv6 interface is up */
    u_char		ready:1;		/* Interface flagged -link0 */
    struct dodcache	dodCache;		/* Dial-on-demand cache */
    struct ng_bpf_hookstat
			idleStats;		/* Stats for idle timeout */
  };
  typedef struct ifacestate	*IfaceState;

  struct acl_pool {			/* Pool of used ACL numbers */
    char	ifname[IFNAMSIZ+1];     /* Name of interface */
    int		acl_number;		/* ACL number given by RADIUS unique on this interface */
    int		real_number;		/* Real ACL number unique on this system */
    struct acl_pool *next;
  };

/*
 * VARIABLES
 */

  extern const struct cmdtab	IfaceSetCmds[];

/*
 * FUNCTIONS
 */

  extern void	IfaceInit(void);
  extern void	IfaceOpen(void);
  extern void	IfaceClose(void);
  extern void	IfaceIpIfaceUp(int ready);
  extern void	IfaceIpIfaceDown(void);
  extern void	IfaceIpv6IfaceUp(int ready);
  extern void	IfaceIpv6IfaceDown(void);
  extern void	IfaceUp(void);
  extern void	IfaceDown(void);
  extern void	IfaceSetParams(int mtu, int speed);
  extern int	IfaceStat(int ac, char *av[], void *arg);

  extern void	IfaceListenInput(int proto, Mbuf pkt);
  #ifndef USE_NG_TCPMSS
  extern void	IfaceListenOutput(int proto, Mbuf pkt);
  #endif
  extern void	IfaceSetMTU(int mtu, int speed);

#endif

