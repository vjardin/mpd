
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
#include <netinet/ip.h>
#include <netinet/tcp.h>
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
#include "nat.h"
#include "vars.h"

/*
 * DEFINITIONS
 */

  #define IFACE_MAX_ROUTES	32
  #define IFACE_MAX_SCRIPT	128

  #define IFACE_IDLE_SPLIT	4
  
  #define IFACE_MIN_MTU		296
  #define IFACE_MAX_MTU		65536

  /*
   * We are in a liberal position about MSS
   * (RFC 879, section 7).
   */
  #define MAXMSS(mtu) (mtu - sizeof(struct ip) - sizeof(struct tcphdr))

/* Configuration options */

  enum {
    IFACE_CONF_ONDEMAND,
    IFACE_CONF_PROXY,
    IFACE_CONF_TCPMSSFIX,
    IFACE_CONF_TEE,
    IFACE_CONF_NAT,
    IFACE_CONF_NETFLOW_IN,
    IFACE_CONF_NETFLOW_OUT,
  };

  /* Dial-on-demand packet cache */
  struct dodcache {
    Mbuf		pkt;
    time_t		ts;
    u_short		proto;
  };

  #define MAX_DOD_CACHE_DELAY	30

  struct ifaceroute {
    struct u_range	dest;			/* Destination of route */
    u_char		ok:1;			/* Route installed OK */
    SLIST_ENTRY(ifaceroute)	next;
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
    SLIST_HEAD(, ifaceroute) routes;
    struct acl 		*tables;		/* List of IP added to tables by iface */
    struct u_range	self_addr;		/* Interface's IP address */
    struct u_addr	peer_addr;		/* Peer's IP address */
    struct u_addr	proxy_addr;		/* Proxied IP address */
    struct u_addr	self_ipv6_addr;
    struct u_addr	peer_ipv6_addr;
    struct pppTimer	idleTimer;		/* Idle timer */
    struct pppTimer	sessionTimer;		/* Session timer */
    char		up_script[IFACE_MAX_SCRIPT];
    char		down_script[IFACE_MAX_SCRIPT];
    u_char		open:1;			/* In an open state */
    u_char		up:1;			/* interface is up */
    u_char		ip_up:1;		/* IP interface is up */
    u_char		ipv6_up:1;		/* IPv6 interface is up */
    u_char		nat_up:1;		/* NAT is up */
    u_char		tee_up:1;		/* TEE is up */
    u_char		nfin_up:1;		/* NFIN is up */
    u_char		nfout_up:1;		/* NFOUT is up */
    u_char		mss_up:1;		/* MSS is up */
    
    u_char		dod:1;			/* Interface flagged -link0 */
    struct dodcache	dodCache;		/* Dial-on-demand cache */
    
    struct natstate	nat;			/* NAT config */

    struct linkstats	idleStats;		/* Statistics for idle timeout */
  };
  typedef struct ifacestate	*IfaceState;

  struct acl_pool {			/* Pool of used ACL numbers */
    char		ifname[IFNAMSIZ+1];     /* Name of interface */
    unsigned short	acl_number;		/* ACL number given by RADIUS unique on this interface */
    unsigned short	real_number;		/* Real ACL number unique on this system */
    struct acl_pool	*next;
  };

/*
 * VARIABLES
 */

  extern const struct cmdtab	IfaceSetCmds[];

  extern struct acl_pool * rule_pool; /* Pointer to the first element in the list of rules */
  extern struct acl_pool * pipe_pool; /* Pointer to the first element in the list of pipes */
  extern struct acl_pool * queue_pool; /* Pointer to the first element in the list of queues */
  extern struct acl_pool * table_pool; /* Pointer to the first element in the list of tables */
  extern int rule_pool_start; /* Initial number of ipfw rules pool */
  extern int pipe_pool_start; /* Initial number of ipfw dummynet pipe pool */
  extern int queue_pool_start; /* Initial number of ipfw dummynet queue pool */
  extern int table_pool_start; /* Initial number of ipfw tables pool */

/*
 * FUNCTIONS
 */

  extern void	IfaceInit(Bund b);
  extern void	IfaceOpen(Bund b);
  extern void	IfaceClose(Bund b);
  extern void	IfaceOpenCmd(Context ctx);
  extern void	IfaceCloseCmd(Context ctx);
  extern void	IfaceIpIfaceUp(Bund b, int ready);
  extern void	IfaceIpIfaceDown(Bund b);
  extern void	IfaceIpv6IfaceUp(Bund b, int ready);
  extern void	IfaceIpv6IfaceDown(Bund b);
  extern void	IfaceUp(Bund b, int ready);
  extern void	IfaceDown(Bund b);
  extern int	IfaceStat(Context ctx, int ac, char *av[], void *arg);

  extern void	IfaceListenInput(Bund b, int proto, Mbuf pkt);
  #ifndef USE_NG_TCPMSS
  extern void	IfaceCorrectMSS(Mbuf pkt, uint16_t maxmss);
  #endif
  extern void	IfaceSetMTU(Bund b, int mtu);
  extern void	IfaceChangeFlags(Bund b, int clear, int set);
  extern void	IfaceChangeAddr(Bund b, int add, struct u_range *self, struct u_addr *peer);

#endif

