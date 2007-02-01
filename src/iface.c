
/*
 * iface.c
 *
 * Written by Archie Cobbs <archie@freebsd.org>
 * Copyright (c) 1995-1999 Whistle Communications, Inc. All rights reserved.
 * See ``COPYRIGHT.whistle''
 *
 * TCP MSSFIX code copyright (c) 2000 Ruslan Ermilov
 * TCP MSSFIX contributed by Sergey Korolew <dsATbittu.org.ru>
 *
 */

#include "ppp.h"
#include "iface.h"
#include "ipcp.h"
#include "auth.h"
#include "custom.h"
#include "ngfunc.h"
#include "netgraph.h"
#include "msgdef.h"
#include "util.h"

#include <sys/sockio.h>
#include <net/if.h>
#include <net/if_types.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <netgraph/ng_message.h>
#ifdef __DragonFly__
#include <netgraph/iface/ng_iface.h>
#include <netgraph/bpf/ng_bpf.h>
#else
#include <netgraph/ng_iface.h>
#include <netgraph/ng_bpf.h>
#endif
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#ifdef USE_NG_NAT
#include <netgraph/ng_nat.h>
#endif

/*
 * DEFINITIONS
 */

  /*
   * We are in a liberal position about MSS
   * (RFC 879, section 7).
   */
  #define MAXMSS(mtu) (mtu - sizeof(struct ip) - sizeof(struct tcphdr))

/* Set menu options */

  enum {
    SET_IDLE,
    SET_SESSION,
    SET_ADDRS,
    SET_ROUTE,
    SET_MTU,
    SET_UP_SCRIPT,
    SET_DOWN_SCRIPT,
    SET_ENABLE,
    SET_DISABLE,
  };

/*
 * INTERNAL FUNCTIONS
 */

  static int	IfaceSetCommand(int ac, char *av[], void *arg);
  static void	IfaceSessionTimeout(void *arg);
  static void	IfaceIdleTimeout(void *arg);
  static void	IfaceIdleTimerExpired(void *arg);

  static void	IfaceCacheSend(void);
  static void	IfaceCachePkt(int proto, Mbuf pkt);
  static int	IfaceIsDemand(int proto, Mbuf pkt);

  static int	IfaceAllocACL (struct acl_pool ***ap, int start, char * ifname, int number);
  static int	IfaceFindACL (struct acl_pool *ap, char * ifname, int number);
  static char *	IFaceParseACL (char * src, char * ifname);
  #ifndef USE_NG_TCPMSS
  static void	IfaceCorrectMSS(Mbuf pkt, uint16_t maxmss);
  #endif
  
/*
 * GLOBAL VARIABLES
 */

  const struct cmdtab IfaceSetCmds[] = {
    { "addrs self peer",		"Set interface addresses",
	IfaceSetCommand, NULL, (void *) SET_ADDRS },
    { "route dest[/width]",		"Add IP route",
	IfaceSetCommand, NULL, (void *) SET_ROUTE },
    { "mtu size",			"Set max allowed interface MTU",
	IfaceSetCommand, NULL, (void *) SET_MTU },
    { "up-script [progname]",		"Interface up script",
	IfaceSetCommand, NULL, (void *) SET_UP_SCRIPT },
    { "down-script [progname]",		"Interface down script",
	IfaceSetCommand, NULL, (void *) SET_DOWN_SCRIPT },
    { "idle seconds",			"Idle timeout",
	IfaceSetCommand, NULL, (void *) SET_IDLE },
    { "session seconds",		"Session timeout",
	IfaceSetCommand, NULL, (void *) SET_SESSION },
    { "enable [opt ...]",		"Enable option",
	IfaceSetCommand, NULL, (void *) SET_ENABLE },
    { "disable [opt ...]",		"Disable option",
	IfaceSetCommand, NULL, (void *) SET_DISABLE },
    { NULL },
  };

/*
 * INTERNAL VARIABLES
 */

  static const struct confinfo	gConfList[] = {
    { 0,	IFACE_CONF_ONDEMAND,		"on-demand"	},
    { 0,	IFACE_CONF_PROXY,		"proxy-arp"	},
    { 0,	IFACE_CONF_TCPMSSFIX,           "tcpmssfix"	},
    { 0,	0,				NULL		},
  };

  struct acl_pool * rule_pool = NULL; /* Pointer to the first element in the list of rules */
  struct acl_pool * pipe_pool = NULL; /* Pointer to the first element in the list of pipes */
  struct acl_pool * queue_pool = NULL; /* Pointer to the first element in the list of queues */
  struct acl_pool * table_pool = NULL; /* Pointer to the first element in the list of tables */
  int rule_pool_start = 10000; /* Initial number of ipfw rules pool */
  int pipe_pool_start = 10000; /* Initial number of ipfw dummynet pipe pool */
  int queue_pool_start = 10000; /* Initial number of ipfw dummynet queue pool */
  int table_pool_start = 32; /* Initial number of ipfw tables pool */

/*
 * IfaceInit()
 */

void
IfaceInit(void)
{
  IfaceState	const iface = &bund->iface;

  /* Default configuration */
  iface->mtu = NG_IFACE_MTU_DEFAULT;
  iface->max_mtu = NG_IFACE_MTU_DEFAULT;
  Disable(&iface->options, IFACE_CONF_ONDEMAND);
  Disable(&iface->options, IFACE_CONF_PROXY);
  Disable(&iface->options, IFACE_CONF_TCPMSSFIX);
  Log(LG_BUND|LG_IFACE, ("[%s] using interface %s",
    bund->name, bund->iface.ifname));
}

/*
 * IfaceOpen()
 *
 * Open the interface layer
 */

void
IfaceOpen(void)
{
  IfaceState	const iface = &bund->iface;

  Log(LG_IFACE, ("[%s] IFACE: Open event", bund->name));

  /* If interface is already open do nothing */
  if (iface->open)
    return;
  iface->open = TRUE;

  /* If on-demand, bring up system interface immediately and start
     listening for outgoing packets. The next outgoing packet will
     cause us to open the lower layer(s) */
  if (Enabled(&iface->options, IFACE_CONF_ONDEMAND)) {
    BundNcpsJoin(NCP_NONE);
    NgFuncConfigBPF(bund, BPF_MODE_DEMAND);
    SetStatus(ADLG_WAN_WAIT_FOR_DEMAND, STR_READY_TO_DIAL);
    return;
  }

}

/*
 * IfaceClose()
 *
 * Close the interface layer
 */

void
IfaceClose(void)
{
  IfaceState	const iface = &bund->iface;

  Log(LG_IFACE, ("[%s] IFACE: Close event", bund->name));

  /* If interface is already closed do nothing */
  if (!iface->open)
    return;
  iface->open = FALSE;

  /* Take down system interface */
  if (iface->ip_up) {
    NgFuncConfigBPF(bund, BPF_MODE_OFF);
  }

  /* Close lower layer(s) */
  BundClose();
}

/*
 * IfaceUp()
 *
 * Our underlying PPP bundle is ready for traffic.
 * Note, while this assumes we're talking about IP traffic
 * here, in general a parameter could specify which type
 * of traffic, IP vs. AppleTalk vs. whatever, along with
 * additional protocol specific information (in this case,
 * the IP addresses of each end of the point-to-point link).
 */

void
IfaceUp(int ready)
{
  IfaceState	const iface = &bund->iface;
  int		session_timeout = 0, idle_timeout = 0;
  struct acl	*acls, *acl;
  char			*buf;
  struct acl_pool 	**poollast;
  int 			poollaststart;
  int		prev_number;
  int		prev_real_number;

  Log(LG_IFACE, ("[%s] IFACE: Up event", bund->name));
  if (ready) {
    SetStatus(ADLG_WAN_CONNECTED, STR_CONN_ESTAB);
  } else {
    SetStatus(ADLG_WAN_WAIT_FOR_DEMAND, STR_READY_TO_DIAL);
  }

  /* Open ourselves if necessary (we in effect slave off IPCP) */
  if (!iface->open) {
    Log(LG_IFACE2, ("[%s] IFACE: Opening", bund->name));
    iface->open = TRUE;		/* Would call IfaceOpen(); effect is same */
  }

  if (ready) {

  /* Start Session timer */
  TimerStop(&iface->sessionTimer);

  if (bund->params.session_timeout > 0) {
    session_timeout = bund->params.session_timeout;
  } else if (iface->session_timeout > 0) {
    session_timeout = iface->session_timeout;
  }

  if (session_timeout > 0) {
    Log(LG_IFACE2, ("[%s] IFACE: session-timeout: %d seconds", 
      bund->name, session_timeout));
    TimerInit(&iface->sessionTimer, "IfaceSession",
      session_timeout * SECONDS, IfaceSessionTimeout, NULL);
    TimerStart(&iface->sessionTimer);
  }

  /* Start idle timer */
  TimerStop(&iface->idleTimer);

  if (bund->params.idle_timeout > 0) {
    idle_timeout = bund->params.idle_timeout;
  } else if (iface->idle_timeout > 0) {
    idle_timeout = iface->idle_timeout;
  }
    
  if (idle_timeout > 0) {
    char	path[NG_PATHLEN + 1];

    Log(LG_IFACE2, ("[%s] IFACE: idle-timeout: %d seconds", 
      bund->name, idle_timeout));
    
    TimerInit(&iface->idleTimer, "IfaceIdle",
      idle_timeout * SECONDS / IFACE_IDLE_SPLIT, IfaceIdleTimeout, NULL);
    TimerStart(&iface->idleTimer);
    iface->traffic[1] = TRUE;
    iface->traffic[0] = FALSE;

    /* Reset bpf node statistics */
    memset(&iface->idleStats, 0, sizeof(iface->idleStats));
    snprintf(path, sizeof(path), "mpd%d-%s:%s", gPid, bund->name,
	NG_PPP_HOOK_INET);
    if (NgSendMsg(bund->csock, path, NGM_BPF_COOKIE,
	NGM_BPF_CLR_STATS, BPF_HOOK_IFACE, sizeof(BPF_HOOK_IFACE)) < 0)
      Log(LG_ERR, ("[%s] can't clear %s stats: %s",
	bund->name, NG_BPF_NODE_TYPE, strerror(errno)));
  }

  /* Allocate ACLs */
  acls = bund->params.acl_pipe;
  poollast = &pipe_pool;
  poollaststart = pipe_pool_start;
  while (acls != NULL) {
    acls->real_number = IfaceAllocACL(&poollast, poollaststart, iface->ifname, acls->number);
    poollaststart = acls->real_number;
    acls = acls->next;
  };
  acls = bund->params.acl_queue;
  poollast = &queue_pool;
  poollaststart = queue_pool_start;
  while (acls != NULL) {
    acls->real_number = IfaceAllocACL(&poollast, poollaststart, iface->ifname, acls->number);
    poollaststart = acls->real_number;
    acls = acls->next;
  };
  prev_number = -1;
  prev_real_number = -1;
  acls = bund->params.acl_table;
  poollast = &table_pool;
  poollaststart = table_pool_start;
  while (acls != NULL) {
    if (acls->real_number == 0) {
	if (acls->number == prev_number) { /* ACL list is presorted so we need not allocate if equal */
	    acls->real_number = prev_real_number;
	} else {
	    acls->real_number = IfaceAllocACL(&poollast, poollaststart, iface->ifname, acls->number);
	    poollaststart = acls->real_number;
	    prev_number = acls->number;
	    prev_real_number = acls->real_number;
	}
    }
    acls = acls->next;
  };
  acls = bund->params.acl_rule;
  poollast = &rule_pool;
  poollaststart = rule_pool_start;
  while (acls != NULL) {
    acls->real_number = IfaceAllocACL(&poollast, poollaststart, iface->ifname, acls->number);
    poollaststart = acls->real_number;
    acls = acls->next;
  };

  /* Set ACLs */
  acls = bund->params.acl_pipe;
  while (acls != NULL) {
    buf = IFaceParseACL(acls->rule, iface->ifname);
    ExecCmd(LG_IFACE2, "%s pipe %d config %s", PATH_IPFW, acls->real_number, acls->rule);
    Freee(MB_IFACE, buf);
    acls = acls->next;
  }
  acls = bund->params.acl_queue;
  while (acls != NULL) {
    buf = IFaceParseACL(acls->rule,iface->ifname);
    ExecCmd(LG_IFACE2, "%s queue %d config %s", PATH_IPFW, acls->real_number, buf);
    Freee(MB_IFACE, buf);
    acls = acls->next;
  }
  acls = bund->params.acl_table;
  while (acls != NULL) {
    acl = Malloc(MB_IFACE, sizeof(struct acl));
    memcpy(acl, acls, sizeof(struct acl));
    acl->next = iface->tables;
    iface->tables = acl;
    ExecCmd(LG_IFACE2, "%s table %d add %s", PATH_IPFW, acls->real_number, acls->rule);
    acls = acls->next;
  };
  acls = bund->params.acl_rule;
  while (acls != NULL) {
    buf = IFaceParseACL(acls->rule, iface->ifname);
    ExecCmd(LG_IFACE2, "%s add %d %s via %s", PATH_IPFW, acls->real_number, buf, iface->ifname);
    Freee(MB_IFACE, buf);
    acls = acls->next;
  };

  };

  /* Bring up system interface */
  ExecCmd(LG_IFACE2, "%s %s up %slink0", 
    PATH_IFCONFIG, iface->ifname, ready ? "-" : "");

  if (ready) {

  /* Turn on interface traffic flow */
  if (Enabled(&iface->options, IFACE_CONF_TCPMSSFIX)) {
    Log(LG_IFACE2, ("[%s] enabling TCPMSSFIX", bund->name));
    NgFuncConfigBPF(bund, BPF_MODE_MSSFIX);
#ifdef USE_NG_TCPMSS
    NgFuncConfigTCPMSS(bund, MAXMSS(iface->mtu));
#endif
  }
  else 
    NgFuncConfigBPF(bund, BPF_MODE_ON);

  /* Send any cached packets */
  IfaceCacheSend();
  
  } else {
    NgFuncConfigBPF(bund, BPF_MODE_DEMAND);
  }
}

/*
 * IfaceDown()
 *
 * Our packet transport mechanism is no longer ready for traffic.
 */

void
IfaceDown(void)
{
  IfaceState	const iface = &bund->iface;
  struct acl_pool	**rp, *rp1;
  char		cb[32768];
  struct acl    *acl, *aclnext;

  Log(LG_IFACE, ("[%s] IFACE: Down event", bund->name));

  /* If we're not open, it doesn't matter to us anyway */
  TimerStop(&iface->idleTimer);
  if (!iface->open)
    return;

  /* Bring down system interface */
  ExecCmd(LG_IFACE2, "%s %s down", 
    PATH_IFCONFIG, iface->ifname);

  TimerStop(&iface->idleTimer);
  TimerStop(&iface->sessionTimer);

  /* Remove rule ACLs */
  rp = &rule_pool;
  cb[0]=0;
  while (*rp != NULL) {
    if (strncmp((*rp)->ifname, iface->ifname, IFNAMSIZ) == 0) {
      sprintf(cb+strlen(cb), " %d", (*rp)->real_number);
      rp1 = *rp;
      *rp = (*rp)->next;
      Freee(MB_IFACE, rp1);
    } else {
      rp = &((*rp)->next);
    };
  };
  if (cb[0]!=0)
    ExecCmd(LG_IFACE2, "%s delete%s",
      PATH_IPFW, cb);

  /* Remove table ACLs */
  rp = &table_pool;
  while (*rp != NULL) {
    if (strncmp((*rp)->ifname, iface->ifname, IFNAMSIZ) == 0) {
      rp1 = *rp;
      *rp = (*rp)->next;
      Freee(MB_IFACE, rp1);
    } else {
      rp = &((*rp)->next);
    };
  };
  acl = iface->tables;
  while (acl != NULL) {
    ExecCmd(LG_IFACE2, "%s table %d delete %s",
	PATH_IPFW, acl->real_number, acl->rule);
    aclnext = acl->next;
    Freee(MB_IFACE, acl);
    acl = aclnext;
  };
  iface->tables = NULL;

  /* Remove queue ACLs */
  rp = &queue_pool;
  cb[0]=0;
  while (*rp != NULL) {
    if (strncmp((*rp)->ifname, iface->ifname, IFNAMSIZ) == 0) {
      sprintf(cb+strlen(cb), " %d", (*rp)->real_number);
      rp1 = *rp;
      *rp = (*rp)->next;
      Freee(MB_IFACE, rp1);
    } else {
      rp = &((*rp)->next);
    };
  };
  if (cb[0]!=0)
    ExecCmd(LG_IFACE2, "%s queue delete%s",
      PATH_IPFW, cb);

  /* Remove pipe ACLs */
  rp = &pipe_pool;
  cb[0]=0;
  while (*rp != NULL) {
    if (strncmp((*rp)->ifname, iface->ifname, IFNAMSIZ) == 0) {
      sprintf(cb+strlen(cb), " %d", (*rp)->real_number);
      rp1 = *rp;
      *rp = (*rp)->next;
      Freee(MB_IFACE, rp1);
    } else {
      rp = &((*rp)->next);
    };
  };
  if (cb[0]!=0)
    ExecCmd(LG_IFACE2, "%s pipe delete%s",
      PATH_IPFW, cb);

  NgFuncConfigBPF(bund, BPF_MODE_OFF);
}

/*
 * IfaceListenInput()
 *
 * A packet was received on our demand snooping hook. Stimulate a connection.
 */

void
IfaceListenInput(int proto, Mbuf pkt)
{
  IfaceState	const iface = &bund->iface;
  int		const isDemand = IfaceIsDemand(proto, pkt);
  Fsm		fsm;

  /* Does this count as demand traffic? */
  if (isDemand)
    iface->traffic[0] = TRUE;

  /* Get FSM for protocol (for now, we know it's IP) */
  assert(proto == PROTO_IP);
  fsm = &bund->ipcp.fsm;

  if (OPEN_STATE(fsm->state)) {
    if (bund->bm.n_up > 0) {
#ifndef USE_NG_TCPMSS
      if (Enabled(&iface->options, IFACE_CONF_TCPMSSFIX)) {
	if (proto == PROTO_IP)
	  IfaceCorrectMSS(pkt, MAXMSS(iface->mtu));
      } else
	Log(LG_IFACE, ("[%s] unexpected outgoing packet, len=%d",
	  bund->name, MBLEN(pkt)));
#endif
      NgFuncWriteFrame(bund->name, MPD_HOOK_DEMAND_TAP, pkt);
    } else {
      IfaceCachePkt(proto, pkt);
    }
  /* Maybe do dial-on-demand here */
  } else if (iface->open && isDemand) {
    Log(LG_IFACE, ("[%s] outgoing packet is demand", bund->name));
    RecordLinkUpDownReason(NULL, 1, STR_DEMAND, "%s", AsciifyPacket(pkt));
    BundOpenLinks();
    IfaceCachePkt(proto, pkt);
  } else {
    PFREE(pkt);
  }
}

#ifndef USE_NG_TCPMSS
/*
 * IfaceListenOutput()
 *
 * Now used only for TCP MSS hacking.
 */

void
IfaceListenOutput(int proto, Mbuf pkt)
{
  IfaceState	const iface = &bund->iface;

  if (Enabled(&iface->options, IFACE_CONF_TCPMSSFIX)) {
    if (proto == PROTO_IP)
      IfaceCorrectMSS(pkt, MAXMSS(iface->mtu));
  } else
    Log(LG_IFACE, ("[%s] unexpected outgoing packet, len=%d",
       bund->name, MBLEN(pkt)));
  NgFuncWriteFrame(bund->name, MPD_HOOK_MSSFIX_OUT, pkt);
}
#endif

/*
 * IfaceAllocACL ()
 *
 * Allocates unique real number for new ACL and adds it to the list of used ones.
 */

static int
IfaceAllocACL(struct acl_pool ***ap, int start, char *ifname, int number)
{
    int	i;
    struct acl_pool **rp,*rp1;

    rp1 = Malloc(MB_IFACE, sizeof(struct acl_pool));
    strncpy(rp1->ifname, ifname, IFNAMSIZ);
    rp1->acl_number = number;

    rp = *ap;
    i = start;
    while (*rp != NULL && (*rp)->real_number <= i) {
        i = (*rp)->real_number+1;
        rp = &((*rp)->next);
    };
    if (*rp == NULL) {
        rp1->next = NULL;
    } else {
        rp1->next = *rp;
    };
    rp1->real_number = i;
    *rp = rp1;
    *ap = rp;
    return(i);
};

/*
 * IfaceFindACL ()
 *
 * Finds ACL in the list and gets its real number.
 */

static int
IfaceFindACL (struct acl_pool *ap, char * ifname, int number)
{
    int	i;
    struct acl_pool *rp;

    rp=ap;
    i=-1;
    while (rp != NULL) {
	if ((rp->acl_number == number) && (strncmp(rp->ifname,ifname,IFNAMSIZ) == 0)) {
    	    i = rp->real_number;
	    break;
	};
        rp = rp->next;
    };
    return(i);
};

/*
 * IFaceParseACL ()
 *
 * Parces ACL and replaces %r, %p and %q macroses 
 * by the real numbers of rules, queues and pipes.
 */

static char *
IFaceParseACL (char * src, char * ifname)
{
    char *buf,*buf1;
    char *begin,*param,*end;
    char t;
    int num,real_number;
    struct acl_pool *ap;
    
    buf = Malloc(MB_IFACE, ACL_LEN+1);
    buf1 = Malloc(MB_IFACE, ACL_LEN+1);

    strncpy(buf,src,ACL_LEN);
    do {
        end = buf;
	begin = strsep(&end, "%");
	param = strsep(&end, " ");
	if (param != NULL) {
	    if (sscanf(param,"%c%d", &t, &num) == 2) {
		switch (t) {
		    case 'r':
			ap = rule_pool;
			break;
		    case 'p':
			ap = pipe_pool;
			break;
		    case 'q':
			ap = queue_pool;
			break;
		    case 't':
			ap = table_pool;
			break;
		    default:
			ap = NULL;
		};
		real_number = IfaceFindACL(ap,ifname,num);
		if (end != NULL) {
		    snprintf(buf1, ACL_LEN, "%s%d %s", begin, real_number, end);
		} else {
		    snprintf(buf1, ACL_LEN, "%s%d", begin, real_number);
		};
		strncpy(buf, buf1, ACL_LEN);
	    };
	};
    } while (end != NULL);
    Freee(MB_IFACE, buf1);
    return(buf);
};

/*
 * IfaceIpIfaceUp()
 *
 * Bring up the IP interface. The "ready" flag means that
 * IPCP is also up and we can deliver packets immediately.
 */

void
IfaceIpIfaceUp(int ready)
{
  IfaceState		const iface = &bund->iface;
  struct sockaddr_dl	hwa;
  char			hisaddr[20],selfaddr[20];
  u_char		*ether;
  int			k;
  char			buf[64];
#ifdef USE_NG_NAT
  char                  path[NG_PATHLEN + 1];
#endif

  /* For good measure */
  BundUpdateParams();

  if (ready) {
    in_addrtou_range(&bund->ipcp.want_addr, 32, &iface->self_addr);
    in_addrtou_addr(&bund->ipcp.peer_addr, &iface->peer_addr);
  }

  /* Set addresses and bring interface up */
  ExecCmd(LG_IFACE2, "%s %s %s %s",
    PATH_IFCONFIG, iface->ifname, u_rangetoa(&iface->self_addr,selfaddr,sizeof(selfaddr)), 
    u_addrtoa(&iface->peer_addr,hisaddr,sizeof(hisaddr)));

  /* Proxy ARP for peer if desired and peer's address is known */
  u_addrclear(&iface->proxy_addr);
  if (Enabled(&iface->options, IFACE_CONF_PROXY)) {
    if (u_addrempty(&iface->peer_addr)) {
      Log(LG_IFACE,
	("[%s] can't proxy arp for %s",
	bund->name, u_addrtoa(&iface->peer_addr,hisaddr,sizeof(hisaddr))));
    } else if (GetEther(&iface->peer_addr, &hwa) < 0) {
      Log(LG_IFACE,
	("[%s] no interface to proxy arp on for %s",
	bund->name, u_addrtoa(&iface->peer_addr,hisaddr,sizeof(hisaddr))));
    } else {
      ether = (u_char *) LLADDR(&hwa);
      if (ExecCmd(LG_IFACE2,
	  "%s -S %s %x:%x:%x:%x:%x:%x pub",
	  PATH_ARP, u_addrtoa(&iface->peer_addr,hisaddr,sizeof(hisaddr)),
	  ether[0], ether[1], ether[2],
	  ether[3], ether[4], ether[5]) == 0)
	iface->proxy_addr = iface->peer_addr;
    }
  }

  /* Add loopback route */
  ExecCmd(LG_IFACE2, "%s add %s/32 -iface lo0",
    PATH_ROUTE, u_addrtoa(&iface->self_addr.addr,selfaddr,sizeof(selfaddr)));
  
  /* Add static routes */
  for (k = 0; k < iface->n_routes; k++) {
    IfaceRoute	const r = &iface->routes[k];

    if (u_rangefamily(&r->dest)==AF_INET) {
	r->ok = (ExecCmd(LG_IFACE2, "%s add %s %s",
	    PATH_ROUTE, u_rangetoa(&r->dest, buf, sizeof(buf)), 
		u_addrtoa(&iface->peer_addr,hisaddr,sizeof(hisaddr))) == 0);
    }
  }
  /* Add dynamic routes */
  for (k = 0; k < bund->params.n_routes; k++) {
    IfaceRoute	const r = &bund->params.routes[k];

    if (u_rangefamily(&r->dest)==AF_INET) {
	r->ok = (ExecCmd(LG_IFACE2, "%s add %s %s",
	    PATH_ROUTE, u_rangetoa(&r->dest, buf, sizeof(buf)), 
		u_addrtoa(&iface->peer_addr,hisaddr,sizeof(hisaddr))) == 0);
    }
  }

#ifdef USE_NG_NAT
  /* Set NAT IP */
  if (bund->nat) {
    snprintf(path, sizeof(path), "mpd%d-%s-nat:", gPid, bund->name);
    if (NgSendMsg(bund->csock, path,
    	    NGM_NAT_COOKIE, NGM_NAT_SET_IPADDR, &iface->self_addr.addr.u.ip4, sizeof(iface->self_addr.addr.u.ip4)) < 0) {
	Log(LG_ERR, ("[%s] can't set NAT ip: %s",
    	    bund->name, strerror(errno)));
    }
  }
#endif

  /* Call "up" script */
  if (*iface->up_script) {
    char	selfbuf[40],peerbuf[40];
    char	ns1buf[21], ns2buf[21];

    if(bund->ipcp.want_dns[0].s_addr != 0)
      snprintf(ns1buf, sizeof(ns1buf), "dns1 %s", inet_ntoa(bund->ipcp.want_dns[0]));
    else
      ns1buf[0] = '\0';
    if(bund->ipcp.want_dns[1].s_addr != 0)
      snprintf(ns2buf, sizeof(ns2buf), "dns2 %s", inet_ntoa(bund->ipcp.want_dns[1]));
    else
      ns2buf[0] = '\0';

    ExecCmd(LG_IFACE2, "%s %s inet %s %s %s %s %s",
      iface->up_script, iface->ifname, u_rangetoa(&iface->self_addr,selfbuf, sizeof(selfbuf)),
      u_addrtoa(&iface->peer_addr, peerbuf, sizeof(peerbuf)), 
      *bund->params.authname ? bund->params.authname : "-", 
      ns1buf, ns2buf);
  }

}

/*
 * IfaceIpIfaceDown()
 *
 * Bring down the IP interface. This implies we're no longer ready.
 */

void
IfaceIpIfaceDown(void)
{
  IfaceState	const iface = &bund->iface;
  int		k;
  char          buf[64];

  /* Call "down" script */
  if (*iface->down_script) {
    ExecCmd(LG_IFACE2, "%s %s inet %s",
      iface->down_script, iface->ifname, 
      *bund->params.authname ? bund->params.authname : "-");
  }

  /* Delete dynamic routes */
  for (k = 0; k < bund->params.n_routes; k++) {
    IfaceRoute	const r = &bund->params.routes[k];

    if (u_rangefamily(&r->dest)==AF_INET) {
	if (!r->ok)
	    continue;
	ExecCmd(LG_IFACE2, "%s delete %s",
	    PATH_ROUTE, u_rangetoa(&r->dest, buf, sizeof(buf)));
	r->ok = 0;
    }
  }
  /* Delete static routes */
  for (k = 0; k < iface->n_routes; k++) {
    IfaceRoute	const r = &iface->routes[k];

    if (u_rangefamily(&r->dest)==AF_INET) {
	if (!r->ok)
	    continue;
	ExecCmd(LG_IFACE2, "%s delete %s",
	    PATH_ROUTE, u_rangetoa(&r->dest, buf, sizeof(buf)));
	r->ok = 0;
    }
  }

  /* Delete any proxy arp entry */
  if (!u_addrempty(&iface->proxy_addr))
    ExecCmd(LG_IFACE2, "%s -d %s", PATH_ARP, u_addrtoa(&iface->proxy_addr, buf, sizeof(buf)));
  u_addrclear(&iface->proxy_addr);

  /* Delete loopback route */
  ExecCmd(LG_IFACE2, "%s delete %s/32 -iface lo0",
    PATH_ROUTE, u_addrtoa(&iface->self_addr.addr,buf,sizeof(buf)));

  /* Bring down system interface */
  ExecCmd(LG_IFACE2, "%s %s %s delete -link0", 
    PATH_IFCONFIG, iface->ifname, u_addrtoa(&iface->self_addr.addr,buf,sizeof(buf)));

}

/*
 * IfaceIpv6IfaceUp()
 *
 * Bring up the IPv6 interface. The "ready" flag means that
 * IPCP is also up and we can deliver packets immediately. We signal
 * that the interface is not "ready" with the IFF_LINK0 flag.
 */

void
IfaceIpv6IfaceUp(int ready)
{
  IfaceState	const iface = &bund->iface;
  int		k;
  char		buf[64];

  /* For good measure */
  BundUpdateParams();

  if (ready) {

    iface->self_ipv6_addr.family = AF_INET6;
    iface->self_ipv6_addr.u.ip6.__u6_addr.__u6_addr16[0] = 0x80fe;  /* Network byte order */
    iface->self_ipv6_addr.u.ip6.__u6_addr.__u6_addr16[1] = 0x0000;
    iface->self_ipv6_addr.u.ip6.__u6_addr.__u6_addr16[2] = 0x0000;
    iface->self_ipv6_addr.u.ip6.__u6_addr.__u6_addr16[3] = 0x0000;
    iface->self_ipv6_addr.u.ip6.__u6_addr.__u6_addr16[4] = ((u_short*)bund->ipv6cp.myintid)[0];
    iface->self_ipv6_addr.u.ip6.__u6_addr.__u6_addr16[5] = ((u_short*)bund->ipv6cp.myintid)[1];
    iface->self_ipv6_addr.u.ip6.__u6_addr.__u6_addr16[6] = ((u_short*)bund->ipv6cp.myintid)[2];
    iface->self_ipv6_addr.u.ip6.__u6_addr.__u6_addr16[7] = ((u_short*)bund->ipv6cp.myintid)[3];

    iface->peer_ipv6_addr.family = AF_INET6;
    iface->peer_ipv6_addr.u.ip6.__u6_addr.__u6_addr16[0] = 0x80fe;  /* Network byte order */
    iface->peer_ipv6_addr.u.ip6.__u6_addr.__u6_addr16[1] = 0x0000;
    iface->peer_ipv6_addr.u.ip6.__u6_addr.__u6_addr16[2] = 0x0000;
    iface->peer_ipv6_addr.u.ip6.__u6_addr.__u6_addr16[3] = 0x0000;
    iface->peer_ipv6_addr.u.ip6.__u6_addr.__u6_addr16[4] = ((u_short*)bund->ipv6cp.hisintid)[0];
    iface->peer_ipv6_addr.u.ip6.__u6_addr.__u6_addr16[5] = ((u_short*)bund->ipv6cp.hisintid)[1];
    iface->peer_ipv6_addr.u.ip6.__u6_addr.__u6_addr16[6] = ((u_short*)bund->ipv6cp.hisintid)[2];
    iface->peer_ipv6_addr.u.ip6.__u6_addr.__u6_addr16[7] = ((u_short*)bund->ipv6cp.hisintid)[3];

    /* Set addresses and bring interface up */
    ExecCmd(LG_IFACE2, "%s %s inet6 %s%%%s",
	PATH_IFCONFIG, iface->ifname, 
	u_addrtoa(&iface->self_ipv6_addr, buf, sizeof(buf)), iface->ifname);
  }
  
  /* Add static routes */
  for (k = 0; k < iface->n_routes; k++) {
    IfaceRoute	const r = &iface->routes[k];

    if (u_rangefamily(&r->dest)==AF_INET6) {
	r->ok = (ExecCmd(LG_IFACE2, "%s add -inet6 %s -interface %s",
	    PATH_ROUTE, u_rangetoa(&r->dest, buf, sizeof(buf)), iface->ifname) == 0);
    }
  }
  /* Add dynamic routes */
  for (k = 0; k < bund->params.n_routes; k++) {
    IfaceRoute	const r = &bund->params.routes[k];

    if (u_rangefamily(&r->dest)==AF_INET6) {
	r->ok = (ExecCmd(LG_IFACE2, "%s add -inet6 %s -interface %s",
	    PATH_ROUTE, u_rangetoa(&r->dest, buf, sizeof(buf)), iface->ifname) == 0);
    }
  }

  /* Call "up" script */
  if (*iface->up_script) {
    char	selfbuf[64],peerbuf[64];

    ExecCmd(LG_IFACE2, "%s %s inet6 %s%%%s %s%%%s %s",
      iface->up_script, iface->ifname, 
      u_addrtoa(&iface->self_ipv6_addr, selfbuf, sizeof(selfbuf)), iface->ifname,
      u_addrtoa(&iface->peer_ipv6_addr, peerbuf, sizeof(peerbuf)), iface->ifname, 
      *bund->params.authname ? bund->params.authname : "-");
  }

}

/*
 * IfaceIpv6IfaceDown()
 *
 * Bring down the IPv6 interface. This implies we're no longer ready.
 */

void
IfaceIpv6IfaceDown(void)
{
  IfaceState	const iface = &bund->iface;
  int 		k;
  char		buf[64];

  /* Call "down" script */
  if (*iface->down_script) {
    ExecCmd(LG_IFACE2, "%s %s inet6 %s",
      iface->down_script, iface->ifname, 
      *bund->params.authname ? bund->params.authname : "-");
  }

  /* Delete dynamic routes */
  for (k = 0; k < bund->params.n_routes; k++) {
    IfaceRoute	const r = &bund->params.routes[k];

    if (u_rangefamily(&r->dest)==AF_INET6) {
	if (!r->ok)
	    continue;
	ExecCmd(LG_IFACE2, "%s delete -inet6 %s -interface %s",
	    PATH_ROUTE, u_rangetoa(&r->dest, buf, sizeof(buf)), iface->ifname);
	r->ok = 0;
    }
  }
  /* Delete static routes */
  for (k = 0; k < iface->n_routes; k++) {
    IfaceRoute	const r = &iface->routes[k];

    if (u_rangefamily(&r->dest)==AF_INET6) {
	if (!r->ok)
	    continue;
	ExecCmd(LG_IFACE2, "%s delete -inet6 %s -interface %s",
	    PATH_ROUTE, u_rangetoa(&r->dest, buf, sizeof(buf)), iface->ifname);
	r->ok = 0;
    }
  }

  if (!u_addrempty(&iface->self_ipv6_addr)) {
    /* Bring down system interface */
    ExecCmd(LG_IFACE2, "%s %s inet6 %s%%%s delete",
	PATH_IFCONFIG, iface->ifname,
        u_addrtoa(&iface->self_ipv6_addr, buf, sizeof(buf)), iface->ifname);
  }

}

/*
 * IfaceIdleTimeout()
 */

static void
IfaceIdleTimeout(void *arg)
{
  IfaceState			const iface = &bund->iface;
  char				path[NG_PATHLEN + 1];
  struct ng_bpf_hookstat	oldStats;
  union {
      u_char			buf[sizeof(struct ng_mesg) + sizeof(oldStats)];
      struct ng_mesg		reply;
  }				u;
  int				k;

  /* Get updated bpf node traffic statistics */
  oldStats = iface->idleStats;
  snprintf(path, sizeof(path), "mpd%d-%s:%s", gPid, bund->name,
      NG_PPP_HOOK_INET);
  if (NgFuncSendQuery(path, NGM_BPF_COOKIE, NGM_BPF_GET_STATS, BPF_HOOK_IFACE,
      sizeof(BPF_HOOK_IFACE), &u.reply, sizeof(u), NULL) < 0) {
    Log(LG_ERR, ("[%s] can't get %s stats: %s",
      bund->name, NG_BPF_NODE_TYPE, strerror(errno)));
    return;
  }
  memcpy(&iface->idleStats, u.reply.data, sizeof(iface->idleStats));

  /* Mark current traffic period if there was traffic */
  if (iface->idleStats.recvFrames + iface->idleStats.xmitFrames > 
	oldStats.recvFrames + oldStats.xmitFrames) {
    iface->traffic[0] = TRUE;
  } else {		/* no demand traffic for a whole idle timeout period? */
    for (k = 0; k < IFACE_IDLE_SPLIT && !iface->traffic[k]; k++);
    if (k == IFACE_IDLE_SPLIT) {
      IfaceIdleTimerExpired(NULL);
      return;
    }
  }

  /* Shift traffic history */
  memmove(iface->traffic + 1,
    iface->traffic, (IFACE_IDLE_SPLIT - 1) * sizeof(*iface->traffic));
  iface->traffic[0] = FALSE;

  /* Restart timer */
  TimerStart(&iface->idleTimer);
}

/*
 * IfaceIdleTimerExpired()
 *
 * The idle timeout expired with no demand traffic. Shutdown the
 * link gracefully. Give custom code a chance to do any last minute
 * things before shutting down though. At this point, the shutdown
 * is going to happen, even if there is subsequent demand.
 */

static void
IfaceIdleTimerExpired(void *arg)
{
  IfaceState	const iface = &bund->iface;

  /* We already did the final short delay, really shut down now */
  if (arg != NULL) {
    RecordLinkUpDownReason(NULL, 0, STR_IDLE_TIMEOUT, NULL);
    BundClose();
    return;
  }

  /* Idle timeout first detected */
  Log(LG_BUND, ("[%s] idle timeout after %d seconds",
    bund->name, iface->idleTimer.load * IFACE_IDLE_SPLIT / SECONDS));

  IfaceIdleTimerExpired((void *)1);
}

/*
 * IfaceSessionTimeout()
 */

static void
IfaceSessionTimeout(void *arg)
{
  Log(LG_BUND, ("[%s] session timeout ", bund->name));

  RecordLinkUpDownReason(NULL, 0, STR_SESSION_TIMEOUT, NULL);

  BundClose();

}

/*
 * IfaceCachePkt()
 *
 * A packet caused dial-on-demand; save it for later if possible.
 * Consumes the mbuf in any case.
 */

static void
IfaceCachePkt(int proto, Mbuf pkt)
{
  IfaceState	const iface = &bund->iface;

  /* Only cache network layer data */
  if (!PROT_NETWORK_DATA(proto)) {
    PFREE(pkt);
    return;
  }

  /* Release previously cached packet, if any, and save this one */
  if (iface->dodCache.pkt)
    PFREE(iface->dodCache.pkt);
  iface->dodCache.pkt = pkt;
  iface->dodCache.proto = proto;
  iface->dodCache.ts = time(NULL);
}

/*
 * IfaceCacheSend()
 *
 * Send cached packet
 */

static void
IfaceCacheSend(void)
{
  IfaceState	const iface = &bund->iface;

  if (iface->dodCache.pkt) {
    if (iface->dodCache.ts + MAX_DOD_CACHE_DELAY < time(NULL))
      PFREE(iface->dodCache.pkt);
    else {
      assert(iface->dodCache.proto == PROTO_IP);
      if (NgFuncWriteFrame(bund->name,
	  MPD_HOOK_DEMAND_TAP, iface->dodCache.pkt) < 0) {
	Log(LG_ERR, ("[%s] can't write cached pkt: %s",
	  bund->name, strerror(errno)));
      }
    }
    iface->dodCache.pkt = NULL;
  }
}

/*
 * IfaceIsDemand()
 *
 * Determine if this outgoing packet qualifies for dial-on-demand
 * Packet must be contiguous
 */

static int
IfaceIsDemand(int proto, Mbuf pkt)
{
  switch (proto) {
    case PROTO_IP:
      {
	u_char	buf[256];
	struct ip       *const ip = (struct ip *)(&buf);

	mbcopy(pkt, buf, sizeof(buf));
	switch (ip->ip_p) {
	  case IPPROTO_IGMP:		/* No multicast stuff */
	    return(0);
	  case IPPROTO_ICMP:
	    {
	      struct icmp	*const icmp =
		(struct icmp *) ((u_int32_t *) ip + ip->ip_hl);

	      switch (icmp->icmp_type)	/* No ICMP replies */
	      {
		case ICMP_ECHOREPLY:
		case ICMP_UNREACH:
		case ICMP_REDIRECT:
		  return(0);
		default:
		  break;
	      }
	    }
	    break;
	  case IPPROTO_UDP:
	    {
	      struct udphdr	*const udp =
		(struct udphdr *) ((u_int32_t *) ip + ip->ip_hl);

#define NTP_PORT	123
	      if (ntohs(udp->uh_dport) == NTP_PORT)	/* No NTP packets */
		return(0);
	    }
	    break;
	  case IPPROTO_TCP:
	    {
	      struct tcphdr	*const tcp =
		(struct tcphdr *) ((u_int32_t *) ip + ip->ip_hl);

	      if (tcp->th_flags & TH_RST)	/* No TCP reset packets */
		return(0);
	    }
	    break;
	  default:
	    break;
	}
	break;
      }
    default:
      break;
  }
  return(1);
}

/*
 * IfaceSetCommand()
 */

static int
IfaceSetCommand(int ac, char *av[], void *arg)
{
  IfaceState	const iface = &bund->iface;

  if (ac == 0)
    return(-1);
  switch ((intptr_t)arg) {
    case SET_IDLE:
      iface->idle_timeout = atoi(*av);
      break;
    case SET_SESSION:
      iface->session_timeout = atoi(*av);
      break;
    case SET_ADDRS:
      {
	struct u_range	self_addr;
	struct u_addr	peer_addr;

	/* Parse */
	if (ac != 2)
	  return(-1);
	if (!ParseRange(av[0], &self_addr, ALLOW_IPV4)) {
	  Log(LG_ERR, ("bad IP address \"%s\"", av[0]));
	  break;
	}
	if (!ParseAddr(av[1], &peer_addr, ALLOW_IPV4)) {
	  Log(LG_ERR, ("bad IP address \"%s\"", av[1]));
	  break;
	}

	/* OK */
	iface->self_addr = self_addr;
	iface->peer_addr = peer_addr;
      }
      break;

    case SET_ROUTE:
      {
	struct u_range		range;
	struct ifaceroute	r;

	/* Check */
	if (ac != 1)
	  return(-1);
	if (iface->n_routes >= IFACE_MAX_ROUTES) {
	  Log(LG_ERR, ("iface: too many routes"));
	  break;
	}

	/* Get dest address */
	if (!strcasecmp(av[0], "default")) {
	  u_rangeclear(&range);
	  range.addr.family=AF_INET;
	}
	else if (!ParseRange(av[0], &range, ALLOW_IPV4|ALLOW_IPV6)) {
	  Log(LG_ERR, ("route: bad dest address \"%s\"", av[0]));
	  break;
	}
	r.dest=range;
	r.ok=0;
	iface->routes[iface->n_routes++] = r;
      }
      break;

    case SET_MTU:
      {
	int	max_mtu;

	max_mtu = atoi(av[0]);
	if (max_mtu < IFACE_MIN_MTU || max_mtu > IFACE_MAX_MTU) {
	  Log(LG_ERR, ("invalid interface mtu %d", max_mtu));
	  break;
	}
	iface->max_mtu = max_mtu;
      }
      break;

    case SET_UP_SCRIPT:
      switch (ac) {
	case 0:
	  *iface->up_script = 0;
	  break;
	case 1:
	  snprintf(iface->up_script,
	    sizeof(iface->up_script), "%s", av[0]);
	  break;
	default:
	  return(-1);
      }
      break;

    case SET_DOWN_SCRIPT:
      switch (ac) {
	case 0:
	  *iface->down_script = 0;
	  break;
	case 1:
	  snprintf(iface->down_script,
	    sizeof(iface->down_script), "%s", av[0]);
	  break;
	default:
	  return(-1);
      }
      break;

    case SET_ENABLE:
      EnableCommand(ac, av, &iface->options, gConfList);
      break;

    case SET_DISABLE:
      DisableCommand(ac, av, &iface->options, gConfList);
      break;

    default:
      assert(0);
  }
  return(0);
}

/*
 * IfaceStat()
 */

int
IfaceStat(int ac, char *av[], void *arg)
{
  IfaceState	const iface = &bund->iface;
  int		k;
  char          buf[64];

  Printf("Interface configuration:\r\n");
  Printf("\tName            : %s\r\n", iface->ifname);
  Printf("\tMaximum MTU     : %d bytes\r\n", iface->max_mtu);
  Printf("\tIdle timeout    : %d seconds\r\n", iface->idle_timeout);
  Printf("\tSession timeout : %d seconds\r\n", iface->session_timeout);
  Printf("\tEvent scripts\r\n");
  Printf("\t  up-script     : \"%s\"\r\n",
    *iface->up_script ? iface->up_script : "<none>");
  Printf("\t  down-script   : \"%s\"\r\n",
    *iface->down_script ? iface->down_script : "<none>");
  Printf("Interface options:\r\n");
  OptStat(&iface->options, gConfList);
  if (iface->n_routes) {
    Printf("Static routes via peer:\r\n");
    for (k = 0; k < iface->n_routes; k++) {
	Printf("\t%s\r\n", u_rangetoa(&iface->routes[k].dest,buf,sizeof(buf)));
    }
  }
  Printf("Interface status:\r\n");
  Printf("\tStatus          : %s\r\n", iface->open ? "OPEN" : "CLOSED");
  Printf("\tMTU             : %d bytes\r\n", iface->mtu);
  if (!u_rangeempty(&iface->self_addr)) {
    Printf("\tIP Addresses    : %s -> ", u_rangetoa(&iface->self_addr,buf,sizeof(buf)));
    Printf("%s\r\n", u_addrtoa(&iface->peer_addr,buf,sizeof(buf)));
  }
  if (!u_addrempty(&iface->self_ipv6_addr)) {
    Printf("\tIPv6 Addresses  : %s%%%s -> ", 
	u_addrtoa(&iface->self_ipv6_addr,buf,sizeof(buf)), iface->ifname);
    Printf("%s%%%s\r\n", u_addrtoa(&iface->peer_ipv6_addr,buf,sizeof(buf)), iface->ifname);
  }
  if (bund->params.n_routes) {
    Printf("Dynamic routes via peer:\r\n");
    for (k = 0; k < bund->params.n_routes; k++) {
	Printf("\t%s\r\n", u_rangetoa(&bund->params.routes[k].dest,buf,sizeof(buf)));
    }
  }
  return(0);
}

/*
 * IfaceSetMTU()
 *
 * Set MTU and bandwidth on bundle's interface
 */

void
IfaceSetMTU(int mtu)
{
  IfaceState	const iface = &bund->iface;
  struct ifreq	ifr;
  int		s;

  /* Get socket */
  if ((s = socket(PF_INET, SOCK_DGRAM, 0)) < 0) {
    Perror("[%s] IFACE: Can't get socket to set MTU!", bund->name);
    return;
  }

  if ((bund->params.mtu > 0) && (mtu > bund->params.mtu)) {
    mtu = bund->params.mtu;
    Log(LG_IFACE2, ("[%s] IFACE: forcing MTU of auth backend: %d bytes",
      bund->name, mtu));
  }

  /* Limit MTU to configured maximum */
  if (mtu > iface->max_mtu) {
      mtu = iface->max_mtu;
  }

  /* Set MTU on interface */
  memset(&ifr, 0, sizeof(ifr));
  strncpy(ifr.ifr_name, bund->iface.ifname, sizeof(ifr.ifr_name));
  ifr.ifr_mtu = mtu;
  Log(LG_IFACE2, ("[%s] IFACE: setting %s MTU to %d bytes",
    bund->name, bund->iface.ifname, mtu));
  if (ioctl(s, SIOCSIFMTU, (char *)&ifr) < 0)
    Perror("[%s] IFACE: ioctl(%s, %s)", bund->name, bund->iface.ifname, "SIOCSIFMTU");
  close(s);

  /* Save MTU */
  iface->mtu = mtu;
}

#ifndef USE_NG_TCPMSS
static void
IfaceCorrectMSS(Mbuf pkt, uint16_t maxmss)
{
  struct ip	*iphdr;
  struct tcphdr	*tc;
  int		pktlen, hlen, olen, optlen, accumulate;
  uint16_t	*mss;
  u_char	*opt;

  iphdr = (struct ip *)MBDATA(pkt);
  hlen = iphdr->ip_hl << 2;
  pktlen = plength(pkt) - hlen;
  tc = (struct tcphdr *)(MBDATA(pkt) + hlen);
  hlen = tc->th_off << 2;

  /* Invalid header length or header without options. */
  if (hlen <= sizeof(struct tcphdr) || hlen > pktlen)
    return;

  /* MSS option only allowed within SYN packets. */  
  if (!(tc->th_flags & TH_SYN))
    return;

  for (olen = hlen - sizeof(struct tcphdr), opt = (u_char *)(tc + 1);
	olen > 0; olen -= optlen, opt += optlen) {
    if (*opt == TCPOPT_EOL)
      break;
    else if (*opt == TCPOPT_NOP)
      optlen = 1;
    else {
      optlen = *(opt + 1);
      if (optlen <= 0 || optlen > olen)
	break;
      if (*opt == TCPOPT_MAXSEG) {
	if (optlen != TCPOLEN_MAXSEG)
	  continue;
	mss = (u_int16_t *)(opt + 2);
	if (ntohs(*mss) > maxmss) {
	  accumulate = *mss;
	  *mss = htons(maxmss);
	  accumulate -= *mss;
	  ADJUST_CHECKSUM(accumulate, tc->th_sum);
	}
      }
    }
  }
}
#endif
