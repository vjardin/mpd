
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
#include <netgraph/tee/ng_tee.h>
#include <netgraph/ksocket/ng_ksocket.h>
#include <netgraph/tcpmss/ng_tcpmss.h>
#else
#include <netgraph/ng_iface.h>
#include <netgraph/ng_bpf.h>
#include <netgraph/ng_tee.h>
#include <netgraph/ng_ksocket.h>
#include <netgraph/ng_tcpmss.h>
#endif
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#ifdef USE_NG_NAT
#include <netgraph/ng_nat.h>
#endif
#ifdef USE_NG_TCPMSS
#include <netgraph/ng_tcpmss.h>
#endif
#ifdef USE_NG_NETFLOW
#include <netgraph/netflow/ng_netflow.h>
#endif
#ifdef USE_NG_CAR
#include <netgraph/ng_car.h>
#endif

#include <pcap.h>

/*
 * DEFINITIONS
 */

  #define TEMPHOOK		"temphook"

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

  static int	IfaceNgIpInit(Bund b, int ready);
  static void	IfaceNgIpShutdown(Bund b);
  static int	IfaceNgIpv6Init(Bund b, int ready);
  static void	IfaceNgIpv6Shutdown(Bund b);

#ifdef USE_NG_NETFLOW
  static int	IfaceInitNetflow(Bund b, char *path, char *hook, char out);
  static int	IfaceSetupNetflow(Bund b, char out);
  static void	IfaceShutdownNetflow(Bund b, char out);
#endif

#ifdef USE_NG_NAT
  static int	IfaceInitNAT(Bund b, char *path, char *hook);
  static int	IfaceSetupNAT(Bund b);
  static void	IfaceShutdownNAT(Bund b);
#endif

  static int	IfaceInitTee(Bund b, char *path, char *hook);
  static void	IfaceShutdownTee(Bund b);

  static int    IfaceInitMSS(Bund b, char *path, char *hook);
  static void	IfaceSetupMSS(Bund b, uint16_t maxMSS);
  static void	IfaceShutdownMSS(Bund b);

  static int    IfaceInitLimits(Bund b, char *path, char *hook);
  static void	IfaceSetupLimits(Bund b);
  static void	IfaceShutdownLimits(Bund b);

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
    { 0,	IFACE_CONF_TEE,			"tee"		},
    { 0,	IFACE_CONF_NAT,			"nat"		},
    { 0,	IFACE_CONF_NETFLOW_IN,		"netflow-in"	},
    { 0,	IFACE_CONF_NETFLOW_OUT,		"netflow-out"	},
    { 0,	0,				NULL		},
  };

  #ifdef USE_NG_TCPMSS
  int gTcpMSSNodeRefs = 0;
  #endif

  struct acl_pool * rule_pool = NULL; /* Pointer to the first element in the list of rules */
  struct acl_pool * pipe_pool = NULL; /* Pointer to the first element in the list of pipes */
  struct acl_pool * queue_pool = NULL; /* Pointer to the first element in the list of queues */
  struct acl_pool * table_pool = NULL; /* Pointer to the first element in the list of tables */
  int rule_pool_start = 10000; /* Initial number of ipfw rules pool */
  int pipe_pool_start = 10000; /* Initial number of ipfw dummynet pipe pool */
  int queue_pool_start = 10000; /* Initial number of ipfw dummynet queue pool */
  int table_pool_start = 32; /* Initial number of ipfw tables pool */

  /* A BPF filter that matches TCP SYN packets */
  static const struct bpf_insn gTCPSYNProg[] = {
/*00*/	BPF_STMT(BPF_LD+BPF_B+BPF_ABS, 9),		/* A <- IP protocol */
/*01*/	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, IPPROTO_TCP, 0, 6), /* !TCP => 8 */
/*02*/	BPF_STMT(BPF_LD+BPF_H+BPF_ABS, 6),	/* A <- fragmentation offset */
/*03*/	BPF_JUMP(BPF_JMP+BPF_JSET+BPF_K, 0x1fff, 4, 0),	/* fragment => 8 */
/*04*/	BPF_STMT(BPF_LDX+BPF_B+BPF_MSH, 0),		/* X <- header len */
/*05*/	BPF_STMT(BPF_LD+BPF_B+BPF_IND, 13),		/* A <- TCP flags */
/*06*/	BPF_JUMP(BPF_JMP+BPF_JSET+BPF_K, TH_SYN, 0, 1),	/* !TH_SYN => 8 */
/*07*/	BPF_STMT(BPF_RET+BPF_K, (u_int)-1),		/* accept packet */
/*08*/	BPF_STMT(BPF_RET+BPF_K, 0),			/* reject packet */
  };

  #define TCPSYN_PROG_LEN	(sizeof(gTCPSYNProg) / sizeof(*gTCPSYNProg))

  /* A BPF filter that matches nothing */
  static const struct bpf_insn gNoMatchProg[] = {
	BPF_STMT(BPF_RET+BPF_K, 0)
  };

  #define NOMATCH_PROG_LEN	(sizeof(gNoMatchProg) / sizeof(*gNoMatchProg))

  /* A BPF filter that matches everything */
  static const struct bpf_insn gMatchProg[] = {
	BPF_STMT(BPF_RET+BPF_K, (u_int)-1)
  };

  #define MATCH_PROG_LEN	(sizeof(gMatchProg) / sizeof(*gMatchProg))


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
    Log(LG_IFACE2, ("[%s] IFACE: idle-timeout: %d seconds", 
      bund->name, idle_timeout));
    
    TimerInit(&iface->idleTimer, "IfaceIdle",
      idle_timeout * SECONDS / IFACE_IDLE_SPLIT, IfaceIdleTimeout, NULL);
    TimerStart(&iface->idleTimer);
    iface->traffic[1] = TRUE;
    iface->traffic[0] = FALSE;

    /* Reset statistics */
    memset(&iface->idleStats, 0, sizeof(iface->idleStats));
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

  /* Send any cached packets */
  IfaceCacheSend();

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

//  NgFuncConfigBPF(bund, BPF_MODE_OFF);
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
    RecordLinkUpDownReason(NULL, 1, STR_DEMAND, NULL);
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
  NgFuncWriteFrame(bund->name, MPD_HOOK_TCPMSS_OUT, pkt);
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

  /* For good measure */
  BundUpdateParams();

  if (ready) {
    in_addrtou_range(&bund->ipcp.want_addr, 32, &iface->self_addr);
    in_addrtou_addr(&bund->ipcp.peer_addr, &iface->peer_addr);
    IfaceNgIpInit(bund, ready);
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
  if (iface->nat_up) {
    IfaceSetupNAT(bund);
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
    
  IfaceNgIpShutdown(bund);
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

    IfaceNgIpv6Init(bund, ready);

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

  IfaceNgIpv6Shutdown(bund);
}

/*
 * IfaceIdleTimeout()
 */

static void
IfaceIdleTimeout(void *arg)
{
  IfaceState			const iface = &bund->iface;
  int				k;

  /* Get updated bpf node traffic statistics */
  BundUpdateStats();

  /* Mark current traffic period if there was traffic */
  if (iface->idleStats.recvFrames + iface->idleStats.xmitFrames < 
	bund->stats.recvFrames + bund->stats.xmitFrames) {
    iface->traffic[0] = TRUE;
  } else {		/* no demand traffic for a whole idle timeout period? */
    for (k = 0; k < IFACE_IDLE_SPLIT && !iface->traffic[k]; k++);
    if (k == IFACE_IDLE_SPLIT) {
      IfaceIdleTimerExpired(NULL);
      return;
    }
  }

  iface->idleStats = bund->stats;

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
  Printf("\tAdmin status    : %s\r\n", iface->open ? "OPEN" : "CLOSED");
  Printf("\tStatus          : %s\r\n", iface->up ? "UP" : "DOWN");
  if (iface->up)
    Printf("\tMTU             : %d bytes\r\n", iface->mtu);
  if (iface->ip_up && !u_rangeempty(&iface->self_addr)) {
    Printf("\tIP Addresses    : %s -> ", u_rangetoa(&iface->self_addr,buf,sizeof(buf)));
    Printf("%s\r\n", u_addrtoa(&iface->peer_addr,buf,sizeof(buf)));
  }
  if (iface->ipv6_up && !u_addrempty(&iface->self_ipv6_addr)) {
    Printf("\tIPv6 Addresses  : %s%%%s -> ", 
	u_addrtoa(&iface->self_ipv6_addr,buf,sizeof(buf)), iface->ifname);
    Printf("%s%%%s\r\n", u_addrtoa(&iface->peer_ipv6_addr,buf,sizeof(buf)), iface->ifname);
  }
  if (iface->up && bund->params.n_routes) {
    Printf("Dynamic routes via peer:\r\n");
    for (k = 0; k < bund->params.n_routes; k++) {
	Printf("\t%s\r\n", u_rangetoa(&bund->params.routes[k].dest,buf,sizeof(buf)));
    }
  }
  if (iface->up && (bund->params.acl_limits[0] || bund->params.acl_limits[1])) {
    struct acl	*a;
    Printf("Traffic filters:\r\n");
    for (k = 0; k < ACL_FILTERS; k++) {
	a = bund->params.acl_filters[k];
	while (a) {
	    Printf("\t%d#%d\t: '%s'\r\n", (k + 1), a->number, a->rule);
	    a = a->next;
	}
    }
    Printf("Traffic limits:\r\n");
    for (k = 0; k < 2; k++) {
	a = bund->params.acl_limits[k];
	while (a) {
	    Printf("\t%s#%d\t: '%s'\r\n", (k?"out":"in"), a->number, a->rule);
	    a = a->next;
	}
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
void
IfaceCorrectMSS(Mbuf pkt, uint16_t maxmss)
{
  struct ip	*iphdr;
  struct tcphdr	*tc;
  int		pktlen, hlen, olen, optlen, accumulate;
  uint16_t	*mss;
  u_char	*opt;

  if (pkt == NULL)
    return;

  iphdr = (struct ip *)MBDATAU(pkt);
  hlen = iphdr->ip_hl << 2;
  pktlen = plength(pkt) - hlen;
  tc = (struct tcphdr *)(MBDATAU(pkt) + hlen);
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

static int
IfaceNgIpInit(Bund b, int ready)
{
    struct ngm_connect	cn;
    char		path[NG_PATHLEN + 1];
    char		hook[NG_HOOKLEN + 1];

    if (!ready) {
	/* Dial-on-Demand mode */
	/* Use demand hook of the socket node */
	snprintf(path, sizeof(path), ".:");
	strcpy(hook, MPD_HOOK_DEMAND_TAP);

    } else {

	snprintf(path, sizeof(path), "%s", MPD_HOOK_PPP);
	strcpy(hook, NG_PPP_HOOK_INET);

#ifdef USE_NG_NAT
	/* Add a nat node if configured */
	if (Enabled(&b->iface.options, IFACE_CONF_NAT)) {
	    if (IfaceInitNAT(b, path, hook))
		goto fail;
	    b->iface.nat_up = 1;
	}
#endif

	/* Add a tee node if configured */
	if (Enabled(&b->iface.options, IFACE_CONF_TEE)) {
	    if (IfaceInitTee(b, path, hook))
		goto fail;
	    b->iface.tee_up = 1;
	}
  
#ifdef USE_NG_NETFLOW
	/* Connect a netflow node if configured */
	if (Enabled(&b->iface.options, IFACE_CONF_NETFLOW_IN)) {
	    if (IfaceInitNetflow(b, path, hook, 0))
		goto fail;
	    b->iface.nfin_up = 1;
	}

	if (Enabled(&b->iface.options, IFACE_CONF_NETFLOW_OUT)) {
	    if (IfaceInitNetflow(b, path, hook, 1))
		goto fail;
	    b->iface.nfout_up = 1;
	}
#endif	/* USE_NG_NETFLOW */

    }

    if (Enabled(&b->iface.options, IFACE_CONF_TCPMSSFIX)) {
	if (IfaceInitMSS(b, path, hook))
    	    goto fail;
	b->iface.mss_up = 1;
    }

    if (IfaceInitLimits(b, path, hook))
	goto fail;

    /* Connect graph to the iface node. */
    strcpy(cn.ourhook, hook);
    snprintf(cn.path, sizeof(cn.path), "%s:", b->iface.ifname);
    snprintf(cn.peerhook, sizeof(cn.peerhook), "%s", NG_IFACE_HOOK_INET);
    if (NgSendMsg(b->csock, path,
    	    NGM_GENERIC_COOKIE, NGM_CONNECT, &cn, sizeof(cn)) < 0) {
	Log(LG_ERR, ("[%s] can't connect \"%s\"->\"%s\" and \"%s\"->\"%s\": %s",
    	    b->name, path, cn.ourhook, cn.path, cn.peerhook, strerror(errno)));
	goto fail;
    }

    if (ready) {
#ifdef USE_NG_NETFLOW
	if (b->iface.nfin_up)
	    IfaceSetupNetflow(b, 0);

	if (b->iface.nfout_up)
	    IfaceSetupNetflow(b, 1);
#endif /* USE_NG_NETFLOW */

	if (b->iface.mss_up)
	    IfaceSetupMSS(b, MAXMSS(b->iface.mtu));
    }
    
    IfaceSetupLimits(b);

    /* OK */
    return(0);

fail:
    return(-1);
}

/*
 * IfaceNgIpShutdown()
 */

static void
IfaceNgIpShutdown(Bund b)
{
#ifdef USE_NG_NAT
    if (b->iface.nat_up)
	IfaceShutdownNAT(b);
    b->iface.nfin_up = 0;
#endif
    if (b->iface.tee_up)
	IfaceShutdownTee(b);
    b->iface.tee_up = 0;
#ifdef USE_NG_NETFLOW
    if (b->iface.nfin_up)
	IfaceShutdownNetflow(b, 0);
    b->iface.nfin_up = 0;
    if (b->iface.nfout_up)
	IfaceShutdownNetflow(b, 1);
    b->iface.nfout_up = 0;
#endif
    if (b->iface.mss_up)
	IfaceShutdownMSS(b);
    b->iface.mss_up = 0;

    IfaceShutdownLimits(b);
    NgFuncDisconnect(b->csock, b->name, MPD_HOOK_PPP, NG_PPP_HOOK_INET);
}

static int
IfaceNgIpv6Init(Bund b, int ready)
{
    struct ngm_connect	cn;
    char		path[NG_PATHLEN + 1];

    if (!ready) {
    } else {
	/* Connect ipv6 hook of ng_ppp(4) node to the ng_iface(4) node. */
	snprintf(path, sizeof(path), "%s", MPD_HOOK_PPP);
	snprintf(cn.ourhook, sizeof(cn.ourhook), "%s", NG_PPP_HOOK_IPV6);
	snprintf(cn.peerhook, sizeof(cn.peerhook), "%s", NG_IFACE_HOOK_INET6);
	if (NgSendMsg(b->csock, path, NGM_GENERIC_COOKIE, NGM_CONNECT, &cn,
		sizeof(cn)) < 0) {
    	    Log(LG_ERR, ("[%s] can't connect \"%s\"->\"%s\" and \"%s\"->\"%s\": %s", 
    		b->name, path, cn.ourhook, cn.path, cn.peerhook, strerror(errno)));
    	    goto fail;
	}
    }

    /* OK */
    return(0);

fail:
    return(-1);
}

/*
 * IfaceNgIpv6Shutdown()
 */

static void
IfaceNgIpv6Shutdown(Bund b)
{
    NgFuncDisconnect(b->csock, b->name, MPD_HOOK_PPP, NG_PPP_HOOK_IPV6);
}

#ifdef USE_NG_NAT
static int
IfaceInitNAT(Bund b, char *path, char *hook)
{
    struct ngm_mkpeer	mp;
    struct ngm_name	nm;
  
    snprintf(mp.type, sizeof(mp.type), "%s", NG_NAT_NODE_TYPE);
    strcpy(mp.ourhook, hook);
    strcpy(mp.peerhook, NG_NAT_HOOK_IN);
    if (NgSendMsg(b->csock, path,
	NGM_GENERIC_COOKIE, NGM_MKPEER, &mp, sizeof(mp)) < 0) {
      Log(LG_ERR, ("[%s] can't create %s node at \"%s\"->\"%s\": %s",
	b->name, NG_NAT_NODE_TYPE, path, mp.ourhook, strerror(errno)));
      return(-1);
    }
    strlcat(path, ".", NG_PATHLEN);
    strlcat(path, hook, NG_PATHLEN);
    snprintf(nm.name, sizeof(nm.name), "mpd%d-%s-nat", gPid, b->name);
    if (NgSendMsg(b->csock, path,
	NGM_GENERIC_COOKIE, NGM_NAME, &nm, sizeof(nm)) < 0) {
      Log(LG_ERR, ("[%s] can't name %s node: %s",
	b->name, NG_NAT_NODE_TYPE, strerror(errno)));
      return(-1);
    }
    strcpy(hook, NG_NAT_HOOK_OUT);

    /* Set NAT IP */
    struct in_addr ip = { 1 }; // Setting something just to make it ready
    if (NgSendMsg(b->csock, path,
	    NGM_NAT_COOKIE, NGM_NAT_SET_IPADDR, &ip, sizeof(ip)) < 0) {
	Log(LG_ERR, ("[%s] can't set NAT ip: %s",
    	    b->name, strerror(errno)));
    }

    return(0);
}

static int
IfaceSetupNAT(Bund b)
{
    char	path[NG_PATHLEN+1];

    snprintf(path, sizeof(path), "mpd%d-%s-nat:", gPid, bund->name);
    if (NgSendMsg(bund->csock, path,
    	    NGM_NAT_COOKIE, NGM_NAT_SET_IPADDR, &b->iface.self_addr.addr.u.ip4, sizeof(b->iface.self_addr.addr.u.ip4)) < 0) {
	Log(LG_ERR, ("[%s] can't set NAT ip: %s",
    	    b->name, strerror(errno)));
	return (-1);
    }
    return (0);
}

static void
IfaceShutdownNAT(Bund b)
{
    char	path[NG_PATHLEN+1];

    snprintf(path, sizeof(path), "mpd%d-%s-nat:", gPid, b->name);
    NgFuncShutdownNode(b->csock, b->name, path);
}
#endif

static int
IfaceInitTee(Bund b, char *path, char *hook)
{
    struct ngm_mkpeer	mp;
    struct ngm_name	nm;
  
    snprintf(mp.type, sizeof(mp.type), "%s", NG_TEE_NODE_TYPE);
    strcpy(mp.ourhook, hook);
    strcpy(mp.peerhook, NG_TEE_HOOK_RIGHT);
    if (NgSendMsg(b->csock, path,
	NGM_GENERIC_COOKIE, NGM_MKPEER, &mp, sizeof(mp)) < 0) {
      Log(LG_ERR, ("[%s] can't create %s node at \"%s\"->\"%s\": %s",
	b->name, NG_TEE_NODE_TYPE, path, mp.ourhook, strerror(errno)));
      return(-1);
    }
    strlcat(path, ".", NG_PATHLEN);
    strlcat(path, hook, NG_PATHLEN);
    snprintf(nm.name, sizeof(nm.name), "%s-tee", b->iface.ifname);
    if (NgSendMsg(b->csock, path,
	NGM_GENERIC_COOKIE, NGM_NAME, &nm, sizeof(nm)) < 0) {
      Log(LG_ERR, ("[%s] can't name %s node: %s",
	b->name, NG_TEE_NODE_TYPE, strerror(errno)));
      return(-1);
    }
    strcpy(hook, NG_TEE_HOOK_LEFT);

    return(0);
}

static void
IfaceShutdownTee(Bund b)
{
    char	path[NG_PATHLEN+1];

    snprintf(path, sizeof(path), "%s-tee:", b->iface.ifname);
    NgFuncShutdownNode(b->csock, b->name, path);
}

#ifdef USE_NG_NETFLOW
static int
IfaceInitNetflow(Bund b, char *path, char *hook, char out)
{
    struct ngm_connect	cn;

    /* Create global ng_netflow(4) node if not yet. */
    if (gNetflowNode == FALSE) {
	if (NgFuncInitGlobalNetflow(b))
	    return(-1);
    }

    /* Connect ng_netflow(4) node to the ng_bpf(4)/ng_tee(4) node. */
    strcpy(cn.ourhook, hook);
    snprintf(cn.path, sizeof(cn.path), "%s:", gNetflowNodeName);
    if (out) {
	snprintf(cn.peerhook, sizeof(cn.peerhook), "%s%d", NG_NETFLOW_HOOK_OUT,
	    gNetflowIface + b->id);
    } else {
	snprintf(cn.peerhook, sizeof(cn.peerhook), "%s%d", NG_NETFLOW_HOOK_DATA,
	    gNetflowIface + b->id);
    }
    if (NgSendMsg(b->csock, path, NGM_GENERIC_COOKIE, NGM_CONNECT, &cn,
	sizeof(cn)) < 0) {
      Log(LG_ERR, ("[%s] can't connect \"%s\"->\"%s\" and \"%s\"->\"%s\": %s", 
        b->name, path, cn.ourhook, cn.path, cn.peerhook, strerror(errno)));
      return (-1);
    }
    strlcat(path, ".", NG_PATHLEN);
    strlcat(path, hook, NG_PATHLEN);
    if (out) {
	snprintf(hook, NG_HOOKLEN, "%s%d", NG_NETFLOW_HOOK_DATA,
	    gNetflowIface + b->id);
    } else {
	snprintf(hook, NG_HOOKLEN, "%s%d", NG_NETFLOW_HOOK_OUT,
	    gNetflowIface + b->id);
    }
    return (0);
}

static int
IfaceSetupNetflow(Bund b, char out)
{
    char path[NG_PATHLEN + 1];
    struct ng_netflow_setdlt	 nf_setdlt;
    struct ng_netflow_setifindex nf_setidx;
    
    /* Configure data link type and interface index. */
    snprintf(path, sizeof(path), "%s:", gNetflowNodeName);
    nf_setdlt.iface = gNetflowIface + b->id;
    nf_setdlt.dlt = DLT_RAW;
    if (NgSendMsg(b->csock, path, NGM_NETFLOW_COOKIE, NGM_NETFLOW_SETDLT,
	&nf_setdlt, sizeof(nf_setdlt)) < 0) {
      Log(LG_ERR, ("[%s] can't configure data link type on %s: %s", b->name,
	path, strerror(errno)));
      goto fail;
    }
    if (!out) {
	nf_setidx.iface = gNetflowIface + b->id;
	nf_setidx.index = if_nametoindex(b->iface.ifname);
	if (NgSendMsg(b->csock, path, NGM_NETFLOW_COOKIE, NGM_NETFLOW_SETIFINDEX,
	    &nf_setidx, sizeof(nf_setidx)) < 0) {
    	  Log(LG_ERR, ("[%s] can't configure interface index on %s: %s", b->name,
	    path, strerror(errno)));
    	  goto fail;
	}
    }

    return 0;
fail:
    return -1;
}

static void
IfaceShutdownNetflow(Bund b, char out)
{
    char	path[NG_PATHLEN+1];
    char	hook[NG_HOOKLEN+1];

    snprintf(path, NG_PATHLEN, "%s:", gNetflowNodeName);
    snprintf(hook, NG_HOOKLEN, "%s%d", NG_NETFLOW_HOOK_DATA,
	    gNetflowIface + b->id);
    NgFuncDisconnect(b->csock, b->name, path, hook);
    snprintf(hook, NG_HOOKLEN, "%s%d", NG_NETFLOW_HOOK_OUT,
	    gNetflowIface + b->id);
    NgFuncDisconnect(b->csock, b->name, path, hook);
}
#endif

static int
IfaceInitMSS(Bund b, char *path, char *hook)
{
    struct ngm_connect	cn;

#ifdef USE_NG_TCPMSS
    if (gTcpMSSNodeRefs <= 0) {
	/* Create global ng_tcpmss(4) node if not yet. */
	struct ngm_mkpeer	mp;
	struct ngm_name		nm;

	/* Create a global tcpmss node. */
	snprintf(mp.type, sizeof(mp.type), "%s", NG_TCPMSS_NODE_TYPE);
	snprintf(mp.ourhook, sizeof(mp.ourhook), "%s", hook);
	snprintf(mp.peerhook, sizeof(mp.peerhook), "%s-in", b->name);
	if (NgSendMsg(b->csock, path,
    		NGM_GENERIC_COOKIE, NGM_MKPEER, &mp, sizeof(mp)) < 0) {
    	    Log(LG_ERR, ("can't create %s node at \"%s\"->\"%s\": %s", 
    		NG_TCPMSS_NODE_TYPE, ".", mp.ourhook, strerror(errno)));
	    goto fail;
	}

	strlcat(path, ".", NG_PATHLEN);
	strlcat(path, hook, NG_PATHLEN);
	snprintf(hook, NG_HOOKLEN, "%s-out", b->name);

	/* Set the new node's name. */
	snprintf(nm.name, sizeof(nm.name), "mpd%d-mss", gPid);
	if (NgSendMsg(b->csock, path,
    		NGM_GENERIC_COOKIE, NGM_NAME, &nm, sizeof(nm)) < 0) {
    	    Log(LG_ERR, ("can't name %s node: %s", NG_TCPMSS_NODE_TYPE,
    		strerror(errno)));
	    goto fail;
	}

    } else {

        /* Connect ng_tcpmss(4) node. */
        snprintf(cn.path, sizeof(cn.path), "mpd%d-mss:", gPid);
        snprintf(cn.ourhook, sizeof(cn.ourhook), "%s", hook);
	snprintf(cn.peerhook, sizeof(cn.peerhook), "%s-in", b->name);
	if (NgSendMsg(b->csock, path, NGM_GENERIC_COOKIE, NGM_CONNECT, &cn,
		sizeof(cn)) < 0) {
    	    Log(LG_ERR, ("[%s] can't connect \"%s\"->\"%s\" and \"%s\"->\"%s\": %s", 
    		b->name, path, cn.ourhook, cn.path, cn.peerhook, strerror(errno)));
    	    goto fail;
	}

	strlcat(path, ".", NG_PATHLEN);
	strlcat(path, hook, NG_PATHLEN);
    }
    
    gTcpMSSNodeRefs++;
    
    snprintf(hook, NG_HOOKLEN, "%s-out", b->name);
#else
    struct ngm_mkpeer	mp;
    struct ngm_name	nm;

    /* Create a bpf node for SYN detection. */
    snprintf(mp.type, sizeof(mp.type), "%s", NG_BPF_NODE_TYPE);
    snprintf(mp.ourhook, sizeof(mp.ourhook), "%s", hook);
    snprintf(mp.peerhook, sizeof(mp.peerhook), "ppp");
    if (NgSendMsg(b->csock, path,
	    NGM_GENERIC_COOKIE, NGM_MKPEER, &mp, sizeof(mp)) < 0) {
    	Log(LG_ERR, ("can't create %s node at \"%s\"->\"%s\": %s", 
    	    NG_TCPMSS_NODE_TYPE, ".", mp.ourhook, strerror(errno)));
	goto fail;
    }

    strlcat(path, ".", NG_PATHLEN);
    strlcat(path, hook, NG_PATHLEN);
    strcpy(hook, "iface");

#if NG_NODESIZ>=32
    /* Set the new node's name. */
    snprintf(nm.name, sizeof(nm.name), "mpd%d-%s-mss", gPid, b->name);
    if (NgSendMsg(b->csock, path,
	    NGM_GENERIC_COOKIE, NGM_NAME, &nm, sizeof(nm)) < 0) {
    	Log(LG_ERR, ("can't name %s node: %s", NG_TCPMSS_NODE_TYPE,
    	    strerror(errno)));
	goto fail;
    }
#endif

    /* Connect to the bundle socket node. */
    snprintf(cn.path, sizeof(cn.path), "%s", path);
    snprintf(cn.ourhook, sizeof(cn.ourhook), "%s", MPD_HOOK_TCPMSS_IN);
    snprintf(cn.peerhook, sizeof(cn.peerhook), "%s", MPD_HOOK_TCPMSS_IN);
    if (NgSendMsg(b->csock, ".:", NGM_GENERIC_COOKIE, NGM_CONNECT, &cn,
    	    sizeof(cn)) < 0) {
    	Log(LG_ERR, ("[%s] can't connect \"%s\"->\"%s\" and \"%s\"->\"%s\": %s", 
    	    b->name, path, cn.ourhook, cn.path, cn.peerhook, strerror(errno)));
    	goto fail;
    }

    snprintf(cn.path, sizeof(cn.path), "%s", path);
    snprintf(cn.ourhook, sizeof(cn.ourhook), "%s", MPD_HOOK_TCPMSS_OUT);
    snprintf(cn.peerhook, sizeof(cn.peerhook), "%s", MPD_HOOK_TCPMSS_OUT);
    if (NgSendMsg(b->csock, ".:", NGM_GENERIC_COOKIE, NGM_CONNECT, &cn,
    	    sizeof(cn)) < 0) {
    	Log(LG_ERR, ("[%s] can't connect \"%s\"->\"%s\" and \"%s\"->\"%s\": %s", 
    	    b->name, path, cn.ourhook, cn.path, cn.peerhook, strerror(errno)));
    	goto fail;
    }
#endif

    return (0);
fail:
    return (-1);
}

/*
 * BundConfigMSS()
 *
 * Configure the tcpmss node to reduce MSS to given value.
 */

static void
IfaceSetupMSS(Bund b, uint16_t maxMSS)
{
#ifdef USE_NG_TCPMSS
  struct	ng_tcpmss_config tcpmsscfg;
  char		path[NG_PATHLEN];

  snprintf(path, sizeof(path), "mpd%d-mss:", gPid);

  /* Send configure message. */
  memset(&tcpmsscfg, 0, sizeof(tcpmsscfg));
  tcpmsscfg.maxMSS = maxMSS;

  snprintf(tcpmsscfg.inHook, sizeof(tcpmsscfg.inHook), "%s-in", b->name);
  snprintf(tcpmsscfg.outHook, sizeof(tcpmsscfg.outHook), "%s-out", b->name);
  if (NgSendMsg(bund->csock, path, NGM_TCPMSS_COOKIE, NGM_TCPMSS_CONFIG,
      &tcpmsscfg, sizeof(tcpmsscfg)) < 0) {
    Log(LG_ERR, ("[%s] can't configure %s node program: %s", b->name,
      NG_TCPMSS_NODE_TYPE, strerror(errno)));
  }
  snprintf(tcpmsscfg.inHook, sizeof(tcpmsscfg.inHook), "%s-out", b->name);
  snprintf(tcpmsscfg.outHook, sizeof(tcpmsscfg.outHook), "%s-in", b->name);
  if (NgSendMsg(bund->csock, path, NGM_TCPMSS_COOKIE, NGM_TCPMSS_CONFIG,
      &tcpmsscfg, sizeof(tcpmsscfg)) < 0) {
    Log(LG_ERR, ("[%s] can't configure %s node program: %s", b->name,
      NG_TCPMSS_NODE_TYPE, strerror(errno)));
  }
#else
    union {
	u_char			buf[NG_BPF_HOOKPROG_SIZE(TCPSYN_PROG_LEN)];
	struct ng_bpf_hookprog	hprog;
    }				u;
    struct ng_bpf_hookprog	*const hp = &u.hprog;

    /* Setup programs for ng_bpf hooks */
    memset(&u, 0, sizeof(u));
    strcpy(hp->thisHook, "ppp");
    hp->bpf_prog_len = TCPSYN_PROG_LEN;
    memcpy(&hp->bpf_prog, &gTCPSYNProg,
        TCPSYN_PROG_LEN * sizeof(*gTCPSYNProg));
    strcpy(hp->ifMatch, MPD_HOOK_TCPMSS_IN);
    strcpy(hp->ifNotMatch, "iface");

    if (NgSendMsg(b->csock, MPD_HOOK_TCPMSS_IN, NGM_BPF_COOKIE,
	    NGM_BPF_SET_PROGRAM, hp, NG_BPF_HOOKPROG_SIZE(hp->bpf_prog_len)) < 0) {
	Log(LG_ERR, ("[%s] can't set %s node program: %s",
    	    b->name, NG_BPF_NODE_TYPE, strerror(errno)));
    }

    memset(&u, 0, sizeof(u));
    strcpy(hp->thisHook, "iface");
    hp->bpf_prog_len = TCPSYN_PROG_LEN;
    memcpy(&hp->bpf_prog, &gTCPSYNProg,
        TCPSYN_PROG_LEN * sizeof(*gTCPSYNProg));
    strcpy(hp->ifMatch, MPD_HOOK_TCPMSS_OUT);
    strcpy(hp->ifNotMatch, "ppp");

    if (NgSendMsg(b->csock, MPD_HOOK_TCPMSS_OUT, NGM_BPF_COOKIE,
	    NGM_BPF_SET_PROGRAM, hp, NG_BPF_HOOKPROG_SIZE(hp->bpf_prog_len)) < 0) {
	Log(LG_ERR, ("[%s] can't set %s node program: %s",
    	    b->name, NG_BPF_NODE_TYPE, strerror(errno)));
    }

    memset(&u, 0, sizeof(u));
    strcpy(hp->thisHook, MPD_HOOK_TCPMSS_IN);
    hp->bpf_prog_len = NOMATCH_PROG_LEN;
    memcpy(&hp->bpf_prog, &gNoMatchProg,
        NOMATCH_PROG_LEN * sizeof(*gNoMatchProg));
    strcpy(hp->ifMatch, "ppp");
    strcpy(hp->ifNotMatch, "ppp");

    if (NgSendMsg(b->csock, MPD_HOOK_TCPMSS_IN, NGM_BPF_COOKIE,
	    NGM_BPF_SET_PROGRAM, hp, NG_BPF_HOOKPROG_SIZE(hp->bpf_prog_len)) < 0) {
	Log(LG_ERR, ("[%s] can't set %s node program: %s",
    	    b->name, NG_BPF_NODE_TYPE, strerror(errno)));
    }

    memset(&u, 0, sizeof(u));
    strcpy(hp->thisHook, MPD_HOOK_TCPMSS_OUT);
    hp->bpf_prog_len = NOMATCH_PROG_LEN;
    memcpy(&hp->bpf_prog, &gNoMatchProg,
        NOMATCH_PROG_LEN * sizeof(*gNoMatchProg));
    strcpy(hp->ifMatch, "iface");
    strcpy(hp->ifNotMatch, "iface");

    if (NgSendMsg(b->csock, MPD_HOOK_TCPMSS_OUT, NGM_BPF_COOKIE,
	    NGM_BPF_SET_PROGRAM, hp, NG_BPF_HOOKPROG_SIZE(hp->bpf_prog_len)) < 0) {
	Log(LG_ERR, ("[%s] can't set %s node program: %s",
    	    b->name, NG_BPF_NODE_TYPE, strerror(errno)));
    }

#endif /* USE_NG_TCPMSS */
}

static void
IfaceShutdownMSS(Bund b)
{
#ifdef USE_NG_TCPMSS
    char	path[NG_PATHLEN+1];
    char	hook[NG_HOOKLEN+1];

    snprintf(path, sizeof(path), "mpd%d-mss:", gPid);
    snprintf(hook, NG_HOOKLEN, "%s-in", b->name);
    NgFuncDisconnect(b->csock, b->name, path, hook);
    snprintf(hook, NG_HOOKLEN, "%s-out", b->name);
    NgFuncDisconnect(b->csock, b->name, path, hook);

    gTcpMSSNodeRefs--;
#else
    NgFuncShutdownNode(b->csock, b->name, MPD_HOOK_TCPMSS_IN);
#endif
}

static int
IfaceInitLimits(Bund b, char *path, char *hook)
{
    struct ngm_mkpeer	mp;
    struct ngm_name	nm;

    if (b->params.acl_limits[0] || b->params.acl_limits[1]) {

	/* Create a bpf node for traffic filtering. */
	snprintf(mp.type, sizeof(mp.type), "%s", NG_BPF_NODE_TYPE);
	snprintf(mp.ourhook, sizeof(mp.ourhook), "%s", hook);
	snprintf(mp.peerhook, sizeof(mp.peerhook), "ppp");
	if (NgSendMsg(b->csock, path,
		NGM_GENERIC_COOKIE, NGM_MKPEER, &mp, sizeof(mp)) < 0) {
    	    Log(LG_ERR, ("can't create %s node at \"%s\"->\"%s\": %s", 
    		NG_TCPMSS_NODE_TYPE, ".", mp.ourhook, strerror(errno)));
	    goto fail;
	}

	strlcat(path, ".", NG_PATHLEN);
	strlcat(path, hook, NG_PATHLEN);
	strcpy(hook, "iface");

#if NG_NODESIZ>=32
	/* Set the new node's name. */
	snprintf(nm.name, sizeof(nm.name), "mpd%d-%s-lim", gPid, b->name);
	if (NgSendMsg(b->csock, path,
		NGM_GENERIC_COOKIE, NGM_NAME, &nm, sizeof(nm)) < 0) {
    	    Log(LG_ERR, ("can't name %s node: %s", NG_TCPMSS_NODE_TYPE,
    		strerror(errno)));
	    goto fail;
	}
#endif

    }

    return (0);
fail:
    return (-1);
}

/*
 * BundConfigLimits()
 *
 * Configure the bpf & car nodes.
 */

static void
IfaceSetupLimits(Bund b)
{
#define	ACL_MAX_PROGLEN	4096
    union {
	u_char			buf[NG_BPF_HOOKPROG_SIZE(ACL_MAX_PROGLEN)];
	struct ng_bpf_hookprog	hprog;
    }				u;
    struct ng_bpf_hookprog	*const hp = &u.hprog;
    
    struct ngm_connect  cn;
    
    char		path[NG_PATHLEN + 1];
    char		inhook[2][NG_HOOKLEN+1];
    char		inhookn[2][NG_HOOKLEN+1];
    char		outhook[NG_HOOKLEN+1];
    struct acl		*l;
    char		str[ACL_LEN];
#define	ACL_MAX_PARAMS	5
    int			ac;
    char		*av[ACL_MAX_PARAMS];
    int			num, dir;
    int			i, p;

    if (b->params.acl_limits[0] || b->params.acl_limits[1]) {

	snprintf(path, sizeof(path), "mpd%d-%s-lim:", gPid, b->name);
	
	for (dir = 0; dir < 2; dir++) {
	    if (dir == 0) {
		strcpy(inhook[0], "ppp");
		strcpy(inhook[1], "");
		strcpy(outhook, "iface");
	    } else {
		strcpy(inhook[0], "iface");
		strcpy(inhook[1], "");
		strcpy(outhook, "ppp");
	    }
	    num = 0;
	    l = b->params.acl_limits[dir];
	
	    while (l) {
		Log(LG_IFACE2, ("[%s] IFACE: limit %s#%d: '%s'",
        	    b->name, (dir?"out":"in"), l->number, l->rule));
		strncpy(str, l->rule, sizeof(str));
    		ac = ParseLine(str, av, ACL_MAX_PARAMS, 0);
	        if (ac >= 2) {
	    	    memset(&u, 0, sizeof(u));
		    if (l->next) {
			sprintf(hp->ifNotMatch, "%d-%d-n", dir, num);
		        sprintf(inhookn[1], "%d-%d-ni", dir, num);

		        /* Connect bpf to itself. */
			strcpy(cn.ourhook, hp->ifNotMatch);
		        strcpy(cn.path, path);
		        strcpy(cn.peerhook, inhookn[1]);
			if (NgSendMsg(b->csock, path,
		    	        NGM_GENERIC_COOKIE, NGM_CONNECT, &cn, sizeof(cn)) < 0) {
			    Log(LG_ERR, ("[%s] IFACE: can't connect \"%s\"->\"%s\" and \"%s\"->\"%s\": %s",
		    		b->name, path, cn.ourhook, cn.path, cn.peerhook, strerror(errno)));
			}
		    } else {
			strcpy(hp->ifNotMatch, outhook);
			strcpy(inhookn[1], "");
		    }
		
		    if (strcasecmp(av[0], "all") == 0) {
			hp->bpf_prog_len = MATCH_PROG_LEN;
			memcpy(&hp->bpf_prog, &gMatchProg,
    			    MATCH_PROG_LEN * sizeof(*gMatchProg));
		    } else if (strncasecmp(av[0], "flt", 3) == 0) {
			int	flt;
		    
			flt = atoi(av[0] + 3);
		        if (flt <= 0 || flt > ACL_FILTERS || b->params.acl_filters[flt - 1] == NULL) {
		    	    Log(LG_ERR, ("[%s] IFACE: incorrect filter: '%s'",
    				b->name, av[0]));
			} else {
			    struct bpf_program pr;
		    	    char	buf[16384], sbuf[256];
		    	    int		bufbraces;
		    	    struct acl	*f;
			    
			    buf[0] = 0;
			    bufbraces = 0;
			    f = b->params.acl_filters[flt - 1];
			    while (f) {
				char	*b1, *b2;
				strlcpy(sbuf, f->rule, sizeof(sbuf));
				b2 = sbuf;
				b1 = strsep(&b2, " ");
				if (b2 != NULL) {
				    if (strcasecmp(b1, "match") == 0) {
					strncat(buf, "( ", sizeof(buf));
					strncat(buf, b2, sizeof(buf));
				        strncat(buf, " ) ", sizeof(buf));
				        if (f->next) {
					    strncat(buf, "|| ( ", sizeof(buf));
					    bufbraces++;
					}
				    } else if (strcasecmp(b1, "nomatch") == 0) {
					strncat(buf, "( not ( ", sizeof(buf));
					strncat(buf, b2, sizeof(buf));
					strncat(buf, " ) ) ", sizeof(buf));
					if (f->next) {
					    strncat(buf, "&& ( ", sizeof(buf));
					    bufbraces++;
					}
				    } else {
					Log(LG_ERR, ("[%s] IFACE: filter action '%s' is unknown",
        				    b->name, b1));
				    }
				};
				f = f->next;
			    }
			    for (i = 0; i < bufbraces; i++)
				strncat(buf, ") ", sizeof(buf));
			    Log(LG_IFACE2, ("[%s] IFACE: flt%d: '%s'",
        			b->name, flt, buf));
				
			    if (pcap_compile_nopcap((u_int)-1, DLT_RAW, &pr, buf, 1, 0xffffff00)) {
				Log(LG_ERR, ("[%s] IFACE: filter '%s' compilation error",
    				    b->name, av[0]));
			    } else if (pr.bf_len > ACL_MAX_PROGLEN) {
				Log(LG_ERR, ("[%s] IFACE: filter '%s' is too long",
        			    b->name, av[0]));
				pcap_freecode(&pr);
			    } else {
				hp->bpf_prog_len = pr.bf_len;
				memcpy(&hp->bpf_prog, pr.bf_insns,
    				    pr.bf_len * sizeof(struct bpf_insn));
				pcap_freecode(&pr);
			    }
			}
		    } else {
			Log(LG_ERR, ("[%s] IFACE: incorrect filter: '%s'",
    			    b->name, av[0]));
			hp->bpf_prog_len = NOMATCH_PROG_LEN;
			memcpy(&hp->bpf_prog, &gNoMatchProg,
    			    NOMATCH_PROG_LEN * sizeof(*gNoMatchProg));
		    }
		
		    p = 1;
		    if (strcasecmp(av[p], "pass") == 0) {
			strcpy(hp->ifMatch, outhook);
			strcpy(inhookn[0], "");
		    } else if (strcasecmp(av[p], "deny") == 0) {
			strcpy(hp->ifMatch, "deny");
			strcpy(inhookn[0], "");
#ifdef USE_NG_CAR
		    } else if ((strcasecmp(av[p], "shape") == 0) ||
			       (strcasecmp(av[p], "rate-limit") == 0)) {
			struct ngm_mkpeer mp;
			struct ng_car_bulkconf car;
			char		tmppath[NG_PATHLEN + 1];

			union {
			    u_char	buf[NG_BPF_HOOKPROG_SIZE(ACL_MAX_PROGLEN)];
			    struct ng_bpf_hookprog	hprog;
			} u1;
			struct ng_bpf_hookprog	*const hp1 = &u1.hprog;

		        sprintf(hp->ifMatch, "%d-%d-m", dir, num);

			snprintf(tmppath, sizeof(tmppath), "%s%d-%d-m", path, dir, num);

			/* Create a car node for traffic shaping. */
			snprintf(mp.type, sizeof(mp.type), "%s", NG_CAR_NODE_TYPE);
			snprintf(mp.ourhook, sizeof(mp.ourhook), "%d-%d-m", dir, num);
			strcpy(mp.peerhook, ((dir == 0)?NG_CAR_HOOK_LOWER:NG_CAR_HOOK_UPPER));
			if (NgSendMsg(b->csock, path,
				NGM_GENERIC_COOKIE, NGM_MKPEER, &mp, sizeof(mp)) < 0) {
		    	    Log(LG_ERR, ("[%s] IFACE: can't create %s node at \"%s\"->\"%s\": %s", 
		    		b->name, NG_CAR_NODE_TYPE, ".", mp.ourhook, strerror(errno)));
			}

		        /* Connect car to bpf. */
			snprintf(cn.ourhook, sizeof(cn.ourhook), "%d-%d-mi", dir, num);
			snprintf(cn.path, sizeof(cn.path), "%s", tmppath);
		        strcpy(cn.peerhook, ((dir == 0)?NG_CAR_HOOK_UPPER:NG_CAR_HOOK_LOWER));
			if (NgSendMsg(b->csock, path,
		    	        NGM_GENERIC_COOKIE, NGM_CONNECT, &cn, sizeof(cn)) < 0) {
			    Log(LG_ERR, ("[%s] IFACE: can't connect \"%s\"->\"%s\" and \"%s\"->\"%s\": %s",
		    		b->name, path, cn.ourhook, cn.path, cn.peerhook, strerror(errno)));
			}
			
			bzero(&car, sizeof(car));
			
			if (strcasecmp(av[p], "shape") == 0) {
			    car.upstream.mode = NG_CAR_SHAPE;
			} else {
			    car.upstream.mode = NG_CAR_RED;
			}
			p++;

			if ((ac > p) && (av[p][0] >= '0') && (av[p][0] <= '9')) {
			    car.upstream.cir = atol(av[p]);
			    p++;
			    if ((ac > p) && (av[p][0] >= '0') && (av[p][0] <= '9')) {
				car.upstream.cbs = atol(av[p]);
				p++;
				if ((ac > p) && (av[p][0] >= '0') && (av[p][0] <= '9')) {
				    car.upstream.ebs = atol(av[p]);
				    p++;
				} else {
				    car.upstream.ebs = car.upstream.cbs * 2;
				}
			    } else {
				car.upstream.cbs = car.upstream.cir / 8;
				car.upstream.ebs = car.upstream.cbs * 2;
			    }
			} else {
			    car.upstream.cir = 8000;
			    car.upstream.cbs = car.upstream.cir / 8;
			    car.upstream.ebs = car.upstream.cbs * 2;
			}
			car.upstream.green_action = NG_CAR_ACTION_FORWARD;
			car.upstream.yellow_action = NG_CAR_ACTION_FORWARD;
			car.upstream.red_action = NG_CAR_ACTION_DROP;
			
			car.downstream = car.upstream;
						
			if (NgSendMsg(b->csock, tmppath,
		    	        NGM_CAR_COOKIE, NGM_CAR_SET_CONF, &car, sizeof(car)) < 0) {
			    Log(LG_ERR, ("[%s] IFACE: can't set %s configuration: %s",
		    		b->name, NG_CAR_NODE_TYPE, strerror(errno)));
			}
			
			if (ac > p) {
			    if (strcasecmp(av[p], "pass") == 0) {
				memset(&u1, 0, sizeof(u1));
				strcpy(hp1->ifMatch, outhook);
			        strcpy(hp1->ifNotMatch, outhook);
			        hp1->bpf_prog_len = MATCH_PROG_LEN;
			        memcpy(&hp1->bpf_prog, &gMatchProg,
    				    MATCH_PROG_LEN * sizeof(*gMatchProg));
		    		sprintf(hp1->thisHook, "%d-%d-mi", dir, num);
			        if (NgSendMsg(b->csock, path, NGM_BPF_COOKIE, NGM_BPF_SET_PROGRAM,
					hp1, NG_BPF_HOOKPROG_SIZE(hp1->bpf_prog_len)) < 0) {
				    Log(LG_ERR, ("[%s] IFACE: can't set %s node program: %s",
	    				b->name, NG_BPF_NODE_TYPE, strerror(errno)));
				}
			    			    
				strcpy(inhookn[0], "");
			    } else {
				Log(LG_ERR, ("[%s] IFACE: unknown action: '%s'",
    				    b->name, av[p]));
				strcpy(inhookn[0], "");
			    }
			} else {
		    	    sprintf(inhookn[0], "%d-%d-mi", dir, num);
			}
#endif /* USE_NG_CAR */
		    } else {
			Log(LG_ERR, ("[%s] IFACE: unknown action: '%s'",
    			    b->name, av[1]));
			strcpy(inhookn[0], "");
		    }

		    for (i = 0; i < 2; i++) {
			if (inhook[i][0] != 0) {
			    strcpy(hp->thisHook, inhook[i]);
			    if (NgSendMsg(b->csock, path, NGM_BPF_COOKIE, NGM_BPF_SET_PROGRAM,
				    hp, NG_BPF_HOOKPROG_SIZE(hp->bpf_prog_len)) < 0) {
				Log(LG_ERR, ("[%s] IFACE: can't set %s node program: %s",
	    			    b->name, NG_BPF_NODE_TYPE, strerror(errno)));
			    }
			}
			strcpy(inhook[i], inhookn[i]);
		    }

		    num++;
		} else {
		    Log(LG_ERR, ("[%s] IFACE: incorrect limit: '%s'",
    			b->name, l->rule));
		}
		l = l->next;
	    }
	
	    for (i = 0; i < 2; i++) {
		if (inhook[i][0] != 0) {
		    memset(&u, 0, sizeof(u));
		    strcpy(hp->thisHook, inhook[i]);
		    hp->bpf_prog_len = MATCH_PROG_LEN;
		    memcpy(&hp->bpf_prog, &gMatchProg,
    			MATCH_PROG_LEN * sizeof(*gMatchProg));
		    strcpy(hp->ifMatch, outhook);
		    strcpy(hp->ifNotMatch, outhook);
		    if (NgSendMsg(b->csock, path, NGM_BPF_COOKIE, NGM_BPF_SET_PROGRAM, 
			    hp, NG_BPF_HOOKPROG_SIZE(hp->bpf_prog_len)) < 0) {
			Log(LG_ERR, ("[%s] IFACE: can't set %s node %s %s program (2): %s",
	    		    b->name, NG_BPF_NODE_TYPE, path, hp->thisHook, strerror(errno)));
		    }
		}
	    }
	}
    }
}

static void
IfaceShutdownLimits(Bund b)
{
    char path[NG_PATHLEN + 1];

    if (b->params.acl_limits[0] || b->params.acl_limits[1]) {
	snprintf(path, sizeof(path), "mpd%d-%s-lim:", gPid, b->name);
	NgFuncShutdownNode(b->csock, b->name, path);
    }
}
