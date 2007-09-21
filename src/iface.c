
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
#include "ngfunc.h"
#include "netgraph.h"
#include "util.h"

#include <sys/sockio.h>
#include <net/if.h>
#include <net/if_types.h>
#include <net/if_dl.h>
#include <net/if_var.h>
#include <net/route.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/in_var.h>
#include <netinet/if_ether.h>
#include <netinet6/nd6.h>
#include <netgraph/ng_message.h>
#ifdef __DragonFly__
#include <netgraph/iface/ng_iface.h>
#include <netgraph/bpf/ng_bpf.h>
#include <netgraph/tee/ng_tee.h>
#include <netgraph/ksocket/ng_ksocket.h>
#else
#include <netgraph/ng_iface.h>
#include <netgraph/ng_bpf.h>
#include <netgraph/ng_tee.h>
#include <netgraph/ng_ksocket.h>
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
#ifdef USE_NG_IPACCT
#include <netgraph/ng_ipacct.h>
#undef r_ip_p	/* XXX:DIRTY CONFLICT! */
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

#ifdef USE_NG_IPACCT
  static int	IfaceInitIpacct(Bund b, char *path, char *hook);
  static void	IfaceShutdownIpacct(Bund b);
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

  static int	IfaceSetCommand(Context ctx, int ac, char *av[], void *arg);
  static void	IfaceSessionTimeout(void *arg);
  static void	IfaceIdleTimeout(void *arg);

  static void	IfaceCacheSend(Bund b);
  static void	IfaceCachePkt(Bund b, int proto, Mbuf pkt);
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
    { 0,	IFACE_CONF_IPACCT,		"ipacct"	},
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

#define IN6MASK128	{{{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, \
			    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff }}}
static const struct in6_addr in6mask128 = IN6MASK128;


/*
 * IfaceInit()
 */

void
IfaceInit(Bund b)
{
  IfaceState	const iface = &b->iface;

  /* Default configuration */
  iface->mtu = NG_IFACE_MTU_DEFAULT;
  iface->max_mtu = NG_IFACE_MTU_DEFAULT;
  Disable(&iface->options, IFACE_CONF_ONDEMAND);
  Disable(&iface->options, IFACE_CONF_PROXY);
  Disable(&iface->options, IFACE_CONF_TCPMSSFIX);
  NatInit(b);
}

/*
 * IfaceInst()
 */

void
IfaceInst(Bund b, Bund bt)
{
    IfaceState	const iface = &b->iface;

    memcpy(iface, &bt->iface, sizeof(*iface));
}

/*
 * IfaceOpen()
 *
 * Open the interface layer
 */

void
IfaceOpen(Bund b)
{
    IfaceState	const iface = &b->iface;

    Log(LG_IFACE, ("[%s] IFACE: Open event", b->name));

    /* Open is useless without on-demand. */
    if (!Enabled(&iface->options, IFACE_CONF_ONDEMAND)) {
	Log(LG_ERR, ("[%s] 'open iface' is useless without on-demand enabled", b->name));
	return;
    }

    /* If interface is already open do nothing */
    if (iface->open)
	return;
    iface->open = TRUE;

    /* If on-demand, bring up system interface immediately and start
     listening for outgoing packets. The next outgoing packet will
     cause us to open the lower layer(s) */
    BundNcpsJoin(b, NCP_NONE);
}

/*
 * IfaceClose()
 *
 * Close the interface layer
 */

void
IfaceClose(Bund b)
{
    IfaceState	const iface = &b->iface;

    Log(LG_IFACE, ("[%s] IFACE: Close event", b->name));

    /* If interface is already closed do nothing */
    if (!iface->open)
	return;
    iface->open = FALSE;

    /* If there was on-demand, tell that it is not needed anymore */
    BundNcpsLeave(b, NCP_NONE);
}

/*
 * IfaceOpenCmd()
 *
 * Open the interface layer
 */

void
IfaceOpenCmd(Context ctx)
{
    IfaceOpen(ctx->bund);
}

/*
 * IfaceCloseCmd()
 *
 * Close the interface layer
 */

void
IfaceCloseCmd(Context ctx)
{
    IfaceClose(ctx->bund);
}

/*
 * IfaceUp()
 *
 * Our underlying PPP bundle is ready for traffic.
 * We may signal that the interface is in DoD with the IFF_LINK0 flag.
 */

void
IfaceUp(Bund b, int ready)
{
  IfaceState	const iface = &b->iface;
  int		session_timeout = 0, idle_timeout = 0;
  struct acl	*acls, *acl;
  char			*buf;
  struct acl_pool 	**poollast;
  int 			poollaststart;
  int		prev_number;
  int		prev_real_number;

  Log(LG_IFACE, ("[%s] IFACE: Up event", b->name));

  if (ready) {

    /* Start Session timer */
    if (b->params.session_timeout > 0) {
	session_timeout = b->params.session_timeout;
    } else if (iface->session_timeout > 0) {
	session_timeout = iface->session_timeout;
    }

    if (session_timeout > 0) {
	Log(LG_IFACE2, ("[%s] IFACE: session-timeout: %d seconds", 
    	    b->name, session_timeout));
	TimerInit(&iface->sessionTimer, "IfaceSession",
    	    session_timeout * SECONDS, IfaceSessionTimeout, b);
	TimerStart(&iface->sessionTimer);
    }

    /* Start idle timer */
    if (b->params.idle_timeout > 0) {
	idle_timeout = b->params.idle_timeout;
    } else if (iface->idle_timeout > 0) {
	idle_timeout = iface->idle_timeout;
    }
    
    if (idle_timeout > 0) {
	Log(LG_IFACE2, ("[%s] IFACE: idle-timeout: %d seconds", 
    	    b->name, idle_timeout));
    
	TimerInit(&iface->idleTimer, "IfaceIdle",
    	    idle_timeout * SECONDS / IFACE_IDLE_SPLIT, IfaceIdleTimeout, b);
	TimerStart(&iface->idleTimer);
	iface->traffic[1] = TRUE;
	iface->traffic[0] = FALSE;

	/* Reset statistics */
	memset(&iface->idleStats, 0, sizeof(iface->idleStats));
    }

  /* Allocate ACLs */
  acls = b->params.acl_pipe;
  poollast = &pipe_pool;
  poollaststart = pipe_pool_start;
  while (acls != NULL) {
    acls->real_number = IfaceAllocACL(&poollast, poollaststart, iface->ifname, acls->number);
    poollaststart = acls->real_number;
    acls = acls->next;
  };
  acls = b->params.acl_queue;
  poollast = &queue_pool;
  poollaststart = queue_pool_start;
  while (acls != NULL) {
    acls->real_number = IfaceAllocACL(&poollast, poollaststart, iface->ifname, acls->number);
    poollaststart = acls->real_number;
    acls = acls->next;
  };
  prev_number = -1;
  prev_real_number = -1;
  acls = b->params.acl_table;
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
  acls = b->params.acl_rule;
  poollast = &rule_pool;
  poollaststart = rule_pool_start;
  while (acls != NULL) {
    acls->real_number = IfaceAllocACL(&poollast, poollaststart, iface->ifname, acls->number);
    poollaststart = acls->real_number;
    acls = acls->next;
  };

  /* Set ACLs */
  acls = b->params.acl_pipe;
  while (acls != NULL) {
    buf = IFaceParseACL(acls->rule, iface->ifname);
    ExecCmd(LG_IFACE2, b->name, "%s pipe %d config %s", PATH_IPFW, acls->real_number, acls->rule);
    Freee(MB_IFACE, buf);
    acls = acls->next;
  }
  acls = b->params.acl_queue;
  while (acls != NULL) {
    buf = IFaceParseACL(acls->rule,iface->ifname);
    ExecCmd(LG_IFACE2, b->name, "%s queue %d config %s", PATH_IPFW, acls->real_number, buf);
    Freee(MB_IFACE, buf);
    acls = acls->next;
  }
  acls = b->params.acl_table;
  while (acls != NULL) {
    acl = Malloc(MB_IFACE, sizeof(struct acl));
    memcpy(acl, acls, sizeof(struct acl));
    acl->next = iface->tables;
    iface->tables = acl;
    ExecCmd(LG_IFACE2, b->name, "%s table %d add %s", PATH_IPFW, acls->real_number, acls->rule);
    acls = acls->next;
  };
  acls = b->params.acl_rule;
  while (acls != NULL) {
    buf = IFaceParseACL(acls->rule, iface->ifname);
    ExecCmd(LG_IFACE2, b->name, "%s add %d %s via %s", PATH_IPFW, acls->real_number, buf, iface->ifname);
    Freee(MB_IFACE, buf);
    acls = acls->next;
  };

  };

  /* Bring up system interface */
  IfaceChangeFlags(b, 0, IFF_UP | (ready?0:IFF_LINK0));

  /* Send any cached packets */
  IfaceCacheSend(b);

}

/*
 * IfaceDown()
 *
 * Our packet transport mechanism is no longer ready for traffic.
 */

void
IfaceDown(Bund b)
{
  IfaceState	const iface = &b->iface;
  struct acl_pool	**rp, *rp1;
  char		cb[32768];
  struct acl    *acl, *aclnext;

  Log(LG_IFACE, ("[%s] IFACE: Down event", b->name));

  /* Bring down system interface */
  IfaceChangeFlags(b, IFF_UP | IFF_LINK0, 0);

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
    ExecCmdNosh(LG_IFACE2, b->name, "%s delete%s",
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
    ExecCmd(LG_IFACE2, b->name, "%s table %d delete %s",
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
    ExecCmdNosh(LG_IFACE2, b->name, "%s queue delete%s",
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
    ExecCmdNosh(LG_IFACE2, b->name, "%s pipe delete%s",
      PATH_IPFW, cb);

}

/*
 * IfaceListenInput()
 *
 * A packet was received on our demand snooping hook. Stimulate a connection.
 */

void
IfaceListenInput(Bund b, int proto, Mbuf pkt)
{
  IfaceState	const iface = &b->iface;
  int		const isDemand = IfaceIsDemand(proto, pkt);
  Fsm		fsm;

  /* Does this count as demand traffic? */
  if (isDemand)
    iface->traffic[0] = TRUE;

  /* Get FSM for protocol (for now, we know it's IP) */
  assert(proto == PROTO_IP);
  fsm = &b->ipcp.fsm;

  if (OPEN_STATE(fsm->state)) {
    if (b->bm.n_up > 0) {
#ifndef USE_NG_TCPMSS
      if (Enabled(&iface->options, IFACE_CONF_TCPMSSFIX)) {
	if (proto == PROTO_IP)
	  IfaceCorrectMSS(pkt, MAXMSS(iface->mtu));
      } else
	Log(LG_IFACE, ("[%s] unexpected outgoing packet, len=%d",
	  b->name, MBLEN(pkt)));
#endif
      NgFuncWriteFrame(b->dsock, MPD_HOOK_DEMAND_TAP, b->name, pkt);
    } else {
      IfaceCachePkt(b, proto, pkt);
    }
  /* Maybe do dial-on-demand here */
  } else if (iface->open && isDemand) {
    Log(LG_IFACE, ("[%s] outgoing packet is demand", b->name));
    RecordLinkUpDownReason(b, NULL, 1, STR_DEMAND, NULL);
    BundOpenLinks(b);
    IfaceCachePkt(b, proto, pkt);
  } else {
    PFREE(pkt);
  }
}

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
IfaceIpIfaceUp(Bund b, int ready)
{
  IfaceState		const iface = &b->iface;
  struct sockaddr_dl	hwa;
  char			hisaddr[20];
  IfaceRoute		r;
  u_char		*ether;

  if (ready) {
    in_addrtou_range(&b->ipcp.want_addr, 32, &iface->self_addr);
    in_addrtou_addr(&b->ipcp.peer_addr, &iface->peer_addr);
  }

  if (IfaceNgIpInit(b, ready)) {
    Log(LG_ERR, ("[%s] IfaceNgIpInit() error, closing IPCP", b->name));
    FsmFailure(&b->ipcp.fsm, FAIL_NEGOT_FAILURE);
    return;
  };

  /* Set addresses */
  IfaceChangeAddr(b, 1, &iface->self_addr, &iface->peer_addr);

  /* Proxy ARP for peer if desired and peer's address is known */
  u_addrclear(&iface->proxy_addr);
  if (Enabled(&iface->options, IFACE_CONF_PROXY)) {
    if (u_addrempty(&iface->peer_addr)) {
      Log(LG_IFACE,
	("[%s] can't proxy arp for %s",
	b->name, u_addrtoa(&iface->peer_addr,hisaddr,sizeof(hisaddr))));
    } else if (GetEther(&iface->peer_addr, &hwa) < 0) {
      Log(LG_IFACE,
	("[%s] no interface to proxy arp on for %s",
	b->name, u_addrtoa(&iface->peer_addr,hisaddr,sizeof(hisaddr))));
    } else {
      ether = (u_char *) LLADDR(&hwa);
      if (ExecCmdNosh(LG_IFACE2, b->name, 
	  "%s -S %s %x:%x:%x:%x:%x:%x pub",
	  PATH_ARP, u_addrtoa(&iface->peer_addr,hisaddr,sizeof(hisaddr)),
	  ether[0], ether[1], ether[2],
	  ether[3], ether[4], ether[5]) == 0)
	iface->proxy_addr = iface->peer_addr;
    }
  }
  
    /* Add static routes */
    SLIST_FOREACH(r, &iface->routes, next) {
	if (u_rangefamily(&r->dest)==AF_INET) {
	    r->ok = (IfaceSetRoute(b, RTM_ADD, &r->dest, &iface->peer_addr) == 0);
	}
    }
    /* Add dynamic routes */
    SLIST_FOREACH(r, &b->params.routes, next) {
	if (u_rangefamily(&r->dest)==AF_INET) {
	    r->ok = (IfaceSetRoute(b, RTM_ADD, &r->dest, &iface->peer_addr) == 0);
	}
    }

#ifdef USE_NG_NAT
  /* Set NAT IP */
  if (iface->nat_up) {
    IfaceSetupNAT(b);
  }
#endif

  /* Call "up" script */
  if (*iface->up_script) {
    char	selfbuf[40],peerbuf[40];
    char	ns1buf[21], ns2buf[21];

    if(b->ipcp.want_dns[0].s_addr != 0)
      snprintf(ns1buf, sizeof(ns1buf), "dns1 %s", inet_ntoa(b->ipcp.want_dns[0]));
    else
      ns1buf[0] = '\0';
    if(b->ipcp.want_dns[1].s_addr != 0)
      snprintf(ns2buf, sizeof(ns2buf), "dns2 %s", inet_ntoa(b->ipcp.want_dns[1]));
    else
      ns2buf[0] = '\0';

    ExecCmd(LG_IFACE2, b->name, "%s %s inet %s %s '%s' %s %s",
      iface->up_script, iface->ifname, u_rangetoa(&iface->self_addr,selfbuf, sizeof(selfbuf)),
      u_addrtoa(&iface->peer_addr, peerbuf, sizeof(peerbuf)), 
      *b->params.authname ? b->params.authname : "-", 
      ns1buf, ns2buf);
  }

}

/*
 * IfaceIpIfaceDown()
 *
 * Bring down the IP interface. This implies we're no longer ready.
 */

void
IfaceIpIfaceDown(Bund b)
{
  IfaceState	const iface = &b->iface;
  IfaceRoute	r;
  char          buf[64];

  /* Call "down" script */
  if (*iface->down_script) {
    char	selfbuf[40],peerbuf[40];

    ExecCmd(LG_IFACE2, b->name, "%s %s inet %s %s '%s'",
      iface->down_script, iface->ifname, u_rangetoa(&iface->self_addr,selfbuf, sizeof(selfbuf)),
      u_addrtoa(&iface->peer_addr, peerbuf, sizeof(peerbuf)), 
      *b->params.authname ? b->params.authname : "-");
  }

    /* Delete dynamic routes */
    SLIST_FOREACH(r, &b->params.routes, next) {
	if (u_rangefamily(&r->dest)==AF_INET) {
	    if (!r->ok)
		continue;
	    IfaceSetRoute(b, RTM_DELETE, &r->dest, &iface->peer_addr);
	    r->ok = 0;
	}
    }
    /* Delete static routes */
    SLIST_FOREACH(r, &iface->routes, next) {
	if (u_rangefamily(&r->dest)==AF_INET) {
	    if (!r->ok)
		continue;
	    IfaceSetRoute(b, RTM_DELETE, &r->dest, &iface->peer_addr);
	    r->ok = 0;
	}
    }

  /* Delete any proxy arp entry */
  if (!u_addrempty(&iface->proxy_addr))
    ExecCmdNosh(LG_IFACE2, b->name, "%s -d %s", PATH_ARP, u_addrtoa(&iface->proxy_addr, buf, sizeof(buf)));
  u_addrclear(&iface->proxy_addr);

  /* Remove address from interface */
  IfaceChangeAddr(b, 0, &iface->self_addr, &iface->peer_addr);
    
  IfaceNgIpShutdown(b);
}

/*
 * IfaceIpv6IfaceUp()
 *
 * Bring up the IPv6 interface. The "ready" flag means that
 * IPv6CP is also up and we can deliver packets immediately.
 */

void
IfaceIpv6IfaceUp(Bund b, int ready)
{
  IfaceState		const iface = &b->iface;
  IfaceRoute		r;
  struct u_range	rng;

  if (ready) {

    iface->self_ipv6_addr.family = AF_INET6;
    iface->self_ipv6_addr.u.ip6.__u6_addr.__u6_addr16[0] = 0x80fe;  /* Network byte order */
    iface->self_ipv6_addr.u.ip6.__u6_addr.__u6_addr16[1] = 0x0000;
    iface->self_ipv6_addr.u.ip6.__u6_addr.__u6_addr16[2] = 0x0000;
    iface->self_ipv6_addr.u.ip6.__u6_addr.__u6_addr16[3] = 0x0000;
    iface->self_ipv6_addr.u.ip6.__u6_addr.__u6_addr16[4] = ((u_short*)b->ipv6cp.myintid)[0];
    iface->self_ipv6_addr.u.ip6.__u6_addr.__u6_addr16[5] = ((u_short*)b->ipv6cp.myintid)[1];
    iface->self_ipv6_addr.u.ip6.__u6_addr.__u6_addr16[6] = ((u_short*)b->ipv6cp.myintid)[2];
    iface->self_ipv6_addr.u.ip6.__u6_addr.__u6_addr16[7] = ((u_short*)b->ipv6cp.myintid)[3];

    iface->peer_ipv6_addr.family = AF_INET6;
    iface->peer_ipv6_addr.u.ip6.__u6_addr.__u6_addr16[0] = 0x80fe;  /* Network byte order */
    iface->peer_ipv6_addr.u.ip6.__u6_addr.__u6_addr16[1] = 0x0000;
    iface->peer_ipv6_addr.u.ip6.__u6_addr.__u6_addr16[2] = 0x0000;
    iface->peer_ipv6_addr.u.ip6.__u6_addr.__u6_addr16[3] = 0x0000;
    iface->peer_ipv6_addr.u.ip6.__u6_addr.__u6_addr16[4] = ((u_short*)b->ipv6cp.hisintid)[0];
    iface->peer_ipv6_addr.u.ip6.__u6_addr.__u6_addr16[5] = ((u_short*)b->ipv6cp.hisintid)[1];
    iface->peer_ipv6_addr.u.ip6.__u6_addr.__u6_addr16[6] = ((u_short*)b->ipv6cp.hisintid)[2];
    iface->peer_ipv6_addr.u.ip6.__u6_addr.__u6_addr16[7] = ((u_short*)b->ipv6cp.hisintid)[3];
  }

  if (IfaceNgIpv6Init(b, ready)) {
    Log(LG_ERR, ("[%s] IfaceNgIpv6Init() failed, closing IPv6CP", b->name));
    FsmFailure(&b->ipv6cp.fsm, FAIL_NEGOT_FAILURE);
    return;
  };
  
    /* Set addresses */
    rng.addr = iface->self_ipv6_addr;
    rng.width = 64;
    IfaceChangeAddr(b, 1, &rng, &iface->peer_ipv6_addr);
  
    /* Add static routes */
    SLIST_FOREACH(r, &iface->routes, next) {
	if (u_rangefamily(&r->dest)==AF_INET6) {
	    r->ok = (IfaceSetRoute(b, RTM_ADD, &r->dest, &iface->peer_ipv6_addr) == 0);
	}
    }
    /* Add dynamic routes */
    SLIST_FOREACH(r, &b->params.routes, next) {
	if (u_rangefamily(&r->dest)==AF_INET6) {
	    r->ok = (IfaceSetRoute(b, RTM_ADD, &r->dest, &iface->peer_ipv6_addr) == 0);
	}
    }

  /* Call "up" script */
  if (*iface->up_script) {
    char	selfbuf[64],peerbuf[64];

    ExecCmd(LG_IFACE2, b->name, "%s %s inet6 %s%%%s %s%%%s '%s'",
      iface->up_script, iface->ifname, 
      u_addrtoa(&iface->self_ipv6_addr, selfbuf, sizeof(selfbuf)), iface->ifname,
      u_addrtoa(&iface->peer_ipv6_addr, peerbuf, sizeof(peerbuf)), iface->ifname, 
      *b->params.authname ? b->params.authname : "-");
  }

}

/*
 * IfaceIpv6IfaceDown()
 *
 * Bring down the IPv6 interface. This implies we're no longer ready.
 */

void
IfaceIpv6IfaceDown(Bund b)
{
  IfaceState		const iface = &b->iface;
  IfaceRoute		r;
  struct u_range        rng;

  /* Call "down" script */
  if (*iface->down_script) {
    char	selfbuf[64],peerbuf[64];

    ExecCmd(LG_IFACE2, b->name, "%s %s inet6 %s%%%s %s%%%s '%s'",
      iface->down_script, iface->ifname, 
      u_addrtoa(&iface->self_ipv6_addr, selfbuf, sizeof(selfbuf)), iface->ifname,
      u_addrtoa(&iface->peer_ipv6_addr, peerbuf, sizeof(peerbuf)), iface->ifname, 
      *b->params.authname ? b->params.authname : "-");
  }

    /* Delete dynamic routes */
    SLIST_FOREACH(r, &b->params.routes, next) {
	if (u_rangefamily(&r->dest)==AF_INET6) {
	    if (!r->ok)
		continue;
	    IfaceSetRoute(b, RTM_DELETE, &r->dest, &iface->peer_ipv6_addr);
	    r->ok = 0;
	}
    }
    /* Delete static routes */
    SLIST_FOREACH(r, &iface->routes, next) {
	if (u_rangefamily(&r->dest)==AF_INET6) {
	    if (!r->ok)
		continue;
	    IfaceSetRoute(b, RTM_DELETE, &r->dest, &iface->peer_ipv6_addr);
	    r->ok = 0;
	}
    }

  if (!u_addrempty(&iface->self_ipv6_addr)) {
    /* Remove address from interface */
    rng.addr = iface->self_ipv6_addr;
    rng.width = 64;
    IfaceChangeAddr(b, 0, &rng, &iface->peer_ipv6_addr);
  }

  IfaceNgIpv6Shutdown(b);
}

/*
 * IfaceIdleTimeout()
 */

static void
IfaceIdleTimeout(void *arg)
{
    Bund b = (Bund)arg;

  IfaceState			const iface = &b->iface;
  int				k;

  /* Get updated bpf node traffic statistics */
  BundUpdateStats(b);

  /* Mark current traffic period if there was traffic */
  if (iface->idleStats.recvFrames + iface->idleStats.xmitFrames < 
	b->stats.recvFrames + b->stats.xmitFrames) {
    iface->traffic[0] = TRUE;
  } else {		/* no demand traffic for a whole idle timeout period? */
    for (k = 0; k < IFACE_IDLE_SPLIT && !iface->traffic[k]; k++);
    if (k == IFACE_IDLE_SPLIT) {
      Log(LG_BUND, ("[%s] idle timeout",
	b->name));
      RecordLinkUpDownReason(b, NULL, 0, STR_IDLE_TIMEOUT, NULL);
      BundClose(b);
      return;
    }
  }

  iface->idleStats = b->stats;

  /* Shift traffic history */
  memmove(iface->traffic + 1,
    iface->traffic, (IFACE_IDLE_SPLIT - 1) * sizeof(*iface->traffic));
  iface->traffic[0] = FALSE;

  /* Restart timer */
  TimerStart(&iface->idleTimer);
}

/*
 * IfaceSessionTimeout()
 */

static void
IfaceSessionTimeout(void *arg)
{
    Bund b = (Bund)arg;

  Log(LG_BUND, ("[%s] session timeout ", b->name));

  RecordLinkUpDownReason(b, NULL, 0, STR_SESSION_TIMEOUT, NULL);

  BundClose(b);

}

/*
 * IfaceCachePkt()
 *
 * A packet caused dial-on-demand; save it for later if possible.
 * Consumes the mbuf in any case.
 */

static void
IfaceCachePkt(Bund b, int proto, Mbuf pkt)
{
  IfaceState	const iface = &b->iface;
  Mbuf		new;
  int		len;

  /* Only cache network layer data */
  if (!PROT_NETWORK_DATA(proto)) {
    PFREE(pkt);
    return;
  }

  /* Release previously cached packet, if any, and save this one */
  if (iface->dodCache.pkt)
    PFREE(iface->dodCache.pkt);

  /* Make an own permanent pkt copy */
  new = mballoc(pkt->type, len = plength(pkt));
  assert(mbread(pkt, MBDATA(new), len, NULL) == NULL);

  iface->dodCache.pkt = new;
  iface->dodCache.proto = proto;
  iface->dodCache.ts = time(NULL);
}

/*
 * IfaceCacheSend()
 *
 * Send cached packet
 */

static void
IfaceCacheSend(Bund b)
{
  IfaceState	const iface = &b->iface;

  if (iface->dodCache.pkt) {
    if (iface->dodCache.ts + MAX_DOD_CACHE_DELAY < time(NULL))
      PFREE(iface->dodCache.pkt);
    else {
      if (NgFuncWritePppFrame(b, NG_PPP_BUNDLE_LINKNUM,
	  iface->dodCache.proto, iface->dodCache.pkt) < 0) {
	Log(LG_ERR, ("[%s] can't write cached pkt: %s",
	  b->name, strerror(errno)));
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
IfaceSetCommand(Context ctx, int ac, char *av[], void *arg)
{
  IfaceState	const iface = &ctx->bund->iface;

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
	  Log(LG_ERR, ("[%s] IFACE: Bad IP address \"%s\"", ctx->bund->name, av[0]));
	  return(-1);
	}
	if (!ParseAddr(av[1], &peer_addr, ALLOW_IPV4)) {
	  Log(LG_ERR, ("[%s] IFACE: Bad IP address \"%s\"", ctx->bund->name, av[1]));
	  return(-1);
	}

	/* OK */
	iface->self_addr = self_addr;
	iface->peer_addr = peer_addr;
      }
      break;

    case SET_ROUTE:
      {
	struct u_range		range;
	IfaceRoute		r;

	/* Check */
	if (ac != 1)
	  return(-1);

	/* Get dest address */
	if (!strcasecmp(av[0], "default")) {
	  u_rangeclear(&range);
	  range.addr.family=AF_INET;
	}
	else if (!ParseRange(av[0], &range, ALLOW_IPV4|ALLOW_IPV6)) {
	  Log(LG_ERR, ("[%s] IFACE: Bad route dest address \"%s\"", ctx->bund->name, av[0]));
	  return(-1);
	}
	r = Malloc(MB_IFACE, sizeof(struct ifaceroute));
	r->dest = range;
	r->ok = 0;
	SLIST_INSERT_HEAD(&iface->routes, r, next);
      }
      break;

    case SET_MTU:
      {
	int	max_mtu;

	max_mtu = atoi(av[0]);
	if (max_mtu < IFACE_MIN_MTU || max_mtu > IFACE_MAX_MTU) {
	  Log(LG_ERR, ("[%s] IFACE: Invalid interface mtu %d", ctx->bund->name, max_mtu));
	  return(-1);
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
IfaceStat(Context ctx, int ac, char *av[], void *arg)
{
  IfaceState	const iface = &ctx->bund->iface;
  IfaceRoute	r;
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
  OptStat(ctx, &iface->options, gConfList);
  if (!SLIST_EMPTY(&iface->routes)) {
    Printf("Static routes via peer:\r\n");
    SLIST_FOREACH(r, &iface->routes, next) {
	Printf("\t%s\r\n", u_rangetoa(&r->dest,buf,sizeof(buf)));
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
  if (iface->up && !SLIST_EMPTY(&ctx->bund->params.routes)) {
    Printf("Dynamic routes via peer:\r\n");
    SLIST_FOREACH(r, &ctx->bund->params.routes, next) {
	Printf("\t%s\r\n", u_rangetoa(&r->dest,buf,sizeof(buf)));
    }
  }
  if (iface->up && (ctx->bund->params.acl_limits[0] || ctx->bund->params.acl_limits[1])) {
    struct acl	*a;
    Printf("Traffic filters:\r\n");
    for (k = 0; k < ACL_FILTERS; k++) {
	a = ctx->bund->params.acl_filters[k];
	while (a) {
	    Printf("\t%d#%d\t: '%s'\r\n", (k + 1), a->number, a->rule);
	    a = a->next;
	}
    }
    Printf("Traffic limits:\r\n");
    for (k = 0; k < 2; k++) {
	a = ctx->bund->params.acl_limits[k];
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
IfaceSetMTU(Bund b, int mtu)
{
  IfaceState	const iface = &b->iface;
  struct ifreq	ifr;
  int		s;

  /* Get socket */
  if ((s = socket(PF_INET, SOCK_DGRAM, 0)) < 0) {
    Perror("[%s] IFACE: Can't get socket to set MTU!", b->name);
    return;
  }

  if ((b->params.mtu > 0) && (mtu > b->params.mtu)) {
    mtu = b->params.mtu;
    Log(LG_IFACE2, ("[%s] IFACE: forcing MTU of auth backend: %d bytes",
      b->name, mtu));
  }

  /* Limit MTU to configured maximum */
  if (mtu > iface->max_mtu) {
      mtu = iface->max_mtu;
  }

  /* Set MTU on interface */
  memset(&ifr, 0, sizeof(ifr));
  strncpy(ifr.ifr_name, b->iface.ifname, sizeof(ifr.ifr_name));
  ifr.ifr_mtu = mtu;
  Log(LG_IFACE2, ("[%s] IFACE: setting %s MTU to %d bytes",
    b->name, b->iface.ifname, mtu));
  if (ioctl(s, SIOCSIFMTU, (char *)&ifr) < 0)
    Perror("[%s] IFACE: ioctl(%s, %s)", b->name, b->iface.ifname, "SIOCSIFMTU");
  close(s);

  /* Save MTU */
  iface->mtu = mtu;
}

void
IfaceChangeFlags(Bund b, int clear, int set)
{
    struct ifreq ifrq;
    int s, new_flags;

    Log(LG_IFACE2, ("[%s] IFACE: Change interface flags: -%d +%d",
	b->name, clear, set)); 

    if ((s = socket(PF_INET, SOCK_DGRAM, 0)) < 0) {
	Perror("[%s] IFACE: Can't get socket to change interface flags!", b->name);
	return;
    }

    memset(&ifrq, '\0', sizeof(ifrq));
    strncpy(ifrq.ifr_name, b->iface.ifname, sizeof(ifrq.ifr_name) - 1);
    ifrq.ifr_name[sizeof(ifrq.ifr_name) - 1] = '\0';
    if (ioctl(s, SIOCGIFFLAGS, &ifrq) < 0) {
	Perror("[%s] IFACE: ioctl(%s, %s)", b->name, b->iface.ifname, "SIOCGIFFLAGS");
	close(s);
	return;
    }
    new_flags = (ifrq.ifr_flags & 0xffff) | (ifrq.ifr_flagshigh << 16);

    new_flags &= ~clear;
    new_flags |= set;

    ifrq.ifr_flags = new_flags & 0xffff;
    ifrq.ifr_flagshigh = new_flags >> 16;

    if (ioctl(s, SIOCSIFFLAGS, &ifrq) < 0) {
	Perror("[%s] IFACE: ioctl(%s, %s)", b->name, b->iface.ifname, "SIOCSIFFLAGS");
	close(s);
	return;
    }
    close(s);
}

#if defined(__KAME__) && !defined(NOINET6)
static void
add_scope(struct sockaddr *sa, int ifindex)
{
  struct sockaddr_in6 *sa6;

  if (sa->sa_family != AF_INET6)
    return;
  sa6 = (struct sockaddr_in6 *)sa;
  if (!IN6_IS_ADDR_LINKLOCAL(&sa6->sin6_addr) &&
      !IN6_IS_ADDR_MC_LINKLOCAL(&sa6->sin6_addr))
    return;
  if (*(u_int16_t *)&sa6->sin6_addr.s6_addr[2] != 0)
    return;
  *(u_int16_t *)&sa6->sin6_addr.s6_addr[2] = htons(ifindex);
}
#endif

void
IfaceChangeAddr(Bund b, int add, struct u_range *self, struct u_addr *peer)
{
    struct ifaliasreq ifra;
    struct in6_aliasreq ifra6;
    struct sockaddr_in *me4, *msk4, *peer4;
    struct sockaddr_storage ssself, sspeer, ssmsk;
    int res = 0;
    int s;
    char buf[64], buf1[64];

    Log(LG_IFACE2, ("[%s] IFACE: %s address %s->%s %s %s",
	b->name, add?"Add":"Remove", u_rangetoa(self, buf, sizeof(buf)), 
	((peer != NULL)?u_addrtoa(peer, buf1, sizeof(buf1)):""),
	add?"to":"from", b->iface.ifname));

    u_rangetosockaddrs(self, &ssself, &ssmsk);
    if (peer)
	u_addrtosockaddr(peer, 0, &sspeer);

    if ((s = socket(self->addr.family, SOCK_DGRAM, 0)) < 0) {
	Perror("[%s] IFACE: Can't get socket to change interface address!", b->name);
	return;
    }

    switch (self->addr.family) {
      case AF_INET:
	memset(&ifra, '\0', sizeof(ifra));
	strncpy(ifra.ifra_name, b->iface.ifname, sizeof(ifra.ifra_name) - 1);

	me4 = (struct sockaddr_in *)&ifra.ifra_addr;
	memcpy(me4, &ssself, sizeof(*me4));

	msk4 = (struct sockaddr_in *)&ifra.ifra_mask;
	memcpy(msk4, &ssmsk, sizeof(*msk4));

	peer4 = (struct sockaddr_in *)&ifra.ifra_broadaddr;
	if (peer == NULL || peer->family == AF_UNSPEC) {
    	    peer4->sin_family = AF_INET;
    	    peer4->sin_len = sizeof(*peer4);
    	    peer4->sin_addr.s_addr = INADDR_NONE;
	} else
    	    memcpy(peer4, &sspeer, sizeof(*peer4));

	res = ioctl(s, add?SIOCAIFADDR:SIOCDIFADDR, &ifra);
	if (res == -1) {
	    Perror("[%s] IFACE: %s IPv4 address %s %s failed", 
		b->name, add?"Adding":"Removing", add?"to":"from", b->iface.ifname);
	}
	break;

      case AF_INET6:
	memset(&ifra6, '\0', sizeof(ifra6));
	strncpy(ifra6.ifra_name, b->iface.ifname, sizeof(ifra6.ifra_name) - 1);

	memcpy(&ifra6.ifra_addr, &ssself, sizeof(ifra6.ifra_addr));
	memcpy(&ifra6.ifra_prefixmask, &ssmsk, sizeof(ifra6.ifra_prefixmask));
	if (peer == NULL || peer->family == AF_UNSPEC)
    	    ifra6.ifra_dstaddr.sin6_family = AF_UNSPEC;
	else if (memcmp(&((struct sockaddr_in6 *)&ssmsk)->sin6_addr, &in6mask128,
		    sizeof(in6mask128)) == 0)
    	    memcpy(&ifra6.ifra_dstaddr, &sspeer, sizeof(ifra6.ifra_dstaddr));
	ifra6.ifra_lifetime.ia6t_vltime = ND6_INFINITE_LIFETIME;
	ifra6.ifra_lifetime.ia6t_pltime = ND6_INFINITE_LIFETIME;

	res = ioctl(s, add?SIOCAIFADDR_IN6:SIOCDIFADDR_IN6, &ifra6);
	if (res == -1) {
	    Perror("[%s] IFACE: %s IPv6 address %s %s failed", 
		b->name, add?"Adding":"Removing", add?"to":"from", b->iface.ifname);
	}
	break;
    }
    close(s);
}

struct rtmsg {
  struct rt_msghdr m_rtm;
  char m_space[256];
};

static size_t
memcpy_roundup(char *cp, const void *data, size_t len)
{
  size_t padlen;

#define ROUNDUP(x) ((x) ? (1 + (((x) - 1) | (sizeof(long) - 1))) : sizeof(long))
  padlen = ROUNDUP(len);
  memcpy(cp, data, len);
  if (padlen > len)
    memset(cp + len, '\0', padlen - len);

  return padlen;
}

int
IfaceSetRoute(Bund b, int cmd, struct u_range *dst,
       struct u_addr *gw)
{
    struct rtmsg rtmes;
    int s, nb, wb;
    char *cp;
    const char *cmdstr = (cmd == RTM_ADD ? "Add" : "Delete");
    struct sockaddr_storage sadst, samask, sagw;
    char buf[64], buf1[64];

    s = socket(PF_ROUTE, SOCK_RAW, 0);
    if (s < 0) {
	Perror("[%s] IFACE: Can't get route socket!", b->name);
	return (-1);
    }
    memset(&rtmes, '\0', sizeof(rtmes));
    rtmes.m_rtm.rtm_version = RTM_VERSION;
    rtmes.m_rtm.rtm_type = cmd;
    rtmes.m_rtm.rtm_addrs = RTA_DST;
    rtmes.m_rtm.rtm_seq = ++gRouteSeq;
    rtmes.m_rtm.rtm_pid = gPid;
    rtmes.m_rtm.rtm_flags = RTF_UP | RTF_GATEWAY | RTF_STATIC;

    u_rangetosockaddrs(dst, &sadst, &samask);
#if defined(__KAME__) && !defined(NOINET6)
    add_scope((struct sockaddr *)&sadst, b->iface.ifindex);
#endif

    cp = rtmes.m_space;
    cp += memcpy_roundup(cp, &sadst, sadst.ss_len);
    if (gw != NULL) {
	u_addrtosockaddr(gw, 0, &sagw);
#if defined(__KAME__) && !defined(NOINET6)
	add_scope((struct sockaddr *)&sagw, b->iface.ifindex);
#endif
    	cp += memcpy_roundup(cp, &sagw, sagw.ss_len);
    	rtmes.m_rtm.rtm_addrs |= RTA_GATEWAY;
    } else if (cmd == RTM_ADD) {
    	Log(LG_ERR, ("[%s] IfaceSetRoute: gw is not set\n", b->name));
    	close(s);
    	return (-1);
    }

    if (!u_rangehost(dst)) {
	cp += memcpy_roundup(cp, &samask, samask.ss_len);
	rtmes.m_rtm.rtm_addrs |= RTA_NETMASK;
    }

    nb = cp - (char *)&rtmes;
    rtmes.m_rtm.rtm_msglen = nb;
    wb = write(s, &rtmes, nb);
    if (wb < 0) {
    	Log(LG_ERR, ("[%s] IFACE: %s route %s %s failed: %s",
	    b->name, cmdstr, u_rangetoa(dst, buf, sizeof(buf)), 
	    ((gw != NULL)?u_addrtoa(gw, buf1, sizeof(buf1)):""),
	    (rtmes.m_rtm.rtm_errno != 0)?strerror(rtmes.m_rtm.rtm_errno):strerror(errno)));
	close(s);
	return (-1);
    }
    close(s);
    Log(LG_IFACE2, ("[%s] IFACE: %s route %s %s",
	    b->name, cmdstr, u_rangetoa(dst, buf, sizeof(buf)), 
	    ((gw != NULL)?u_addrtoa(gw, buf1, sizeof(buf1)):"")));
    return (0);
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
  
#ifdef USE_NG_IPACCT
	/* Connect a ipacct node if configured */
	if (Enabled(&b->iface.options, IFACE_CONF_IPACCT)) {
	    if (IfaceInitIpacct(b, path, hook))
		goto fail;
	    b->iface.ipacct_up = 1;
	}
#endif	/* USE_NG_IPACCT */

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
    char		path[NG_PATHLEN + 1];

#ifdef USE_NG_NAT
    if (b->iface.nat_up)
	IfaceShutdownNAT(b);
    b->iface.nat_up = 0;
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
#ifdef USE_NG_IPACCT
    if (b->iface.ipacct_up)
	IfaceShutdownIpacct(b);
    b->iface.ipacct_up = 0;
#endif
    if (b->iface.mss_up)
	IfaceShutdownMSS(b);
    b->iface.mss_up = 0;

    IfaceShutdownLimits(b);
    NgFuncDisconnect(b->csock, b->name, MPD_HOOK_PPP, NG_PPP_HOOK_INET);

    snprintf(path, sizeof(path), "%s:", b->iface.ifname);
    NgFuncDisconnect(b->csock, b->name, path, NG_IFACE_HOOK_INET);
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
	snprintf(cn.path, sizeof(cn.path), "%s:", b->iface.ifname);
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
    char		path[NG_PATHLEN + 1];

    NgFuncDisconnect(b->csock, b->name, MPD_HOOK_PPP, NG_PPP_HOOK_IPV6);

    snprintf(path, sizeof(path), "%s:", b->iface.ifname);
    NgFuncDisconnect(b->csock, b->name, path, NG_IFACE_HOOK_INET);
}

#ifdef USE_NG_NAT
static int
IfaceInitNAT(Bund b, char *path, char *hook)
{
    NatState      const nat = &b->iface.nat;
    struct ngm_mkpeer	mp;
    struct ngm_name	nm;
    struct in_addr	ip;
#ifdef NG_NAT_LOG
    struct ng_nat_mode	mode;
#endif  
    Log(LG_IFACE2, ("[%s] IFACE: Connecting NAT", b->name));
  
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
    if (u_addrempty(&nat->alias_addr)) {
	ip.s_addr = 1; // Set something just to make it ready
    } else {
	ip = nat->alias_addr.u.ip4;
    }
    if (NgSendMsg(b->csock, path,
	    NGM_NAT_COOKIE, NGM_NAT_SET_IPADDR, &ip, sizeof(ip)) < 0) {
	Log(LG_ERR, ("[%s] can't set NAT ip: %s",
    	    b->name, strerror(errno)));
    }

#ifdef NG_NAT_LOG
    /* Set NAT mode */
    mode.flags = 0;
    if (Enabled(&nat->options, NAT_CONF_LOG))
	mode.flags |= NG_NAT_LOG;
    if (!Enabled(&nat->options, NAT_CONF_INCOMING))
	mode.flags |= NG_NAT_DENY_INCOMING;
    if (Enabled(&nat->options, NAT_CONF_SAME_PORTS))
	mode.flags |= NG_NAT_SAME_PORTS;
    if (Enabled(&nat->options, NAT_CONF_UNREG_ONLY))
	mode.flags |= NG_NAT_UNREGISTERED_ONLY;
    
    mode.mask = NG_NAT_LOG | NG_NAT_DENY_INCOMING | 
	NG_NAT_SAME_PORTS | NG_NAT_UNREGISTERED_ONLY;
    if (NgSendMsg(b->csock, path,
	    NGM_NAT_COOKIE, NGM_NAT_SET_MODE, &mode, sizeof(mode)) < 0) {
	Log(LG_ERR, ("[%s] can't set NAT mode: %s",
    	    b->name, strerror(errno)));
    }

    /* Set NAT target IP */
    if (!u_addrempty(&nat->target_addr)) {
	ip = nat->target_addr.u.ip4;
	if (NgSendMsg(b->csock, path,
		NGM_NAT_COOKIE, NGM_NAT_SET_IPADDR, &ip, sizeof(ip)) < 0) {
	    Log(LG_ERR, ("[%s] can't set NAT target IP: %s",
    		b->name, strerror(errno)));
	}
    }
#endif

    return(0);
}

static int
IfaceSetupNAT(Bund b)
{
    NatState	const nat = &b->iface.nat;
    char	path[NG_PATHLEN+1];

    if (u_addrempty(&nat->alias_addr)) {
	snprintf(path, sizeof(path), "mpd%d-%s-nat:", gPid, b->name);
	if (NgSendMsg(b->csock, path,
    		NGM_NAT_COOKIE, NGM_NAT_SET_IPADDR,
		&b->iface.self_addr.addr.u.ip4,
		sizeof(b->iface.self_addr.addr.u.ip4)) < 0) {
	    Log(LG_ERR, ("[%s] can't set NAT ip: %s",
    		b->name, strerror(errno)));
	    return (-1);
	}
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

    Log(LG_IFACE2, ("[%s] IFACE: Connecting tee", b->name));
  
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

#ifdef USE_NG_IPACCT
static int
IfaceInitIpacct(Bund b, char *path, char *hook)
{
    struct ngm_mkpeer	mp;
    struct ngm_name	nm;
    struct ngm_connect  cn;
    char		path1[NG_PATHLEN+1];
    struct {
	struct ng_ipacct_mesg m;
	int		data;
    } ipam;

    Log(LG_IFACE2, ("[%s] IFACE: Connecting ipacct", b->name));
  
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
    snprintf(nm.name, sizeof(nm.name), "%s_acct_tee", b->iface.ifname);
    if (NgSendMsg(b->csock, path,
	NGM_GENERIC_COOKIE, NGM_NAME, &nm, sizeof(nm)) < 0) {
      Log(LG_ERR, ("[%s] can't name %s node: %s",
	b->name, NG_TEE_NODE_TYPE, strerror(errno)));
      return(-1);
    }
    strcpy(hook, NG_TEE_HOOK_LEFT);

    snprintf(mp.type, sizeof(mp.type), "%s", NG_IPACCT_NODE_TYPE);
    strcpy(mp.ourhook, NG_TEE_HOOK_RIGHT2LEFT);
    snprintf(mp.peerhook, sizeof(mp.peerhook), "%s_in", b->iface.ifname);
    if (NgSendMsg(b->csock, path,
	NGM_GENERIC_COOKIE, NGM_MKPEER, &mp, sizeof(mp)) < 0) {
      Log(LG_ERR, ("[%s] can't create %s node at \"%s\"->\"%s\": %s",
	b->name, NG_IPACCT_NODE_TYPE, path, mp.ourhook, strerror(errno)));
      return(-1);
    }
    snprintf(path1, sizeof(path1), "%s.%s", path, NG_TEE_HOOK_RIGHT2LEFT);
    snprintf(nm.name, sizeof(nm.name), "%s_ip_acct", b->iface.ifname);
    if (NgSendMsg(b->csock, path1,
	NGM_GENERIC_COOKIE, NGM_NAME, &nm, sizeof(nm)) < 0) {
      Log(LG_ERR, ("[%s] can't name %s node: %s",
	b->name, NG_IPACCT_NODE_TYPE, strerror(errno)));
      return(-1);
    }
    strcpy(cn.ourhook, NG_TEE_HOOK_LEFT2RIGHT);
    strcpy(cn.path, NG_TEE_HOOK_RIGHT2LEFT);
    snprintf(cn.peerhook, sizeof(cn.peerhook), "%s_out", b->iface.ifname);
    if (NgSendMsg(b->csock, path, NGM_GENERIC_COOKIE, NGM_CONNECT, &cn,
	sizeof(cn)) < 0) {
      Log(LG_ERR, ("[%s] can't connect \"%s\"->\"%s\" and \"%s\"->\"%s\": %s", 
        b->name, path, cn.ourhook, cn.path, cn.peerhook, strerror(errno)));
      return (-1);
    }
    
    snprintf(ipam.m.hname, sizeof(ipam.m.hname), "%s_in", b->iface.ifname);
    ipam.data = DLT_RAW;
    if (NgSendMsg(b->csock, path1, NGM_IPACCT_COOKIE, NGM_IPACCT_SETDLT, 
	&ipam, sizeof(ipam)) < 0) {
      Log(LG_ERR, ("[%s] can't set DLT \"%s\"->\"%s\": %s", 
        b->name, path, ipam.m.hname, strerror(errno)));
      return (-1);
    }
    ipam.data = 10000;
    if (NgSendMsg(b->csock, path1, NGM_IPACCT_COOKIE, NGM_IPACCT_STHRS, 
	&ipam, sizeof(ipam)) < 0) {
      Log(LG_ERR, ("[%s] can't set DLT \"%s\"->\"%s\": %s", 
        b->name, path, ipam.m.hname, strerror(errno)));
      return (-1);
    }
    
    snprintf(ipam.m.hname, sizeof(ipam.m.hname), "%s_out", b->iface.ifname);
    ipam.data = DLT_RAW;
    if (NgSendMsg(b->csock, path1, NGM_IPACCT_COOKIE, NGM_IPACCT_SETDLT, 
	&ipam, sizeof(ipam)) < 0) {
      Log(LG_ERR, ("[%s] can't set DLT \"%s\"->\"%s\": %s", 
        b->name, path, ipam.m.hname, strerror(errno)));
      return (-1);
    }
    ipam.data = 10000;
    if (NgSendMsg(b->csock, path1, NGM_IPACCT_COOKIE, NGM_IPACCT_STHRS, 
	&ipam, sizeof(ipam)) < 0) {
      Log(LG_ERR, ("[%s] can't set DLT \"%s\"->\"%s\": %s", 
        b->name, path, ipam.m.hname, strerror(errno)));
      return (-1);
    }

    return(0);
}

static void
IfaceShutdownIpacct(Bund b)
{
    char	path[NG_PATHLEN+1];

    snprintf(path, sizeof(path), "%s_acct_tee:", b->iface.ifname);
    NgFuncShutdownNode(b->csock, b->name, path);
}
#endif

#ifdef USE_NG_NETFLOW
static int
IfaceInitNetflow(Bund b, char *path, char *hook, char out)
{
    struct ngm_connect	cn;

    Log(LG_IFACE2, ("[%s] IFACE: Connecting netflow (%s)", b->name, out?"out":"in"));
  
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
	    gNetflowIface + b->id*2 + out);
    } else {
	snprintf(cn.peerhook, sizeof(cn.peerhook), "%s%d", NG_NETFLOW_HOOK_DATA,
	    gNetflowIface + b->id*2 + out);
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
	    gNetflowIface + b->id*2 + out);
    } else {
	snprintf(hook, NG_HOOKLEN, "%s%d", NG_NETFLOW_HOOK_OUT,
	    gNetflowIface + b->id*2 + out);
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
    nf_setdlt.iface = gNetflowIface + b->id*2 + out;
    nf_setdlt.dlt = DLT_RAW;
    if (NgSendMsg(b->csock, path, NGM_NETFLOW_COOKIE, NGM_NETFLOW_SETDLT,
	&nf_setdlt, sizeof(nf_setdlt)) < 0) {
      Log(LG_ERR, ("[%s] can't configure data link type on %s: %s", b->name,
	path, strerror(errno)));
      goto fail;
    }
    if (!out) {
	nf_setidx.iface = gNetflowIface + b->id*2 + out;
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
	    gNetflowIface + b->id*2 + out);
    NgFuncDisconnect(b->csock, b->name, path, hook);
    snprintf(hook, NG_HOOKLEN, "%s%d", NG_NETFLOW_HOOK_OUT,
	    gNetflowIface + b->id*2 + out);
    NgFuncDisconnect(b->csock, b->name, path, hook);
}
#endif

static int
IfaceInitMSS(Bund b, char *path, char *hook)
{
	struct ngm_mkpeer	mp;
	struct ngm_name		nm;
#ifndef USE_NG_TCPMSS
	struct ngm_connect	cn;
#endif

	Log(LG_IFACE2, ("[%s] IFACE: Connecting tcpmssfix", b->name));
  
#ifdef USE_NG_TCPMSS
	/* Create ng_tcpmss(4) node. */
	snprintf(mp.type, sizeof(mp.type), "%s", NG_TCPMSS_NODE_TYPE);
	snprintf(mp.ourhook, sizeof(mp.ourhook), "%s", hook);
	snprintf(mp.peerhook, sizeof(mp.peerhook), "in");
	if (NgSendMsg(b->csock, path,
    		NGM_GENERIC_COOKIE, NGM_MKPEER, &mp, sizeof(mp)) < 0) {
    	    Log(LG_ERR, ("can't create %s node at \"%s\"->\"%s\": %s", 
    		NG_TCPMSS_NODE_TYPE, path, mp.ourhook, strerror(errno)));
	    goto fail;
	}

	strlcat(path, ".", NG_PATHLEN);
	strlcat(path, hook, NG_PATHLEN);
	snprintf(hook, NG_HOOKLEN, "out");

	/* Set the new node's name. */
	snprintf(nm.name, sizeof(nm.name), "mpd%d-%s-mss", gPid, b->name);
	if (NgSendMsg(b->csock, path,
    		NGM_GENERIC_COOKIE, NGM_NAME, &nm, sizeof(nm)) < 0) {
    	    Log(LG_ERR, ("can't name %s node: %s", NG_TCPMSS_NODE_TYPE,
    		strerror(errno)));
	    goto fail;
	}

#else
    /* Create a bpf node for SYN detection. */
    snprintf(mp.type, sizeof(mp.type), "%s", NG_BPF_NODE_TYPE);
    snprintf(mp.ourhook, sizeof(mp.ourhook), "%s", hook);
    snprintf(mp.peerhook, sizeof(mp.peerhook), "ppp");
    if (NgSendMsg(b->csock, path,
	    NGM_GENERIC_COOKIE, NGM_MKPEER, &mp, sizeof(mp)) < 0) {
    	Log(LG_ERR, ("can't create %s node at \"%s\"->\"%s\": %s", 
    	    NG_BPF_NODE_TYPE, path, mp.ourhook, strerror(errno)));
	goto fail;
    }

    strlcat(path, ".", NG_PATHLEN);
    strlcat(path, hook, NG_PATHLEN);
    strcpy(hook, "iface");

    /* Set the new node's name. */
    snprintf(nm.name, sizeof(nm.name), "mpd%d-%s-mss", gPid, b->name);
    if (NgSendMsg(b->csock, path,
	    NGM_GENERIC_COOKIE, NGM_NAME, &nm, sizeof(nm)) < 0) {
    	Log(LG_ERR, ("can't name tcpmssfix %s node: %s", NG_BPF_NODE_TYPE,
    	    strerror(errno)));
	goto fail;
    }

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

  snprintf(path, sizeof(path), "mpd%d-%s-mss:", gPid, b->name);

  /* Send configure message. */
  memset(&tcpmsscfg, 0, sizeof(tcpmsscfg));
  tcpmsscfg.maxMSS = maxMSS;

  snprintf(tcpmsscfg.inHook, sizeof(tcpmsscfg.inHook), "in");
  snprintf(tcpmsscfg.outHook, sizeof(tcpmsscfg.outHook), "out");
  if (NgSendMsg(b->csock, path, NGM_TCPMSS_COOKIE, NGM_TCPMSS_CONFIG,
      &tcpmsscfg, sizeof(tcpmsscfg)) < 0) {
    Log(LG_ERR, ("[%s] can't configure %s node program: %s", b->name,
      NG_TCPMSS_NODE_TYPE, strerror(errno)));
  }
  snprintf(tcpmsscfg.inHook, sizeof(tcpmsscfg.inHook), "out");
  snprintf(tcpmsscfg.outHook, sizeof(tcpmsscfg.outHook), "in");
  if (NgSendMsg(b->csock, path, NGM_TCPMSS_COOKIE, NGM_TCPMSS_CONFIG,
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

	snprintf(path, sizeof(path), "mpd%d-%s-mss:", gPid, b->name);
	NgFuncShutdownNode(b->csock, b->name, path);
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

	Log(LG_IFACE2, ("[%s] IFACE: Connecting limits", b->name));
  
	/* Create a bpf node for traffic filtering. */
	snprintf(mp.type, sizeof(mp.type), "%s", NG_BPF_NODE_TYPE);
	snprintf(mp.ourhook, sizeof(mp.ourhook), "%s", hook);
	snprintf(mp.peerhook, sizeof(mp.peerhook), "ppp");
	if (NgSendMsg(b->csock, path,
		NGM_GENERIC_COOKIE, NGM_MKPEER, &mp, sizeof(mp)) < 0) {
    	    Log(LG_ERR, ("can't create %s node at \"%s\"->\"%s\": %s", 
    		NG_BPF_NODE_TYPE, path, mp.ourhook, strerror(errno)));
	    goto fail;
	}

	strlcat(path, ".", NG_PATHLEN);
	strlcat(path, hook, NG_PATHLEN);
	strcpy(hook, "iface");

	/* Set the new node's name. */
	snprintf(nm.name, sizeof(nm.name), "mpd%d-%s-lim", gPid, b->name);
	if (NgSendMsg(b->csock, path,
		NGM_GENERIC_COOKIE, NGM_NAME, &nm, sizeof(nm)) < 0) {
    	    Log(LG_ERR, ("can't name limits %s node: %s", NG_BPF_NODE_TYPE,
    		strerror(errno)));
	    goto fail;
	}

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
		    		b->name, NG_CAR_NODE_TYPE, path, mp.ourhook, strerror(errno)));
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
