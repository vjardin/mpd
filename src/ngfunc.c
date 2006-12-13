
/*
 * ngfunc.c
 *
 * Written by Archie Cobbs <archie@freebsd.org>
 * Copyright (c) 1995-1999 Whistle Communications, Inc. All rights reserved.
 * See ``COPYRIGHT.whistle''
 *
 * TCP MSSFIX contributed by Sergey Korolew <dsATbittu.org.ru>
 *
 * Routines for doing netgraph stuff
 *
 */

#include "ppp.h"
#include "bund.h"
#include "ngfunc.h"
#include "input.h"
#include "ccp.h"
#include "netgraph.h"
#include "command.h"
#include "util.h"

#include <net/bpf.h>
#include <arpa/inet.h>

#include <netgraph/ng_message.h>

#ifdef __DragonFly__
#include <netgraph/socket/ng_socket.h>
#include <netgraph/ksocket/ng_ksocket.h>
#include <netgraph/iface/ng_iface.h>
#include <netgraph/ppp/ng_ppp.h>
#include <netgraph/vjc/ng_vjc.h>
#include <netgraph/bpf/ng_bpf.h>
#include <netgraph/tee/ng_tee.h>
#else
#include <netgraph/ng_socket.h>
#include <netgraph/ng_ksocket.h>
#include <netgraph/ng_iface.h>
#include <netgraph/ng_ppp.h>
#include <netgraph/ng_vjc.h>
#include <netgraph/ng_bpf.h>
#include <netgraph/ng_tee.h>
#endif
#ifdef USE_NG_TCPMSS
#include <netgraph/ng_tcpmss.h>
#endif
#ifdef USE_NG_NETFLOW
#include <netgraph/netflow/ng_netflow.h>
#endif
#ifdef USE_NG_NAT
#include <netgraph/ng_nat.h>
#endif

#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>

/*
 * DEFINITIONS
 */

  #define TEMPHOOK		"temphook"
  #define MAX_IFACE_CREATE	128

  /* Set menu options */
  enum {
    SET_EXPORT,
    SET_SOURCE,
    SET_TIMEOUTS,
    SET_NODE,
    SET_HOOK,
  };

/*
 * INTERNAL FUNCTIONS
 */

  static void	NgFuncDataEvent(int type, void *cookie);
  static void	NgFuncCtrlEvent(int type, void *cookie);
  static int	NgFuncCreateIface(Bund b,
			const char *ifname, char *buf, int max);
  static int	NgFuncIfaceExists(Bund b,
			const char *ifname, char *buf, int max);
  static void	NgFuncShutdownInternal(Bund b, int iface, int ppp);

  static void	NgFuncErrx(const char *fmt, ...);
  static void	NgFuncErr(const char *fmt, ...);
#ifdef USE_NG_NETFLOW
  static int	NetflowSetCommand(int ac, char *av[], void *arg);
  static int	NgFuncInitNetflow(Bund b);
  static int	NgFuncInitNetflowHook(Bund b, int iface);
#endif
  static int	NgFuncInitVJ(Bund b);
  static int    NgFuncInitMSS(Bund b);
/*
 * GLOBAL VARIABLES
 */

#ifdef USE_NG_NETFLOW
  const struct cmdtab NetflowSetCmds[] = {
    { "export <ip> <port>",	"Set export destination" ,
        NetflowSetCommand, NULL, (void *) SET_EXPORT },
    { "source <ip> <port>",	"Set local binding" ,
        NetflowSetCommand, NULL, (void *) SET_SOURCE },
    { "timeouts <inactive> <active>", "Set NetFlow timeouts" ,
        NetflowSetCommand, NULL, (void *) SET_TIMEOUTS },
    { "node <name>", "Set node name to use" ,
        NetflowSetCommand, NULL, (void *) SET_NODE },
    { "hook <number>", "Set initial hook number" ,
        NetflowSetCommand, NULL, (void *) SET_HOOK },
    { NULL },
  };
#endif

/*
 * INTERNAL VARIABLES
 */

  /* A BPF filter for matching an IP packet if it constitutes 'demand' */
  static const struct bpf_insn gDemandProg[] = {

	/* Load IP protocol number and IP header length */
/*00*/	BPF_STMT(BPF_LD+BPF_B+BPF_ABS, 9),		/* A <- IP protocol */
/*01*/	BPF_STMT(BPF_LDX+BPF_B+BPF_MSH, 0),		/* X <- header len */

	/* Compare to interesting possibilities */
/*02*/	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, IPPROTO_IGMP, 4, 0),	/* -> 07 */
/*03*/	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, IPPROTO_ICMP, 4, 0),	/* -> 08 */
/*04*/	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, IPPROTO_UDP, 11, 0),	/* -> 16 */
/*05*/	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, IPPROTO_TCP, 16, 0),	/* -> 22 */

	/* Some other protocol -> accept */
/*06*/	BPF_STMT(BPF_RET+BPF_K, (u_int)-1),

	/* Protocol is IGMP -> reject (no multicast stuff) */
/*07*/	BPF_STMT(BPF_RET+BPF_K, 0),

	/* Protocol is ICMP -> reject ICMP replies */
/*08*/	BPF_STMT(BPF_LD+BPF_B+BPF_IND, 0),		/* A <- ICMP type */
/*09*/	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, ICMP_ECHOREPLY, 0, 1),
/*10*/	BPF_STMT(BPF_RET+BPF_K, 0),			/* reject ECHOREPLY */
/*11*/	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, ICMP_UNREACH, 0, 1),
/*12*/	BPF_STMT(BPF_RET+BPF_K, 0),			/* reject UNREACH */
/*13*/	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, ICMP_REDIRECT, 0, 1),
/*14*/	BPF_STMT(BPF_RET+BPF_K, 0),			/* reject REDIRECT */
/*15*/	BPF_STMT(BPF_RET+BPF_K, (u_int)-1),		/* OK, accept */

	/* Protocol is UDP -> reject NTP and port 24 traffic */
#define NTP_PORT	123
#define U24_PORT	24			/* XXX InterJet-specific hack */
/*16*/	BPF_STMT(BPF_LD+BPF_H+BPF_IND, 2),		/* A <- UDP dest port */
/*17*/	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, NTP_PORT, 0, 1),/* compare NTP_PORT */
/*18*/	BPF_STMT(BPF_RET+BPF_K, 0),			/* reject NTP */
/*19*/	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, U24_PORT, 0, 1),/* compare port 24 */
/*20*/	BPF_STMT(BPF_RET+BPF_K, 0),			/* reject port 24 */
/*21*/	BPF_STMT(BPF_RET+BPF_K, (u_int)-1),		/* OK, accept */

	/* Protocol is TCP -> reject if TH_RST bit set */
/*22*/	BPF_STMT(BPF_LD+BPF_B+BPF_IND, 13),		/* A <- TCP flags */
/*23*/	BPF_STMT(BPF_ALU+BPF_AND+BPF_K, TH_RST),	/* A <- A & TH_RST */
/*24*/	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0, 0, 1),	/* compare to zero */
/*25*/	BPF_STMT(BPF_RET+BPF_K, (u_int)-1),		/* accept packet */
/*26*/	BPF_STMT(BPF_RET+BPF_K, 0),			/* reject packet */

  };

  #define DEMAND_PROG_LEN	(sizeof(gDemandProg) / sizeof(*gDemandProg))

  /* A BPF filter that matches nothing */
  static const struct bpf_insn gNoMatchProg[] = {
	BPF_STMT(BPF_RET+BPF_K, 0)
  };

  #define NOMATCH_PROG_LEN	(sizeof(gNoMatchProg) / sizeof(*gNoMatchProg))

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

  #ifdef USE_NG_TCPMSS
  static u_char gTcpMSSNode = FALSE;
  #endif
  #ifdef USE_NG_NETFLOW
  static u_char gNetflowNode = FALSE;
  static u_char gNetflowNodeShutdown = TRUE;
  static u_char gNetflowNodeName[64] = "mpd-nf";
  static u_int gNetflowIface = 0;
  static struct sockaddr_storage gNetflowExport;
  static struct sockaddr_storage gNetflowSource;
  static uint32_t gNetflowInactive = 0;
  static uint32_t gNetflowActive = 0;
  #endif
  
  static int	gNgStatSock=0;

/*
 * NgFuncInit()
 *
 * Setup the initial PPP netgraph framework. Initializes these fields
 * in the supplied bundle structure:
 *
 *	iface.ifname	- Interface name
 *	csock		- Control socket for socket netgraph node
 *	dsock		- Data socket for socket netgraph node
 *
 * Returns -1 if error.
 */

int
NgFuncInit(Bund b, const char *reqIface)
{
  union {
      u_char		buf[sizeof(struct ng_mesg) + sizeof(struct nodeinfo)];
      struct ng_mesg	reply;
  }			u;
  struct nodeinfo	*const ni = (struct nodeinfo *)(void *)u.reply.data;
  struct ngm_mkpeer	mp;
  struct ngm_connect	cn;
  struct ngm_name	nm;
  char			path[NG_PATHLEN + 1];
  char			hook[NG_HOOKLEN + 1];
  int			newIface = 0;
  int			newPpp = 0;

  /* Set up libnetgraph logging */
  NgSetErrLog(NgFuncErr, NgFuncErrx);

  /* Create a netgraph socket node */
  if (NgMkSockNode(NULL, &b->csock, &b->dsock) < 0) {
    Log(LG_ERR, ("[%s] can't create %s node: %s",
      b->name, NG_SOCKET_NODE_TYPE, strerror(errno)));
    return(0);
  }
  (void) fcntl(b->csock, F_SETFD, 1);
  (void) fcntl(b->dsock, F_SETFD, 1);

  /* Give it a name */
  snprintf(nm.name, sizeof(nm.name), "mpd%d-%s-so", gPid, b->name);
  if (NgSendMsg(b->csock, ".",
      NGM_GENERIC_COOKIE, NGM_NAME, &nm, sizeof(nm)) < 0) {
    Log(LG_ERR, ("[%s] can't name %s node: %s",
      b->name, NG_SOCKET_NODE_TYPE, strerror(errno)));
    goto fail;
  }

  /* Create new iface node if necessary, else find the one specified */
  if (reqIface != NULL) {
    switch (NgFuncIfaceExists(b,
	reqIface, b->iface.ifname, sizeof(b->iface.ifname))) {
    case -1:			/* not a netgraph interface */
      Log(LG_ERR, ("[%s] interface \"%s\" is not a netgraph interface",
	b->name, reqIface));
      goto fail;
      break;
    case 0:			/* interface does not exist */
      if (NgFuncCreateIface(b,
	  reqIface, b->iface.ifname, sizeof(b->iface.ifname)) < 0) {
	Log(LG_ERR, ("[%s] can't create interface \"%s\"", b->name, reqIface));
	goto fail;
      }
      break;
    case 1:			/* interface exists */
      break;
    default:
      assert(0);
    }
  } else {
    if (NgFuncCreateIface(b,
	NULL, b->iface.ifname, sizeof(b->iface.ifname)) < 0) {
      Log(LG_ERR, ("[%s] can't create netgraph interface", b->name));
      goto fail;
    }
    newIface = 1;
  }
 
  /* Create new PPP node */
  snprintf(mp.type, sizeof(mp.type), "%s", NG_PPP_NODE_TYPE);
  snprintf(mp.ourhook, sizeof(mp.ourhook), "%s", MPD_HOOK_PPP);
  snprintf(mp.peerhook, sizeof(mp.peerhook), "%s", NG_PPP_HOOK_BYPASS);
  if (NgSendMsg(b->csock, ".",
      NGM_GENERIC_COOKIE, NGM_MKPEER, &mp, sizeof(mp)) < 0) {
    Log(LG_ERR, ("[%s] can't create %s node: %s",
      b->name, mp.type, strerror(errno)));
    goto fail;
  }
  newPpp = 1;

  /* Give it a name */
  snprintf(nm.name, sizeof(nm.name), "mpd%d-%s", gPid, b->name);
  if (NgSendMsg(b->csock, MPD_HOOK_PPP,
      NGM_GENERIC_COOKIE, NGM_NAME, &nm, sizeof(nm)) < 0) {
    Log(LG_ERR, ("[%s] can't name %s node: %s",
      b->name, NG_PPP_NODE_TYPE, strerror(errno)));
    goto fail;
  }
  Log(LG_ALWAYS, ("[%s] %s node is \"%s\"",
    b->name, NG_PPP_NODE_TYPE, nm.name));

  /* Get PPP node ID */
  if (NgSendMsg(b->csock, MPD_HOOK_PPP,
      NGM_GENERIC_COOKIE, NGM_NODEINFO, NULL, 0) < 0) {
    Log(LG_ERR, ("[%s] ppp nodeinfo: %s", b->name, strerror(errno)));
    goto fail;
  }
  if (NgRecvMsg(b->csock, &u.reply, sizeof(u), NULL) < 0) {
    Log(LG_ERR, ("[%s] node \"%s\" reply: %s",
      b->name, MPD_HOOK_PPP, strerror(errno)));
    goto fail;
  }
  b->nodeID = ni->id;

  if (NgFuncInitVJ(b)) 
    goto fail;

  /* Add a bpf node to the PPP node on the "inet" hook */
  snprintf(mp.type, sizeof(mp.type), "%s", NG_BPF_NODE_TYPE);
  snprintf(mp.ourhook, sizeof(mp.ourhook), "%s", NG_PPP_HOOK_INET);
  snprintf(mp.peerhook, sizeof(mp.peerhook), "%s", BPF_HOOK_PPP);
  if (NgSendMsg(b->csock, MPD_HOOK_PPP,
      NGM_GENERIC_COOKIE, NGM_MKPEER, &mp, sizeof(mp)) < 0) {
    Log(LG_ERR, ("[%s] can't create %s node: %s",
      b->name, NG_BPF_NODE_TYPE, strerror(errno)));
    goto fail;
  }

  /* Connect a hook from the bpf node to our socket node */
  snprintf(cn.path, sizeof(cn.path), "%s.%s", MPD_HOOK_PPP, NG_PPP_HOOK_INET);
  snprintf(cn.ourhook, sizeof(cn.ourhook), "%s", MPD_HOOK_DEMAND_TAP);
  snprintf(cn.peerhook, sizeof(cn.peerhook), "%s", BPF_HOOK_MPD);
  if (NgSendMsg(b->csock, ".",
      NGM_GENERIC_COOKIE, NGM_CONNECT, &cn, sizeof(cn)) < 0) {
    Log(LG_ERR, ("[%s] can't connect %s and %s: %s",
      b->name, BPF_HOOK_MPD, MPD_HOOK_DEMAND_TAP, strerror(errno)));
    goto fail;
  }

  snprintf(path, sizeof(path), "%s.%s", MPD_HOOK_PPP, NG_PPP_HOOK_INET);
  strcpy(hook, BPF_HOOK_IFACE);

  /* Give it a name */
  snprintf(nm.name, sizeof(nm.name), "mpd%d-%s-bpf", gPid, b->name);
  if (NgSendMsg(b->csock, path,
      NGM_GENERIC_COOKIE, NGM_NAME, &nm, sizeof(nm)) < 0) {
    Log(LG_ERR, ("[%s] can't name %s node: %s",
      b->name, NG_BPF_NODE_TYPE, strerror(errno)));
    goto fail;
  }

#ifdef USE_NG_NAT
  /* Add a nat node if configured */
  if (b->nat) {
    snprintf(mp.type, sizeof(mp.type), "%s", NG_NAT_NODE_TYPE);
    strcpy(mp.ourhook, hook);
    strcpy(mp.peerhook, NG_NAT_HOOK_IN);
    if (NgSendMsg(b->csock, path,
	NGM_GENERIC_COOKIE, NGM_MKPEER, &mp, sizeof(mp)) < 0) {
      Log(LG_ERR, ("[%s] can't create %s node: %s",
	b->name, NG_NAT_NODE_TYPE, strerror(errno)));
      goto fail;
    }
    strlcat(path, ".", sizeof(path));
    strlcat(path, hook, sizeof(path));
    snprintf(nm.name, sizeof(nm.name), "mpd%d-%s-nat", gPid, b->name);
    if (NgSendMsg(b->csock, path,
	NGM_GENERIC_COOKIE, NGM_NAME, &nm, sizeof(nm)) < 0) {
      Log(LG_ERR, ("[%s] can't name %s node: %s",
	b->name, NG_NAT_NODE_TYPE, strerror(errno)));
      goto fail;
    }
    strcpy(hook, NG_NAT_HOOK_OUT);

    /* Set NAT IP */
    struct in_addr ip = { 1 }; // Setting something just to make it ready
    if (NgSendMsg(b->csock, path,
	    NGM_NAT_COOKIE, NGM_NAT_SET_IPADDR, &ip, sizeof(ip)) < 0) {
	Log(LG_ERR, ("[%s] can't set NAT ip: %s",
    	    b->name, strerror(errno)));
    }
  }
#endif

  /* Add a tee node if configured */
  if (b->tee) {
    snprintf(mp.type, sizeof(mp.type), "%s", NG_TEE_NODE_TYPE);
    strcpy(mp.ourhook, hook);
    strcpy(mp.peerhook, NG_TEE_HOOK_RIGHT);
    if (NgSendMsg(b->csock, path,
	NGM_GENERIC_COOKIE, NGM_MKPEER, &mp, sizeof(mp)) < 0) {
      Log(LG_ERR, ("[%s] can't create %s node: %s",
	b->name, NG_TEE_NODE_TYPE, strerror(errno)));
      goto fail;
    }
    strlcat(path, ".", sizeof(path));
    strlcat(path, hook, sizeof(path));
    snprintf(nm.name, sizeof(nm.name), "%s-tee", b->iface.ifname);
    if (NgSendMsg(b->csock, path,
	NGM_GENERIC_COOKIE, NGM_NAME, &nm, sizeof(nm)) < 0) {
      Log(LG_ERR, ("[%s] can't name %s node: %s",
	b->name, NG_TEE_NODE_TYPE, strerror(errno)));
      goto fail;
    }
    strcpy(hook, NG_TEE_HOOK_LEFT);
  }
  
#ifdef USE_NG_NETFLOW
  if (b->netflow) {

    /* Create global ng_netflow(4) node if not yet. */
    if (gNetflowNode == FALSE) {
	if (NgFuncInitNetflow(b))
	    goto fail;
    }

    gNetflowIface++;
  
    /* Connect ng_netflow(4) node to the ng_bpf(4)/ng_tee(4) node. */
    strcpy(cn.ourhook, hook);
    snprintf(cn.path, sizeof(cn.path), "%s:", gNetflowNodeName);
    if (b->netflow == NETFLOW_OUT) {
	snprintf(cn.peerhook, sizeof(cn.peerhook), "%s%d", NG_NETFLOW_HOOK_OUT,
	    gNetflowIface);
    } else {
	snprintf(cn.peerhook, sizeof(cn.peerhook), "%s%d", NG_NETFLOW_HOOK_DATA,
	    gNetflowIface);
    }
    if (NgSendMsg(b->csock, path, NGM_GENERIC_COOKIE, NGM_CONNECT, &cn,
	sizeof(cn)) < 0) {
      Log(LG_ERR, ("[%s] can't connect %s and %s: %s", b->name,
	cn.path, path, strerror(errno)));
      goto fail;
    }
    strlcat(path, ".", sizeof(path));
    strlcat(path, hook, sizeof(path));
    if (b->netflow == NETFLOW_OUT) {
	snprintf(hook, sizeof(hook), "%s%d", NG_NETFLOW_HOOK_DATA,
	    gNetflowIface);
    } else {
	snprintf(hook, sizeof(hook), "%s%d", NG_NETFLOW_HOOK_OUT,
	    gNetflowIface);
    }

  }
#endif	/* USE_NG_NETFLOW */

  /* Connect the entire graph to the iface node. */
  strcpy(cn.ourhook, hook);
  snprintf(cn.path, sizeof(cn.path), "%s:", b->iface.ifname);
  snprintf(cn.peerhook, sizeof(cn.peerhook), "%s", NG_IFACE_HOOK_INET);
  if (NgSendMsg(b->csock, path,
      NGM_GENERIC_COOKIE, NGM_CONNECT, &cn, sizeof(cn)) < 0) {
    Log(LG_ERR, ("[%s] can't connect %s and %s: %s",
      b->name, cn.ourhook, NG_IFACE_HOOK_INET, strerror(errno)));
    goto fail;
  }

#ifdef USE_NG_NETFLOW
  if (b->netflow) {
    if (NgFuncInitNetflowHook(b, gNetflowIface)) 
	goto fail;
  }
#endif /* USE_NG_NETFLOW */

  /* Connect ipv6 hook of ng_ppp(4) node to the ng_iface(4) node. */
  snprintf(path, sizeof(path), "%s", MPD_HOOK_PPP);
  snprintf(cn.ourhook, sizeof(cn.ourhook), "%s", NG_PPP_HOOK_IPV6);
  snprintf(cn.peerhook, sizeof(cn.peerhook), "%s", NG_IFACE_HOOK_INET6);
  if (NgSendMsg(b->csock, path, NGM_GENERIC_COOKIE, NGM_CONNECT, &cn,
	sizeof(cn)) < 0) {
      Log(LG_ERR, ("[%s] can't connect %s and %s: %s", b->name,
	cn.path, path, strerror(errno)));
      goto fail;
  }

#ifdef USE_NG_TCPMSS
    if (NgFuncInitMSS(b)) 
	goto fail;
#else
  /* Connect a second hook from the bpf node to our socket node. */
  snprintf(cn.path, sizeof(cn.path), "%s.%s", MPD_HOOK_PPP, NG_PPP_HOOK_INET);
  snprintf(cn.ourhook, sizeof(cn.ourhook), "%s", MPD_HOOK_MSSFIX_OUT);
  snprintf(cn.peerhook, sizeof(cn.peerhook), "%s", BPF_HOOK_MPD_OUT);
  if (NgSendMsg(b->csock, ".",
      NGM_GENERIC_COOKIE, NGM_CONNECT, &cn, sizeof(cn)) < 0) {
    Log(LG_ERR, ("[%s] can't connect %s and %s: %s",
      b->name, BPF_HOOK_MPD_OUT, MPD_HOOK_MSSFIX_OUT, strerror(errno)));
    goto fail;
  }
#endif

  /* Configure bpf(8) node */
  NgFuncConfigBPF(b, BPF_MODE_OFF);

  /* Listen for happenings on our node */
  EventRegister(&b->dataEvent, EVENT_READ,
    b->dsock, EVENT_RECURRING, NgFuncDataEvent, b);
  EventRegister(&b->ctrlEvent, EVENT_READ,
    b->csock, EVENT_RECURRING, NgFuncCtrlEvent, b);

  /* OK */
  return(0);

fail:
  NgFuncShutdownInternal(b, newIface, newPpp);
  return(-1);
}

#ifdef USE_NG_NETFLOW
static int
NgFuncInitNetflow(Bund b)
{
    char path[NG_PATHLEN + 1];

      snprintf(gNetflowNodeName, sizeof(gNetflowNodeName), "mpd%d-nf", gPid);

      struct ngm_mkpeer	mp;
      struct ngm_rmhook	rm;
      struct ngm_name	nm;

      /* Create a global netflow node. */
      snprintf(mp.type, sizeof(mp.type), "%s", NG_NETFLOW_NODE_TYPE);
      snprintf(mp.ourhook, sizeof(mp.ourhook), "%s", TEMPHOOK);
      snprintf(mp.peerhook, sizeof(mp.peerhook), "%s0", NG_NETFLOW_HOOK_DATA);
      if (NgSendMsg(b->csock, ".",
	  NGM_GENERIC_COOKIE, NGM_MKPEER, &mp, sizeof(mp)) < 0) {
	Log(LG_ERR, ("can't create %s node: %s", NG_NETFLOW_NODE_TYPE,
	  strerror(errno)));
	goto fail;
      }

      /* Set the new node's name. */
      strcpy(nm.name, gNetflowNodeName);
      if (NgSendMsg(b->csock, TEMPHOOK,
          NGM_GENERIC_COOKIE, NGM_NAME, &nm, sizeof(nm)) < 0) {
	Log(LG_ERR, ("can't name %s node: %s", NG_NETFLOW_NODE_TYPE,
          strerror(errno)));
	goto fail;
      }
      Log(LG_ALWAYS, ("%s node is \"%s\"", NG_NETFLOW_NODE_TYPE, nm.name));

      /* Connect ng_ksocket(4) node for export. */
      snprintf(mp.type, sizeof(mp.type), "%s", NG_KSOCKET_NODE_TYPE);
      snprintf(mp.ourhook, sizeof(mp.ourhook), "%s", NG_NETFLOW_HOOK_EXPORT);
      if (gNetflowExport.ss_family==AF_INET6) {
	snprintf(mp.peerhook, sizeof(mp.peerhook), "%d/%d/%d", PF_INET6, SOCK_DGRAM, IPPROTO_UDP);
      } else {
        snprintf(mp.peerhook, sizeof(mp.peerhook), "inet/dgram/udp");
      }
      snprintf(path, sizeof(path), "%s:", nm.name);
      if (NgSendMsg(b->csock, path,
	  NGM_GENERIC_COOKIE, NGM_MKPEER, &mp, sizeof(mp)) < 0) {
	Log(LG_ERR, ("can't create %s node: %s", NG_KSOCKET_NODE_TYPE,
	  strerror(errno)));
	goto fail;
      }

      /* Configure timeouts for ng_netflow(4). */
      if (gNetflowInactive != 0 && gNetflowActive != 0) {
	struct ng_netflow_settimeouts nf_settime;

	nf_settime.inactive_timeout = gNetflowInactive;
	nf_settime.active_timeout = gNetflowActive;

	if (NgSendMsg(bund->csock, path, NGM_NETFLOW_COOKIE,
	    NGM_NETFLOW_SETTIMEOUTS, &nf_settime, sizeof(nf_settime)) < 0) {
	  Log(LG_ERR, ("[%s] can't set timeouts on netflow %s node: %s",
	    b->name, NG_NETFLOW_NODE_TYPE, strerror(errno)));
	  goto fail;
	}
      }

      /* Configure export destination and source on ng_ksocket(4). */
      snprintf(path, sizeof(path), "%s:%s", gNetflowNodeName,
	    NG_NETFLOW_HOOK_EXPORT);
      if (gNetflowSource.ss_len != 0) {
	if (NgSendMsg(bund->csock, path, NGM_KSOCKET_COOKIE,
	    NGM_KSOCKET_BIND, &gNetflowSource, sizeof(gNetflowSource)) < 0) {
	  Log(LG_ERR, ("[%s] can't bind export %s node: %s",
	    b->name, NG_KSOCKET_NODE_TYPE, strerror(errno)));
	  goto fail;
	}
      }
      if (gNetflowExport.ss_len != 0) {
	if (NgSendMsg(bund->csock, path, NGM_KSOCKET_COOKIE,
	    NGM_KSOCKET_CONNECT, &gNetflowExport, sizeof(gNetflowExport)) < 0) {
	  Log(LG_ERR, ("[%s] can't connect export %s node: %s",
	    b->name, NG_KSOCKET_NODE_TYPE, strerror(errno)));
	  goto fail;
	}
      }

      /* Set the new node's name. */
      snprintf(nm.name, sizeof(nm.name), "mpd%d-nfso", gPid);
      if (NgSendMsg(b->csock, path,
          NGM_GENERIC_COOKIE, NGM_NAME, &nm, sizeof(nm)) < 0) {
	Log(LG_ERR, ("can't name %s node: %s", NG_KSOCKET_NODE_TYPE,
          strerror(errno)));
	goto fail;
      }

      /* Disconnect temporary hook. */
      snprintf(rm.ourhook, sizeof(rm.ourhook), "%s", TEMPHOOK);
      if (NgSendMsg(b->csock, ".",
	  NGM_GENERIC_COOKIE, NGM_RMHOOK, &rm, sizeof(rm)) < 0) {
	Log(LG_ERR, ("can't remove hook %s: %s", TEMPHOOK, strerror(errno)));
	goto fail;
      }
      gNetflowNode = TRUE;

      return 0;
fail:
    return -1;
}

static int
NgFuncInitNetflowHook(Bund b, int iface)
{
    char path[NG_PATHLEN + 1];
    struct ng_netflow_setdlt	 nf_setdlt;
    struct ng_netflow_setifindex nf_setidx;
    
    /* Configure data link type and interface index. */
    snprintf(path, sizeof(path), "%s:", gNetflowNodeName);
    nf_setdlt.iface = iface;
    nf_setdlt.dlt = DLT_RAW;
    if (NgSendMsg(b->csock, path, NGM_NETFLOW_COOKIE, NGM_NETFLOW_SETDLT,
	&nf_setdlt, sizeof(nf_setdlt)) < 0) {
      Log(LG_ERR, ("[%s] can't configure data link type on %s: %s", b->name,
	path, strerror(errno)));
      goto fail;
    }
    if (b->netflow == NETFLOW_IN) {
	nf_setidx.iface = gNetflowIface;
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
#endif

static int
NgFuncInitVJ(Bund b)
{
  char path[NG_PATHLEN + 1];
  struct ngm_mkpeer	mp;
  struct ngm_connect	cn;
  struct ngm_name	nm;

  /* Add a VJ compression node */
  snprintf(mp.type, sizeof(mp.type), "%s", NG_VJC_NODE_TYPE);
  snprintf(mp.ourhook, sizeof(mp.ourhook), "%s", NG_PPP_HOOK_VJC_IP);
  snprintf(mp.peerhook, sizeof(mp.peerhook), "%s", NG_VJC_HOOK_IP);
  if (NgSendMsg(b->csock, MPD_HOOK_PPP,
      NGM_GENERIC_COOKIE, NGM_MKPEER, &mp, sizeof(mp)) < 0) {
    Log(LG_ERR, ("[%s] can't create %s node: %s",
      b->name, NG_VJC_NODE_TYPE, strerror(errno)));
    goto fail;
  }

  /* Give it a name */
  snprintf(path, sizeof(path), "%s.%s", MPD_HOOK_PPP, NG_PPP_HOOK_VJC_IP);
  snprintf(nm.name, sizeof(nm.name), "mpd%d-%s-vjc", gPid, b->name);
  if (NgSendMsg(b->csock, path,
      NGM_GENERIC_COOKIE, NGM_NAME, &nm, sizeof(nm)) < 0) {
    Log(LG_ERR, ("[%s] can't name %s node: %s",
      b->name, NG_VJC_NODE_TYPE, strerror(errno)));
    goto fail;
  }

  /* Connect the other three hooks between the ppp and vjc nodes */
  snprintf(cn.path, sizeof(cn.path), "%s", NG_PPP_HOOK_VJC_IP);
  snprintf(cn.ourhook, sizeof(cn.ourhook), "%s", NG_PPP_HOOK_VJC_COMP);
  snprintf(cn.peerhook, sizeof(cn.peerhook), "%s", NG_VJC_HOOK_VJCOMP);
  if (NgSendMsg(b->csock, MPD_HOOK_PPP,
      NGM_GENERIC_COOKIE, NGM_CONNECT, &cn, sizeof(cn)) < 0) {
    Log(LG_ERR, ("[%s] can't connect %s and %s: %s",
      b->name, NG_PPP_HOOK_VJC_COMP, NG_VJC_HOOK_VJCOMP, strerror(errno)));
    goto fail;
  }
  snprintf(cn.ourhook, sizeof(cn.ourhook), "%s", NG_PPP_HOOK_VJC_UNCOMP);
  snprintf(cn.peerhook, sizeof(cn.peerhook), "%s", NG_VJC_HOOK_VJUNCOMP);
  if (NgSendMsg(b->csock, MPD_HOOK_PPP,
      NGM_GENERIC_COOKIE, NGM_CONNECT, &cn, sizeof(cn)) < 0) {
    Log(LG_ERR, ("[%s] can't connect %s and %s: %s", b->name,
      NG_PPP_HOOK_VJC_UNCOMP, NG_VJC_HOOK_VJUNCOMP, strerror(errno)));
    goto fail;
  }
  snprintf(cn.ourhook, sizeof(cn.ourhook), "%s", NG_PPP_HOOK_VJC_VJIP);
  snprintf(cn.peerhook, sizeof(cn.peerhook), "%s", NG_VJC_HOOK_VJIP);
  if (NgSendMsg(b->csock, MPD_HOOK_PPP,
      NGM_GENERIC_COOKIE, NGM_CONNECT, &cn, sizeof(cn)) < 0) {
    Log(LG_ERR, ("[%s] can't connect %s and %s: %s",
      b->name, NG_PPP_HOOK_VJC_VJIP, NG_VJC_HOOK_VJIP, strerror(errno)));
    goto fail;
  }

    return 0;
fail:
    return -1;
}

static int
NgFuncInitMSS(Bund b)
{
  char path[NG_PATHLEN + 1];
  struct ngm_connect	cn;

  /* Create global ng_tcpmss(4) node if not yet. */
  if (gTcpMSSNode == FALSE) {
    struct ngm_mkpeer	mp;
    struct ngm_name	nm;

    /* Create a global tcpmss node. */
    snprintf(mp.type, sizeof(mp.type), "%s", NG_TCPMSS_NODE_TYPE);
    snprintf(mp.ourhook, sizeof(mp.ourhook), "%s", TEMPHOOK);
    snprintf(mp.peerhook, sizeof(mp.peerhook), "%s", TEMPHOOK);
    if (NgSendMsg(b->csock, ".",
        NGM_GENERIC_COOKIE, NGM_MKPEER, &mp, sizeof(mp)) < 0) {
      Log(LG_ERR, ("can't create %s node: %s", NG_TCPMSS_NODE_TYPE,
        strerror(errno)));
      goto fail;
    }

    /* Set the new node's name. */
    snprintf(nm.name, sizeof(nm.name), "mpd%d-mss", gPid);
    if (NgSendMsg(b->csock, TEMPHOOK,
        NGM_GENERIC_COOKIE, NGM_NAME, &nm, sizeof(nm)) < 0) {
      Log(LG_ERR, ("can't name %s node: %s", NG_TCPMSS_NODE_TYPE,
        strerror(errno)));
      goto fail;
    }
    Log(LG_ALWAYS, ("%s node is \"%s\"", NG_TCPMSS_NODE_TYPE, nm.name));
  }
  /* Connect ng_bpf(4) node to the ng_tcpmss(4) node. */
  snprintf(path, sizeof(path), "%s.%s", MPD_HOOK_PPP, NG_PPP_HOOK_INET);
  snprintf(cn.path, sizeof(cn.path), "mpd%d-mss:", gPid);
  snprintf(cn.ourhook, sizeof(cn.ourhook), "%s", BPF_HOOK_TCPMSS_IN);
  snprintf(cn.peerhook, sizeof(cn.peerhook), "%s-in", b->name);
  if (NgSendMsg(b->csock, path, NGM_GENERIC_COOKIE, NGM_CONNECT, &cn,
      sizeof(cn)) < 0) {
    Log(LG_ERR, ("[%s] can't connect %s and %s-in: %s", b->name,
      BPF_HOOK_TCPMSS_IN, b->name, strerror(errno)));
    goto fail;
  }
  snprintf(cn.ourhook, sizeof(cn.ourhook), "%s", BPF_HOOK_TCPMSS_OUT);
  snprintf(cn.peerhook, sizeof(cn.peerhook), "%s-out", b->name);
  if (NgSendMsg(b->csock, path, NGM_GENERIC_COOKIE, NGM_CONNECT, &cn,
      sizeof(cn)) < 0) {
    Log(LG_ERR, ("[%s] can't connect %s and %s-out: %s", b->name,
      BPF_HOOK_TCPMSS_OUT, b->name, strerror(errno)));
    goto fail;
  }
  if (gTcpMSSNode == FALSE) {
    struct ngm_rmhook	rm;

    /* Disconnect temporary hook */
    snprintf(rm.ourhook, sizeof(rm.ourhook), "%s", TEMPHOOK);
    if (NgSendMsg(b->csock, ".",
        NGM_GENERIC_COOKIE, NGM_RMHOOK, &rm, sizeof(rm)) < 0) {
      Log(LG_ERR, ("can't remove hook %s: %s", TEMPHOOK, strerror(errno)));
      goto fail;
    }
    gTcpMSSNode = TRUE;
  }

    return 0;
fail:
    return -1;
}

/*
 * NgFuncIfaceExists()
 *
 * Test if a netgraph interface exists. Returns:
 *
 *	0	Netgraph interface does not exist
 *	1	Netgraph interface exists
 *     -1	Interface is not a netgraph interface
 */

static int
NgFuncIfaceExists(Bund b, const char *ifname, char *buf, int max)
{
  union {
      u_char		buf[sizeof(struct ng_mesg) + sizeof(struct nodeinfo)];
      struct ng_mesg	reply;
  }			u;
  char		path[NG_PATHLEN + 1];
  char		*eptr;
  int		ifnum;

  /* Check interface name */
  if (strncmp(ifname, NG_IFACE_IFACE_NAME, strlen(NG_IFACE_IFACE_NAME)) != 0)
    return(-1);
  ifnum = (int)strtoul(ifname + strlen(NG_IFACE_IFACE_NAME), &eptr, 10);
  if (ifnum < 0 || *eptr != '\0')
    return(-1);

  /* See if interface exists */
  snprintf(path, sizeof(path), "%s%d:", NG_IFACE_IFACE_NAME, ifnum);
  if (NgSendMsg(b->csock, path, NGM_GENERIC_COOKIE, NGM_NODEINFO, NULL, 0) < 0)
    return(0);
  if (NgRecvMsg(b->csock, &u.reply, sizeof(u), NULL) < 0) {
    Log(LG_ERR, ("[%s] node \"%s\" reply: %s", b->name, path, strerror(errno)));
    return(-1);
  }

  /* It exists */
  if (buf != NULL)
    snprintf(buf, max, "%s%d", NG_IFACE_IFACE_NAME, ifnum);
  return(1);
}

/*
 * NgFuncCreateIface()
 *
 * Create a new netgraph interface, optionally with a specific name.
 * If "ifname" is not NULL, then create interfaces until "ifname" is
 * created.  Interfaces are consecutively numbered when created, so
 * we have no other choice but to create all lower numbered interfaces
 * in order to create one with a given index.
 */

static int
NgFuncCreateIface(Bund b, const char *ifname, char *buf, int max)
{
  union {
      u_char		buf[sizeof(struct ng_mesg) + sizeof(struct nodeinfo)];
      struct ng_mesg	reply;
  }			u;
  struct nodeinfo	*const ni = (struct nodeinfo *)(void *)u.reply.data;
  struct ngm_rmhook	rm;
  struct ngm_mkpeer	mp;
  int			rtn = 0;

  /* If ifname is not null, create interfaces until it gets created */
  if (ifname != NULL) {
    int count;

    for (count = 0; count < MAX_IFACE_CREATE; count++) {
      switch (NgFuncIfaceExists(b, ifname, buf, max)) {
      case 1:				/* ok now it exists */
	return(0);
      case 0:				/* nope, create another one */
	NgFuncCreateIface(b, NULL, NULL, 0);
	break;
      case -1:				/* something weird happened */
	return(-1);
      default:
	assert(0);
      }
    }
    Log(LG_ERR, ("[%s] created %d interfaces, that's too many!",
      b->name, count));
    return(-1);
  }

  /* Create iface node (as a temporary peer of the socket node) */
  snprintf(mp.type, sizeof(mp.type), "%s", NG_IFACE_NODE_TYPE);
  snprintf(mp.ourhook, sizeof(mp.ourhook), "%s", TEMPHOOK);
  snprintf(mp.peerhook, sizeof(mp.peerhook), "%s", NG_IFACE_HOOK_INET);
  if (NgSendMsg(b->csock, ".",
      NGM_GENERIC_COOKIE, NGM_MKPEER, &mp, sizeof(mp)) < 0) {
    Log(LG_ERR, ("[%s] can't create %s node: %s",
      b->name, NG_IFACE_NODE_TYPE, strerror(errno)));
    return(-1);
  }

  /* Get the new node's name */
  if (NgSendMsg(b->csock, TEMPHOOK,
      NGM_GENERIC_COOKIE, NGM_NODEINFO, NULL, 0) < 0) {
    Log(LG_ERR, ("[%s] %s: %s", b->name, "NGM_NODEINFO", strerror(errno)));
    rtn = -1;
    goto done;
  }
  if (NgRecvMsg(b->csock, &u.reply, sizeof(u), NULL) < 0) {
    Log(LG_ERR, ("[%s] reply from %s: %s",
      b->name, NG_IFACE_NODE_TYPE, strerror(errno)));
    rtn = -1;
    goto done;
  }
  snprintf(buf, max, "%s", ni->name);

done:
  /* Disconnect temporary hook */
  snprintf(rm.ourhook, sizeof(rm.ourhook), "%s", TEMPHOOK);
  if (NgSendMsg(b->csock, ".",
      NGM_GENERIC_COOKIE, NGM_RMHOOK, &rm, sizeof(rm)) < 0) {
    Log(LG_ERR, ("[%s] can't remove hook %s: %s",
      b->name, TEMPHOOK, strerror(errno)));
    rtn = -1;
  }

  /* Done */
  return(rtn);
}

/*
 * NgFuncConfigBPF()
 *
 * Configure the BPF node for one of three modes: either total pass through,
 * total blockage, or else block all traffic and redirect outgoing demand
 * to mpd's socket node or ng_tcpmss(4) node.
 */

void
NgFuncConfigBPF(Bund b, int mode)
{
  union {
      u_char			buf[NG_BPF_HOOKPROG_SIZE(DEMAND_PROG_LEN)];
      struct ng_bpf_hookprog	hprog;
  }				u;
  struct ng_bpf_hookprog	*const hp = &u.hprog;
  char				path[NG_PATHLEN + 1];

  /* Get absolute path to bpf node */
  snprintf(path, sizeof(path), "mpd%d-%s:%s", gPid, b->name,
      NG_PPP_HOOK_INET);

  /* First, configure the hook on the interface node side of the BPF node */
  memset(&u, 0, sizeof(u));
  snprintf(hp->thisHook, sizeof(hp->thisHook), "%s", BPF_HOOK_IFACE);
  switch (mode) {
    case BPF_MODE_OFF:
      hp->bpf_prog_len = NOMATCH_PROG_LEN;
      memcpy(&hp->bpf_prog, &gNoMatchProg,
        NOMATCH_PROG_LEN * sizeof(*gNoMatchProg));
      memset(&hp->ifMatch, 0, sizeof(hp->ifMatch));
      memset(&hp->ifNotMatch, 0, sizeof(hp->ifNotMatch));
      break;
    case BPF_MODE_ON:
      hp->bpf_prog_len = NOMATCH_PROG_LEN;
      memcpy(&hp->bpf_prog, &gNoMatchProg,
        NOMATCH_PROG_LEN * sizeof(*gNoMatchProg));
      snprintf(hp->ifMatch, sizeof(hp->ifMatch), "%s", BPF_HOOK_PPP);
      snprintf(hp->ifNotMatch, sizeof(hp->ifNotMatch), "%s", BPF_HOOK_PPP);
      break;
    case BPF_MODE_MSSFIX:
      hp->bpf_prog_len = TCPSYN_PROG_LEN;
      memcpy(&hp->bpf_prog, &gTCPSYNProg,
        TCPSYN_PROG_LEN * sizeof(*gTCPSYNProg));
#ifdef USE_NG_TCPMSS
      snprintf(hp->ifMatch, sizeof(hp->ifMatch), "%s", BPF_HOOK_TCPMSS_OUT);
#else
      snprintf(hp->ifMatch, sizeof(hp->ifMatch), "%s", BPF_HOOK_MPD_OUT);
#endif
      snprintf(hp->ifNotMatch, sizeof(hp->ifNotMatch), "%s", BPF_HOOK_PPP);
      break;
    case BPF_MODE_DEMAND:
      hp->bpf_prog_len = DEMAND_PROG_LEN;
      memcpy(&hp->bpf_prog, &gDemandProg,
        DEMAND_PROG_LEN * sizeof(*gDemandProg));
      snprintf(hp->ifMatch, sizeof(hp->ifMatch), "%s", BPF_HOOK_MPD);
      memset(&hp->ifNotMatch, 0, sizeof(hp->ifNotMatch));
      break;
    default:
      assert(0);
  }

  /* Set new program on the BPF_HOOK_IFACE hook */
  if (NgSendMsg(b->csock, path, NGM_BPF_COOKIE,
      NGM_BPF_SET_PROGRAM, hp, NG_BPF_HOOKPROG_SIZE(hp->bpf_prog_len)) < 0) {
    Log(LG_ERR, ("[%s] can't set %s node program: %s",
      b->name, NG_BPF_NODE_TYPE, strerror(errno)));
    DoExit(EX_ERRDEAD);
  }

  /* Now, configure the hook on the PPP node side of the BPF node */
  memset(&u, 0, sizeof(u));
  snprintf(hp->thisHook, sizeof(hp->thisHook), "%s", BPF_HOOK_PPP);
  hp->bpf_prog_len = TCPSYN_PROG_LEN;
  memcpy(&hp->bpf_prog,
    &gTCPSYNProg, TCPSYN_PROG_LEN * sizeof(*gTCPSYNProg));
  switch (mode) {
    case BPF_MODE_OFF:
    case BPF_MODE_DEMAND:
      memset(&hp->ifMatch, 0, sizeof(hp->ifMatch));
      memset(&hp->ifNotMatch, 0, sizeof(hp->ifNotMatch));
      break;
    case BPF_MODE_ON:
      snprintf(hp->ifMatch, sizeof(hp->ifMatch), "%s", BPF_HOOK_IFACE);
      snprintf(hp->ifNotMatch, sizeof(hp->ifNotMatch), "%s", BPF_HOOK_IFACE);
      break;
    case BPF_MODE_MSSFIX:
#ifdef USE_NG_TCPMSS
      snprintf(hp->ifMatch, sizeof(hp->ifMatch), "%s", BPF_HOOK_TCPMSS_IN);
#else
      snprintf(hp->ifMatch, sizeof(hp->ifMatch), "%s", BPF_HOOK_MPD);
#endif
      snprintf(hp->ifNotMatch, sizeof(hp->ifNotMatch), "%s", BPF_HOOK_IFACE);
      break;
    default:
      assert(0);
  }

  /* Set new program on the BPF_HOOK_PPP hook */
  if (NgSendMsg(b->csock, path, NGM_BPF_COOKIE,
      NGM_BPF_SET_PROGRAM, hp, NG_BPF_HOOKPROG_SIZE(hp->bpf_prog_len)) < 0) {
    Log(LG_ERR, ("[%s] can't set %s node program: %s",
      b->name, NG_BPF_NODE_TYPE, strerror(errno)));
    DoExit(EX_ERRDEAD);
  }

  /* Configure the hook on the MPD demand/tap node side of the BPF node */
  memset(&u, 0, sizeof(u));
  snprintf(hp->thisHook, sizeof(hp->thisHook), "%s", BPF_HOOK_MPD);
  hp->bpf_prog_len = NOMATCH_PROG_LEN;
  memcpy(&hp->bpf_prog,
    &gNoMatchProg, NOMATCH_PROG_LEN * sizeof(*gNoMatchProg));
  switch (mode) {
    case BPF_MODE_OFF:
    case BPF_MODE_DEMAND:
      memset(&hp->ifMatch, 0, sizeof(hp->ifMatch));
      memset(&hp->ifNotMatch, 0, sizeof(hp->ifNotMatch));
      break;
    case BPF_MODE_ON:
    case BPF_MODE_MSSFIX:
      snprintf(hp->ifMatch, sizeof(hp->ifMatch), "%s", BPF_HOOK_IFACE);
      snprintf(hp->ifNotMatch, sizeof(hp->ifNotMatch), "%s", BPF_HOOK_IFACE);
      break;
    default:
      assert(0);
  }

  /* Set new program on the BPF_HOOK_MPD hook */
  if (NgSendMsg(b->csock, path, NGM_BPF_COOKIE,
      NGM_BPF_SET_PROGRAM, hp, NG_BPF_HOOKPROG_SIZE(hp->bpf_prog_len)) < 0) {
    Log(LG_ERR, ("[%s] can't set %s node program: %s",
      b->name, NG_BPF_NODE_TYPE, strerror(errno)));
    DoExit(EX_ERRDEAD);
  }

#ifdef USE_NG_TCPMSS
  /* Configure hooks between global TCPMSS node and the BPF node. */
  memset(&u, 0, sizeof(u));
  snprintf(hp->thisHook, sizeof(hp->thisHook), "%s", BPF_HOOK_TCPMSS_IN);
  hp->bpf_prog_len = NOMATCH_PROG_LEN;
  memcpy(&hp->bpf_prog,
    &gNoMatchProg, NOMATCH_PROG_LEN * sizeof(*gNoMatchProg));
  switch (mode) {
    case BPF_MODE_OFF:
    case BPF_MODE_DEMAND:
    case BPF_MODE_ON:
      memset(&hp->ifMatch, 0, sizeof(hp->ifMatch));
      memset(&hp->ifNotMatch, 0, sizeof(hp->ifNotMatch));
      break;
    case BPF_MODE_MSSFIX:
      snprintf(hp->ifMatch, sizeof(hp->ifMatch), "%s", BPF_HOOK_IFACE);
      snprintf(hp->ifNotMatch, sizeof(hp->ifNotMatch), "%s", BPF_HOOK_IFACE);
      break;
    default:
      assert(0);
  }
  /* Set new program on the BPF_HOOK_TCPMSS hook. */
  if (NgSendMsg(b->csock, path, NGM_BPF_COOKIE,
      NGM_BPF_SET_PROGRAM, hp, NG_BPF_HOOKPROG_SIZE(hp->bpf_prog_len)) < 0) {
    Log(LG_ERR, ("[%s] can't set %s node program: %s",
      b->name, NG_BPF_NODE_TYPE, strerror(errno)));
    DoExit(EX_ERRDEAD);
  }
  memset(&u, 0, sizeof(u));
  snprintf(hp->thisHook, sizeof(hp->thisHook), "%s", BPF_HOOK_TCPMSS_OUT);
  hp->bpf_prog_len = NOMATCH_PROG_LEN;
  memcpy(&hp->bpf_prog,
    &gNoMatchProg, NOMATCH_PROG_LEN * sizeof(*gNoMatchProg));
  switch (mode) {
    case BPF_MODE_OFF:
    case BPF_MODE_DEMAND:
    case BPF_MODE_ON:
      memset(&hp->ifMatch, 0, sizeof(hp->ifMatch));
      memset(&hp->ifNotMatch, 0, sizeof(hp->ifNotMatch));
      break;
    case BPF_MODE_MSSFIX:
      snprintf(hp->ifMatch, sizeof(hp->ifMatch), "%s", BPF_HOOK_PPP);
      snprintf(hp->ifNotMatch, sizeof(hp->ifNotMatch), "%s", BPF_HOOK_PPP);
      break;
    default:
      assert(0);
  }
  /* Set new program on the BPF_HOOK_TCPMSS hook. */
  if (NgSendMsg(b->csock, path, NGM_BPF_COOKIE,
      NGM_BPF_SET_PROGRAM, hp, NG_BPF_HOOKPROG_SIZE(hp->bpf_prog_len)) < 0) {
    Log(LG_ERR, ("[%s] can't set %s node program: %s",
      b->name, NG_BPF_NODE_TYPE, strerror(errno)));
    DoExit(EX_ERRDEAD);
  }
#else
  /* Configure the hook on the MPD mssfix-out node side of the BPF node */
  memset(&u, 0, sizeof(u));
  snprintf(hp->thisHook, sizeof(hp->thisHook), "%s", BPF_HOOK_MPD_OUT);
  hp->bpf_prog_len = NOMATCH_PROG_LEN;
  memcpy(&hp->bpf_prog,
    &gNoMatchProg, NOMATCH_PROG_LEN * sizeof(*gNoMatchProg));
  switch (mode) {
    case BPF_MODE_OFF:
    case BPF_MODE_DEMAND:
      memset(&hp->ifMatch, 0, sizeof(hp->ifMatch));
      memset(&hp->ifNotMatch, 0, sizeof(hp->ifNotMatch));
      break;
    case BPF_MODE_ON:
    case BPF_MODE_MSSFIX:
      snprintf(hp->ifMatch, sizeof(hp->ifMatch), "%s", BPF_HOOK_PPP);
      snprintf(hp->ifNotMatch, sizeof(hp->ifNotMatch), "%s", BPF_HOOK_PPP);
      break;
    default:
      assert(0);
  }

  /* Set new program on the BPF_HOOK_MPD hook */
  if (NgSendMsg(b->csock, path, NGM_BPF_COOKIE,
      NGM_BPF_SET_PROGRAM, hp, NG_BPF_HOOKPROG_SIZE(hp->bpf_prog_len)) < 0) {
    Log(LG_ERR, ("[%s] can't set %s node program: %s",
      b->name, NG_BPF_NODE_TYPE, strerror(errno)));
    DoExit(EX_ERRDEAD);
  }
#endif
}

/*
 * NgFuncShutdownGlobal()
 *
 * Shutdown nodes, that are shared between bundles.
 *
 */

void
NgFuncShutdownGlobal(Bund b)
{
#ifdef USE_NG_NETFLOW
  char	path[NG_PATHLEN + 1];

  if (gNetflowNode == FALSE || gNetflowNodeShutdown==FALSE)
    return;

  snprintf(path, sizeof(path), "%s:", gNetflowNodeName);
  NgFuncShutdownNode(b, "netflow", path);
#endif
}

/*
 * NgFuncShutdown()
 *
 * Shutdown the netgraph stuff associated with the current bundle
 */

void
NgFuncShutdown(Bund b)
{
  NgFuncShutdownInternal(b, 1, 1);
}

/*
 * NgFuncShutdownInternal()
 */

static void
NgFuncShutdownInternal(Bund b, int iface, int ppp)
{
  char	path[NG_PATHLEN + 1];
  Bund	bund_save;
  Link	lnk_save;
  int	k;

  if (iface) {
    snprintf(path, sizeof(path), "%s:", b->iface.ifname);
    NgFuncShutdownNode(b, b->name, path);
  }
  lnk_save = lnk;
  bund_save = bund;
  for (k = 0; k < b->n_links; k++) {
    lnk = b->links[k];
    bund = lnk->bund;
    if (lnk && lnk->phys && lnk->phys->type && lnk->phys->type->shutdown)
      (*lnk->phys->type->shutdown)(lnk->phys);
  }
  bund = bund_save;
  lnk = lnk_save;
  if (ppp) {
    if (b->tee) {
	snprintf(path, sizeof(path), "mpd%d-%s-tee:", gPid, b->name);
	NgFuncShutdownNode(b, b->name, path);
    }
    if (b->nat) {
	snprintf(path, sizeof(path), "mpd%d-%s-nat:", gPid, b->name);
	NgFuncShutdownNode(b, b->name, path);
    }
    snprintf(path, sizeof(path), "%s.%s", MPD_HOOK_PPP, NG_PPP_HOOK_INET);
    NgFuncShutdownNode(b, b->name, path);
    NgFuncShutdownNode(b, b->name, MPD_HOOK_PPP);
  }
  close(b->csock);
  b->csock = -1;
  EventUnRegister(&b->ctrlEvent);
  close(b->dsock);
  b->dsock = -1;
  EventUnRegister(&b->dataEvent);
}

/*
 * NgFuncShutdownNode()
 */

int
NgFuncShutdownNode(Bund b, const char *label, const char *path)
{
  int rtn;

  if ((rtn = NgSendMsg(b->csock, path,
      NGM_GENERIC_COOKIE, NGM_SHUTDOWN, NULL, 0)) < 0) {
    if (errno != ENOENT) {
      Log(LG_ERR, ("[%s] can't shutdown \"%s\": %s",
	label, path, strerror(errno)));
    }
  }
  return(rtn);
}

/*
 * NgFuncSetConfig()
 */

void
NgFuncSetConfig(void)
{
  if (NgSendMsg(bund->csock, MPD_HOOK_PPP, NGM_PPP_COOKIE,
      NGM_PPP_SET_CONFIG, &bund->pppConfig, sizeof(bund->pppConfig)) < 0) {
    Log(LG_ERR, ("[%s] can't config %s: %s",
      bund->name, MPD_HOOK_PPP, strerror(errno)));
    DoExit(EX_ERRDEAD);
  }
}

/*
 * NgFuncDataEvent()
 */

static void
NgFuncDataEvent(int type, void *cookie)
{
  u_char		buf[8192];
  u_char		bufout[8192];
  struct sockaddr_ng	naddr;
  int			nread, nsize = sizeof(naddr);
  int			newlen;

  /* Set bundle */
  bund = (Bund) cookie;
  lnk = bund->links[0];

  /* Read data */
  if ((nread = recvfrom(bund->dsock, buf, sizeof(buf),
      0, (struct sockaddr *)&naddr, &nsize)) < 0) {
    if (errno == EAGAIN)
      return;
    Log(LG_BUND, ("[%s] socket read: %s", bund->name, strerror(errno)));
    DoExit(EX_ERRDEAD);
  }

  /* A PPP frame from the bypass hook? */
  if (strcmp(naddr.sg_data, MPD_HOOK_PPP) == 0) {
    u_int16_t	linkNum, proto;

    /* Extract link number and protocol */
    memcpy(&linkNum, buf, 2);
    linkNum = ntohs(linkNum);
    memcpy(&proto, buf + 2, 2);
    proto = ntohs(proto);

    /* Debugging */
    LogDumpBuf(LG_FRAME, buf, nread,
      "[%s] rec'd bypass frame link=%d proto=0x%04x",
      bund->name, (int16_t)linkNum, proto);

    /* Set link */
    assert(linkNum == NG_PPP_BUNDLE_LINKNUM || linkNum < bund->n_links);
    lnk = (linkNum < bund->n_links) ? bund->links[linkNum] : NULL;

    /* Input frame */
    InputFrame(linkNum, proto,
      mbwrite(mballoc(MB_FRAME_IN, nread - 4), buf + 4, nread - 4));
    return;
  }

  /* A snooped, outgoing IP frame? */
  if (strcmp(naddr.sg_data, MPD_HOOK_DEMAND_TAP) == 0) {

    /* Debugging */
    LogDumpBuf(LG_FRAME, buf, nread,
      "[%s] rec'd IP frame on demand/mssfix-in hook", bund->name);
    IfaceListenInput(PROTO_IP,
      mbwrite(mballoc(MB_FRAME_IN, nread), buf, nread));
    return;
  }
#ifndef USE_NG_TCPMSS
  /* A snooped, outgoing TCP SYN frame? */
  if (strcmp(naddr.sg_data, MPD_HOOK_MSSFIX_OUT) == 0) {
    /* Debugging */
    LogDumpBuf(LG_FRAME, buf, nread,
      "[%s] rec'd IP frame on mssfix-out hook", bund->name);
    IfaceListenOutput(PROTO_IP,
      mbwrite(mballoc(MB_FRAME_IN, nread), buf, nread));
    return;
  }
#endif

  /* Packet requiring compression */
  if (strcmp(naddr.sg_data, NG_PPP_HOOK_COMPRESS) == 0) {

    /* Debugging */
    LogDumpBuf(LG_FRAME, buf, nread,
      "[%s] rec'd frame on %s hook", bund->name, NG_PPP_HOOK_COMPRESS);

    if (bund->ccp.xmit && bund->ccp.xmit->Compress)
	bund->ccp.xmit->Compress(buf, nread, bufout, &newlen);
    else {
	Log(LG_BUND, ("[%s] Compressor routine not defined", bund->name));
	return;
    }

    if (newlen){
	/* Write data */
	if ((nread = sendto(bund->dsock, bufout, newlen,
	        0, (struct sockaddr *)&naddr, naddr.sg_len)) < 0) {
	    if (errno == EAGAIN)
    		return;
	    Log(LG_BUND, ("[%s] %s socket write: %s", bund->name, NG_PPP_HOOK_COMPRESS, strerror(errno)));
	}
    }
    return;
  }

  /* Packet requiring decompression */
  if (strcmp(naddr.sg_data, NG_PPP_HOOK_DECOMPRESS) == 0) {
    /* Debugging */
    LogDumpBuf(LG_FRAME, buf, nread,
      "[%s] rec'd frame on %s hook", bund->name, NG_PPP_HOOK_DECOMPRESS);

    if (bund->ccp.xmit && bund->ccp.xmit->Decompress)
	bund->ccp.xmit->Decompress(buf, nread, bufout, &newlen);
    else {
	Log(LG_BUND, ("[%s] Decompressor routine not defined", bund->name));
	return;
    }

    if (newlen){
	/* Write data */
	if ((nread = sendto(bund->dsock, bufout, newlen,
		0, (struct sockaddr *)&naddr, naddr.sg_len)) < 0) {
	    if (errno == EAGAIN)
    		return;
	    Log(LG_BUND, ("[%s] %s socket write: %s", bund->name, NG_PPP_HOOK_DECOMPRESS, strerror(errno)));
	}
    }
    return;
  }

  /* Packet requiring encryption */
  if (strcmp(naddr.sg_data, NG_PPP_HOOK_ENCRYPT) == 0) {

    /* Debugging */
    LogDumpBuf(LG_FRAME, buf, nread,
      "[%s] rec'd frame on %s hook", bund->name, NG_PPP_HOOK_ENCRYPT);

    Mbuf nbp = EcpDataOutput(mbwrite(mballoc(MB_FRAME_IN, nread), buf, nread));
    if (!nbp) {
	Log(LG_BUND, ("[%s] Encryptor error", bund->name));
	return;
    }

    NgFuncWriteFrame(bund->name, NG_PPP_HOOK_ENCRYPT, nbp);
    return;
  }

  /* Packet requiring decryption */
  if (strcmp(naddr.sg_data, NG_PPP_HOOK_DECRYPT) == 0) {
    /* Debugging */
    LogDumpBuf(LG_FRAME, buf, nread,
      "[%s] rec'd frame on %s hook", bund->name, NG_PPP_HOOK_DECRYPT);

    Mbuf nbp = EcpDataInput(mbwrite(mballoc(MB_FRAME_IN, nread), buf, nread));
    if (!nbp) {
	Log(LG_BUND, ("[%s] Decryptor error", bund->name));
	return;
    }

    NgFuncWriteFrame(bund->name, NG_PPP_HOOK_DECRYPT, nbp);
    return;
  }

  /* Unknown hook! */
  LogDumpBuf(LG_FRAME, buf, nread,
    "[%s] rec'd data on unknown hook \"%s\"", bund->name, naddr.sg_data);
  DoExit(EX_ERRDEAD);
}

/*
 * NgFuncCtrlEvent()
 *
 */

static void
NgFuncCtrlEvent(int type, void *cookie)
{
  union {
      u_char		buf[8192];
      struct ng_mesg	msg;
  }			u;
  char			raddr[NG_PATHLEN + 1];
  int			len;

  /* Set bundle */
  bund = (Bund) cookie;
  lnk = bund->links[0];

  /* Read message */
  if ((len = NgRecvMsg(bund->csock, &u.msg, sizeof(u), raddr)) < 0) {
    Log(LG_ERR, ("[%s] can't read unexpected message: %s",
      bund->name, strerror(errno)));
    return;
  }

  /* Examine message */
  switch (u.msg.header.typecookie) {

    case NGM_MPPC_COOKIE:
      CcpRecvMsg(&u.msg, len);
      return;

    case NGM_KSOCKET_COOKIE:		/* XXX ignore NGM_KSOCKET_CONNECT */
      if (u.msg.header.cmd == NGM_KSOCKET_CONNECT)
	return;
      break;
    default:
      break;
  }

  /* Unknown message */
  Log(LG_ERR, ("[%s] rec'd unknown ctrl message, cookie=%d cmd=%d",
    bund->name, u.msg.header.typecookie, u.msg.header.cmd));
}

/*
 * NgFuncSendQuery()
 */

int
NgFuncSendQuery(const char *path, int cookie, int cmd, const void *args,
	size_t arglen, struct ng_mesg *rbuf, size_t replen, char *raddr)
{
  int token, len;
  int ret = 0;

  if (!gNgStatSock) {
    /* Create a netgraph socket node */
    if (NgMkSockNode(NULL, &gNgStatSock, NULL) < 0) {
      Log(LG_ERR, ("can't create %s node: %s",
    	NG_SOCKET_NODE_TYPE, strerror(errno)));
      return(0);
    }
    (void) fcntl(gNgStatSock, F_SETFD, 1);
  }

  /* Send message */
  if ((token = NgSendMsg(gNgStatSock, path, cookie, cmd, args, arglen)) < 0)
    goto fail;

  /* Read message */
  if ((len = NgRecvMsg(gNgStatSock, rbuf, replen, raddr)) < 0) {
    Log(LG_ERR, ("[%s] can't read unexpected message: %s",
      bund->name, strerror(errno)));
    goto fail;
  }

 goto done;

fail:
  ret = -1;
done:
  return ret;

}

/*
 * NgFuncConnect()
 */

int
NgFuncConnect(const char *path, const char *hook,
	const char *path2, const char *hook2)
{
  struct ngm_connect	cn;

  snprintf(cn.path, sizeof(cn.path), "%s", path2);
  snprintf(cn.ourhook, sizeof(cn.ourhook), "%s", hook);
  snprintf(cn.peerhook, sizeof(cn.peerhook), "%s", hook2);
  if (NgSendMsg(bund->csock, path,
      NGM_GENERIC_COOKIE, NGM_CONNECT, &cn, sizeof(cn)) < 0) {
    Log(LG_ERR, ("[%s] can't connect %s,%s and %s,%s: %s",
      bund->name, path, hook, path2, hook2, strerror(errno)));
    return(-1);
  }
  return(0);
}

/*
 * NgFuncDisconnect()
 */

int
NgFuncDisconnect(const char *path, const char *hook)
{
  struct ngm_rmhook	rm;

  /* Disconnect hook */
  snprintf(rm.ourhook, sizeof(rm.ourhook), "%s", hook);
  if (NgSendMsg(bund->csock, path,
      NGM_GENERIC_COOKIE, NGM_RMHOOK, &rm, sizeof(rm)) < 0) {
    Log(LG_ERR, ("[%s] can't remove hook %s from node \"%s\": %s",
      bund->name, hook, path, strerror(errno)));
    return(-1);
  }
  return(0);
}

/*
 * NgFuncWritePppFrame()
 *
 * Consumes the mbuf.
 */

int
NgFuncWritePppFrame(int linkNum, int proto, Mbuf bp)
{
  Mbuf		hdr;
  u_int16_t	temp;

  /* Prepend ppp node bypass header */
  hdr = mballoc(bp->type, 4);
  temp = htons(linkNum);
  memcpy(MBDATA(hdr), &temp, 2);
  temp = htons(proto);
  memcpy(MBDATA(hdr) + 2, &temp, 2);
  hdr->next = bp;
  bp = hdr;

  /* Debugging */
  LogDumpBp(LG_FRAME, bp,
    "[%s] xmit bypass frame link=%d proto=0x%04x",
    bund->name, (int16_t)linkNum, proto);

  /* Write frame */
  return NgFuncWriteFrame(
    linkNum == NG_PPP_BUNDLE_LINKNUM ? bund->name : bund->links[linkNum]->name,
    MPD_HOOK_PPP, bp);
}

/*
 * NgFuncWriteFrame()
 *
 * Consumes the mbuf.
 */

int
NgFuncWriteFrame(const char *label, const char *hookname, Mbuf bp)
{
  u_char		buf[sizeof(struct sockaddr_ng) + NG_HOOKLEN];
  struct sockaddr_ng	*ng = (struct sockaddr_ng *)buf;
  int			rtn;

  /* Set dest address */
  memset(&buf, 0, sizeof(buf));
  snprintf(ng->sg_data, NG_HOOKLEN + 1, "%s", hookname);
  ng->sg_family = AF_NETGRAPH;
  ng->sg_len = 3 + strlen(ng->sg_data);

  /* Write frame */
  bp = mbunify(bp);
  rtn = sendto(bund->dsock, MBDATA(bp), MBLEN(bp),
    0, (struct sockaddr *)ng, ng->sg_len);

  /* ENOBUFS can be expected on some links, e.g., ng_pptpgre(4) */
  if (rtn < 0 && errno != ENOBUFS) {
    Log(LG_ERR, ("[%s] error writing len %d frame to %s: %s",
      label, MBLEN(bp), hookname, strerror(errno)));
  }
  PFREE(bp);
  return rtn;
}

/*
 * NgFuncGetStats()
 *
 * Get (and optionally clear) link or whole bundle statistics
 */

int
NgFuncGetStats(u_int16_t linkNum, int clear, struct ng_ppp_link_stat *statp)
{
  union {
      u_char			buf[sizeof(struct ng_mesg)
				  + sizeof(struct ng_ppp_link_stat)];
      struct ng_mesg		reply;
  }				u;
  int				cmd;
  char                          path[NG_PATHLEN + 1];

  /* Get stats */
  cmd = clear ? NGM_PPP_GETCLR_LINK_STATS : NGM_PPP_GET_LINK_STATS;
  snprintf(path, sizeof(path), "mpd%d-%s:", gPid, bund->name);
  if (NgFuncSendQuery(path, NGM_PPP_COOKIE, cmd,
       &linkNum, sizeof(linkNum), &u.reply, sizeof(u), NULL) < 0) {
    Log(LG_ERR, ("[%s] can't get stats, link=%d: %s",
      bund->name, linkNum, strerror(errno)));
    return -1;
  }
  if (statp != NULL)
    memcpy(statp, u.reply.data, sizeof(*statp));
  return(0);
}

/*
 * NgFuncErrx()
 */

static void
NgFuncErrx(const char *fmt, ...)
{
  char		buf[1024];
  va_list	args;

  va_start(args, fmt);
  vsnprintf(buf, sizeof(buf), fmt, args);
  va_end(args);
  Log(LG_ERR, ("[%s] netgraph: %s", bund ? bund->name : "", buf));
}

/*
 * NgFuncErr()
 */

static void
NgFuncErr(const char *fmt, ...)
{
  char		buf[100];
  va_list	args;

  va_start(args, fmt);
  vsnprintf(buf, sizeof(buf), fmt, args);
  va_end(args);
  Log(LG_ERR, ("[%s] netgraph: %s: %s", bund ? bund->name : "",
    buf, strerror(errno)));
}

#ifdef USE_NG_NETFLOW
/*
 * NetflowSetCommand()
 */
       
static int
NetflowSetCommand(int ac, char *av[], void *arg)
{
  struct sockaddr_storage *sin;

  switch ((int) arg) {
    case SET_EXPORT: 
      if ((sin = ParseAddrPort(ac, av, ALLOW_IPV4|ALLOW_IPV6)) == NULL)
	return (-1);
      gNetflowExport = *sin;
      break;
    case SET_SOURCE:
      if ((sin = ParseAddrPort(ac, av, ALLOW_IPV4|ALLOW_IPV6)) == NULL)
	return (-1);
      gNetflowSource = *sin;
      break;
    case SET_TIMEOUTS:
      if (ac != 2)
	return (-1);
      if (atoi(av[0]) <= 0 || atoi(av[1]) <= 0) {
	Log(LG_ERR, ("Bad netflow timeouts \"%s %s\"", av[0], av[1]));
	return (-1);
      }
      gNetflowInactive = atoi(av[0]);
      gNetflowActive = atoi(av[1]);
      break;
    case SET_NODE:
      if (ac != 1)
	return (-1);
      if (strlen(av[0]) == 0 || strlen(av[0]) > 63) {
	Log(LG_ERR, ("Bad netflow node name \"%s\"", av[0]));
	return (-1);
      }
      strncpy(gNetflowNodeName,av[0],63);
      gNetflowNode=TRUE;
      gNetflowNodeShutdown=FALSE;
      break;
    case SET_HOOK:
      if (ac != 1)
	return (-1);
      if (atoi(av[0]) <= 0) {
	Log(LG_ERR, ("Bad netflow hook number \"%s\"", av[0]));
	return (-1);
      }
      gNetflowIface = atoi(av[0])-1;
      break;

    default:
	return (-1);
  }

  return (0);
}
#endif /* USE_NG_NETFLOW */

#ifdef USE_NG_TCPMSS
/*
 * NgFuncConfigTCPMSS()
 *
 * Configure the tcpmss node to reduce MSS to given value.
 */

void
NgFuncConfigTCPMSS(Bund b, uint16_t maxMSS)
{
  struct	ng_tcpmss_config tcpmsscfg;
  char		path[NG_PATHLEN];

  snprintf(path, sizeof(path), "mpd%d-mss:", gPid);

  /* Send configure message. */
  memset(&tcpmsscfg, 0, sizeof(tcpmsscfg));
  tcpmsscfg.maxMSS = maxMSS;

  snprintf(tcpmsscfg.inHook, sizeof(tcpmsscfg.inHook), "%s-in", b->name);
  snprintf(tcpmsscfg.outHook, sizeof(tcpmsscfg.outHook), "%s-in", b->name);
  if (NgSendMsg(bund->csock, path, NGM_TCPMSS_COOKIE, NGM_TCPMSS_CONFIG,
      &tcpmsscfg, sizeof(tcpmsscfg)) < 0) {
    Log(LG_ERR, ("[%s] can't set %s node program: %s", b->name,
      NG_TCPMSS_NODE_TYPE, strerror(errno)));
    DoExit(EX_ERRDEAD);
  }
  snprintf(tcpmsscfg.inHook, sizeof(tcpmsscfg.inHook), "%s-out", b->name);
  snprintf(tcpmsscfg.outHook, sizeof(tcpmsscfg.outHook), "%s-out", b->name);
  if (NgSendMsg(bund->csock, path, NGM_TCPMSS_COOKIE, NGM_TCPMSS_CONFIG,
      &tcpmsscfg, sizeof(tcpmsscfg)) < 0) {
    Log(LG_ERR, ("[%s] can't set %s node program: %s", b->name,
      NG_TCPMSS_NODE_TYPE, strerror(errno)));
    DoExit(EX_ERRDEAD);
  }
}
#endif /* USE_NG_TCPMSS */
