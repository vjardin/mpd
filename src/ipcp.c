
/*
 * ipcp.c
 *
 * Written by Toshiharu OHNO <tony-o@iij.ad.jp>
 * Copyright (c) 1993, Internet Initiative Japan, Inc. All rights reserved.
 * See ``COPYRIGHT.iij''
 * 
 * Rewritten by Archie Cobbs <archie@freebsd.org>
 * Copyright (c) 1995-1999 Whistle Communications, Inc. All rights reserved.
 * See ``COPYRIGHT.whistle''
 */

#include "ppp.h"
#include "ipcp.h"
#include "fsm.h"
#include "ip.h"
#include "iface.h"
#include "custom.h"
#include "msg.h"
#include "ngfunc.h"

#include <netgraph.h>
#include <sys/mbuf.h>
#include <net/slcompress.h>
#ifdef __DragonFly__
#include <netgraph/vjc/ng_vjc.h>
#else
#include <netgraph/ng_vjc.h>
#endif

/*
 * DEFINITIONS
 */

  #define IPCP_KNOWN_CODES	(   (1 << CODE_CONFIGREQ)	\
				  | (1 << CODE_CONFIGACK)	\
				  | (1 << CODE_CONFIGNAK)	\
				  | (1 << CODE_CONFIGREJ)	\
				  | (1 << CODE_TERMREQ)		\
				  | (1 << CODE_TERMACK)		\
				  | (1 << CODE_CODEREJ)		)

  #define TY_IPADDRS		1
  #define TY_COMPPROTO		2
  #define TY_IPADDR		3
  #define TY_PRIMARYDNS		129
  #define TY_PRIMARYNBNS	130
  #define TY_SECONDARYDNS	131
  #define TY_SECONDARYNBNS	132

  #define IPCP_REJECTED(p,x)	((p)->peer_reject & (1<<(x)))
  #define IPCP_PEER_REJ(p,x)	do{(p)->peer_reject |= (1<<(x));}while(0)

  #define IPCP_VJCOMP_MIN_MAXCHAN	(NG_VJC_MIN_CHANNELS - 1)
  #define IPCP_VJCOMP_MAX_MAXCHAN	(NG_VJC_MAX_CHANNELS - 1)
  #define IPCP_VJCOMP_DEFAULT_MAXCHAN	IPCP_VJCOMP_MAX_MAXCHAN

  /* Set menu options */
  enum {
    SET_RANGES,
    SET_ENABLE,
    SET_DNS,
    SET_NBNS,
    SET_DISABLE,
    SET_ACCEPT,
    SET_DENY,
    SET_YES,
    SET_NO,
  };

/*
 * INTERNAL FUNCTIONS
 */

  static void	IpcpConfigure(Fsm fp);
  static void	IpcpUnConfigure(Fsm fp);

  static u_char	*IpcpBuildConfigReq(Fsm fp, u_char *cp);
  static void	IpcpDecodeConfig(Fsm fp, FsmOption list, int num, int mode);
  static void	IpcpLayerStart(Fsm fp);
  static void	IpcpLayerFinish(Fsm fp);
  static void	IpcpLayerUp(Fsm fp);
  static void	IpcpLayerDown(Fsm fp);
  static void	IpcpFailure(Fsm fp, enum fsmfail reason);

  static int	IpcpSetCommand(int ac, char *av[], void *arg);

/*
 * GLOBAL VARIABLES
 */

  const struct cmdtab IpcpSetCmds[] = {
    { "ranges self/width peer/width",	"Allowed IP address ranges",
	IpcpSetCommand, NULL, (void *) SET_RANGES },
    { "enable [opt ...]",		"Enable option",
	IpcpSetCommand, NULL, (void *) SET_ENABLE},
    { "dns primary [secondary]",	"Set peer DNS servers",
	IpcpSetCommand, NULL, (void *) SET_DNS},
    { "nbns primary [secondary]",	"Set peer NBNS servers",
	IpcpSetCommand, NULL, (void *) SET_NBNS},
    { "disable [opt ...]",		"Disable option",
	IpcpSetCommand, NULL, (void *) SET_DISABLE},
    { "accept [opt ...]",		"Accept option",
	IpcpSetCommand, NULL, (void *) SET_ACCEPT},
    { "deny [opt ...]",			"Deny option",
	IpcpSetCommand, NULL, (void *) SET_DENY},
    { "yes [opt ...]",			"Enable and accept option",
	IpcpSetCommand, NULL, (void *) SET_YES},
    { "no [opt ...]",			"Disable and deny option",
	IpcpSetCommand, NULL, (void *) SET_NO},
    { NULL },
  };

/*
 * INTERNAL VARIABLES
 */

  static const struct fsmoptinfo	gIpcpConfOpts[] = {
    { "IPADDRS",	TY_IPADDRS,		8, 8, FALSE },
    { "COMPPROTO",	TY_COMPPROTO,		4, 4, TRUE },
    { "IPADDR",		TY_IPADDR,		4, 4, TRUE },
    { "PRIDNS",		TY_PRIMARYDNS,		4, 4, TRUE },
    { "PRINBNS",	TY_PRIMARYNBNS,		4, 4, TRUE },
    { "SECDNS",		TY_SECONDARYDNS,	4, 4, TRUE },
    { "SECNBNS",	TY_SECONDARYNBNS,	4, 4, TRUE },
    { NULL }
  };

  static const struct confinfo gConfList[] = {
    { 1,	IPCP_CONF_VJCOMP,	"vjcomp"	},
    { 0,	IPCP_CONF_REQPRIDNS,	"req-pri-dns"	},
    { 0,	IPCP_CONF_REQSECDNS,	"req-sec-dns"	},
    { 0,	IPCP_CONF_REQPRINBNS,	"req-pri-nbns"	},
    { 0,	IPCP_CONF_REQSECNBNS,	"req-sec-nbns"	},
    { 0,	IPCP_CONF_PRETENDIP,	"pretend-ip"	},
    { 0,	0,			NULL		},
  };

  static const struct fsmtype gIpcpFsmType = {
    "IPCP",
    PROTO_IPCP,
    IPCP_KNOWN_CODES,
    LG_IPCP, LG_IPCP,
    FALSE,
    NULL,
    IpcpLayerUp,
    IpcpLayerDown,
    IpcpLayerStart,
    IpcpLayerFinish,
    IpcpBuildConfigReq,
    IpcpDecodeConfig,
    IpcpConfigure,
    IpcpUnConfigure,
    NULL,
    NULL,
    NULL,
    NULL,
    IpcpFailure,
    NULL,
    NULL,
    NULL,
  };

/*
 * IpcpStat()
 */

int
IpcpStat(int ac, char *av[], void *arg)
{
  char			path[NG_PATHLEN + 1];
  IpcpState		const ipcp = &bund->ipcp;
  Fsm			fp = &ipcp->fsm;
  union {
      u_char		buf[sizeof(struct ng_mesg) + sizeof(struct slcompress)];
      struct ng_mesg	reply;
  }			u;
  struct slcompress	*const sls = (struct slcompress *)(void *)u.reply.data;

  Printf("%s [%s]\r\n", Pref(fp), FsmStateName(fp->state));
  Printf("Allowed IP address ranges:\r\n");
  Printf("\tSelf: %s/%d\r\n",
    inet_ntoa(ipcp->conf.self_allow.ipaddr), ipcp->conf.self_allow.width);
  Printf("\tPeer: %s/%d\r\n",
    inet_ntoa(ipcp->conf.peer_allow.ipaddr), ipcp->conf.peer_allow.width);
  Printf("Current addressing:\r\n");
  Printf("\tSelf: %s\r\n", inet_ntoa(ipcp->want_addr));
  Printf("\tPeer: %s\r\n", inet_ntoa(ipcp->peer_addr));
  Printf("Compression:\r\n");
  Printf("\tSelf: ");
  if (ipcp->want_comp.proto != 0)
    Printf("%s, %d compression channels, CID %scompressible\r\n",
      ProtoName(ntohs(ipcp->want_comp.proto)),
      ipcp->want_comp.maxchan + 1, ipcp->want_comp.compcid ? "" : "not ");
  else
    Printf("None\r\n");
  Printf("\tPeer: ");
  if (ipcp->peer_comp.proto != 0)
    Printf("%s, %d compression channels, CID %scompressible\n",
      ProtoName(ntohs(ipcp->peer_comp.proto)),
      ipcp->peer_comp.maxchan + 1, ipcp->peer_comp.compcid ? "" : "not ");
  else
    Printf("None\r\n");
  Printf("Server info we give to peer:\r\n");
  Printf("DNS servers : %15s", inet_ntoa(ipcp->conf.peer_dns[0]));
  Printf("  %15s\r\n", inet_ntoa(ipcp->conf.peer_dns[1]));
  Printf("NBNS servers: %15s", inet_ntoa(ipcp->conf.peer_nbns[0]));
  Printf("  %15s\r\n", inet_ntoa(ipcp->conf.peer_nbns[1]));
  Printf("Server info peer gave to us:\r\n");
  Printf("DNS servers : %15s", inet_ntoa(ipcp->want_dns[0]));
  Printf("  %15s\r\n", inet_ntoa(ipcp->want_dns[1]));
  Printf("NBNS servers: %15s", inet_ntoa(ipcp->want_nbns[0]));
  Printf("  %15s\r\n", inet_ntoa(ipcp->want_nbns[1]));
  Printf("IPCP Options:\r\n");
  OptStat(&ipcp->conf.options, gConfList);

  /* Get VJC state */
  snprintf(path, sizeof(path), "%s.%s", MPD_HOOK_PPP, NG_PPP_HOOK_VJC_IP);
  if (NgFuncSendQuery(path, NGM_VJC_COOKIE, NGM_VJC_GET_STATE,
      NULL, 0, &u.reply, sizeof(u), NULL) < 0)
    return(0);

  Printf("VJ Compression:\r\n");
  Printf("\tOut comp : %d\r\n", sls->sls_compressed);
  Printf("\tOut total: %d\r\n", sls->sls_packets);
  Printf("\tMissed   : %d\r\n", sls->sls_misses);
  Printf("\tSearched : %d\r\n", sls->sls_searches);
  Printf("\tIn comp  : %d\r\n", sls->sls_compressedin);
  Printf("\tIn uncomp: %d\r\n", sls->sls_uncompressedin);
  Printf("\tIn error : %d\r\n", sls->sls_errorin);
  Printf("\tIn tossed: %d\r\n", sls->sls_tossed);
  return(0);
}

/*
 * IpcpInit()
 */

void
IpcpInit(void)
{
  IpcpState		const ipcp = &bund->ipcp;

  /* Init state machine */
  memset(ipcp, 0, sizeof(*ipcp));
  FsmInit(&ipcp->fsm, &gIpcpFsmType);

  /* Come up with a default IP address for my side of the link */
  memset(&ipcp->conf.self_allow, 0, sizeof(ipcp->conf.self_allow));
  IfaceGetAnyIpAddress(&ipcp->conf.self_allow.ipaddr);

  /* Default we want VJ comp */
  Enable(&ipcp->conf.options, IPCP_CONF_VJCOMP);
  Accept(&ipcp->conf.options, IPCP_CONF_VJCOMP);
}

/*
 * IpcpConfigure()
 */

static void
IpcpConfigure(Fsm fp)
{
  IpcpState	const ipcp = &bund->ipcp;

  /* FSM stuff */
  ipcp->peer_reject = 0;

  /* Get allowed IP addresses from config and/or from current bundle */
  ipcp->self_allow = ipcp->conf.self_allow;
  if (bund->peer_allow.ipaddr.s_addr != 0 || bund->peer_allow.width != 0)
    ipcp->peer_allow = bund->peer_allow;
  else
    ipcp->peer_allow = ipcp->conf.peer_allow;

  /* Initially request addresses as specified by config */
  ipcp->want_addr = ipcp->self_allow.ipaddr;
  ipcp->peer_addr = ipcp->peer_allow.ipaddr;

  /* Van Jacobson compression */
  ipcp->peer_comp.proto = 0;
  ipcp->peer_comp.maxchan = IPCP_VJCOMP_DEFAULT_MAXCHAN;
  ipcp->peer_comp.compcid = 0;

  ipcp->want_comp.proto =
    Enabled(&ipcp->conf.options, IPCP_CONF_VJCOMP) ? htons(PROTO_VJCOMP) : 0;
  ipcp->want_comp.maxchan = IPCP_VJCOMP_MAX_MAXCHAN;

  /* DNS and NBNS servers */
  memset(&ipcp->want_dns, 0, sizeof(ipcp->want_dns));
  memset(&ipcp->want_nbns, 0, sizeof(ipcp->want_nbns));

  /* If any of our links are unable to give receive error indications, we must
     tell the peer not to compress the slot-id in VJCOMP packets (cf. RFC1144).
     To be on the safe side, we always say this. */
  ipcp->want_comp.compcid = 0;
}

/*
 * IpcpUnConfigure()
 */

static void
IpcpUnConfigure(Fsm fp)
{
}

/*
 * IpcpBuildConfigReq()
 */

static u_char *
IpcpBuildConfigReq(Fsm fp, u_char *cp)
{
  IpcpState	const ipcp = &bund->ipcp;

  /* Put in my desired IP address */
  if (!IPCP_REJECTED(ipcp, TY_IPADDR) || ipcp->want_addr.s_addr == 0)
    cp = FsmConfValue(cp, TY_IPADDR, 4, &ipcp->want_addr.s_addr);

  /* Put in my requested compression protocol */
  if (ipcp->want_comp.proto != 0 && !IPCP_REJECTED(ipcp, TY_COMPPROTO))
    cp = FsmConfValue(cp, TY_COMPPROTO, 4, &ipcp->want_comp);

  /* Request peer's DNS and NBNS servers */
  {
    const int	sopts[2][2] = { { IPCP_CONF_REQPRIDNS, IPCP_CONF_REQSECDNS },
				{ IPCP_CONF_REQPRINBNS, IPCP_CONF_REQSECNBNS }};
    const int	nopts[2][2] = { { TY_PRIMARYDNS, TY_SECONDARYDNS }, 
				{ TY_PRIMARYNBNS, TY_SECONDARYNBNS } };
    struct in_addr	*vals[2] = { ipcp->want_dns, ipcp->want_nbns };
    int			sopt, pri;

    for (sopt = 0; sopt < 2; sopt++) {
      for (pri = 0; pri < 2; pri++) {
	const int	opt = nopts[sopt][pri];

	/* Add option if we desire it and it hasn't been rejected */
	if (Enabled(&ipcp->conf.options, sopts[sopt][pri])
	    && !IPCP_REJECTED(ipcp, opt)) {
	  cp = FsmConfValue(cp, opt, 4, &vals[sopt][pri]);
	}
      }
    }
  }

/* Done */

  return(cp);
}

/*
 * IpcpLayerStart()
 *
 * Tell the lower layer (the bundle) that we need it
 */

static void
IpcpLayerStart(Fsm fp)
{
  BundOpen(/*PROTO_IPCP*/);
}

/*
 * IpcpLayerFinish()
 *
 * Tell the lower layer (the bundle) that we no longer need it
 */

static void
IpcpLayerFinish(Fsm fp)
{
  BundClose(/*PROTO_IPCP*/);
}

/*
 * IpcpLayerUp()
 *
 * Called when IPCP has reached the OPEN state
 */

static void
IpcpLayerUp(Fsm fp)
{
  IpcpState		const ipcp = &bund->ipcp;
  char			ipbuf[20];
  char			path[NG_PATHLEN + 1];
  struct ngm_vjc_config	vjc;

  /* Determine actual address we'll use for ourselves */
  if (!IpAddrInRange(&ipcp->self_allow, ipcp->want_addr)) {
    Log(fp->log, ("  Note: ignoring negotiated %s IP %s,",
      "self", inet_ntoa(ipcp->want_addr)));
    Log(fp->log, ("        using %s instead.",
      inet_ntoa(ipcp->self_allow.ipaddr)));
    ipcp->want_addr = ipcp->self_allow.ipaddr;
  }

  /* Determine actual address we'll use for peer */
  if (!IpAddrInRange(&ipcp->peer_allow, ipcp->peer_addr)
      && ipcp->peer_allow.ipaddr.s_addr != 0) {
    Log(fp->log, ("  Note: ignoring negotiated %s IP %s,",
      "peer", inet_ntoa(ipcp->peer_addr)));
    Log(fp->log, ("        using %s instead.",
      inet_ntoa(ipcp->peer_allow.ipaddr)));
    ipcp->peer_addr = ipcp->peer_allow.ipaddr;
  }

  /* Report */
  snprintf(ipbuf, sizeof(ipbuf), "%s", inet_ntoa(ipcp->peer_addr));
  Log(fp->log, ("  %s -> %s", inet_ntoa(ipcp->want_addr), ipbuf));

  /* Bring up IP interface */
  IfaceUp(ipcp->want_addr, ipcp->peer_addr);

  /* Configure VJ compression node */
  memset(&vjc, 0, sizeof(vjc));
  vjc.enableComp = ntohs(ipcp->peer_comp.proto) == PROTO_VJCOMP;
  vjc.enableDecomp = ntohs(ipcp->want_comp.proto) == PROTO_VJCOMP;
  vjc.maxChannel = ipcp->peer_comp.maxchan;
  vjc.compressCID = ipcp->peer_comp.compcid;
  snprintf(path, sizeof(path), "%s.%s", MPD_HOOK_PPP, NG_PPP_HOOK_VJC_IP);
  if (NgSendMsg(bund->csock, path,
      NGM_VJC_COOKIE, NGM_VJC_SET_CONFIG, &vjc, sizeof(vjc)) < 0) {
    Log(LG_ERR, ("[%s] can't config %s node: %s",
      bund->name, NG_VJC_NODE_TYPE, strerror(errno)));
  }

  /* Tell upper layer (ip interface) that we are available */
  IfaceUp(ipcp->want_addr, ipcp->peer_addr);

  /* Enable IP packets in the PPP node */
#if NGM_PPP_COOKIE < 940897794
  bund->pppConfig.enableIP = 1;
  bund->pppConfig.enableVJCompression = vjc.enableComp;
  bund->pppConfig.enableVJDecompression = vjc.enableDecomp;
#else
  bund->pppConfig.bund.enableIP = 1;
  bund->pppConfig.bund.enableVJCompression = vjc.enableComp;
  bund->pppConfig.bund.enableVJDecompression = vjc.enableDecomp;
#endif
  NgFuncSetConfig();
}

/*
 * IpcpLayerDown()
 *
 * Called when IPCP leaves the OPEN state
 */

static void
IpcpLayerDown(Fsm fp)
{
  struct ngm_vjc_config	vjc;
  char			path[NG_PATHLEN + 1];

  /* Turn off IP packets */
#if NGM_PPP_COOKIE < 940897794
  bund->pppConfig.enableIP = 0;
  bund->pppConfig.enableVJCompression = 0;
  bund->pppConfig.enableVJDecompression = 0;
#else
  bund->pppConfig.bund.enableIP = 0;
  bund->pppConfig.bund.enableVJCompression = 0;
  bund->pppConfig.bund.enableVJDecompression = 0;
#endif
  NgFuncSetConfig();

  /* Turn off VJ compression node */
  memset(&vjc, 0, sizeof(vjc));
  snprintf(path, sizeof(path), "%s.%s", MPD_HOOK_PPP, NG_PPP_HOOK_VJC_IP);
  if (NgSendMsg(bund->csock, path,
      NGM_VJC_COOKIE, NGM_VJC_SET_CONFIG, &vjc, sizeof(vjc)) < 0) {
    Log(LG_ERR, ("[%s] can't config %s node: %s",
      bund->name, NG_VJC_NODE_TYPE, strerror(errno)));
  }

  /* Notify interface */
  IfaceDown();
}

/*
 * IpcpUp()
 */

void
IpcpUp(void)
{
  FsmUp(&bund->ipcp.fsm);
}

/*
 * IpcpClose()
 */

void
IpcpClose(void)
{
  FsmClose(&bund->ipcp.fsm);
}

/*
 * IpcpDown()
 */

void
IpcpDown(void)
{
  FsmDown(&bund->ipcp.fsm);
}

/*
 * IpcpOpen()
 */

void
IpcpOpen(void)
{
  FsmOpen(&bund->ipcp.fsm);
}

/*
 * IpcpFailure()
 */

static void
IpcpFailure(Fsm fp, enum fsmfail reason)
{
  char	buf[100];

  snlcatf(buf, sizeof(buf), STR_IPCP_FAILED, FsmFailureStr(reason));
  SetStatus(ADLG_WAN_NEGOTIATION_FAILURE, STR_COPY, buf);
  RecordLinkUpDownReason(NULL, 0, STR_PROTO_ERR, "%s", buf);
  RecordLinkUpDownReason(NULL, 1, STR_REDIAL, NULL);
}

/*
 * IpcpDecodeConfig()
 */

static void
IpcpDecodeConfig(Fsm fp, FsmOption list, int num, int mode)
{
  IpcpState		const ipcp = &bund->ipcp;
  struct in_addr	*wantip, *peerip;
  int			k;

  /* Decode each config option */
  for (k = 0; k < num; k++) {
    FsmOption	const opt = &list[k];
    FsmOptInfo	const oi = FsmFindOptInfo(gIpcpConfOpts, opt->type);

    if (!oi) {
      Log(LG_IPCP, (" UNKNOWN[%d] len=%d", opt->type, opt->len));
      if (mode == MODE_REQ)
	FsmRej(fp, opt);
      continue;
    }
    if (!oi->supported) {
      Log(LG_IPCP, (" %s", oi->name));
      if (mode == MODE_REQ) {
	Log(LG_IPCP, ("   Not supported"));
	FsmRej(fp, opt);
      }
      continue;
    }
    if (opt->len < oi->minLen + 2 || opt->len > oi->maxLen + 2) {
      Log(LG_IPCP, (" %s", oi->name));
      if (mode == MODE_REQ) {
	Log(LG_IPCP, ("   bogus len=%d", opt->len));
	FsmRej(fp, opt);
      }
      continue;
    }
    switch (opt->type) {
      case TY_IPADDR:
	{
	  struct in_addr	ip;

	  memcpy(&ip, opt->data, 4);
	  Log(LG_IPCP, (" %s %s", oi->name, inet_ntoa(ip)));
	  switch (mode) {
	    case MODE_REQ:
	      if (!IpAddrInRange(&ipcp->peer_allow, ip) || !ip.s_addr) {
		if (ipcp->peer_addr.s_addr == 0)
		  Log(LG_IPCP, ("   %s", "no IP address available for peer!"));
		if (Enabled(&ipcp->conf.options, IPCP_CONF_PRETENDIP)) {
		  Log(LG_IPCP, ("   pretending that %s is OK, will ignore",
		      inet_ntoa(ip)));
		  ipcp->peer_addr = ip;
		  FsmAck(fp, opt);
		  break;
		}
		memcpy(opt->data, &ipcp->peer_addr, 4);
		Log(LG_IPCP, ("   NAKing with %s", inet_ntoa(ipcp->peer_addr)));
		FsmNak(fp, opt);
		break;
	      }
	      Log(LG_IPCP, ("   %s is OK", inet_ntoa(ip)));
	      ipcp->peer_addr = ip;
	      FsmAck(fp, opt);
	      break;
	    case MODE_NAK:
	      {
		if (IpAddrInRange(&ipcp->self_allow, ip)) {
		  Log(LG_IPCP, ("   %s is OK", inet_ntoa(ip)));
		  ipcp->want_addr = ip;
		} else if (Enabled(&ipcp->conf.options, IPCP_CONF_PRETENDIP)) {
		  Log(LG_IPCP, ("   pretending that %s is OK, will ignore",
		      inet_ntoa(ip)));
		  ipcp->want_addr = ip;
		} else
		  Log(LG_IPCP, ("   %s is unacceptable", inet_ntoa(ip)));
	      }
	      break;
	    case MODE_REJ:
	      IPCP_PEER_REJ(ipcp, opt->type);
	      if (ipcp->want_addr.s_addr == 0)
		Log(LG_IPCP, ("   Problem: I need an IP address!"));
	      break;
	  }
	}
	break;

      case TY_COMPPROTO:
	{
	  struct ipcpvjcomp	vj;

	  memcpy(&vj, opt->data, sizeof(vj));
	  Log(LG_IPCP, (" %s %s, %d comp. channels, %s comp-cid",
	    oi->name, ProtoName(ntohs(vj.proto)),
	    vj.maxchan + 1, vj.compcid ? "allow" : "no"));
	  switch (mode) {
	    case MODE_REQ:
	      if (!Acceptable(&ipcp->conf.options, IPCP_CONF_VJCOMP)) {
		FsmRej(fp, opt);
		break;
	      }
	      if (ntohs(vj.proto) == PROTO_VJCOMP
		  && vj.maxchan <= IPCP_VJCOMP_MAX_MAXCHAN
		  && vj.maxchan >= IPCP_VJCOMP_MIN_MAXCHAN) {
		ipcp->peer_comp = vj;
		FsmAck(fp, opt);
		break;
	      }
	      vj.proto = htons(PROTO_VJCOMP);
	      vj.maxchan = IPCP_VJCOMP_MAX_MAXCHAN;
	      vj.compcid = 0;
	      memcpy(opt->data, &vj, sizeof(vj));
	      FsmNak(fp, opt);
	      break;
	    case MODE_NAK:
	      if (ntohs(vj.proto) != PROTO_VJCOMP) {
		Log(LG_IPCP, ("  Can't accept proto 0x%04x",
		  (u_short) ntohs(vj.proto)));
		break;
	      }
	      if (vj.maxchan != ipcp->want_comp.maxchan) {
		if (vj.maxchan <= IPCP_VJCOMP_MAX_MAXCHAN
		    && vj.maxchan >= IPCP_VJCOMP_MIN_MAXCHAN) {
		  Log(LG_IPCP, ("  Adjusting # compression channels"));
		  ipcp->want_comp.maxchan = vj.maxchan;
		} else {
		  Log(LG_IPCP, ("  Can't handle %d maxchan", vj.maxchan));
		}
	      }
	      if (vj.compcid) {
		Log(LG_IPCP, ("  Can't accept comp-cid"));
		break;
	      }
	      break;
	    case MODE_REJ:
	      IPCP_PEER_REJ(ipcp, opt->type);
	      ipcp->want_comp.proto = 0;
	      break;
	  }
	}
	break;

      case TY_PRIMARYDNS:
	peerip = &ipcp->conf.peer_dns[0];
	wantip = &ipcp->want_dns[0];
	goto doDnsNbns;
      case TY_PRIMARYNBNS:
	peerip = &ipcp->conf.peer_nbns[0];
	wantip = &ipcp->want_nbns[0];
	goto doDnsNbns;
      case TY_SECONDARYDNS:
	peerip = &ipcp->conf.peer_dns[1];
	wantip = &ipcp->want_dns[1];
	goto doDnsNbns;
      case TY_SECONDARYNBNS:
	peerip = &ipcp->conf.peer_nbns[1];
	wantip = &ipcp->want_nbns[1];
doDnsNbns:
	{
	  struct in_addr	hisip;

	  memcpy(&hisip, opt->data, 4);
	  Log(LG_IPCP, (" %s %s", oi->name, inet_ntoa(hisip)));
	  switch (mode) {
	    case MODE_REQ:
	      if (hisip.s_addr == 0) {		/* he's asking for one */
		if (peerip->s_addr == 0) {	/* we don't got one */
		  FsmRej(fp, opt);
		  break;
		}
		Log(LG_IPCP, ("   NAKing with %s", inet_ntoa(*peerip)));
		memcpy(opt->data, peerip, sizeof(*peerip));
		FsmNak(fp, opt);		/* we got one for him */
		break;
	      }
	      FsmAck(fp, opt);			/* he knows what he wants */
	      break;
	    case MODE_NAK:	/* we asked for his server, he's telling us */
	      *wantip = hisip;
	      break;
	    case MODE_REJ:	/* we asked for his server, he's ignorant */
	      IPCP_PEER_REJ(ipcp, opt->type);
	      break;
	  }
	}
	break;

      default:
	assert(0);
    }
  }
}

/*
 * IpcpInput()
 *
 * Deal with an incoming IPCP packet
 */

void
IpcpInput(Mbuf bp, int linkNum)
{
  FsmInput(&bund->ipcp.fsm, bp, linkNum);
}

/*
 * IpcpSetCommand()
 */

static int
IpcpSetCommand(int ac, char *av[], void *arg)
{
  IpcpState		const ipcp = &bund->ipcp;
  struct in_addr	*ips;

  if (ac == 0)
    return(-1);
  switch ((intptr_t)arg) {
    case SET_RANGES:
      {
	struct in_range	self_new_allow;
	struct in_range	peer_new_allow;

	/* Parse args */
	if (ac != 2
	    || !ParseAddr(*av++, &self_new_allow)
	    || !ParseAddr(*av++, &peer_new_allow))
	  return(-1);
	ipcp->conf.self_allow = self_new_allow;
	ipcp->conf.peer_allow = peer_new_allow;

      }
      break;

    case SET_DNS:
      ips = ipcp->conf.peer_dns;
      goto getPrimSec;
      break;
    case SET_NBNS:
      ips = ipcp->conf.peer_nbns;
getPrimSec:
      if (!inet_aton(av[0], &ips[0])) {
	Log(LG_ERR, ("[%s] %s: invalid IP address", bund->name, av[0]));
	return(0);
      }
      ips[1].s_addr = 0;
      if (ac > 1 && !inet_aton(av[1], &ips[1])) {
	Log(LG_ERR, ("[%s] %s: invalid IP address", bund->name, av[1]));
	return(0);
      }
      break;

    case SET_ACCEPT:
      AcceptCommand(ac, av, &ipcp->conf.options, gConfList);
      break;

    case SET_DENY:
      DenyCommand(ac, av, &ipcp->conf.options, gConfList);
      break;

    case SET_ENABLE:
      EnableCommand(ac, av, &ipcp->conf.options, gConfList);
      break;

    case SET_DISABLE:
      DisableCommand(ac, av, &ipcp->conf.options, gConfList);
      break;

    case SET_YES:
      YesCommand(ac, av, &ipcp->conf.options, gConfList);
      break;

    case SET_NO:
      NoCommand(ac, av, &ipcp->conf.options, gConfList);
      break;

    default:
      assert(0);
  }
  return(0);
}

