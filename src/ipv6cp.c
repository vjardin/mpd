
/*
 * ipv6cp.c
 *
 * Written by Alexander Motin <mav@alkar.net>
 */

#include "ppp.h"
#include "ipv6cp.h"
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

  #define IPV6CP_KNOWN_CODES	(   (1 << CODE_CONFIGREQ)	\
				  | (1 << CODE_CONFIGACK)	\
				  | (1 << CODE_CONFIGNAK)	\
				  | (1 << CODE_CONFIGREJ)	\
				  | (1 << CODE_TERMREQ)		\
				  | (1 << CODE_TERMACK)		\
				  | (1 << CODE_CODEREJ)		)

  #define TY_INTIDENT		1
  #define TY_COMPPROTO		2

  #define TY_IPADDRS		1
  #define TY_COMPPROTO		2
  #define TY_IPADDR		3
  #define TY_PRIMARYDNS		129
  #define TY_PRIMARYNBNS	130
  #define TY_SECONDARYDNS	131
  #define TY_SECONDARYNBNS	132


  #define IPV6CP_REJECTED(p,x)	((p)->peer_reject & (1<<(x)))
  #define IPV6CP_PEER_REJ(p,x)	do{(p)->peer_reject |= (1<<(x));}while(0)

  #define IPV6CP_VJCOMP_MIN_MAXCHAN	(NG_VJC_MIN_CHANNELS - 1)
  #define IPV6CP_VJCOMP_MAX_MAXCHAN	(NG_VJC_MAX_CHANNELS - 1)
  #define IPV6CP_VJCOMP_DEFAULT_MAXCHAN	IPV6CP_VJCOMP_MAX_MAXCHAN

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

  static void	Ipv6cpConfigure(Fsm fp);
  static void	Ipv6cpUnConfigure(Fsm fp);

  static u_char	*Ipv6cpBuildConfigReq(Fsm fp, u_char *cp);
  static void	Ipv6cpDecodeConfig(Fsm fp, FsmOption list, int num, int mode);
  static void	Ipv6cpLayerStart(Fsm fp);
  static void	Ipv6cpLayerFinish(Fsm fp);
  static void	Ipv6cpLayerUp(Fsm fp);
  static void	Ipv6cpLayerDown(Fsm fp);
  static void	Ipv6cpFailure(Fsm fp, enum fsmfail reason);

  static int	Ipv6cpSetCommand(int ac, char *av[], void *arg);

  void 		CreateInterfaceID(u_char *intid, int random);
/*
 * GLOBAL VARIABLES
 */

  const struct cmdtab Ipv6cpSetCmds[] = {
/*    { "ranges self/width peer/width",	"Allowed IP address ranges",
	Ipv6cpSetCommand, NULL, (void *) SET_RANGES },*/
    { "enable [opt ...]",		"Enable option",
	Ipv6cpSetCommand, NULL, (void *) SET_ENABLE},
/*    { "dns primary [secondary]",	"Set peer DNS servers",
	Ipv6cpSetCommand, NULL, (void *) SET_DNS},
    { "nbns primary [secondary]",	"Set peer NBNS servers",
	Ipv6cpSetCommand, NULL, (void *) SET_NBNS}, */
    { "disable [opt ...]",		"Disable option",
	Ipv6cpSetCommand, NULL, (void *) SET_DISABLE},
    { "accept [opt ...]",		"Accept option",
	Ipv6cpSetCommand, NULL, (void *) SET_ACCEPT},
    { "deny [opt ...]",			"Deny option",
	Ipv6cpSetCommand, NULL, (void *) SET_DENY},
    { "yes [opt ...]",			"Enable and accept option",
	Ipv6cpSetCommand, NULL, (void *) SET_YES},
    { "no [opt ...]",			"Disable and deny option",
	Ipv6cpSetCommand, NULL, (void *) SET_NO},
    { NULL },
  };

/*
 * INTERNAL VARIABLES
 */

  static const struct fsmoptinfo	gIpv6cpConfOpts[] = {
    { "INTIDENT",	TY_INTIDENT,		8, 8, TRUE },
    { "COMPPROTO",	TY_COMPPROTO,		4, 4, FALSE },
    { NULL }
  };

  static const struct confinfo gConfList[] = {
/*    { 1,	IPV6CP_CONF_VJCOMP,	"vjcomp"	},
    { 0,	IPV6CP_CONF_REQPRIDNS,	"req-pri-dns"	},
    { 0,	IPV6CP_CONF_REQSECDNS,	"req-sec-dns"	},
    { 0,	IPV6CP_CONF_REQPRINBNS,	"req-pri-nbns"	},
    { 0,	IPV6CP_CONF_REQSECNBNS,	"req-sec-nbns"	},
    { 0,	IPV6CP_CONF_PRETENDIP,	"pretend-ip"	},*/
    { 0,	0,			NULL		},
  };

  static const struct fsmtype gIpv6cpFsmType = {
    "IPV6CP",
    PROTO_IPV6CP,
    IPV6CP_KNOWN_CODES,
    LG_IPV6CP, LG_IPV6CP2,
    FALSE,
    NULL,
    Ipv6cpLayerUp,
    Ipv6cpLayerDown,
    Ipv6cpLayerStart,
    Ipv6cpLayerFinish,
    Ipv6cpBuildConfigReq,
    Ipv6cpDecodeConfig,
    Ipv6cpConfigure,
    Ipv6cpUnConfigure,
    NULL,
    NULL,
    NULL,
    NULL,
    Ipv6cpFailure,
    NULL,
    NULL,
    NULL,
  };

/*
 * Ipv6cpStat()
 */

int
Ipv6cpStat(int ac, char *av[], void *arg)
{
  Ipv6cpState		const ipv6cp = &bund->ipv6cp;
  Fsm			fp = &ipv6cp->fsm;

  Printf("%s [%s]\r\n", Pref(fp), FsmStateName(fp->state));
  Printf("Interface identificators:\r\n");
  Printf("\tSelf: %04x:%04x:%04x:%04x\r\n", ntohs(((u_short*)ipv6cp->myintid)[0]), ntohs(((u_short*)ipv6cp->myintid)[1]), ntohs(((u_short*)ipv6cp->myintid)[2]), ntohs(((u_short*)ipv6cp->myintid)[3]));
  Printf("\tPeer: %04x:%04x:%04x:%04x\r\n", ntohs(((u_short*)ipv6cp->hisintid)[0]), ntohs(((u_short*)ipv6cp->hisintid)[1]), ntohs(((u_short*)ipv6cp->hisintid)[2]), ntohs(((u_short*)ipv6cp->hisintid)[3]));
  Printf("IPV6CP Options:\r\n");
  OptStat(&ipv6cp->conf.options, gConfList);

  return(0);
}

/*
 * CreateInterfaceID()
 */

void
CreateInterfaceID(u_char *intid, int r)
{
    struct sockaddr_dl hwaddr;
    u_char	*ether;

    if (!r) {
	if (!GetEther(NULL, &hwaddr)) {
	    ether = (u_char *) LLADDR(&hwaddr);
	    intid[0]=ether[0] ^ 0x02; /* reverse the u/l bit*/
	    intid[1]=ether[1];
	    intid[2]=ether[2];
	    intid[3]=0xff;
	    intid[4]=0xfe;
	    intid[5]=ether[3];
	    intid[6]=ether[4];
	    intid[7]=ether[5];
	    return;
	}
    }

    srandomdev();
    ((u_int32_t*)intid)[0]=(((u_int32_t)random()) % 0xFFFFFFFF) + 1;
    ((u_int32_t*)intid)[1]=(((u_int32_t)random()) % 0xFFFFFFFF) + 1;
    intid[0] &= 0xfd;

}

/*
 * Ipv6cpInit()
 */

void
Ipv6cpInit(void)
{
  Ipv6cpState	ipv6cp = &bund->ipv6cp;

  /* Init state machine */
  memset(ipv6cp, 0, sizeof(*ipv6cp));
  FsmInit(&ipv6cp->fsm, &gIpv6cpFsmType);

  CreateInterfaceID(ipv6cp->myintid,0);

}

/*
 * Ipv6cpConfigure()
 */

static void
Ipv6cpConfigure(Fsm fp)
{
  Ipv6cpState	const ipv6cp = &bund->ipv6cp;

  /* FSM stuff */
  ipv6cp->peer_reject = 0;

}

/*
 * Ipv6cpUnConfigure()
 */

static void
Ipv6cpUnConfigure(Fsm fp)
{
}

/*
 * Ipv6cpBuildConfigReq()
 */

static u_char *
Ipv6cpBuildConfigReq(Fsm fp, u_char *cp)
{
  Ipv6cpState	const ipv6cp = &bund->ipv6cp;

  cp = FsmConfValue(cp, TY_INTIDENT, 8, ipv6cp->myintid);

/* Done */

  return(cp);
}

/*
 * Ipv6cpLayerStart()
 *
 * Tell the lower layer (the bundle) that we need it
 */

static void
Ipv6cpLayerStart(Fsm fp)
{
    BundNcpsStart(NCP_IPV6CP);
}

/*
 * Ipv6cpLayerFinish()
 *
 * Tell the lower layer (the bundle) that we no longer need it
 */

static void
Ipv6cpLayerFinish(Fsm fp)
{
    BundNcpsFinish(NCP_IPV6CP);
}

/*
 * Ipv6cpLayerUp()
 *
 * Called when IPV6CP has reached the OPEN state
 */

static void
Ipv6cpLayerUp(Fsm fp)
{
  Ipv6cpState		const ipv6cp = &bund->ipv6cp;

  /* Report */
  Log(fp->log, ("  %04x:%04x:%04x:%04x -> %04x:%04x:%04x:%04x", 
    ntohs(((u_short*)ipv6cp->myintid)[0]), ntohs(((u_short*)ipv6cp->myintid)[1]), ntohs(((u_short*)ipv6cp->myintid)[2]), ntohs(((u_short*)ipv6cp->myintid)[3]),
    ntohs(((u_short*)ipv6cp->hisintid)[0]), ntohs(((u_short*)ipv6cp->hisintid)[1]), ntohs(((u_short*)ipv6cp->hisintid)[2]), ntohs(((u_short*)ipv6cp->hisintid)[3])));

  BundNcpsJoin(NCP_IPV6CP);

  /* Enable IP packets in the PPP node */
#if NGM_PPP_COOKIE < 940897794
  bund->pppConfig.enableIPv6 = 1;
#else
  bund->pppConfig.bund.enableIPv6 = 1;
#endif
  NgFuncSetConfig();
}

/*
 * Ipv6cpLayerDown()
 *
 * Called when IPV6CP leaves the OPEN state
 */

static void
Ipv6cpLayerDown(Fsm fp)
{
  struct ngm_vjc_config	vjc;
  char			path[NG_PATHLEN + 1];

  /* Turn off IP packets */
#if NGM_PPP_COOKIE < 940897794
  bund->pppConfig.enableIPv6 = 0;
#else
  bund->pppConfig.bund.enableIPv6 = 0;
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

  BundNcpsLeave(NCP_IPV6CP);

}

/*
 * Ipv6cpUp()
 */

void
Ipv6cpUp(void)
{
  FsmUp(&bund->ipv6cp.fsm);
}

/*
 * Ipv6cpClose()
 */

void
Ipv6cpClose(void)
{
  FsmClose(&bund->ipv6cp.fsm);
}

/*
 * Ipv6cpDown()
 */

void
Ipv6cpDown(void)
{
  FsmDown(&bund->ipv6cp.fsm);
}

/*
 * Ipv6cpOpen()
 */

void
Ipv6cpOpen(void)
{
  FsmOpen(&bund->ipv6cp.fsm);
}

/*
 * Ipv6cpFailure()
 */

static void
Ipv6cpFailure(Fsm fp, enum fsmfail reason)
{
  char	buf[100];

  snlcatf(buf, sizeof(buf), STR_IPV6CP_FAILED, FsmFailureStr(reason));
  SetStatus(ADLG_WAN_NEGOTIATION_FAILURE, STR_COPY, buf);
  RecordLinkUpDownReason(NULL, 0, STR_PROTO_ERR, "%s", buf);
  RecordLinkUpDownReason(NULL, 1, STR_REDIAL, NULL);
}

/*
 * Ipv6cpDecodeConfig()
 */

static void
Ipv6cpDecodeConfig(Fsm fp, FsmOption list, int num, int mode)
{
  Ipv6cpState		const ipv6cp = &bund->ipv6cp;
  int			k;

  /* Decode each config option */
  for (k = 0; k < num; k++) {
    FsmOption	const opt = &list[k];
    FsmOptInfo	const oi = FsmFindOptInfo(gIpv6cpConfOpts, opt->type);

    if (!oi) {
      Log(LG_IPV6CP, (" UNKNOWN[%d] len=%d", opt->type, opt->len));
      if (mode == MODE_REQ)
	FsmRej(fp, opt);
      continue;
    }
    if (!oi->supported) {
      Log(LG_IPV6CP, (" %s", oi->name));
      if (mode == MODE_REQ) {
	Log(LG_IPV6CP, ("   Not supported"));
	FsmRej(fp, opt);
      }
      continue;
    }
    if (opt->len < oi->minLen + 2 || opt->len > oi->maxLen + 2) {
      Log(LG_IPV6CP, (" %s", oi->name));
      if (mode == MODE_REQ) {
	Log(LG_IPV6CP, ("   bogus len=%d min=%d max=%d", opt->len, oi->minLen + 2, oi->maxLen + 2));
	FsmRej(fp, opt);
      }
      continue;
    }
    switch (opt->type) {
      case TY_INTIDENT:
	{
	  Log(LG_IPV6CP2, (" %s %04x:%04x:%04x:%04x", oi->name, ntohs(((u_short*)opt->data)[0]), ntohs(((u_short*)opt->data)[1]), ntohs(((u_short*)opt->data)[2]), ntohs(((u_short*)opt->data)[3])));
	  switch (mode) {
	    case MODE_REQ:
	      if ((((u_int32_t*)opt->data)[0]==0) && (((u_int32_t*)opt->data)[1]==0)) {
		Log(LG_IPV6CP2, ("   Empty INTIDENT, propose our."));
		CreateInterfaceID(ipv6cp->hisintid, 1);
	        memcpy(opt->data, ipv6cp->hisintid, 8);
	        FsmNak(fp, opt);
	      } else if ((((u_int32_t*)opt->data)[0]==((u_int32_t*)ipv6cp->myintid)[0]) && (((u_int32_t*)opt->data)[1]==((u_int32_t*)ipv6cp->myintid)[1])) {
		Log(LG_IPV6CP2, ("   Duplicate INTIDENT, generate and propose other."));
		CreateInterfaceID(ipv6cp->hisintid, 1);
	        memcpy(opt->data, ipv6cp->hisintid, 8);
	        FsmNak(fp, opt);
	      } else {
		Log(LG_IPV6CP2, ("   It's OK."));
	        memcpy(ipv6cp->hisintid, opt->data, 8);
	        FsmAck(fp, opt);
	      }
	      break;
	    case MODE_NAK:
		Log(LG_IPV6CP2, ("   I agree to get this to myself."));
	        memcpy(ipv6cp->myintid, opt->data, 8);
	      break;
	    case MODE_REJ:
	      IPV6CP_PEER_REJ(ipv6cp, opt->type);
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
 * Ipv6cpInput()
 *
 * Deal with an incoming IPV6CP packet
 */

void
Ipv6cpInput(Mbuf bp, int linkNum)
{
  FsmInput(&bund->ipv6cp.fsm, bp, linkNum);
}

/*
 * Ipv6cpSetCommand()
 */

static int
Ipv6cpSetCommand(int ac, char *av[], void *arg)
{
  Ipv6cpState		const ipv6cp = &bund->ipv6cp;

  if (ac == 0)
    return(-1);
  switch ((intptr_t)arg) {
    case SET_ACCEPT:
      AcceptCommand(ac, av, &ipv6cp->conf.options, gConfList);
      break;

    case SET_DENY:
      DenyCommand(ac, av, &ipv6cp->conf.options, gConfList);
      break;

    case SET_ENABLE:
      EnableCommand(ac, av, &ipv6cp->conf.options, gConfList);
      break;

    case SET_DISABLE:
      DisableCommand(ac, av, &ipv6cp->conf.options, gConfList);
      break;

    case SET_YES:
      YesCommand(ac, av, &ipv6cp->conf.options, gConfList);
      break;

    case SET_NO:
      NoCommand(ac, av, &ipv6cp->conf.options, gConfList);
      break;

    default:
      assert(0);
  }
  return(0);
}

