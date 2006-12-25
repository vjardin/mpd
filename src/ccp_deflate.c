
/*
 * ccp_deflate.c
 *
 * Written by Alexander Motin <mav@alkar.net>
 */

#include "defs.h"

#ifdef USE_NG_DEFLATE

#include "ppp.h"
#include "ccp.h"
#include "util.h"
#include "ngfunc.h"

#include <netgraph/ng_message.h>
#ifdef __DragonFly__
#include <netgraph/ppp/ng_ppp.h>
#else
#include <netgraph/ng_ppp.h>
#endif
#include <netgraph.h>

/*
 * INTERNAL FUNCTIONS
 */

  static int	DeflateInit(int direction);
  static void   DeflateConfigure(void);
  static char   *DeflateDescribe(int xmit);
  static void	DeflateCleanup(int direction);

  static u_char	*DeflateBuildConfigReq(u_char *cp, int *ok);
  static void   DeflateDecodeConfigReq(Fsm fp, FsmOption opt, int mode);
  static Mbuf	DeflateRecvResetReq(int id, Mbuf bp, int *noAck);
  static Mbuf	DeflateSendResetReq(void);
  static void	DeflateRecvResetAck(int id, Mbuf bp);
  static int    DeflateNegotiated(int xmit);
  static int    DeflateSubtractBloat(int size);
  static int	DeflateStat(int dir);

/*
 * GLOBAL VARIABLES
 */

  const struct comptype	gCompDeflateInfo =
  {
    "deflate",
    CCP_TY_DEFLATE,
    2,
    DeflateInit,
    DeflateConfigure,
    DeflateDescribe,
    DeflateSubtractBloat,
    DeflateCleanup,
    DeflateBuildConfigReq,
    DeflateDecodeConfigReq,
    DeflateSendResetReq,
    DeflateRecvResetReq,
    DeflateRecvResetAck,
    DeflateNegotiated,
    DeflateStat,
    NULL,
    NULL,
  };

/*
 * DeflateInit()
 */

static int
DeflateInit(int dir)
{
  DeflateInfo		const deflate = &bund->ccp.deflate;
  struct ng_deflate_config	conf;
  struct ngm_mkpeer	mp;
  char			path[NG_PATHLEN + 1];
  const char		*deflatehook, *ppphook;
  int			cmd;

  /* Initialize configuration structure */
  memset(&conf, 0, sizeof(conf));
  conf.enable = 1;
  cmd = NGM_DEFLATE_CONFIG;
  switch (dir) {
    case COMP_DIR_XMIT:
      ppphook = NG_PPP_HOOK_COMPRESS;
      deflatehook = NG_DEFLATE_HOOK_COMP;
      conf.windowBits = deflate->xmit_windowBits;
      break;
    case COMP_DIR_RECV:
      ppphook = NG_PPP_HOOK_DECOMPRESS;
      deflatehook = NG_DEFLATE_HOOK_DECOMP;
      conf.windowBits = deflate->recv_windowBits;
      break;
    default:
      assert(0);
      return(-1);
  }

  /* Attach a new DEFLATE node to the PPP node */
  snprintf(mp.type, sizeof(mp.type), "%s", NG_DEFLATE_NODE_TYPE);
  snprintf(mp.ourhook, sizeof(mp.ourhook), "%s", ppphook);
  snprintf(mp.peerhook, sizeof(mp.peerhook), "%s", deflatehook);
  if (NgSendMsg(bund->csock, MPD_HOOK_PPP,
      NGM_GENERIC_COOKIE, NGM_MKPEER, &mp, sizeof(mp)) < 0) {
    Log(LG_ERR, ("[%s] can't create %s node: %s",
      bund->name, mp.type, strerror(errno)));
    return(-1);
  }

  /* Configure DEFLATE node */
  snprintf(path, sizeof(path), "%s.%s", MPD_HOOK_PPP, ppphook);
  if (NgSendMsg(bund->csock, path,
      NGM_DEFLATE_COOKIE, cmd, &conf, sizeof(conf)) < 0) {
    Log(LG_ERR, ("[%s] can't config %s node at %s: %s",
      bund->name, NG_DEFLATE_NODE_TYPE, path, strerror(errno)));
    NgFuncDisconnect(MPD_HOOK_PPP, ppphook);
    return(-1);
  }

  return 0;
}

/*
 * DeflateConfigure()
 */

static void
DeflateConfigure(void)
{
  CcpState	const ccp = &bund->ccp;
  DeflateInfo	const deflate = &ccp->deflate;
  
  deflate->xmit_windowBits=15;
  deflate->recv_windowBits=0;
}

/*
 * DeflateCleanup()
 */

static char *
DeflateDescribe(int dir)
{
    CcpState	const ccp = &bund->ccp;
    DeflateInfo	const deflate = &ccp->deflate;
    static char str[64];

    switch (dir) {
	case COMP_DIR_XMIT:
	    snprintf(str,sizeof(str),"win %d",deflate->xmit_windowBits);
	    break;
	case COMP_DIR_RECV:
	    snprintf(str,sizeof(str),"win %d",deflate->recv_windowBits);
	    break;
	default:
    	    assert(0);
    	    return(NULL);
    }
    return (str);
};

/*
 * DeflateCleanup()
 */

void
DeflateCleanup(int dir)
{
  const char	*ppphook;
  char		path[NG_PATHLEN + 1];

  /* Remove node */
  switch (dir) {
    case COMP_DIR_XMIT:
      ppphook = NG_PPP_HOOK_COMPRESS;
      break;
    case COMP_DIR_RECV:
      ppphook = NG_PPP_HOOK_DECOMPRESS;
      break;
    default:
      assert(0);
      return;
  }
  snprintf(path, sizeof(path), "%s.%s", MPD_HOOK_PPP, ppphook);
  (void)NgFuncShutdownNode(bund, bund->name, path);
}

/*
 * DeflateRecvResetReq()
 */

static Mbuf
DeflateRecvResetReq(int id, Mbuf bp, int *noAck)
{
  char	path[NG_PATHLEN + 1];

  /* Forward ResetReq to the DEFLATE compression node */
  snprintf(path, sizeof(path), "%s.%s", MPD_HOOK_PPP, NG_PPP_HOOK_COMPRESS);
  if (NgSendMsg(bund->csock, path,
      NGM_DEFLATE_COOKIE, NGM_DEFLATE_RESETREQ, NULL, 0) < 0) {
    Log(LG_ERR, ("[%s] reset-req to %s node: %s",
      bund->name, NG_DEFLATE_NODE_TYPE, strerror(errno)));
  }
  return(NULL);
}

/*
 * DeflateSendResetReq()
 */

static Mbuf
DeflateSendResetReq(void)
{
  return(NULL);
}

/*
 * DeflateRecvResetAck()
 */

static void
DeflateRecvResetAck(int id, Mbuf bp)
{
  char	path[NG_PATHLEN + 1];

  /* Forward ResetReq to the DEFLATE compression node */
  snprintf(path, sizeof(path), "%s.%s", MPD_HOOK_PPP, NG_PPP_HOOK_DECOMPRESS);
  if (NgSendMsg(bund->csock, path,
      NGM_DEFLATE_COOKIE, NGM_DEFLATE_RESETREQ, NULL, 0) < 0) {
    Log(LG_ERR, ("[%s] reset-ack to %s node: %s",
      bund->name, NG_DEFLATE_NODE_TYPE, strerror(errno)));
  }
}

/*
 * DeflateBuildConfigReq()
 */

static u_char *
DeflateBuildConfigReq(u_char *cp, int *ok)
{
  CcpState	const ccp = &bund->ccp;
  DeflateInfo	const deflate = &ccp->deflate;
  u_int16_t	opt;
  
  if (deflate->xmit_windowBits > 0) {
    opt = ((deflate->xmit_windowBits-8)<<12) + (8<<8) + (0<<2) + 0;
  
    cp = FsmConfValue(cp, CCP_TY_DEFLATE, -2, &opt);
    *ok = 1;
  }
  return (cp);
}

/*
 * DeflateDecodeConfigReq()
 */

static void
DeflateDecodeConfigReq(Fsm fp, FsmOption opt, int mode)
{
  CcpState	const ccp = &bund->ccp;
  DeflateInfo	const deflate = &ccp->deflate;
  u_int16_t     o;
  u_char	window, method, chk;

  /* Sanity check */
  if (opt->len != 4) {
    Log(LG_CCP, ("   bogus length %d", opt->len));
    if (mode == MODE_REQ)
      FsmRej(fp, opt);
    return;
  }

  /* Get bits */
  memcpy(&o, opt->data, 2);
  o = ntohs(o);
  window = (o>>12)&0x000F;
  method = (o>>8)&0x000F;
  chk = o&0x0003;

  /* Display it */
  Log(LG_CCP, ("   0x%04x: w:%d, m:%d, c:%d", o, window, method, chk));

  /* Deal with it */
  switch (mode) {
    case MODE_REQ:
	if ((window > 0) && (window<=7) && (method == 8) && (chk == 0)) {
	    deflate->recv_windowBits = window + 8;
	    FsmAck(fp, opt);
	} else {
	    o = htons((7<<12) + (8<<8) + (0<<2) + 0);
	    memcpy(opt->data, &o, 2);
	    FsmNak(fp, opt);
	}
      break;

    case MODE_NAK:
	if ((window > 0) && (window<=7) && (method == 8) && (chk == 0))
	    deflate->xmit_windowBits = window + 8;
	else {
	    deflate->xmit_windowBits = 0;
	}
      break;
  }
}

/*
 * DeflateNegotiated()
 */

static int
DeflateNegotiated(int dir)
{
  return 1;
}

/*
 * DeflateSubtractBloat()
 */

static int
DeflateSubtractBloat(int size)
{
  return(size + CCP_OVERHEAD);  /* Compression compensate header size */
}

static int
DeflateStat(int dir) 
{
    char			path[NG_PATHLEN + 1];
    struct ng_deflate_stats	stats;
    union {
	u_char			buf[sizeof(struct ng_mesg) + sizeof(stats)];
	struct ng_mesg		reply;
    }				u;

    switch (dir) {
	case COMP_DIR_XMIT:
	    snprintf(path, sizeof(path), "mpd%d-%s:%s", gPid, bund->name,
		NG_PPP_HOOK_COMPRESS);
	    break;
	case COMP_DIR_RECV:
	    snprintf(path, sizeof(path), "mpd%d-%s:%s", gPid, bund->name,
		NG_PPP_HOOK_DECOMPRESS);
	    break;
	default:
	    assert(0);
    }
    if (NgFuncSendQuery(path, NGM_DEFLATE_COOKIE, NGM_DEFLATE_GET_STATS, NULL, 0, 
	&u.reply, sizeof(u), NULL) < 0) {
	    Log(LG_ERR, ("[%s] can't get %s stats: %s",
		bund->name, NG_BPF_NODE_TYPE, strerror(errno)));
	    return(0);
    }
    memcpy(&stats, u.reply.data, sizeof(stats));
    switch (dir) {
	case COMP_DIR_XMIT:
	    Printf("\t\tBytes: %llu -> %llu (%lld%%), Errors: %llu\r\n",
		stats.InOctets,
		stats.OutOctets,
		((stats.InOctets!=0)?
		    ((int64_t)(stats.InOctets - stats.OutOctets)*100/(int64_t)stats.InOctets):
		    0),
		stats.Errors);
	    break;
	case COMP_DIR_RECV:
	    Printf("\t\tBytes: %llu -> %llu (%lld%%), Errors: %llu\r\n",
		stats.InOctets,
		stats.OutOctets,
		((stats.OutOctets!=0)?
		    ((int64_t)(stats.OutOctets - stats.InOctets)*100/(int64_t)stats.OutOctets):
		    0),
		stats.Errors);
    	    break;
	default:
    	    assert(0);
    }
    return (0);
}

#endif /* USE_NG_DEFLATE */
