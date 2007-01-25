
/*
 * pptp.c
 *
 * Written by Archie Cobbs <archie@freebsd.org>
 * Copyright (c) 1998-1999 Whistle Communications, Inc. All rights reserved.
 * See ``COPYRIGHT.whistle''
 */

#include "ppp.h"
#include "phys.h"
#include "mbuf.h"
#include "ngfunc.h"
#include "pptp.h"
#include "pptp_ctrl.h"
#include "log.h"
#include "msgdef.h"

#include <netgraph/ng_message.h>
#ifdef __DragonFly__
#include <netgraph/socket/ng_socket.h>
#include <netgraph/ksocket/ng_ksocket.h>
#include <netgraph/pptpgre/ng_pptpgre.h>
#else
#include <netgraph/ng_socket.h>
#include <netgraph/ng_ksocket.h>
#include <netgraph/ng_pptpgre.h>
#endif
#include <netgraph.h>

/*
 * DEFINITIONS
 */

  #define PPTP_MRU		PPTP_MTU

  #define PPTP_MAX_ERRORS	10
  #define PPTP_REOPEN_PAUSE	5

  #define MAX_IOVEC		32

  #define PPTP_CALL_MIN_BPS	56000
  #define PPTP_CALL_MAX_BPS	64000

  struct pptpinfo {
    struct {
	struct u_range	peer_addr_req;	/* Peer IP addresses allowed */
	in_port_t	peer_port_req;	/* Peer port required (or zero) */
	struct optinfo	options;
	char		callingnum[64];	/* PPTP phone number to use */
	char		callednum[64];	/* PPTP phone number to use */
    } conf;
    u_char		originate:1;	/* Call originated locally */
    u_char		incoming:1;	/* Call is incoming vs. outgoing */
    struct u_addr	peer_addr;	/* Current peer IP address */
    in_port_t		peer_port;	/* Current peer port */
    char		callingnum[64];	/* PPTP phone number to use */
    char		callednum[64];	/* PPTP phone number to use */
    struct pptpctrlinfo	cinfo;
  };
  typedef struct pptpinfo	*PptpInfo;

  /* Set menu options */
  enum {
    SET_SELFADDR,
    SET_PEERADDR,
    SET_CALLINGNUM,
    SET_CALLEDNUM,
    SET_ENABLE,
    SET_DISABLE,
  };

  /* Binary options */
  enum {
    PPTP_CONF_ORIGINATE,	/* allow originating connections to peer */
    PPTP_CONF_INCOMING,		/* allow accepting connections from peer */
    PPTP_CONF_OUTCALL,		/* when originating, calls are "outgoing" */
    PPTP_CONF_DELAYED_ACK,	/* enable delayed receive ack algorithm */
#if NGM_PPTPGRE_COOKIE >= 942783547
    PPTP_CONF_ALWAYS_ACK,	/* include ack with all outgoing data packets */
#endif
#if NGM_PPTPGRE_COOKIE >= 1082548365
    PPTP_CONF_WINDOWING,	/* control (stupid) windowing algorithm */
#endif
  };

/*
 * INTERNAL FUNCTIONS
 */

  static int	PptpInit(PhysInfo p);
  static void	PptpOpen(PhysInfo p);
  static void	PptpClose(PhysInfo p);
  static void	PptpShutdown(PhysInfo p);
  static void	PptpStat(PhysInfo p);
  static int	PptpOriginated(PhysInfo p);
  static int	PptpPeerAddr(PhysInfo p, void *buf, int buf_len);
  static int	PptpCallingNum(PhysInfo p, void *buf, int buf_len);
  static int	PptpCalledNum(PhysInfo p, void *buf, int buf_len);

  static void	PptpInitCtrl(void);
  static int	PptpOriginate(PptpInfo pptp);
  static void	PptpDoClose(PhysInfo pptp);
  static void	PptpKillNode(PptpInfo pptp);
  static void	PptpResult(void *cookie, const char *errmsg);
  static void	PptpCancel(void *cookie);
  static int	PptpHookUp(PptpInfo pptp);

  static struct pptplinkinfo	PptpIncoming(struct pptpctrlinfo cinfo,
				  struct u_addr peer, in_port_t port, int bearType,
				  const char *callingNum,
				  const char *calledNum,
				  const char *subAddress);

  static struct pptplinkinfo	PptpOutgoing(struct pptpctrlinfo cinfo,
				  struct u_addr peer, in_port_t port, int bearType,
				  int frameType, int minBps, int maxBps,
				  const char *calledNum,
				  const char *subAddress);

  static struct pptplinkinfo	PptpPeerCall(struct pptpctrlinfo *cinfo,
				  struct u_addr peer, in_port_t port, int incoming,
				  const char *callingNum,
				  const char *calledNum,
				  const char *subAddress);

  static int	PptpSetCommand(int ac, char *av[], void *arg);

/*
 * GLOBAL VARIABLES
 */

  const struct phystype	gPptpPhysType = {
    .name		= "pptp",
    .synchronous	= TRUE,
    .minReopenDelay	= PPTP_REOPEN_PAUSE,
    .mtu		= PPTP_MTU,
    .mru		= PPTP_MRU,
    .init		= PptpInit,
    .open		= PptpOpen,
    .close		= PptpClose,
    .shutdown		= PptpShutdown,
    .showstat		= PptpStat,
    .originate		= PptpOriginated,
    .peeraddr		= PptpPeerAddr,
    .callingnum		= PptpCallingNum,
    .callednum		= PptpCalledNum,
  };

  const struct cmdtab	PptpSetCmds[] = {
    { "self ip [port]",			"Set local IP address",
	PptpSetCommand, NULL, (void *) SET_SELFADDR },
    { "peer ip [port]",			"Set remote IP address",
	PptpSetCommand, NULL, (void *) SET_PEERADDR },
    { "callingnum number",		"Set calling PPTP telephone number",
	PptpSetCommand, NULL, (void *) SET_CALLINGNUM },
    { "callednum number",		"Set called PPTP telephone number",
	PptpSetCommand, NULL, (void *) SET_CALLEDNUM },
    { "enable [opt ...]",		"Enable option",
	PptpSetCommand, NULL, (void *) SET_ENABLE },
    { "disable [opt ...]",		"Disable option",
	PptpSetCommand, NULL, (void *) SET_DISABLE },
    { NULL },
  };

/*
 * INTERNAL VARIABLES
 */

  static struct u_addr		gLocalIp = { AF_INET };
  static u_short		gLocalPort;
  static u_char			gInitialized;
  static struct confinfo	gConfList[] = {
    { 0,	PPTP_CONF_ORIGINATE,	"originate"	},
    { 0,	PPTP_CONF_INCOMING,	"incoming"	},
    { 0,	PPTP_CONF_OUTCALL,	"outcall"	},
    { 0,	PPTP_CONF_DELAYED_ACK,	"delayed-ack"	},
#if NGM_PPTPGRE_COOKIE >= 942783547
    { 0,	PPTP_CONF_ALWAYS_ACK,	"always-ack"	},
#endif
#if NGM_PPTPGRE_COOKIE >= 1082548365
    { 0,	PPTP_CONF_WINDOWING,	"windowing"	},
#endif
    { 0,	0,			NULL		},
  };

/*
 * PptpInit()
 */

static int
PptpInit(PhysInfo p)
{
  PptpInfo	pptp;
//  int		k;

  /* Only one PPTP link is allowed in a bundle XXX but this should be allowed */
/* XXX Why only one? Commented it out.
  for (k = 0; k < gNumLinks; k++) {
    if (gLinks[k] && gLinks[k] != lnk && gLinks[k]->bund == bund) {
      Log(LG_ERR, ("[%s] only one PPTP link allowed per bundle", lnk->name));
      return(-1);
    }
  }
*/

  /* Initialize this link */
  pptp = (PptpInfo) (p->info = Malloc(MB_PHYS, sizeof(*pptp)));
  Enable(&pptp->conf.options, PPTP_CONF_OUTCALL);
  Enable(&pptp->conf.options, PPTP_CONF_DELAYED_ACK);
#if NGM_PPTPGRE_COOKIE >= 1082548365
  Enable(&pptp->conf.options, PPTP_CONF_WINDOWING);
#endif
  return(0);
}

/*
 * PptpOpen()
 */

static void
PptpOpen(PhysInfo p)
{
  PptpInfo		const pptp = (PptpInfo) lnk->phys->info;

  /* Initialize if needed */
  if (!gInitialized)
    PptpInitCtrl();

  /* Check state */
  switch (p->state) {
    case PHYS_STATE_DOWN:
      if (!Enabled(&pptp->conf.options, PPTP_CONF_ORIGINATE)) {
	Log(LG_ERR, ("[%s] pptp originate option is not enabled", lnk->name));
	PhysDown(STR_DEV_NOT_READY, NULL);
	return;
      }
      if (PptpOriginate(pptp) < 0) {
	Log(LG_PHYS, ("[%s] PPTP call failed", lnk->name));
	PhysDown(STR_CON_FAILED0, NULL);
	return;
      }
      p->state = PHYS_STATE_CONNECTING;
      break;

    case PHYS_STATE_CONNECTING:
      if (pptp->originate)	/* our call to peer is already in progress */
	break;
      if (!pptp->incoming) {

	/* Hook up nodes */
	Log(LG_PHYS, ("[%s] attaching to peer's outgoing call", lnk->name));
	if (PptpHookUp(pptp) < 0) {
	  PptpDoClose(p);	/* We should not set state=DOWN as PptpResult() will be called once more */
	  break;
	}

	(*pptp->cinfo.answer)(pptp->cinfo.cookie,
	  PPTP_OCR_RESL_OK, 0, 0, 64000 /*XXX*/ );
	p->state = PHYS_STATE_UP;
	PhysUp();
	return;
      }
      return; 	/* wait for peer's incoming pptp call to complete */

    case PHYS_STATE_UP:
      PhysUp();
      return;

    default:
      assert(0);
  }
}

/*
 * PptpOriginate()
 *
 * Initiate an "incoming" or an "outgoing" call to the remote site
 */

static int
PptpOriginate(PptpInfo pptp)
{
  struct pptpctrlinfo	cinfo;
  struct pptplinkinfo	linfo;
  struct u_addr		ip = pptp->conf.peer_addr_req.addr;
  const u_short		port = pptp->conf.peer_port_req ?
			  pptp->conf.peer_port_req : PPTP_PORT;

  pptp->originate = TRUE;
  pptp->incoming = !Enabled(&pptp->conf.options, PPTP_CONF_OUTCALL);
  memset(&linfo, 0, sizeof(linfo));
  linfo.cookie = lnk;
  linfo.result = PptpResult;
  linfo.setLinkInfo = NULL;
  linfo.cancel = PptpCancel;
  strlcpy(pptp->callingnum, pptp->conf.callingnum, sizeof(pptp->callingnum));
  strlcpy(pptp->callednum, pptp->conf.callednum, sizeof(pptp->callednum));
  if (pptp->incoming)
    cinfo = PptpCtrlInCall(linfo, &gLocalIp, &ip, port,
      PPTP_BEARCAP_ANY, PPTP_FRAMECAP_SYNC,
      PPTP_CALL_MIN_BPS, PPTP_CALL_MAX_BPS, 
      pptp->callingnum, pptp->callednum, "");
  else
    cinfo = PptpCtrlOutCall(linfo, &gLocalIp, &ip, port,
      PPTP_BEARCAP_ANY, PPTP_FRAMECAP_SYNC,
      PPTP_CALL_MIN_BPS, PPTP_CALL_MAX_BPS,
      pptp->callednum, "");
  if (cinfo.cookie == NULL)
    return(-1);
  pptp->peer_addr = ip;
  pptp->peer_port = port;
  pptp->cinfo = cinfo;
  return(0);
}

/*
 * PptpClose()
 */

static void
PptpClose(PhysInfo p)
{
  PptpDoClose(p);
}

/*
 * PptpShutdown()
 */

static void
PptpShutdown(PhysInfo p)
{
  PptpInfo	const pptp = (PptpInfo) p->info;

  PptpKillNode(pptp);
}

/*
 * PptpDoClose()
 */

static void
PptpDoClose(PhysInfo p)
{
  PptpInfo      const pptp = (PptpInfo) p->info;

  if (p->state != PHYS_STATE_DOWN) {		/* avoid double close */
    (*pptp->cinfo.close)(pptp->cinfo.cookie, PPTP_CDN_RESL_ADMIN, 0, 0);
    PptpKillNode(pptp);
  }
}

/*
 * PptpKillNode()
 */

static void
PptpKillNode(PptpInfo pptp)
{
  char	path[NG_PATHLEN + 1];

  snprintf(path, sizeof(path), "%s.%s%d",
    MPD_HOOK_PPP, NG_PPP_HOOK_LINK_PREFIX, lnk->bundleIndex);
  NgFuncShutdownNode(bund, lnk->name, path);
}

/*
 * PptpOriginated()
 */

static int
PptpOriginated(PhysInfo p)
{
  PptpInfo	const pptp = (PptpInfo) lnk->phys->info;

  return(pptp->originate ? LINK_ORIGINATE_LOCAL : LINK_ORIGINATE_REMOTE);
}

static int
PptpPeerAddr(PhysInfo p, void *buf, int buf_len)
{
  PptpInfo	const pptp = (PptpInfo) p->info;

  if (u_addrtoa(&pptp->peer_addr, buf, buf_len))
    return(0);
  else
    return(-1);
}

static int
PptpCallingNum(PhysInfo p, void *buf, int buf_len)
{
    PptpInfo	const pptp = (PptpInfo) p->info;

    strlcpy((char*)buf, pptp->callingnum, buf_len);
    return(0);
}

static int
PptpCalledNum(PhysInfo p, void *buf, int buf_len)
{
    PptpInfo	const pptp = (PptpInfo) p->info;

    strlcpy((char*)buf, pptp->callednum, buf_len);
    return(0);
}

/*
 * PptpStat()
 */

void
PptpStat(PhysInfo p)
{
  PptpInfo	const pptp = (PptpInfo) lnk->phys->info;
  char		buf[32];

  Printf("PPTP configuration:\r\n");
  Printf("\tSelf addr    : %s",
    u_addrtoa(&gLocalIp, buf, sizeof(buf)));
  if (gLocalPort)
    Printf(", port %u", gLocalPort);
  Printf("\r\n");
  Printf("\tPeer range   : %s",
    u_rangetoa(&pptp->conf.peer_addr_req, buf, sizeof(buf)));
  if (pptp->conf.peer_port_req)
    Printf(", port %u", pptp->conf.peer_port_req);
  Printf("\r\n");
  Printf("\tCalling number: %s\r\n", pptp->conf.callingnum);
  Printf("\tCalled number: %s\r\n", pptp->conf.callednum);
  Printf("PPTP options:\r\n");
  OptStat(&pptp->conf.options, gConfList);
  Printf("PPTP status:\r\n");
  Printf("\tState        : %s\r\n", gPhysStateNames[p->state]);
  if (p->state != PHYS_STATE_DOWN) {
    Printf("\tIncoming     : %s\r\n", (pptp->originate?"NO":"YES"));
    Printf("\tCurrent peer : %s, port %u\r\n",
	u_addrtoa(&pptp->peer_addr, buf, sizeof(buf)), pptp->peer_port);
    Printf("\tCalling number: %s\r\n", pptp->callingnum);
    Printf("\tCalled number: %s\r\n", pptp->callednum);
  }
}

/*
 * PptpInitCtrl()
 */

static void
PptpInitCtrl(void)
{
#if 0
  if (gLocalIp.s_addr == 0)
    GetAnyIpAddress(&gLocalIp, NULL);
#endif
  if (PptpCtrlInit(PptpIncoming, PptpOutgoing, gLocalIp) < 0) {
    Log(LG_ERR, ("[%s] PPTP ctrl init failed", lnk->name));
    return;
  }
  gInitialized = TRUE;
}

/*
 * PptpResult()
 *
 * The control code calls this function to report a PPTP link
 * being connected, disconnected, or failing to connect.
 */

static void
PptpResult(void *cookie, const char *errmsg)
{
  PptpInfo	pptp;
  PhysInfo 	p;

  /* It this fake call? */
  if (!cookie)
    return;

  lnk = (Link) cookie;
  bund = lnk->bund;
  p = lnk->phys;
  pptp = (PptpInfo) lnk->phys->info;

  switch (p->state) {
    case PHYS_STATE_CONNECTING:
      if (!errmsg) {

	/* Hook up nodes */
	Log(LG_PHYS, ("[%s] PPTP call successful", lnk->name));
	if (PptpHookUp(pptp) < 0) {
	  PptpDoClose(p); /* We should not set state=DOWN as PptpResult() will be called once more */
	  break;
	}

	/* OK */
	p->state = PHYS_STATE_UP;
	PhysUp();
      } else {
	Log(LG_PHYS, ("[%s] PPTP call failed", lnk->name));
	PhysDown(STR_CON_FAILED, "%s", errmsg);
	p->state = PHYS_STATE_DOWN;
	u_addrclear(&pptp->peer_addr);
	pptp->peer_port = 0;
        pptp->callingnum[0]=0;
        pptp->callednum[0]=0;
      }
      break;
    case PHYS_STATE_UP:
      assert(errmsg);
      Log(LG_PHYS, ("[%s] PPTP call terminated", lnk->name));
      PptpDoClose(p);
      PhysDown(0, NULL);
      p->state = PHYS_STATE_DOWN;
      u_addrclear(&pptp->peer_addr);
      pptp->peer_port = 0;
      pptp->callingnum[0]=0;
      pptp->callednum[0]=0;
      break;
    case PHYS_STATE_DOWN:
      return;
    default:
      assert(0);
  }
}

/*
 * PptpHookUp()
 *
 * Connect the PPTP/GRE node to the PPP node
 */

static int
PptpHookUp(PptpInfo pptp)
{
  char	        		ksockpath[NG_PATHLEN+1];
  char	        		pptppath[NG_PATHLEN+1];
  struct ngm_mkpeer		mkp;
  struct ng_pptpgre_conf	gc;
  struct sockaddr_storage	self_addr, peer_addr;
  struct u_addr			u_self_addr, u_peer_addr;
  union {
	u_char buf[sizeof(struct ng_ksocket_sockopt) + sizeof(int)];
	struct ng_ksocket_sockopt ksso;
  } u;
  struct ng_ksocket_sockopt *const ksso = &u.ksso;

  /* Get session info */
  memset(&gc, 0, sizeof(gc));
  PptpCtrlGetSessionInfo(&pptp->cinfo, &u_self_addr,
    &u_peer_addr, &gc.cid, &gc.peerCid, &gc.recvWin, &gc.peerPpd);
    
  u_addrtosockaddr(&u_self_addr, 0, &self_addr);
  u_addrtosockaddr(&u_peer_addr, 0, &peer_addr);

  /* Attach PPTP/GRE node to PPP node */
  snprintf(mkp.type, sizeof(mkp.type), "%s", NG_PPTPGRE_NODE_TYPE);
  snprintf(mkp.ourhook, sizeof(mkp.ourhook),
    "%s%d", NG_PPP_HOOK_LINK_PREFIX, lnk->bundleIndex);
  snprintf(mkp.peerhook, sizeof(mkp.peerhook),
    "%s", NG_PPTPGRE_HOOK_UPPER);
  if (NgSendMsg(bund->csock, MPD_HOOK_PPP, NGM_GENERIC_COOKIE,
      NGM_MKPEER, &mkp, sizeof(mkp)) < 0) {
    Log(LG_ERR, ("[%s] can't attach %s node: %s",
      lnk->name, NG_PPTPGRE_NODE_TYPE, strerror(errno)));
    return(-1);
  }
  snprintf(pptppath, sizeof(pptppath), "%s.%s", MPD_HOOK_PPP, mkp.ourhook);

  /* Attach ksocket node to PPTP/GRE node */
  snprintf(mkp.type, sizeof(mkp.type), "%s", NG_KSOCKET_NODE_TYPE);
  snprintf(mkp.ourhook, sizeof(mkp.ourhook), "%s", NG_PPTPGRE_HOOK_LOWER);
  if (u_self_addr.family==AF_INET6) {
    //ng_ksocket doesn't support inet6 name
    snprintf(mkp.peerhook, sizeof(mkp.peerhook), "%d/%d/%d", PF_INET6, SOCK_RAW, IPPROTO_GRE); 
  } else {
    snprintf(mkp.peerhook, sizeof(mkp.peerhook), "inet/raw/gre");
  }
  if (NgSendMsg(bund->csock, pptppath, NGM_GENERIC_COOKIE,
      NGM_MKPEER, &mkp, sizeof(mkp)) < 0) {
    Log(LG_ERR, ("[%s] can't attach %s node: %s",
      lnk->name, NG_KSOCKET_NODE_TYPE, strerror(errno)));
    return(-1);
  }
  snprintf(ksockpath, sizeof(ksockpath),
    "%s.%s", pptppath, NG_PPTPGRE_HOOK_LOWER);

    /* increase recvspace to avoid packet loss due to very small GRE recv buffer. */
    ksso->level=SOL_SOCKET;
    ksso->name=SO_RCVBUF;
    ((int *)(ksso->value))[0]=48*1024;
    if (NgSendMsg(bund->csock, ksockpath, NGM_KSOCKET_COOKIE,
	NGM_KSOCKET_SETOPT, &u, sizeof(u)) < 0) {
	    Log(LG_ERR, ("[%s] can't setsockopt %s node: %s",
		lnk->name, NG_KSOCKET_NODE_TYPE, strerror(errno)));
    }

  /* Bind ksocket socket to local IP address */
  if (NgSendMsg(bund->csock, ksockpath, NGM_KSOCKET_COOKIE,
      NGM_KSOCKET_BIND, &self_addr, self_addr.ss_len) < 0) {
    Log(LG_ERR, ("[%s] can't bind() %s node: %s",
      lnk->name, NG_KSOCKET_NODE_TYPE, strerror(errno)));
    return(-1);
  }

  /* Connect ksocket socket to remote IP address */
  if (NgSendMsg(bund->csock, ksockpath, NGM_KSOCKET_COOKIE,
      NGM_KSOCKET_CONNECT, &peer_addr, peer_addr.ss_len) < 0
      && errno != EINPROGRESS) {	/* happens in -current (weird) */
    Log(LG_ERR, ("[%s] can't connect() %s node: %s",
      lnk->name, NG_KSOCKET_NODE_TYPE, strerror(errno)));
    return(-1);
  }

  /* Configure PPTP/GRE node */
  gc.enabled = 1;
  gc.enableDelayedAck = Enabled(&pptp->conf.options, PPTP_CONF_DELAYED_ACK);
#if NGM_PPTPGRE_COOKIE >= 942783547
  gc.enableAlwaysAck = Enabled(&pptp->conf.options, PPTP_CONF_ALWAYS_ACK);
#endif
#if NGM_PPTPGRE_COOKIE >= 1082548365
  gc.enableWindowing = Enabled(&pptp->conf.options, PPTP_CONF_WINDOWING);
#endif

  if (NgSendMsg(bund->csock, pptppath, NGM_PPTPGRE_COOKIE,
      NGM_PPTPGRE_SET_CONFIG, &gc, sizeof(gc)) < 0) {
    Log(LG_ERR, ("[%s] can't config %s node: %s",
      lnk->name, NG_PPTPGRE_NODE_TYPE, strerror(errno)));
    return(-1);
  }

  /* Done */
  return(0);
}

/*
 * PptpIncoming()
 *
 * The control code calls this function to report that some
 * remote PPTP client has asked us if we will accept an incoming
 * call relayed over PPTP.
 */

static struct pptplinkinfo
PptpIncoming(struct pptpctrlinfo cinfo,
	struct u_addr peer, in_port_t port, int bearType,
	const char *callingNum,
	const char *calledNum,
	const char *subAddress)
{
  return(PptpPeerCall(&cinfo, peer, port, TRUE, callingNum, calledNum, subAddress));
}

/*
 * PptpOutgoing()
 *
 * The control code calls this function to report that some
 * remote PPTP client has asked us if we will dial out to some
 * phone number. We don't actually do this, but some clients
 * initiate their connections as outgoing calls for some reason.
 */

static struct pptplinkinfo
PptpOutgoing(struct pptpctrlinfo cinfo,
	struct u_addr peer, in_port_t port, int bearType,
	int frameType, int minBps, int maxBps,
	const char *calledNum, const char *subAddress)
{
  return(PptpPeerCall(&cinfo, peer, port, FALSE, "", calledNum, subAddress));
}

/*
 * PptpPeerCall()
 *
 * Peer has initiated a call (either incoming or outgoing; either
 * way it's the same to us). If we have an available link that may
 * accept calls from the peer's IP addresss and port, then say yes.
 */

static struct pptplinkinfo
PptpPeerCall(struct pptpctrlinfo *cinfo,
	struct u_addr peer, in_port_t port, int incoming,
	const char *callingNum,
	const char *calledNum,
	const char *subAddress)
{
  struct pptplinkinfo	linfo;
  Link			l = NULL;
  PptpInfo		pptp = NULL;
  int			k;
  time_t  		now = time(NULL);

  memset(&linfo, 0, sizeof(linfo));

  linfo.cookie = NULL;
  linfo.result = PptpResult;
  linfo.setLinkInfo = NULL;
  linfo.cancel = PptpCancel;

  if (gShutdownInProgress) {
    Log(LG_PHYS, ("Shutdown sequence in progress, ignoring"));
    return(linfo);
  }

  /* Find a suitable link; prefer the link best matching peer's IP address */
  for (k = 0; k < gNumLinks; k++) {
    Link	const l2 = gLinks[k];
    PptpInfo	pptp2 = (PptpInfo) l2->phys->info;

    /* See if link is feasible */
    if (l2 != NULL
	&& l2->phys->type == &gPptpPhysType
	&& l2->phys->state == PHYS_STATE_DOWN
	&& (now - l2->phys->lastClose) >= PPTP_REOPEN_PAUSE
	&& Enabled(&pptp2->conf.options, PPTP_CONF_INCOMING)
	&& IpAddrInRange(&pptp2->conf.peer_addr_req, &peer)
	&& (!pptp2->conf.peer_port_req || pptp2->conf.peer_port_req == port)) {

      /* Link is feasible; now see if it's preferable */
      if (!pptp || pptp2->conf.peer_addr_req.width > pptp->conf.peer_addr_req.width) {
	l = l2;
	pptp = pptp2;
      }
    }
  }

  /* If no link is suitable, can't take the call */
  if (l == NULL) {
    Log(LG_PHYS, ("No free PPTP link with requested parameters "
	"was found"));
    return(linfo);
  }

  /* Open link to pick up the call */
  lnk = l;
  bund = lnk->bund;

  Log(LG_PHYS, ("[%s] Accepting PPTP connection", lnk->name));
  BundOpenLink(lnk);

  /* Got one */
  linfo.cookie = lnk;
  lnk->phys->state = PHYS_STATE_CONNECTING;
  pptp->cinfo = *cinfo;
  pptp->originate = FALSE;
  pptp->incoming = incoming;
  pptp->peer_addr = peer;
  pptp->peer_port = port;
  strlcpy(pptp->callingnum, callingNum, sizeof(pptp->callingnum));
  strlcpy(pptp->callednum, calledNum, sizeof(pptp->callednum));
  return(linfo);
}

/*
 * PptpCancel()
 *
 * The control code calls this function to cancel a
 * local outgoing call in progress.
 */

static void
PptpCancel(void *cookie)
{
  PptpInfo	pptp;
  PhysInfo 	p;

  /* It this fake call? */
  if (!cookie)
    return;

  lnk = (Link) cookie;
  bund = lnk->bund;
  p = lnk->phys;
  pptp = (PptpInfo) lnk->phys->info;

  Log(LG_PHYS, ("[%s] PPTP call cancelled in state %s",
    lnk->name, gPhysStateNames[p->state]));
  if (p->state == PHYS_STATE_DOWN)
    return;
  PhysDown(STR_CON_FAILED0, NULL);
  p->state = PHYS_STATE_DOWN;
  u_addrclear(&pptp->peer_addr);
  pptp->peer_port = 0;
  pptp->callingnum[0]=0;
  pptp->callednum[0]=0;
}

/*
 * PptpListenUpdate()
 */

static void
PptpListenUpdate(void)
{
  int	allow_incoming = 0;
  int	allow_multiple = 1;
  int	k;

  /* Examine all PPTP links */
  for (k = 0; k < gNumLinks; k++) {
    if (gLinks[k] && gLinks[k]->phys->type == &gPptpPhysType) {
      PptpInfo	const p = (PptpInfo)gLinks[k]->phys->info;

      if (Enabled(&p->conf.options, PPTP_CONF_INCOMING))
	allow_incoming = 1;
      if (Enabled(&p->conf.options, PPTP_CONF_ORIGINATE)
	  && u_rangeempty(&p->conf.peer_addr_req))
	allow_multiple = 0;
    }
  }

  /* Initialize first time */
  if (!gInitialized) {
    if (!allow_incoming)
      return;		/* wait till later; we may not have an IP address yet */
    PptpInitCtrl();
  }

  /* Set up listening for incoming connections */
  PptpCtrlListen(allow_incoming, gLocalPort, allow_multiple);
}

/*
 * PptpSetCommand()
 */

static int
PptpSetCommand(int ac, char *av[], void *arg)
{
  PptpInfo		const pptp = (PptpInfo) lnk->phys->info;
  struct u_range	rng;
  int			port;

  switch ((intptr_t)arg) {
    case SET_SELFADDR:
    case SET_PEERADDR:
      if (ac < 1 || ac > 2 || !ParseRange(av[0], &rng, ALLOW_IPV4|ALLOW_IPV6))
	return(-1);
      if (ac > 1) {
	if ((port = atoi(av[1])) < 0 || port > 0xffff)
	  return(-1);
      } else {
	port = 0;
      }
      if ((intptr_t)arg == SET_SELFADDR) {
	gLocalIp = rng.addr;
	gLocalPort = port;
      } else {
	pptp->conf.peer_addr_req = rng;
	pptp->conf.peer_port_req = port;
      }
      PptpListenUpdate();
      break;
    case SET_CALLINGNUM:
      if (ac != 1)
	return(-1);
      snprintf(pptp->conf.callingnum, sizeof(pptp->conf.callingnum), "%s", av[0]);
      break;
    case SET_CALLEDNUM:
      if (ac != 1)
	return(-1);
      snprintf(pptp->conf.callednum, sizeof(pptp->conf.callednum), "%s", av[0]);
      break;
    case SET_ENABLE:
      EnableCommand(ac, av, &pptp->conf.options, gConfList);
      PptpListenUpdate();
      break;
    case SET_DISABLE:
      DisableCommand(ac, av, &pptp->conf.options, gConfList);
      PptpListenUpdate();
      break;
    default:
      assert(0);
  }
  return(0);
}

