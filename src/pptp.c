
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

#include <netgraph/ng_socket.h>
#include <netgraph/ng_message.h>
#include <netgraph/ng_ksocket.h>
#include <netgraph/ng_pptpgre.h>
#include <netgraph.h>

/*
 * DEFINITIONS
 */

  #define PPTP_MRU		PPTP_MTU

  #define PPTP_MAX_ERRORS	10
  #define PPTP_REOPEN_PAUSE	8

  #define PPTP_STATE_DOWN	0
  #define PPTP_STATE_CONNECTING	1
  #define PPTP_STATE_UP		2

  #define MAX_IOVEC		32

  #define PPTP_CALL_MIN_BPS	56000
  #define PPTP_CALL_MAX_BPS	64000

  struct pptpinfo {
    int			state;		/* PPTP link state */
    u_char		originate:1;	/* Call originated locally */
    u_char		incoming:1;	/* Call is incoming vs. outgoing */
    struct in_range	peer_addr_req;	/* Peer IP addresses allowed */
    struct in_addr	peer_addr;	/* Current peer IP address */
    u_short		peer_port_req;	/* Peer port required (or zero) */
    u_short		peer_port;	/* Current peer port */
    struct optinfo	options;
    struct pptpctrlinfo	cinfo;
    char		phonenum[64];	/* PPTP phone number to use */
  };
  typedef struct pptpinfo	*PptpInfo;

  /* Set menu options */
  enum {
    SET_SELFADDR,
    SET_PEERADDR,
    SET_PHONENUM,
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

  static void	PptpInitCtrl(void);
  static int	PptpOriginate(PptpInfo pptp);
  static void	PptpDoClose(PptpInfo pptp);
  static void	PptpKillNode(PptpInfo pptp);
  static void	PptpResult(void *cookie, const char *errmsg);
  static void	PptpCancel(void *cookie);
  static int	PptpHookUp(PptpInfo pptp);

  static struct pptplinkinfo	PptpIncoming(struct pptpctrlinfo cinfo,
				  struct in_addr peer, int port, int bearType,
				  const char *callingNum,
				  const char *calledNum,
				  const char *subAddress);

  static struct pptplinkinfo	PptpOutgoing(struct pptpctrlinfo cinfo,
				  struct in_addr peer, int port, int bearType,
				  int frameType, int minBps, int maxBps,
				  const char *calledNum,
				  const char *subAddress);

  static struct pptplinkinfo	PptpPeerCall(struct pptpctrlinfo *cinfo,
				  struct in_addr peer, int port, int incoming);

  static int	PptpSetCommand(int ac, char *av[], void *arg);

/*
 * GLOBAL VARIABLES
 */

  const struct phystype	gPptpPhysType = {
    "pptp",
    TRUE, PPTP_REOPEN_PAUSE,
    PPTP_MTU, PPTP_MRU,
    PptpInit,
    PptpOpen,
    PptpClose,
    NULL,
    PptpShutdown,
    PptpStat,
    PptpOriginated,
    PptpPeerAddr,
  };

  const struct cmdtab	PptpSetCmds[] = {
    { "self ip [port]",			"Set local IP address",
	PptpSetCommand, NULL, (void *) SET_SELFADDR },
    { "peer ip [port]",			"Set remote IP address",
	PptpSetCommand, NULL, (void *) SET_PEERADDR },
    { "phonenum number",		"Set PPTP telephone number",
	PptpSetCommand, NULL, (void *) SET_PHONENUM },
    { "enable [opt ...]",		"Enable option",
	PptpSetCommand, NULL, (void *) SET_ENABLE },
    { "disable [opt ...]",		"Disable option",
	PptpSetCommand, NULL, (void *) SET_DISABLE },
    { NULL },
  };

/*
 * INTERNAL VARIABLES
 */

  static struct in_addr		gLocalIp;
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

  static const char		*gPptpStateNames[] = {
    "DOWN",
    "CONNECTING",
    "UP",
  };

/*
 * PptpInit()
 */

static int
PptpInit(PhysInfo p)
{
  PptpInfo	pptp;
  int		k;

  /* Only one PPTP link is allowed in a bundle XXX but this should be allowed */
  for (k = 0; k < gNumLinks; k++) {
    if (gLinks[k] && gLinks[k] != lnk && gLinks[k]->bund == bund) {
      Log(LG_ERR, ("[%s] only one PPTP link allowed per bundle", lnk->name));
      return(-1);
    }
  }

  /* Initialize this link */
  pptp = (PptpInfo) (p->info = Malloc(MB_PHYS, sizeof(*pptp)));
  Enable(&pptp->options, PPTP_CONF_OUTCALL);
  Enable(&pptp->options, PPTP_CONF_DELAYED_ACK);
#if NGM_PPTPGRE_COOKIE >= 1082548365
  Enable(&pptp->options, PPTP_CONF_WINDOWING);
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
  switch (pptp->state) {
    case PPTP_STATE_DOWN:
      if (!Enabled(&pptp->options, PPTP_CONF_ORIGINATE)) {
	Log(LG_ERR, ("[%s] pptp originate option is not enabled", lnk->name));
	PhysDown(STR_DEV_NOT_READY, NULL);
	return;
      }
      if (PptpOriginate(pptp) < 0) {
	Log(LG_ERR, ("[%s] PPTP call failed", lnk->name));
	PhysDown(STR_CON_FAILED0, NULL);
	return;
      }
      pptp->state = PPTP_STATE_CONNECTING;
      break;

    case PPTP_STATE_CONNECTING:
      if (pptp->originate)	/* our call to peer is already in progress */
	break;
      if (!pptp->incoming) {

	/* Hook up nodes */
	Log(LG_PHYS, ("[%s] attaching to peer's outgoing call", lnk->name));
	if (PptpHookUp(pptp) < 0) {
	  PptpDoClose(pptp);
	  PhysDown(STR_ERROR, NULL);
	  break;
	}

	(*pptp->cinfo.answer)(pptp->cinfo.cookie,
	  PPTP_OCR_RESL_OK, 0, 0, 64000 /*XXX*/ );
	pptp->state = PPTP_STATE_UP;
	PhysUp();
	return;
      }
      return; 	/* wait for peer's incoming pptp call to complete */

    case PPTP_STATE_UP:
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
  const struct in_addr	ip = pptp->peer_addr_req.ipaddr;
  const u_short		port = pptp->peer_port_req ?
			  pptp->peer_port_req : PPTP_PORT;

  assert(pptp->state == PPTP_STATE_DOWN);
  pptp->originate = TRUE;
  pptp->incoming = !Enabled(&pptp->options, PPTP_CONF_OUTCALL);
  memset(&linfo, 0, sizeof(linfo));
  linfo.cookie = lnk;
  linfo.result = PptpResult;
  linfo.setLinkInfo = NULL;
  linfo.cancel = PptpCancel;
  if (pptp->incoming)
    cinfo = PptpCtrlInCall(linfo, gLocalIp, ip, port,
      PPTP_BEARCAP_ANY, PPTP_FRAMECAP_SYNC,
      PPTP_CALL_MIN_BPS, PPTP_CALL_MAX_BPS, inet_ntoa(gLocalIp), "", "");
  else
    cinfo = PptpCtrlOutCall(linfo, gLocalIp, ip, port,
      PPTP_BEARCAP_ANY, PPTP_FRAMECAP_SYNC,
      PPTP_CALL_MIN_BPS, PPTP_CALL_MAX_BPS, pptp->phonenum, "");
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
  PptpInfo	const pptp = (PptpInfo) p->info;

  PptpDoClose(pptp);
  PhysDown(0, NULL);
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
PptpDoClose(PptpInfo pptp)
{
  if (pptp->state != PPTP_STATE_DOWN) {		/* avoid double close */
    (*pptp->cinfo.close)(pptp->cinfo.cookie, PPTP_CDN_RESL_ADMIN, 0, 0);
    PptpKillNode(pptp);
    pptp->state = PPTP_STATE_DOWN;
  }
  if (!Enabled(&pptp->options, PPTP_CONF_ORIGINATE))	/* XXX necessary ? */
    IfaceClose();
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

static int
PptpOriginated(PhysInfo p)
{
  PptpInfo	const pptp = (PptpInfo) lnk->phys->info;

  return(pptp->originate ? LINK_ORIGINATE_LOCAL : LINK_ORIGINATE_REMOTE);
}

static int
PptpPeerAddr(PhysInfo p, void *buf, int buf_len)
{
  PptpInfo	const pptp = (PptpInfo) p;

  if (inet_ntop(AF_INET, &pptp->peer_addr, buf, buf_len))
    return(0);
  else
    return(-1);
}

/*
 * PptpOriginated()
 */


/*
 * PptpStat()
 */

void
PptpStat(PhysInfo p)
{
  PptpInfo	const pptp = (PptpInfo) lnk->phys->info;

  printf("PPTP status:\n");
  printf("\tConnection   : %s\n", gPptpStateNames[pptp->state]);
  printf("\tPeer range   : %s/%d",
    inet_ntoa(pptp->peer_addr_req.ipaddr), pptp->peer_addr_req.width);
  if (pptp->peer_port_req)
    printf(", port %u", pptp->peer_port_req);
  printf("\n");
  printf("\tCurrent peer : %s, port %u\n",
    inet_ntoa(pptp->peer_addr), pptp->peer_port);
  printf("PPTP options:\n");
  OptStat(&pptp->options, gConfList);
}

/*
 * PptpInitCtrl()
 */

static void
PptpInitCtrl(void)
{
#if 0
  if (gLocalIp.s_addr == 0)
    IfaceGetAnyIpAddress(&gLocalIp);
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

  lnk = (Link) cookie;
  bund = lnk->bund;
  pptp = (PptpInfo) lnk->phys->info;

  switch (pptp->state) {
    case PPTP_STATE_CONNECTING:
      if (!errmsg) {

	/* Hook up nodes */
	Log(LG_PHYS, ("[%s] PPTP call successful", lnk->name));
	if (PptpHookUp(pptp) < 0) {
	  PptpDoClose(pptp);
	  PhysDown(STR_ERROR, NULL);
	  break;
	}

	/* OK */
	pptp->state = PPTP_STATE_UP;
	PhysUp();
      } else {
	Log(LG_PHYS, ("[%s] PPTP call failed", lnk->name));
	PhysDown(STR_CON_FAILED, "%s", errmsg);
	pptp->state = PPTP_STATE_DOWN;
	pptp->peer_addr.s_addr = 0;
	pptp->peer_port = 0;
      }
      break;
    case PPTP_STATE_UP:
      assert(errmsg);
      Log(LG_PHYS, ("[%s] PPTP call terminated", lnk->name));
      PptpDoClose(pptp);
      PhysDown(0, NULL);
      pptp->state = PPTP_STATE_DOWN;
      pptp->peer_addr.s_addr = 0;
      pptp->peer_port = 0;
      if (!Enabled(&pptp->options, PPTP_CONF_ORIGINATE))
	IfaceClose();
      break;
    case PPTP_STATE_DOWN:
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
  struct sockaddr_in		self_addr, peer_addr;

  /* Get session info */
  memset(&self_addr, 0, sizeof(self_addr));
  self_addr.sin_family = AF_INET;
  self_addr.sin_len = sizeof(self_addr);
  peer_addr = self_addr;
  memset(&gc, 0, sizeof(gc));
  PptpCtrlGetSessionInfo(&pptp->cinfo, &self_addr.sin_addr,
    &peer_addr.sin_addr, &gc.cid, &gc.peerCid, &gc.recvWin, &gc.peerPpd);

  /* Attach PPTP/GRE node to PPP node */
  snprintf(mkp.type, sizeof(mkp.type), "%s", NG_PPTPGRE_NODE_TYPE);
  snprintf(mkp.ourhook, sizeof(mkp.ourhook),
    "%s%d", NG_PPP_HOOK_LINK_PREFIX, lnk->bundleIndex);
  snprintf(mkp.peerhook, sizeof(mkp.peerhook),
    "%s", NG_PPTPGRE_HOOK_UPPER);
  if (NgSendMsg(bund->csock, MPD_HOOK_PPP, NGM_GENERIC_COOKIE,
      NGM_MKPEER, &mkp, sizeof(mkp)) < 0) {
    Log(LG_PHYS, ("[%s] can't attach %s node: %s",
      lnk->name, NG_PPTPGRE_NODE_TYPE, strerror(errno)));
    return(-1);
  }
  snprintf(pptppath, sizeof(pptppath), "%s.%s", MPD_HOOK_PPP, mkp.ourhook);

  /* Attach ksocket node to PPTP/GRE node */
  snprintf(mkp.type, sizeof(mkp.type), "%s", NG_KSOCKET_NODE_TYPE);
  snprintf(mkp.ourhook, sizeof(mkp.ourhook), "%s", NG_PPTPGRE_HOOK_LOWER);
  snprintf(mkp.peerhook, sizeof(mkp.peerhook), "inet/raw/gre");
  if (NgSendMsg(bund->csock, pptppath, NGM_GENERIC_COOKIE,
      NGM_MKPEER, &mkp, sizeof(mkp)) < 0) {
    Log(LG_PHYS, ("[%s] can't attach %s node: %s",
      lnk->name, NG_KSOCKET_NODE_TYPE, strerror(errno)));
    return(-1);
  }
  snprintf(ksockpath, sizeof(ksockpath),
    "%s.%s", pptppath, NG_PPTPGRE_HOOK_LOWER);

  /* Bind ksocket socket to local IP address */
  if (NgSendMsg(bund->csock, ksockpath, NGM_KSOCKET_COOKIE,
      NGM_KSOCKET_BIND, &self_addr, sizeof(self_addr)) < 0) {
    Log(LG_PHYS, ("[%s] can't bind %s node: %s",
      lnk->name, NG_KSOCKET_NODE_TYPE, strerror(errno)));
    return(-1);
  }

  /* Connect ksocket socket to remote IP address */
  if (NgSendMsg(bund->csock, ksockpath, NGM_KSOCKET_COOKIE,
      NGM_KSOCKET_CONNECT, &peer_addr, sizeof(peer_addr)) < 0
      && errno != EINPROGRESS) {	/* happens in -current (weird) */
    Log(LG_PHYS, ("[%s] can't connect %s node: %s",
      lnk->name, NG_KSOCKET_NODE_TYPE, strerror(errno)));
    return(-1);
  }

  /* Configure PPTP/GRE node */
  gc.enabled = 1;
  gc.enableDelayedAck = Enabled(&pptp->options, PPTP_CONF_DELAYED_ACK);
#if NGM_PPTPGRE_COOKIE >= 942783547
  gc.enableAlwaysAck = Enabled(&pptp->options, PPTP_CONF_ALWAYS_ACK);
#endif
#if NGM_PPTPGRE_COOKIE >= 1082548365
  gc.enableWindowing = Enabled(&pptp->options, PPTP_CONF_WINDOWING);
#endif

  if (NgSendMsg(bund->csock, pptppath, NGM_PPTPGRE_COOKIE,
      NGM_PPTPGRE_SET_CONFIG, &gc, sizeof(gc)) < 0) {
    Log(LG_PHYS, ("[%s] can't config %s node: %s",
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
	struct in_addr peer, int port, int bearType,
	const char *callingNum,
	const char *calledNum,
	const char *subAddress)
{
  return(PptpPeerCall(&cinfo, peer, port, TRUE));
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
	struct in_addr peer, int port, int bearType,
	int frameType, int minBps, int maxBps,
	const char *calledNum, const char *subAddress)
{
  return(PptpPeerCall(&cinfo, peer, port, FALSE));
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
	struct in_addr peer, int port, int incoming)
{
  struct pptplinkinfo	linfo;
  Link			l = NULL;
  PptpInfo		pptp = NULL;
  int			k;

  /* Find a suitable link; prefer the link best matching peer's IP address */
  memset(&linfo, 0, sizeof(linfo));
  for (k = 0; k < gNumLinks; k++) {
    Link	const l2 = gLinks[k];
    PptpInfo	pptp2;

    /* See if link is feasible */
    if (l2 != NULL
	&& l2->phys->type == &gPptpPhysType
	&& (pptp2 = (PptpInfo) l2->phys->info)->state == PPTP_STATE_DOWN
	&& Enabled(&pptp2->options, PPTP_CONF_INCOMING)
	&& IpAddrInRange(&pptp2->peer_addr_req, peer)
	&& (!pptp2->peer_port_req || pptp2->peer_port_req == port)) {

      /* Link is feasible; now see if it's preferable */
      if (!pptp || pptp2->peer_addr_req.width > pptp->peer_addr_req.width) {
	l = l2;
	pptp = pptp2;
      }
    }
  }

  /* If no link is suitable, can't take the call */
  if (l == NULL)
    return(linfo);

  /* Open link to pick up the call */
  lnk = l;
  pptp = pptp;
  bund = lnk->bund;
  IfaceOpen();
  IfaceOpenNcps();

  /* Got one */
  pptp->cinfo = *cinfo;
  pptp->originate = FALSE;
  pptp->incoming = incoming;
  pptp->state = PPTP_STATE_CONNECTING;
  pptp->peer_addr = peer;
  pptp->peer_port = port;
  linfo.cookie = lnk;
  linfo.result = PptpResult;
  linfo.setLinkInfo = NULL;
  linfo.cancel = PptpCancel;
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

  lnk = (Link) cookie;
  bund = lnk->bund;
  pptp = (PptpInfo) lnk->phys->info;

  Log(LG_PHYS, ("[%s] PPTP call cancelled in state %s",
    lnk->name, gPptpStateNames[pptp->state]));
  if (pptp->state == PPTP_STATE_DOWN)
    return;
  PhysDown(STR_CON_FAILED0, NULL);
  pptp->state = PPTP_STATE_DOWN;
  pptp->peer_addr.s_addr = 0;
  pptp->peer_port = 0;
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

      if (Enabled(&p->options, PPTP_CONF_INCOMING))
	allow_incoming = 1;
      if (Enabled(&p->options, PPTP_CONF_ORIGINATE)
	  && p->peer_addr_req.ipaddr.s_addr != 0)
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
  struct in_range	rng;
  int			port;

  switch ((intptr_t)arg) {
    case SET_SELFADDR:
    case SET_PEERADDR:
      if (ac < 1 || ac > 2 || !ParseAddr(av[0], &rng))
	return(-1);
      if (ac > 1) {
	if ((port = atoi(av[1])) < 0 || port > 0xffff)
	  return(-1);
      } else {
	port = 0;
      }
      if ((intptr_t)arg == SET_SELFADDR) {
	gLocalIp = rng.ipaddr;
	gLocalPort = port;
      } else {
	pptp->peer_addr_req = rng;
	pptp->peer_port_req = port;
      }
      PptpListenUpdate();
      break;
    case SET_PHONENUM:
      if (ac != 1)
	return(-1);
      snprintf(pptp->phonenum, sizeof(pptp->phonenum), "%s", av[0]);
      break;
    case SET_ENABLE:
      EnableCommand(ac, av, &pptp->options, gConfList);
      PptpListenUpdate();
      break;
    case SET_DISABLE:
      DisableCommand(ac, av, &pptp->options, gConfList);
      PptpListenUpdate();
      break;
    default:
      assert(0);
  }
  return(0);
}

