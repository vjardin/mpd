
/*
 * bund.c
 *
 * Written by Archie Cobbs <archie@freebsd.org>
 * Copyright (c) 1995-1999 Whistle Communications, Inc. All rights reserved.
 * See ``COPYRIGHT.whistle''
 *
 * Bundle handling stuff
 */

#include "ppp.h"
#include "bund.h"
#include "ipcp.h"
#include "ccp.h"
#include "mp.h"
#include "iface.h"
#include "link.h"
#include "msg.h"
#include "custom.h"
#include "ngfunc.h"

#ifdef __DragonFly__
#include <netgraph/iface/ng_iface.h>
#else
#include <netgraph/ng_iface.h>
#endif

/*
 * DEFINITIONS
 */

  /* #define DEBUG_BOD */

  #define BUND_MSG_TIMEOUT	3
  #define BUND_REOPEN_DELAY	3	/* wait this long before closing */
  #define BUND_REOPEN_PAUSE	3	/* wait this long before re-opening */

  #define BUND_MIN_TOT_BW	9600

  /* Set menu options */
  enum {
    SET_PERIOD,
    SET_LOW_WATER,
    SET_HIGH_WATER,
    SET_MIN_CONNECT,
    SET_MIN_DISCONNECT,
    SET_AUTHNAME,
    SET_PASSWORD,
    SET_RETRY,
    SET_ACCEPT,
    SET_DENY,
    SET_ENABLE,
    SET_DISABLE,
    SET_YES,
    SET_NO,
  };

/*
 * INTERNAL FUNCTIONS
 */

  static void	BundBmStart(void);
  static void	BundBmStop(void);
  static void	BundMsgTimeout(void *arg);
  static void	BundBmTimeout(void *arg);

  static Bund	BundFind(char *name);
  static void	BundReasses(int add);
  static int	BundSetCommand(int ac, char *av[], void *arg);
  static void	BundShowLinks(Bund sb);

  static void	BundUpNcps(void);
  static void	BundDownNcps(void);

  static void	BundOpenLinks(void);
  static void	BundOpenLink(Link l);
  static void	BundReOpenLinks(void *arg);
  static void	BundCloseLink(Link l);

  static void	BundMsg(int type, void *cookie);

/*
 * GLOBAL VARIABLES
 */

  struct discrim	self_discrim;

  const struct cmdtab BundSetCmds[] = {
    { "period seconds",			"BOD sampling period",
	BundSetCommand, NULL, (void *) SET_PERIOD },
    { "lowat percent",			"BOD low water mark",
	BundSetCommand, NULL, (void *) SET_LOW_WATER },
    { "hiwat percent",			"BOD high water mark",
	BundSetCommand, NULL, (void *) SET_HIGH_WATER },
    { "min-con seconds",		"BOD min connected time",
	BundSetCommand, NULL, (void *) SET_MIN_CONNECT },
    { "min-dis seconds",		"BOD min disconnected time",
	BundSetCommand, NULL, (void *) SET_MIN_DISCONNECT },
    { "retry seconds",			"FSM retry timeout",
	BundSetCommand, NULL, (void *) SET_RETRY },
    { "accept [opt ...]",		"Accept option",
	BundSetCommand, NULL, (void *) SET_ACCEPT },
    { "deny [opt ...]",			"Deny option",
	BundSetCommand, NULL, (void *) SET_DENY },
    { "enable [opt ...]",		"Enable option",
	BundSetCommand, NULL, (void *) SET_ENABLE },
    { "disable [opt ...]",		"Disable option",
	BundSetCommand, NULL, (void *) SET_DISABLE },
    { "yes [opt ...]",			"Enable and accept option",
	BundSetCommand, NULL, (void *) SET_YES },
    { "no [opt ...]",			"Disable and deny option",
	BundSetCommand, NULL, (void *) SET_NO },
    { NULL },
  };

/*
 * INTERNAL VARIABLES
 */

  static const struct confinfo	gConfList[] = {
    { 0,	BUND_CONF_MULTILINK,	"multilink"	},
    { 1,	BUND_CONF_SHORTSEQ,	"shortseq"	},
    { 0,	BUND_CONF_COMPRESSION,	"compression"	},
    { 0,	BUND_CONF_ENCRYPTION,	"encryption"	},
    { 0,	BUND_CONF_CRYPT_REQD,	"crypt-reqd"	},
    { 0,	BUND_CONF_BWMANAGE,	"bw-manage"	},
    { 0,	BUND_CONF_ROUNDROBIN,	"round-robin"	},
    { 0,	BUND_CONF_NORETRY,	"noretry"	},
    { 0,	0,			NULL		},
  };

/*
 * BundOpen()
 */

void
BundOpen(void)
{
  MsgSend(bund->msgs, MSG_OPEN, NULL);
}

/*
 * BundClose()
 */

void
BundClose(void)
{
  MsgSend(bund->msgs, MSG_CLOSE, NULL);
}

/*
 * BundJoin()
 *
 * This is called when a link enters the NETWORK phase.
 *
 * Verify that link is OK to come up as part of it's bundle.
 * If so, join it to the bundle. Returns FALSE if there's a problem.
 * If this is the first link to join, and it's not supporting
 * multi-link, then prevent any further links from joining.
 *
 * Right now this is fairly simple minded: you have to define
 * the links in a bundle first, then stick to that plan. For
 * a server this might be too restrictive a policy.
 *
 * Returns zero if fails, otherwise the new number of up links.
 */

int
BundJoin(void)
{
  BundBm	const bm = &bund->bm;
  LcpState	const lcp = &lnk->lcp;

  /* Other links in this bundle yet? If so, enforce bundling */
  if (bm->n_up > 0) {

    /* First of all, we have to be doing multi-link */
    if (!bund->multilink || !lcp->peer_multilink) {
      Log(LG_LCP,
	("[%s] multi-link is not active on this bundle", lnk->name));
      return(0);
    }

    /* Discriminator and authname must match */
    if (!MpDiscrimEqual(&lnk->peer_discrim, &bund->peer_discrim)) {
      Log(LG_LCP,
	("[%s] multi-link peer discriminator mismatch", lnk->name));
      return(0);
    }
    if (strcmp(lnk->peer_authname, bund->peer_authname)) {
      Log(LG_LCP,
	("[%s] multi-link peer authorization name mismatch", lnk->name));
      return(0);
    }
  } else {

    /* Cancel re-open timer; we've come up somehow (eg, LCP renegotiation) */
    TimerStop(&bund->reOpenTimer);

    /* Record peer's authname */
    strcpy(bund->peer_authname, lnk->peer_authname);

    /* Initialize multi-link stuff */
    if ((bund->multilink = lcp->peer_multilink)) {
      bund->peer_discrim = lnk->peer_discrim;
      MpInit();
    }

    /* Start bandwidth management */
    BundBmStart();
  }

  /* Reasses MTU, bandwidth, etc. */
  BundReasses(1);

  /* Configure this link */
  bund->pppConfig.links[lnk->bundleIndex].enableLink = 1;
  bund->pppConfig.links[lnk->bundleIndex].mru = lcp->peer_mru;
  bund->pppConfig.links[lnk->bundleIndex].enableACFComp = lcp->peer_acfcomp;
  bund->pppConfig.links[lnk->bundleIndex].enableProtoComp = lcp->peer_protocomp;
  bund->pppConfig.links[lnk->bundleIndex].bandwidth = (lnk->bandwidth + 5) / 10;
  bund->pppConfig.links[lnk->bundleIndex].latency = (lnk->latency + 500) / 1000;

  /* What to do when the first link comes up */
  if (bm->n_up == 1) {

    /* Copy over peer's IP address range if specified in secrets file */
    if (lnk->range_valid)
      bund->peer_allow = lnk->peer_allow;
    else
      memset(&bund->peer_allow, 0, sizeof(bund->peer_allow));

    /* Make sure IPCP, et.al. renegotiate */
    if (bm->ncps_up)
      BundDownNcps();
    BundUpNcps();

    /* Configure the bundle */
#if NGM_PPP_COOKIE < 940897794
    bund->pppConfig.enableMultilink = lcp->peer_multilink;
    bund->pppConfig.mrru = lcp->peer_mrru;
    bund->pppConfig.xmitShortSeq = lcp->peer_shortseq;
    bund->pppConfig.recvShortSeq = lcp->want_shortseq;
    bund->pppConfig.enableRoundRobin =
      Enabled(&bund->conf.options, BUND_CONF_ROUNDROBIN);
#else
    bund->pppConfig.bund.enableMultilink = lcp->peer_multilink;
    bund->pppConfig.bund.mrru = lcp->peer_mrru;
    bund->pppConfig.bund.xmitShortSeq = lcp->peer_shortseq;
    bund->pppConfig.bund.recvShortSeq = lcp->want_shortseq;
    bund->pppConfig.bund.enableRoundRobin =
      Enabled(&bund->conf.options, BUND_CONF_ROUNDROBIN);
#endif

    /* generate a uniq session id */
    snprintf(bund->session_id, LINK_MAX_NAME, "%d-%s",
      time(NULL) % 10000000, bund->name);
  }

  /* Update PPP node configuration */
  NgFuncSetConfig();

  /* generate a uniq session id */
  snprintf(lnk->session_id, LINK_MAX_NAME, "%d-%s",
    time(NULL) % 10000000, lnk->name);

  AuthAccountStart(AUTH_ACCT_START);

  /* starting link statistics timer */
  TimerInit(&lnk->stats.updateTimer, "LinkUpdateStats", 
    LINK_STATS_UPDATE_INTERVAL, LinkUpdateStatsTimer, NULL);
  TimerStart(&lnk->stats.updateTimer);

  /* Done */
  return(bm->n_up);
}

/*
 * BundLeave()
 *
 * This is called when a link leaves the NETWORK phase.
 */

void
BundLeave(void)
{
  BundBm	const bm = &bund->bm;

  /* Elvis has left the bundle */
  assert(bm->n_up > 0);
  
  /* stopping link statistics timer */
  TimerStop(&lnk->stats.updateTimer);

  AuthAccountStart(AUTH_ACCT_STOP);
  AuthCleanup();

  BundReasses(0);
  
  /* Disable link */
  bund->pppConfig.links[lnk->bundleIndex].enableLink = 0;
  NgFuncSetConfig();

  /* Special stuff when last link goes down... */
  if (bm->n_up == 0) {
  
    /* Reset statistics and auth information */
    BundBmStop();
    if (bm->ncps_up)
      BundDownNcps();
    memset(bund->peer_authname, 0, sizeof(bund->peer_authname));
    memset(&bund->ccp.mppc, 0, sizeof(bund->ccp.mppc));
    
    /* Close links, or else wait and try to open again later */
    if (!bund->open || Enabled(&bund->conf.options, BUND_CONF_NORETRY)) {
      BundCloseLinks();
      if (Enabled(&bund->conf.options, BUND_CONF_NORETRY))
	IfaceCloseNcps();
    } else {		/* wait BUND_REOPEN_DELAY to see if it comes back up */
      TimerStop(&bund->reOpenTimer);
      TimerInit(&bund->reOpenTimer, "BundReOpen",
	BUND_REOPEN_DELAY * SECONDS, BundReOpenLinks, NULL);
      TimerStart(&bund->reOpenTimer);
    }
  }
}

/*
 * BundReOpenLinks()
 *
 * The last link went down, and we waited BUND_REOPEN_DELAY seconds for
 * it to come back up. It didn't, so close all the links and re-open them
 * BUND_REOPEN_PAUSE seconds from now.
 *
 * The timer calling this is cancelled whenever any link comes up.
 */

static void
BundReOpenLinks(void *arg)
{
  BundCloseLinks();
  TimerStop(&bund->reOpenTimer);
  TimerInit(&bund->reOpenTimer, "BundOpen",
    BUND_REOPEN_PAUSE * SECONDS, (void (*)(void *)) BundOpenLinks, NULL);
  TimerStart(&bund->reOpenTimer);
  RecordLinkUpDownReason(NULL, 1, STR_REDIAL, NULL);
}

/*
 * BundLinkGaveUp()
 *
 * This is called when one of our links we've told to open has
 * been unable to do so and is now giving up (due to a maximum
 * consecutive redial limitation, or whatever). This may result
 * in us closing the whole bundle.
 */

void
BundLinkGaveUp(void)
{
  int	k;

  /* Close this link */
  BundCloseLink(lnk);

  /* If links are not supposed to be open anyway, do nothing */
  if (!bund->bm.links_open)
    return;

  /* See if any other links are still open; if not, close down everything */
  for (k = 0; k < bund->n_links; k++) {
    if (bund->links[k] != lnk && OPEN_STATE(bund->links[k]->lcp.fsm.state))
      break;
  }
  if (k == bund->n_links)
    IfaceCloseNcps();
}

/*
 * BundMsg()
 *
 * Deal with incoming message to the bundle
 */

static void
BundMsg(int type, void *arg)
{
  Log(LG_BUND, ("[%s] bundle: %s event in state %s",
    bund->name, MsgName(type), bund->open ? "OPENED" : "CLOSED"));
  TimerStop(&bund->reOpenTimer);
  switch (type) {
    case MSG_OPEN:
      bund->open = TRUE;
      BundOpenLinks();
      break;

    case MSG_CLOSE:
      bund->open = FALSE;
      BundCloseLinks();
      break;

    default:
      assert(FALSE);
  }
}

/*
 * BundOpenLinks()
 *
 * Open one link or all links, depending on whether bandwidth
 * management is in effect or not.
 */

static void
BundOpenLinks(void)
{
  TimerStop(&bund->reOpenTimer);
  if (Enabled(&bund->conf.options, BUND_CONF_BWMANAGE)) {
    if (!bund->bm.links_open || bund->bm.n_open == 0)
      BundOpenLink(bund->links[0]);
  } else {
    int	k;

    for (k = 0; k < bund->n_links; k++)
      BundOpenLink(bund->links[k]);
  }
}

/*
 * BundOpenLink()
 */

static void
BundOpenLink(Link l)
{
  Log(LG_BUND, ("[%s] opening link \"%s\"...", bund->name, l->name));
  LinkOpen(l);
  bund->bm.links_open = 1;
  l->bm.last_open = time(NULL);
}

/*
 * BundCloseLinks()
 *
 * Close all links
 */

void
BundCloseLinks(void)
{
  int	k;

  TimerStop(&bund->reOpenTimer);
  for (k = 0; k < bund->n_links; k++)
    if (OPEN_STATE(bund->links[k]->lcp.fsm.state))
      BundCloseLink(bund->links[k]);
  TimerStop(&bund->msgTimer);
  TimerInit(&bund->msgTimer, "BundMsg",
    BUND_MSG_TIMEOUT * SECONDS, BundMsgTimeout, NULL);
  TimerStart(&bund->msgTimer);
  bund->bm.links_open = 0;
}

/*
 * BundCloseLink()
 */

static void
BundCloseLink(Link l)
{
  Log(LG_BUND, ("[%s] closing link \"%s\"...", bund->name, l->name));
  LinkClose(l);
  bund->bm.last_close = time(NULL);
}

/*
 * BundUpNcps()
 */

static void
BundUpNcps(void)
{
  IpcpUp();
  if (Enabled(&bund->conf.options, BUND_CONF_COMPRESSION)) {
    CcpOpen();
    CcpUp();
  }
  if (Enabled(&bund->conf.options, BUND_CONF_ENCRYPTION)) {
    EcpOpen();
    EcpUp();
  }
  bund->bm.ncps_up = TRUE;
}

/*
 * BundDownNcps()
 */

static void
BundDownNcps(void)
{
  IpcpDown();
  if (bund->ccp.fsm.state != ST_INITIAL) {
    CcpDown();
    CcpClose();
  }
  if (bund->ecp.fsm.state != ST_INITIAL) {
    EcpDown();
    EcpClose();
  }
  bund->bm.ncps_up = FALSE;
}

/*
 * BundReasses()
 *
 * Here we do a reassessment of things after a new link has been
 * added to or removed from the bundle.
 */

static void
BundReasses(int add)
{
  BundBm	const bm = &bund->bm;

  /* Add or subtract link */
  if (add)
    bm->n_up++;
  else
    bm->n_up--;

  /* Update system interface parameters */
  BundUpdateParams();

  Log(LG_BUND, ("[%s] up: %d link%s, total bandwidth %d bps",
    bund->name, bm->n_up, bm->n_up == 1 ? "" : "s", bm->total_bw));

}

/*
 * BundUpdateParams()
 *
 * Recalculate interface MTU and bandwidth.
 */

void
BundUpdateParams(void)
{
  BundBm	const bm = &bund->bm;
  int		k, mtu, the_link = 0;

  /* Recalculate how much bandwidth we have */
  for (bm->total_bw = k = 0; k < bund->n_links; k++) {
    if (bund->links[k]->lcp.phase == PHASE_NETWORK) {
      bm->total_bw += bund->links[k]->bandwidth;
      the_link = k;
    }
  }
  if (bm->total_bw < BUND_MIN_TOT_BW)
    bm->total_bw = BUND_MIN_TOT_BW;

  /* Recalculate MTU corresponding to peer's MRU */
  switch (bm->n_up) {
    case 0:
      mtu = NG_IFACE_MTU_DEFAULT;	/* Reset to default settings */
      break;
    case 1:
      if (!bund->multilink) {		/* If no multilink, use peer MRU */
	mtu = MIN(bund->links[the_link]->lcp.peer_mru,
		  bund->links[the_link]->phys->type->mtu);
	break;
      }
      /* FALLTHROUGH */
    default:			/* We fragment everything, use bundle MRRU */
      mtu = bund->mp.peer_mrru;
      break;
  }

  /* Subtract to make room for various frame-bloating protocols */
  if (bm->n_up > 0) {
    if (Enabled(&bund->conf.options, BUND_CONF_COMPRESSION))
      mtu = CcpSubtractBloat(mtu);
    if (Enabled(&bund->conf.options, BUND_CONF_ENCRYPTION))
      mtu = EcpSubtractBloat(mtu);
  }

  /* Update interface MTU */
  IfaceSetMTU(mtu, bm->total_bw);
}

/*
 * BundCommand()
 *
 * Show list of all bundles or set bundle
 */

int
BundCommand(int ac, char *av[], void *arg)
{
  Bund	sb;
  int	k;

  switch (ac) {
    case 0:

      #define BUND_FMT "\t%-15s"

      Printf("Defined bundles:\r\n");
      Printf(BUND_FMT "Links\r\n", "Bundle");
      Printf(BUND_FMT "-----\r\n", "------");

      for (k = 0; k < gNumBundles; k++)
	if ((sb = gBundles[k]) != NULL) {
	  Printf(BUND_FMT, sb->name);
	  BundShowLinks(sb);
	}
      break;

    case 1:

      /* Change bundle, and link also if needed */
      if ((sb = BundFind(av[0])) != NULL) {
	if (gConsoleSession) {
	  gConsoleSession->bund = sb;
	  gConsoleSession->link = sb->links[0];
	} else {
	  bund = sb;
	  if (lnk->bund != bund)
	    lnk = bund->links[0];
	}
      } else
	Printf("Bundle \"%s\" not defined.\r\n", av[0]);
      break;

    default:
      return(-1);
  }
  return(0);
}

/*
 * BundCreateCmd()
 *
 * Create a new bundle. If some of the links can't be added,
 * then we just use the ones that could.
 */

int
BundCreateCmd(int ac, char *av[], void *arg)
{
  Bund	old_bund = bund;
  Link	new_link;
  char	*reqIface = NULL;
  u_char tee = 0;
  u_char netflow = 0;
  int	k;

  /* Args */
  if (ac < 2)
    return(-1);

  if (ac > 0 && av[0][0] == '-') {
    optreset = 1; 
    optind = 0;
    while ((k = getopt(ac, av, "nti:")) != -1) {
      switch (k) {
      case 'i':
	reqIface = optarg;
	break;
      case 't':
	tee = 1;
	break;
      case 'n':
#ifdef USE_NG_NETFLOW
	netflow = 1;
#endif
	break;
      default:
	return (-1);
      }
    }
    ac -= optind;
    av += optind;
  }

  /* See if bundle name already taken */
  if ((bund = BundFind(av[0])) != NULL) {
    Log(LG_ERR, ("mpd: bundle \"%s\" already exists", av[0]));
    goto fail;
  }

  /* Create a new bundle structure */
  bund = Malloc(MB_BUND, sizeof(*bund));
  snprintf(bund->name, sizeof(bund->name), "%s", av[0]);
  bund->csock = bund->dsock = -1;
  bund->tee = tee;
  bund->netflow = netflow;

  /* Setup netgraph stuff */
  if (NgFuncInit(bund, reqIface) < 0) {
    Log(LG_ERR, ("[%s] netgraph initialization failed", bund->name));
    goto fail2;
  }

  /* Create each link and add it to the bundle */
  bund->links = Malloc(MB_BUND, (ac - 1) * sizeof(*bund->links));
  for (k = 1; k < ac; k++) {
    if ((new_link = LinkNew(av[k])) == NULL)
      Log(LG_ERR, ("[%s] addition of link \"%s\" failed", av[0], av[k]));
    else {
      new_link->bund = bund;
      new_link->bundleIndex = bund->n_links;
      bund->links[bund->n_links] = new_link;
      bund->n_links++;
    }
  }

  /* We need at least one link in the bundle */
  if (bund->n_links == 0) {
    Log(LG_ERR, ("mpd: bundle \"%s\" creation failed: no links", av[0]));
    Freee(MB_BUND, bund->links);
    NgFuncShutdown(bund);
fail2:
    Freee(MB_BUND, bund);
fail:
    bund = old_bund;
    return(0);
  }

  /* Add bundle to the list of bundles and make it the current active bundle */
  for (k = 0; k < gNumBundles && gBundles[k] != NULL; k++);
  if (k == gNumBundles)			/* add a new bundle pointer */
    LengthenArray(&gBundles, sizeof(*gBundles), &gNumBundles, MB_BUND);
  gBundles[k] = bund;

  /* Init interface stuff */
  IfaceInit();

  /* Get message channel */
  bund->msgs = MsgRegister(BundMsg, 0);

  /* Initialize bundle configuration */
  bund->conf.mrru = MP_DEFAULT_MRRU;
  bund->conf.retry_timeout = BUND_DEFAULT_RETRY;
  bund->conf.bm_S = BUND_BM_DFL_S;
  bund->conf.bm_Hi = BUND_BM_DFL_Hi;
  bund->conf.bm_Lo = BUND_BM_DFL_Lo;
  bund->conf.bm_Mc = BUND_BM_DFL_Mc;
  bund->conf.bm_Md = BUND_BM_DFL_Md;

  Enable(&bund->conf.options, BUND_CONF_MULTILINK);
  Enable(&bund->conf.options, BUND_CONF_SHORTSEQ);
  Accept(&bund->conf.options, BUND_CONF_SHORTSEQ);

  Disable(&bund->conf.options, BUND_CONF_BWMANAGE);
  Disable(&bund->conf.options, BUND_CONF_COMPRESSION);
  Disable(&bund->conf.options, BUND_CONF_ENCRYPTION);
  Disable(&bund->conf.options, BUND_CONF_CRYPT_REQD);

  /* Init NCP's */
  IpcpInit();
  CcpInit();
  EcpInit();
  
  AuthInit();

  if (gConsoleSession) {
    gConsoleSession->bund = bund;
    gConsoleSession->link = bund->links[0];
  }
  
  /* Done */
  return(0);
}

/*
 * BundStat()
 *
 * Show state of a bundle
 */

int
BundStat(int ac, char *av[], void *arg)
{
  Bund	sb;
  int	k, bw, tbw, nup;

  /* Find bundle they're talking about */
  switch (ac) {
    case 0:
      sb = bund;
      break;
    case 1:
      if ((sb = BundFind(av[0])) == NULL) {
	Printf("Bundle \"%s\" not defined.\r\n", av[0]);
	return(0);
      }
      break;
    default:
      return(-1);
  }

  /* Show stuff about the bundle */
  for (tbw = bw = nup = k = 0; k < sb->n_links; k++) {
    if (sb->links[k]->lcp.phase == PHASE_NETWORK) {
      nup++;
      bw += sb->links[k]->bandwidth;
    }
    tbw += sb->links[k]->bandwidth;
  }

  Printf("Bundle %s:\r\n", sb->name);
  Printf("\tLinks          : \r\n");
  BundShowLinks(sb);
  Printf("\tStatus         : %s\r\n", sb->open ? "OPEN" : "CLOSED");
  Printf("\tSession-Id     : %s\r\n", sb->session_id);
  Printf("\tTotal bandwidth: %u\r\n", tbw);
  Printf("\tAvail bandwidth: %u\r\n", bw);
  Printf("\tPeer authname  : \"%s\"\r\n", sb->peer_authname);
  Printf("\tPeer discrim.  : %s\r\n", MpDiscrimText(&sb->peer_discrim));

  /* Show configuration */
  Printf("Configuration:\r\n");
  Printf("\tMy auth name   : \"%s\"\r\n", sb->conf.auth.authname);
  Printf("\tMy MRRU        : %d bytes\r\n", sb->conf.mrru);
  Printf("\tRetry timeout  : %d seconds\r\n", sb->conf.retry_timeout);
  Printf("\tSample period  : %d seconds\r\n", sb->conf.bm_S);
  Printf("\tLow water mark : %d%%\r\n", sb->conf.bm_Lo);
  Printf("\tHigh water mark: %d%%\r\n", sb->conf.bm_Hi);
  Printf("\tMin connected  : %d seconds\r\n", sb->conf.bm_Mc);
  Printf("\tMax connected  : %d seconds\r\n", sb->conf.bm_Md);
  Printf("Bundle level options:\r\n");
  OptStat(&sb->conf.options, gConfList);

  /* Show peer info */
  if (sb->bm.n_up > 0) {
    Printf("Multilink PPP:\r\n");
    Printf("\tStatus         : %s\r\n",
      sb->multilink ? "Active" : "Inactive\r\n");
    if (sb->multilink) {
      Printf("\tPeer auth name : \"%s\"\r\n", sb->peer_authname);
      Printf("\tPeer discrimin.: %s\r\n", MpDiscrimText(&sb->peer_discrim));
    }
  }

  /* Show stats */
  LinkUpdateStats();
  Printf("Traffic stats:\r\n");

  Printf("\tOctets input   : %llu\r\n", lnk->stats.recvOctets);
  Printf("\tFrames input   : %llu\r\n", lnk->stats.recvFrames);
  Printf("\tOctets output  : %llu\r\n", lnk->stats.xmitOctets);
  Printf("\tFrames output  : %llu\r\n", lnk->stats.xmitFrames);
  Printf("\tBad protocols  : %llu\r\n", lnk->stats.badProtos);
#if NGM_PPP_COOKIE >= 940897794
  Printf("\tRunts          : %llu\r\n", lnk->stats.runts);
#endif
  Printf("\tDup fragments  : %llu\r\n", lnk->stats.dupFragments);
#if NGM_PPP_COOKIE >= 940897794
  Printf("\tDrop fragments : %llu\r\n", lnk->stats.dropFragments);
#endif

  return(0);
}

/*
 * BundShowLinks()
 */

static void
BundShowLinks(Bund sb)
{
  int	j;

  for (j = 0; j < sb->n_links; j++) {
    Printf("%s", sb->links[j]->name);
    if (!sb->links[j]->phys->type)
      Printf("[no type] ");
    else
      Printf("[%s/%s] ", FsmStateName(sb->links[j]->lcp.fsm.state),
	PhysState(sb->links[j]->phys));
  }
  Printf("\r\n");
}

/*
 * BundFind()
 *
 * Find a bundle structure
 */

static Bund
BundFind(char *name)
{
  int	k;

  for (k = 0;
    k < gNumBundles && (!gBundles[k] || strcmp(gBundles[k]->name, name));
    k++);
  return((k < gNumBundles) ? gBundles[k] : NULL);
}

/*
 * BundMsgTimeout()
 */

static void
BundMsgTimeout(void *arg)
{
  SetStatus(ADLG_WAN_WAIT_FOR_DEMAND, STR_READY_TO_DIAL);
}

/*
 * BundBmStart()
 *
 * Start bandwidth management timer
 */

static void
BundBmStart(void)
{
  int	k;

  /* Reset bandwidth management stats */
  for (k = 0; k < bund->n_links; k++) {
    memset(&bund->links[k]->bm.traffic, 0, sizeof(bund->links[k]->bm.traffic));
    memset(&bund->links[k]->bm.wasUp, 0, sizeof(bund->links[k]->bm.wasUp));
    memset(&bund->links[k]->bm.idleStats,
      0, sizeof(bund->links[k]->bm.idleStats));
  }

  /* Start bandwidth management timer */
  TimerStop(&bund->bm.bmTimer);
  if (Enabled(&bund->conf.options, BUND_CONF_BWMANAGE)) {
    TimerInit(&bund->bm.bmTimer, "BundBm",
      bund->conf.bm_S * SECONDS / LINK_BM_N,
      BundBmTimeout, NULL);
    TimerStart(&bund->bm.bmTimer);
  }
}

/*
 * BundBmStop()
 */

static void
BundBmStop(void)
{
  TimerStop(&bund->bm.bmTimer);
}

/*
 * BundBmTimeout()
 *
 * Do a bandwidth management update
 */

static void
BundBmTimeout(void *arg)
{
  const time_t	now = time(NULL);
  u_int		availTotal;
  u_int		inUtilTotal = 0, outUtilTotal = 0;
  u_int		inBitsTotal, outBitsTotal;
  u_int		inUtil[LINK_BM_N];	/* Incoming % utilization */
  u_int		outUtil[LINK_BM_N];	/* Outgoing % utilization */
  int		j, k;

  /* Shift and update stats */
  for (k = 0; k < bund->n_links; k++) {
    Link	const l = bund->links[k];

    /* Shift stats */
    memmove(&l->bm.wasUp[1], &l->bm.wasUp[0],
      (LINK_BM_N - 1) * sizeof(l->bm.wasUp[0]));
    l->bm.wasUp[0] = (l->lcp.fsm.state == ST_OPENED);
    memmove(&l->bm.traffic[0][1], &l->bm.traffic[0][0],
      (LINK_BM_N - 1) * sizeof(l->bm.traffic[0][0]));
    memmove(&l->bm.traffic[1][1], &l->bm.traffic[1][0],
      (LINK_BM_N - 1) * sizeof(l->bm.traffic[1][0]));
    if (!l->bm.wasUp[0]) {
      l->bm.traffic[0][0] = 0;
      l->bm.traffic[1][0] = 0;
    } else {
      struct ng_ppp_link_stat	oldStats;

      /* Get updated link traffic statistics */
      oldStats = l->bm.idleStats;
      NgFuncGetStats(l->bundleIndex, FALSE, &l->bm.idleStats);
      l->bm.traffic[0][0] = l->bm.idleStats.recvOctets - oldStats.recvOctets;
      l->bm.traffic[1][0] = l->bm.idleStats.xmitOctets - oldStats.xmitOctets;
    }
  }

  /* Compute utilizations */
  memset(&inUtil, 0, sizeof(inUtil));
  memset(&outUtil, 0, sizeof(outUtil));
  for (availTotal = inBitsTotal = outBitsTotal = j = 0; j < LINK_BM_N; j++) {
    u_int	avail, inBits, outBits;

    /* Sum up over all links */
    for (avail = inBits = outBits = k = 0; k < bund->n_links; k++) {
      Link	const l = bund->links[k];

      if (l->bm.wasUp[j]) {
	avail += (l->bandwidth * bund->conf.bm_S) / LINK_BM_N;
	inBits += l->bm.traffic[0][j] * 8;
	outBits += l->bm.traffic[1][j] * 8;
      }
    }
    availTotal += avail;
    inBitsTotal += inBits;
    outBitsTotal += outBits;

    /* Compute bandwidth utilizations as percentages */
    if (avail != 0) {
      inUtil[j] = ((float) inBits / avail) * 100;
      outUtil[j] = ((float) outBits / avail) * 100;
    }
  }

  /* Compute total averaged utilization */
  if (availTotal != 0) {
    inUtilTotal = ((float) inBitsTotal / availTotal) * 100;
    outUtilTotal = ((float) outBitsTotal / availTotal) * 100;
  }

#ifdef DEBUG_BOD
  {
    char	ins[100], outs[100];

    snprintf(ins, sizeof(ins), ">>Link status:             ");
    for (j = 0; j < LINK_BM_N; j++) {
      for (k = 0; k < bund->n_links; k++) {
	Link	const l = bund->links[k];

	snprintf(ins + strlen(ins), sizeof(ins) - strlen(ins),
	  l->bm.wasUp[LINK_BM_N - 1 - j] ? "Up" : "Dn");
      }
      snprintf(ins + strlen(ins), sizeof(ins) - strlen(ins), " ");
    }
    LogStdout("%s", ins);

    snprintf(ins, sizeof(ins), " IN util: total %3u%%  ", inUtilTotal);
    snprintf(outs, sizeof(outs), "OUT util: total %3u%%  ", outUtilTotal);
    for (j = 0; j < LINK_BM_N; j++) {
      snprintf(ins + strlen(ins), sizeof(ins) - strlen(ins),
	" %3u%%", inUtil[LINK_BM_N - 1 - j]);
      snprintf(outs + strlen(outs), sizeof(outs) - strlen(outs),
	" %3u%%", outUtil[LINK_BM_N - 1 - j]);
    }
    LogStdout("  %s", ins);
    LogStdout("  %s", outs);
  }
#endif

  /* See if it's time to bring up another link */
  if (now - bund->bm.last_close >= bund->conf.bm_Md
      && (inUtilTotal >= bund->conf.bm_Hi || outUtilTotal >= bund->conf.bm_Hi)
      && bund->bm.n_open < bund->n_links) {
    for (k = 0; k < bund->n_links; k++) {
      if (!OPEN_STATE(bund->links[k]->lcp.fsm.state)) {
	Log(LG_BUND, ("[%s] opening link %s due to increased demand",
	  bund->name, bund->links[k]->name));
	BundOpenLink(bund->links[k]);
	break;
      }
    }
  }

  /* See if it's time to bring down a link */
  if (bund->bm.n_up > 1) {
    for (j = 0; j < LINK_BM_N; j++) {
      if (inUtil[j] + outUtil[j] >= 2 * bund->conf.bm_Lo)
	break;
    }
    if (j == LINK_BM_N) {
      for (k = 0; k < bund->n_links; k++) {
	if (OPEN_STATE(bund->links[k]->lcp.fsm.state)
	    && (now - bund->links[k]->bm.last_open < bund->conf.bm_Mc))
	  break;
      }
      if (k == bund->n_links) {
	while (--k >= 0 && !OPEN_STATE(bund->links[k]->lcp.fsm.state));
	assert(k >= 0);
	Log(LG_BUND, ("[%s] closing link %s due to reduced demand",
	  bund->name, bund->links[k]->name));
	BundCloseLink(bund->links[k]);
      }
    }
  }

  /* Restart timer */
  TimerStart(&bund->bm.bmTimer);
}

/*
 * BundSetCommand()
 */

static int
BundSetCommand(int ac, char *av[], void *arg)
{
  if (ac == 0)
    return(-1);
  switch ((intptr_t)arg) {
    case SET_PERIOD:
      bund->conf.bm_S = atoi(*av);
      break;
    case SET_LOW_WATER:
      bund->conf.bm_Lo = atoi(*av);
      break;
    case SET_HIGH_WATER:
      bund->conf.bm_Hi = atoi(*av);
      break;
    case SET_MIN_CONNECT:
      bund->conf.bm_Mc = atoi(*av);
      break;
    case SET_MIN_DISCONNECT:
      bund->conf.bm_Md = atoi(*av);
      break;

    case SET_RETRY:
      bund->conf.retry_timeout = atoi(*av);
      if (bund->conf.retry_timeout < 1 || bund->conf.retry_timeout > 10)
	bund->conf.retry_timeout = BUND_DEFAULT_RETRY;
      break;

    case SET_ACCEPT:
      AcceptCommand(ac, av, &bund->conf.options, gConfList);
      break;

    case SET_DENY:
      DenyCommand(ac, av, &bund->conf.options, gConfList);
      break;

    case SET_ENABLE:
      EnableCommand(ac, av, &bund->conf.options, gConfList);
      break;

    case SET_DISABLE:
      DisableCommand(ac, av, &bund->conf.options, gConfList);
      if (!Enabled(&bund->conf.options, BUND_CONF_MULTILINK)
	  && bund->n_links > 1) {
	Log(LG_ERR, ("[%s] multilink option required for %d links",
	  bund->name, bund->n_links));
	Enable(&bund->conf.options, BUND_CONF_MULTILINK);
      }
      break;

    case SET_YES:
      YesCommand(ac, av, &bund->conf.options, gConfList);
      break;

    case SET_NO:
      NoCommand(ac, av, &bund->conf.options, gConfList);
      break;

    default:
      assert(0);
  }
  return(0);
}

