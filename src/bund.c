
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
#include "log.h"
#include "util.h"
#include "input.h"

#include <netgraph.h>
#include <netgraph/ng_message.h>
#ifdef __DragonFly__
#include <netgraph/socket/ng_socket.h>
#include <netgraph/iface/ng_iface.h>
#include <netgraph/ppp/ng_ppp.h>
#include <netgraph/vjc/ng_vjc.h>
#else
#include <netgraph/ng_socket.h>
#include <netgraph/ng_iface.h>
#include <netgraph/ng_ppp.h>
#include <netgraph/ng_vjc.h>
#endif

/*
 * DEFINITIONS
 */

  /* #define DEBUG_BOD */

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

  static int	BundNgInit(Bund b, const char *reqIface);
  static void	BundNgShutdown(Bund b, int iface, int ppp);

  static void	BundNgDataEvent(int type, void *cookie);
  static void	BundNgCtrlEvent(int type, void *cookie);

  static void	BundBmStart(void);
  static void	BundBmStop(void);
  static void	BundBmTimeout(void *arg);

  static Bund	BundFind(char *name);
  static void	BundReasses(int add);
  static int	BundSetCommand(int ac, char *av[], void *arg);
  static void	BundShowLinks(Bund sb);

  static void	BundNcpsUp(void);
  static void	BundNcpsDown(void);

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
    { 0,	BUND_CONF_IPCP,		"ipcp"		},
    { 0,	BUND_CONF_IPV6CP,	"ipv6cp"	},
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

  if (!bund->open) bund->open = TRUE; /* Open bundle on incoming */

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
    if (strcmp(lnk->lcp.auth.params.authname, bund->params.authname)) {
      Log(LG_LCP,
	("[%s] multi-link peer authorization name mismatch", lnk->name));
      return(0);
    }
  } else {

    /* Cancel re-open timer; we've come up somehow (eg, LCP renegotiation) */
    TimerStop(&bund->reOpenTimer);

    /* Copy auth params from the first link */
    authparamsCopy(&lnk->lcp.auth.params,&bund->params);

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
  bund->pppConfig.links[lnk->bundleIndex].bandwidth = (lnk->bandwidth / 8 + 5) / 10;
  bund->pppConfig.links[lnk->bundleIndex].latency = (lnk->latency + 500) / 1000;

  /* What to do when the first link comes up */
  if (bm->n_up == 1) {

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
    snprintf(bund->msession_id, LINK_MAX_NAME, "%d-%s",
      (int)(time(NULL) % 10000000), bund->name);
      
    bund->originate = lnk->originate;
  }

  /* Update PPP node configuration */
  NgFuncSetConfig();

  /* copy multysession-id to link */
  strncpy(lnk->msession_id, bund->msession_id,
    sizeof(lnk->msession_id));

  /* generate a uniq session id */
  snprintf(lnk->session_id, LINK_MAX_NAME, "%d-%s",
    (int)(time(NULL) % 10000000), lnk->name);

  /* What to do when the first link comes up */
  if (bm->n_up == 1) {

    BundNcpsOpen();

    BundNcpsUp();

    BundResetStats();
    
    /* starting bundle statistics timer */
    TimerInit(&bund->statsUpdateTimer, "BundUpdateStats", 
	BUND_STATS_UPDATE_INTERVAL, BundUpdateStatsTimer, bund);
    TimerStart(&bund->statsUpdateTimer);
    
  }

  AuthAccountStart(AUTH_ACCT_START);

  /* starting link statistics timer */
  TimerInit(&lnk->statsUpdateTimer, "LinkUpdateStats", 
    LINK_STATS_UPDATE_INTERVAL, LinkUpdateStatsTimer, lnk);
  TimerStart(&lnk->statsUpdateTimer);

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
  TimerStop(&lnk->statsUpdateTimer);

  AuthAccountStart(AUTH_ACCT_STOP);
  AuthCleanup();

  BundReasses(0);
  
  /* Disable link */
  bund->pppConfig.links[lnk->bundleIndex].enableLink = 0;
  NgFuncSetConfig();

  /* Special stuff when last link goes down... */
  if (bm->n_up == 0) {
  
    /* stopping bundle statistics timer */
    TimerStop(&bund->statsUpdateTimer);

    /* Reset statistics and auth information */
    BundBmStop();

    BundNcpsClose();
    BundNcpsDown();

    authparamsDestroy(&bund->params);
    memset(&bund->ccp.mppc, 0, sizeof(bund->ccp.mppc));
 
    /* try to open again later */
    if (bund->open && !Enabled(&bund->conf.options, BUND_CONF_NORETRY)) {
	/* wait BUND_REOPEN_DELAY to see if it comes back up */
      int delay = BUND_REOPEN_DELAY;
      delay += ((random() ^ gPid ^ time(NULL)) & 1);
      Log(LG_BUND, ("[%s] Last link has gone and no noretry option, will reopen in %d seconds", 
        bund->name, delay));
      TimerStop(&bund->reOpenTimer);
      TimerInit(&bund->reOpenTimer, "BundReOpen",
	delay * SECONDS, BundReOpenLinks, bund);
      TimerStart(&bund->reOpenTimer);
    } else if (bund->open) {
	bund->open = FALSE;
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
    Bund b = (Bund)arg;
    
  Log(LG_BUND, ("[%s] Last link has gone and no noretry option, reopening in %d seconds", bund->name, BUND_REOPEN_PAUSE));
  BundCloseLinks();
  TimerStop(&b->reOpenTimer);
  TimerInit(&b->reOpenTimer, "BundOpen",
    BUND_REOPEN_PAUSE * SECONDS, (void (*)(void *)) BundOpenLinks, b);
  TimerStart(&b->reOpenTimer);
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

void
BundOpenLinks(Bund b)
{
  TimerStop(&b->reOpenTimer);
  if (Enabled(&b->conf.options, BUND_CONF_BWMANAGE)) {
    if (!b->bm.links_open || b->bm.n_open == 0)
      BundOpenLink(b->links[0]);
  } else {
    int	k;

    for (k = 0; k < b->n_links; k++)
      BundOpenLink(b->links[k]);
  }
}

/*
 * BundOpenLink()
 */

void
BundOpenLink(Link l)
{
  Log(LG_BUND, ("[%s] opening link \"%s\"...", l->bund->name, l->name));
  LinkOpen(l);
  l->bund->bm.links_open = 1;
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
  bund->bm.links_open = 0;
}

/*
 * BundCloseLink()
 */

static void
BundCloseLink(Link l)
{
  Log(LG_BUND, ("[%s] closing link \"%s\"...", l->bund->name, l->name));
  LinkClose(l);
}

/*
 * BundNcpsOpen()
 */

void
BundNcpsOpen(void)
{
  if (Enabled(&bund->conf.options, BUND_CONF_IPCP))
    IpcpOpen();
  if (Enabled(&bund->conf.options, BUND_CONF_IPV6CP))
    Ipv6cpOpen();
  if (Enabled(&bund->conf.options, BUND_CONF_COMPRESSION))
    CcpOpen();
  if (Enabled(&bund->conf.options, BUND_CONF_ENCRYPTION))
    EcpOpen();
}

/*
 * BundNcpsUp()
 */

static void
BundNcpsUp(void)
{
  if (Enabled(&bund->conf.options, BUND_CONF_IPCP))
    IpcpUp();
  if (Enabled(&bund->conf.options, BUND_CONF_IPV6CP))
    Ipv6cpUp();
  if (Enabled(&bund->conf.options, BUND_CONF_COMPRESSION))
    CcpUp();
  if (Enabled(&bund->conf.options, BUND_CONF_ENCRYPTION))
    EcpUp();
}

void
BundNcpsStart(int proto)
{
    bund->ncpstarted |= ((1<<proto)>>1);
}

void
BundNcpsFinish(int proto)
{
    bund->ncpstarted &= (~((1<<proto)>>1));
    if (!bund->ncpstarted) {
	Log(LG_BUND, ("[%s] No NCPs left. Closing links...", bund->name));
	RecordLinkUpDownReason(NULL, 0, STR_PROTO_ERR, NULL);
	BundCloseLinks(); /* We have nothing to live for */
    }
}

void
BundNcpsJoin(int proto)
{
    IfaceState	iface = &bund->iface;
    switch(proto) {
	case NCP_IPCP:
	    if (!iface->ip_up) {
		iface->ip_up=1;
		IfaceIpIfaceUp(1);
	    } else if (iface->dod) {
		iface->dod = 0;
		iface->up = 0;
		IfaceDown();
		if (iface->ip_up) {
		    iface->ip_up=0;
		    IfaceIpIfaceDown();
		}
		if (iface->ipv6_up) {
		    iface->ipv6_up=0;
		    IfaceIpv6IfaceDown();
		}
		
		iface->ip_up=1;
		IfaceIpIfaceUp(1);
	    }
	    break;
	case NCP_IPV6CP:
	    if (!iface->ipv6_up) {
		iface->ipv6_up=1;
		IfaceIpv6IfaceUp(1);
	    } else if (iface->dod) {
		iface->dod = 0;
		iface->up = 0;
		IfaceDown();
		if (iface->ip_up) {
		    iface->ip_up=0;
		    IfaceIpIfaceDown();
		}
		if (iface->ipv6_up) {
		    iface->ipv6_up=0;
		    IfaceIpv6IfaceDown();
		}
		
		iface->ipv6_up=1;
		IfaceIpv6IfaceUp(1);
	    }
	    break;
	case NCP_NONE: /* Manual call by 'open iface' */
	    if (Enabled(&iface->options, IFACE_CONF_ONDEMAND)) {
		if (!(iface->up || iface->ip_up || iface->ipv6_up)) {
		    iface->dod=1;
		    iface->up=1;
		    IfaceUp(0);
		    if (Enabled(&bund->conf.options, BUND_CONF_IPCP)) {
			iface->ip_up=1;
			IfaceIpIfaceUp(0);
		    }
		    if (Enabled(&bund->conf.options, BUND_CONF_IPV6CP)) {
			iface->ipv6_up=1;
			IfaceIpv6IfaceUp(0);
		    }
		}
	    }
	    break;
    }
    
    if ((proto==NCP_IPCP || proto==NCP_IPV6CP) && (!iface->up)) {
	iface->up=1;
	IfaceUp(1);
    }
}

void
BundNcpsLeave(int proto)
{
    IfaceState	iface = &bund->iface;
    switch(proto) {
	case NCP_IPCP:
	    if (iface->ip_up && !iface->dod) {
		iface->ip_up=0;
		IfaceIpIfaceDown();
	    }
	    break;
	case NCP_IPV6CP:
	    if (iface->ipv6_up && !iface->dod) {
		iface->ipv6_up=0;
		IfaceIpv6IfaceDown();
	    }
	    break;
    }
    
    if ((iface->up) && (!iface->ip_up) && (!iface->ipv6_up)) {
	iface->up=0;
	IfaceDown();
        if (Enabled(&iface->options, IFACE_CONF_ONDEMAND)) {
	    iface->dod=1;
	    iface->up=1;
	    IfaceUp(0);
	    if (Enabled(&bund->conf.options, BUND_CONF_IPCP)) {
		iface->ip_up=1;
		IfaceIpIfaceUp(0);
	    }
	    if (Enabled(&bund->conf.options, BUND_CONF_IPV6CP)) {
		iface->ipv6_up=1;
		IfaceIpv6IfaceUp(0);
	    }
	}
    }
}

/*
 * BundNcpsDown()
 */

static void
BundNcpsDown(void)
{
  if (Enabled(&bund->conf.options, BUND_CONF_IPCP))
    IpcpDown();
  if (Enabled(&bund->conf.options, BUND_CONF_IPV6CP))
    Ipv6cpDown();
  if (Enabled(&bund->conf.options, BUND_CONF_COMPRESSION))
    CcpDown();
  if (Enabled(&bund->conf.options, BUND_CONF_ENCRYPTION))
    EcpDown();
}

/*
 * BundNcpsClose()
 */

void
BundNcpsClose(void)
{
  if (Enabled(&bund->conf.options, BUND_CONF_IPCP))
    IpcpClose();
  if (Enabled(&bund->conf.options, BUND_CONF_IPV6CP))
    Ipv6cpClose();
  if (Enabled(&bund->conf.options, BUND_CONF_COMPRESSION))
    CcpClose();
  if (Enabled(&bund->conf.options, BUND_CONF_ENCRYPTION))
    EcpClose();
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

  Log(LG_BUND, ("[%s] Bundle up: %d link%s, total bandwidth %d bps",
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
  IfaceSetMTU(mtu);
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
	bund = sb;
	if (lnk == NULL || lnk->bund != bund) {
	    lnk = bund->links[0];
	}
	phys = lnk->phys;
	rep = NULL;
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
  u_char netflow_in = 0;
  u_char netflow_out = 0;
  u_char nat = 0;
  int	k;

  /* Args */
  if (ac < 2)
    return(-1);

  if (ac > 0 && av[0][0] == '-') {
    optreset = 1; 
    optind = 0;
    while ((k = getopt(ac, av, "nNati:")) != -1) {
      switch (k) {
      case 'i':
	reqIface = optarg;
	break;
      case 't':
	tee = 1;
	break;
      case 'n':
#ifdef USE_NG_NETFLOW
	netflow_in = 1;
#endif
	break;
      case 'N':
#ifdef USE_NG_NETFLOW
	netflow_out = 1;
#endif
	break;
      case 'a':
#ifdef USE_NG_NAT
	nat = 1;
#endif
	break;
      default:
	return (-1);
      }
    }
    ac -= optind;
    av += optind;
  }

#if NG_NODESIZ>=32
  if (strlen(av[0])>16) {
#else
  if (strlen(av[0])>6) {
#endif
    Log(LG_ERR, ("bundle name \"%s\" is too long", av[0]));
    bund = old_bund;
    return(0);
  }

  /* See if bundle name already taken */
  if ((bund = BundFind(av[0])) != NULL) {
    Log(LG_ERR, ("bundle \"%s\" already exists", av[0]));
    bund = old_bund;
    return(0);
  }

  /* Create a new bundle structure */
  bund = Malloc(MB_BUND, sizeof(*bund));
  snprintf(bund->name, sizeof(bund->name), "%s", av[0]);
  bund->csock = bund->dsock = -1;

  /* Setup netgraph stuff */
  if (BundNgInit(bund, reqIface) < 0) {
    Log(LG_ERR, ("[%s] netgraph initialization failed", bund->name));
    Freee(MB_BUND, bund);
    bund = old_bund;
    return(0);
  }

  /* Create each link and add it to the bundle */
  bund->links = Malloc(MB_LINK, (ac - 1) * sizeof(*bund->links));
  for (k = 1; k < ac; k++) {
#if NG_NODESIZ>=32
    if (strlen(av[k])>16) {
#else
    if (strlen(av[k])>6) {
#endif
	Log(LG_ERR, ("link name \"%s\" is too long", av[k]));
	BundShutdown(bund);
	bund = old_bund;
	return(0);
    }
    if ((new_link = LinkNew(av[k], bund, bund->n_links)) == NULL)
      Log(LG_ERR, ("[%s] addition of link \"%s\" failed", av[0], av[k]));
    else {
      bund->links[bund->n_links] = new_link;
      bund->n_links++;
    }
  }

  /* We need at least one link in the bundle */
  if (bund->n_links == 0) {
    Log(LG_ERR, ("bundle \"%s\" creation failed: no links", av[0]));
    BundShutdown(bund);
    bund = old_bund;
    return(0);
  }

  /* Add bundle to the list of bundles and make it the current active bundle */
  for (k = 0; k < gNumBundles && gBundles[k] != NULL; k++);
  if (k == gNumBundles)			/* add a new bundle pointer */
    LengthenArray(&gBundles, sizeof(*gBundles), &gNumBundles, MB_BUND);

  bund->id = k;
  gBundles[k] = bund;

  /* Init interface stuff */
  IfaceInit();

  if (tee)
    Enable(&bund->iface.options, IFACE_CONF_TEE);
  if (nat)
    Enable(&bund->iface.options, IFACE_CONF_NAT);
  if (netflow_in)
    Enable(&bund->iface.options, IFACE_CONF_NETFLOW_IN);
  if (netflow_out)
    Enable(&bund->iface.options, IFACE_CONF_NETFLOW_OUT);

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

  Enable(&bund->conf.options, BUND_CONF_IPCP);
  Disable(&bund->conf.options, BUND_CONF_IPV6CP);

  Disable(&bund->conf.options, BUND_CONF_BWMANAGE);
  Disable(&bund->conf.options, BUND_CONF_COMPRESSION);
  Disable(&bund->conf.options, BUND_CONF_ENCRYPTION);
  Disable(&bund->conf.options, BUND_CONF_CRYPT_REQD);
  
  Enable(&bund->conf.options, BUND_CONF_NORETRY);

  /* Init NCP's */
  IpcpInit();
  Ipv6cpInit();
  CcpInit();
  EcpInit();
  
  /* Done */
  return(0);
}

/*
 * BundShutdown()
 *
 * Shutdown the netgraph stuff associated with bundle
 */

void
BundShutdown(Bund b)
{
  Link	l;
  int	k;

  for (k = 0; k < b->n_links; k++) {
    l = b->links[k];
    if (l)
	LinkShutdown(l);
  }
  Freee(MB_LINK, b->links);

  BundNgShutdown(b, 1, 1);
  gBundles[b->id] = NULL;
  Freee(MB_BUND, b);
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
  Printf("\tLinks          : ");
  BundShowLinks(sb);
  Printf("\tStatus         : %s\r\n", sb->open ? "OPEN" : "CLOSED");
  Printf("\tM-Session-Id   : %s\r\n", sb->msession_id);
  Printf("\tTotal bandwidth: %u bits/sec\r\n", tbw);
  Printf("\tAvail bandwidth: %u bits/sec\r\n", bw);
  Printf("\tPeer authname  : \"%s\"\r\n", sb->params.authname);
  Printf("\tPeer discrim.  : %s\r\n", MpDiscrimText(&sb->peer_discrim));

  /* Show configuration */
  Printf("Configuration:\r\n");
  Printf("\tMy MRRU        : %d bytes\r\n", sb->conf.mrru);
  Printf("\tRetry timeout  : %d seconds\r\n", sb->conf.retry_timeout);
  Printf("\tBW-manage:\r\n");
  Printf("\t  Period       : %d seconds\r\n", sb->conf.bm_S);
  Printf("\t  Low mark     : %d%%\r\n", sb->conf.bm_Lo);
  Printf("\t  High mark    : %d%%\r\n", sb->conf.bm_Hi);
  Printf("\t  Min conn     : %d seconds\r\n", sb->conf.bm_Mc);
  Printf("\t  Min disc     : %d seconds\r\n", sb->conf.bm_Md);
  Printf("Bundle level options:\r\n");
  OptStat(&sb->conf.options, gConfList);

  /* Show peer info */
  if (sb->bm.n_up > 0) {
    Printf("Multilink PPP:\r\n");
    Printf("\tStatus         : %s\r\n",
      sb->multilink ? "Active" : "Inactive\r\n");
    if (sb->multilink) {
      Printf("\tPeer auth name : \"%s\"\r\n", sb->params.authname);
      Printf("\tPeer discrimin.: %s\r\n", MpDiscrimText(&sb->peer_discrim));
    }
  }

  /* Show stats */
  BundUpdateStats(bund);
  Printf("Traffic stats:\r\n");

  Printf("\tOctets input   : %llu\r\n", bund->stats.recvOctets);
  Printf("\tFrames input   : %llu\r\n", bund->stats.recvFrames);
  Printf("\tOctets output  : %llu\r\n", bund->stats.xmitOctets);
  Printf("\tFrames output  : %llu\r\n", bund->stats.xmitFrames);
  Printf("\tBad protocols  : %llu\r\n", bund->stats.badProtos);
#if NGM_PPP_COOKIE >= 940897794
  Printf("\tRunts          : %llu\r\n", bund->stats.runts);
#endif
  Printf("\tDup fragments  : %llu\r\n", bund->stats.dupFragments);
#if NGM_PPP_COOKIE >= 940897794
  Printf("\tDrop fragments : %llu\r\n", bund->stats.dropFragments);
#endif

  return(0);
}

/* 
 * BundUpdateStats()
 */

void
BundUpdateStats(Bund b)
{
  struct ng_ppp_link_stat	stats;

  if (NgFuncGetStats(b, NG_PPP_BUNDLE_LINKNUM, FALSE, &stats) != -1) {
    b->stats.xmitFrames += abs(stats.xmitFrames - b->oldStats.xmitFrames);
    b->stats.xmitOctets += abs(stats.xmitOctets - b->oldStats.xmitOctets);
    b->stats.recvFrames += abs(stats.recvFrames - b->oldStats.recvFrames);
    b->stats.recvOctets += abs(stats.recvOctets - b->oldStats.recvOctets);
    b->stats.badProtos  += abs(stats.badProtos - b->oldStats.badProtos);
#if NGM_PPP_COOKIE >= 940897794
    b->stats.runts	  += abs(stats.runts - b->oldStats.runts);
#endif
    b->stats.dupFragments += abs(stats.dupFragments - b->oldStats.dupFragments);
#if NGM_PPP_COOKIE >= 940897794
    b->stats.dropFragments += abs(stats.dropFragments - b->oldStats.dropFragments);
#endif
  }

  b->oldStats = stats;
}

/* 
 * BundUpdateStatsTimer()
 */

void
BundUpdateStatsTimer(void *cookie)
{
  Bund b = (Bund)cookie;
  TimerStop(&b->statsUpdateTimer);
  BundUpdateStats(b);
  TimerStart(&b->statsUpdateTimer);
}

/*
 * BundResetStats()
 */

void
BundResetStats(void)
{
  NgFuncGetStats(bund, NG_PPP_BUNDLE_LINKNUM, TRUE, NULL);
  memset(&bund->stats, 0, sizeof(struct linkstats));
  memset(&bund->oldStats, 0, sizeof(bund->oldStats));
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
	gPhysStateNames[sb->links[j]->phys->state]);
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
      BundBmTimeout, bund);
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
    Bund b = (Bund)arg;

  const time_t	now = time(NULL);
  u_int		availTotal;
  u_int		inUtilTotal = 0, outUtilTotal = 0;
  u_int		inBitsTotal, outBitsTotal;
  u_int		inUtil[LINK_BM_N];	/* Incoming % utilization */
  u_int		outUtil[LINK_BM_N];	/* Outgoing % utilization */
  int		j, k;

  /* Shift and update stats */
  for (k = 0; k < b->n_links; k++) {
    Link	const l = b->links[k];

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
      NgFuncGetStats(l->bund, l->bundleIndex, FALSE, &l->bm.idleStats);
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
    for (avail = inBits = outBits = k = 0; k < b->n_links; k++) {
      Link	const l = b->links[k];

      if (l->bm.wasUp[j]) {
	avail += (l->bandwidth * b->conf.bm_S) / LINK_BM_N;
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
      for (k = 0; k < b->n_links; k++) {
	Link	const l = b->links[k];

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
  if (now - b->bm.last_open >= b->conf.bm_Mc
      && (inUtilTotal >= b->conf.bm_Hi || outUtilTotal >= b->conf.bm_Hi)
      && b->bm.n_open < b->n_links) {
    k = 0;
    while (k < b->n_links && OPEN_STATE(b->links[k]->lcp.fsm.state))
	k++;
    assert(k < b->n_links);
    Log(LG_BUND, ("[%s] opening link %s due to increased demand",
      b->name, b->links[k]->name));
    b->bm.last_open = now;
    RecordLinkUpDownReason(lnk, 1, STR_PORT_NEEDED, NULL);
    BundOpenLink(b->links[k]);
  }

  /* See if it's time to bring down a link */
  if (now - b->bm.last_close >= b->conf.bm_Md
      && (inUtilTotal < b->conf.bm_Lo && outUtilTotal < b->conf.bm_Lo)
      && b->bm.n_up > 1) {
    k = b->n_links - 1;
    while (k >= 0 && !OPEN_STATE(b->links[k]->lcp.fsm.state))
	k--;
    assert(k >= 0);
    Log(LG_BUND, ("[%s] closing link %s due to reduced demand",
      b->name, b->links[k]->name));
    b->bm.last_close = now;
    RecordLinkUpDownReason(lnk, 0, STR_PORT_UNNEEDED, NULL);
    BundCloseLink(b->links[k]);
  }

  /* Restart timer */
  TimerStart(&b->bm.bmTimer);
}

/*
 * BundNgInit()
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

static int
BundNgInit(Bund b, const char *reqIface)
{
  union {
      u_char		buf[sizeof(struct ng_mesg) + sizeof(struct nodeinfo)];
      struct ng_mesg	reply;
  }			u;
  struct nodeinfo	*const ni = (struct nodeinfo *)(void *)u.reply.data;
  struct ngm_mkpeer	mp;
  struct ngm_name	nm;
  int			newIface = 0;
  int			newPpp = 0;

  /* Create a netgraph socket node */
  if (NgMkSockNode(NULL, &b->csock, &b->dsock) < 0) {
    Log(LG_ERR, ("[%s] can't create %s node: %s",
      b->name, NG_SOCKET_NODE_TYPE, strerror(errno)));
    return(-1);
  }
  (void) fcntl(b->csock, F_SETFD, 1);
  (void) fcntl(b->dsock, F_SETFD, 1);

#if NG_NODESIZ>=32
  /* Give it a name */
  snprintf(nm.name, sizeof(nm.name), "mpd%d-%s-so", gPid, b->name);
  if (NgSendMsg(b->csock, ".",
      NGM_GENERIC_COOKIE, NGM_NAME, &nm, sizeof(nm)) < 0) {
    Log(LG_ERR, ("[%s] can't name %s node: %s",
      b->name, NG_SOCKET_NODE_TYPE, strerror(errno)));
    goto fail;
  }
#endif

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
    Log(LG_ERR, ("[%s] can't create %s node at \"%s\"->\"%s\": %s",
      b->name, mp.type, ".", mp.ourhook, strerror(errno)));
    goto fail;
  }
  newPpp = 1;

  /* Give it a name */
  snprintf(nm.name, sizeof(nm.name), "mpd%d-%s", gPid, b->name);
  if (NgSendMsg(b->csock, MPD_HOOK_PPP,
      NGM_GENERIC_COOKIE, NGM_NAME, &nm, sizeof(nm)) < 0) {
    Log(LG_ERR, ("[%s] can't name %s node \"%s\": %s",
      b->name, NG_PPP_NODE_TYPE, MPD_HOOK_PPP, strerror(errno)));
    goto fail;
  }

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

  /* Listen for happenings on our node */
  EventRegister(&b->dataEvent, EVENT_READ,
    b->dsock, EVENT_RECURRING, BundNgDataEvent, b);
  EventRegister(&b->ctrlEvent, EVENT_READ,
    b->csock, EVENT_RECURRING, BundNgCtrlEvent, b);

  /* OK */
  return(0);

fail:
  BundNgShutdown(b, newIface, newPpp);
  return(-1);
}

/*
 * NgFuncShutdown()
 */

void
BundNgShutdown(Bund b, int iface, int ppp)
{
  char	path[NG_PATHLEN + 1];

  if (iface) {
    snprintf(path, sizeof(path), "%s:", b->iface.ifname);
    NgFuncShutdownNode(b->csock, b->name, path);
  }
  if (ppp) {
    NgFuncShutdownNode(b->csock, b->name, MPD_HOOK_PPP);
  }
  close(b->csock);
  b->csock = -1;
  EventUnRegister(&b->ctrlEvent);
  close(b->dsock);
  b->dsock = -1;
  EventUnRegister(&b->dataEvent);
}


/*
 * BundNgDataEvent()
 */

static void
BundNgDataEvent(int type, void *cookie)
{
  u_char		buf[8192];
  struct sockaddr_ng	naddr;
  int			nread, nsize = sizeof(naddr);
  Mbuf 			nbp;

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
      mbufise(MB_FRAME_IN, buf + 4, nread - 4));
    return;
  }

  /* A snooped, outgoing IP frame? */
  if (strcmp(naddr.sg_data, MPD_HOOK_DEMAND_TAP) == 0) {

    /* Debugging */
    LogDumpBuf(LG_FRAME, buf, nread,
      "[%s] rec'd IP frame on demand/mssfix-in hook", bund->name);
    IfaceListenInput(PROTO_IP,
      mbufise(MB_FRAME_IN, buf, nread));
    return;
  }
#ifndef USE_NG_TCPMSS
  /* A snooped, outgoing TCP SYN frame? */
  if (strcmp(naddr.sg_data, MPD_HOOK_TCPMSS_OUT) == 0) {
    /* Debugging */
    LogDumpBuf(LG_FRAME, buf, nread,
      "[%s] rec'd IP frame on mssfix-out hook", bund->name);
    nbp = mbufise(MB_FRAME_IN, buf, nread);
    IfaceCorrectMSS(nbp, MAXMSS(bund->iface.mtu));
    NgFuncWriteFrame(bund->name, MPD_HOOK_TCPMSS_IN, nbp);
    return;
  }
  /* A snooped, incoming TCP SYN frame? */
  if (strcmp(naddr.sg_data, MPD_HOOK_TCPMSS_IN) == 0) {
    /* Debugging */
    LogDumpBuf(LG_FRAME, buf, nread,
      "[%s] rec'd IP frame on mssfix-in hook", bund->name);
    nbp = mbufise(MB_FRAME_IN, buf, nread);
    IfaceCorrectMSS(nbp, MAXMSS(bund->iface.mtu));
    NgFuncWriteFrame(bund->name, MPD_HOOK_TCPMSS_OUT, nbp);
    return;
  }
#endif

  /* Packet requiring compression */
  if (strcmp(naddr.sg_data, NG_PPP_HOOK_COMPRESS) == 0) {

    /* Debugging */
    LogDumpBuf(LG_FRAME, buf, nread,
      "[%s] rec'd frame on %s hook", bund->name, NG_PPP_HOOK_COMPRESS);

    nbp = CcpDataOutput(mbufise(MB_COMP, buf, nread));
    if (nbp)
	NgFuncWriteFrame(bund->name, NG_PPP_HOOK_COMPRESS, nbp);

    return;
  }

  /* Packet requiring decompression */
  if (strcmp(naddr.sg_data, NG_PPP_HOOK_DECOMPRESS) == 0) {
    /* Debugging */
    LogDumpBuf(LG_FRAME, buf, nread,
      "[%s] rec'd frame on %s hook", bund->name, NG_PPP_HOOK_DECOMPRESS);

    nbp = CcpDataInput(mbufise(MB_COMP, buf, nread));
    if (nbp)
	NgFuncWriteFrame(bund->name, NG_PPP_HOOK_DECOMPRESS, nbp);

    return;
  }

  /* Packet requiring encryption */
  if (strcmp(naddr.sg_data, NG_PPP_HOOK_ENCRYPT) == 0) {

    /* Debugging */
    LogDumpBuf(LG_FRAME, buf, nread,
      "[%s] rec'd frame on %s hook", bund->name, NG_PPP_HOOK_ENCRYPT);

    nbp = EcpDataOutput(mbufise(MB_CRYPT, buf, nread));
    if (nbp)
	NgFuncWriteFrame(bund->name, NG_PPP_HOOK_ENCRYPT, nbp);

    return;
  }

  /* Packet requiring decryption */
  if (strcmp(naddr.sg_data, NG_PPP_HOOK_DECRYPT) == 0) {
    /* Debugging */
    LogDumpBuf(LG_FRAME, buf, nread,
      "[%s] rec'd frame on %s hook", bund->name, NG_PPP_HOOK_DECRYPT);

    nbp = EcpDataInput(mbufise(MB_CRYPT, buf, nread));
    if (nbp) 
	NgFuncWriteFrame(bund->name, NG_PPP_HOOK_DECRYPT, nbp);

    return;
  }

  /* Unknown hook! */
  LogDumpBuf(LG_FRAME, buf, nread,
    "[%s] rec'd data on unknown hook \"%s\"", bund->name, naddr.sg_data);
  DoExit(EX_ERRDEAD);
}

/*
 * BundNgCtrlEvent()
 *
 */

static void
BundNgCtrlEvent(int type, void *cookie)
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
#ifdef COMPRESSION_DEFLATE
#ifdef USE_NG_DEFLATE
    case NGM_DEFLATE_COOKIE:
#endif
#endif
#ifdef COMPRESSION_PRED1
#ifdef USE_NG_PRED1
    case NGM_PRED1_COOKIE:
#endif
#endif
      CcpRecvMsg(&u.msg, len);
      return;

    default:
      break;
  }

  /* Unknown message */
  Log(LG_ERR, ("[%s] rec'd unknown ctrl message, cookie=%d cmd=%d",
    bund->name, u.msg.header.typecookie, u.msg.header.cmd));
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

