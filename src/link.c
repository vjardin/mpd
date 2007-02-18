
/*
 * link.c
 *
 * Written by Archie Cobbs <archie@freebsd.org>
 * Copyright (c) 1995-1999 Whistle Communications, Inc. All rights reserved.
 * See ``COPYRIGHT.whistle''
 */

#include "ppp.h"
#include "link.h"
#include "msg.h"
#include "lcp.h"
#include "phys.h"
#include "command.h"
#include "input.h"
#include "ngfunc.h"
#include "util.h"

/*
 * DEFINITIONS
 */

  /* Set menu options */
  enum {
    SET_DEVTYPE,
    SET_BANDWIDTH,
    SET_LATENCY,
    SET_ACCMAP,
    SET_MRU,
    SET_MTU,
    SET_FSM_RETRY,
    SET_MAX_RETRY,
    SET_KEEPALIVE,
    SET_IDENT,
    SET_ACCEPT,
    SET_DENY,
    SET_ENABLE,
    SET_DISABLE,
    SET_YES,
    SET_NO,
  };

  #define RBUF_SIZE		100

/*
 * INTERNAL FUNCTIONS
 */

  static int	LinkSetCommand(int ac, char *av[], void *arg);
  static void	LinkMsg(int type, void *cookie);

/*
 * GLOBAL VARIABLES
 */

  const struct cmdtab LinkSetCmds[] = {
    { "bandwidth bps",			"Link bandwidth",
	LinkSetCommand, NULL, (void *) SET_BANDWIDTH },
    { "type type",			"Device type",
	LinkSetCommand, NULL, (void *) SET_DEVTYPE },
    { "latency microsecs",		"Link latency",
	LinkSetCommand, NULL, (void *) SET_LATENCY },
    { "accmap hex-value",		"Accmap value",
	LinkSetCommand, NULL, (void *) SET_ACCMAP },
    { "mru value",			"Link MRU value",
	LinkSetCommand, NULL, (void *) SET_MRU },
    { "mtu value",			"Link MTU value",
	LinkSetCommand, NULL, (void *) SET_MTU },
    { "fsm-timeout seconds",		"FSM retry timeout",
	LinkSetCommand, NULL, (void *) SET_FSM_RETRY },
    { "max-redial num",			"Max connect attempts",
	LinkSetCommand, NULL, (void *) SET_MAX_RETRY },
    { "keep-alive secs max",		"LCP echo keep-alives",
	LinkSetCommand, NULL, (void *) SET_KEEPALIVE },
    { "ident ident-string",		"LCP ident string",
	LinkSetCommand, NULL, (void *) SET_IDENT },
    { "accept [opt ...]",		"Accept option",
	LinkSetCommand, NULL, (void *) SET_ACCEPT },
    { "deny [opt ...]",			"Deny option",
	LinkSetCommand, NULL, (void *) SET_DENY },
    { "enable [opt ...]",		"Enable option",
	LinkSetCommand, NULL, (void *) SET_ENABLE },
    { "disable [opt ...]",		"Disable option",
	LinkSetCommand, NULL, (void *) SET_DISABLE },
    { "yes [opt ...]",			"Enable and accept option",
	LinkSetCommand, NULL, (void *) SET_YES },
    { "no [opt ...]",			"Disable and deny option",
	LinkSetCommand, NULL, (void *) SET_NO },
    { NULL },
  };

/*
 * INTERNAL VARIABLES
 */

  static struct confinfo	gConfList[] = {
    { 1,	LINK_CONF_PAP,		"pap"		},
    { 1,	LINK_CONF_CHAPMD5,	"chap-md5"	},
    { 1,	LINK_CONF_CHAPMSv1,	"chap-msv1"	},
    { 1,	LINK_CONF_CHAPMSv2,	"chap-msv2"	},
    { 1,	LINK_CONF_EAP,		"eap"		},
    { 1,	LINK_CONF_ACFCOMP,	"acfcomp"	},
    { 1,	LINK_CONF_PROTOCOMP,	"protocomp"	},
    { 0,	LINK_CONF_MSDOMAIN,	"keep-ms-domain"},
    { 0,	LINK_CONF_MAGICNUM,	"magicnum"	},
    { 0,	LINK_CONF_PASSIVE,	"passive"	},
    { 0,	LINK_CONF_CHECK_MAGIC,	"check-magic"	},
    { 0,	LINK_CONF_NO_ORIG_AUTH,	"no-orig-auth"	},
    { 0,	LINK_CONF_CALLBACK,	"callback"	},
    { 0,	0,			NULL		},
  };

/*
 * LinkOpenCmd()
 */

void
LinkOpenCmd(void)
{
  RecordLinkUpDownReason(lnk, 1, STR_MANUALLY, NULL);
  LinkOpen(lnk);
}

/*
 * LinkCloseCmd()
 */

void
LinkCloseCmd(void)
{
  RecordLinkUpDownReason(lnk, 0, STR_MANUALLY, NULL);
  LinkClose(lnk);
}

/*
 * LinkOpen()
 */

void
LinkOpen(Link l)
{
  MsgSend(l->msgs, MSG_OPEN, NULL);
}

/*
 * LinkClose()
 */

void
LinkClose(Link l)
{
  MsgSend(l->msgs, MSG_CLOSE, NULL);
}

/*
 * LinkUp()
 */

void
LinkUp(Link l)
{
  MsgSend(l->msgs, MSG_UP, NULL);
}

/*
 * LinkDown()
 */

void
LinkDown(Link l)
{
  MsgSend(l->msgs, MSG_DOWN, NULL);
}

/*
 * LinkMsg()
 *
 * Deal with incoming message to this link
 */

static void
LinkMsg(int type, void *arg)
{
  Log(LG_LINK, ("[%s] link: %s event", lnk->name, MsgName(type)));
  switch (type) {
    case MSG_OPEN:
      lnk->last_open = time(NULL);
      lnk->num_redial = 0;
      LcpOpen();
      break;
    case MSG_CLOSE:
      LcpClose();
      break;
    case MSG_UP:
      lnk->originate = PhysGetOriginate();
      Log(LG_LINK, ("[%s] link: origination is %s",
	lnk->name, LINK_ORIGINATION(lnk->originate)));
      LcpUp();
      break;
    case MSG_DOWN:
      if (OPEN_STATE(lnk->lcp.fsm.state)) {
	if ((lnk->conf.max_redial != 0) && (lnk->num_redial >= lnk->conf.max_redial)) {
	  if (lnk->conf.max_redial >= 0)
	    Log(LG_LINK, ("[%s] link: giving up after %d reconnection attempts",
		lnk->name, lnk->num_redial));
	  SetStatus(ADLG_WAN_WAIT_FOR_DEMAND, STR_READY_TO_DIAL);
	  LcpClose();
          LcpDown();
	  BundLinkGaveUp();	/* now doing nothing */
	} else {
	  lnk->num_redial++;
	  Log(LG_LINK, ("[%s] link: reconnection attempt %d",
	    lnk->name, lnk->num_redial));
	  RecordLinkUpDownReason(lnk, 1, STR_REDIAL, NULL);
    	  LcpDown();
	  PhysOpen();					/* Try again */
	}
      } else {
        LcpDown();
      }
      /* reset Link-stats */
      LinkResetStats();  /* XXX: I don't think this is a right place */
      break;
  }
}

/*
 * LinkNew()
 *
 * Allocate a new link for the specified device, then
 * read in any device-specific commands from ppp.links.
 */

Link
LinkNew(char *name, Bund b, int bI)
{
  int		k;

  /* Check if name is already used */
  for (k = 0; k < gNumLinks; k++) {
    if (gLinks[k] && !strcmp(gLinks[k]->name, name)) {
      Log(LG_ERR, ("link \"%s\" already defined in bundle \"%s\"",
	name, gLinks[k]->bund->name));
      return(NULL);
    }
  }

  /* Find a free link pointer */
  for (k = 0; k < gNumLinks && gLinks[k] != NULL; k++);
  if (k == gNumLinks)			/* add a new link pointer */
    LengthenArray(&gLinks, sizeof(*gLinks), &gNumLinks, MB_LINK);

  /* Create and initialize new link */
  lnk = Malloc(MB_LINK, sizeof(*lnk));
  gLinks[k] = lnk;
  snprintf(lnk->name, sizeof(lnk->name), "%s", name);
  lnk->bund = b;
  lnk->bundleIndex = bI;
  lnk->msgs = MsgRegister(LinkMsg, 0);

  /* Initialize link configuration with defaults */
  lnk->conf.mru = LCP_DEFAULT_MRU;
  lnk->conf.mtu = LCP_DEFAULT_MRU;
  lnk->conf.accmap = 0x000a0000;
  lnk->conf.max_redial = -1;
  lnk->conf.retry_timeout = LINK_DEFAULT_RETRY;
  lnk->bandwidth = LINK_DEFAULT_BANDWIDTH;
  lnk->latency = LINK_DEFAULT_LATENCY;
  lnk->upReason = NULL;
  lnk->upReasonValid = 0;
  lnk->downReason = NULL;
  lnk->downReasonValid = 0;

  Disable(&lnk->conf.options, LINK_CONF_CHAPMD5);
  Accept(&lnk->conf.options, LINK_CONF_CHAPMD5);

  Disable(&lnk->conf.options, LINK_CONF_CHAPMSv1);
  Deny(&lnk->conf.options, LINK_CONF_CHAPMSv1);

  Disable(&lnk->conf.options, LINK_CONF_CHAPMSv2);
  Accept(&lnk->conf.options, LINK_CONF_CHAPMSv2);

  Disable(&lnk->conf.options, LINK_CONF_PAP);
  Accept(&lnk->conf.options, LINK_CONF_PAP);

  Disable(&lnk->conf.options, LINK_CONF_EAP);
  Accept(&lnk->conf.options, LINK_CONF_EAP);

  Disable(&lnk->conf.options, LINK_CONF_MSDOMAIN);

  Enable(&lnk->conf.options, LINK_CONF_ACFCOMP);
  Accept(&lnk->conf.options, LINK_CONF_ACFCOMP);

  Enable(&lnk->conf.options, LINK_CONF_PROTOCOMP);
  Accept(&lnk->conf.options, LINK_CONF_PROTOCOMP);

  Enable(&lnk->conf.options, LINK_CONF_MAGICNUM);
  Disable(&lnk->conf.options, LINK_CONF_PASSIVE);
  Enable(&lnk->conf.options, LINK_CONF_CHECK_MAGIC);

  LcpInit();
  EapInit();

  /* Initialize link layer stuff */
  lnk->phys = PhysInit(lnk->name, lnk);

  /* Hang out and be a link */
  return(lnk);
}

/*
 * LinkCopy()
 *
 * Makes a copy of the active Link.
 */

Link
LinkCopy(void)
{
  Link	nlnk;
  
  nlnk = Malloc(MB_LINK, sizeof(*nlnk));
  memcpy(nlnk, lnk, sizeof(*lnk));
  nlnk->downReason = NULL;
  if (lnk->downReason != NULL) {
    nlnk->downReason = Malloc(MB_LINK, strlen(lnk->downReason) + 1);
    strcpy(nlnk->downReason, lnk->downReason);
  }

  return nlnk;
}

/*
 * LinkCommand()
 */

int
LinkCommand(int ac, char *av[], void *arg)
{
  int	k;

  if (ac != 1)
    return(-1);

  k = gNumLinks;
  if ((sscanf(av[0], "[%x]", &k) != 1) || (k < 0) || (k >= gNumLinks)) {
     /* Find link */
    for (k = 0;
	k < gNumLinks && (!gLinks[k] || strcmp(gLinks[k]->name, av[0]));
	k++);
  };
  if (k == gNumLinks) {
    Printf("Link \"%s\" is not defined\r\n", av[0]);
    return(0);
  }

  /* Change default link and bundle */
  if (gConsoleSession) {
    gConsoleSession->link = gLinks[k];
    gConsoleSession->bund = gConsoleSession->link->bund;
  } else {
    lnk = gLinks[k];
    bund = lnk->bund;
    phys = lnk->phys;
  }
  return(0);
}

/*
 * RecordLinkUpDownReason()
 *
 * This is called whenever a reason for the link going up or
 * down has just become known. Record this reason so that when
 * the link actually goes up or down, we can record it.
 *
 * If this gets called more than once in the "down" case,
 * the first call prevails.
 */
static void
RecordLinkUpDownReason2(Link l, int up, const char *key, const char *fmt, va_list args)
{
  char	**const cpp = up ? &l->upReason : &l->downReason;
  char	*buf;

  /* First reason overrides later ones */
  if (up) {
    if (l->upReasonValid) {
	return;
    } else {
	l->upReasonValid = 1;
    }
  } else {
    if (l->downReasonValid) {
	return;
    } else {
	l->downReasonValid = 1;
    }
  }

  /* Allocate buffer if necessary */
  if (!*cpp)
    *cpp = Malloc(MB_UTIL, RBUF_SIZE);
  buf = *cpp;

  /* Record reason */
  if (fmt) {
    snprintf(buf, RBUF_SIZE, "%s:", key);
    vsnprintf(buf + strlen(buf), RBUF_SIZE - strlen(buf), fmt, args);
  } else 
    snprintf(buf, RBUF_SIZE, "%s", key);
}

void
RecordLinkUpDownReason(Link l, int up, const char *key, const char *fmt, ...)
{
  va_list	args;
  int		k;

  if (!bund)
    return;

  if (l == NULL) {
    for (k = 0; k < bund->n_links; k++) {
      if (bund && bund->links[k]) {
	va_start(args, fmt);
	RecordLinkUpDownReason2(bund->links[k], up, key, fmt, args);
	va_end(args);
      }
    }
  } else {
    va_start(args, fmt);
    RecordLinkUpDownReason2(l, up, key, fmt, args);
    va_end(args);
  }
}

/*
 * LinkStat()
 */

int
LinkStat(int ac, char *av[], void *arg)
{
  Printf("Link %s:\r\n", lnk->name);

  Printf("Configuration\r\n");
  Printf("\tMRU            : %d bytes\r\n", lnk->conf.mru);
  Printf("\tCtrl char map  : 0x%08x bytes\r\n", lnk->conf.accmap);
  Printf("\tRetry timeout  : %d seconds\r\n", lnk->conf.retry_timeout);
  Printf("\tMax redial     : ");
  if (lnk->conf.max_redial < 0)
    Printf("no redial\r\n");
  else if (lnk->conf.max_redial == 0) 
    Printf("unlimited\r\n");
  else
    Printf("%d connect attempts\r\n", lnk->conf.max_redial);
  Printf("\tBandwidth      : %d bits/sec\r\n", lnk->bandwidth);
  Printf("\tLatency        : %d usec\r\n", lnk->latency);
  Printf("\tKeep-alive     : ");
  if (lnk->lcp.fsm.conf.echo_int == 0)
    Printf("disabled\r\n");
  else
    Printf("every %d secs, timeout %d\r\n",
      lnk->lcp.fsm.conf.echo_int, lnk->lcp.fsm.conf.echo_max);
  Printf("\tIdent string   : \"%s\"\r\n", lnk->conf.ident ? lnk->conf.ident : "");
  Printf("\tSession-Id     : %s\r\n", lnk->session_id);
  Printf("Link level options\r\n");
  OptStat(&lnk->conf.options, gConfList);
  LinkUpdateStats();
  Printf("Up/Down stats:\r\n");
  if (lnk->downReason && (!lnk->downReasonValid))
    Printf("\tDown Reason    : %s\r\n", lnk->downReason);
  if (lnk->upReason)
    Printf("\tUp Reason      : %s\r\n", lnk->upReason);
  if (lnk->downReason && lnk->downReasonValid)
    Printf("\tDown Reason    : %s\r\n", lnk->downReason);
  
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
 * LinkUpdateStats()
 */

void
LinkUpdateStats(void)
{
  struct ng_ppp_link_stat	stats;

  if (NgFuncGetStats(lnk->bundleIndex, FALSE, &stats) != -1) {
    lnk->stats.xmitFrames += abs(stats.xmitFrames - lnk->oldStats.xmitFrames);
    lnk->stats.xmitOctets += abs(stats.xmitOctets - lnk->oldStats.xmitOctets);
    lnk->stats.recvFrames += abs(stats.recvFrames - lnk->oldStats.recvFrames);
    lnk->stats.recvOctets += abs(stats.recvOctets - lnk->oldStats.recvOctets);
    lnk->stats.badProtos  += abs(stats.badProtos - lnk->oldStats.badProtos);
#if NGM_PPP_COOKIE >= 940897794
    lnk->stats.runts	  += abs(stats.runts - lnk->oldStats.runts);
#endif
    lnk->stats.dupFragments += abs(stats.dupFragments - lnk->oldStats.dupFragments);
#if NGM_PPP_COOKIE >= 940897794
    lnk->stats.dropFragments += abs(stats.dropFragments - lnk->oldStats.dropFragments);
#endif
  }

  lnk->oldStats = stats;
}

/* 
 * LinkUpdateStatsTimer()
 */

void
LinkUpdateStatsTimer(void *cookie)
{
  TimerStop(&lnk->statsUpdateTimer);
  LinkUpdateStats();
  TimerStart(&lnk->statsUpdateTimer);
}

/*
 * LinkResetStats()
 */

void
LinkResetStats(void)
{
  NgFuncGetStats(lnk->bundleIndex, TRUE, NULL);
  memset(&lnk->stats, 0, sizeof(struct linkstats));
}

/*
 * LinkSetCommand()
 */

static int
LinkSetCommand(int ac, char *av[], void *arg)
{
  int		val, nac = 0;
  const char	*name;
  char		*nav[ac];
  const char	*av2[] = { "chap-md5", "chap-msv1", "chap-msv2" };

  if (ac == 0)
    return(-1);

  /* make "chap" as an alias for all chap-variants, this should keep BC */
  switch ((intptr_t)arg) {
    case SET_ACCEPT:
    case SET_DENY:
    case SET_ENABLE:
    case SET_DISABLE:
    case SET_YES:
    case SET_NO:
    {
      int	i = 0;
      for ( ; i < ac; i++)
      {
	if (strcasecmp(av[i], "chap") == 0) {
	  LinkSetCommand(3, (char **)av2, arg);
	} else {
	  nav[nac++] = av[i];
	} 
      }
      av = nav;
      ac = nac;
      break;
    }
  }

  switch ((intptr_t)arg) {
    case SET_BANDWIDTH:
      val = atoi(*av);
      if (val <= 0)
	Log(LG_ERR, ("[%s] Bandwidth must be positive", lnk->name));
      else if (val > NG_PPP_MAX_BANDWIDTH * 10 * 8) {
	lnk->bandwidth = NG_PPP_MAX_BANDWIDTH * 10 * 8;
	Log(LG_ERR, ("[%s] Bandwidth truncated to %d bit/s", lnk->name, 
	    lnk->bandwidth));
      } else
	lnk->bandwidth = val;
      break;

    case SET_LATENCY:
      val = atoi(*av);
      if (val < 0)
	Log(LG_ERR, ("[%s] Latency must be not negative", lnk->name));
      else if (val > NG_PPP_MAX_LATENCY * 1000) {
	Log(LG_ERR, ("[%s] Latency truncated to %d usec", lnk->name, 
	    NG_PPP_MAX_LATENCY * 1000));
	lnk->latency = NG_PPP_MAX_LATENCY * 1000;
      } else
        lnk->latency = val;
      break;

    case SET_DEVTYPE:
      PhysSetDeviceType(*av);
      break;

    case SET_MRU:
    case SET_MTU:
      val = atoi(*av);
      name = ((intptr_t)arg == SET_MTU) ? "MTU" : "MRU";
      if (!lnk->phys->type)
	Log(LG_ERR, ("[%s] this link has no type set", lnk->name));
      else if (val < LCP_MIN_MRU)
	Log(LG_ERR, ("[%s] the min %s is %d", lnk->name, name, LCP_MIN_MRU));
      else if (lnk->phys->type && (val > lnk->phys->type->mru))
	Log(LG_ERR, ("[%s] the max %s on type \"%s\" links is %d",
	  lnk->name, name, lnk->phys->type->name, lnk->phys->type->mru));
      else if ((intptr_t)arg == SET_MTU)
	lnk->conf.mtu = val;
      else
	lnk->conf.mru = val;
      break;

    case SET_FSM_RETRY:
      lnk->conf.retry_timeout = atoi(*av);
      if (lnk->conf.retry_timeout < 1 || lnk->conf.retry_timeout > 10)
	lnk->conf.retry_timeout = LINK_DEFAULT_RETRY;
      break;

    case SET_MAX_RETRY:
      lnk->conf.max_redial = atoi(*av);
      break;

    case SET_ACCMAP:
      sscanf(*av, "%x", &val);
      lnk->conf.accmap = val;
      break;

    case SET_KEEPALIVE:
      if (ac != 2)
	return(-1);
      lnk->lcp.fsm.conf.echo_int = atoi(av[0]);
      lnk->lcp.fsm.conf.echo_max = atoi(av[1]);
      break;

    case SET_IDENT:
      if (ac != 1)
	return(-1);
      if (lnk->conf.ident != NULL) {
	Freee(MB_FSM, lnk->conf.ident);
	lnk->conf.ident = NULL;
      }
      if (*av[0] != '\0')
	strcpy(lnk->conf.ident = Malloc(MB_FSM, strlen(av[0]) + 1), av[0]);
      break;

    case SET_ACCEPT:
      AcceptCommand(ac, av, &lnk->conf.options, gConfList);
      break;

    case SET_DENY:
      DenyCommand(ac, av, &lnk->conf.options, gConfList);
      break;

    case SET_ENABLE:
      EnableCommand(ac, av, &lnk->conf.options, gConfList);
      break;

    case SET_DISABLE:
      DisableCommand(ac, av, &lnk->conf.options, gConfList);
      break;

    case SET_YES:
      YesCommand(ac, av, &lnk->conf.options, gConfList);
      break;

    case SET_NO:
      NoCommand(ac, av, &lnk->conf.options, gConfList);
      break;

    default:
      assert(0);
  }

  return(0);
}

