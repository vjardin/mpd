
/*
 * phys.c
 *
 * Written by Archie Cobbs <archie@freebsd.org>
 * Copyright (c) 1995-1999 Whistle Communications, Inc. All rights reserved.
 * See ``COPYRIGHT.whistle''
 */

#include "ppp.h"
#include "msg.h"
#include "link.h"
#include "devices.h"
#include "util.h"

/*
 * The physical layer has four states: DOWN, OPENING, CLOSING, and UP.
 * Each device type must implement this set of standard methods:
 *
 *  init	Called once for each device to initialize it.
 *  open	Called in the DOWN state to initiate connection.
 *		Device should eventually call PhysUp() or PhysDown().
 *  close	Called in the OPENING or UP states.
 *		Device should eventually call PhysDown().
 *  update	Called when LCP reaches the UP state. Device should
 *		update its configuration based on LCP negotiated
 *		settings, if necessary.
 *  showstat	Display device statistics.
 *
 * The device should generate UP and DOWN events in response to OPEN
 * and CLOSE events. If the device goes down suddenly after being OPEN,
 * the close method will not be explicitly called to clean up.
 *
 * All device types must support MRU's of at least 1500.
 *
 * Each device is responsible for connecting the appropriate netgraph
 * node to the PPP node when the link comes up, and disconnecting it
 * when the link goes down (or is closed). The device should NOT send
 * any NGM_PPP_SET_CONFIG messsages to the ppp node.
 */

/*
 * DEFINITIONS
 */

  struct downmsg {
    const char	*reason;
    char	buf[256];
  };

  /* Set menu options */
  enum {
    SET_DEVTYPE,
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

  static void	PhysOpenTimeout(void *arg);
  static void	PhysMsg(int type, void *arg);
  static int	PhysSetCommand(int ac, char *av[], void *arg);

/*
 * GLOBAL VARIABLES
 */

  const struct cmdtab PhysSetCmds[] = {
    { "type type",			"Device type",
	PhysSetCommand, NULL, (void *) SET_DEVTYPE },
    { NULL },
  };


  const PhysType gPhysTypes[] = {
#define _WANT_DEVICE_TYPES
#include "devices.h"
    NULL,
  };

  const char *gPhysStateNames[] = {
    "DOWN",
    "CONNECTING",
    "READY",
    "UP",
  };

/*
 * PhysInit()
 *
 * Initialize physical layer state. Note that
 * the device type remains unspecified at this point.
 */

PhysInfo
PhysInit(char *name, Link l, Rep r)
{
  PhysInfo	p;
  int		k;

  p = Malloc(MB_PHYS, sizeof(*p));
  phys = p;
  
  strlcpy(p->name, name, sizeof(p->name));
  p->state = PHYS_STATE_DOWN;
  p->msgs = MsgRegister(PhysMsg, 0);
  p->link = l;
  p->rep = r;

  /* Find a free link pointer */
  for (k = 0; k < gNumPhyses && gPhyses[k] != NULL; k++);
  if (k == gNumPhyses)			/* add a new link pointer */
    LengthenArray(&gPhyses, sizeof(*gPhyses), &gNumPhyses, MB_PHYS);

  gPhyses[k] = p;

  /* Read special configuration for link, if any */
  (void) ReadFile(LINKS_FILE, name, DoCommand);

  return(p);
}

/*
 * PhysOpenCmd()
 */

void
PhysOpenCmd(void)
{
    PhysOpen(phys);
}

/*
 * PhysOpen()
 */

void
PhysOpen(PhysInfo p)
{
  MsgSend(p->msgs, MSG_OPEN, NULL);
}

/*
 * PhysCloseCmd()
 */

void
PhysCloseCmd(void)
{
    PhysClose(phys);
}

/*
 * PhysClose()
 */

void
PhysClose(PhysInfo p)
{
  MsgSend(p->msgs, MSG_CLOSE, NULL);
}

/*
 * PhysUp()
 */

void
PhysUp(PhysInfo p)
{
  MsgSend(p->msgs, MSG_UP, NULL);
}

/*
 * PhysDown()
 */

void
PhysDown(PhysInfo p, const char *reason, const char *details, ...)
{
  struct downmsg	*dm = Malloc(MB_PHYS, sizeof(*dm));
  va_list		args;

  p->lastClose = time(NULL); /* dirty hack to avoid race condition */
  dm->reason = reason;
  if (details) {
    va_start(args, details);
    vsnprintf(dm->buf, sizeof(dm->buf), details, args);
    va_end(args);
  }
  MsgSend(p->msgs, MSG_DOWN, dm);
}

/*
 * PhysIncoming()
 */

void
PhysIncoming(PhysInfo p)
{
    if (p->link) {
	RecordLinkUpDownReason(p->link, 1, STR_INCOMING_CALL, NULL);
	BundOpenLink(p->link);
    } else if (p->rep) {
        RepIncoming(p);
    }
}

/*
 * PhysSetAccm()
 */

int
PhysSetAccm(PhysInfo p, uint32_t accm)
{
    if (p->type && p->type->setaccm)
	return (*p->type->setaccm)(p, accm);
    else 
	return (0);
}

/*
 * PhysUpdate()
 */

void
PhysUpdate(void)
{
  const PhysInfo	p = phys;

  if (p->type->update != NULL)
    (*p->type->update)(p);
}

/*
 * PhysGetUpperHook()
 */

int
PhysGetUpperHook(PhysInfo p, char *path, char *hook)
{
    if (p->link && p->link->bund) {
	snprintf(path, NG_PATHLEN, "[%lx]:", (u_long)p->link->bund->nodeID);
	snprintf(hook, NG_HOOKLEN, "%s%d",
	    NG_PPP_HOOK_LINK_PREFIX, p->link->bundleIndex);
	return 1;
    } else if (p->rep) {
	return RepGetHook(p, path, hook);
    }
    return 0;
}

/*
 * PhysGetOriginate()
 *
 * This returns one of LINK_ORIGINATE_{UNKNOWN, LOCAL, REMOTE}
 */

int
PhysGetOriginate(void)
{
  PhysInfo	const p = phys;
  PhysType	const pt = p->type;

  return((pt && pt->originate) ? (*pt->originate)(p) : LINK_ORIGINATE_UNKNOWN);
}

/*
 * PhysSetDeviceType()
 */

void
PhysSetDeviceType(char *typename)
{
  PhysInfo	const p = phys;
  PhysType	pt;
  int		k;

    Log(LG_ERR, ("[%s] device type set to %s", p->name, typename));

  /* Make sure device type not already set */
  if (p->type) {
    Log(LG_ERR, ("[%s] device type already set to %s",
      p->name, p->type->name));
    return;
  }

  /* Locate type */
  for (k = 0; (pt = gPhysTypes[k]); k++) {
    if (!strcmp(pt->name, typename))
      break;
  }
  if (pt == NULL) {
    Log(LG_ERR, ("[%s] device type \"%s\" unknown", p->name, typename));
    return;
  }
  p->type = pt;

  /* Initialize type specific stuff */
  if ((p->type->init)(p) < 0) {
    Log(LG_ERR, ("[%s] type \"%s\" initialization failed",
      p->name, p->type->name));
    p->type = NULL;
    return;
  }
}

/*
 * PhysMsg()
 */

static void
PhysMsg(int type, void *arg)
{
  PhysInfo	const p = phys;
  time_t	const now = time(NULL);

  Log(LG_PHYS2, ("[%s] device: %s event",
    p->name, MsgName(type)));
  if (!p->type) {
    Log(LG_ERR, ("[%s] this link has no type set", p->name));
    return;
  }
  switch (type) {
    case MSG_OPEN:
      if (p->link)
        p->link->downReasonValid=0;
      p->want_open = TRUE;
      if (now - p->lastClose < p->type->minReopenDelay) {
	if (TimerRemain(&p->openTimer) < 0) {
	  int	delay = p->type->minReopenDelay - (now - p->lastClose);

	  if ((random() ^ gPid ^ time(NULL)) & 1)
		delay++;
	  Log(LG_PHYS, ("[%s] pausing %d seconds before open",
	    p->name, delay));
	  TimerStop(&p->openTimer);
	  TimerInit(&p->openTimer, "PhysOpen",
	    delay * SECONDS, PhysOpenTimeout, NULL);
	  TimerStart(&p->openTimer);
	}
	break;
      }
      TimerStop(&p->openTimer);
      (*p->type->open)(p);
      break;
    case MSG_CLOSE:
      p->want_open = FALSE;
      TimerStop(&p->openTimer);
      (*p->type->close)(p);
      break;
    case MSG_DOWN:
      {
	struct downmsg	*const dm = (struct downmsg *) arg;

	p->lastClose = now;
	if (p->link) {
    	    p->link->upReasonValid=0;
	    if (*dm->buf) {
		SetStatus(ADLG_WAN_CONNECT_FAILURE, STR_COPY, dm->buf);
		RecordLinkUpDownReason(p->link, 0, dm->reason, dm->buf);
	    } else {
		SetStatus(ADLG_WAN_CONNECT_FAILURE, STR_CON_FAILED0);
		RecordLinkUpDownReason(p->link, 0, dm->reason, NULL);
	    }
	    LinkDown(p->link);
	} else if (p->rep) {
	    RepDown(p);
	}
	Freee(MB_PHYS, dm);
      }
      break;
    case MSG_UP:
	if (p->link) {
    	    LinkUp(p->link);
	} else if (p->rep) {
	    RepUp(p);
	}
      break;
  }
}

/*
 * PhysOpenTimeout()
 */

static void
PhysOpenTimeout(void *arg)
{
  PhysInfo	const p = phys;

  TimerStop(&p->openTimer);
  assert(p->want_open);
  PhysOpen(p);
}

/*
 * PhysCommand()
 */

int
PhysCommand(int ac, char *av[], void *arg)
{
  int	k;

  if (ac != 1)
    return(-1);

  k = gNumPhyses;
  if ((sscanf(av[0], "[%x]", &k) != 1) || (k < 0) || (k >= gNumLinks)) {
     /* Find link */
    for (k = 0;
	k < gNumPhyses && strcmp(gPhyses[k]->name, av[0]);
	k++);
  };
  if (k == gNumPhyses) {
    Printf("Phys \"%s\" is not defined\r\n", av[0]);
    return(0);
  }

  /* Change default link and bundle */
  if (gConsoleSession) {
    gConsoleSession->phys = gPhyses[k];
    if (gConsoleSession->phys->link) {
	gConsoleSession->link = gConsoleSession->phys->link;
	gConsoleSession->bund = gConsoleSession->link->bund;
    } else {
	gConsoleSession->link = NULL;
	gConsoleSession->bund = NULL;
    }
  } else {
    phys = gPhyses[k];
    if (phys->link) {
	lnk = phys->link;
	bund = lnk->bund;
    } else {
	lnk = NULL;
	bund = NULL;
    }
    if (phys->rep)
	rep = phys->rep;
    else
	rep = NULL;
  }
  return(0);
}


/*
 * PhysStat()
 */

int
PhysStat(int ac, char *av[], void *arg)
{
  PhysInfo	const p = phys;

  Printf("\tType  : %s\r\n", p->type->name);
  if (p->type->showstat)
    (*p->type->showstat)(p);
  return 0;
}

/*
 * PhysSetCommand()
 */

static int
PhysSetCommand(int ac, char *av[], void *arg)
{
  if (ac == 0)
    return(-1);

  switch ((intptr_t)arg) {
    case SET_DEVTYPE:
      PhysSetDeviceType(*av);
      break;
/*
    case SET_ACCEPT:
      AcceptCommand(ac, av, &phys->options, gConfList);
      break;

    case SET_DENY:
      DenyCommand(ac, av, &phys->options, gConfList);
      break;

    case SET_ENABLE:
      EnableCommand(ac, av, &phys->options, gConfList);
      break;

    case SET_DISABLE:
      DisableCommand(ac, av, &phys->options, gConfList);
      break;

    case SET_YES:
      YesCommand(ac, av, &phys->options, gConfList);
      break;

    case SET_NO:
      NoCommand(ac, av, &phys->options, gConfList);
      break;
*/
    default:
      assert(0);
  }

  return(0);
}

