
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

#ifdef __DragonFly__
#include <netgraph/tee/ng_tee.h>
#else
#include <netgraph/ng_tee.h>
#endif

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
  static int	PhysSetCommand(Context ctx, int ac, char *av[], void *arg);
  static PhysInfo	PhysFind(char *name);

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
    PhysInfo		p;
    struct context	ctx;
    int			k;

    /* See if bundle name already taken */
    if ((p = PhysFind(name)) != NULL) {
	Log(LG_ERR, ("phys \"%s\" already exists", name));
	return NULL;
    }

    p = Malloc(MB_PHYS, sizeof(*p));
  
    strlcpy(p->name, name, sizeof(p->name));
    p->state = PHYS_STATE_DOWN;
    p->msgs = MsgRegister(PhysMsg);
    p->link = l;
    p->rep = r;

    /* Find a free link pointer */
    for (k = 0; k < gNumPhyses && gPhyses[k] != NULL; k++);
    if (k == gNumPhyses)			/* add a new link pointer */
	LengthenArray(&gPhyses, sizeof(*gPhyses), &gNumPhyses, MB_PHYS);

    p->id = k;
    gPhyses[k] = p;

    memset(&ctx, 0, sizeof(ctx));
    ctx.lnk = l;
    ctx.phys = p;
    ctx.rep = NULL;
    ctx.bund = NULL;

    /* Read special configuration for link, if any */
    (void) ReadFile(LINKS_FILE, name, DoCommand, &ctx);

    return(p);
}

/*
 * PhysOpenCmd()
 */

void
PhysOpenCmd(Context ctx)
{
    PhysOpen(ctx->phys);
}

/*
 * PhysOpen()
 */

void
PhysOpen(PhysInfo p)
{
    MsgSend(p->msgs, MSG_OPEN, p);
}

/*
 * PhysCloseCmd()
 */

void
PhysCloseCmd(Context ctx)
{
    PhysClose(ctx->phys);
}

/*
 * PhysClose()
 */

void
PhysClose(PhysInfo p)
{
    MsgSend(p->msgs, MSG_CLOSE, p);
}

/*
 * PhysUp()
 */

void
PhysUp(PhysInfo p)
{
    Log(LG_PHYS2, ("[%s] device: UP event", p->name));
    if (p->link) {
	LinkUp(p->link);
    } else if (p->rep) {
	RepUp(p);
    }
}

/*
 * PhysDown()
 */

void
PhysDown(PhysInfo p, const char *reason, const char *details, ...)
{
    Log(LG_PHYS2, ("[%s] device: DOWN event", p->name));
    p->lastClose = time(NULL);
    if (p->link) {
	if (details) {
	    va_list	args;
	    char	buf[256];
	    
	    va_start(args, details);
	    vsnprintf(buf, sizeof(buf), details, args);
	    va_end(args);
	    RecordLinkUpDownReason(NULL, p->link, 0, reason, buf);
	} else {
	    RecordLinkUpDownReason(NULL, p->link, 0, reason, NULL);
	}
	p->link->upReasonValid=0;
	LinkDown(p->link);
    } else if (p->rep) {
	RepDown(p);
    }
}

/*
 * PhysIncoming()
 */

void
PhysIncoming(PhysInfo p)
{
    if (p->link) {
	RecordLinkUpDownReason(NULL, p->link, 1, STR_INCOMING_CALL, NULL);
	BundOpenLink(p->link);
    } else if (p->rep) {
        RepIncoming(p);
    }
}

/*
 * PhysSetAccm()
 */

int
PhysSetAccm(PhysInfo p, uint32_t xmit, u_int32_t recv)
{
    if (p->type && p->type->setaccm)
	return (*p->type->setaccm)(p, xmit, recv);
    else 
	return (0);
}

/*
 * PhysGetUpperHook()
 */

int
PhysGetUpperHook(PhysInfo p, char *path, char *hook)
{
    if (p->link && p->link->bund) {
	snprintf(path, NG_PATHLEN, "[%lx]:", (u_long)p->link->nodeID);
	snprintf(hook, NG_HOOKLEN, "%s", NG_TEE_HOOK_LEFT);
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
PhysGetOriginate(PhysInfo p)
{
  PhysType	const pt = p->type;

  return((pt && pt->originate) ? (*pt->originate)(p) : LINK_ORIGINATE_UNKNOWN);
}

/*
 * PhysIsSync()
 *
 * This returns 1 if link is synchronous
 */

int
PhysIsSync(PhysInfo p)
{
  PhysType	const pt = p->type;

  return((pt && pt->issync) ? (*pt->issync)(p) : 0);
}

/*
 * PhysSetCalledNum()
 */

int
PhysSetCallingNum(PhysInfo p, char *buf)
{
    PhysType	const pt = p->type;

    if (pt && pt->setcallingnum)
	return ((*pt->setcallingnum)(p, buf));
    else
	return (0);
}

/*
 * PhysSetCalledNum()
 */

int
PhysSetCalledNum(PhysInfo p, char *buf)
{
    PhysType	const pt = p->type;

    if (pt && pt->setcallednum)
	return ((*pt->setcallednum)(p, buf));
    else
	return (0);
}

/*
 * PhysGetPeerAddr()
 */

int
PhysGetPeerAddr(PhysInfo p, char *buf, int buf_len)
{
    PhysType	const pt = p->type;

    buf[0] = 0;

    if (pt && pt->peeraddr)
	return ((*pt->peeraddr)(p, buf, buf_len));
    else
	return (0);
}

/*
 * PhysGetPeerPort()
 */

int
PhysGetPeerPort(PhysInfo p, char *buf, int buf_len)
{
    PhysType	const pt = p->type;

    buf[0] = 0;

    if (pt && pt->peerport)
	return ((*pt->peerport)(p, buf, buf_len));
    else
	return (0);
}

/*
 * PhysGetCalledNum()
 */

int
PhysGetCallingNum(PhysInfo p, char *buf, int buf_len)
{
    PhysType	const pt = p->type;

    buf[0] = 0;

    if (pt && pt->callingnum)
	return ((*pt->callingnum)(p, buf, buf_len));
    else
	return (0);
}

/*
 * PhysGetCalledNum()
 */

int
PhysGetCalledNum(PhysInfo p, char *buf, int buf_len)
{
    PhysType	const pt = p->type;

    buf[0] = 0;

    if (pt && pt->callednum)
	return ((*pt->callednum)(p, buf, buf_len));
    else
	return (0);
}

/*
 * PhysShutdown()
 */

void
PhysShutdown(PhysInfo p)
{
    PhysType	const pt = p->type;
    int		k;

    if (pt && pt->shutdown)
	(*pt->shutdown)(p);

    for (k = 0; 
	k < gNumPhyses && gPhyses[k] != p;
	k++);
    if (k < gNumPhyses)
	gPhyses[k] = NULL;

    Freee(MB_PHYS, p);
}

/*
 * PhysSetDeviceType()
 */

void
PhysSetDeviceType(PhysInfo p, char *typename)
{
  PhysType	pt;
  int		k;

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
  PhysInfo	const p = (PhysInfo)arg;
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
        if (now - p->lastClose < p->type->minReopenDelay) {
	    if (TimerRemain(&p->openTimer) < 0) {
		int	delay = p->type->minReopenDelay - (now - p->lastClose);

		if ((random() ^ gPid ^ time(NULL)) & 1)
		    delay++;
		Log(LG_PHYS, ("[%s] pausing %d seconds before open",
		    p->name, delay));
		TimerStop(&p->openTimer);
		TimerInit(&p->openTimer, "PhysOpen",
		    delay * SECONDS, PhysOpenTimeout, p);
		TimerStart(&p->openTimer);
	    }
	    break;
        }
        TimerStop(&p->openTimer);
        (*p->type->open)(p);
        break;
    case MSG_CLOSE:
        TimerStop(&p->openTimer);
        (*p->type->close)(p);
        break;
    default:
        assert(FALSE);
  }
}

/*
 * PhysOpenTimeout()
 */

static void
PhysOpenTimeout(void *arg)
{
  PhysInfo	const p = (PhysInfo)arg;

  TimerStop(&p->openTimer);
  PhysOpen(p);
}

/*
 * PhysCommand()
 */

int
PhysCommand(Context ctx, int ac, char *av[], void *arg)
{
  int		k;
  PhysInfo	p;

  switch (ac) {
    case 0:

        Printf("Defined phys items:\r\n");

        for (k = 0; k < gNumPhyses; k++) {
	    if ((p = gPhyses[k]) != NULL) {
		if (p->link && p->link->bund)
		    Printf("\t\"%s\" -> link \"%s\" -> bundle \"%s\"\r\n", 
			p->name, p->link->name, p->link->bund->name);
		else if (p->rep)
		    Printf("\t\"%s\" -> repeater \"%s\"\r\n", p->name, p->rep->name);
		else
		    Printf("\t\"%s\" -> unknown\r\n", p->name);
	    }
	}
      break;

    case 1:

	if ((p = PhysFind(av[0])) == NULL) {
	    Printf("Phys \"%s\" is not defined\r\n", av[0]);
	    return(0);
	}

	/* Change default link and bundle */
        ctx->phys = p;
        ctx->lnk = p->link;
        if (p->link) {
    	    ctx->bund = ctx->lnk->bund;
	} else {
	    ctx->bund = NULL;
	}
	ctx->rep = p->rep;
	break;

    default:
      return(-1);
  }	
  return(0);
}

/*
 * PhysFind()
 *
 * Find a phys structure
 */

static PhysInfo
PhysFind(char *name)
{
  int	k;

  for (k = 0;
    k < gNumPhyses && strcmp(gPhyses[k]->name, name);
    k++);
  return((k < gNumPhyses) ? gPhyses[k] : NULL);
}


/*
 * PhysStat()
 */

int
PhysStat(Context ctx, int ac, char *av[], void *arg)
{
  PhysInfo	const p = ctx->phys;

  Printf("\tType  : %s\r\n", p->type->name);
  if (p->type->showstat)
    (*p->type->showstat)(ctx);
  return 0;
}

/*
 * PhysSetCommand()
 */

static int
PhysSetCommand(Context ctx, int ac, char *av[], void *arg)
{
  if (ac == 0)
    return(-1);

  switch ((intptr_t)arg) {
    case SET_DEVTYPE:
      PhysSetDeviceType(ctx->phys, *av);
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

