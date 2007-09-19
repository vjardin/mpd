
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
    SET_LINK,
    SET_REPEATER,
    SET_ENABLE,
    SET_DISABLE,
  };

/*
 * INTERNAL FUNCTIONS
 */

  static void	PhysOpenTimeout(void *arg);
  static void	PhysMsg(int type, void *arg);

/*
 * GLOBAL VARIABLES
 */

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

int
PhysInit(Link l)
{
    l->pmsgs = MsgRegister(PhysMsg);

    /* Initialize type specific stuff */
    if ((l->type->init)(l) < 0) {
	Log(LG_ERR, ("[%s] type \"%s\" initialization failed",
    	    l->name, l->type->name));
	l->type = NULL;
	return (0);
    }

    return (0);
}

/*
 * PhysInst()
 */

int
PhysInst(Link l, Link lt)
{
    l->pmsgs = MsgRegister(PhysMsg);

    return ((l->type->inst)(l, lt));
}

/*
 * PhysGetRep()
 */

int
PhysGetRep(Rep r)
{
    if (r->links[1])
	return (1);
    
    if (r->linkt[0]) {
	Link	l = LinkFind(r->linkt);
	if (l) {
	    if (l->tmpl) {
		l = LinkInst(l, NULL, 0, 0);
		if (!l) {
		    Log(LG_REP, ("[%s] rep: Can't instantiate link \"%s\"", r->name, r->linkt));
		    return (0);
		}
	    }
	} else {
	    Log(LG_REP, ("[%s] rep: Can't find link \"%s\"", r->name, r->linkt));
	    return (0);
	}
	if (l) {
	    r->links[1] = l;
	    l->rep = r;
	}
    } else {
	Log(LG_REP, ("[%s] rep: Link template not specified", r->name));
	return (0);
    }
    
    return (1);
}

/*
 * PhysOpenCmd()
 */

void
PhysOpenCmd(Context ctx)
{
    PhysOpen(ctx->lnk);
}

/*
 * PhysOpen()
 */

void
PhysOpen(Link l)
{
    REF(l);
    MsgSend(l->pmsgs, MSG_OPEN, l);
}

/*
 * PhysCloseCmd()
 */

void
PhysCloseCmd(Context ctx)
{
    PhysClose(ctx->lnk);
}

/*
 * PhysClose()
 */

void
PhysClose(Link l)
{
    REF(l);
    MsgSend(l->pmsgs, MSG_CLOSE, l);
}

/*
 * PhysUp()
 */

void
PhysUp(Link l)
{
    Log(LG_PHYS2, ("[%s] device: UP event", l->name));
    if (!l->rep) {
	LinkUp(l);
    } else {
	RepUp(l);
    }
}

/*
 * PhysDown()
 */

void
PhysDown(Link l, const char *reason, const char *details, ...)
{
    Log(LG_PHYS2, ("[%s] device: DOWN event", l->name));
    l->lastClose = time(NULL);
    if (!l->rep) {
	if (details) {
	    va_list	args;
	    char	buf[256];
	    
	    va_start(args, details);
	    vsnprintf(buf, sizeof(buf), details, args);
	    va_end(args);
	    RecordLinkUpDownReason(NULL, l, 0, reason, buf);
	} else {
	    RecordLinkUpDownReason(NULL, l, 0, reason, NULL);
	}
	l->upReasonValid=0;
	LinkDown(l);
    } else {
	RepDown(l);
	if (l->rep->links[0] == l)
	    l->rep->links[0] = NULL;
	else
	    l->rep->links[1] = NULL;
	l->rep = NULL;
	if (!l->stay)
	    LinkShutdown(l);
    }
}

/*
 * PhysIncoming()
 */

void
PhysIncoming(Link l)
{
    if (!l->rep && l->rept[0]!=0) {
	Rep rt = RepFind(l->rept);
	if (rt) {
	    if (rt->tmpl)
		l->rep = RepInst(rt, NULL, 0, 0);
	    else
		l->rep = rt;
	    l->rep->links[0] = l;
	} else {
	    Log(LG_ERR, ("[%s] Repeater template '%s' not found", l->name, l->rept));
	    PhysClose(l);
	}
    }

    if (!l->rep) {
	RecordLinkUpDownReason(NULL, l, 1, STR_INCOMING_CALL, NULL);
	LinkOpen(l);
    } else {
        RepIncoming(l);
    }
}

/*
 * PhysSetAccm()
 */

int
PhysSetAccm(Link l, uint32_t xmit, u_int32_t recv)
{
    if (l->type && l->type->setaccm)
	return (*l->type->setaccm)(l, xmit, recv);
    else 
	return (0);
}

/*
 * PhysGetUpperHook()
 */

int
PhysGetUpperHook(Link l, char *path, char *hook)
{
    if (!l->rep) {
	snprintf(path, NG_PATHLEN, "[%lx]:", (u_long)l->nodeID);
	snprintf(hook, NG_HOOKLEN, "%s", NG_TEE_HOOK_LEFT);
	return 1;
    } else {
	return RepGetHook(l, path, hook);
    }
    return 0;
}

/*
 * PhysGetOriginate()
 *
 * This returns one of LINK_ORIGINATE_{UNKNOWN, LOCAL, REMOTE}
 */

int
PhysGetOriginate(Link l)
{
  PhysType	const pt = l->type;

  return((pt && pt->originate) ? (*pt->originate)(l) : LINK_ORIGINATE_UNKNOWN);
}

/*
 * PhysIsSync()
 *
 * This returns 1 if link is synchronous
 */

int
PhysIsSync(Link l)
{
  PhysType	const pt = l->type;

  return((pt && pt->issync) ? (*pt->issync)(l) : 0);
}

/*
 * PhysSetCalledNum()
 */

int
PhysSetCallingNum(Link l, char *buf)
{
    PhysType	const pt = l->type;

    if (pt && pt->setcallingnum)
	return ((*pt->setcallingnum)(l, buf));
    else
	return (0);
}

/*
 * PhysSetCalledNum()
 */

int
PhysSetCalledNum(Link l, char *buf)
{
    PhysType	const pt = l->type;

    if (pt && pt->setcallednum)
	return ((*pt->setcallednum)(l, buf));
    else
	return (0);
}

/*
 * PhysGetPeerAddr()
 */

int
PhysGetPeerAddr(Link l, char *buf, int buf_len)
{
    PhysType	const pt = l->type;

    buf[0] = 0;

    if (pt && pt->peeraddr)
	return ((*pt->peeraddr)(l, buf, buf_len));
    else
	return (0);
}

/*
 * PhysGetPeerPort()
 */

int
PhysGetPeerPort(Link l, char *buf, int buf_len)
{
    PhysType	const pt = l->type;

    buf[0] = 0;

    if (pt && pt->peerport)
	return ((*pt->peerport)(l, buf, buf_len));
    else
	return (0);
}

/*
 * PhysGetCalledNum()
 */

int
PhysGetCallingNum(Link l, char *buf, int buf_len)
{
    PhysType	const pt = l->type;

    buf[0] = 0;

    if (pt && pt->callingnum)
	return ((*pt->callingnum)(l, buf, buf_len));
    else
	return (0);
}

/*
 * PhysGetCalledNum()
 */

int
PhysGetCalledNum(Link l, char *buf, int buf_len)
{
    PhysType	const pt = l->type;

    buf[0] = 0;

    if (pt && pt->callednum)
	return ((*pt->callednum)(l, buf, buf_len));
    else
	return (0);
}

/*
 * PhysIsBusy()
 *
 * This returns 1 if link is busy
 */

int
PhysIsBusy(Link l)
{
  return (l->rep || l->state != PHYS_STATE_DOWN);
}

/*
 * PhysShutdown()
 */

void
PhysShutdown(Link l)
{
    PhysType	const pt = l->type;

    if (pt && pt->shutdown)
	(*pt->shutdown)(l);
}

/*
 * PhysSetDeviceType()
 */

void
PhysSetDeviceType(Link l, char *typename)
{
  PhysType	pt;
  int		k;

  /* Make sure device type not already set */
  if (l->type) {
    Log(LG_ERR, ("[%s] device type already set to %s",
      l->name, l->type->name));
    return;
  }

  /* Locate type */
  for (k = 0; (pt = gPhysTypes[k]); k++) {
    if (!strcmp(pt->name, typename))
      break;
  }
  if (pt == NULL) {
    Log(LG_ERR, ("[%s] device type \"%s\" unknown", l->name, typename));
    return;
  }
  l->type = pt;

  /* Initialize type specific stuff */
  if ((l->type->init)(l) < 0) {
    Log(LG_ERR, ("[%s] type \"%s\" initialization failed",
      l->name, l->type->name));
    l->type = NULL;
    return;
  }
}

/*
 * PhysMsg()
 */

static void
PhysMsg(int type, void *arg)
{
    Link	const l = (Link)arg;
    time_t	const now = time(NULL);

    if (l->dead) {
	UNREF(l);
	return;
    }
    Log(LG_PHYS2, ("[%s] device: %s event",
	l->name, MsgName(type)));
    switch (type) {
    case MSG_OPEN:
        if (!l->rep)
    	    l->downReasonValid=0;
        if (now - l->lastClose < l->type->minReopenDelay) {
	    if (TimerRemain(&l->openTimer) < 0) {
		int	delay = l->type->minReopenDelay - (now - l->lastClose);

		if ((random() ^ gPid ^ time(NULL)) & 1)
		    delay++;
		Log(LG_PHYS, ("[%s] pausing %d seconds before open",
		    l->name, delay));
		TimerStop(&l->openTimer);
		TimerInit(&l->openTimer, "PhysOpen",
		    delay * SECONDS, PhysOpenTimeout, l);
		TimerStart(&l->openTimer);
	    }
	    break;
        }
        TimerStop(&l->openTimer);
        (*l->type->open)(l);
        break;
    case MSG_CLOSE:
        TimerStop(&l->openTimer);
        (*l->type->close)(l);
        break;
    default:
        assert(FALSE);
    }
    UNREF(l);
}

/*
 * PhysOpenTimeout()
 */

static void
PhysOpenTimeout(void *arg)
{
  Link	const l = (Link)arg;

  TimerStop(&l->openTimer);
  PhysOpen(l);
}

/*
 * PhysStat()
 */

int
PhysStat(Context ctx, int ac, char *av[], void *arg)
{
    Link	const l = ctx->lnk;

    Printf("Device '%s' (%s)\r\n", l->name, (l->tmpl)?"template":"instance");
    Printf("\tType         : %s\r\n", l->type->name);
    Printf("\tRepeater temp: %s\r\n", l->rept);

    if (l->type->showstat)
	(*l->type->showstat)(ctx);
    return 0;
}

