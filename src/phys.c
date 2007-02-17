
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

/*
 * INTERNAL FUNCTIONS
 */

  static void	PhysOpenTimeout(void *arg);
  static void	PhysMsg(int type, void *arg);

/*
 * PhysInit()
 *
 * Initialize physical layer state. Note that
 * the device type remains unspecified at this point.
 */

PhysInfo
PhysInit(char *name)
{
  PhysInfo	p;

  p = Malloc(MB_PHYS, sizeof(*p));
  strlcpy(p->name, name, sizeof(p->name));
  p->state = PHYS_STATE_DOWN;
  p->msgs = MsgRegister(PhysMsg, 0);
  return(p);
}

/*
 * PhysOpen()
 */

void
PhysOpen(void)
{
  MsgSend(lnk->phys->msgs, MSG_OPEN, NULL);
}

/*
 * PhysClose()
 */

void
PhysClose(void)
{
  MsgSend(lnk->phys->msgs, MSG_CLOSE, NULL);
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
  RecordLinkUpDownReason(p->link, 1, STR_INCOMING_CALL, NULL);
  BundOpenLink(p->link);
}

/*
 * PhysUpdate()
 */

void
PhysUpdate(void)
{
  const PhysInfo	p = lnk->phys;

  if (p->type->update != NULL)
    (*p->type->update)(p);
}

/*
 * PhysGetOriginate()
 *
 * This returns one of LINK_ORIGINATE_{UNKNOWN, LOCAL, REMOTE}
 */

int
PhysGetOriginate(void)
{
  PhysInfo	const p = lnk->phys;
  PhysType	const pt = p->type;

  return((pt && pt->originate) ? (*pt->originate)(p) : LINK_ORIGINATE_UNKNOWN);
}

/*
 * PhysSetDeviceType()
 */

void
PhysSetDeviceType(char *typename)
{
  PhysInfo	const p = lnk->phys;
  PhysType	pt;
  int		k;

  /* Make sure device type not already set */
  if (p->type) {
    Log(LG_ERR, ("[%s] device type already set to %s",
      lnk->name, p->type->name));
    return;
  }

  /* Locate type */
  for (k = 0; (pt = gPhysTypes[k]); k++) {
    if (!strcmp(pt->name, typename))
      break;
  }
  if (pt == NULL) {
    Log(LG_ERR, ("[%s] device type \"%s\" unknown", lnk->name, typename));
    return;
  }
  p->type = pt;

  /* Initialize type specific stuff */
  if ((p->type->init)(p) < 0) {
    Log(LG_ERR, ("[%s] type \"%s\" initialization failed",
      lnk->name, p->type->name));
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
  PhysInfo	const p = lnk->phys;
  time_t	const now = time(NULL);

  Log(LG_PHYS2, ("[%s] device: %s event",
    lnk->name, MsgName(type)));
  if (!p->type) {
    Log(LG_ERR, ("[%s] this link has no type set", lnk->name));
    return;
  }
  switch (type) {
    case MSG_OPEN:
      lnk->downReasonValid=0;
      p->want_open = TRUE;
      if (now - p->lastClose < p->type->minReopenDelay) {
	if (TimerRemain(&p->openTimer) < 0) {
	  int	delay = p->type->minReopenDelay - (now - p->lastClose);

	  if ((random() ^ gPid ^ time(NULL)) & 1)
		delay++;
	  Log(LG_PHYS, ("[%s] pausing %d seconds before open",
	    lnk->name, delay));
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

        lnk->upReasonValid=0;
	p->lastClose = now;
	if (*dm->buf) {
	  SetStatus(ADLG_WAN_CONNECT_FAILURE, STR_COPY, dm->buf);
	  RecordLinkUpDownReason(lnk, 0, dm->reason, dm->buf);
	} else {
	  SetStatus(ADLG_WAN_CONNECT_FAILURE, STR_CON_FAILED0);
	  RecordLinkUpDownReason(lnk, 0, dm->reason, NULL);
	}
	Freee(MB_PHYS, dm);
	LinkDown(lnk);
      }
      break;
    case MSG_UP:
      LinkUp(lnk);
      break;
  }
}

/*
 * PhysOpenTimeout()
 */

static void
PhysOpenTimeout(void *arg)
{
  PhysInfo	const p = lnk->phys;

  TimerStop(&p->openTimer);
  assert(p->want_open);
  PhysOpen();
}

/*
 * PhysStat()
 */

int
PhysStat(int ac, char *av[], void *arg)
{
  PhysInfo	const p = lnk->phys;

  Printf("\tType  : %s\r\n", p->type->name);
  if (p->type->showstat)
    (*p->type->showstat)(p);
  return 0;
}

