
/*
 * phys.c
 *
 * Written by Archie Cobbs <archie@whistle.com>
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
 * All device types must support MRU's of at least 1500 + LCP_MRU_MARGIN.
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
PhysInit(void)
{
  PhysInfo	p;

  p = Malloc(MB_PHYS, sizeof(*p));
  p->state = PHYS_DOWN;
  p->msgs = MsgRegister(PhysMsg, PHYS_PRIO);
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
PhysUp(void)
{
  MsgSend(lnk->phys->msgs, MSG_UP, NULL);
}

/*
 * PhysDown()
 */

void
PhysDown(const char *reason, const char *details, ...)
{
  struct downmsg	*dm = Malloc(MB_UTIL, sizeof(*dm));
  va_list		args;

  dm->reason = reason;
  if (details) {
    va_start(args, details);
    vsnprintf(dm->buf, sizeof(dm->buf), details, args);
    va_end(args);
  }
  MsgSend(lnk->phys->msgs, MSG_DOWN, dm);
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

  Log(LG_PHYS, ("[%s] device: %s event in state %s",
    lnk->name, MsgName(type), PhysState(p)));
  if (!p->type) {
    Log(LG_ERR, ("[%s] this link has no type set", lnk->name));
    goto done;
  }
  switch (type) {
    case MSG_OPEN:
      p->want_open = TRUE;
      if (now - p->lastClose < p->type->minReopenDelay) {
	if (TimerRemain(&p->openTimer) < 0) {
	  int	delay = p->type->minReopenDelay - (now - p->lastClose);

	  if ((random() ^ getpid() ^ time(NULL)) & 1)
		delay++;
	  else if (delay > 1)
		delay--;
	  Log(LG_PHYS, ("[%s] pausing %d seconds before open",
	    lnk->name, delay));
	  TimerStop(&p->openTimer);
	  TimerInit(&p->openTimer, "PhysOpen",
	    delay * SECONDS, PhysOpenTimeout, NULL);
	  TimerStart(&p->openTimer);
	}
	break;
      }
      switch (p->state) {
	case PHYS_DOWN:
	  if (TimerRemain(&p->openTimer) >= 0)
	    goto done;
	  (*p->type->open)(p);
	  p->state = PHYS_OPENING;
	  break;
	case PHYS_CLOSING:
	case PHYS_OPENING:
	case PHYS_UP:
	  break;
      }
      break;
    case MSG_CLOSE:
      p->want_open = FALSE;
      TimerStop(&p->openTimer);
      switch (p->state) {
	case PHYS_DOWN:
	case PHYS_CLOSING:
	  break;
	case PHYS_OPENING:
	case PHYS_UP:
	  (*p->type->close)(p);
	  p->state = PHYS_CLOSING;
	  break;
      }
      break;
    case MSG_DOWN:
      {
	struct downmsg	*const dm = (struct downmsg *) arg;

	p->lastClose = now;
	switch (p->state) {
	  case PHYS_CLOSING:
	    RecordLinkUpDown(-1);
	    /* fall through */
	  case PHYS_DOWN:
	    if (p->want_open)
	      PhysOpen();
	    break;
	  case PHYS_OPENING:
	    if (*dm->buf) {
	      SetStatus(ADLG_WAN_CONNECT_FAILURE, STR_COPY, dm->buf);
	      RecordLinkUpDownReason(lnk, 0, dm->reason, dm->buf);
	    } else {
	      SetStatus(ADLG_WAN_CONNECT_FAILURE, STR_CON_FAILED0);
	      RecordLinkUpDownReason(lnk, 0, dm->reason, NULL);
	    }
	    RecordLinkUpDown(0);
#if 0
	    SetStatus(ADLG_WAN_WAIT_FOR_DEMAND, STR_COPY, dm->buf);
#endif
	    RecordLinkUpDownReason(lnk, 1, STR_REDIAL, NULL);
	    break;
	  case PHYS_UP:
	    if (dm->reason)
	      RecordLinkUpDownReason(lnk, 0, dm->reason, dm->buf);
	    RecordLinkUpDown(-1);
	    SetStatus(ADLG_WAN_WAIT_FOR_DEMAND, STR_COPY, dm->buf);
	    RecordLinkUpDownReason(lnk, 1, STR_REDIAL, NULL);
	    break;
	}
	p->state = PHYS_DOWN;
	LinkDown(lnk);
	Freee(dm);
      }
      break;
    case MSG_UP:
      switch (p->state)
      {
	case PHYS_DOWN:
	case PHYS_CLOSING:
	  Log(LG_ERR, ("[%s] weird event in this state", lnk->name));
	  break;
	case PHYS_OPENING:
/*
	  Log(LG_PHYS, ("[%s] connection successful", lnk->name));
*/
	  RecordLinkUpDown(1);
	  LinkUp(lnk);
	  break;
	case PHYS_UP:
	  break;
      }
      p->state = PHYS_UP;
      break;
  }
done:
  Log(LG_PHYS, ("[%s] device is now in state %s",
    lnk->name, PhysState(p)));
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

void
PhysStat(int ac, char *av[], void *arg)
{
  PhysInfo	const p = lnk->phys;

  printf("\tType  : %s\n", p->type->name);
  printf("\tState : %s\n", PhysState(p));
  if (p->type->showstat)
    (*p->type->showstat)(p);
}

/*
 * PhysState()
 */

const char *
PhysState(PhysInfo p)
{
  switch (p->state) {
    case PHYS_DOWN:	return("DOWN");
    case PHYS_CLOSING:	return("CLOSING");
    case PHYS_OPENING:	return("OPENING");
    case PHYS_UP:	return("UP");
  }
  return("???");
}

