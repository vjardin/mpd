
/*
 * timer.c
 *
 * Written by Archie Cobbs <archie@whistle.com>
 * Copyright (c) 1995-1999 Whistle Communications, Inc. All rights reserved.
 * See ``COPYRIGHT.whistle''
 */

#include "ppp.h"

/*
 * INTERNAL FUNCTIONS
 */

  static void	TimerExpires(int type, void *cookie);

/*
 * TimerInit()
 */

void
TimerInit(PppTimer timer, const char *desc,
  int load, void (*handler)(void *), void *arg)
{
  memset(timer, 0, sizeof(*timer));
  timer->load	= (load >= 0) ? load : 0;
  timer->func	= handler;
  timer->arg	= arg;
  timer->init	= TRUE;
}

/*
 * TimerStart()
 */

void
TimerStart(PppTimer timer)
{

  /* Stop timer if running */
  assert(timer->init);
  if (timer->event != NULL)
    EventUnRegister(&timer->event);

  /* Save "context" for this timer */
  timer->lnk = lnk;
  timer->bund = bund;

  /* Register timeout event */
  EventRegister(&timer->event, EVENT_TIMEOUT,
    timer->load, TIMER_PRIO, TimerExpires, timer);
}

/*
 * TimerExpires()
 */

static void
TimerExpires(int type, void *cookie)
{
  PppTimer	const timer = (PppTimer) cookie;

  lnk = timer->lnk;
  bund = timer->bund;
  (*timer->func)(timer->arg);
}

/*
 * TimerRemain()
 *
 * Return number of ticks left on a timer, or -1 if not running.
 */

int
TimerRemain(PppTimer t)
{
  return(EventTimerRemain(t->event));
}

