
/*
 * timer.h
 *
 * Written by Archie Cobbs <archie@freebsd.org>
 * Copyright (c) 1995-1999 Whistle Communications, Inc. All rights reserved.
 * See ``COPYRIGHT.whistle''
 */

#ifndef _TIMER_H_
#define	_TIMER_H_

#include "defs.h"
#include "event.h"

/*
 * DEFINITIONS
 */

  #define TICKSPERSEC	1000		/* Microsecond granularity */
  #define SECONDS	TICKSPERSEC	/* Timers count in usec */

  struct pppTimer;
  typedef struct pppTimer *PppTimer;

  struct pppTimer
  {
    EventRef	event;			/* Event registration */
    u_int	load;			/* Initial load value */
    void	(*func)(void *arg);	/* Called when timer expires */
    void	*arg;			/* Arg passed to timeout function */
    Bund	bund;			/* Bundle this timer belongs to */
    Link	lnk;			/* Link this timer belongs to */
    u_char	init;			/* Indicates struct is initialized */
  };

  #define TimerStop(t)	EventUnRegister(&(t)->event)

/*
 * FUNCTIONS
 */

  extern void	TimerInit(PppTimer timer, const char *desc,
		  int load, void (*handler)(void *), void *arg);
  extern void	TimerStart(PppTimer t);
  extern void	TimerStartRecurring(PppTimer t);
  extern int	TimerRemain(PppTimer t);

#endif

