
/*
 * event.h
 * 
 * Copyright (C) 1996-1999 by Whistle Communications Corp.
 * All rights reserved.
 */

#ifndef _EVENT_H_
#define _EVENT_H_

/*
 * DEFINITIONS
 */

/* Types of events */

  enum
  {
    EVENT_READ,		/* value = file descriptor */
    EVENT_WRITE,	/* value = file descriptor */
    EVENT_EXCEPTION,	/* value = file descriptor */
    EVENT_TIMEOUT,	/* value = time in miliseconds */
    EVENT_SIGNAL,	/* value = signal number */
  };

  typedef u_int		EventRef;
  typedef void		(*EventHdlr)(int type, void *cookie);

/*
 * FUNCTIONS
 */

  extern int	EventStart(void);
  extern void	EventStop(void);
  extern int	EventRegister(EventRef *ref, int type, int value,
		  int prio, EventHdlr action, void *cookie);
  extern int	EventUnRegister(EventRef *ref);
  extern int	EventIsRegistered(EventRef ref);
  extern int	EventTimerRemain(EventRef ref);
  extern void	EventDump(const char *msg);

  extern void	EventSetLog(int sanity, void (*warnx)(const char *fmt, ...));

#endif

