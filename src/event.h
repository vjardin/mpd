
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

  #define  EVENT_READ		PEVENT_READ	/* value = file descriptor */
  #define  EVENT_WRITE		PEVENT_WRITE	/* value = file descriptor */
  #define  EVENT_TIMEOUT	PEVENT_TIME	/* value = time in miliseconds */

  typedef void		(*EventHdlr)(int type, void *cookie);

  struct event_ref
  {
    int			type;
    EventHdlr		handler;
    struct pevent	*pe;
    void		*arg;
  };
  typedef struct event_ref	*EventRef;

/*
 * FUNCTIONS
 */

  extern int	EventInit(void);
  extern void	EventStop(void);
  extern int	EventRegister(EventRef *ref, int type, int value,
		  int prio, EventHdlr action, void *cookie);
  extern int	EventUnRegister(EventRef *ref);
  extern int	EventIsRegistered(EventRef *ref);
  extern int	EventTimerRemain(EventRef *ref);
  extern void	EventDump(const char *msg);

  extern void	EventSetLog(int sanity, void (*warnx)(const char *fmt, ...));

#endif

