
/*
 * event.c
 * 
 * Copyright (C) 1996 by Whistle Communications Corp.
 * All rights reserved.
 */

  #include <sys/types.h>
  #include <sys/param.h>
  #include <sys/time.h>
  #include <unistd.h>
  #include <stdio.h>
  #include <stdlib.h>
  #include <signal.h>
  #include <stdarg.h>
  #include <string.h>
  #include <errno.h>
  #include <err.h>
  #include "event.h"

/*
 * DEFINITIONS
 */

  #define MAX_EVENT_NAME	32
  #define EVENT_MAGIC		0x3de80f67

  #define MAXOF(x,y)		((x)>(y)?(x):(y))

  struct event
  {
    u_int		magic;
    EventRef		ref;
    EventRef		*refp;
    int			val;
    int			prio;
    u_short		type;
    u_short		occurring:1;	/* Event is occurring */
    struct timeval	to;
    struct event	*next;
    void		*cookie;
    void		(*action)(int type, void *cookie);
  };
  typedef struct event	*Event;

/*
 * INTERNAL VARIABLES
 */

  static u_int	gNextRefNum;	/* non-zero if initialized */
  static Event	gEvents;
  static int	gServiceOn;
  static int	gEventOk;
  static u_char	gSigsCaught[NSIG];

  static int	gSanityCheck = 1;
  static void	(*gWarnx)(const char *fmt, ...) = warnx;

/*
 * INTERNAL FUNCTIONS
 */

  static void		EventInit(void);
  static void		EventCatchSignal(int sig);
  static char		*EventDesc(Event event);
  static struct timeval	TimevalDiff(struct timeval *lo, struct timeval *hi);

  static void		MyWarn(const char *fmt, ...) __printflike(1, 2);
  static void		MyWarnx(const char *fmt, ...) __printflike(1, 2);

  static void		ShowList(const char *fmt, ...) __printflike(1, 2);

/*
 * MyWarn()
 */

static void
MyWarn(const char *fmt, ...)
{
  va_list	args;
  char		buf[100];

  va_start(args, fmt);
  vsnprintf(buf, sizeof(buf), fmt, args);
  snprintf(buf + strlen(buf), sizeof(buf) - strlen(buf),
    ": %s", sys_errlist[errno]);
  (*gWarnx)("%s", buf);
  va_end(args);
}

/*
 * MyWarnx()
 */

static void
MyWarnx(const char *fmt, ...)
{
  va_list	args;
  char		buf[100];

  va_start(args, fmt);
  vsnprintf(buf, sizeof(buf), fmt, args);
  (*gWarnx)("%s", buf);
  va_end(args);
}

/*
 * EventSetLog()
 */

void
EventSetLog(int sanity, void (*warnx)(const char *fmt, ...))
{
  gSanityCheck = sanity;
  if (warnx) gWarnx = warnx;
}

/*
 * EventInit()
 */

static void
EventInit(void)
{
  if (gNextRefNum == 0)
    gNextRefNum = (((getpid() << 16) ^ ((u_int) EventStart)) & 0x0fffffff);
}

/*
 * EventStart()
 *
 * Start servicing events. Any signal events that are registered
 * should have their signals blocked before calling this.
 *
 * This function does not return unless one of these two things
 * becomes true:
 *
 *	Return value	Condition
 *	------------	---------
 *	     -1		EventStop() was called
 *	      0		No events are registered
 */

int
EventStart(void)
{
  struct timeval	lastTime;

/* Initialize */

  if (gNextRefNum == 0)
    EventInit();

/* Main loop */

  gettimeofday(&lastTime, NULL);
  for (gServiceOn = 1; gServiceOn; )
  {
    Event		event;
    int			rtn, maxfd;
    struct timeval	to, *top;
    struct timeval	now, diff;
    fd_set		rfds, wfds, efds;
    sigset_t		sigs;

  /* If no events are registered, return */

    if (!gEvents)
      return(0);

  /* Initialize info */

    maxfd = 0;
    top = NULL;
    FD_ZERO(&rfds);
    FD_ZERO(&wfds);
    FD_ZERO(&efds);
    sigemptyset(&sigs);

  /* Accumulate info from each pending event */

    for (event = gEvents; event; event = event->next)
    {
      switch (event->type)
      {
	case EVENT_READ:
	  FD_SET(event->val, &rfds);
	  maxfd = MAXOF(maxfd, event->val + 1);
	  break;
	case EVENT_WRITE:
	  FD_SET(event->val, &wfds);
	  maxfd = MAXOF(maxfd, event->val + 1);
	  break;
	case EVENT_EXCEPTION:
	  FD_SET(event->val, &efds);
	  maxfd = MAXOF(maxfd, event->val + 1);
	  break;
	case EVENT_SIGNAL:
	  sigaddset(&sigs, event->val);
	  break;
	case EVENT_TIMEOUT:
	  if (top == NULL || timercmp(&event->to, &to, < ))
	    memcpy(&to, &event->to, sizeof(to));
	  top = &to;
	  break;
	default:
	  MyWarnx("%s: bogus type %d", __FUNCTION__, event->type);
	  break;
      }
    }

  /* Sanity check, if desired */

    if (gSanityCheck)
    {
      Event	*ep, *nextp;

    /* Check all events */

      for (ep = &gEvents; (event = *ep); ep = nextp)
      {
	if (event->occurring)
	{
	  MyWarnx("%s: occurring", __FUNCTION__);
	  goto problem;
	}
	if (event->magic != EVENT_MAGIC)
	{
	  MyWarnx("%s: bad magic2", __FUNCTION__);
	  goto problem;
	}
	if (event->refp && (*event->refp != event->ref))
	{
	  MyWarnx("%s: bad ref at %p: %u != %u",
	    __FUNCTION__, event->refp, *event->refp, event->ref);
	  goto problem;
	}
	nextp = &event->next;
	continue;
problem:
	*ep = event->next;
	memset(event, 0, sizeof(*event));
	free(event);
	nextp = ep;
      }
    }

  /* Wait for some event(s) to happen */

    gEventOk = 1;
    memset(gSigsCaught, 0, sizeof(gSigsCaught));
    sigprocmask(SIG_UNBLOCK, &sigs, NULL);

    rtn = select(maxfd, &rfds, &wfds, &efds, top);

    sigprocmask(SIG_BLOCK, &sigs, NULL);
    gEventOk = 0;

  /* Calculate time difference since last service */

    gettimeofday(&now, NULL);
    diff = TimevalDiff(&lastTime, &now);
    lastTime = now;

  /* Check return value */

    if (rtn == -1 && errno != EINTR)	/* should never happen! */
    {
      MyWarn("select");
      MyWarnx("select args: %d [%ld, %ld]", maxfd,
	top ? top->tv_sec : 0, top ? top->tv_usec : 0);
      continue;		/* XXX? */
    }

  /* Mark occurring events */

    for (event = gEvents; event; event = event->next)
    {
      event->occurring = 0;
      switch (event->type)
      {
	case EVENT_READ:
	  if (rtn >= 0 && FD_ISSET(event->val, &rfds))
	    event->occurring = 1;
	  break;
	case EVENT_WRITE:
	  if (rtn >= 0 && FD_ISSET(event->val, &wfds))
	    event->occurring = 1;
	  break;
	case EVENT_EXCEPTION:
	  if (rtn >= 0 && FD_ISSET(event->val, &efds))
	    event->occurring = 1;
	  break;
	case EVENT_TIMEOUT:
	  event->to = TimevalDiff(&diff, &event->to);
	  if (!timerisset(&event->to))
	    event->occurring = 1;
	  break;
	case EVENT_SIGNAL:
	  if (gSigsCaught[event->val])
	    event->occurring = 1;
	  break;
	default:
	  MyWarnx("%s: bogus type %d", __FUNCTION__, event->type);
	  break;
      }
    }

#ifdef DEBUG_EVENT
    {
      Event	e2;

      MyWarnx("ACTIVE EVENTS:");
      for (e2 = gEvents; e2; e2 = e2->next)
	if (e2->occurring)
	  MyWarnx(" -> 0x%08x %s", (u_int) e2, EventDesc(e2));
      MyWarnx("DOING ACTIONS:");
    }
#endif

  /* Do event actions */

    while (1)
    {
      Event	*nextp, *ep;

    /* Get next occurring event */

      for (ep = &gEvents;
	(event = *ep) && !event->occurring;
	ep = &event->next);
      if (!event)
	break;

#ifdef DEBUG_EVENT
      MyWarnx("Doing action for %s", EventDesc(event));
#endif

    /* Remove this event and all others with the same ref # from list */

      for (ep = &gEvents; *ep; ep = nextp)
      {
	Event	const event2 = *ep;

	if (event2->ref != event->ref)
	  nextp = &event2->next;
	else
	{
	  nextp = ep;
	  *ep = event2->next;
	  if (event2 != event)
	  {
	    memset(event2, 0, sizeof(*event2));
	    free(event2);
	  }
	}
      }

    /* Deactivate caller's reference and do action */

      if (event->refp)
	*event->refp = 0;
      if (event->action)
	(*event->action)(event->type, event->cookie);

    /* Nuke entry */

      memset(event, 0, sizeof(*event));
      free(event);
    }
  }

/* EventStop() was called */

  return(-1);
}

/*
 * EventStop()
 *
 * Stop servicing events
 */

void
EventStop(void)
{
  gServiceOn = 0;
}

/*
 * EventDump()
 */

void
EventDump(const char *msg)
{
  ShowList("%s", msg);
}

/*
 * EventRegister()
 */

int
EventRegister(EventRef *refp, int type, int val, int prio,
	void (*action)(int type, void *cookie), void *cookie)
{
  Event	event, e2, *ep;
  int	bad;

/* Initialize */

  if (gNextRefNum == 0)
    EventInit();

/* Create new event descriptor */

  if ((event = malloc(sizeof(*event))) == NULL)
  {
    MyWarn("%s: malloc", __FUNCTION__);
    return(-1);
  }

/* Initialize */

  memset(event, 0, sizeof(*event));
  event->magic = EVENT_MAGIC;
  event->type = type;
  event->val = val;
  event->prio = prio;
  event->action = action;
  event->cookie = cookie;
  event->refp = refp;

/* Check type and value */

  switch (event->type)
  {
    case EVENT_READ:
    case EVENT_WRITE:
    case EVENT_EXCEPTION:
    case EVENT_TIMEOUT:
      bad = (val < 0);
      break;
    case EVENT_SIGNAL:
      bad = (val <= 0 || val >= NSIG);
      break;
    default:
      bad = 1;
      break;
  }
  if (bad)
  {
    MyWarnx("%s: bad event: %s", __FUNCTION__, EventDesc(event));
bogus:
    memset(event, 0, sizeof(event));
    free(event);
    return(-1);
  }

/* See if it conflicts with some other event */

  if (event->type != EVENT_TIMEOUT)
    for (e2 = gEvents; e2; e2 = e2->next)
      if (event->type == e2->type && event->val == e2->val)
      {
	MyWarnx("%s: event %s conflicts", __FUNCTION__, EventDesc(event));
	goto bogus;
      }

/* Assign reference; duplicates of pending events are allowed */

  if (refp && *refp != 0)
  {
    event->ref = *refp;
    for (e2 = gEvents; e2; e2 = e2->next)
      if (e2->ref == event->ref && e2->refp == refp)
	break;
    if (!e2)
    {
      MyWarnx("%s: invalid ref %s", __FUNCTION__, EventDesc(event));
      goto bogus;
    }
  }
  else
  {
    event->ref = gNextRefNum++;
    if (refp)
      *refp = event->ref;
  }

/* Block/catch newly registered signals */

  if (event->type == EVENT_SIGNAL)
  {
    sigset_t	sigs;

    signal(event->val, EventCatchSignal);
    if (sigprocmask(SIG_BLOCK, NULL, &sigs) < 0)
      MyWarn("sigprocmask1");
    sigaddset(&sigs, event->val);
    if (sigprocmask(SIG_BLOCK, &sigs, NULL) < 0)
      MyWarn("sigprocmask2");
  }

/* Convert miliseconds to timeval */

  if (event->type == EVENT_TIMEOUT)
  {
    event->to.tv_sec = val / 1000;
    event->to.tv_usec = (val % 1000) * 1000;
  }

/* Add to the list, sorted by priority */

  for (ep = &gEvents; *ep && prio <= (*ep)->prio; ep = &(*ep)->next);
  event->next = *ep;
  *ep = event;

/* Done */

#ifdef DEBUG_EVENT
  ShowList("After %s(%u)", __FUNCTION__, event->ref);
#endif
  return(0);
}

/*
 * EventUnRegister()
 */

int
EventUnRegister(EventRef *refp)
{
  Event		*ep, *nextp;
  const int	ref = refp ? *refp : 0;

/* Check reference */

  if (!ref)
    return(0);

/* Find matching events in chain and detach */

  for (ep = &gEvents; *ep; ep = nextp)
  {
    Event	const event = *ep;

    if (event->ref != ref)
      nextp = &event->next;
    else
    {
      nextp = ep;
      *ep = event->next;
      memset(event, 0, sizeof(*event));
      free(event);
      *refp = 0;
    }
  }
  if (*refp)
  {
    MyWarnx("%s: event not found", __FUNCTION__);
    return(-1);
  }

/* Done */

#ifdef DEBUG_EVENT
  ShowList("After %s", __FUNCTION__);
#endif
  return(0);
}

/*
 * EventIsRegistered()
 */

int
EventIsRegistered(EventRef ref)
{
  Event	event;

  if (ref == 0)
    return(0);
  for (event = gEvents; event; event = event->next)
    if (event->ref == ref)
      return(1);
  return(0);
}

/*
 * EventTimerRemain()
 *
 * Returns the number of milliseconds remaining on a timer.
 * Returns -1 if the timer is not registered or is not a timer event.
 */

int
EventTimerRemain(EventRef ref)
{
  Event	event;

  for (event = gEvents; event; event = event->next)
    if (event->ref == ref && event->type == EVENT_TIMEOUT)
      return(event->to.tv_sec * 1000 + event->to.tv_usec / 1000);
  return(-1);
}

/*
 * EventCatchSignal()
 */

static void
EventCatchSignal(int sig)
{

/* Spurious? */

  if (!gEventOk)
  {
    MyWarnx("caught unexpected signal %s", sys_signame[sig]);
    return;
  }

/* Mark signal as having occurred */

  gSigsCaught[sig] = 1;
}

/*
 * EventDesc()
 *
 * Return a brief textual description of what an event is
 */

#define DESC_NBUFS	5

static char *
EventDesc(Event event)
{
  static int	bn;
  static char	buf[DESC_NBUFS][50];

  bn = (bn + 1) % DESC_NBUFS;
  switch (event->type)
  {
    case EVENT_READ:
      snprintf(buf[bn], sizeof(buf[bn]), "Read(%d)", event->val);
      break;
    case EVENT_WRITE:
      snprintf(buf[bn], sizeof(buf[bn]), "Write(%d)", event->val);
      break;
    case EVENT_EXCEPTION:
      snprintf(buf[bn], sizeof(buf[bn]), "Except(%d)", event->val);
      break;
    case EVENT_SIGNAL:
      snprintf(buf[bn], sizeof(buf[bn]), "Signal(%s)", sys_signame[event->val]);
      break;
    case EVENT_TIMEOUT:
      snprintf(buf[bn], sizeof(buf[bn]), "Timeout(%d)", event->val);
      break;
    default:
      snprintf(buf[bn], sizeof(buf[bn]), "??[%d](%d)", event->type, event->val);
      return(NULL);
  }
  snprintf(buf[bn] + strlen(buf[bn]), sizeof(buf[bn]) - strlen(buf[bn]),
    " REF %u @ %p", event->ref, event->refp);
  if (event->magic != EVENT_MAGIC)
    snprintf(buf[bn] + strlen(buf[bn]),
      sizeof(buf[bn]) - strlen(buf[bn]), " BAD MAGIC");
  return(buf[bn]);
}

/*
 * TimevalDiff()
 */

static struct timeval
TimevalDiff(struct timeval *lo, struct timeval *hi)
{
  struct timeval	diff;

/* Convert "negative" answer to zero */

  if (timercmp(lo, hi, > ))
  {
    memset(&diff, 0, sizeof(diff));
    return(diff);
  }

/* Subtract */

  diff.tv_sec = hi->tv_sec - lo->tv_sec;
  if (hi->tv_usec >= lo->tv_usec)
    diff.tv_usec = hi->tv_usec - lo->tv_usec;
  else
  {
    diff.tv_sec--;
    diff.tv_usec = hi->tv_usec + 1000000 - lo->tv_usec;
  }
  return(diff);
}

/*
 * ShowList()
 */

static void
ShowList(const char *fmt, ...)
{
  Event		e2;
  char		buf[100];
  va_list	args;

  va_start(args, fmt);
  vsnprintf(buf, sizeof(buf), fmt, args);
  va_end(args);
  MyWarnx("Event list: %s", buf);
  for (e2 = gEvents; e2; e2 = e2->next)
    MyWarnx("  %p: %s -> %p", e2, EventDesc(e2), e2->action);
}

