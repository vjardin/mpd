/*
 * See ``COPYRIGHT.mpd''
 *
 * $Id$
 *
 */

  #include "ppp.h"
  #include "event.h"

/*
 * DEFINITIONS
 */

  #define MAX_EVENT_NAME	32
  #define EVENT_MAGIC		0x3de80f67

  #define MAXOF(x,y)		((x)>(y)?(x):(y))

  struct pevent_ctx	*gPeventCtx = NULL;

/*
 * INTERNAL VARIABLES
 */

  static void   (*gWarnx)(const char *fmt, ...) = warnx;

/*
 * INTERNAL FUNCTIONS
 */

  static void		EventHandler(void *arg);

  static void		MyWarn(const char *fmt, ...) __printflike(1, 2);
  static void		MyWarnx(const char *fmt, ...) __printflike(1, 2);

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
  if (warnx) gWarnx = warnx;
}

/*
 * EventInit()
 *
 */

int
EventInit(void)
{

  gPeventCtx = pevent_ctx_create(MB_EVENT, NULL);
  if (!gPeventCtx) {
    MyWarnx("%s: error pevent_ctx_create: %d", __FUNCTION__, errno);
    return(-1);
  }

  return(0);
}

/*
 * EventStop()
 *
 * Stop servicing events
 */

void
EventStop(void)
{
  pevent_ctx_destroy(&gPeventCtx);
}

/*
 * EventDump()
 */

void
EventDump(Context ctx, const char *msg)
{
  u_int	n;

  n = pevent_ctx_count(gPeventCtx);
  Printf("%d Events registered\n", n);
}

/*
 * EventRegister()
 */

int
EventRegister2(EventRef *refp, int type, int val, int flags,
	void (*action)(int type, void *cookie), void *cookie, const char *dbg,
	const char *file, int line)
{
    EventRef	ev;

    Log(LG_EVENTS, ("EVENT: Registering event %s at %s:%d", dbg, file, line));
    if (!gPeventCtx)
	EventInit();

    if (*refp != NULL)
	FREE(MB_EVENT, *refp);

    if ((ev = MALLOC(MB_EVENT, sizeof(struct event_ref))) == NULL) {
	MyWarn("%s: malloc", __FUNCTION__);
	return(-1);
    }

    ev->arg = cookie;
    ev->handler = action;
    ev->type = type;
    ev->pe = NULL;
    ev->dbg = dbg;

    if (pevent_register(gPeventCtx, &ev->pe, flags, &gGiantMutex, EventHandler,
	    ev, type, val) == -1) {
        MyWarnx("%s: error pevent_register: %s", __FUNCTION__, strerror(errno));
        return(-1);
    }
  
    *refp = ev;
    Log(LG_EVENTS, ("EVENT: Registering event %s done at %s:%d", dbg, file, line));
    return(0);
}

/*
 * EventUnRegister()
 */

int
EventUnRegister2(EventRef *refp, const char *file, int line)
{
    const EventRef	ev = *refp;

    if (ev == NULL)
	return(0);

    Log(LG_EVENTS, ("EVENT: Unregistering event %s at %s:%d", ev->dbg, file, line));
    pevent_unregister(&ev->pe);
    Log(LG_EVENTS, ("EVENT: Unregistering event %s done at %s:%d", ev->dbg, file, line));
    FREE(MB_EVENT, ev);
    *refp = NULL;
    return(0);
}

/*
 * EventIsRegistered()
 */

int
EventIsRegistered(EventRef *ref)
{
  if (*ref == NULL)
    return FALSE;

  if ((*ref)->pe == NULL)
    return FALSE;

  return TRUE;
}

/*
 * EventTimerRemain()
 *
 * Returns the number of milliseconds remaining on a timer.
 * Returns -1 if the timer is not registered or is not a timer event.
 */

int
EventTimerRemain(EventRef *refp)
{
  const EventRef	ev = *refp;
  struct pevent_info	info;

  if (ev == NULL)
    return(-1);

  if (pevent_get_info(ev->pe, &info) == -1)
    return(-1);

  return(info.u.millis);
}

static void
EventHandler(void *arg)
{
    EventRef	ev = (EventRef) arg;
    const char	*dbg = ev->dbg;

    Log(LG_EVENTS, ("EVENT: Processing event %s", dbg));
    (ev->handler)(ev->type, ev->arg);
    Log(LG_EVENTS, ("EVENT: Processing event %s done", dbg));
}
