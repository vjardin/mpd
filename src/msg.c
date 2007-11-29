
/*
 * msg.c
 *
 * Written by Archie Cobbs <archie@freebsd.org>
 * Copyright (c) 1995-1999 Whistle Communications, Inc. All rights reserved.
 * See ``COPYRIGHT.whistle''
 */

#include "ppp.h"
#include "msg.h"

/*
 * DEFINITIONS
 */

/* Which pipe file descriptor is which */

  #define PIPE_READ		0
  #define PIPE_WRITE		1

  struct mpmsg
  {
    int		type;
    void	(*func)(int type, void *arg);
    void	*arg;
    const char	*dbg;
  };
  typedef struct mpmsg	*Msg;

  int		msgpipe[2];
  EventRef	msgevent;
  int		pipelen = 0;

/*
 * INTERNAL FUNCTIONS
 */

  static void	MsgEvent(int type, void *cookie);

/*
 * MsgRegister()
 */

void
MsgRegister2(MsgHandler *m, void (*func)(int type, void *arg), const char *dbg)
{
    if ((msgpipe[0]==0) || (msgpipe[1]==0)) {
	if (pipe(msgpipe) < 0) {
	    Perror("%s: Can't create message pipe", 
		__FUNCTION__);
	    DoExit(EX_ERRDEAD);
	}
	fcntl(msgpipe[PIPE_READ], F_SETFD, 1);
	fcntl(msgpipe[PIPE_WRITE], F_SETFD, 1);

	if (fcntl(msgpipe[PIPE_WRITE], F_SETFL, O_NONBLOCK) < 0)
    	    Perror("%s: fcntl", __FUNCTION__);

	if (EventRegister(&msgevent, EVENT_READ,
		msgpipe[PIPE_READ], EVENT_RECURRING, MsgEvent, NULL) < 0) {
	    Perror("%s: Can't register event!", __FUNCTION__);
	    DoExit(EX_ERRDEAD);
        }
    }

    m->func = func;
    m->dbg = dbg;
}

/*
 * MsgUnRegister()
 */

void
MsgUnRegister(MsgHandler *m)
{
    m->func = NULL;
    m->dbg = NULL;
}

/*
 * MsgEvent()
 */

static void
MsgEvent(int type, void *cookie)
{
    int			nread, nrode;
    struct mpmsg	msg;

    for (nrode = 0; nrode < sizeof(msg); nrode += nread) {
	if ((nread = read(msgpipe[PIPE_READ],
    	  (u_char *) &msg + nrode, sizeof(msg) - nrode)) < 0) {
    	    Perror("%s: Can't read from message pipe", __FUNCTION__);
    	    DoExit(EX_ERRDEAD);
	}
	if (nread == 0) {
    	    Log(LG_ERR, ("%s: Unexpected EOF on message pipe!", __FUNCTION__));
    	    DoExit(EX_ERRDEAD);
	}
    }

    SETOVERLOAD(--pipelen);

    Log(LG_EVENTS, ("EVENT: Message %d to %s received", msg.type, msg.dbg));
    (*msg.func)(msg.type, msg.arg);
    Log(LG_EVENTS, ("EVENT: Message %d to %s processed", msg.type, msg.dbg));
}

/*
 * MsgSend()
 */

void
MsgSend(MsgHandler *m, int type, void *arg)
{
    struct mpmsg	msg;
    int			nw, nwrote, retry;

    assert(m);
    assert(m->func);

    SETOVERLOAD(++pipelen);

    msg.type = type;
    msg.func = m->func;
    msg.arg = arg;
    msg.dbg = m->dbg;
    for (nwrote = 0, retry = 10; nwrote < sizeof(msg) && retry > 0; nwrote += nw, retry--) {
	if ((nw = write(msgpipe[PIPE_WRITE],
    	  ((u_char *) &msg) + nwrote, sizeof(msg) - nwrote)) < 0) {
    	    Perror("%s: Message pipe write error", __FUNCTION__);
    	    DoExit(EX_ERRDEAD);
	}
    }
    if (nwrote < sizeof(msg)) {
        Log(LG_ERR, ("%s: Can't write to message pipe, fatal pipe overflow!", 
	  __FUNCTION__));
        DoExit(EX_ERRDEAD);
    }
    Log(LG_EVENTS, ("EVENT: Message %d to %s sent", type, m->dbg));
}

/*
 * MsgName()
 */

const char *
MsgName(int msg)
{
  switch (msg)
  {
    case MSG_OPEN:
      return("OPEN");
    case MSG_CLOSE:
      return("CLOSE");
    case MSG_UP:
      return("UP");
    case MSG_DOWN:
      return("DOWN");
    case MSG_SHUTDOWN:
      return("SHUTDOWN");
    default:
      return("???");
  }
}

