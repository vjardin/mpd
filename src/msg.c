
/*
 * msg.c
 *
 * Written by Archie Cobbs <archie@whistle.com>
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
    long	type;
    void	*arg;
  };
  typedef struct mpmsg	*Msg;

  struct msghandler
  {
    int		pipe[2];
    int		prio;
    void	(*func)(int type, void *arg);
    EventRef	event;
    Bund	bund;
    Link	lnk;
  };

/*
 * INTERNAL FUNCTIONS
 */

  static void	MsgEvent(int type, void *cookie);
  static void	MsgReregister(MsgHandler m);

/*
 * MsgRegister()
 */

MsgHandler
MsgRegister(void (*func)(int type, void *arg), int prio)
{
  MsgHandler	m;

  m = Malloc(MB_UTIL, sizeof(*m));
  if (pipe(m->pipe) < 0)
  {
    Log(LG_ERR, ("mpd: pipe: %s", strerror(errno)));
    DoExit(EX_ERRDEAD);
  }
  fcntl(m->pipe[PIPE_READ], F_SETFD, 1);
  fcntl(m->pipe[PIPE_WRITE], F_SETFD, 1);
  m->prio = prio;
  m->func = func;
  m->bund = bund;
  m->lnk = lnk;
  MsgReregister(m);
  return(m);
}

/*
 * MsgUnRegister()
 */

void
MsgUnRegister(MsgHandler *m)
{
  close((*m)->pipe[PIPE_WRITE]);
  close((*m)->pipe[PIPE_READ]);
  EventUnRegister(&(*m)->event);
  Freee(*m);
  *m = NULL;
}

/*
 * MsgEvent()
 */

static void
MsgEvent(int type, void *cookie)
{
  MsgHandler	const m = (MsgHandler) cookie;
  int		nread, nrode;
  struct mpmsg	msg;

  lnk = m->lnk;
  bund = m->bund;
  for (nrode = 0; nrode < sizeof(msg); nrode += nread)
  {
    if ((nread = read(m->pipe[PIPE_READ],
      (u_char *) &msg + nrode, sizeof(msg) - nrode)) < 0)
    {
      Log(LG_ERR, ("mpd: %s: read: %s", __FUNCTION__, strerror(errno)));
      DoExit(EX_ERRDEAD);
    }
    if (nread == 0)
    {
      Log(LG_ERR, ("mpd: %s: EOF", __FUNCTION__));
      DoExit(EX_ERRDEAD);
    }
  }
  (*m->func)(msg.type, msg.arg);
  MsgReregister(m);
}

/*
 * MsgSend()
 */

void
MsgSend(MsgHandler m, int type, void *arg)
{
  struct mpmsg	msg;
  int		nw, nwrote;

  if (m == NULL)
    return;
  msg.type = type;
  msg.arg = arg;
  for (nwrote = 0; nwrote < sizeof(msg); nwrote += nw)
    if ((nw = write(m->pipe[PIPE_WRITE],
      (u_char *) &msg + nwrote, sizeof(msg) - nwrote)) < 0)
    {
      Perror("MsgSend: write");
      DoExit(EX_ERRDEAD);
    }
}

/*
 * MsgReregister()
 */

static void
MsgReregister(MsgHandler m)
{
  if (EventRegister(&m->event, EVENT_READ,
    m->pipe[PIPE_READ], m->prio, MsgEvent, m) < 0)
  {
    Log(LG_ERR, ("mpd: can't register event"));
    DoExit(EX_ERRDEAD);
  }
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
    default:
      return("???");
  }
}

