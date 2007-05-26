
/*
 * modem.c
 *
 * Written by Archie Cobbs <archie@freebsd.org>
 * Copyright (c) 1995-1999 Whistle Communications, Inc. All rights reserved.
 * See ``COPYRIGHT.whistle''
 */

#include "ppp.h"
#include <termios.h>
#include "chat.h"
#include "phys.h"
#include "modem.h"
#include "ngfunc.h"
#include "lcp.h"
#include "event.h"
#include "util.h"
#include "log.h"

#include <netgraph/ng_message.h>
#ifdef __DragonFly__
#include <netgraph/socket/ng_socket.h>
#include <netgraph/async/ng_async.h>
#include <netgraph/tty/ng_tty.h>
#else
#include <netgraph/ng_socket.h>
#include <netgraph/ng_async.h>
#include <netgraph/ng_tty.h>
#endif
#include <netgraph.h>

/*
 * DEFINITIONS
 */

#ifndef NETGRAPHDISC
  #define NETGRAPHDISC			7	/* XXX */
#endif

  #define MODEM_MTU			1600
  #define MODEM_MRU			1600

  #define MODEM_REOPEN_PAUSE		8
  #define MODEM_MIN_CLOSE_TIME		3
  #define MODEM_CONNECT_TIMEOUT		30
  #define MODEM_CHECK_INTERVAL		1
  #define MODEM_DEFAULT_SPEED		115200
  #define MODEM_MAX_SCRIPT_NAME		32
  #define MODEM_MAX_QUEUE		8192
  #define MODEM_ERR_REPORT_INTERVAL	60

  #define MODEM_IDLE_RESULT_ANSWER	"answer"
  #define MODEM_IDLE_RESULT_RINGBACK	"ringback"

  /* Special chat script variables we set/use */
  #define CHAT_VAR_LOGIN		"$Login"
  #define CHAT_VAR_PASSWORD		"$Password"
  #define CHAT_VAR_DEVICE		"$modemDevice"
  #define CHAT_VAR_IDLE_RESULT		"$IdleResult"
  #define CHAT_VAR_CONNECT_SPEED	"$ConnectionSpeed"

  /* Nominal link parameters */
  #define MODEM_DEFAULT_BANDWIDTH	28800	/* ~33.6 modem */
  #define MODEM_DEFAULT_LATENCY		10000	/* 10ms */

  /* Modem device state */
  struct modeminfo {
    int			fd;			/* Device file desc, or -1 */
    int			csock;			/* netgraph control socket */
    int			speed;			/* Port speed */
    u_int		watch;			/* Signals to watch */
    char		device[20];		/* Serial device name */
    char		ttynode[NG_NODELEN + 1];	/* TTY node name */
    char		connScript[CHAT_MAX_LABEL];	/* Connect script */
    char		idleScript[CHAT_MAX_LABEL];	/* Idle script */
    struct pppTimer	checkTimer;		/* Timer to check pins */
    struct pppTimer	reportTimer;		/* Timer to report errs */
    struct pppTimer	startTimer;		/* Timer for ModemStart() */
    struct optinfo	options;		/* Binary options */
    struct ng_async_cfg	acfg;			/* ng_async node config */
    ChatInfo		chat;			/* Chat script state */
    time_t		lastClosed;		/* Last time device closed */
    u_char		opened:1;		/* We have been opened */
    u_char		originated:1;		/* We originated current call */
    u_char		answering:1;		/* $IdleResult was "answer" */
  };
  typedef struct modeminfo	*ModemInfo;

  /* Set menu options */
  enum {
    SET_DEVICE,
    SET_SPEED,
    SET_CSCRIPT,
    SET_ISCRIPT,
    SET_SCRIPT_VAR,
    SET_WATCH,
  };

/*
 * INTERNAL FUNCTIONS
 */

  static int		ModemInit(PhysInfo p);
  static void		ModemOpen(PhysInfo p);
  static void		ModemClose(PhysInfo p);
  static int		ModemSetAccm(PhysInfo p, u_int32_t accm);
  static void		ModemStat(Context ctx);
  static int		ModemOriginated(PhysInfo p);
  static int		ModemIsSync(PhysInfo p);
  static int		ModemPeerAddr(PhysInfo p, void *buf, int buf_len);

  static void		ModemStart(void *arg);
  static void		ModemDoClose(PhysInfo p, int opened);

  /* Chat callbacks */
  static int		ModemChatSetBaudrate(void *arg, int baud);
  static void		ModemChatLog(void *arg,
				int level, const char *fmt, ...);
  static void		*ModemChatMalloc(void *arg, size_t size);
  static void		ModemChatFree(void *arg, void *mem);
  static void		ModemChatConnectResult(void *arg,
				int rslt, const char *msg);
  static void		ModemChatIdleResult(void *arg, int rslt,
				const char *msg);

  static int		ModemSetCommand(Context ctx, int ac, char *av[], void *arg);
  static int		ModemInstallNodes(PhysInfo p);
  static int		ModemGetNgStats(PhysInfo p, struct ng_async_stat *sp);

  static void		ModemCheck(void *arg);
  static void		ModemErrorCheck(void *arg);

/*
 * GLOBAL VARIABLES
 */

  const struct phystype gModemPhysType = {
    .name		= "modem",
    .minReopenDelay	= MODEM_REOPEN_PAUSE,
    .mtu		= MODEM_MTU,
    .mru		= MODEM_MRU,
    .init		= ModemInit,
    .open		= ModemOpen,
    .close		= ModemClose,
    .showstat		= ModemStat,
    .originate		= ModemOriginated,
    .issync		= ModemIsSync,
    .setaccm 		= ModemSetAccm,
    .peeraddr		= ModemPeerAddr,
    .callingnum		= NULL,
    .callednum		= NULL,
  };

  const struct cmdtab ModemSetCmds[] = {
    { "device name",			"Set modem device",
      ModemSetCommand, NULL, (void *) SET_DEVICE },
    { "speed port-speed",		"Set modem speed",
      ModemSetCommand, NULL, (void *) SET_SPEED },
    { "script [label]",			"Set connect script",
      ModemSetCommand, NULL, (void *) SET_CSCRIPT },
    { "idle-script [label]",		"Set idle script",
      ModemSetCommand, NULL, (void *) SET_ISCRIPT },
    { "var $var string",		"Set script variable",
      ModemSetCommand, NULL, (void *) SET_SCRIPT_VAR },
    { "watch [+|-cd] [+|-dsr]", 	"Set signals to monitor",
      ModemSetCommand, NULL, (void *) SET_WATCH },
    { NULL },
  };

/*
 * INTERNAL VARIABLES
 */

  static int	gSpeedList[] = {
    50, 75, 110, 134, 150, 200, 300, 600, 1200, 1800, 2400, 4800, 9600, 19200, 
    38400, 7200, 14400, 28800, 57600, 76800, 115200, 230400, 460800, 921600, -1
  };

/*
 * ModemInit()
 *
 * Allocate and initialize device private info
 */

static int
ModemInit(PhysInfo p)
{
  char		defSpeed[32];
  ModemInfo	m;

  m = (ModemInfo) (p->info = Malloc(MB_PHYS, sizeof(*m)));
  m->watch = TIOCM_CAR;
  m->chat = ChatInit(p, ModemChatSetBaudrate,
		ModemChatLog, ModemChatMalloc, ModemChatFree);
  m->fd = -1;
  m->opened = FALSE;

  if (p->link) {
    /* Set nominal link speed and bandwith for a modem connection */
    p->link->latency = MODEM_DEFAULT_LATENCY;
    p->link->bandwidth = MODEM_DEFAULT_BANDWIDTH;
  }

    /* Set default speed */
    m->speed = MODEM_DEFAULT_SPEED;
    snprintf(defSpeed, sizeof(defSpeed), "%d", m->speed);
    ChatPresetVar(m->chat, CHAT_VAR_BAUDRATE, defSpeed);
    return(0);
}

/*
 * ModemOpen()
 */

static void
ModemOpen(PhysInfo p)
{
  ModemInfo	const m = (ModemInfo) p->info;

  assert(!m->opened);
  m->opened = TRUE;
  if (m->fd >= 0) {			/* Device is already open.. */
    if (m->answering) {			/* We just answered a call */
      m->originated = FALSE;
      m->answering = FALSE;
      ModemChatConnectResult(p, TRUE, NULL);
    } else
      ModemDoClose(p, TRUE);		/* Stop idle script then dial back */
  } else
    ModemStart(p);			/* Open device and try to dial */
}

/*
 * ModemStart()
 */

static void
ModemStart(void *arg)
{
  PhysInfo		const p = (PhysInfo) arg;
  ModemInfo		const m = (ModemInfo) p->info;
  const time_t		now = time(NULL);
  char			password[AUTH_MAX_PASSWORD];
  FILE			*scriptfp;

  /* If we're idle, and there's no idle script, there's nothing to do */
  assert(!m->answering);
  TimerStop(&m->startTimer);
  if (!m->opened && !*m->idleScript)
    return;

  /* Avoid brief hang from kernel enforcing minimum DTR hold time */
  if (now - m->lastClosed < MODEM_MIN_CLOSE_TIME) {
    TimerInit(&m->startTimer, "ModemStart",
      (MODEM_MIN_CLOSE_TIME - (now - m->lastClosed)) * SECONDS, ModemStart, p);
    TimerStart(&m->startTimer);
    return;
  }

  /* Open and configure serial port */
  if ((m->fd = OpenSerialDevice(p->name, m->device, m->speed)) < 0)
    goto fail;

  /* If connecting, but no connect script, then skip chat altogether */
  if (m->opened && !*m->connScript) {
    ModemChatConnectResult(p, TRUE, NULL);
    return;
  }

  /* Open chat script file */
  if ((scriptfp = OpenConfFile(SCRIPT_FILE, NULL)) == NULL) {
    Log(LG_ERR, ("[%s] MODEM: can't open chat script file", p->name));
    ExclusiveCloseDevice(p->name, m->fd, m->device);
    m->fd = -1;
fail:
    m->opened = FALSE;
    m->lastClosed = time(NULL);
    p->state = PHYS_STATE_DOWN;
    PhysDown(p, STR_ERROR, STR_DEV_NOT_READY);
    return;
  }

    /* Preset some special chat variables */
    ChatPresetVar(m->chat, CHAT_VAR_DEVICE, m->device);
    if (p->link) {
	ChatPresetVar(m->chat, CHAT_VAR_LOGIN, p->link->lcp.auth.conf.authname);
	if (p->link->lcp.auth.conf.password[0] != 0) {
	    ChatPresetVar(m->chat, CHAT_VAR_PASSWORD, p->link->lcp.auth.conf.password);
	} else if (AuthGetData(p->link->lcp.auth.conf.authname,
	    password, sizeof(password), NULL, NULL) >= 0) {
		ChatPresetVar(m->chat, CHAT_VAR_PASSWORD, password);
	}
    }

  /* Run connect or idle script as appropriate */
  if (!m->opened) {
    ChatPresetVar(m->chat, CHAT_VAR_IDLE_RESULT, "<unknown>");
    ChatStart(m->chat, m->fd, scriptfp, m->idleScript, ModemChatIdleResult);
  } else {
    m->originated = TRUE;
    p->state = PHYS_STATE_CONNECTING;
    ChatStart(m->chat, m->fd, scriptfp, m->connScript, ModemChatConnectResult);
  }
}

/*
 * ModemClose()
 */

static void
ModemClose(PhysInfo p)
{
  ModemInfo	const m = (ModemInfo) p->info;

  if (!m->opened)
    return;
  ModemDoClose(p, FALSE);
  p->state = PHYS_STATE_DOWN;
  PhysDown(p, 0, NULL);
}

/*
 * ModemDoClose()
 */

static void
ModemDoClose(PhysInfo p, int opened)
{
  ModemInfo     const m = (ModemInfo) p->info;
  char		path[NG_PATHLEN + 1];
  const char	ch = ' ';

  /* Shutdown everything */
  assert(m->fd >= 0);
  ChatAbort(m->chat);
  TimerStop(&m->checkTimer);
  TimerStop(&m->startTimer);
  TimerStop(&m->reportTimer);
  (void) write(m->fd, &ch, 1);	/* USR kludge to prevent dial lockup */
  if (*m->ttynode != '\0') {
    snprintf(path, sizeof(path), "%s:%s", m->ttynode, NG_TTY_HOOK);
    NgFuncShutdownNode(m->csock, p->name, path);
    *m->ttynode = '\0';
  }
  if (m->csock > 0) {
    close(m->csock);
    m->csock = -1;
  }

  ExclusiveCloseDevice(p->name, m->fd, m->device);
  m->lastClosed = time(NULL);
  m->answering = FALSE;
  m->fd = -1;
  m->opened = opened;
  ModemStart(p);
}

/*
 * ModemSetAccm()
 */

static int
ModemSetAccm(PhysInfo p, u_int32_t accm)
{
  ModemInfo		const m = (ModemInfo) p->info;
  char        		path[NG_PATHLEN+1];

  /* Update async config */
  m->acfg.accm = accm;
  snprintf(path, sizeof(path), "%s:%s", m->ttynode, NG_TTY_HOOK);
  if (NgSendMsg(m->csock, path, NGM_ASYNC_COOKIE,
      NGM_ASYNC_CMD_SET_CONFIG, &m->acfg, sizeof(m->acfg)) < 0) {
    Log(LG_PHYS, ("[%s] MODEM: can't update config for %s: %s",
      p->name, path, strerror(errno)));
      return (-1);
  }
  return (0);
}

/*
 * ModemChatConnectResult()
 *
 * Connect chat script returns here when finished.
 */

static void
ModemChatConnectResult(void *arg, int result, const char *msg)
{
  PhysInfo		const p = (PhysInfo) arg;
  ModemInfo		const m = (ModemInfo) p->info;
  const char	*cspeed;
  int		bw;

  /* Was the connect script successful? */
  Log(LG_PHYS, ("[%s] MODEM: chat script %s",
    p->name, result ? "succeeded" : "failed"));
  if (!result) {
failed:
    ModemDoClose(p, FALSE);
    p->state = PHYS_STATE_DOWN;
    PhysDown(p, STR_ERROR, "%s", msg);
    return;
  }

  /* Set modem's reported connection speed (if any) as the link bandwidth */
  if ((cspeed = ChatGetVar(m->chat, CHAT_VAR_CONNECT_SPEED)) != NULL) {
    if ((bw = (int) strtoul(cspeed, NULL, 10)) > 0) {
	if (p->link)
	    p->link->bandwidth = bw;
    }
    Freee(MB_CHAT, cspeed);
  }

  /* Do async <-> sync conversion via netgraph node */
  if (ModemInstallNodes(p) < 0) {
    msg = STR_DEV_NOT_READY;
    goto failed;
  }

  /* Start pin check and report timers */
  TimerInit(&m->checkTimer, "ModemCheck",
    MODEM_CHECK_INTERVAL * SECONDS, ModemCheck, p);
  TimerStart(&m->checkTimer);
  TimerStop(&m->reportTimer);
  TimerInit(&m->reportTimer, "ModemReport",
    MODEM_ERR_REPORT_INTERVAL * SECONDS, ModemErrorCheck, p);
  TimerStart(&m->reportTimer);

  /* Done */
  p->state = PHYS_STATE_UP;
  PhysUp(p);
}

/*
 * ModemChatIdleResult()
 *
 * Idle chat script returns here when finished. If the script returned
 * successfully, then one of two things happened: either we answered
 * an incoming call, or else we got a ring and want to do ringback.
 * We tell the difference by checking $IdleResult.
 */

static void
ModemChatIdleResult(void *arg, int result, const char *msg)
{
  PhysInfo		const p = (PhysInfo) arg;
  ModemInfo		const m = (ModemInfo) p->info;
  const char	*idleResult;

  /* If script failed, then do nothing */
  if (!result) {
    ModemDoClose(p, FALSE);
    return;
  }

  /* See what script wants us to do now by checking variable $IdleResult */
  if ((idleResult = ChatGetVar(m->chat, CHAT_VAR_IDLE_RESULT)) == NULL) {
    Log(LG_ERR, ("[%s] MODEM: idle script succeeded, but %s not defined",
      p->name, CHAT_VAR_IDLE_RESULT));
    ModemDoClose(p, FALSE);
    return;
  }

  /* Do whatever */
  Log(LG_PHYS, ("[%s] MODEM: idle script succeeded, action=%s",
    p->name, idleResult));

  if (gShutdownInProgress) {
    Log(LG_PHYS, ("Shutdown sequence in progress, ignoring"));
    ModemDoClose(p, FALSE);
  }
  else
  {
    if (strcasecmp(idleResult, MODEM_IDLE_RESULT_ANSWER) == 0) {
      Log(LG_PHYS, ("[%s] MODEM: opening link in %s mode", p->name, "answer"));
      if (p->link)
        RecordLinkUpDownReason(NULL, p->link, 1, STR_INCOMING_CALL, msg ? "%s" : NULL, msg);
      m->answering = TRUE;
      p->state = PHYS_STATE_READY;
      PhysIncoming(p);
    } else if (strcasecmp(idleResult, MODEM_IDLE_RESULT_RINGBACK) == 0) {
      Log(LG_PHYS, ("[%s] MODEM: opening link in %s mode", p->name, "ringback"));
      if (p->link)
        RecordLinkUpDownReason(NULL, p->link, 1, STR_RINGBACK, msg ? "%s" : NULL, msg);
      m->answering = FALSE;
      PhysIncoming(p);
    } else {
      Log(LG_ERR, ("[%s] MODEM: idle script succeeded, but action \"%s\" unknown",
        p->name, idleResult));
      ModemDoClose(p, FALSE);
    }
  }
  Freee(MB_CHAT, idleResult);
}

/*
 * ModemInstallNodes()
 */

static int
ModemInstallNodes(PhysInfo p)
{
  ModemInfo 		m = (ModemInfo) p->info;
  struct nodeinfo	ngtty;
  struct ngm_mkpeer	ngm;
  struct ngm_connect	cn;
  char        		path[NG_PATHLEN+1];
  int			hotchar = PPP_FLAG;
  int			ldisc = NETGRAPHDISC;

    /* Get a temporary netgraph socket node */
    if (NgMkSockNode(NULL, &m->csock, NULL) == -1) {
    	Log(LG_ERR, ("MODEM: NgMkSockNode: %s", strerror(errno)));
    	return(-1);
    }

  /* Install ng_tty line discipline */
  if (ioctl(m->fd, TIOCSETD, &ldisc) < 0) {

    /* Installation of the tty node type should be automatic, but isn't yet.
       The 'mkpeer' below will fail, because you can only create a ng_tty
       node via TIOCSETD; however, this will force a load of the node type. */
    if (errno == ENODEV) {
      (void)NgSendAsciiMsg(m->csock, ".",
	"mkpeer { type=\"%s\" ourhook=\"dummy\" peerhook=\"%s\" }",
	NG_TTY_NODE_TYPE, NG_TTY_HOOK);
    }
    if (ioctl(m->fd, TIOCSETD, &ldisc) < 0) {
      Log(LG_ERR, ("[%s] ioctl(TIOCSETD, %d): %s",
	p->name, ldisc, strerror(errno))); 
      close(m->csock);
      return(-1);
    }
  }

  /* Get the name of the ng_tty node */
  if (ioctl(m->fd, NGIOCGINFO, &ngtty) < 0) {
    Log(LG_ERR, ("[%s] MODEM: ioctl(NGIOCGINFO): %s", p->name, strerror(errno))); 
    return(-1);
  }
  snprintf(m->ttynode, sizeof(m->ttynode), "%s", ngtty.name);

  /* Set the ``hot char'' on the TTY node */
  snprintf(path, sizeof(path), "%s:", ngtty.name);
  if (NgSendMsg(m->csock, path, NGM_TTY_COOKIE,
      NGM_TTY_SET_HOTCHAR, &hotchar, sizeof(hotchar)) < 0) {
    Log(LG_ERR, ("[%s] MODEM: can't set hotchar", p->name));
    close(m->csock);
    return(-1);
  }

  /* Attach an async converter node */
  snprintf(ngm.type, sizeof(ngm.type), "%s", NG_ASYNC_NODE_TYPE);
  snprintf(ngm.ourhook, sizeof(ngm.ourhook), "%s", NG_TTY_HOOK);
  snprintf(ngm.peerhook, sizeof(ngm.peerhook), "%s", NG_ASYNC_HOOK_ASYNC);
  if (NgSendMsg(m->csock, path, NGM_GENERIC_COOKIE,
      NGM_MKPEER, &ngm, sizeof(ngm)) < 0) {
    Log(LG_ERR, ("[%s] MODEM: can't connect %s node", p->name, NG_ASYNC_NODE_TYPE));
    close(m->csock);
    return(-1);
  }

  /* Configure the async converter node */
  snprintf(path, sizeof(path), "%s:%s", ngtty.name, NG_TTY_HOOK);
  memset(&m->acfg, 0, sizeof(m->acfg));
  m->acfg.enabled = TRUE;
  m->acfg.accm = ~0;
  m->acfg.amru = MODEM_MRU;
  m->acfg.smru = MODEM_MTU;
  if (NgSendMsg(m->csock, path, NGM_ASYNC_COOKIE,
      NGM_ASYNC_CMD_SET_CONFIG, &m->acfg, sizeof(m->acfg)) < 0) {
    Log(LG_ERR, ("[%s] MODEM: can't config %s", p->name, path));
    close(m->csock);
    return(-1);
  }

    /* Attach async node to PPP node */
    if (!PhysGetUpperHook(p, cn.path, cn.peerhook)) {
        Log(LG_PHYS, ("[%s] MODEM: can't get upper hook", p->name));
	close(m->csock);
	return (-1);
    }
    snprintf(cn.ourhook, sizeof(cn.ourhook), NG_ASYNC_HOOK_SYNC);
    if (NgSendMsg(m->csock, path, NGM_GENERIC_COOKIE, NGM_CONNECT, 
        &cn, sizeof(cn)) < 0) {
    	    Log(LG_ERR, ("[%s] MODEM: can't connect \"%s\"->\"%s\" and \"%s\"->\"%s\": %s",
	        p->name, path, cn.ourhook, cn.path, cn.peerhook, strerror(errno)));
	    close(m->csock);
	    return (-1);
    }

    /* OK */
    return(0);
}

/*
 * ModemChatSetBaudrate()
 *
 * This callback changes the actual baudrate of the serial port.
 * Should only be called once the device is already open.
 * Returns -1 on failure.
 */

static int
ModemChatSetBaudrate(void *arg, int baud)
{
  PhysInfo		const p = (PhysInfo) arg;
  ModemInfo		const m = (ModemInfo) p->info;
  struct termios	attr;

  /* Change baud rate */
  if (tcgetattr(m->fd, &attr) < 0) {
    Log(LG_ERR, ("[%s] MODEM: can't tcgetattr \"%s\": %s",
      p->name, m->device, strerror(errno)));
    return(-1);
  }
  if (cfsetspeed(&attr, (speed_t) baud) < 0) {
    Log(LG_ERR, ("[%s] MODEM: can't set speed %d: %s",
      p->name, baud, strerror(errno)));
    return(-1);
  }
  if (tcsetattr(m->fd, TCSANOW, &attr) < 0) {
    Log(LG_ERR, ("[%s] MODEM: can't tcsetattr \"%s\": %s",
      p->name, m->device, strerror(errno)));
    return(-1);
  }
  return(0);
}

/*
 * ModemChatLog()
 */

static void
ModemChatLog(void *arg, int level, const char *fmt, ...)
{
  PhysInfo		const p = (PhysInfo) arg;
  char		buf[128];
  va_list	args;
  int		logLevel;

  /* Convert level */
  switch (level) {
    default:
    case CHAT_LG_NORMAL:
      logLevel = LG_CHAT;
      break;
    case CHAT_LG_ERROR:
      logLevel = LG_ERR;
      break;
    case CHAT_LG_DEBUG:
      logLevel = LG_CHAT2;
      break;
  }
  if ((gLogOptions & logLevel) == 0)
    return;

  /* Concat prefix and message */
  va_start(args, fmt);
  vsnprintf(buf, sizeof(buf), fmt, args);
  va_end(args);
  if (*buf != ' ')
    snprintf(buf, sizeof(buf), "[%s] chat: ", p->name);
  else
    *buf = '\0';
  va_start(args, fmt);
  vsnprintf(buf + strlen(buf), sizeof(buf) - strlen(buf), fmt, args);
  va_end(args);

  /* Log it */
  LogPrintf("%s", buf);
}

/*
 * ModemChatMalloc()
 */

static void *
ModemChatMalloc(void *arg, size_t size)
{
  return Malloc(MB_CHAT, size);
}

/*
 * ModemChatFree()
 */

static void
ModemChatFree(void *arg, void *mem)
{
  Freee(MB_CHAT, mem);
}

/*
 * ModemGetVar()
 */

const char *
ModemGetVar(PhysInfo p, const char *name)
{
  ModemInfo	const m = (ModemInfo) p->info;

  return ChatGetVar(m->chat, name);
}

/*
 * ModemCheck()
 */

static void
ModemCheck(void *arg)
{
  PhysInfo	const p = (PhysInfo)arg;
  ModemInfo	const m = (ModemInfo) p->info;
  int		state;

  if (ioctl(m->fd, TIOCMGET, &state) < 0) {
    Log(LG_ERR, ("[%s] MODEM: can't ioctl(%s) %s: %s",
      p->name, "TIOCMGET", m->device, strerror(errno)));
    p->state = PHYS_STATE_DOWN;
    PhysDown(p, STR_ERROR, "ioctl(%s): %s", "TIOCMGET", strerror(errno));
    ModemDoClose(p, FALSE);
    return;
  }
  if ((m->watch & TIOCM_CAR) && !(state & TIOCM_CAR)) {
    Log(LG_PHYS, ("[%s] MODEM: carrier detect (CD) signal lost", p->name));
    p->state = PHYS_STATE_DOWN;
    PhysDown(p, STR_DROPPED, "%s", STR_LOST_CD);
    ModemDoClose(p, FALSE);
    return;
  }
  if ((m->watch & TIOCM_DSR) && !(state & TIOCM_DSR)) {
    Log(LG_PHYS, ("[%s] MODEM: data-set ready (DSR) signal lost", p->name));
    p->state = PHYS_STATE_DOWN;
    PhysDown(p, STR_DROPPED, "%s", STR_LOST_DSR);
    ModemDoClose(p, FALSE);
    return;
  }
  TimerStart(&m->checkTimer);
}

/*
 * ModemErrorCheck()
 *
 * Called every second to record errors to the log
 */

static void
ModemErrorCheck(void *arg)
{
  PhysInfo		const p = (PhysInfo) arg;
  ModemInfo		const m = (ModemInfo) p->info;
  char			path[NG_PATHLEN + 1];
  struct ng_async_stat	stats;

  /* Check for errors */
  snprintf(path, sizeof(path), "%s:%s", m->ttynode, NG_TTY_HOOK);
  if (ModemGetNgStats(p, &stats) >= 0
      && (stats.asyncBadCheckSums
	|| stats.asyncRunts || stats.asyncOverflows)) {
    Log(LG_PHYS, ("[%s] NEW FRAME ERRS: FCS %u RUNT %u OVFL %u",
      p->name, stats.asyncBadCheckSums,
      stats.asyncRunts, stats.asyncOverflows));
    (void) NgSendMsg(m->csock, path,
      NGM_ASYNC_COOKIE, NGM_ASYNC_CMD_CLR_STATS, NULL, 0);
  }

  /* Restart timer */
  TimerStop(&m->reportTimer);
  TimerStart(&m->reportTimer);
}

/*
 * ModemGetNgStats()
 */

static int
ModemGetNgStats(PhysInfo p, struct ng_async_stat *sp)
{
  ModemInfo             const m = (ModemInfo) p->info;
  char			path[NG_PATHLEN + 1];
  union {
    u_char		buf[sizeof(struct ng_mesg) + sizeof(*sp)];
    struct ng_mesg	resp;
  } u;

  /* Get stats */
  snprintf(path, sizeof(path), "%s:%s", m->ttynode, NG_TTY_HOOK);
  if (NgFuncSendQuery(path, NGM_ASYNC_COOKIE, NGM_ASYNC_CMD_GET_STATS,
      NULL, 0, &u.resp, sizeof(u), NULL) < 0) {
    Log(LG_ERR, ("[%s] MODEM: can't get stats: %s", p->name, strerror(errno)));
    return(-1);
  }

  /* Done */
  memcpy(sp, u.resp.data, sizeof(*sp));
  return(0);
}

/*
 * ModemSetCommand()
 */

static int
ModemSetCommand(Context ctx, int ac, char *av[], void *arg)
{
  PhysInfo	const p = ctx->phys;
  ModemInfo	const m = (ModemInfo) p->info;

  switch ((intptr_t)arg) {
    case SET_DEVICE:
      if (ac == 1)
	snprintf(m->device, sizeof(m->device), "%s", av[0]);
      break;
    case SET_SPEED:
      {
	int	k, baud;

	if (ac != 1)
	  return(-1);
	baud = atoi(*av);
	for (k = 0; gSpeedList[k] != -1 && baud != gSpeedList[k]; k++);
	if (gSpeedList[k] == -1)
	  Log(LG_ERR, ("[%s] %s: invalid speed", p->name, *av));
	else
	{
	  char	buf[32];

	  m->speed = baud;
	  snprintf(buf, sizeof(buf), "%d", m->speed);
	  ChatPresetVar(m->chat, CHAT_VAR_BAUDRATE, buf);
	}
      }
      break;
    case SET_CSCRIPT:
      if (ac != 1)
	return(-1);
      *m->connScript = 0;
      snprintf(m->connScript, sizeof(m->connScript), "%s", av[0]);
      break;
    case SET_ISCRIPT:
      if (ac != 1)
	return(-1);
      *m->idleScript = 0;
      snprintf(m->idleScript, sizeof(m->idleScript), "%s", av[0]);
      if (m->opened || TimerRemain(&m->startTimer) >= 0)
	break;		/* nothing needs to be done right now */
      if (m->fd >= 0 && !*m->idleScript)
	ModemDoClose(p, FALSE);
      else if (m->fd < 0 && *m->idleScript)
	ModemStart(p);
      break;
    case SET_SCRIPT_VAR:
      if (ac != 2)
	return(-1);
      ChatPresetVar(m->chat, av[0], av[1]);
      break;
    case SET_WATCH:
      {
	int	bit, add;

	while (ac--)
	{
	  switch (**av)
	  {
	    case '+':
	      (*av)++;
	    default:
	      add = TRUE;
	      break;
	    case '-':
	      add = FALSE;
	      (*av)++;
	      break;
	  }
	  if (!strcasecmp(*av, "cd"))
	    bit = TIOCM_CAR;
	  else if (!strcasecmp(*av, "dsr"))
	    bit = TIOCM_DSR;
	  else
	  {
	    Printf("[%s] modem signal \"%s\" is unknown\r\n", p->name, *av);
	    bit = 0;
	  }
	  if (add)
	    m->watch |= bit;
	  else
	    m->watch &= ~bit;
	  av++;
	}
      }
      break;
    default:
      assert(0);
  }
  return(0);
}

/*
 * ModemOriginated()
 */

static int
ModemOriginated(PhysInfo p)
{
  ModemInfo	const m = (ModemInfo) p->info;

  return(m->originated ? LINK_ORIGINATE_LOCAL : LINK_ORIGINATE_REMOTE);
}

/*
 * ModemIsSync()
 */

static int
ModemIsSync(PhysInfo p)
{
  return (0);
}

/* XXX mbretter: the phone-number would be correct */
static int
ModemPeerAddr(PhysInfo p, void *buf, int buf_len)
{
  ModemInfo	const m = (ModemInfo) p->info;

  if (buf_len < sizeof(m->ttynode))
    return(-1);

  memcpy(buf, m->ttynode, sizeof(m->ttynode));

  return(0);
}


/*
 * ModemStat()
 */

void
ModemStat(Context ctx)
{
  ModemInfo		const m = (ModemInfo) ctx->phys->info;
  struct ng_async_stat	stats;
  const char		*cspeed;

  Printf("Modem info:\r\n");
  Printf("\tDevice       : %s\r\n", m->device);
  Printf("\tPort speed   : %d baud\r\n", m->speed);
  Printf("\tConn. script : \"%s\"\r\n", m->connScript);
  Printf("\tIdle script  : \"%s\"\r\n", m->idleScript);
  Printf("\tPins to watch: %s%s\r\n",
    (m->watch & TIOCM_CAR) ? "CD " : "",
    (m->watch & TIOCM_DSR) ? "DSR" : "");

    Printf("Modem status:\r\n");
    Printf("\tState        : %s\r\n", gPhysStateNames[ctx->phys->state]);
    if (ctx->phys->state != PHYS_STATE_DOWN) {
	Printf("\tOpened       : %s\r\n", (m->opened?"YES":"NO"));
	Printf("\tIncoming     : %s\r\n", (m->originated?"NO":"YES"));

	/* Set modem's reported connection speed (if any) as the link bandwidth */
	if ((cspeed = ChatGetVar(m->chat, CHAT_VAR_CONNECT_SPEED)) != NULL) {
	    Printf("\tConnect speed: %s baud\r\n", cspeed);
	    Freee(MB_CHAT, cspeed);
	}

	if (ctx->phys->state == PHYS_STATE_UP && 
    		ModemGetNgStats(ctx->phys, &stats) >= 0) {
    	    Printf("Async stats:\r\n");
    	    Printf("\t       syncOctets: %8u\r\n", stats.syncOctets);
    	    Printf("\t       syncFrames: %8u\r\n", stats.syncFrames);
    	    Printf("\t    syncOverflows: %8u\r\n", stats.syncOverflows);
	    Printf("\t      asyncOctets: %8u\r\n", stats.asyncOctets);
    	    Printf("\t      asyncFrames: %8u\r\n", stats.asyncFrames);
    	    Printf("\t       asyncRunts: %8u\r\n", stats.asyncRunts);
    	    Printf("\t   asyncOverflows: %8u\r\n", stats.asyncOverflows);
    	    Printf("\tasyncBadCheckSums: %8u\r\n", stats.asyncBadCheckSums);
      }
    }
}

