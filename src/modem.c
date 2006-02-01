
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

#ifdef __DragonFly__
#include <netgraph/socket/ng_socket.h>
#include <netgraph/ng_message.h>
#include <netgraph/async/ng_async.h>
#include <netgraph/tty/ng_tty.h>
#else
#include <netgraph/ng_socket.h>
#include <netgraph/ng_message.h>
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
  #define MODEM_DEFAULT_SPEED		"115200"
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
  static void		ModemUpdate(PhysInfo p);
  static void		ModemStat(PhysInfo p);
  static int		ModemOriginated(PhysInfo p);
  static int		ModemPeerAddr(PhysInfo p, void *buf, int buf_len);

  static void		ModemStart(void *arg);
  static void		ModemDoClose(ModemInfo m, int opened);

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

  static int		ModemSetCommand(int ac, char *av[], void *arg);
  static int		ModemInstallNodes(ModemInfo m);
  static int		ModemGetNgStats(ModemInfo m, struct ng_async_stat *sp);

  static void		ModemCheck(void *arg);
  static void		ModemErrorCheck(void *arg);

/*
 * GLOBAL VARIABLES
 */

  const struct phystype gModemPhysType = {
    .name		= "modem",
    .synchronous	= FALSE,
    .minReopenDelay	= MODEM_REOPEN_PAUSE,
    .mtu		= MODEM_MTU,
    .mru		= MODEM_MRU,
    .init		= ModemInit,
    .open		= ModemOpen,
    .close		= ModemClose,
    .update 		= ModemUpdate,
    .showstat		= ModemStat,
    .originate		= ModemOriginated,
    .peeraddr		= ModemPeerAddr,
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
    50, 75, 110, 134, 150, 200, 300, 600, 1200, 1800, 2400, 4800, 9600,
    19200, 38400, 7200, 14400, 28800, 57600, 76800, 115200, 230400, -1
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
  char		*s;
  ModemInfo	m;

  m = (ModemInfo) (p->info = Malloc(MB_PHYS, sizeof(*m)));
  m->watch = TIOCM_CAR;
  m->chat = ChatInit(lnk, ModemChatSetBaudrate,
		ModemChatLog, ModemChatMalloc, ModemChatFree);
  m->fd = -1;
  m->opened = FALSE;

  /* Set nominal link speed and bandwith for a modem connection */
  lnk->latency = MODEM_DEFAULT_LATENCY;
  lnk->bandwidth = MODEM_DEFAULT_BANDWIDTH;

  /* Set default speed */
  strlcpy(defSpeed, MODEM_DEFAULT_SPEED, sizeof(defSpeed));
  s = defSpeed;
  ModemSetCommand(1, &s, (void *) SET_SPEED);
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
      ModemChatConnectResult(lnk, TRUE, NULL);
    } else
      ModemDoClose(m, TRUE);		/* Stop idle script then dial back */
  } else
    ModemStart(m);			/* Open device and try to dial */
}

/*
 * ModemStart()
 */

static void
ModemStart(void *arg)
{
  ModemInfo		const m = (ModemInfo) arg;
  const time_t		now = time(NULL);
  struct authdata	auth;
  FILE			*scriptfp;

  /* If we're idle, and there's no idle script, there's nothing to do */
  assert(!m->answering);
  TimerStop(&m->startTimer);
  if (!m->opened && !*m->idleScript)
    return;

  /* Avoid brief hang from kernel enforcing minimum DTR hold time */
  if (now - m->lastClosed < MODEM_MIN_CLOSE_TIME) {
    TimerInit(&m->startTimer, "ModemStart",
      (MODEM_MIN_CLOSE_TIME - (now - m->lastClosed)) * SECONDS, ModemStart, m);
    TimerStart(&m->startTimer);
    return;
  }

  /* Open and configure serial port */
  if ((m->fd = OpenSerialDevice(m->device, m->speed)) < 0)
    goto fail;

  /* If connecting, but no connect script, then skip chat altogether */
  if (m->opened && !*m->connScript) {
    ModemChatConnectResult(lnk, TRUE, NULL);
    return;
  }

  /* Open chat script file */
  if ((scriptfp = OpenConfFile(SCRIPT_FILE)) == NULL) {
    Log(LG_ERR, ("[%s] can't open chat script file", lnk->name));
    ExclusiveCloseDevice(m->fd, m->device);
    m->fd = -1;
fail:
    m->opened = FALSE;
    m->lastClosed = time(NULL);
    PhysDown(STR_ERROR, lcats(STR_DEV_NOT_READY));
    return;
  }

  /* Preset some special chat variables */
  ChatPresetVar(m->chat, CHAT_VAR_DEVICE, m->device);
  ChatPresetVar(m->chat, CHAT_VAR_LOGIN, bund->conf.auth.authname);
  memset(&auth, 0, sizeof(auth));
  strlcpy(auth.authname, bund->conf.auth.authname, sizeof(auth.authname));
  if (AuthGetData(&auth, 0) >= 0)
    ChatPresetVar(m->chat, CHAT_VAR_PASSWORD, auth.password);

  /* Run connect or idle script as appropriate */
  if (!m->opened) {
    ChatPresetVar(m->chat, CHAT_VAR_IDLE_RESULT, "<unknown>");
    ChatStart(m->chat, m->fd, scriptfp, m->idleScript, ModemChatIdleResult);
  } else {
    m->originated = TRUE;
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
  ModemDoClose(m, FALSE);
  PhysDown(0, NULL);
}

/*
 * ModemDoClose()
 */

static void
ModemDoClose(ModemInfo m, int opened)
{
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
    NgFuncShutdownNode(bund, lnk->name, path);
    *m->ttynode = '\0';
  }
  ExclusiveCloseDevice(m->fd, m->device);
  m->lastClosed = time(NULL);
  m->answering = FALSE;
  m->fd = -1;
  m->opened = opened;
  ModemStart(m);
}

/*
 * ModemUpdate()
 */

static void
ModemUpdate(PhysInfo p)
{
  ModemInfo		const m = (ModemInfo) p->info;
  LcpState		const lcp = &lnk->lcp;
  char        		path[NG_PATHLEN+1];

  /* Update async config */
  m->acfg.accm = lcp->peer_accmap | lcp->want_accmap;
  if (NgSendMsg(bund->csock, path, NGM_ASYNC_COOKIE,
      NGM_ASYNC_CMD_SET_CONFIG, &m->acfg, sizeof(m->acfg)) < 0) {
    Log(LG_PHYS, ("[%s] can't update config for %s: %s",
      lnk->name, path, strerror(errno)));
  }
}

/*
 * ModemChatConnectResult()
 *
 * Connect chat script returns here when finished.
 */

static void
ModemChatConnectResult(void *arg, int result, const char *msg)
{
  ModemInfo	m;
  const char	*cspeed;
  int		bw;

  /* Retrieve context */
  lnk = (Link) arg;
  bund = lnk->bund;
  m = (ModemInfo) lnk->phys->info;

  /* Was the connect script successful? */
  Log(LG_ERR, ("[%s] chat script %s",
    lnk->name, result ? "succeeded" : "failed"));
  if (!result) {
failed:
    ModemDoClose(m, FALSE);
    PhysDown(STR_ERROR, "%s", msg);
    return;
  }

  /* Set modem's reported connection speed (if any) as the link bandwidth */
  if ((cspeed = ChatGetVar(m->chat, CHAT_VAR_CONNECT_SPEED)) != NULL) {
    if ((bw = (int) strtoul(cspeed, NULL, 10)) > 0)
      lnk->bandwidth = bw;
    Freee(MB_CHAT, cspeed);
  }

  /* Do async <-> sync conversion via netgraph node */
  if (ModemInstallNodes(m) < 0) {
    msg = lcats(STR_DEV_NOT_READY);
    goto failed;
  }

  /* Start pin check and report timers */
  TimerInit(&m->checkTimer, "ModemCheck",
    MODEM_CHECK_INTERVAL * SECONDS, ModemCheck, NULL);
  TimerStart(&m->checkTimer);
  TimerStop(&m->reportTimer);
  TimerInit(&m->reportTimer, "ModemReport",
    MODEM_ERR_REPORT_INTERVAL * SECONDS, ModemErrorCheck, NULL);
  TimerStart(&m->reportTimer);

  /* Done */
  PhysUp();
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
  ModemInfo	m;
  const char	*idleResult;

  /* Retrieve context */
  lnk = (Link) arg;
  bund = lnk->bund;
  m = (ModemInfo) lnk->phys->info;

  /* If script failed, then do nothing */
  if (!result) {
    ModemDoClose(m, FALSE);
    return;
  }

  /* See what script wants us to do now by checking variable $IdleResult */
  if ((idleResult = ModemGetVar(CHAT_VAR_IDLE_RESULT)) == NULL) {
    Log(LG_ERR, ("[%s] idle script succeeded, but %s not defined",
      lnk->name, CHAT_VAR_IDLE_RESULT));
    ModemDoClose(m, FALSE);
    return;
  }

  /* Do whatever */
  Log(LG_PHYS, ("[%s] idle script succeeded, action=%s",
    lnk->name, idleResult));
  if (strcasecmp(idleResult, MODEM_IDLE_RESULT_ANSWER) == 0) {
    Log(LG_PHYS, ("[%s] opening link in %s mode", lnk->name, "answer"));
    RecordLinkUpDownReason(NULL, 1, STR_INCOMING_CALL, msg ? "%s" : "", msg);
    m->answering = TRUE;
    IfaceOpenNcps();
  } else if (strcasecmp(idleResult, MODEM_IDLE_RESULT_RINGBACK) == 0) {
    Log(LG_PHYS, ("[%s] opening link in %s mode", lnk->name, "ringback"));
    RecordLinkUpDownReason(NULL, 1, STR_RINGBACK, msg ? "%s" : "", msg);
    m->answering = FALSE;
    IfaceOpenNcps();
  } else {
    Log(LG_ERR, ("[%s] idle script succeeded, but action \"%s\" unknown",
      lnk->name, idleResult));
    ModemDoClose(m, FALSE);
  }
  Freee(MB_CHAT, idleResult);
}

/*
 * ModemInstallNodes()
 */

static int
ModemInstallNodes(ModemInfo m)
{
  struct nodeinfo	ngtty;
  struct ngm_mkpeer	ngm;
  char        		path[NG_PATHLEN+1];
  char        		idpath[32];
  int			hotchar = PPP_FLAG;
  int			ldisc = NETGRAPHDISC;
  char			linkHook[NG_HOOKLEN + 1];

  /* Install ng_tty line discipline */
  if (ioctl(m->fd, TIOCSETD, &ldisc) < 0) {

    /* Installation of the tty node type should be automatic, but isn't yet.
       The 'mkpeer' below will fail, because you can only create a ng_tty
       node via TIOCSETD; however, this will force a load of the node type. */
    if (errno == ENODEV) {
      (void)NgSendAsciiMsg(bund->csock, ".",
	"mkpeer { type=\"%s\" ourhook=\"dummy\" peerhook=\"%s\" }",
	NG_TTY_NODE_TYPE, NG_TTY_HOOK);
    }
    if (ioctl(m->fd, TIOCSETD, &ldisc) < 0) {
      Log(LG_PHYS, ("[%s] ioctl(TIOCSETD, %d): %s",
	lnk->name, ldisc, strerror(errno))); 
      return(-1);
    }
  }

  /* Get the name of the ng_tty node */
  if (ioctl(m->fd, NGIOCGINFO, &ngtty) < 0) {
    Log(LG_PHYS, ("[%s] ioctl(NGIOCGINFO): %s", lnk->name, strerror(errno))); 
    return(-1);
  }
  snprintf(m->ttynode, sizeof(m->ttynode), "%s", ngtty.name);

  /* Set the ``hot char'' on the TTY node */
  snprintf(path, sizeof(path), "%s:", ngtty.name);
  if (NgSendMsg(bund->csock, path, NGM_TTY_COOKIE,
      NGM_TTY_SET_HOTCHAR, &hotchar, sizeof(hotchar)) < 0) {
    Log(LG_PHYS, ("[%s] can't set hotchar", lnk->name));
    return(-1);
  }

  /* Attach an async converter node */
  snprintf(ngm.type, sizeof(ngm.type), "%s", NG_ASYNC_NODE_TYPE);
  snprintf(ngm.ourhook, sizeof(ngm.ourhook), "%s", NG_TTY_HOOK);
  snprintf(ngm.peerhook, sizeof(ngm.peerhook), "%s", NG_ASYNC_HOOK_ASYNC);
  if (NgSendMsg(bund->csock, path, NGM_GENERIC_COOKIE,
      NGM_MKPEER, &ngm, sizeof(ngm)) < 0) {
    Log(LG_PHYS, ("[%s] can't connect %s node", lnk->name, NG_ASYNC_NODE_TYPE));
    return(-1);
  }

  /* Configure the async converter node */
  snprintf(path, sizeof(path), "%s:%s", ngtty.name, NG_TTY_HOOK);
  memset(&m->acfg, 0, sizeof(m->acfg));
  m->acfg.enabled = TRUE;
  m->acfg.accm = ~0;
  m->acfg.amru = MODEM_MRU;
  m->acfg.smru = MODEM_MTU;
  if (NgSendMsg(bund->csock, path, NGM_ASYNC_COOKIE,
      NGM_ASYNC_CMD_SET_CONFIG, &m->acfg, sizeof(m->acfg)) < 0) {
    Log(LG_PHYS, ("[%s] can't config %s", lnk->name, path));
    return(-1);
  }

  /* Attach async node to PPP node */
  snprintf(linkHook, sizeof(linkHook),
    "%s%d", NG_PPP_HOOK_LINK_PREFIX, lnk->bundleIndex);
  snprintf(idpath, sizeof(idpath), "[%x]:", bund->nodeID);
  NgFuncConnect(path, NG_ASYNC_HOOK_SYNC, idpath, linkHook);

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
  ModemInfo		m;
  struct termios	attr;

  /* Retrieve context */
  lnk = (Link) arg;
  bund = lnk->bund;
  m = (ModemInfo) lnk->phys->info;

  /* Change baud rate */
  if (tcgetattr(m->fd, &attr) < 0) {
    Log(LG_ERR, ("[%s] can't tcgetattr \"%s\": %s",
      lnk->name, m->device, strerror(errno)));
    return(-1);
  }
  if (cfsetspeed(&attr, (speed_t) baud) < 0) {
    Log(LG_ERR, ("[%s] can't set speed %d: %s",
      lnk->name, baud, strerror(errno)));
    return(-1);
  }
  if (tcsetattr(m->fd, TCSANOW, &attr) < 0) {
    Log(LG_ERR, ("[%s] can't tcsetattr \"%s\": %s",
      lnk->name, m->device, strerror(errno)));
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
  char		buf[128];
  va_list	args;
  int		logLevel;

  /* Retrieve context */
  lnk = (Link) arg;
  bund = lnk->bund;

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
    snprintf(buf, sizeof(buf), "[%s] chat: ", lnk->name);
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
ModemGetVar(const char *name)
{
  ModemInfo	const m = (ModemInfo) lnk->phys->info;

  return ChatGetVar(m->chat, name);
}

/*
 * ModemCheck()
 */

static void
ModemCheck(void *arg)
{
  ModemInfo	const m = (ModemInfo) lnk->phys->info;
  int		state;

  if (ioctl(m->fd, TIOCMGET, &state) < 0) {
    Log(LG_PHYS, ("[%s] can't ioctl(%s) %s: %s",
      lnk->name, "TIOCMGET", m->device, strerror(errno)));
    PhysDown(STR_ERROR, "ioctl(%s): %s", "TIOCMGET", strerror(errno));
    ModemDoClose(m, FALSE);
    return;
  }
  if ((m->watch & TIOCM_CAR) && !(state & TIOCM_CAR)) {
    Log(LG_PHYS, ("[%s] carrier detect (CD) signal lost", lnk->name));
    PhysDown(STR_DROPPED, "%s", lcats(STR_LOST_CD));
    ModemDoClose(m, FALSE);
    return;
  }
  if ((m->watch & TIOCM_DSR) && !(state & TIOCM_DSR)) {
    Log(LG_PHYS, ("[%s] data-set ready (DSR) signal lost", lnk->name));
    PhysDown(STR_DROPPED, "%s", lcats(STR_LOST_DSR));
    ModemDoClose(m, FALSE);
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
  ModemInfo		const m = (ModemInfo) lnk->phys->info;
  char			path[NG_PATHLEN + 1];
  struct ng_async_stat	stats;

  /* Check for errors */
  snprintf(path, sizeof(path), "%s:%s", m->ttynode, NG_TTY_HOOK);
  if (ModemGetNgStats(m, &stats) >= 0
      && (stats.asyncBadCheckSums
	|| stats.asyncRunts || stats.asyncOverflows)) {
    Log(LG_PHYS, ("[%s] NEW FRAME ERRS: FCS %u RUNT %u OVFL %u",
      lnk->name, stats.asyncBadCheckSums,
      stats.asyncRunts, stats.asyncOverflows));
    (void) NgSendMsg(bund->csock, path,
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
ModemGetNgStats(ModemInfo m, struct ng_async_stat *sp)
{
  char			path[NG_PATHLEN + 1];
  union {
    u_char		buf[sizeof(struct ng_mesg) + sizeof(*sp)];
    struct ng_mesg	resp;
  } u;

  /* Get stats */
  snprintf(path, sizeof(path), "%s:%s", m->ttynode, NG_TTY_HOOK);
  if (NgFuncSendQuery(path, NGM_ASYNC_COOKIE, NGM_ASYNC_CMD_GET_STATS,
      NULL, 0, &u.resp, sizeof(u), NULL) < 0) {
    Log(LG_PHYS, ("[%s] can't get stats: %s", lnk->name, strerror(errno)));
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
ModemSetCommand(int ac, char *av[], void *arg)
{
  ModemInfo	const m = (ModemInfo) lnk->phys->info;

  if (lnk->phys->type != &gModemPhysType) {
    Log(LG_ERR, ("[%s] link type is not modem", lnk->name));
    return(0);
  }
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
	  Log(LG_ERR, ("[%s] %s: invalid speed", lnk->name, *av));
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
	ModemDoClose(m, FALSE);
      else if (m->fd < 0 && *m->idleScript)
	ModemStart(m);
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
	    Printf("[%s] modem signal \"%s\" is unknown\r\n", lnk->name, *av);
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

/* XXX mbretter: the phone-number would be correct */
static int
ModemPeerAddr(PhysInfo p, void *buf, int buf_len)
{
  ModemInfo	const m = (ModemInfo) p;

  if (buf_len < sizeof(m->ttynode))
    return(-1);

  memcpy(buf, m->ttynode, sizeof(m->ttynode));

  return(0);
}


/*
 * ModemStat()
 */

void
ModemStat(PhysInfo p)
{
  ModemInfo		const m = (ModemInfo) p->info;
  struct ng_async_stat	stats;

  Printf("Modem info:\r\n");
  Printf("\tDevice       : %s\r\n", m->device);
  Printf("\tPort speed   : %d baud\r\n", m->speed);
  Printf("\tConn. script : \"%s\"\r\n", m->connScript);
  Printf("\tIdle script  : \"%s\"\r\n", m->idleScript);
  Printf("\tPins to watch: %s%s\r\n",
    (m->watch & TIOCM_CAR) ? "CD " : "",
    (m->watch & TIOCM_DSR) ? "DSR" : "");
  if (ModemGetNgStats(m, &stats) >= 0) {
    Printf("Async stats:\n");
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

