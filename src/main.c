
/*
 * main.c
 *
 * Written by Toshiharu OHNO <tony-o@iij.ad.jp>
 * Copyright (c) 1993, Internet Initiative Japan, Inc. All rights reserved.
 * See ``COPYRIGHT.iij''
 * 
 * Rewritten by Archie Cobbs <archie@freebsd.org>
 * Copyright (c) 1995-1999 Whistle Communications, Inc. All rights reserved.
 * See ``COPYRIGHT.whistle''
 */

#include "ppp.h"
#include "mp.h"
#include "iface.h"
#include "command.h"
#include "console.h"
#include "ngfunc.h"

/*
 * DEFINITIONS
 */

  /* Implied system name when none specified on the command line */
  #define DEFAULT_CONF	"default"

  #define MAX_ARGS	50

  struct option {
    short	n_args;	
    char	sflag;
    const char	*lflag;
    const char	*usage;
    const char	*desc;
  };
  typedef struct option	*Option;

  static const char		*UsageStr = "[options] [system]";
  static struct option		OptList[] = {
    { 1, 'a',	"console-address",	"IP-address",
				"Set console bind IP-address"	},
    { 0, 'b',	"background",	"",
				"Run as a background daemon"	},
    { 1, 'c',	"console-port",	"port",
				"Enable telnet console port"	},
    { 1, 'd',	"directory",	"config-dir",
				"Set config file directory"	},
    { 0, 'k',	"kill",		"",
				"Kill any running mpd process"	},
    { 1, 'f',	"file",		"config-file",
				"Set configuration file"	},
    { 1, 'p',	"pidfile",	"filename",
				"Set PID filename"		},
#ifdef SYSLOG_FACILITY
    { 1, 's',	"syslog-ident",	"ident",
				"Identifier to use for syslog"	},
#endif
    { 0, 'v',	"version",	"",
				"Show version information"	},
    { 0, 'h',	"help",		"",
				"Show usage information"	},
    { 0, 't',	"tee",		"",
				"Insert ng_tee into netgraph"	},
  };

  #define OPTLIST_SIZE		(sizeof(OptList) / sizeof(*OptList))

  /* How long to wait for graceful shutdown when we recieve a SIGTERM */
  #define TERMINATE_DEATH_WAIT	(2 * SECONDS)

/*
 * GLOBAL VARIABLES
 */

  Link			lnk;
  Bund			bund;
  Link			*gLinks;
  Bund			*gBundles;
  int			gNumLinks;
  int			gNumBundles;
  int			gEnableTee = FALSE;

  pthread_mutex_t	gGiantMutex;

  const char		*gConfigFile = CONF_FILE;
  const char		*gConfDirectory = PATH_CONF_DIR;

  char			gLoginAuthName[AUTH_MAX_AUTHNAME];
  const char		*gVersion = MPD_VERSION;

/*
 * INTERNAL FUNCTIONS
 */

  static void		Usage(int ex);
  static void		OptParse(int ac, char *av[]);
  static int		OptApply(Option opt, int ac, char *av[]);
  static Option		OptDecode(char *arg, int longform);
  static void		EventWarnx(const char *fmt, ...);

  static void		SendSignal(int sig);
  static void		OpenSignal(int sig);
  static void		CloseSignal(int sig);
  static void		FatalSignal(int sig);
  static void		SignalHandler(int type, void *arg);
  static void		CloseIfaces(void);

/*
 * INTERNAL VARIABLES
 */

  static struct in_addr	gConsoleBindAddr;
  static int		gConsoleBindPort = DEFAULT_CONSOLE_PORT;
  static int		gConsoleListen = FALSE;
  static int		gBackground = FALSE;
  static int		gKillProc = FALSE;
  static const char	*gPidFile = PID_FILE;
  static const char	*gPeerSystem = NULL;
  static int		gSignalPipe[2];
  static EventRef	gSignalEvent;

/*
 * main()
 */

int
main(int ac, char *av[])
{
  int	listen_fd;
  int	console_fd;
  int	ret;
  char	*args[MAX_ARGS];

  /* enable libpdel typed_mem */
  typed_mem_enable();

  /* Read and parse command line */
  if (ac > MAX_ARGS)
    ac = MAX_ARGS;
  memcpy(args, av, ac * sizeof(*av));	/* Copy to preserve "ps" output */
  OptParse(ac - 1, args + 1);

  /* Background mode? */
  if (gBackground) {
    if (daemon(TRUE, FALSE) < 0)
      err(1, "daemon");
    (void) chdir(gConfDirectory);
  }

  /* Open log file */
  if (LogOpen())
    exit(EX_ERRDEAD);

  /* Randomize */
  srandomdev();

  /* Welcome */
  Greetings();

  /* Check PID file */
  if (PIDCheck(gPidFile, gKillProc) < 0)
    exit(EX_UNAVAILABLE);

  /* Do some initialization */
  MpSetDiscrim();
#ifdef LOCAT_MAIN_FILE
  LocatPush(LOCAT_MAIN_FILE);
#endif

  ret = pthread_mutex_init (&gGiantMutex, NULL);
  if (ret != 0) {
    Log(LG_ERR, ("Could not create giant mutex %d", ret));
    exit(EX_UNAVAILABLE);
  }

  EventSetLog(1, EventWarnx);

  /* Creating signaling pipe */
  if ((ret = pipe(gSignalPipe)) != 0) {
    Log(LG_ERR, ("Could not create signal pipe %d", ret));
    exit(EX_UNAVAILABLE);
  }

  if (EventRegister(&gSignalEvent, EVENT_READ, gSignalPipe[0], DEV_PRIO, SignalHandler, NULL) != 0)
    exit(EX_UNAVAILABLE);

  /* Register for some common fatal signals so we can exit cleanly */
  signal(SIGINT, SendSignal);
  signal(SIGTERM, SendSignal);
  signal(SIGHUP, SendSignal);

  /* Catastrophic signals */
  signal(SIGSEGV, SendSignal);
  signal(SIGBUS, SendSignal);
  signal(SIGABRT, SendSignal);

  /* Other signals make us do things */
  signal(SIGUSR1, SendSignal);
  signal(SIGUSR2, SendSignal);

  /* Signals we ignore */
  signal(SIGPIPE, SIG_IGN);

  /* Get console telnet port */
  if (gConsoleListen) {
    if ((listen_fd = TcpGetListenPort(gConsoleBindAddr,
	&gConsoleBindPort)) < 0) {
      Log(LG_ERR, ("mpd: can't bind console telnet port on %s:%d",
	inet_ntoa(gConsoleBindAddr), gConsoleBindPort));
      DoExit(EX_UNAVAILABLE);
    }
    Log(LG_ALWAYS, ("mpd: telnet console address is %s:%d",
      inet_ntoa(gConsoleBindAddr), gConsoleBindPort));
  } else
    listen_fd = -1;

  console_fd = gBackground ? -1 : fileno(stdin);

  /* Read configuration as specified on the command line, or default */
  if (!gPeerSystem)
    ReadFile(gConfigFile, DEFAULT_CONF, DoCommand);
  else {
    if (ReadFile(gConfigFile, gPeerSystem, DoCommand) < 0) {
      Log(LG_ERR, ("mpd: can't read configuration for \"%s\"", gPeerSystem));
      DoExit(EX_CONFIG);
    }
  }

  /* Intialize console */
  ConsoleInit(console_fd, listen_fd);

  while(1)
    sleep(10000000);

  assert(0);
  return(1);	/* Never reached, but needed to silence compiler warning */
}

/*
 * Greetings()
 */

void
Greetings(void)
{
  LogConsole("Multi-link PPP for FreeBSD, by Archie L. Cobbs.");
  LogConsole("Based on iij-ppp, by Toshiharu OHNO.");
  Log(LG_ALWAYS, ("mpd: pid %lu, version %s", (u_long) getpid(), gVersion));
}

/*
 * CloseIfaces()
 */

static void
CloseIfaces(void)
{
  int	k;

  /* Shut down all interfaces we grabbed */
  for (k = 0; k < gNumBundles; k++) {
    if ((bund = gBundles[k]) != NULL) {
      IpcpDown();			/* XXX */
      IfaceClose();
    }
  }
}

/*
 * DoExit()
 *
 * Cleanup and exit
 */

void
DoExit(int code)
{
  int	j, k;

  /* Weak attempt to record what happened */
  if (code == EX_ERRDEAD)
    Log(LG_ERR, ("mpd: fatal error, exiting"));

  /* Shutdown stuff */
  if (code != EX_TERMINATE)	/* kludge to avoid double shutdown */
    CloseIfaces();

  /* Final link status reports */
  for (k = 0; k < gNumBundles; k++) {
    if ((bund = gBundles[k]) != NULL) {
      for (j = 0; j < bund->n_links; j++) {
	if ((lnk = bund->links[j]) != NULL) {
	  switch (lnk->phys->state) {
	    case PHYS_OPENING:
	      RecordLinkUpDown(0);
	      break;
	    case PHYS_UP:
	    case PHYS_CLOSING:
	      RecordLinkUpDown(-1);
	      break;
	  }
	  SetStatus(ADLG_WAN_DISABLED, STR_PPP_DISABLED);
	}
      }
    }
  }

  /* Blow away all netgraph nodes */
  for (k = 0; k < gNumBundles; k++) {
    if ((bund = gBundles[k]) != NULL)
      NgFuncShutdown(bund);
  }

  /* Remove our PID file and exit */
  Log(LG_ALWAYS, ("mpd: process %d terminated", getpid()));
  LogClose();
  (void) unlink(gPidFile);
  exit(code == EX_TERMINATE ? EX_NORMAL : code);
}

/*
 * SendSignal()
 *
 * Send a signal through the signaling pipe
 * don't add printf's here or any function
 * wich isn't re-entrant
 */

static void
SendSignal(sig)
{
  if (sig == SIGSEGV || sig == SIGBUS || sig == SIGABRT) {
    FatalSignal(sig);
  }
  write(gSignalPipe[1], &sig, 1);
}

/*
 * SignalHandler()
 *
 * dispatch signal
 */
static void
SignalHandler(int type, void *arg)
{
  u_char	sig;

  read(gSignalPipe[0], &sig, sizeof(sig));

  switch(sig) {
    case SIGUSR1:
      OpenSignal(sig);
      break;

    case SIGUSR2:
      CloseSignal(sig);
      break;

    default:
      FatalSignal(sig);
  }

  EventRegister(&gSignalEvent, EVENT_READ, gSignalPipe[0], DEV_PRIO, SignalHandler, NULL);
}

/*
 * FatalSignal()
 *
 * Gracefully exit on receipt of a fatal signal
 */

static void
FatalSignal(sig)
{
  static struct pppTimer	gDeathTimer;
  int				k;

  /* If a SIGTERM, gracefully shutdown; otherwise shutdown now */
  Log(LG_ERR, ("mpd: caught fatal signal %s", sys_signame[sig]));
  for (k = 0; k < gNumBundles; k++) {
    if ((bund = gBundles[k]))
      RecordLinkUpDownReason(NULL, 0, STR_PORT_SHUTDOWN, NULL);
  }

  signal(SIGUSR1, SIG_IGN);
  signal(SIGUSR2, SIG_IGN);
  if (sig != SIGTERM)
    DoExit(EX_ERRDEAD);

  TimerInit(&gDeathTimer, "DeathTimer",
    TERMINATE_DEATH_WAIT, (void (*)(void *)) DoExit, (void *) &gBackground);
  TimerStart(&gDeathTimer);
  CloseIfaces();
}

/*
 * OpenSignal()
 */

static void
OpenSignal(int sig)
{
  /* Apply signal to console bundle & link */
  lnk = gConsoleLink;
  bund = gConsoleBund;

  /* Open bundle */
  if (bund && lnk && lnk->phys && lnk->phys->type) {
    Log(LG_ALWAYS, ("[%s] rec'd signal %s, opening",
      bund->name, sys_signame[sig]));
    RecordLinkUpDownReason(NULL, 1, STR_MANUALLY, NULL);
    IfaceOpenNcps();
    BundOpen();
  } else
    Log(LG_ALWAYS, ("mpd: rec'd signal %s, ignored", sys_signame[sig]));

}

/*
 * CloseSignal()
 */

static void
CloseSignal(int sig)
{

  /* Apply signal to console bundle & link */
  lnk = gConsoleLink;
  bund = gConsoleBund;

  /* Close bundle */
  if (bund && lnk && lnk->phys && lnk->phys->type) {
    Log(LG_ALWAYS, ("[%s] rec'd signal %s, closing",
      bund->name, sys_signame[sig]));
    RecordLinkUpDownReason(NULL, 0, STR_MANUALLY, NULL);
    IpcpClose();
  } else
    Log(LG_ALWAYS, ("mpd: rec'd signal %s, ignored", sys_signame[sig]));

}

/*
 * EventWarnx()
 *
 * Callback used by Event...() routines to report problems.
 */

static void
EventWarnx(const char *fmt, ...)
{
  va_list	args;
  char		buf[100];

  va_start(args, fmt);
  vsnprintf(buf, sizeof(buf), fmt, args);
  Log(LG_ALWAYS, ("[%s] EVENT: %s", lnk->name, buf));
#if 0
{
  EventSetLog(1, warnx);
  EventDump("event list");
  abort();
}
#endif
  va_end(args);
}

/*
 * OptParse()
 */

static void
OptParse(int ac, char *av[])
{
  int	used, consumed;

  /* Get option flags */
  for ( ; ac > 0 && **av == '-'; ac--, av++) {
    if (*++(*av) == '-') {	/* Long form */
      if (*++(*av) == 0) {	/* "--" forces end of options */
	ac--; av++;
	break;
      } else {
	used = OptApply(OptDecode(*av, TRUE), ac - 1, av + 1);
	ac -= used; av += used;
      }
    } else {			/* Short form */
      for (used = 0; **av; (*av)++, used += consumed) {
	consumed = OptApply(OptDecode(*av, FALSE), ac - 1, av + 1);
	if (used && consumed)
	  Usage(EX_USAGE);
      }
      ac -= used; av += used;
    }
  }

  /* Get system names */
  switch (ac) {
    case 0:
      break;
    case 1:
      gPeerSystem = *av;
      break;
    default:
      Usage(EX_USAGE);
  }
}

/*
 * OptApply()
 */

static int
OptApply(Option opt, int ac, char *av[])
{
  memset(gSysLogIdent, 0, sizeof(gSysLogIdent));

  if (opt == NULL)
    Usage(EX_USAGE);
  if (ac < opt->n_args)
    Usage(EX_USAGE);
  switch (opt->sflag) {
    case 'a':
      if (!inet_aton(*av, &gConsoleBindAddr)) {
	fprintf(stderr, "invalid IP address %s\n", *av);
	Usage(EX_USAGE);
      }
      gConsoleListen = TRUE;
      return(1);
    case 'b':
      gBackground = TRUE;
      return(0);
    case 'c':
      gConsoleBindPort = atoi(*av);
      gConsoleListen = TRUE;
      return(1);
    case 'd':
      gConfDirectory = *av;
      return(1);
    case 'f':
      gConfigFile = *av;
      return(1);
    case 'p':
      gPidFile = *av;
      return(1);
    case 'k':
      gKillProc = TRUE;
      return(0);
#ifdef SYSLOG_FACILITY
    case 's':
      snprintf(gSysLogIdent, sizeof(gSysLogIdent), "%s", *av);
      return(1);
#endif
    case 'v':
      fprintf(stderr, "Version %s\n", gVersion);
      exit(EX_NORMAL);
    case 'h':
      Usage(EX_NORMAL);
    case 't':
      gEnableTee = TRUE;
      return(0);
    default:
      assert(0);
  }
  return(0);
}

/*
 * OptDecode()
 */

static Option
OptDecode(char *arg, int longform)
{
  Option	opt;
  int		k;

  for (k = 0; k < OPTLIST_SIZE; k++) {
    opt = OptList + k;
    if (longform ?
	!strcmp(arg, opt->lflag) : (*arg == opt->sflag))
      return(opt);
  }
  return(NULL);
}

/*
 * Usage()
 */

static void
Usage(int ex)
{
  Option	opt;
  char		buf[100];
  int		k;

  fprintf(stderr, "Usage: mpd %s\n", UsageStr);
  fprintf(stderr, "Options:\n");
  for (k = 0; k < OPTLIST_SIZE; k++) {
    opt = OptList + k;
    snprintf(buf, sizeof(buf), "  -%c, --%-s %s",
      opt->sflag, opt->lflag, opt->usage);
    fprintf(stderr, "%-40s%s\n", buf, opt->desc);
  }
  exit(ex);
}

