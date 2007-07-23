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
#include "web.h"
#include "ngfunc.h"
#include "util.h"

#include <netgraph.h>

/*
 * DEFINITIONS
 */

  /* Implied system name when none specified on the command line */
  #define DEFAULT_CONF	"default"
  #define STARTUP_CONF	"startup"

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
    { 0, 'b',	"background",	"",
				"Run as a background daemon"	},
    { 1, 'd',	"directory",	"config-dir",
				"Set config file directory"	},
    { 0, 'k',	"kill",		"",
				"Kill running mpd process before start"	},
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
  };

  #define OPTLIST_SIZE		(sizeof(OptList) / sizeof(*OptList))

  /* How long to wait for graceful shutdown when we recieve a SIGTERM */
  #define TERMINATE_DEATH_WAIT	(2 * SECONDS)

/*
 * GLOBAL VARIABLES
 */

  PhysInfo		*gPhyses;
  Rep			*gReps;
  Bund			*gBundles;
  int			gNumPhyses;
  int			gNumReps;
  int			gNumBundles;
  struct console	gConsole;
  struct web		gWeb;
  int			gBackground = FALSE;
  int			gShutdownInProgress = FALSE;
  int			gOverload = 0;
  pid_t          	gPid;
  int			gRouteSeq = 0;

  struct globalconf	gGlobalConf;

  pthread_mutex_t	gGiantMutex;

  const char		*gConfigFile = CONF_FILE;
  const char		*gConfDirectory = PATH_CONF_DIR;

  const char		*gVersion = MPD_VERSION;

/*
 * INTERNAL FUNCTIONS
 */

  static void		Usage(int ex);
  static void		OptParse(int ac, char *av[]);
  static int		OptApply(Option opt, int ac, char *av[]);
  static Option		OptDecode(char *arg, int longform);
  static void		EventWarnx(const char *fmt, ...);

  static void		ConfigRead(int type, void *arg);
  static void		OpenCloseSignal(int sig);
  static void		FatalSignal(int sig);
  static void		SignalHandler(int type, void *arg);
  static void		CloseIfaces(void);


/*
 * INTERNAL VARIABLES
 */

  static int		gKillProc = FALSE;
  static const char	*gPidFile = PID_FILE;
  static const char	*gPeerSystem = NULL;
  static EventRef	gSignalEvent;
  static EventRef	gConfigReadEvent;
  static int		gSignalPipe[2];

/*
 * main()
 */

int
main(int ac, char *av[])
{
  int			ret;
  char			*args[MAX_ARGS];

  gPid=getpid();

  /* enable libpdel typed_mem */
  typed_mem_enable();

  /* init console-stuff */
  ConsoleInit(&gConsole);

  /* init web-stuff */
  WebInit(&gWeb);

  /* Set up libnetgraph logging */
  NgSetErrLog(NgFuncErr, NgFuncErrx);

  /* init global-config */
  memset(&gGlobalConf, 0, sizeof(gGlobalConf));
  Disable(&gGlobalConf.options, GLOBAL_CONF_TCPWRAPPER);

  /* Read and parse command line */
  if (ac > MAX_ARGS)
    ac = MAX_ARGS;
  memcpy(args, av, ac * sizeof(*av));	/* Copy to preserve "ps" output */
  OptParse(ac - 1, args + 1);

  /* Background mode? */
  if (gBackground) {
    if (daemon(TRUE, FALSE) < 0)
      err(1, "daemon");
    gPid=getpid();
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

  /* Create signaling pipe */
  if ((ret = pipe(gSignalPipe)) != 0) {
    Log(LG_ERR, ("Could not create signal pipe %d", ret));
    exit(EX_UNAVAILABLE);
  }
  if (EventRegister(&gSignalEvent, EVENT_READ, gSignalPipe[0], 
      EVENT_RECURRING, SignalHandler, NULL) != 0)
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

  EventRegister(&gConfigReadEvent, EVENT_TIMEOUT,
    0, 0, ConfigRead, NULL);

  pthread_exit(NULL);

  assert(0);
  return(1);	/* Never reached, but needed to silence compiler warning */
}

/*
 * Greetings()
 */

void
Greetings(void)
{
  LogStdout("Multi-link PPP daemon for FreeBSD");
  Log(LG_ALWAYS, ("process %lu started, version %s", (u_long) gPid, gVersion));
  LogStdout(" ");
  LogStdout("process %lu started, version %s", (u_long) gPid, gVersion);
}

/*
 * ConfigRead()
 *
 * handler of initial configuration reading event
 */
static void
ConfigRead(int type, void *arg)
{
    struct context	ctx;
    Context		c;

    ctx.lnk = NULL;
    ctx.bund = NULL;
    ctx.phys = NULL;
    ctx.rep = NULL;
    ctx.cs = NULL;

    if (gBackground) {
        c = &ctx;
    } else {
        c = StdConsoleConnect(&gConsole);
	if (c == NULL)
    	    c = &ctx;
    }

    /* Read startup configuration section */
    ReadFile(gConfigFile, STARTUP_CONF, DoCommand, c);

    /* Read configuration as specified on the command line, or default */
    if (!gPeerSystem)
	ReadFile(gConfigFile, DEFAULT_CONF, DoCommand, c);
    else {
	if (ReadFile(gConfigFile, gPeerSystem, DoCommand, c) < 0) {
	    Log(LG_ERR, ("can't read configuration for \"%s\"", gPeerSystem));
	    DoExit(EX_CONFIG);
	}
    }
}

/*
 * CloseIfaces()
 */

static void
CloseIfaces(void)
{
    Bund	b;
    int		k;

  /* Shut down all interfaces we grabbed */
  for (k = 0; k < gNumBundles; k++) {
    if ((b = gBundles[k]) != NULL) {
      BundNcpsClose(b);
      IfaceClose(b);
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
    Bund	b;
    Rep		r;
  int	k;

  gShutdownInProgress=1;
  /* Weak attempt to record what happened */
  if (code == EX_ERRDEAD)
    Log(LG_ERR, ("fatal error, exiting"));

  /* Shutdown stuff */
  if (code != EX_TERMINATE)	/* kludge to avoid double shutdown */
    CloseIfaces();

  /* Blow away all netgraph nodes */
  for (k = 0; k < gNumBundles; k++) {
    int global = 0;

    if ((b = gBundles[k]) != NULL) {
      if (global == 0) {
	/*
	 * XXX: We can't move NgFuncShutdownGlobal() out of cycle,
	 * because we need active netgraph socket to perform shutdown.
	 */
        NgFuncShutdownGlobal(b);
	global = 1;
      }
      BundShutdown(b);
    }
  }

  for (k = 0; k < gNumReps; k++) {
    if ((r = gReps[k]) != NULL) {
      RepShutdown(r);
    }
  }

  /* Remove our PID file and exit */
  Log(LG_ALWAYS, ("process %d terminated", gPid));
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

void
SendSignal(int sig)
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
    case SIGUSR2:
      OpenCloseSignal(sig);
      break;

    default:
      FatalSignal(sig);
  }

}

/*
 * FatalSignal()
 *
 * Gracefully exit on receipt of a fatal signal
 */

static void
FatalSignal(sig)
{
    Bund 	b;
  static struct pppTimer	gDeathTimer;
  int				k;
  int				upLinkCount;

  /* If a SIGTERM or SIGINT, gracefully shutdown; otherwise shutdown now */
  Log(LG_ERR, ("caught fatal signal %s", sys_signame[sig]));
  gShutdownInProgress=1;
  for (k = 0; k < gNumBundles; k++) {
    if ((b = gBundles[k])) {
      if (sig != SIGTERM && sig != SIGINT)
        RecordLinkUpDownReason(b, NULL, 0, STR_FATAL_SHUTDOWN, NULL);
      else
        RecordLinkUpDownReason(b, NULL, 0, STR_ADMIN_SHUTDOWN, NULL);
    }
  }
  upLinkCount = 0;
  for (k = 0; k < gNumPhyses; k++) {
    if (gPhyses[k] && (gPhyses[k]->state!=PHYS_STATE_DOWN))
	upLinkCount++;
  }

  /* We are going down. No more signals. */
  signal(SIGINT, SIG_IGN);
  signal(SIGTERM, SIG_IGN);
  signal(SIGUSR1, SIG_IGN);
  signal(SIGUSR2, SIG_IGN);

  if (sig != SIGTERM && sig != SIGINT)
    DoExit(EX_ERRDEAD);

  CloseIfaces();
  TimerInit(&gDeathTimer, "DeathTimer",
    TERMINATE_DEATH_WAIT * (upLinkCount/100+1), (void (*)(void *)) DoExit, (void *) EX_TERMINATE);
  TimerStart(&gDeathTimer);
}

/*
 * OpenCloseSignal()
 */

static void
OpenCloseSignal(int sig)
{
    int		k;
    Link	l;

    for (k = 0;
	k < gNumPhyses && (gPhyses[k] == NULL || gPhyses[k]->link == NULL);
	k++);
    if (k == gNumPhyses) {
	Log(LG_ALWAYS, ("rec'd signal %s, no link defined, ignored", sys_signame[sig]));
	return;
    }

    l = gPhyses[k]->link;

    /* Open/Close Link */
    if (l && l->phys && l->phys->type) {
	if (sig == SIGUSR1) {
	    Log(LG_ALWAYS, ("[%s] rec'd signal %s, opening",
    		l->name, sys_signame[sig]));
	    RecordLinkUpDownReason(NULL, l, 1, STR_MANUALLY, NULL);
	    LinkOpen(l);
	} else {
	    Log(LG_ALWAYS, ("[%s] rec'd signal %s, closing",
    		l->name, sys_signame[sig]));
	    RecordLinkUpDownReason(NULL, l, 0, STR_MANUALLY, NULL);
	    LinkClose(l);
	}
    } else
	Log(LG_ALWAYS, ("rec'd signal %s, ignored", sys_signame[sig]));
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
  Log(LG_ALWAYS, ("EVENT: %s", buf));
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
    case 'b':
      gBackground = TRUE;
      return(0);
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
