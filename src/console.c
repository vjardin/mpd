
/*
 * console.c
 *
 * Written by Archie Cobbs <archie@freebsd.org>
 * Copyright (c) 1995-1999 Whistle Communications, Inc. All rights reserved.
 * See ``COPYRIGHT.whistle''
 */

#include "ppp.h"
#include "console.h"

/*
 * DEFINITIONS
 */

  #define MAX_CONSOLE_ARGS	50
  #define MAX_CONSOLE_LINE	400

/*
 * INTERNAL FUNCTIONS
 */

  static void	ConsoleListen(void);
  static void	ConsoleInput(int type, void *cookie);
  static void	ConsoleConnect(int type, void *cookie);
  static int	GetConsoleInput(void);

/*
 * GLOBAL VARIABLES
 */

  Link		gConsoleLink;
  Bund		gConsoleBund;

/*
 * INTERNAL VARIABLES
 */

  static int		gPrompt;

  static int		gListenFd;
  static int		gConsoleFd;
  static int		gConsoleAuth;

  static EventRef	gConsoleInputEvent;
  static EventRef	gConsoleConnectEvent;

/*
 * ConsoleInit()
 *
 * We assume that stdin and stdout are always open & valid, though
 * when there's no console connection they are directed at /dev/null.
 */

void
ConsoleInit(int cfd, int lfd)
{

/* Initialize globals */

  gConsoleLink = lnk;
  gConsoleBund = bund;
  gConsoleFd = cfd;
  gListenFd = lfd;
  gConsoleAuth = (gConsoleFd >= 0);
  gPrompt = TRUE;

/* Wait for activity */

  ConsoleListen();
}

/*
 * ConsoleListen()
 */

static void
ConsoleListen()
{
  if (gConsoleFd >= 0)
  {
    if (gPrompt)
    {
      if (!gConsoleAuth)
	printf("Password: ");
      else
	printf("[%s:%s] ",
	  gConsoleBund ? gConsoleBund->name : "",
	  gConsoleLink ? gConsoleLink->name : "");
      fflush(stdout);
      gPrompt = FALSE;
    }
    EventRegister(&gConsoleInputEvent, EVENT_READ, gConsoleFd,
      CONSOLE_PRIO, ConsoleInput, NULL);
  }
  else if (gListenFd >= 0)
    EventRegister(&gConsoleConnectEvent, EVENT_READ, gListenFd,
      CONSOLE_PRIO, ConsoleConnect, NULL);
}

/*
 * ConsoleInput()
 */

static void
ConsoleInput(int type, void *cookie)
{
  bund = gConsoleBund;
  lnk = gConsoleLink;
  gPrompt = GetConsoleInput();
  gConsoleBund = bund;
  gConsoleLink = lnk;
  ConsoleListen();
}

/*
 * ConsoleConnect()
 */

static void
ConsoleConnect(int type, void *cookie)
{
  struct sockaddr_in	addr;
  int fdi=-1, fdo=-1;

  assert(gConsoleFd < 0);
  if ((gConsoleFd = TcpAcceptConnection(gListenFd, &addr)) < 0)
  {
    Log(LG_ERR, ("mpd: can't accept console connection"));
    goto done;
  }

/* Say who we connected to */

  Log(LG_ALWAYS, ("mpd: console connection from %s, %d",
    inet_ntoa(addr.sin_addr), (int) ntohs(addr.sin_port)));

/* Make reads non-blocking */

  if (fcntl(gConsoleFd, F_SETFL, O_NONBLOCK) < 0)
  {
    (void) close(gConsoleFd);
    gConsoleFd = -1;
    Perror("fcntl");
    Log(LG_ERR, ("mpd: can't make console non-blocking"));
    goto done;
  }

/* Associate stdin and stdout with this new socket */

    if (stdin != NULL) {
	fclose(stdin);
	stdin = NULL;
    }
    fdi = dup(gConsoleFd);
    if ((stdin = fdopen(fdi, "r")) == NULL) {
	Perror("fdopen(%d)", fdi);
	Log(LG_ERR, ("mpd: can't fdopen() stdin"));
	(void) close(fdi);
	(void) close(gConsoleFd);
	gConsoleFd = -1;
	goto done;
    }
    
    if (stdout != NULL) {
	fclose(stdout);
	stdout = NULL;
    }
    fdo = dup(gConsoleFd);
    if ((stdout = fdopen(fdo, "w")) == NULL) {
	Perror("fdopen(%d)", gConsoleFd);
	Log(LG_ERR, ("mpd: can't fdopen() stdout"));
	(void) close(fdo);
	(void) close(gConsoleFd);
	gConsoleFd = -1;
	goto done;
    }

/* Login required? */

  gConsoleAuth = !*gLoginAuthName;
  if (gConsoleAuth)
    Greetings();
  gPrompt = TRUE;

done:
  ConsoleListen();
}

/*
 * GetConsoleInput()
 *
 * Read and interpret a console command
 */

static int
GetConsoleInput(void)
{
  int		gotWholeLine = FALSE;
  int		ac, exitflag = FALSE;
  char		*av[MAX_CONSOLE_ARGS];
  char		*av_copy[MAX_CONSOLE_ARGS];
  static char	line[MAX_CONSOLE_LINE];

/* Read console input (unless buffer is full) XXX bug: can't use fgets() */

  if (fgets(line + strlen(line), sizeof(line) - strlen(line), stdin))
  {
    if (strlen(line) >= sizeof(line) - 1)
    {
      Log(LG_ERR, ("mpd: console input line too long"));
      exitflag = TRUE;
    }
    else
      if (line[strlen(line) - 1] == '\n')
      {
	gotWholeLine = TRUE;
	if (!gConsoleAuth)
	{
	  struct authdata	auth;

	  while (line[strlen(line) - 1] == '\n'
	      || line[strlen(line) - 1] == '\r')
	    line[strlen(line) - 1] = 0;
	  memset(&auth, 0, sizeof(auth));
	  strlcpy(auth.authname, gLoginAuthName, sizeof(auth.authname));
	  if (AuthGetData(&auth, 1, NULL) < 0 || strcmp(line, auth.password))
	  {
	    printf("Login incorrect.\n");
	    exitflag = TRUE;
	  }
	  else
	  {
	    Greetings();
	    gConsoleAuth = TRUE;
	    exitflag = FALSE;
	    *line = 0;
	  }
	}
	else
	{
	  ac = ParseLine(line, av, sizeof(av) / sizeof(*av));
	  memcpy(av_copy, av, sizeof(av));
	  exitflag = DoCommand(ac, av);
	  FreeArgs(ac, av_copy);
	  *line = 0;
	}
      }
  }
  else
  {
    if (ferror(stdin))
      Log(LG_ERR, ("mpd: error reading console: %s", strerror(errno)));
    else
    {
      Log(LG_ERR, ("mpd: EOF on console"));
      assert(feof(stdin));
    }
    exitflag = TRUE;
  }

/* Exit the console? */

  if (exitflag)
  {
    Log(LG_ALWAYS, ("mpd: exiting console"));
    (void) close(gConsoleFd);
    gConsoleFd = -1;
    if (freopen("/dev/null", "r", stdin) == NULL)
      Log(LG_ERR, ("mpd: freopen: %s", strerror(errno)));
    if (freopen("/dev/null", "w", stdout) == NULL)
      Log(LG_ERR, ("mpd: freopen: %s", strerror(errno)));
    *line = 0;
  }

/* Return TRUE if we got a whole line */

  return(gotWholeLine);
}

