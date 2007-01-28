
/*
 * console.c
 *
 * Written by Archie Cobbs <archie@freebsd.org>
 * Copyright (c) 1995-1999 Whistle Communications, Inc. All rights reserved.
 * See ``COPYRIGHT.whistle''
 */

#include "ppp.h"
#include "console.h"
#include "util.h"

/*
 * DEFINITIONS
 */

  #ifndef CTRL
  #define CTRL(c) (c - '@')
  #endif

  #define EchoOff()	cs->write(cs, "\xFF\xFB\x01\xFF\xFD\x01");
  #define EchoOn()	cs->write(cs, "\xFF\xFC\x01\xFF\xFE\x01");
						  

  enum {
    STATE_USERNAME = 0,
    STATE_PASSWORD,
    STATE_AUTHENTIC
  };

  /* Set menu options */
  enum {
    SET_OPEN,
    SET_CLOSE,
    SET_USER,
    SET_PORT,
    SET_IP,
    SET_DISABLE,
    SET_ENABLE,
  };


/*
 * INTERNAL FUNCTIONS
 */

  static void	ConsoleConnect(int type, void *cookie);
  static void	ConsoleSessionClose(ConsoleSession cs);
  static void	ConsoleSessionReadEvent(int type, void *cookie);
  static void	ConsoleSessionWriteEvent(int type, void *cookie);
  static void	ConsoleSessionWrite(ConsoleSession cs, const char *fmt, ...);
  static void	ConsoleSessionWriteV(ConsoleSession cs, const char *fmt, va_list vl);
  static void	ConsoleSessionShowPrompt(ConsoleSession cs);

  static int		ConsoleUserHashEqual(struct ghash *g, const void *item1, 
		  		const void *item2);
  static u_int32_t	ConsoleUserHash(struct ghash *g, const void *item);
  static int	ConsoleSetCommand(int ac, char *av[], void *arg);


/*
 * GLOBAL VARIABLES
 */

  const struct cmdtab ConsoleSetCmds[] = {
    { "open",		"Open the console" ,
  	ConsoleSetCommand, NULL, (void *) SET_OPEN },
    { "close",		"Close the console" ,
  	ConsoleSetCommand, NULL, (void *) SET_CLOSE },
    { "user <name> <password>", "Add a console user" ,
      	ConsoleSetCommand, NULL, (void *) SET_USER },
    { "port <port>",		"Set port" ,
  	ConsoleSetCommand, NULL, (void *) SET_PORT },
    { "ip <ip>",		"Set IP address" ,
  	ConsoleSetCommand, NULL, (void *) SET_IP },
    { "enable [opt ...]",	"Enable this console option" ,
  	ConsoleSetCommand, NULL, (void *) SET_ENABLE },
    { "disable [opt ...]",	"Disable this console option" ,
  	ConsoleSetCommand, NULL, (void *) SET_DISABLE },
    { NULL },
  };


/*
 * INTERNAL VARIABLES
 */

  static const struct confinfo	gConfList[] = {
    { 0,	CONSOLE_LOGGING,	"logging"	},
    { 0,	0,			NULL		},
  };


/*
 * ConsoleInit()
 */

int
ConsoleInit(Console c)
{
  /* setup console-defaults */
  memset(&gConsole, 0, sizeof(gConsole));
  ParseAddr(DEFAULT_CONSOLE_IP, &c->addr, ALLOW_IPV4|ALLOW_IPV6);
  c->port = DEFAULT_CONSOLE_PORT;

  c->sessions = ghash_create(c, 0, 0, MB_CONS, NULL, NULL, NULL, NULL);
  c->users = ghash_create(c, 0, 0, MB_CONS, ConsoleUserHash, ConsoleUserHashEqual, NULL, NULL);

  return 0;
}

/*
 * ConsoleOpen()
 */

int
ConsoleOpen(Console c)
{
  char		addrstr[INET6_ADDRSTRLEN];

  if (c->fd) {
    Log(LG_ERR, ("CONSOLE: Console already running"));
    return -1;
  }
  
  u_addrtoa(&c->addr, addrstr, sizeof(addrstr));
  if ((c->fd = TcpGetListenPort(&c->addr, c->port, FALSE)) < 0) {
    Log(LG_ERR, ("CONSOLE: Can't listen for connections on %s %d", 
	addrstr, c->port));
    return -1;
  }

  if (EventRegister(&c->event, EVENT_READ, c->fd, 
	EVENT_RECURRING, ConsoleConnect, c) < 0)
    return -1;

  Log(LG_CONSOLE, ("CONSOLE: listening on %s %d", 
	addrstr, c->port));
  return 0;
}

/*
 * ConsoleClose()
 */

int
ConsoleClose(Console c)
{
  if (!c->fd)
    return 0;
  EventUnRegister(&c->event);
  close(c->fd);
  c->fd = 0;
  return 0;
}

/*
 * ConsoleStat()
 */

int
ConsoleStat(int ac, char *av[], void *arg)
{
  Console		c = &gConsole;
  ConsoleUser		u;
  ConsoleSession	s;
  ConsoleSession	cs = gConsoleSession;
  struct ghash_walk	walk;
  char       		addrstr[INET6_ADDRSTRLEN];

  Printf("Configuration:\r\n");
  Printf("\tState         : %s\r\n", c->fd ? "OPENED" : "CLOSED");
  Printf("\tIP-Address    : %s\r\n", u_addrtoa(&c->addr,addrstr,sizeof(addrstr)));
  Printf("\tPort          : %d\r\n", c->port);

  Printf("Configured users:\r\n");
  ghash_walk_init(c->users, &walk);
  while ((u = ghash_walk_next(c->users, &walk)) !=  NULL)
    Printf("\tUsername: %s\r\n", u->username);

  Printf("Active sessions:\r\n");
  ghash_walk_init(c->sessions, &walk);
  while ((s = ghash_walk_next(c->sessions, &walk)) !=  NULL) {
    Printf("\tUsername: %s\tFrom: %s\r\n",
	s->user.username, u_addrtoa(&s->peer_addr,addrstr,sizeof(addrstr)));
  }

  if (cs) {
    Printf("This session options:\r\n");
    OptStat(&cs->options, gConfList);
  }
  return 0;
}

/*
 * ConsoleConnect()
 */

static void
ConsoleConnect(int type, void *cookie)
{
  Console		c = cookie;
  ConsoleSession	cs;
  const char		*options = 
	  "\xFF\xFB\x03"	/* WILL Suppress Go-Ahead */
	  "\xFF\xFD\x03"	/* DO Suppress Go-Ahead */
	  "\xFF\xFB\x01"	/* WILL echo */
	  "\xFF\xFD\x01";	/* DO echo */
  char                  addrstr[INET6_ADDRSTRLEN];
  struct sockaddr_storage ss;
  
  Log(LG_CONSOLE, ("CONSOLE: Connect"));
  cs = Malloc(MB_CONS, sizeof(*cs));
  memset(cs, 0, sizeof(*cs));
  if ((cs->fd = TcpAcceptConnection(c->fd, &ss, FALSE)) < 0) 
    goto cleanup;
  sockaddrtou_addr(&ss, &cs->peer_addr, &cs->peer_port);

  if (EventRegister(&cs->readEvent, EVENT_READ, cs->fd, 
	EVENT_RECURRING, ConsoleSessionReadEvent, cs) < 0)
    goto fail;

  cs->console = c;
  cs->bund = bund;
  cs->link = lnk;
  cs->close = ConsoleSessionClose;
  cs->write = ConsoleSessionWrite;
  cs->writev = ConsoleSessionWriteV;
  cs->prompt = ConsoleSessionShowPrompt;
  cs->state = STATE_USERNAME;
  ghash_put(c->sessions, cs);
  Log(LG_CONSOLE, ("CONSOLE: Allocated new console session %p from %s", 
    cs, u_addrtoa(&cs->peer_addr,addrstr,sizeof(addrstr))));
  cs->write(cs, "Multi-link PPP daemon for FreeBSD\r\n\r\n");
  cs->write(cs, options);
  cs->prompt(cs);
  return;

fail:
  close(cs->fd);

cleanup:
  Freee(MB_CONS, cs);
  return;

}


/*
 * ConsoleSessionClose()
 */

static void
ConsoleSessionClose(ConsoleSession cs)
{
  EventUnRegister(&cs->readEvent);
  EventUnRegister(&cs->writeEvent);
  ghash_remove(cs->console->sessions, cs);
  close(cs->fd);
  if (cs->user.username)
    FREE(MB_CONS, cs->user.username);
  Freee(MB_CONS, cs);
  return;
}


/*
 * ConsoleSessionReadEvent()
 */

static void
ConsoleSessionReadEvent(int type, void *cookie)
{
  ConsoleSession	cs = cookie;
  CmdTab		cmd, tab;
  int			n, ac, ac2, exitflag, i;
  u_char		c;
  char			compl[MAX_CONSOLE_LINE], line[MAX_CONSOLE_LINE];
  char			*av[MAX_CONSOLE_ARGS], *av2[MAX_CONSOLE_ARGS];
  char			*av_copy[MAX_CONSOLE_ARGS];
  Bund			bund_orig;
  Link 			link_orig;
  char                  addrstr[INET6_ADDRSTRLEN];

  gConsoleSession = cs;
  bund_orig = bund;
  link_orig = lnk;
  bund = cs->bund;
  lnk = cs->link;
  while(1) {
    if ((n = read(cs->fd, &c, 1)) <= 0) {
      if (n < 0) {
	if (errno == EAGAIN)
	  goto out;
	Log(LG_ERR, ("CONSOLE: Error while reading: %s", strerror(errno)));
      } else {
	Log(LG_ERR, ("CONSOLE: Connection closed by peer"));
      }
      goto abort;
    }

    /* deal with escapes, map cursors */
    if (cs->escaped) {
      if (cs->escaped == '[') {
	switch(c) {
	  case 'A':	/* up */
	    c = CTRL('P');
	    break;
	  case 'B':	/* down */
	    c = CTRL('N');
	    break;
	  case 'C':	/* right */
	    c = CTRL('F');
	    break;
	  case 'D':	/* left */
	    c = CTRL('B');
	    break;
	  default:
	    c = 0;
	}
	cs->escaped = FALSE;
      } else {
	cs->escaped = c == '[' ? c : 0;
	continue;
      }
    }

    switch(c) {
    case 0:
    case '\n':
      break;
    case 27:	/* escape */
      cs->escaped = TRUE;
      break;
    case 255:	/* telnet option follows */
      cs->telnet = TRUE;
      break;
    case 253:	/* telnet option-code DO */
      break;
    case 9:	/* TAB */
      if (cs->state != STATE_AUTHENTIC)
        break;
      strcpy(line, cs->cmd);
      ac = ParseLine(line, av, sizeof(av) / sizeof(*av), 1);
      memset(compl, 0, sizeof(compl));
      tab = gCommands;
      for (i = 0; i < ac; i++) {

        if (FindCommand(tab, av[i], &cmd)) {
	    cs->write(cs, "\a");
	    goto notfound;
	}
	strcpy(line, cmd->name);
        ac2 = ParseLine(line, av2, sizeof(av2) / sizeof(*av2), 1);
	snprintf(&compl[strlen(compl)], sizeof(compl) - strlen(compl), "%s ", av2[0]);
	FreeArgs(ac2, av2);
	if (cmd->func != CMD_SUBMENU && 
	  (i != 0 || strncmp(av[0], "help", strlen(av[0])) !=0)) {
	    i++;
	    if (i < ac) {
		cs->write(cs, "\a");
		for (; i < ac; i++) {
		    strcat(compl, av[i]);
		    if ((i+1) < ac)
			strcat(compl, " ");
		}
	    }
	    break;
	} else if (cmd->func == CMD_SUBMENU) {
	    tab = cmd->arg;
	}
      }
      for (i = 0; i < cs->cmd_len; i++)
	cs->write(cs, "\b \b");
      strcpy(cs->cmd, compl);
      cs->cmd_len = strlen(cs->cmd);
      cs->write(cs, cs->cmd);
notfound:
      FreeArgs(ac, av);
      break;
    case CTRL('C'):
      if (cs->telnet)
	break;
      cs->write(cs, "\r\n");
      Log(LG_CONSOLE, ("CONSOLE: CTRL-C"));
      memset(cs->cmd, 0, MAX_CONSOLE_LINE);
      cs->cmd_len = 0;
      cs->prompt(cs);
      cs->telnet = FALSE;
      break;
    case CTRL('P'):	/* page up */
      if ((*cs->history) && 
        (strncmp(cs->cmd, cs->history, MAX_CONSOLE_LINE) != 0)) {
        if (cs->cmd_len>0) {
    	    cs->write(cs, "\r\n");
	    cs->prompt(cs);
	}
	memcpy(cs->cmd, cs->history, MAX_CONSOLE_LINE);
	cs->cmd_len = strlen(cs->cmd);
	cs->write(cs, cs->cmd);
      }
      break;
    case CTRL('N'):	/* page down */
        if (cs->cmd_len>0) {
	    if (strncmp(cs->cmd, cs->history, MAX_CONSOLE_LINE) != 0) {
		memcpy(cs->history, cs->cmd, MAX_CONSOLE_LINE);
    		cs->write(cs, "\r\n");
		cs->prompt(cs);
	    } else {
    		for (i = 0; i < cs->cmd_len; i++)
		    cs->write(cs, "\b \b");    
	    }
	}
	memset(cs->cmd, 0, MAX_CONSOLE_LINE);
	cs->cmd_len = 0;
        break;
    case CTRL('F'):
    case CTRL('B'):
      break;
    case CTRL('H'):
    case 127:	/* BS */
      if (cs->cmd_len > 0) {
	cs->cmd_len -= 1;
	cs->cmd[cs->cmd_len] = 0;
        if (cs->state != STATE_PASSWORD)
	    cs->write(cs, "\b \b");
      }
      break;
    case '\r':
    case '?':
    { 
      if (c == '?')
        cs->write(cs, "?");
      cs->write(cs, "\r\n");
      
      cs->telnet = FALSE;
      if (cs->state == STATE_USERNAME) {
	cs->user.username = typed_mem_strdup(MB_CONS, cs->cmd);
        memset(cs->cmd, 0, MAX_CONSOLE_LINE);
        cs->cmd_len = 0;
	cs->state = STATE_PASSWORD;
	cs->prompt(cs);
	break;
      } else if (cs->state == STATE_PASSWORD) {
	ConsoleUser u;

	u = ghash_get(cs->console->users, &cs->user);

	if (!u) 
	  goto failed;

	if (strcmp(u->password, cs->cmd)) 
	  goto failed;

	cs->state = STATE_AUTHENTIC;
	cs->write(cs, "\r\nWelcome!\r\nMpd pid %lu, version %s\r\n", 
		(u_long) gPid, gVersion);
	goto success;

failed:
	cs->write(cs, "Login failed\r\n");
	Log(LG_CONSOLE, ("CONSOLE: Failed login attempt from %s", 
		u_addrtoa(&cs->peer_addr,addrstr,sizeof(addrstr))));
	FREE(MB_CONS, cs->user.username);
	cs->user.username=NULL;
	cs->state = STATE_USERNAME;
success:
	memset(cs->cmd, 0, MAX_CONSOLE_LINE);
	cs->cmd_len = 0;
	cs->prompt(cs);
	break;
      }

      memcpy(line, cs->cmd, sizeof(line));
      ac = ParseLine(line, av, sizeof(av) / sizeof(*av), 1);
      memcpy(av_copy, av, sizeof(av));
      if (c != '?') {
        Log(LG_CONSOLE, ("[%s] CONSOLE: %s: %s", 
	    cs->link->name, cs->user.username, cs->cmd));
        exitflag = DoCommand(ac, av, NULL, 0);
      } else {
        HelpCommand(ac, av, NULL);
	exitflag = 0;
      }
      FreeArgs(ac, av_copy);
      if (exitflag)
	goto abort;
      cs->prompt(cs);
      if (c != '?') {
	memcpy(cs->history, cs->cmd, MAX_CONSOLE_LINE);
        memset(cs->cmd, 0, MAX_CONSOLE_LINE);
	cs->cmd_len = 0;
      } else {
	cs->write(cs, cs->cmd);
      }
      break;
    }
    /* "normal" char entered */
    default:
      if (cs->telnet) {
	if (c < 251)
	  cs->telnet = FALSE;
	break;
      }

      if (cs->state != STATE_PASSWORD)
 	cs->write(cs, "%c", c);

      /* XXX ToDo testing */
      if ((cs->cmd_len + 1) >= MAX_CONSOLE_LINE) {
        Log(LG_ERR, ("CONSOLE: console input line too long"));
        break;
      }
      cs->cmd[cs->cmd_len++] = c;
    }
  }

abort:
  cs->close(cs);
out:
  gConsoleSession = NULL;
  bund = bund_orig;
  lnk = link_orig;
  return;
}


/*
 * ConsoleWriteEvent()
 */

static void
ConsoleSessionWriteEvent(int type, void *cookie)
{
  ConsoleSession	cs = cookie;
  int			written;
  char			buf[MAX_CONSOLE_BUF_LEN];

  if ((written = write(cs->fd, cs->writebuf, cs->writebuf_len)) <= 0) {
//    if (written < 0 && errno != EAGAIN) {
//      Log(LG_ERR, ("CONSOLE: Error writing to console %s", strerror(errno)));
//    }
    return;
  }

  if (written == cs->writebuf_len) {
    cs->writebuf_len = 0;
  } else {
    cs->writebuf_len -= written;
    memcpy(buf, &cs->writebuf[written], cs->writebuf_len);
    memcpy(cs->writebuf, buf, cs->writebuf_len);
    EventRegister(&cs->writeEvent, EVENT_WRITE, cs->fd, 
	0, ConsoleSessionWriteEvent, cs);
  }
}

/*
 * ConsoleSessionWrite()
 */

static void 
ConsoleSessionWrite(ConsoleSession cs, const char *fmt, ...)
{
  va_list vl;

  va_start(vl, fmt);
  ConsoleSessionWriteV(cs, fmt, vl);
  va_end(vl);
}

/*
 * ConsoleSessionWriteV()
 */

static void 
ConsoleSessionWriteV(ConsoleSession cs, const char *fmt, va_list vl)
{
  cs->writebuf_len += vsnprintf(&cs->writebuf[cs->writebuf_len],
	MAX_CONSOLE_BUF_LEN - cs->writebuf_len - 1,
	fmt, vl);

  ConsoleSessionWriteEvent(EVENT_WRITE, cs);
}

/*
 * ConsoleShowPrompt()
 */

static void
ConsoleSessionShowPrompt(ConsoleSession cs)
{
  switch(cs->state) {
  case STATE_USERNAME:
    cs->write(cs, "Username: ");
    break;
  case STATE_PASSWORD:
    cs->write(cs, "Password: ");
    break;
  case STATE_AUTHENTIC:
    cs->write(cs, "[%s] ", cs->link->name);
    break;
  }
}


/*
 * ConsoleUserHash
 *
 * Fowler/Noll/Vo- hash
 * see http://www.isthe.com/chongo/tech/comp/fnv/index.html
 *
 * By:
 *  chongo <Landon Curt Noll> /\oo/\
 *  http://www.isthe.com/chongo/
 */

static u_int32_t
ConsoleUserHash(struct ghash *g, const void *item)
{
  ConsoleUser u = (ConsoleUser) item;
  u_char *s = (u_char *) u->username;
  u_int32_t hash = 0x811c9dc5;

  while (*s) {
    hash += (hash<<1) + (hash<<4) + (hash<<7) + (hash<<8) + (hash<<24);
    /* xor the bottom with the current octet */
    hash ^= (u_int32_t)*s++;
  }

  return hash;
}

/*
 * ConsoleUserHashEqual
 */

static int
ConsoleUserHashEqual(struct ghash *g, const void *item1, const void *item2)
{
  ConsoleUser u1 = (ConsoleUser) item1;
  ConsoleUser u2 = (ConsoleUser) item2;

  if (u1 && u2)
    return (strcmp(u1->username, u2->username) == 0);
  else
    return 0;
}

/*
 * ConsoleSetCommand()
 */

static int
ConsoleSetCommand(int ac, char *av[], void *arg) 
{
  Console	 	c = &gConsole;
  ConsoleSession	cs = gConsoleSession;
  ConsoleUser		u;
  int			port;

  switch ((intptr_t)arg) {

    case SET_OPEN:
      ConsoleOpen(c);
      break;

    case SET_CLOSE:
      ConsoleClose(c);
      break;

    case SET_ENABLE:
      if (cs)
	EnableCommand(ac, av, &cs->options, gConfList);
      break;

    case SET_DISABLE:
      if (cs)
	DisableCommand(ac, av, &cs->options, gConfList);
      break;

    case SET_USER:
      if (ac != 2) 
	return(-1);

      u = Malloc(MB_CONS, sizeof(*u));
      u->username = typed_mem_strdup(MB_CONS, av[0]);
      u->password = typed_mem_strdup(MB_CONS, av[1]);
      ghash_put(c->users, u);
      break;

    case SET_PORT:
      if (ac != 1)
	return(-1);

      port =  strtol(av[0], NULL, 10);
      if (port < 1 && port > 65535) {
	Log(LG_ERR, ("CONSOLE: Bogus port given %s", av[0]));
	return(-1);
      }
      c->port=port;
      break;

    case SET_IP:
      if (ac != 1)
	return(-1);

      if (!ParseAddr(av[0],&c->addr, ALLOW_IPV4|ALLOW_IPV6)) 
      {
	Log(LG_ERR, ("CONSOLE: Bogus IP address given %s", av[0]));
	return(-1);
      }
      break;

    default:
      return(-1);

  }

  return 0;
}
