
/*
 * log.c
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
#ifdef SYSLOG_FACILITY
#include <syslog.h>
#endif

#include <pdel/sys/alog.h>

/*
 * DEFINITIONS
 */

  #define DUMP_BYTES_PER_LINE	16
  #define ROUNDUP(x,r)		(((x)%(r))?((x)+((r)-((x)%(r)))):(x))
  #define MAX_LOG_LINE		500

/* Log option descriptor */

  struct logopt
  {
    int		mask;
    const char	*name;
    const char	*desc;
  };

/*
 * GLOBAL VARIABLES
 */

  struct alog_config	gLogConf;

  int	gLogOptions = LG_DEFAULT_OPT | LG_ALWAYS;
#ifdef SYSLOG_FACILITY
  char	gSysLogIdent[32];
#endif

/*
 * INTERNAL VARIABLES
 */

#ifndef SYSLOG_FACILITY
  static FILE		*logfp = stderr;
#endif

  #define ADD_OPT(x,d)	{ LG_ ##x, #x, d },

  static struct logopt	LogOptionList[] =
  {
#ifdef LG_BUND
    ADD_OPT(BUND,	"Bundle events")
#endif
#ifdef LG_LINK
    ADD_OPT(LINK,	"Link events")
#endif
#ifdef LG_LCP
    ADD_OPT(LCP,	"LCP events and negotiation")
#endif
#ifdef LG_AUTH
    ADD_OPT(AUTH,	"Link authentication events")
#endif
#ifdef LG_IPCP
    ADD_OPT(IPCP,	"IPCP events and negotiation")
#endif
#ifdef LG_CCP
    ADD_OPT(CCP,	"CCP events and negotiation")
#endif
#ifdef LG_CCP2
    ADD_OPT(CCP2,	"CCP additional debugging output")
#endif
#ifdef LG_CCP3
    ADD_OPT(CCP3,	"CCP complete packet dumps")
#endif
#ifdef LG_ECP
    ADD_OPT(ECP,	"ECP events and negotiation")
#endif
#ifdef LG_ECP2
    ADD_OPT(ECP2,	"ECP extra debugging output")
#endif
#ifdef LG_FSM
    ADD_OPT(FSM,	"All FSM events (except echo & reset)")
#endif
#ifdef LG_ECHO
    ADD_OPT(ECHO,	"Echo/reply events for all automata")
#endif
#ifdef LG_PHYS
    ADD_OPT(PHYS,	"Physical layer events")
#endif
#ifdef LG_CHAT
    ADD_OPT(CHAT,	"Modem chat script")
#endif
#ifdef LG_CHAT2
    ADD_OPT(CHAT2,	"Chat script extra debugging output")
#endif
#ifdef LG_IFACE
    ADD_OPT(IFACE,	"IP interface and route management")
#endif
#ifdef LG_FRAME
    ADD_OPT(FRAME,	"Dump all incoming & outgoing frames")
#endif
#ifdef LG_PPTP
    ADD_OPT(PPTP,	"PPTP high level events")
#endif
#ifdef LG_PPTP2
    ADD_OPT(PPTP2,	"PPTP more detailed events")
#endif
#ifdef LG_PPTP3
    ADD_OPT(PPTP3,	"PPTP packet dumps")
#endif
#ifdef LG_RADIUS
    ADD_OPT(RADIUS,	"Radius authentication events")
#endif
#ifdef LG_CONSOLE
    ADD_OPT(CONSOLE,	"Log to the console as well as the log file")
#endif
  };

  #define NUM_LOG_LEVELS (sizeof(LogOptionList) / sizeof(*LogOptionList))

/*
 * INTERNAL FUNCTIONS
 */

  static int	logprintf(const char *fmt, ...);
  static int	vlogprintf(const char *fmt, va_list ap);

  static void	LogDoDumpBuf(int (*func)(const char *fmt, ...),
  		  int (*vfunc)(const char *fmt, va_list ap),
		  int timestamp, const u_char *buf, int count,
		  const char *fmt, va_list ap);
  static void	LogDoDumpBp(int (*func)(const char *fmt, ...),
  		  int (*vfunc)(const char *fmt, va_list ap),
		  int timestamp, Mbuf bp, const char *fmt, va_list ap);

#ifndef SYSLOG_FACILITY
  static void	LogTimeStamp(int (*func)(const char *fmt, ...));
#else
  #define LogTimeStamp(c)	do{}while(0)
#endif

/*
 * LogOpen()
 */

int
LogOpen(void)
{
  memset(&gLogConf, 0, sizeof(gLogConf));
  if (!*gSysLogIdent)
    strcpy(gSysLogIdent, "mpd");
#ifdef SYSLOG_FACILITY
  gLogConf.name = gSysLogIdent;
  gLogConf.facility = alog_facility_name(SYSLOG_FACILITY);
  gLogConf.min_severity = LOG_INFO;
#else
  gLogConf.path = LG_FILE;
#endif

  if (alog_configure(0, &gLogConf) == -1) {
    warn("mpd: alog_configure failed");
    return(-1);
  }
  alog_set_channel(0);
  return(0);
}

/*
 * LogClose()
 */

void
LogClose(void)
{
  alog_shutdown(0);
}

/*
 * LogCommand()
 */

int
LogCommand(int ac, char *av[], void *arg)
{
  int	k, bits, add;

  if (ac == 0)
  {
    #define LG_FMT	"    %-12s  %-10s  %s\n"

    printf(LG_FMT, "Log Option", "Enabled", "Description");
    printf(LG_FMT, "----------", "-------", "-----------");
    for (k = 0; k < NUM_LOG_LEVELS; k++)
    {
      int	j;
      char	buf[100];

      snprintf(buf, sizeof(buf), "%s", LogOptionList[k].desc);
      for (j = 0; buf[j]; j++)
	buf[j] = tolower(buf[j]);
      printf("  " LG_FMT, LogOptionList[k].name,
	(gLogOptions & LogOptionList[k].mask) ? "Yes" : "No", buf);
    }
    return(0);
  }

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
    for (k = 0;
      k < NUM_LOG_LEVELS && strcasecmp(*av, LogOptionList[k].name);
      k++);
    if (k < NUM_LOG_LEVELS)
      bits = LogOptionList[k].mask;
    else
    {
      if (!strcasecmp(*av, "all"))
      {
	for (bits = k = 0; k < NUM_LOG_LEVELS; k++)
	  bits |= LogOptionList[k].mask;
	bits &= ~LG_CONSOLE;
      }
      else
      {
	printf("\"%s\" is unknown. Enter \"log\" for list.\n", *av);
	bits = 0;
      }
    }
    if (add)
      gLogOptions |= bits;
    else
      gLogOptions &= ~bits;
    av++;
  }
  return(0);
}

/*
 * LogPrintf()
 *
 * The way to print something to the log
 */

void
LogPrintf(const char *fmt, ...)
{
  va_list	args;

  LogTimeStamp(logprintf);
  va_start(args, fmt);
  vlogprintf(fmt, args);
  va_end(args);

  if (gLogOptions & LG_CONSOLE)
  {
    va_start(args, fmt);
    vfprintf(stdout, fmt, args);
    va_end(args);
    putc('\n', stdout);
    fflush(stdout);
  }
}

/*
 * LogConsole()
 *
 * Print something to the console.
 */

void
LogConsole(const char *fmt, ...)
{
  va_list	args;

  va_start(args, fmt);
  vfprintf(stdout, fmt, args);
  putc('\n', stdout);
  fflush(stdout);
  va_end(args);
}

/*
 * LogDumpBp()
 *
 * Dump the contents of an Mbuf to the log
 */

void
LogDumpBp(int level, Mbuf bp, const char *fmt, ...)
{
  int		log, console;
  va_list	ap;

/* Where to we log it? */

  log = (level & gLogOptions) || (level & LG_ALWAYS);
  console = (log && (gLogOptions & LG_CONSOLE)) || (level & LG_CONSOLE);

/* Dump it */

  if (console) {
    va_start(ap, fmt);
    LogDoDumpBp(printf, vprintf, FALSE, bp, fmt, ap);
    va_end(ap);
  }
  if (log) {
    va_start(ap, fmt);
    LogDoDumpBp(logprintf, vlogprintf, TRUE, bp, fmt, ap);
    va_end(ap);
  }
}

/*
 * LogDumpBuf()
 *
 * Dump the contents of a buffer to the log
 */

void
LogDumpBuf(int level, const u_char *buf, int count, const char *fmt, ...)
{
  int		log, console;
  va_list	ap;

/* Where to we log it? */

  log = (level & gLogOptions) || (level & LG_ALWAYS);
  console = (log && (gLogOptions & LG_CONSOLE)) || (level & LG_CONSOLE);

/* Dump it */

  if (console) {
    va_start(ap, fmt);
    LogDoDumpBuf(printf, vprintf, FALSE, buf, count, fmt, ap);
    va_end(ap);
  }
  if (log) {
    va_start(ap, fmt);
    LogDoDumpBuf(logprintf, vlogprintf, TRUE, buf, count, fmt, ap);
    va_end(ap);
  }
}

/*
 * LogDoDumpBp()
 *
 * Dump the contents of an mbuf
 */

static void
LogDoDumpBp(int (*func)(const char *fmt, ...),
  int (*vfunc)(const char *fmt, va_list ap),
  int timestamp, Mbuf bp, const char *fmt, va_list ap)
{
  int		k, total;
  u_char	bytes[DUMP_BYTES_PER_LINE];

/* Do header */

  if (timestamp)
    LogTimeStamp(func);
  (*vfunc)(fmt, ap);
  (*func)(":\n");

/* Do data */

  for (total = 0; bp; bp = bp->next)
  {
    int	start, stop, last = 0;

    stop = bp->next ? total + bp->cnt :
		ROUNDUP(total + bp->cnt, DUMP_BYTES_PER_LINE);
    for (start = total; total < stop; )
    {
      u_int	const byte = (MBDATA(bp))[total - start];

      if (total % DUMP_BYTES_PER_LINE == 0 && timestamp)
	LogTimeStamp(func);
      if (total < start + bp->cnt)
      {
	(*func)(" %02x", byte);
	last = total % DUMP_BYTES_PER_LINE;
      }
      else
	(*func)("   ");
      bytes[total % DUMP_BYTES_PER_LINE] = byte;
      total++;
      if (total % DUMP_BYTES_PER_LINE == 0)
      {
	(*func)("  ");
	for (k = 0; k <= last; k++)
	  (*func)("%c", isgraph(bytes[k]) ? bytes[k] : '.');
	(*func)("\n");
      }
    }
  }
}

/*
 * LogDoDumpBuf()
 *
 * Dump the contents of a buffer to the log
 */

static void
LogDoDumpBuf(int (*func)(const char *fmt, ...),
  int (*vfunc)(const char *fmt, va_list ap),
  int timestamp, const u_char *buf, int count, const char *fmt, va_list ap)
{
  int	k, stop, total;

/* Do header */

  if (timestamp)
    LogTimeStamp(func);
  (*vfunc)(fmt, ap);
  (*func)(":\n");

/* Do data */

  stop = ROUNDUP(count, DUMP_BYTES_PER_LINE);
  for (total = 0; total < stop; )
  {
    if (total % DUMP_BYTES_PER_LINE == 0 && timestamp)
      LogTimeStamp(func);
    if (total < count)
      (*func)(" %02x", buf[total]);
    else
      (*func)("   ");
    total++;
    if (total % DUMP_BYTES_PER_LINE == 0)
    {
      (*func)("  ");
      for (k = total - DUMP_BYTES_PER_LINE; k < total && k < count; k++)
	(*func)("%c", isgraph(buf[k]) ? buf[k] : '.');
      (*func)("\n");
    }
  }
}

#ifndef SYSLOG_FACILITY

/*
 * LogTimeStamp()
 *
 * Print a timestamp
 */

static void
LogTimeStamp(int (*func)(const char *fmt, ...))
{
  struct tm	*ptm;
  time_t	now;

  now = time(NULL);
  ptm = localtime(&now);
  (*func)("%02d-%02d %02d:%02d:%02d ",
    ptm->tm_mon + 1, ptm->tm_mday,
    ptm->tm_hour, ptm->tm_min, ptm->tm_sec);
}

#endif

/*
 * Perror()
 */

void
Perror(const char *fmt, ...)
{
  va_list	args;
  char		buf[200];

  snprintf(buf, sizeof(buf), "mpd: ");
  va_start(args, fmt);
  vsnprintf(buf + strlen(buf), sizeof(buf) - strlen(buf), fmt, args);
  va_end(args);
  snprintf(buf + strlen(buf), sizeof(buf) - strlen(buf),
    ": %s", strerror(errno));
  Log(LG_ERR, ("%s", buf));
}

/*
 * logprintf()
 */

static int
logprintf(const char *fmt, ...)
{
  va_list	args;

  va_start(args, fmt);
  valog(LOG_INFO, fmt, args);
  va_end(args);
  return(0);
}

/*
 * vlogprintf()
 */

static int
vlogprintf(const char *fmt, va_list ap)
{
  valog(LOG_INFO, fmt, ap);
  return(0);
}
