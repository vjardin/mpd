
/*
 * util.c
 *
 * Written by Archie Cobbs <archie@freebsd.org>
 * Copyright (c) 1995-1999 Whistle Communications, Inc. All rights reserved.
 * See ``COPYRIGHT.whistle''
 */

#include "ppp.h"
#include <termios.h>

/*
 * DEFINITIONS
 */

  #define MAX_FILENAME		50
  #define MAX_LINE_ARGS		50
  #define BIG_LINE_SIZE		1000
  #define MAX_OPEN_DELAY	2
  #define MAX_LOCK_ATTEMPTS	30

/*
 * INTERNAL VARIABLES
 */

  static const u_int16_t	Crc16Table[];
  static FILE			*lockFp = NULL;

/*
 * INTERNAL FUNCTIONS
 */

  static int		UuLock(const char *devname);
  static int		UuUnlock(const char *devname);

  static void		Escape(char *line);
  static char		*ReadLine(FILE *fp, int *lineNum);

/*
 * LengthenArray()
 */

void
LengthenArray(void *array, int esize, int *alenp, int type)
{
	void **const arrayp = (void **)array;
	void *newa;

	newa = Malloc(type, (*alenp + 1) * esize);
	if (*arrayp != NULL) {
		memcpy(newa, *arrayp, *alenp * esize);
		Freee(*arrayp);
	}
	*arrayp = newa;
	(*alenp)++;
}

/*
 * ExecCmd()
 */

int
ExecCmd(int log, const char *fmt, ...)
{
  int		rtn;
  char		cmd[BIG_LINE_SIZE];
  va_list	ap;

  va_start(ap, fmt);
  vsnprintf(cmd, sizeof(cmd), fmt, ap);

/* Log command on the console */

  Log(log, ("[%s] exec: %s", bund->name, cmd));

/* Hide any stdout output of command */

  snprintf(cmd + strlen(cmd), sizeof(cmd) - strlen(cmd), " >/dev/null 2>&1");

/* Do command */

  if ((rtn = system(cmd)))
    Log(log, ("[%s] exec: command returned %d", bund->name, rtn));

/* Return command's return value */

  va_end(ap);
  return(rtn);
}

/*
 * ParseAddr()
 *
 * Parse an IP address & mask of the form X.Y.Z.W/M.
 * If no slash, then M is assumed to be 32.
 * Returns TRUE if successful
 */

int
ParseAddr(char *s, struct in_range *r)
{
  int			n_bits;
  char			*widp, buf[100];
  struct in_addr	address;

  snprintf(buf, sizeof(buf), "%s", s);
  if ((widp = strchr(buf, '/')) != NULL)
    *widp++ = '\0';
  else
    widp = "";

/* Get IP address part */

  if (!inet_aton(buf, &address))
    return(FALSE);

/* Get mask width */

  if (*widp)
  {
    if ((n_bits = atoi(widp)) < 0 || n_bits > 32)
    {
      Log(LG_ERR, ("mpd: bad IP mask width: \"%s\"", widp));
      return(FALSE);
    }
  }
  else
    n_bits = 32;

/* Done */

  r->ipaddr = address;
  r->width = n_bits;
  return(TRUE);
}

/*
 * ParseLine()
 *
 * Parse arguments, respecting double quotes and backslash escapes.
 * Returns number of arguments, at most "max_args". This destroys
 * the original line. The arguments returned are Malloc()'d strings
 * which must be freed by the caller using FreeArgs().
 */

int
ParseLine(char *line, char *av[], int max_args)
{
  int	ac;
  char	*s, *arg;

/* Get args one at a time */

  for (ac = 0; ac < max_args; ac++)
  {

  /* Skip white space */

    while (*line && isspace(*line))
      line++;

  /* Done? */

    if (*line == 0)
      break;

  /* Get normal or quoted arg */

    if (*line == '"')
    {

    /* Stop only upon matching quote or NUL */

      for (arg = ++line; *line; line++)
	if (*line == '"')
	{
	  *line++ = 0;
	  break;
	}
	else if (*line == '\\' && line[1] != 0)
	{
	  strcpy(line, line + 1);
	  Escape(line);
	}
    }
    else
    {

    /* NUL terminate this argument at first white space */

      for (arg = line; *line && !isspace(*line); line++);
      if (*line)
	*line++ = 0;

    /* Convert characters */

      for (s = arg; *s; s++)
	if (*s == '\\')
	{
	  strcpy(s, s + 1);
	  Escape(s);
	}
    }

  /* Make a copy of this arg */

    strcpy(av[ac] = Malloc(MB_UTIL, strlen(arg) + 1), arg);
  }

#if 0
  {
    int	k;

    printf("ParseLine: %d args:\n", ac);
    for (k = 0; k < ac; k++)
      printf("  [%2d] \"%s\"\n", k, av[k]);
  }
#endif

  return(ac);
}

/*
 * FreeArgs()
 */

void
FreeArgs(int ac, char *av[])
{
  while (ac > 0)
    Freee(av[--ac]);
}

/*
 * Escape()
 *
 * Give a string, interpret the beginning characters as an escape
 * code and return with that code converted.
 */

static void
Escape(char *line)
{
  int	x, k;
  char	*s = line;

  switch (*line)
  {
    case 't': *s = '\t'; return;
    case 'n': *s = '\n'; return;
    case 'r': *s = '\r'; return;
    case 's': *s =  ' '; return;
    case '"': *s =  '"'; return;
    case '0': case '1': case '2': case '3':
    case '4': case '5': case '6': case '7':
      for (x = k = 0; k < 3 && *s >= '0' && *s <= '7'; s++)
	x = (x << 3) + (*s - '0');
      *--s = x;
      break;
    case 'x':
      for (s++, x = k = 0; k < 2 && isxdigit(*s); s++)
	x = (x << 4) + (isdigit(*s) ? (*s - '0') : (tolower(*s) - 'a' + 10));
      *--s = x;
      break;
    default:
      return;
  }
  strcpy(line, s);
}

/*
 * ReadFile()
 *
 * Read the commands specified for the target in the specified
 * file, which can be found in the PATH_CONF_DIR directory.
 * Returns negative if the file or target was not found.
 */

int
ReadFile(char *filename, char *target, int (*func)(int ac, char *av[]))
{
  FILE	*fp;
  int	ac;
  char	*av[MAX_LINE_ARGS], *av_copy[MAX_LINE_ARGS];
  char	*line;

/* Open file */

  if ((fp = OpenConfFile(filename)) == NULL)
    return(-1);

/* Find label */

  if (SeekToLabel(fp, target, NULL) < 0) {
    fclose(fp);
    return(-1);
  }

/* Execute command list */

  while ((line = ReadFullLine(fp, NULL)) != NULL)
  {
    if (!isspace(*line))
    {
      Freee(line);
      break;
    }
    ac = ParseLine(line, av, sizeof(av) / sizeof(*av));
    Freee(line);
    memcpy(av_copy, av, sizeof(av));
    (*func)(ac, av);
    FreeArgs(ac, av_copy);
  }

/* Done */

  fclose(fp);
  return(0);
}

/*
 * SeekToLabel()
 *
 * Find a label in file and position file pointer just after it
 */

int
SeekToLabel(FILE *fp, const char *label, int *lineNum)
{
  char	*s, *line;

/* Start at beginning */

  rewind(fp);
  if (lineNum)
    *lineNum = 0;

/* Find label */

  while ((line = ReadFullLine(fp, lineNum)) != NULL)
  {
    int	found;

    if (isspace(*line))
    {
      Freee(line);
      continue;
    }
    found = (s = strtok(line, " \t\f:")) && !strcmp(s, label);
    Freee(line);
    if (found)
      return(0);
  }

/* Not found */

  return(-1);
}

/*
 * OpenConfFile()
 *
 * Open a configuration file
 */

FILE *
OpenConfFile(const char *name)
{
  char	pathname[MAX_FILENAME];
  FILE	*fp;

/* Build full pathname */

  snprintf(pathname, sizeof(pathname), "%s/%s", gConfDirectory, name);

/* Open file */

  if ((fp = fopen(pathname, "r")) == NULL)
  {
    Perror("fopen(%s)", pathname);
    Log(LG_ERR, ("mpd: can't open file \"%s\"", pathname));
    return(NULL);
  }
  (void) fcntl(fileno(fp), F_SETFD, 1);
  return(fp);
}

/*
 * ReadFullLine()
 *
 * Read a full line, respecting backslash continuations.
 * Returns pointer to Malloc'd storage, which must be Freee'd
 */

char *
ReadFullLine(FILE *fp, int *lineNum)
{
  int		len, continuation;
  char		*real_line;
  static char	line[BIG_LINE_SIZE];

  for (*line = 0, continuation = TRUE; continuation; )
  {

  /* Get next real line */

    if ((real_line = ReadLine(fp, lineNum)) == NULL) {
      if (*line)
	break;
      else
	return(NULL);
    }

  /* Strip trailing white space, detect backslash */

    for (len = strlen(real_line);
	len > 0 && isspace(real_line[len - 1]);
	len--)
      real_line[len - 1] = 0;
    if ((continuation = (*real_line && real_line[len - 1] == '\\')))
      real_line[len - 1] = ' ';

  /* Append real line to what we've got so far */

    snprintf(line + strlen(line),
      sizeof(line) - strlen(line), "%s", real_line);
  }

/* Report any overflow */

  if (strlen(line) >= sizeof(line) - 1)
    Log(LG_ERR, ("mpd: warning: line too long, truncated"));

/* Copy line and return */

  return(strcpy(Malloc(MB_UTIL, strlen(line) + 1), line));
}

/*
 * ReadLine()
 *
 * Read a line, skipping blank lines & comments. A comment
 * is a line whose first non-white-space character is a hash.
 */

static char *
ReadLine(FILE *fp, int *lineNum)
{
  int		empty;
  char		ch, *s;
  static char	line[BIG_LINE_SIZE];

/* Get first non-empty, non-commented line */

  for (empty = TRUE; empty; )
  {

  /* Read next line from file */

    if ((fgets(line, sizeof(line), fp)) == NULL)
      return(NULL);
    if (lineNum)
      (*lineNum)++;

  /* Truncate long lines */

    if (line[strlen(line) - 1] == '\n')
      line[strlen(line) - 1] = 0;
    else
    {
      Log(LG_ERR, ("mpd: warning: line too long, truncated"));
      while ((ch = getc(fp)) != EOF && ch != '\n');
    }

  /* Ignore comments */

    s = line + strspn(line, " \t");
    if (*s == '#')
      *s = 0;

  /* Is this line empty? */

    for (empty = TRUE, s = line; *s; s++)
      if (!isspace(*s))
      {
	empty = FALSE;
	break;
      }
  }

/* Done */

  return(line);
}

/*
 * OpenSerialDevice()
 *
 * Open and configure a serial device. Call ExclusiveCloseDevice()
 * to close a file descriptor returned by this function.
 */

int
OpenSerialDevice(const char *path, int baudrate)
{
  struct termios	attr;
  int			fd;

/* Open & lock serial port */

  if ((fd = ExclusiveOpenDevice(path)) < 0)
    return(-1);

/* Set non-blocking I/O */

  if (fcntl(fd, F_SETFL, O_NONBLOCK) < 0)
  {
    Log(LG_PHYS, ("[%s] can't set \"%s\" to non-blocking: %s",
      lnk->name, path, strerror(errno)));
    goto failed;
  }

/* Set serial port raw mode, baud rate, hardware flow control, etc. */

  if (tcgetattr(fd, &attr) < 0)
  {
    Log(LG_ERR, ("[%s] can't tcgetattr \"%s\": %s",
      lnk->name, path, strerror(errno)));
    goto failed;
  }

  cfmakeraw(&attr);

  attr.c_cflag &= ~(CSIZE|PARENB|PARODD);
  attr.c_cflag |= (CS8|CREAD|CLOCAL|HUPCL|CCTS_OFLOW|CRTS_IFLOW);
  attr.c_iflag &= ~(IXANY|IMAXBEL|ISTRIP|IXON|IXOFF|BRKINT|ICRNL|INLCR);
  attr.c_iflag |= (IGNBRK|IGNPAR);
  attr.c_oflag &= ~OPOST;
  attr.c_lflag = 0;

  cfsetspeed(&attr, (speed_t) baudrate);

  if (tcsetattr(fd, TCSANOW, &attr) < 0)
  {
    Log(LG_ERR, ("[%s] can't tcsetattr \"%s\": %s",
      lnk->name, path, strerror(errno)));
failed:
    ExclusiveCloseDevice(fd, path);
    return(-1);
  }

/* OK */

  return(fd);
}

/*
 * ExclusiveOpenDevice()
 */

int
ExclusiveOpenDevice(const char *pathname)
{
  int		fd, locked = FALSE;
  const char	*ttyname = NULL;
  time_t	startTime;

/* Lock device UUCP style, if it resides in /dev */

  if (!strncmp(pathname, "/dev/", 5))
  {
    ttyname = pathname + 5;
    if (UuLock(ttyname) < 0)
    {
      Log(LG_ERR, ("[%s] can't lock device %s", lnk->name, ttyname));
      return(-1);
    }
    locked = TRUE;
  }

/* Open it, but give up after so many interruptions */

  for (startTime = time(NULL);
      (fd = open(pathname, O_RDWR, 0)) < 0
      && time(NULL) < startTime + MAX_OPEN_DELAY; )
    if (errno != EINTR)
    {
      Log(LG_ERR, ("[%s] can't open %s: %s",
	lnk->name, pathname, strerror(errno)));
      if (locked)
	UuUnlock(ttyname);
      return(-1);
    }

/* Did we succeed? */

  if (fd < 0)
  {
    Log(LG_ERR, ("[%s] can't open %s after %d secs",
      lnk->name, pathname, MAX_OPEN_DELAY));
    if (locked)
      UuUnlock(ttyname);
    return(-1);
  }
  (void) fcntl(fd, F_SETFD, 1);

/* Done */

  return(fd);
}

/*
 * ExclusiveCloseDevice()
 */

void
ExclusiveCloseDevice(int fd, const char *pathname)
{
  int		rtn = -1;
  const char	*ttyname;
  time_t	startTime;

/* Close file(s) */

  for (startTime = time(NULL);
      time(NULL) < startTime + MAX_OPEN_DELAY && (rtn = close(fd)) < 0; )
    if (errno != EINTR)
    {
      Log(LG_ERR, ("[%s] can't close %s: %s",
	lnk->name, pathname, strerror(errno)));
      DoExit(EX_ERRDEAD);
    }

/* Did we succeed? */

  if (rtn < 0)
  {
    Log(LG_ERR, ("[%s] can't close %s after %d secs",
      lnk->name, pathname, MAX_OPEN_DELAY));
    DoExit(EX_ERRDEAD);
  }

/* Remove lock */

  if (!strncmp(pathname, "/dev/", 5))
  {
    ttyname = pathname + 5;
    if (UuUnlock(ttyname) < 0)
      Log(LG_ERR, ("[%s] can't unlock %s: %s",
	lnk->name, ttyname, strerror(errno)));
  }
}

/*
 * UuLock()
 *
 * Try to atomically create lockfile. Returns negative if failed.
 */

static int
UuLock(const char *ttyname)
{
  int	fd, pid;
  char	tbuf[sizeof(PATH_LOCKFILENAME) + MAX_FILENAME];
  char	pid_buf[64];

  snprintf(tbuf, sizeof(tbuf), PATH_LOCKFILENAME, ttyname);
  if ((fd = open(tbuf, O_RDWR|O_CREAT|O_EXCL, 0664)) < 0)
  {

  /* File is already locked; Check to see if the process
   * holding the lock still exists */

    if ((fd = open(tbuf, O_RDWR, 0)) < 0)
    {
      Perror("UuLock: open(%s)", tbuf);
      return(-1);
    }

    if (read(fd, pid_buf, sizeof(pid_buf)) <= 0)
    {
      (void)close(fd);
      Perror("UuLock: read");
      return(-1);
    }

    pid = atoi(pid_buf);

    if (kill(pid, 0) == 0 || errno != ESRCH)
    {
      (void)close(fd);  /* process is still running */
      return(-1);
    }

  /* The process that locked the file isn't running, so we'll lock it */

    if (lseek(fd, (off_t) 0, L_SET) < 0)
    {
      (void)close(fd);
      Perror("UuLock: lseek");
      return(-1);
    }
  }

/* Finish the locking process */

  sprintf(pid_buf, "%10u\n", (int) getpid());
  if (write(fd, pid_buf, strlen(pid_buf)) != strlen(pid_buf))
  {
    (void)close(fd);
    (void)unlink(tbuf);
    Perror("UuLock: write");
    return(-1);
  }
  (void)close(fd);
  return(0);
}

/*
 * UuUnlock()
 */

static int
UuUnlock(const char *ttyname)
{
  char	tbuf[sizeof(PATH_LOCKFILENAME) + MAX_FILENAME];

  (void) sprintf(tbuf, PATH_LOCKFILENAME, ttyname);
  return(unlink(tbuf));
}

/*
 * WriteMbuf()
 *
 * Write an mbuf to a file descriptor which is character based.
 * Leave whatever portion of the mbuf is remaining.
 */

int
WriteMbuf(Mbuf *mp, int fd, const char *label)
{
  while (*mp)
  {
    Mbuf	const bp = *mp;
    int		nw;

    if ((nw = write(fd, MBDATA(bp), MBLEN(bp))) < 0)
    {
      if (errno == EAGAIN)
	return(0);
      Log(LG_ERR, ("[%s] %s write: %s", lnk->name, label, strerror(errno)));
      return(-1);
    }
    bp->offset += nw;
    bp->cnt -= nw;
    if (bp->cnt != 0)
      break;
    *mp = mbfree(bp);
  }
  return(0);
}

/*
 * GenerateMagic()
 *
 * Generate random number which will be used as magic number.
 * This could be made a little more "random"...
 */

u_long
GenerateMagic(void)
{
  time_t		now;
  struct timeval	tval;

  time(&now);
  gettimeofday(&tval, NULL);
  now += (tval.tv_sec ^ tval.tv_usec) + getppid();
  now *= getpid();
  return(now);
}

/*
 * PIDCheck()
 *
 * See if process is already running and deal with PID file.
 */

int
PIDCheck(char *filename, int killem)
{
  int	fd = -1, n_tries;

/* Sanity */

  assert(!lockFp);

/* Atomically open and lock file */

  for (n_tries = 0;
    n_tries < MAX_LOCK_ATTEMPTS
      && (fd = open(filename, O_RDWR|O_CREAT|O_EXLOCK|O_NONBLOCK, 0644)) < 0;
    n_tries++)
  {
    int		nscan, old_pid;
    FILE	*fp;

  /* Abort on any unexpected errors */

    if (errno != EAGAIN)
    {
      Perror("open(%s)", filename);
      return(-1);
    }

  /* We're already running ... see who it is */

    if ((fp = fopen(filename, "r")) == NULL)
    {
      Perror("fopen(%s)", filename);
      return(-1);
    }

  /* If there's a PID in there, sniff it out */

    nscan = fscanf(fp, "%d", &old_pid);
    fclose(fp);
    if (nscan != 1)
    {
      Log(LG_ERR, ("%s: contents mangled", filename));
      return(-1);
    }

  /* Maybe kill the other guy */

    if (!killem)
    {
      Log(LG_ERR, ("mpd: already running as process %d", old_pid));
      return(-1);
    }
    if (kill(old_pid, SIGTERM) < 0)
      switch (errno)
      {
	case ESRCH:
	  Log(LG_ERR, ("mpd: process %d no longer exists", old_pid));
	  break;
	default:
	  Perror("kill(%d)", old_pid);
	  return(-1);
      }

  /* Wait and try again */

    Log(LG_ERR, ("mpd: waiting for process %d to die...", old_pid));
    sleep(1);
  }
  if (n_tries == MAX_LOCK_ATTEMPTS)
  {
    Log(LG_ERR, ("mpd: can't lock %s after %d attempts", filename, n_tries));
    return(-1);
  }

/* Close on exec */

  (void) fcntl(fd, F_SETFD, 1);

/* Create a stream on top of file descriptor */

  if ((lockFp = fdopen(fd, "r+")) == NULL)
  {
    Perror("fdopen");
    return(-1);
  }
  setbuf(lockFp, NULL);

/* Write my PID in there */

  rewind(lockFp);
  fprintf(lockFp, "%u\n", (u_int) getpid());
  fflush(lockFp);
  (void) ftruncate(fileno(lockFp), ftell(lockFp));
  return(0);
}

/*
 * GetInetSocket()
 *
 * Get a TCP socket and bind it to an address. Set SO_REUSEADDR on the socket.
 */

int
GetInetSocket(int type, struct in_addr locip, int locport, char *ebuf, int len)
{
  struct sockaddr_in	self;
  int			sock, self_size = sizeof(self);
  static int		one = 1;

/* Get and bind non-blocking socket */

  if ((sock = socket(AF_INET, type, type == SOCK_STREAM ? IPPROTO_TCP : 0)) < 0)
  {
    snprintf(ebuf, len, "socket: %s", strerror(errno));
    return(-1);
  }
  (void) fcntl(sock, F_SETFD, 1);
  if (fcntl(sock, F_SETFL, O_NONBLOCK) < 0)
  {
    snprintf(ebuf, len, "can't set socket non-blocking: %s", strerror(errno));
    close(sock);
    return(-1);
  }
  if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)))
  {
    snprintf(ebuf, len, "setsockopt: %s", strerror(errno));
    close(sock);
    return(-1);
  }
  memset(&self, 0, sizeof(self));
  self.sin_family = AF_INET;
  self.sin_addr = locip;
  self.sin_port = htons((u_short) locport);
  if (bind(sock, (struct sockaddr *) &self, self_size) < 0)
  {
    snprintf(ebuf, len, "bind: %s", strerror(errno));
    close(sock);
    return(-1);
  }
  return(sock);
}

/*
 * TcpGetListenPort()
 *
 * Get port for incoming telnet connections
 */

int
TcpGetListenPort(struct in_addr ip, int *port)
{
  char	ebuf[100];
  int	sock;

/* Get socket */

  if ((sock = GetInetSocket(SOCK_STREAM, ip, *port, ebuf, sizeof(ebuf))) < 0)
  {
    Log(LG_ERR, ("mpd: %s", ebuf));
    return(-1);
  }

/* Get the port number assigned by system if none requested */

  if (*port == 0)
  {
    struct sockaddr_in	address;
    int			size = sizeof(address);

    if (getsockname(sock, (struct sockaddr *) &address, &size) < 0)
    {
      Perror("getsockname");
      (void) close(sock);
      return(-1);
    }
    *port = (int) ntohs(address.sin_port);
  }

/* Make socket available for connections  */

  if (listen(sock, 2) < 0)
  {
    Perror("listen");
    (void) close(sock);
    return(-1);
  }

/* Done */

  return(sock);
}

/*
 * TcpAcceptConnection()
 *
 * Accept next connection on port
 */

int
TcpAcceptConnection(int sock, struct sockaddr_in *addr)
{
  int	new_sock;
  int	size = sizeof(*addr);

/* Accept incoming connection */

  memset(addr, 0, sizeof(*addr));
  if ((new_sock = accept(sock, (struct sockaddr *) addr, &size)) < 0) {
    Perror("accept");
    return(-1);
  }
  (void) fcntl(new_sock, F_SETFD, 1);
  if (fcntl(new_sock, F_SETFL, O_NONBLOCK) < 0) {
    Perror("fcntl");
    return(-1);
  }

/* Done */

  return(new_sock);
}

/*
 * ShowMesg()
 */

void
ShowMesg(int log, const char *buf, int len)
{
  char	*s, mesg[256];

  if (len > 0)
  {
    if (len > sizeof(mesg) - 1)
      len = sizeof(mesg) - 1;
    memcpy(mesg, buf, len);
    mesg[len] = 0;
    for (s = strtok(mesg, "\r\n"); s; s = strtok(NULL, "\r\n"))
      Log(log, (" MESG: %s", s));
  }
}

/*
 * Crc16()
 *
 * Compute the 16 bit frame check value, per RFC 1171 Appendix B,
 * on an array of bytes.
 */

u_short
Crc16(u_short crc, u_char *cp, int len)
{
  while (len--)
    crc = (crc >> 8) ^ Crc16Table[(crc ^ *cp++) & 0xff];
  return(crc);
}

static const u_int16_t Crc16Table[256] = {
/* 00 */    0x0000, 0x1189, 0x2312, 0x329b, 0x4624, 0x57ad, 0x6536, 0x74bf,
/* 08 */    0x8c48, 0x9dc1, 0xaf5a, 0xbed3, 0xca6c, 0xdbe5, 0xe97e, 0xf8f7,
/* 10 */    0x1081, 0x0108, 0x3393, 0x221a, 0x56a5, 0x472c, 0x75b7, 0x643e,
/* 18 */    0x9cc9, 0x8d40, 0xbfdb, 0xae52, 0xdaed, 0xcb64, 0xf9ff, 0xe876,
/* 20 */    0x2102, 0x308b, 0x0210, 0x1399, 0x6726, 0x76af, 0x4434, 0x55bd,
/* 28 */    0xad4a, 0xbcc3, 0x8e58, 0x9fd1, 0xeb6e, 0xfae7, 0xc87c, 0xd9f5,
/* 30 */    0x3183, 0x200a, 0x1291, 0x0318, 0x77a7, 0x662e, 0x54b5, 0x453c,
/* 38 */    0xbdcb, 0xac42, 0x9ed9, 0x8f50, 0xfbef, 0xea66, 0xd8fd, 0xc974,
/* 40 */    0x4204, 0x538d, 0x6116, 0x709f, 0x0420, 0x15a9, 0x2732, 0x36bb,
/* 48 */    0xce4c, 0xdfc5, 0xed5e, 0xfcd7, 0x8868, 0x99e1, 0xab7a, 0xbaf3,
/* 50 */    0x5285, 0x430c, 0x7197, 0x601e, 0x14a1, 0x0528, 0x37b3, 0x263a,
/* 58 */    0xdecd, 0xcf44, 0xfddf, 0xec56, 0x98e9, 0x8960, 0xbbfb, 0xaa72,
/* 60 */    0x6306, 0x728f, 0x4014, 0x519d, 0x2522, 0x34ab, 0x0630, 0x17b9,
/* 68 */    0xef4e, 0xfec7, 0xcc5c, 0xddd5, 0xa96a, 0xb8e3, 0x8a78, 0x9bf1,
/* 70 */    0x7387, 0x620e, 0x5095, 0x411c, 0x35a3, 0x242a, 0x16b1, 0x0738,
/* 78 */    0xffcf, 0xee46, 0xdcdd, 0xcd54, 0xb9eb, 0xa862, 0x9af9, 0x8b70,
/* 80 */    0x8408, 0x9581, 0xa71a, 0xb693, 0xc22c, 0xd3a5, 0xe13e, 0xf0b7,
/* 88 */    0x0840, 0x19c9, 0x2b52, 0x3adb, 0x4e64, 0x5fed, 0x6d76, 0x7cff,
/* 90 */    0x9489, 0x8500, 0xb79b, 0xa612, 0xd2ad, 0xc324, 0xf1bf, 0xe036,
/* 98 */    0x18c1, 0x0948, 0x3bd3, 0x2a5a, 0x5ee5, 0x4f6c, 0x7df7, 0x6c7e,
/* a0 */    0xa50a, 0xb483, 0x8618, 0x9791, 0xe32e, 0xf2a7, 0xc03c, 0xd1b5,
/* a8 */    0x2942, 0x38cb, 0x0a50, 0x1bd9, 0x6f66, 0x7eef, 0x4c74, 0x5dfd,
/* b0 */    0xb58b, 0xa402, 0x9699, 0x8710, 0xf3af, 0xe226, 0xd0bd, 0xc134,
/* b8 */    0x39c3, 0x284a, 0x1ad1, 0x0b58, 0x7fe7, 0x6e6e, 0x5cf5, 0x4d7c,
/* c0 */    0xc60c, 0xd785, 0xe51e, 0xf497, 0x8028, 0x91a1, 0xa33a, 0xb2b3,
/* c8 */    0x4a44, 0x5bcd, 0x6956, 0x78df, 0x0c60, 0x1de9, 0x2f72, 0x3efb,
/* d0 */    0xd68d, 0xc704, 0xf59f, 0xe416, 0x90a9, 0x8120, 0xb3bb, 0xa232,
/* d8 */    0x5ac5, 0x4b4c, 0x79d7, 0x685e, 0x1ce1, 0x0d68, 0x3ff3, 0x2e7a,
/* e0 */    0xe70e, 0xf687, 0xc41c, 0xd595, 0xa12a, 0xb0a3, 0x8238, 0x93b1,
/* e8 */    0x6b46, 0x7acf, 0x4854, 0x59dd, 0x2d62, 0x3ceb, 0x0e70, 0x1ff9,
/* f0 */    0xf78f, 0xe606, 0xd49d, 0xc514, 0xb1ab, 0xa022, 0x92b9, 0x8330,
/* f8 */    0x7bc7, 0x6a4e, 0x58d5, 0x495c, 0x3de3, 0x2c6a, 0x1ef1, 0x0f78
};


