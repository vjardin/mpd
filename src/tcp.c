
/*
 * tcp.c
 *
 * Written by Archie Cobbs <archie@freebsd.org>
 * Copyright (c) 1995-1999 Whistle Communications, Inc. All rights reserved.
 * See ``COPYRIGHT.whistle''
 */

#include "ppp.h"
#include "phys.h"
#include "mbuf.h"
#include "async.h"
#include "tcp.h"

#error NEEDS UPDATING

/*
 * DEFINITIONS
 */

  #define TCP_MTU		2048
  #define TCP_MRU		2048

  #define TCP_REOPEN_PAUSE	10

  struct tcpinfo
  {

  /* Configuration */

    struct in_addr	peer_addr;
    struct in_addr	self_addr;
    u_short		peer_port;
    u_short		self_port;

  /* State */

    int			sock;
    EventRef		connEvent;
    EventRef		readEvent;
    EventRef		writeEvent;
    AsyncInfo		async;
    Mbuf		out;
    u_char		active:1;
  };
  typedef struct tcpinfo	*TcpInfo;

/* Set menu options */

  enum
  {
    SET_MODE,
    SET_PEERADDR,
    SET_SELFADDR,
  };

/*
 * INTERNAL FUNCTIONS
 */

  static int	TcpInit(PhysInfo p);
  static void	TcpOpen(PhysInfo p);
  static void	TcpClose(PhysInfo p);
  static Mbuf	TcpOutput(PhysInfo p, Mbuf bp, int proto);
  static void	TcpStat(PhysInfo p);
  static int	TcpOriginated(PhysInfo p);
  static int	TcpPeerAddr(PhysInfo p, void *buf, int buf_len);

  static void	TcpDoClose(TcpInfo tcp);
  static void	TcpWrite(int type, void *cookie);
  static void	TcpConEvent(int type, void *cookie);
  static void	TcpRead(int type, void *cookie);

  static int	TcpSetCommand(int ac, char *av[], void *arg);

/*
 * GLOBAL VARIABLES
 */

  const struct phystype gTcpPhysType =
  {
    "tcp",
    FALSE, TCP_REOPEN_PAUSE,
    TCP_MTU, TCP_MRU,
    TcpInit,
    TcpOpen,
    TcpClose,
    NULL,
    TcpShutdown,
    TcpStat,
    TcpOriginated,
    TcpPeerAddr,
  };

  const struct cmdtab TcpSetCmds[] =
  {
    { "mode active|passive",		"Set connect method",
	TcpSetCommand, NULL, (void *) SET_MODE },
    { "self ip [port]",			"Set local IP address",
	TcpSetCommand, NULL, (void *) SET_SELFADDR },
    { "peer ip [port]",			"Set remote IP address",
	TcpSetCommand, NULL, (void *) SET_PEERADDR },
    { NULL },
  };

/*
 * TcpInit()
 */

static int
TcpInit(PhysInfo p)
{
  TcpInfo	tcp;

  tcp = (TcpInfo) (p->info = Malloc(MB_PHYS, sizeof(*tcp)));
  tcp->sock = -1;
  AsyncInit(&tcp->async, NULL, 0);
  return(0);
}

/*
 * TcpOpen()
 */

static void
TcpOpen(PhysInfo p)
{
  TcpInfo	const tcp = (TcpInfo) lnk->phys->info;
  char		errbuf[100];

/* Get socket */

  if ((tcp->sock = GetInetSocket(SOCK_STREAM,
    tcp->self_addr, tcp->self_port, errbuf, sizeof(errbuf))) < 0)
  {
    Log(LG_PHYS, ("[%s] %s", lnk->name, errbuf));
    PhysDown(STR_ERROR, NULL);
    return;
  }

/* Connect to peer, actively or passively */

  if (tcp->active)		/* Initiate connection */
  {
    struct sockaddr_in	peer;

    memset(&peer, 0, sizeof(peer));
    peer.sin_family = AF_INET;
    peer.sin_addr = tcp->peer_addr;
    peer.sin_port = htons(tcp->peer_port);
    if (connect(tcp->sock, (struct sockaddr *) &peer, sizeof(peer)) >= 0)
      TcpConEvent(EVENT_WRITE, lnk);
    else
    {
      if (errno == EINPROGRESS)
      {
	EventRegister(&tcp->connEvent, EVENT_WRITE, tcp->sock,
	  DEV_PRIO, TcpConEvent, lnk);
	Log(LG_PHYS, ("[%s] connecting to %s:%u",
	  lnk->name, inet_ntoa(tcp->peer_addr), tcp->peer_port));
	return;
      }
      Log(LG_PHYS, ("[%s] connect: %s", lnk->name, strerror(errno)));
      close(tcp->sock);
      tcp->sock = -1;
      PhysDown(STR_ERROR, NULL);
      return;
    }
  }
  else				/* Listen for a connection */
  {

  /* Make socket available for connections  */

    if (listen(tcp->sock, 2) < 0) {
      Log(LG_PHYS, ("[%s] listen: %s", lnk->name, strerror(errno)));
      close(tcp->sock);
      tcp->sock = -1;
      PhysDown(STR_ERROR, NULL);
      return;
    }
    Log(LG_PHYS, ("[%s] waiting for connection on %s:%u",
      lnk->name, inet_ntoa(tcp->self_addr), tcp->self_port));
    EventRegister(&tcp->connEvent, EVENT_READ, tcp->sock,
      DEV_PRIO, TcpConEvent, lnk);
  }
}

/*
 * TcpConEvent()
 */

static void
TcpConEvent(int type, void *cookie)
{
  TcpInfo		tcp;
  struct sockaddr_in	peerAddr;

/* Get event */

  lnk = (Link) cookie;
  bund = lnk->bund;
  tcp = (TcpInfo) lnk->phys->info;

/* If passive, accept the incoming connection */

  if (type == EVENT_READ)
  {
    int	sock;

    if ((sock = TcpAcceptConnection(tcp->sock, &peerAddr)) < 0)
      goto failed;
    (void) close(tcp->sock);
    tcp->sock = sock;
    Log(LG_PHYS, ("[%s] incoming connection from %s:%u",
      lnk->name, inet_ntoa(peerAddr.sin_addr), ntohs(peerAddr.sin_port)));

  /* If passive, and peer address specified, only accept from that address */

    if (tcp->peer_addr.s_addr
      && tcp->peer_addr.s_addr != peerAddr.sin_addr.s_addr)
    {
      Log(LG_PHYS, ("[%s] rejected: wrong IP address", lnk->name));
      goto failed;
    }

  /* If passive, and peer port specified, only accept from that port */

    if (tcp->peer_port != 0 && tcp->peer_port != ntohs(peerAddr.sin_port))
    {
      Log(LG_PHYS, ("[%s] rejected: wrong port", lnk->name));
      goto failed;
    }
  }
  else
  {
    int	addrLen = sizeof(peerAddr);

  /* Check whether the connection was successful or not */

    if (getpeername(tcp->sock, (struct sockaddr *) &peerAddr, &addrLen) < 0) {
      Log(LG_PPTP, ("[%s] connection to %s:%d failed",
	lnk->name, inet_ntoa(tcp->peer_addr), tcp->peer_port));
failed:
      PhysDown(STR_ERROR, NULL);
      TcpDoClose(tcp);
      return;
    }
  }

/* Report connected */

  Log(LG_PHYS, ("[%s] connected to %s:%u",
    lnk->name, inet_ntoa(peerAddr.sin_addr), ntohs(peerAddr.sin_port)));
  AsyncInit(&tcp->async, LinkInput, TCP_MRU + MAX_PPP_FRAME_OVERHEAD);
  PhysUp();

/* Wait for input */

  EventRegister(&tcp->readEvent, EVENT_READ,
    tcp->sock, DEV_PRIO, TcpRead, lnk);
}

/*
 * TcpClose()
 */

static void
TcpClose(PhysInfo p)
{
  TcpDoClose((TcpInfo) p->info);
  PhysDown(0, NULL);
}

/*
 * TcpDoClose()
 */

static void
TcpDoClose(TcpInfo tcp)
{
  PFREE(tcp->out);
  EventUnRegister(&tcp->connEvent);
  EventUnRegister(&tcp->readEvent);
  EventUnRegister(&tcp->writeEvent);
  (void) close(tcp->sock);
  tcp->sock = -1;
}

/*
 * TcpRead()
 */

static void
TcpRead(int type, void *cookie)
{
  TcpInfo	tcp;
  u_char	buf[LCP_DEFAULT_MRU];
  int		nread;

/* Get event */

  lnk = (Link) cookie;
  bund = lnk->bund;
  tcp = (TcpInfo) lnk->phys->info;

/* Read data */

  if ((nread = read(tcp->sock, buf, sizeof(buf))) <= 0)
  {
    if (nread < 0)
    {
      if (errno == EAGAIN)
	goto done;
      Log(LG_LINK, ("[%s] device read: %s", lnk->name, strerror(errno)));
      PhysDown(STR_READ_ERR, "%s", strerror(errno));
    }
    else
      PhysDown(STR_READ_EOF, NULL);
    TcpDoClose(tcp);
    return;
  }

/* Run bytes through async decoder */

  AsyncDecode(tcp->async, buf, nread);

/* Reregister input event */

done:
  EventRegister(&tcp->readEvent, EVENT_READ,
    tcp->sock, DEV_PRIO, TcpRead, lnk);
}

/*
 * TcpOutput()
 */

static Mbuf
TcpOutput(PhysInfo p, Mbuf frame, int proto)
{
  TcpInfo	const tcp = (TcpInfo) p->info;

  if (proto != PROTO_UNKNOWN
    && (proto == PROTO_LCP || !lnk->lcp.peer_acfcomp))
  {
    Mbuf	hdr;

    hdr = mballoc(MB_FRAME_OUT, 2);
    MBDATA(hdr)[0] = PPP_ALLSTATIONS;
    MBDATA(hdr)[1] = PPP_UI;
    hdr->next = frame;
    frame = hdr;
  }
  if (tcp->out)
    return(frame);
  tcp->out = AsyncEncode(tcp->async, frame, proto == PROTO_LCP);
  TcpWrite(EVENT_WRITE, lnk);
  return(NULL);
}

/*
 * TcpWrite()
 */

static void
TcpWrite(int type, void *cookie)
{
  TcpInfo	tcp;

  lnk = (Link) cookie;
  bund = lnk->bund;
  tcp = (TcpInfo) lnk->phys->info;
  if (WriteMbuf(&tcp->out, tcp->sock, "socket") < 0)
  {
    PhysDown(STR_WRITE_ERR, "%s", strerror(errno));
    TcpDoClose(tcp);
    return;
  }
  if (tcp->out)
    EventRegister(&tcp->writeEvent, EVENT_WRITE,
      tcp->sock, DEV_PRIO, TcpWrite, lnk);
}

/*
 * TcpOriginated()
 */

static int
TcpOriginated(PhysInfo p)
{
  TcpInfo	const tcp = (TcpInfo) lnk->phys->info;

  return(tcp->active ? LINK_ORIGINATE_LOCAL : LINK_ORIGINATE_REMOTE);
}

static int
TcpPeerAddr(PhysInfo p, void *buf, int buf_len)
{
  TcpInfo	const tcp = (TcpInfo) p;

  if (inet_ntop(AF_INET, &tcp->peer_addr, buf, buf_len))
    return(0);
  else
    return(-1);
}

/*
 * TcpStat()
 */

void
TcpStat(PhysInfo p)
{
  TcpInfo	const tcp = (TcpInfo) lnk->phys->info;

  printf("TCP configuration:\n");
  printf("\tSelf address : %s, port %u\n",
    inet_ntoa(tcp->self_addr), tcp->self_port);
  printf("\tPeer address : %s, port %u\n",
    inet_ntoa(tcp->peer_addr), tcp->peer_port);
  printf("\tConnect mode : %s\n", tcp->active ? "ACTIVE" : "PASSIVE");
  AsyncStat(tcp->async);
}

/*
 * TcpSetCommand()
 */

static int
TcpSetCommand(int ac, char *av[], void *arg)
{
  TcpInfo		const tcp = (TcpInfo) lnk->phys->info;
  struct in_addr	*ap;
  u_short		*pp;

  switch ((int) arg)
  {
    case SET_MODE:
      if (ac != 1)
	return(-1);
      if (!strcasecmp(av[0], "active"))
	tcp->active = TRUE;
      else if (!strcasecmp(av[0], "passive"))
	tcp->active = FALSE;
      else
	return(-1);
      break;

    case SET_PEERADDR:
      ap = &tcp->peer_addr;
      pp = &tcp->peer_port;
      goto getAddrPort;
    case SET_SELFADDR:
      ap = &tcp->self_addr;
      pp = &tcp->self_port;
getAddrPort:
      if (ac < 1 || ac > 2)
	return(-1);
      if (!inet_aton(av[0], ap))
      {
	Log(LG_ERR, ("Bad ip address \"%s\"", av[0]));
	return(-1);
      }
      if (ac > 1)
      {
	if (atoi(av[1]) <= 0)
	{
	  Log(LG_ERR, ("Bad port \"%s\"", av[1]));
	  return(-1);
	}
	*pp = atoi(av[1]);
      }
      break;

    default:
      assert(0);
  }
  return(0);
}


