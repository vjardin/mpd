
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
#include "ngfunc.h"
#include "tcp.h"

#ifdef __DragonFly__
#include <netgraph/socket/ng_socket.h>
#include <netgraph/ng_message.h>
#include <netgraph/async/ng_async.h>
#include <netgraph/ksocket/ng_ksocket.h>
#else
#include <netgraph/ng_socket.h>
#include <netgraph/ng_message.h>
#include <netgraph/ng_async.h>
#include <netgraph/ng_ksocket.h>
#endif
#include <netgraph.h>

/*
 * DEFINITIONS
 */

  #define TCP_MTU		2048
  #define TCP_MRU		2048

  #define TCP_REOPEN_PAUSE	10

  #define LISTENHOOK		"listen"

  struct tcpinfo {
    /* Configuration */
    struct in_addr	peer_addr;
    struct in_addr	self_addr;
    uint16_t		peer_port;
    uint16_t		self_port;

    /* State */
    int			csock;
    int			dsock;
    struct sockaddr_in	sin_peer;
    struct ng_async_cfg	acfg;
    EventRef		ev_connect;
    EventRef		ev_accept;
    EventRef		readEvent;
    EventRef		writeEvent;
    int			origination;
  };
  typedef struct tcpinfo	*TcpInfo;

/* Set menu options */
  enum {
    SET_PEERADDR,
    SET_SELFADDR,
    SET_ORIGINATION,
  };

/*
 * INTERNAL FUNCTIONS
 */

  static int	TcpInit(PhysInfo p);
  static void	TcpOpen(PhysInfo p);
  static void	TcpClose(PhysInfo p);
  static void	TcpStat(PhysInfo p);
  static int	TcpOriginated(PhysInfo p);
  static int	TcpPeerAddr(PhysInfo p, void *buf, int buf_len);

  static void	TcpDoClose(TcpInfo tcp);
  static void	TcpAcceptEvent(int type, void *cookie);
  static void	TcpConnectEvent(int type, void *cookie);

  static int	TcpSetCommand(int ac, char *av[], void *arg);

/*
 * GLOBAL VARIABLES
 */

  const struct phystype gTcpPhysType = {
    .name		= "tcp",
    .synchronous	= FALSE,
    .minReopenDelay	= TCP_REOPEN_PAUSE,
    .mtu		= TCP_MTU,
    .mru		= TCP_MRU,
    .init		= TcpInit,
    .open		= TcpOpen,
    .close		= TcpClose,
    .showstat		= TcpStat,
    .originate		= TcpOriginated,
    .peeraddr		= TcpPeerAddr,
  };

  const struct cmdtab TcpSetCmds[] = {
    { "self ip [port]",			"Set local IP address",
	TcpSetCommand, NULL, (void *) SET_SELFADDR },
    { "peer ip [port]",			"Set remote IP address",
	TcpSetCommand, NULL, (void *) SET_PEERADDR },
    { "origination < local | remote >",	"Set link origination",
	TcpSetCommand, NULL, (void *) SET_ORIGINATION },
    { NULL },
  };


/*
 * TcpInit()
 */

static int
TcpInit(PhysInfo p)
{
	TcpInfo tcp;

	tcp = (TcpInfo) (p->info = Malloc(MB_PHYS, sizeof(*tcp)));
	tcp->origination = LINK_ORIGINATE_UNKNOWN;
	return (0);
}

/*
 * TcpOpen()
 */

static void
TcpOpen(PhysInfo p)
{
	TcpInfo	const tcp = (TcpInfo) lnk->phys->info;
	struct ngm_mkpeer mkp;
	char path[NG_PATHLEN + 1];

	/* Attach async node to PPP node. */
	snprintf(mkp.type, sizeof(mkp.type), "%s", NG_ASYNC_NODE_TYPE);
	snprintf(mkp.ourhook, sizeof(mkp.ourhook), "%s%d",
	    NG_PPP_HOOK_LINK_PREFIX, lnk->bundleIndex);
	snprintf(mkp.peerhook, sizeof(mkp.peerhook), NG_ASYNC_HOOK_SYNC);
	if (NgSendMsg(bund->csock, MPD_HOOK_PPP, NGM_GENERIC_COOKIE,
	    NGM_MKPEER, &mkp, sizeof(mkp)) < 0) {
		Log(LG_PHYS, ("[%s] can't attach %s node: %s",
		    lnk->name, NG_ASYNC_NODE_TYPE, strerror(errno)));
		goto fail;
	}
	
	/* Configure the async converter node. */
	memset(&tcp->acfg, 0, sizeof(tcp->acfg));
	tcp->acfg.enabled = TRUE;
	tcp->acfg.accm = ~0;
	tcp->acfg.amru = TCP_MRU;
	tcp->acfg.smru = TCP_MTU;
	snprintf(path, sizeof(path), ".:%s.%s%d", MPD_HOOK_PPP,
	    NG_PPP_HOOK_LINK_PREFIX, lnk->bundleIndex);
	if (NgSendMsg(bund->csock, path, NGM_ASYNC_COOKIE,
	    NGM_ASYNC_CMD_SET_CONFIG, &tcp->acfg, sizeof(tcp->acfg)) < 0) {
		Log(LG_PHYS, ("[%s] can't config %s", lnk->name, path));
		goto fail;
	}

	/* Create a new netgraph node to control TCP ksocket node. */
	if (NgMkSockNode(NULL, &tcp->csock, &tcp->dsock) < 0) {
		Log(LG_ERR, ("[%s] TCP can't create control socket: %s",
		    lnk->name, strerror(errno)));
		goto fail;
	}

	/* Connect to peer, actively or passively. */
	if (tcp->origination == LINK_ORIGINATE_LOCAL) {
		struct sockaddr_in addr;
		int rval;

		/* Attach ksocket node to next async node. */
		snprintf(mkp.type, sizeof(mkp.type), "%s",
		    NG_KSOCKET_NODE_TYPE);
		snprintf(mkp.ourhook, sizeof(mkp.ourhook), NG_ASYNC_HOOK_ASYNC);
		snprintf(mkp.peerhook, sizeof(mkp.peerhook), "inet/stream/tcp");
		snprintf(path, sizeof(path), "[%x]:%s%d.%s", bund->nodeID,
		    NG_PPP_HOOK_LINK_PREFIX, lnk->bundleIndex,
		    NG_ASYNC_HOOK_SYNC);
		if (NgSendMsg(tcp->csock, path, NGM_GENERIC_COOKIE,
		    NGM_MKPEER, &mkp, sizeof(mkp)) < 0) {
			Log(LG_PHYS, ("[%s] can't attach %s node: %s",
			    lnk->name, NG_KSOCKET_NODE_TYPE, strerror(errno)));
			goto fail;
		}

		/* Start connecting to peer. */
		memset(&addr, 0, sizeof(addr));
		addr.sin_family = AF_INET;
		addr.sin_addr = tcp->peer_addr;
		addr.sin_port = htons(tcp->peer_port);
		snprintf(path, sizeof(path), "mpd%d-%s:%s%d.%s", getpid(),
		    bund->name, NG_PPP_HOOK_LINK_PREFIX, lnk->bundleIndex,
		    NG_ASYNC_HOOK_ASYNC);
		rval = NgSendMsg(tcp->csock, path, NGM_KSOCKET_COOKIE,
		    NGM_KSOCKET_CONNECT, &addr, sizeof(addr));
		if (rval < 0 && errno != EINPROGRESS) {
			Log(LG_PHYS, ("[%s] can't connect %s node: %s",
			    lnk->name, NG_KSOCKET_NODE_TYPE, strerror(errno))); 
			goto fail;
		}
		if (rval == 0)	/* Can happen when peer is local. */
			TcpConnectEvent(EVENT_READ, lnk);
		else {
			assert(errno == EINPROGRESS);
			EventRegister(&tcp->ev_connect, EVENT_READ, tcp->csock,
			    0, TcpConnectEvent, lnk);
			Log(LG_PHYS, ("[%s] connecting to %s:%u",
			    lnk->name, inet_ntoa(tcp->peer_addr),
			    tcp->peer_port));
		}
	} else if (tcp->origination == LINK_ORIGINATE_REMOTE) {
		struct sockaddr_in addr;
		int32_t backlog = 1;

		/* Make listening TCP ksocket node. */
		snprintf(mkp.type, sizeof(mkp.type), "%s",
		    NG_KSOCKET_NODE_TYPE);
		snprintf(mkp.ourhook, sizeof(mkp.ourhook), LISTENHOOK);
		snprintf(mkp.peerhook, sizeof(mkp.peerhook), "inet/stream/tcp");
		if (NgSendMsg(tcp->csock, ".", NGM_GENERIC_COOKIE, NGM_MKPEER,
		    &mkp, sizeof(mkp)) < 0) {
			Log(LG_PHYS, ("[%s] can't attach %s node: %s",
			    lnk->name, NG_KSOCKET_NODE_TYPE, strerror(errno)));
			goto fail;
		}

		/* Bind socket. */
		memset(&addr, 0, sizeof(addr));
		addr.sin_len = sizeof(addr);
		addr.sin_family = AF_INET;
		addr.sin_addr = tcp->self_addr;
		addr.sin_port = htons(tcp->self_port);
		if (NgSendMsg(tcp->csock, LISTENHOOK, NGM_KSOCKET_COOKIE,
		    NGM_KSOCKET_BIND, &addr, sizeof(addr)) < 0) {
			Log(LG_PHYS, ("[%s] can't bind %s node: %s",
			    lnk->name, NG_KSOCKET_NODE_TYPE, strerror(errno)));
			goto fail;
		}

		/* Listen. */
		if (NgSendMsg(tcp->csock, LISTENHOOK, NGM_KSOCKET_COOKIE,
		    NGM_KSOCKET_LISTEN, &backlog, sizeof(backlog)) < 0) {
			Log(LG_PHYS, ("[%s] can't listen on %s node: %s",
			    lnk->name, NG_KSOCKET_NODE_TYPE, strerror(errno)));
			goto fail;
		}

		/* Tell that we are willing to receive accept message. */
		if (NgSendMsg(tcp->csock, LISTENHOOK, NGM_KSOCKET_COOKIE,
		    NGM_KSOCKET_ACCEPT, NULL, 0) < 0) {
			Log(LG_PHYS, ("[%s] can't accept on %s node: %s",
			    lnk->name, NG_KSOCKET_NODE_TYPE, strerror(errno)));
			goto fail;
		}

		Log(LG_PHYS, ("[%s] waiting for connection on %s:%u",
		    lnk->name, inet_ntoa(tcp->self_addr), tcp->self_port));
		EventRegister(&tcp->ev_accept, EVENT_READ, tcp->csock,
		    0, TcpAcceptEvent, lnk);
	} else
		assert(0);

	return;
fail:
	TcpDoClose(tcp);
	PhysDown(STR_ERROR, NULL);
}

/*
 * TcpConnectEvent() triggers when outgoing connection succeeds.
 */
static void
TcpConnectEvent(int type, void *cookie)
{
	struct {
		struct ng_mesg	resp;
		int32_t		rval;
	} cn;
	TcpInfo	tcp;
	char path[NG_PATHLEN + 1];

	/* Restore context. */
	lnk = (Link) cookie;
	bund = lnk->bund;
	tcp = (TcpInfo) lnk->phys->info;

	assert(type == EVENT_READ);
	assert(tcp->origination == LINK_ORIGINATE_LOCAL);

	/* Get absolute path of TCP ksocket node. */
	snprintf(path, sizeof(path), "[%x]:%s%d.%s", bund->nodeID,
	    NG_PPP_HOOK_LINK_PREFIX, lnk->bundleIndex, NG_ASYNC_HOOK_SYNC);

	/* Check whether the connection was successful or not. */
	if (NgRecvMsg(tcp->csock, &cn.resp, sizeof(cn), path) < 0) {
		Log(LG_ERR, ("[%s] error reading message from \"%s\": %s",
		    lnk->name, path, strerror(errno)));
		goto failed;
	}

	assert(cn.resp.header.typecookie != NGM_KSOCKET_COOKIE);
	assert(cn.resp.header.cmd != NGM_KSOCKET_CONNECT);

	if (cn.rval != 0) {
		Log(LG_PHYS, ("[%s] failed to connect: %s", lnk->name,
		    strerror(cn.rval)));
		goto failed;
	}

	/* Report connected. */
	Log(LG_PHYS, ("[%s] connection established", lnk->name));
	PhysUp();

	return;
failed:
	TcpDoClose(tcp);
	PhysDown(STR_ERROR, NULL);
}

/*
 * TcpAcceptEvent() triggers when we accept incoming connection.
 */
static void
TcpAcceptEvent(int type, void *cookie)
{
	struct {
		struct ng_mesg	resp;
		uint32_t	id;
		struct sockaddr_in sin;
	} ac;
	TcpInfo	tcp;
	struct ngm_connect cn;
	char path[NG_PATHLEN + 1];

	/* Restore context. */
	lnk = (Link) cookie;
	bund = lnk->bund;
	tcp = (TcpInfo) lnk->phys->info;

	assert(type == EVENT_READ);
	assert(tcp->origination == LINK_ORIGINATE_REMOTE);

	/* Accept cloned ng_ksocket(4). */
	if (NgRecvMsg(tcp->csock, &ac.resp, sizeof(ac), NULL) < 0) {
		Log(LG_ERR, ("[%s] error reading message from \"%s\": %s",
		    lnk->name, path, strerror(errno)));
		goto failed;
	}

	Log(LG_PHYS, ("[%s] incoming connection from %s:%u", lnk->name,
	    inet_ntoa(ac.sin.sin_addr), ntohs(ac.sin.sin_port)));

	/*
	 * If passive, and peer address specified,
	 * only accept from that address. Same check with port.
	 */
	if (tcp->peer_addr.s_addr != 0 &&
	    tcp->peer_addr.s_addr != ac.sin.sin_addr.s_addr) {
		Log(LG_PHYS, ("[%s] rejected: wrong IP address", lnk->name));
		goto failed;
	}
	if (tcp->peer_port != 0 &&
	    tcp->peer_port != ntohs(ac.sin.sin_port)) {
		Log(LG_PHYS, ("[%s] rejected: wrong port", lnk->name));
		goto failed;
	}
	memcpy(&tcp->sin_peer, &ac.sin, sizeof(tcp->sin_peer));

	/* Connect new born ksocket to our link. */
	snprintf(cn.path, sizeof(cn.path), "[%x]:", ac.id);
	snprintf(cn.ourhook, sizeof(cn.ourhook), NG_ASYNC_HOOK_ASYNC);
	snprintf(cn.peerhook, sizeof(cn.peerhook), "data");
	snprintf(path, sizeof(path), "[%x]:%s%d.%s", bund->nodeID,
	    NG_PPP_HOOK_LINK_PREFIX, lnk->bundleIndex, NG_ASYNC_HOOK_SYNC);
	if (NgSendMsg(bund->csock, path, NGM_GENERIC_COOKIE, NGM_CONNECT,
	    &cn, sizeof(cn)) < 0) {
		Log(LG_ERR, ("[%s] can't connect new born ksocket: %s",
		    lnk->name, strerror(errno)));
		goto failed;
  	}

	/* Report connected. */
	Log(LG_PHYS, ("[%s] connected with %s:%u", lnk->name,
	    inet_ntoa(ac.sin.sin_addr), ntohs(ac.sin.sin_port)));
	PhysUp();

	return;

failed:
	TcpDoClose(tcp);
	PhysDown(STR_ERROR, NULL);
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
	char hook[NG_HOOKLEN + 1];

	EventUnRegister(&tcp->ev_connect);
	EventUnRegister(&tcp->readEvent);
	EventUnRegister(&tcp->writeEvent);
	snprintf(hook, sizeof(hook), "%s%d", NG_PPP_HOOK_LINK_PREFIX,
	    lnk->bundleIndex);
	NgFuncDisconnect(MPD_HOOK_PPP, hook);
	close(tcp->csock);
	close(tcp->dsock);
}

/*
 * TcpOriginated()
 */

static int
TcpOriginated(PhysInfo p)
{
	TcpInfo const tcp = (TcpInfo) lnk->phys->info;

	return (tcp->origination ?
	    LINK_ORIGINATE_LOCAL : LINK_ORIGINATE_REMOTE);
}

static int
TcpPeerAddr(PhysInfo p, void *buf, int buf_len)
{
	TcpInfo const tcp = (TcpInfo) p;

	if (inet_ntop(AF_INET, &tcp->peer_addr, buf, buf_len))
		return (0);
  	else
		return (-1);
}

/*
 * TcpStat()
 */

void
TcpStat(PhysInfo p)
{
	TcpInfo const tcp = (TcpInfo) lnk->phys->info;

	Printf("TCP configuration:\r\n");
	Printf("\tSelf address : %s, port %u\r\n",
	    inet_ntoa(tcp->self_addr), tcp->self_port);
	Printf("\tPeer address : %s, port %u\r\n",
	    inet_ntoa(tcp->peer_addr), tcp->peer_port);
	Printf("\tConnect mode : %s\r\n",
	    tcp->origination == LINK_ORIGINATE_LOCAL ?
	    "local" : "remote");
}

/*
 * TcpSetCommand()
 */

static int
TcpSetCommand(int ac, char *av[], void *arg)
{
	TcpInfo	const tcp = (TcpInfo) lnk->phys->info;
	struct sockaddr_in *sin;   
  
	switch ((intptr_t)arg) {
	case SET_PEERADDR:
		if ((sin = ParseAddrPort(ac, av)) == NULL)
			return (-1);
		tcp->peer_addr = sin->sin_addr;
		tcp->peer_port = ntohs(sin->sin_port);
		break;
	case SET_SELFADDR:
		if ((sin = ParseAddrPort(ac, av)) == NULL)
			return (-1);
		tcp->self_addr = sin->sin_addr;
		tcp->self_port = ntohs(sin->sin_port);
		break;
	case SET_ORIGINATION:
		if (ac != 1)
			return (-1);
		if (strcasecmp(av[0], "local") == 0) {
			tcp->origination = LINK_ORIGINATE_LOCAL;
			break;
		}
		if (strcasecmp(av[0], "remote") == 0) {
			tcp->origination = LINK_ORIGINATE_REMOTE;
			break;
      		}
		Log(LG_ERR, ("Invalid link origination \"%s\"", av[0]));
		return (-1);

	default:
		assert(0);
	}

	return (0);
}
