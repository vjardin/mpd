
/*
 * tcp.c
 *
 * Written by Alexander Motin <mav@alkar.net>
 */

#include "ppp.h"
#include "phys.h"
#include "mbuf.h"
#include "ngfunc.h"
#include "tcp.h"
#include "log.h"

#include <netgraph/ng_message.h>
#ifdef __DragonFly__
#include <netgraph/socket/ng_socket.h>
#include <netgraph/async/ng_async.h>
#include <netgraph/ksocket/ng_ksocket.h>
#else
#include <netgraph/ng_socket.h>
#include <netgraph/ng_async.h>
#include <netgraph/ng_ksocket.h>
#endif
#include <netgraph.h>

/*
 * DEFINITIONS
 */

#define TCP_MTU		2048
#define TCP_MRU		2048
#define TCP_REOPEN_PAUSE	5
#define LISTENHOOK		"listen"

#define TCP_MAXPARENTIFS	256

struct tcpinfo {
	/* Configuration */
	struct	{
	    struct optinfo  	options;
	    struct u_addr	self_addr;
	    struct u_addr	peer_addr;
	    in_port_t		self_port;
	    in_port_t		peer_port;
	} conf;

	/* State */
	u_char		incoming:1;		/* incoming vs. outgoing */
	struct TcpIf 	*If;
	int		csock;
	struct u_addr	peer_addr;
	in_port_t	peer_port;
	EventRef	ev_connect;
};

typedef struct tcpinfo	*TcpInfo;

/* Set menu options */
enum {
	SET_PEERADDR,
	SET_SELFADDR,
	SET_ENABLE,
	SET_DISABLE,
};

enum {
	TCP_CONF_ORIGINATE,	/* allow originating connections to peer */
	TCP_CONF_INCOMING,	/* allow accepting connections from peer */
};

/*
 * INTERNAL FUNCTIONS
 */

static int	TcpInit(PhysInfo p);
static void	TcpOpen(PhysInfo p);
static void	TcpClose(PhysInfo p);
static void	TcpShutdown(PhysInfo p);
static void	TcpStat(PhysInfo p);
static int	TcpOriginate(PhysInfo p);
static int	TcpPeerAddr(PhysInfo p, void *buf, int buf_len);
static int	TcpCallingNum(PhysInfo p, void *buf, int buf_len);
static int	TcpCalledNum(PhysInfo p, void *buf, int buf_len);

static void	TcpDoClose(PhysInfo p);
static int	TcpAsyncConfig(PhysInfo p);
static void	TcpAcceptEvent(int type, void *cookie);
static void	TcpConnectEvent(int type, void *cookie);

static int	TcpSetCommand(int ac, char *av[], void *arg);

/*
 * GLOBAL VARIABLES
 */

const struct phystype gTcpPhysType = {
	.name		= "tcp",
	.synchronous	= TRUE,
	.minReopenDelay	= TCP_REOPEN_PAUSE,
	.mtu		= TCP_MTU,
	.mru		= TCP_MRU,
	.init		= TcpInit,
	.open		= TcpOpen,
	.close		= TcpClose,
	.shutdown	= TcpShutdown,
	.showstat	= TcpStat,
	.originate	= TcpOriginate,
	.peeraddr	= TcpPeerAddr,
	.callingnum	= TcpCallingNum,
	.callednum	= TcpCalledNum,
};

const struct cmdtab TcpSetCmds[] = {
    { "self ip [port]",			"Set local IP address",
	TcpSetCommand, NULL, (void *) SET_SELFADDR },
    { "peer ip [port]",			"Set remote IP address",
	TcpSetCommand, NULL, (void *) SET_PEERADDR },
    { "enable [opt ...]",		"Enable option",
	TcpSetCommand, NULL, (void *) SET_ENABLE },
    { "disable [opt ...]",		"Disable option",
	TcpSetCommand, NULL, (void *) SET_DISABLE },
    { NULL },
};

static struct confinfo	gConfList[] = {
    { 0,	TCP_CONF_ORIGINATE,	"originate"	},
    { 0,	TCP_CONF_INCOMING,	"incoming"	},
    { 0,	0,			NULL		},
};

struct TcpIf {
    struct u_addr	self_addr;
    in_port_t	self_port;
    int		csock;                  /* netgraph Control socket */
    EventRef	ctrlEvent;		/* listen for ctrl messages */
};
int TcpIfCount=0;
struct TcpIf TcpIfs[TCP_MAXPARENTIFS];

int TcpListenUpdateSheduled=0;
struct pppTimer TcpListenUpdateTimer;

/*
 * TcpInit()
 */

static int
TcpInit(PhysInfo p)
{
	TcpInfo pi;

	pi = (TcpInfo) (p->info = Malloc(MB_PHYS, sizeof(*pi)));

	u_addrclear(&pi->conf.self_addr);
	u_addrclear(&pi->conf.peer_addr);
	pi->conf.self_port=0;
	pi->conf.peer_port=0;

	pi->incoming = 0;
	pi->If = NULL;
	pi->csock = -1;

	u_addrclear(&pi->peer_addr);
	pi->peer_port=0;

	/* Attach async node to PPP node. */
	if (TcpAsyncConfig(p))
	    return -1;

	return (0);
}

static int
TcpAsyncConfig(PhysInfo p)
{
	struct ngm_mkpeer mkp;
	struct ng_async_cfg	acfg;
	char path[NG_PATHLEN + 1];

	snprintf(mkp.type, sizeof(mkp.type), "%s", NG_ASYNC_NODE_TYPE);
	snprintf(mkp.ourhook, sizeof(mkp.ourhook), "%s%d",
	    NG_PPP_HOOK_LINK_PREFIX, p->link->bundleIndex);
	snprintf(mkp.peerhook, sizeof(mkp.peerhook), NG_ASYNC_HOOK_SYNC);
	if (NgSendMsg(bund->csock, MPD_HOOK_PPP, NGM_GENERIC_COOKIE,
	    NGM_MKPEER, &mkp, sizeof(mkp)) < 0) {
		Log(LG_ERR, ("[%s] can't attach %s %s node: %s",
		    p->name, NG_ASYNC_NODE_TYPE, mkp.ourhook, strerror(errno)));
		return (errno);
	}
	
	/* Configure the async converter node. */
	memset(&acfg, 0, sizeof(acfg));
	acfg.enabled = TRUE;
	acfg.accm = 0;  /* we do not need thie on TCP */
	acfg.amru = TCP_MRU;
	acfg.smru = TCP_MTU;
	snprintf(path, sizeof(path), ".:%s.%s%d", MPD_HOOK_PPP,
	    NG_PPP_HOOK_LINK_PREFIX, p->link->bundleIndex);
	if (NgSendMsg(bund->csock, path, NGM_ASYNC_COOKIE,
	    NGM_ASYNC_CMD_SET_CONFIG, &acfg, sizeof(acfg)) < 0) {
		Log(LG_ERR, ("[%s] can't config %s", p->name, path));
		return (errno);
	}

	return (0);
}

/*
 * TcpOpen()
 */

static void
TcpOpen(PhysInfo p)
{
	TcpInfo	const pi = (TcpInfo) p->info;
	struct ngm_mkpeer mkp;
	char path[NG_PATHLEN + 1];
	struct sockaddr_storage addr;
	int rval;
	char buf[64];

	if (pi->incoming) {
		Log(LG_PHYS2, ("[%s] %s() on incoming call", p->name,
		    __func__));
		p->state = PHYS_STATE_UP;
		PhysUp(p);
		return;
	}

	if (!Enabled(&pi->conf.options, TCP_CONF_ORIGINATE)) {
		Log(LG_ERR, ("[%s] Originate option is not enabled",
		    p->name));
		p->state = PHYS_STATE_DOWN;
		TcpDoClose(p);
		PhysDown(p, STR_DEV_NOT_READY, NULL);
		return;
	};

	u_addrcopy(&pi->conf.peer_addr,&pi->peer_addr);
	pi->conf.peer_port = pi->peer_port;

	/* Create a new netgraph node to control TCP ksocket node. */
	if (NgMkSockNode(NULL, &pi->csock, NULL) < 0) {
		Log(LG_ERR, ("[%s] TCP can't create control socket: %s",
		    p->name, strerror(errno)));
		goto fail;
	}
	(void)fcntl(pi->csock, F_SETFD, 1);

	/*
	 * Attach fresh ksocket node next to async node.
	 */
	snprintf(mkp.type, sizeof(mkp.type), "%s", NG_KSOCKET_NODE_TYPE);
	snprintf(mkp.ourhook, sizeof(mkp.ourhook), NG_ASYNC_HOOK_ASYNC);
	if ((pi->conf.self_addr.family==AF_INET6) || 
	    (pi->conf.self_addr.family==AF_UNSPEC && pi->conf.peer_addr.family==AF_INET6)) {
	    snprintf(mkp.peerhook, sizeof(mkp.peerhook), "%d/%d/%d", PF_INET6, SOCK_STREAM, IPPROTO_TCP);
	} else {
	    snprintf(mkp.peerhook, sizeof(mkp.peerhook), "inet/stream/tcp");
	}
	snprintf(path, sizeof(path), "[%x]:%s%d", bund->nodeID,
	    NG_PPP_HOOK_LINK_PREFIX, lnk->bundleIndex);
	if (NgSendMsg(pi->csock, path, NGM_GENERIC_COOKIE, NGM_MKPEER, &mkp,
	    sizeof(mkp)) < 0) {
		Log(LG_ERR, ("[%s] can't attach %s node: %s", p->name,
		    NG_KSOCKET_NODE_TYPE, strerror(errno)));
		goto fail;
	}

	/* Start connecting to peer. */
	u_addrtosockaddr(&pi->peer_addr, pi->peer_port, &addr);
	snprintf(path, sizeof(path), "[%x]:%s%d.%s", bund->nodeID,
	    NG_PPP_HOOK_LINK_PREFIX, lnk->bundleIndex, NG_ASYNC_HOOK_ASYNC);
	rval = NgSendMsg(pi->csock, path, NGM_KSOCKET_COOKIE,
	    NGM_KSOCKET_CONNECT, &addr, addr.ss_len);
	if (rval < 0 && errno != EINPROGRESS) {
		Log(LG_ERR, ("[%s] can't connect() %s node: %s", p->name,
		    NG_KSOCKET_NODE_TYPE, strerror(errno))); 
		goto fail;
	}

	p->state = PHYS_STATE_CONNECTING;

	if (rval == 0)	/* Can happen when peer is local. */
		TcpConnectEvent(EVENT_READ, p);
	else {
		assert(errno == EINPROGRESS);
		EventRegister(&pi->ev_connect, EVENT_READ, pi->csock,
		    0, TcpConnectEvent, p);
		Log(LG_PHYS, ("[%s] connecting to %s %u", p->name,
		    u_addrtoa(&pi->conf.peer_addr, buf, sizeof(buf)), pi->conf.peer_port));
	}

	return;
fail:
	p->state = PHYS_STATE_DOWN;
	TcpDoClose(p);
	PhysDown(p, STR_ERROR, NULL);
}

/*
 * TcpConnectEvent() triggers when outgoing connection succeeds/fails.
 */

static void
TcpConnectEvent(int type, void *cookie)
{
	struct {
		struct ng_mesg	resp;
		int32_t		rval;
	} cn;
	PhysInfo	p;
	TcpInfo		pi;
	char path[NG_PATHLEN + 1];

	/* Restore context. */
	p = (PhysInfo)cookie;
	pi = (TcpInfo)p->info;
	lnk = p->link;
	bund = lnk->bund;

	assert(type == EVENT_READ);

	/* Check whether the connection was successful or not. */
	if (NgRecvMsg(pi->csock, &cn.resp, sizeof(cn), path) < 0) {
		Log(LG_ERR, ("[%s] error reading message from \"%s\": %s",
		    p->name, path, strerror(errno)));
		goto failed;
	}

	assert(cn.resp.header.typecookie == NGM_KSOCKET_COOKIE);
	assert(cn.resp.header.cmd == NGM_KSOCKET_CONNECT);

	if (cn.rval != 0) {
		Log(LG_PHYS, ("[%s] failed to connect: %s", p->name,
		    strerror(cn.rval)));
		goto failed;
	}

	/* Report connected. */
	Log(LG_PHYS, ("[%s] connection established", p->name));

	p->state = PHYS_STATE_UP;
	PhysUp(p);

	return;
failed:
	p->state = PHYS_STATE_DOWN;
	TcpDoClose(p);
	PhysDown(p, STR_ERROR, NULL);

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
		struct sockaddr_storage sin;
	} ac;
	struct ngm_connect cn;
	char path[NG_PATHLEN + 1];
	struct u_addr	addr;
	in_port_t	port;
	char		buf[64];
	int 		k;
	struct TcpIf 	*If=(struct TcpIf *)(cookie);
	time_t const 	now = time(NULL);

	assert(type == EVENT_READ);

	/* Accept cloned ng_ksocket(4). */
	if (NgRecvMsg(If->csock, &ac.resp, sizeof(ac), NULL) < 0) {
		Log(LG_ERR, ("TCP: error reading message from \"%s\": %s",
		    path, strerror(errno)));
		goto failed;
	}
	sockaddrtou_addr(&ac.sin, &addr, &port);

	Log(LG_PHYS, ("Incoming TCP connection from %s %u",
	    u_addrtoa(&addr, buf, sizeof(buf)), port));

	if (gShutdownInProgress) {
		Log(LG_PHYS, ("Shutdown sequence in progress, ignoring"));
		return;
	}

	/* Examine all TCP links. */
	for (k = 0; k < gNumPhyses; k++) {
		PhysInfo p;
	        TcpInfo pi;

		if (gPhyses[k] && gPhyses[k]->type != &gTcpPhysType)
			continue;

		p = gPhyses[k];
		pi = (TcpInfo)p->info;

		if ((If!=pi->If) ||
		    (p->state != PHYS_STATE_DOWN) ||
		    (now-p->lastClose < TCP_REOPEN_PAUSE) ||
		    !Enabled(&pi->conf.options, TCP_CONF_INCOMING) ||
		    ((!u_addrempty(&pi->conf.peer_addr)) && u_addrcompare(&pi->conf.peer_addr, &addr)) ||
		    (pi->conf.peer_port != 0 && pi->conf.peer_port != port))
			continue;

		/* Restore context. */
		lnk = p->link;
		bund = lnk->bund;

		Log(LG_PHYS, ("[%s] Accepting connection", p->name));

		sockaddrtou_addr(&ac.sin, &pi->peer_addr, &pi->peer_port);

		/* Connect new born ksocket to our link. */
		snprintf(cn.path, sizeof(cn.path), "[%x]:", ac.id);
		snprintf(cn.ourhook, sizeof(cn.ourhook), NG_ASYNC_HOOK_ASYNC);
		snprintf(cn.peerhook, sizeof(cn.peerhook), "data");
		snprintf(path, sizeof(path), "[%x]:%s%d", bund->nodeID,
		    NG_PPP_HOOK_LINK_PREFIX, lnk->bundleIndex);
		if (NgSendMsg(bund->csock, path, NGM_GENERIC_COOKIE, NGM_CONNECT,
		    &cn, sizeof(cn)) < 0) {
			Log(LG_ERR, ("[%s] can't connect new born ksocket: %s",
			    p->name, strerror(errno)));
			goto failed;
	  	}

		pi->incoming=1;
		p->state = PHYS_STATE_READY;

		/* Report connected. */
		Log(LG_PHYS, ("[%s] connected with %s %u", p->name,
		    u_addrtoa(&addr, buf, sizeof(buf)), port));

		PhysIncoming(p);

		break;
	}

	if (k == gNumLinks) {
	    Log(LG_PHYS, ("No free TCP link with requested parameters "
	        "was found"));
	    snprintf(path, sizeof(path), "[%x]:", ac.id);
	    NgFuncShutdownNode(bund, "", path);
	}

failed:
	/* Tell that we are willing to receive accept message. */
	if (NgSendMsg(If->csock, LISTENHOOK, NGM_KSOCKET_COOKIE,
	    NGM_KSOCKET_ACCEPT, NULL, 0) < 0) {
		Log(LG_ERR, ("TCP: can't accept on %s node: %s",
		    NG_KSOCKET_NODE_TYPE, strerror(errno)));
	}
	EventRegister(&If->ctrlEvent, EVENT_READ, If->csock,
	    0, TcpAcceptEvent, If);
}

/*
 * TcpClose()
 */

static void
TcpClose(PhysInfo p)
{
	TcpInfo const pi = (TcpInfo) p->info;

	TcpDoClose(p);

	if (p->state != PHYS_STATE_DOWN) {
	    pi->incoming=0;
	    p->state = PHYS_STATE_DOWN;

	    u_addrclear(&pi->peer_addr);
	    pi->peer_port=0;

	    PhysDown(p, 0, NULL);
	}
}

/*
 * TcpShutdown()
 */

static void
TcpShutdown(PhysInfo p)
{
	char path[NG_PATHLEN + 1];

	TcpDoClose(p);

	snprintf(path, sizeof(path), "[%x]:%s%d", bund->nodeID,
	    NG_PPP_HOOK_LINK_PREFIX, lnk->bundleIndex);
	NgFuncShutdownNode(bund, bund->name, path);
}

/*
 * TcpDoClose()
 */

static void
TcpDoClose(PhysInfo p)
{
	char path[NG_PATHLEN + 1];
	TcpInfo const pi = (TcpInfo) p->info;

	if (pi->csock>=0) {
	    close(pi->csock);
	    pi->csock = -1;
	}

	snprintf(path, sizeof(path), "[%x]:%s%d", bund->nodeID,
	    NG_PPP_HOOK_LINK_PREFIX, lnk->bundleIndex);
	NgFuncDisconnect(path, NG_ASYNC_HOOK_ASYNC);
	EventUnRegister(&pi->ev_connect);
}

/*
 * TcpOriginate()
 */

static int
TcpOriginate(PhysInfo p)
{
	TcpInfo const pi = (TcpInfo) p->info;

	return (pi->incoming ? LINK_ORIGINATE_REMOTE : LINK_ORIGINATE_LOCAL);
}

static int
TcpPeerAddr(PhysInfo p, void *buf, int buf_len)
{
	TcpInfo const pi = (TcpInfo) p->info;

	if (u_addrtoa(&pi->peer_addr, buf, buf_len))
		return (0);
  	else
		return (-1);
}

static int
TcpCallingNum(PhysInfo p, void *buf, int buf_len)
{
	TcpInfo const pi = (TcpInfo) p->info;

	if (pi->incoming) {
	    if (u_addrtoa(&pi->peer_addr, buf, buf_len))
	    	return (0);
  	    else
		return (-1);
	} else {
	    if (u_addrtoa(&pi->conf.self_addr, buf, buf_len))
	    	return (0);
  	    else
		return (-1);
	}
}

static int
TcpCalledNum(PhysInfo p, void *buf, int buf_len)
{
	TcpInfo const pi = (TcpInfo) p->info;

	if (!pi->incoming) {
	    if (u_addrtoa(&pi->peer_addr, buf, buf_len))
	    	return (0);
  	    else
		return (-1);
	} else {
	    if (u_addrtoa(&pi->conf.self_addr, buf, buf_len))
	    	return (0);
  	    else
		return (-1);
	}
}

/*
 * TcpStat()
 */

void
TcpStat(PhysInfo p)
{
	TcpInfo const pi = (TcpInfo) p->info;
	char	buf[64];

	Printf("TCP configuration:\r\n");
	Printf("\tSelf address : %s, port %u\r\n",
	    u_addrtoa(&pi->conf.self_addr, buf, sizeof(buf)), pi->conf.self_port);
	Printf("\tPeer address : %s, port %u\r\n",
	    u_addrtoa(&pi->conf.peer_addr, buf, sizeof(buf)), pi->conf.peer_port);
	Printf("TCP options:\r\n");
	OptStat(&pi->conf.options, gConfList);
	Printf("TCP state:\r\n");
	Printf("\tState        : %s\r\n", gPhysStateNames[p->state]);
	if (p->state != PHYS_STATE_DOWN) {
	    Printf("\tIncoming     : %s\r\n", (pi->incoming?"YES":"NO"));
	    Printf("\tCurrent peer : %s, port %u\r\n",
		u_addrtoa(&pi->peer_addr, buf, sizeof(buf)), pi->peer_port);
	}
}

static int 
ListenTcpNode(struct TcpIf *If)
{
	struct ngm_mkpeer mkp;
	struct sockaddr_storage addr;
	int32_t backlog = 1;
	int error;
	char buf[64];
	union {
	    u_char buf[sizeof(struct ng_ksocket_sockopt) + sizeof(int)];
	    struct ng_ksocket_sockopt ksso;
	} u;
	struct ng_ksocket_sockopt *const ksso = &u.ksso;
	
	/* Create a new netgraph node */
	if (NgMkSockNode(NULL, &If->csock, NULL) < 0) {
	    Log(LG_ERR, ("TCP: can't create ctrl socket: %s",
	        strerror(errno)));
	    return(0);
	}
	(void)fcntl(If->csock, F_SETFD, 1);

	/* Make listening TCP ksocket node. */
	snprintf(mkp.type, sizeof(mkp.type), "%s",
	    NG_KSOCKET_NODE_TYPE);
	snprintf(mkp.ourhook, sizeof(mkp.ourhook), LISTENHOOK);
	if (If->self_addr.family==AF_INET6) {
	    snprintf(mkp.peerhook, sizeof(mkp.peerhook), "%d/%d/%d", PF_INET6, SOCK_STREAM, IPPROTO_TCP);
	} else {
	    snprintf(mkp.peerhook, sizeof(mkp.peerhook), "inet/stream/tcp");
	}
	if (NgSendMsg(If->csock, ".", NGM_GENERIC_COOKIE, NGM_MKPEER,
	    &mkp, sizeof(mkp)) < 0) {
		Log(LG_ERR, ("TCP: can't attach %s node: %s",
		    NG_KSOCKET_NODE_TYPE, strerror(errno)));
		error = errno;
		goto fail2;
	}

	/* Setsockopt socket. */
	ksso->level=SOL_SOCKET;
	ksso->name=SO_REUSEPORT;
	((int *)(ksso->value))[0]=1;
	if (NgSendMsg(If->csock, LISTENHOOK, NGM_KSOCKET_COOKIE,
	    NGM_KSOCKET_SETOPT, &u, sizeof(u)) < 0) {
		Log(LG_ERR, ("TCP: can't setsockopt() %s node: %s",
		    NG_KSOCKET_NODE_TYPE, strerror(errno)));
		error = errno;
		goto fail2;
	}

	/* Bind socket. */
	u_addrtosockaddr(&If->self_addr, If->self_port, &addr);
	if (NgSendMsg(If->csock, LISTENHOOK, NGM_KSOCKET_COOKIE,
	    NGM_KSOCKET_BIND, &addr, addr.ss_len) < 0) {
		Log(LG_ERR, ("TCP: can't bind() %s node: %s",
		    NG_KSOCKET_NODE_TYPE, strerror(errno)));
		error = errno;
		goto fail2;
	}

	/* Listen. */
	if (NgSendMsg(If->csock, LISTENHOOK, NGM_KSOCKET_COOKIE,
	    NGM_KSOCKET_LISTEN, &backlog, sizeof(backlog)) < 0) {
		Log(LG_ERR, ("TCP: can't listen() on %s node: %s",
		    NG_KSOCKET_NODE_TYPE, strerror(errno)));
		error = errno;
		goto fail2;
	}

	/* Tell that we are willing to receive accept message. */
	if (NgSendMsg(If->csock, LISTENHOOK, NGM_KSOCKET_COOKIE,
	    NGM_KSOCKET_ACCEPT, NULL, 0) < 0) {
		Log(LG_ERR, ("TCP: can't accept() on %s node: %s",
		    NG_KSOCKET_NODE_TYPE, strerror(errno)));
		error = errno;
		goto fail2;
	}

	Log(LG_PHYS, ("TCP: waiting for connection on %s %u",
	    u_addrtoa(&If->self_addr, buf, sizeof(buf)), If->self_port));
	EventRegister(&If->ctrlEvent, EVENT_READ, If->csock,
	    0, TcpAcceptEvent, If);

	return (1);
fail2:
	NgSendMsg(If->csock, LISTENHOOK, NGM_GENERIC_COOKIE, NGM_SHUTDOWN,
	    NULL, 0);
	return (0);
};

/*
 * TcpListenUpdate()
 */

static void
TcpListenUpdate(void *arg)
{
	int k;

	TcpListenUpdateSheduled = 0;

	/* Examine all PPPoE links. */
	for (k = 0; k < gNumPhyses; k++) {
        	PhysInfo p;
        	TcpInfo pi;
		int i, j = -1;

		if (gPhyses[k] == NULL ||
		    gPhyses[k]->type != &gTcpPhysType)
			continue;

		p = gPhyses[k];
		pi = (TcpInfo)p->info;

		if (!Enabled(&pi->conf.options, TCP_CONF_INCOMING))
			continue;

		if (!pi->conf.self_port) {
			Log(LG_ERR, ("Tcp: Skipping link %s with undefined "
			    "port number", p->name));
			continue;
		}

		for (i = 0; i < TcpIfCount; i++)
			if ((u_addrcompare(&TcpIfs[i].self_addr, &pi->conf.self_addr) == 0) &&
			    (TcpIfs[i].self_port == pi->conf.self_port))
				j = i;

		if (j == -1) {
			if (TcpIfCount>=TCP_MAXPARENTIFS) {
			    Log(LG_ERR, ("[%s] TCP: Too many different parent interfaces! ", 
				p->name));
			    continue;
			}
			u_addrcopy(&pi->conf.self_addr,&TcpIfs[TcpIfCount].self_addr);
			TcpIfs[TcpIfCount].self_port=pi->conf.self_port;

			if (ListenTcpNode(&(TcpIfs[TcpIfCount]))) {

				pi->If=&TcpIfs[TcpIfCount];
				TcpIfCount++;
			}
		} else {
			pi->If=&TcpIfs[j];
		}
	}
}

/*
 * TcpNodeUpdate()
 */

static void
TcpNodeUpdate(PhysInfo p)
{
  TcpInfo pi = (TcpInfo)p->info;

  if (Enabled(&pi->conf.options, TCP_CONF_INCOMING) &&
        (!TcpListenUpdateSheduled)) {
    	    /* Set a timer to run TcpListenUpdate(). */
	    TimerInit(&TcpListenUpdateTimer, "TcpListenUpdate",
		0, TcpListenUpdate, NULL);
	    TimerStart(&TcpListenUpdateTimer);
	    TcpListenUpdateSheduled = 1;
  }
}

/*
 * TcpSetCommand()
 */

static int
TcpSetCommand(int ac, char *av[], void *arg)
{
	TcpInfo	const pi = (TcpInfo) lnk->phys->info;
	struct sockaddr_storage *sin;   

	switch ((intptr_t)arg) {
	case SET_PEERADDR:
		if ((sin = ParseAddrPort(ac, av, ALLOW_IPV4|ALLOW_IPV6)) == NULL)
			return (-1);
		sockaddrtou_addr(sin, &pi->conf.peer_addr, &pi->conf.peer_port);
		break;
	case SET_SELFADDR:
		if ((sin = ParseAddrPort(ac, av, ALLOW_IPV4|ALLOW_IPV6)) == NULL)
			return (-1);
		sockaddrtou_addr(sin, &pi->conf.self_addr, &pi->conf.self_port);
		break;
	case SET_ENABLE:
		EnableCommand(ac, av, &pi->conf.options, gConfList);
    	    	TcpNodeUpdate(lnk->phys);
        	break;
        case SET_DISABLE:
    		DisableCommand(ac, av, &pi->conf.options, gConfList);
    		break;

	default:
		assert(0);
	}

	return (0);
}
