
/*
 * tcp.c
 *
 * Written by Alexander Motin <mav@FreeBSD.org>
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
	    struct u_range	peer_addr;
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
	ng_ID_t		async_node_id;
	ng_ID_t		node_id;
};

typedef struct tcpinfo	*TcpInfo;

/* Set menu options */
enum {
	SET_PEERADDR,
	SET_SELFADDR,
	SET_ENABLE,
	SET_DISABLE,
};

/*
 * INTERNAL FUNCTIONS
 */

static int	TcpInit(Link l);
static int	TcpInst(Link l, Link lt);
static void	TcpOpen(Link l);
static void	TcpClose(Link l);
static void	TcpShutdown(Link l);
static void	TcpStat(Context ctx);
static int	TcpOriginate(Link l);
static int	TcpIsSync(Link l);
static int	TcpPeerAddr(Link l, void *buf, int buf_len);
static int	TcpPeerPort(Link l, void *buf, int buf_len);
static int	TcpCallingNum(Link l, void *buf, int buf_len);
static int	TcpCalledNum(Link l, void *buf, int buf_len);

static void	TcpDoClose(Link l);
static void	TcpAcceptEvent(int type, void *cookie);
static void	TcpConnectEvent(int type, void *cookie);

static int	TcpSetCommand(Context ctx, int ac, char *av[], void *arg);
static void	TcpNodeUpdate(Link l);

/*
 * GLOBAL VARIABLES
 */

const struct phystype gTcpPhysType = {
	.name		= "tcp",
	.descr		= "PPP over TCP",
	.minReopenDelay	= TCP_REOPEN_PAUSE,
	.mtu		= TCP_MTU,
	.mru		= TCP_MRU,
	.tmpl		= 1,
	.init		= TcpInit,
	.inst		= TcpInst,
	.open		= TcpOpen,
	.close		= TcpClose,
	.update		= TcpNodeUpdate,
	.shutdown	= TcpShutdown,
	.showstat	= TcpStat,
	.originate	= TcpOriginate,
	.issync		= TcpIsSync,
	.peeraddr	= TcpPeerAddr,
	.peerport	= TcpPeerPort,
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
TcpInit(Link l)
{
	TcpInfo pi;

	pi = (TcpInfo) (l->info = Malloc(MB_PHYS, sizeof(*pi)));

	u_addrclear(&pi->conf.self_addr);
	u_rangeclear(&pi->conf.peer_addr);
	pi->conf.self_port=0;
	pi->conf.peer_port=0;

	pi->incoming = 0;
	pi->If = NULL;
	pi->csock = -1;

	u_addrclear(&pi->peer_addr);
	pi->peer_port=0;

	return (0);
}

/*
 * TcpInst()
 */

static int
TcpInst(Link l, Link lt)
{
	l->info = Malloc(MB_PHYS, sizeof(struct tcpinfo));
	memcpy(l->info, lt->info, sizeof(struct tcpinfo));

	return (0);
}

/*
 * TcpOpen()
 */

static void
TcpOpen(Link l)
{
	TcpInfo	const 		pi = (TcpInfo) l->info;
	struct ngm_mkpeer	mkp;
	struct ngm_connect	cn;
	struct ngm_name		nm;
	char 			path[NG_PATHSIZ];
	char 			hook[NG_HOOKSIZ];
	struct sockaddr_storage addr;
	struct ng_async_cfg	acfg;
	int 			rval;
	char 			buf[64];
    union {
        u_char buf[sizeof(struct ng_mesg) + sizeof(struct nodeinfo)];
        struct ng_mesg reply;
    } repbuf;
    struct ng_mesg *const reply = &repbuf.reply;
    struct nodeinfo *ninfo = (struct nodeinfo *)&reply->data;

	/* Create a new netgraph node to control TCP ksocket node. */
	if (NgMkSockNode(NULL, &pi->csock, NULL) < 0) {
		Log(LG_ERR, ("[%s] TCP can't create control socket: %s",
		    l->name, strerror(errno)));
		goto fail;
	}
	(void)fcntl(pi->csock, F_SETFD, 1);

	/* Give it a name */
	snprintf(nm.name, sizeof(nm.name), "mpd%d-%s-so", gPid, l->name);
	if (NgSendMsg(pi->csock, ".:",
	    NGM_GENERIC_COOKIE, NGM_NAME, &nm, sizeof(nm)) < 0) {
		Log(LG_ERR, ("[%s] can't name %s node: %s",
		    l->name, NG_BPF_NODE_TYPE, strerror(errno)));
	}

        if (!PhysGetUpperHook(l, path, hook)) {
		Log(LG_PHYS, ("[%s] TCP: can't get upper hook", l->name));
    		goto fail;
        }
    
	snprintf(mkp.type, sizeof(mkp.type), "%s", NG_ASYNC_NODE_TYPE);
	snprintf(mkp.ourhook, sizeof(mkp.ourhook), "%s", hook);
	snprintf(mkp.peerhook, sizeof(mkp.peerhook), NG_ASYNC_HOOK_SYNC);
	if (NgSendMsg(pi->csock, path, NGM_GENERIC_COOKIE,
	    NGM_MKPEER, &mkp, sizeof(mkp)) < 0) {
		Log(LG_ERR, ("[%s] can't attach %s %s node: %s",
		    l->name, NG_ASYNC_NODE_TYPE, mkp.ourhook, strerror(errno)));
		goto fail;
	}
	
	strlcat(path, ".", sizeof(path));
	strlcat(path, hook, sizeof(path));
	
	/* Give it a name */
	snprintf(nm.name, sizeof(nm.name), "mpd%d-%s-as", gPid, l->name);
	if (NgSendMsg(pi->csock, path,
	    NGM_GENERIC_COOKIE, NGM_NAME, &nm, sizeof(nm)) < 0) {
		Log(LG_ERR, ("[%s] can't name %s node: %s",
		    l->name, NG_BPF_NODE_TYPE, strerror(errno)));
	}

	/* Get async node ID */
	if (NgSendMsg(pi->csock, path,
    	    NGM_GENERIC_COOKIE, NGM_NODEINFO, NULL, 0) != -1) {
		if (NgRecvMsg(pi->csock, reply, sizeof(repbuf), NULL) != -1) {
	    	    pi->async_node_id = ninfo->id;
		}
	}

	/* Configure the async converter node. */
	memset(&acfg, 0, sizeof(acfg));
	acfg.enabled = TRUE;
	acfg.accm = 0;  /* we do not need thie on TCP */
	acfg.amru = TCP_MRU;
	acfg.smru = TCP_MTU;
	if (NgSendMsg(pi->csock, path, NGM_ASYNC_COOKIE,
	    NGM_ASYNC_CMD_SET_CONFIG, &acfg, sizeof(acfg)) < 0) {
		Log(LG_ERR, ("[%s] can't config %s", l->name, path));
		goto fail;
	}

	if (pi->incoming) {
		Log(LG_PHYS2, ("[%s] %s() on incoming call", l->name,
		    __func__));

		/* Connect new born ksocket to our link. */
		snprintf(cn.path, sizeof(cn.path), "[%x]:", pi->node_id);
		snprintf(cn.ourhook, sizeof(cn.ourhook), NG_ASYNC_HOOK_ASYNC);
		snprintf(cn.peerhook, sizeof(cn.peerhook), "data");
		if (NgSendMsg(pi->csock, path, NGM_GENERIC_COOKIE, NGM_CONNECT,
		    &cn, sizeof(cn)) < 0) {
			Log(LG_ERR, ("[%s] can't connect new born ksocket: %s",
			    l->name, strerror(errno)));
			goto fail;
	  	}

		l->state = PHYS_STATE_UP;
		PhysUp(l);
		return;
	}

	u_addrcopy(&pi->conf.peer_addr.addr,&pi->peer_addr);
	pi->peer_port = pi->conf.peer_port;

	/*
	 * Attach fresh ksocket node next to async node.
	 */
	snprintf(mkp.type, sizeof(mkp.type), "%s", NG_KSOCKET_NODE_TYPE);
	snprintf(mkp.ourhook, sizeof(mkp.ourhook), NG_ASYNC_HOOK_ASYNC);
	if ((pi->conf.self_addr.family==AF_INET6) || 
	    (pi->conf.self_addr.family==AF_UNSPEC && pi->conf.peer_addr.addr.family==AF_INET6)) {
	    snprintf(mkp.peerhook, sizeof(mkp.peerhook), "%d/%d/%d", PF_INET6, SOCK_STREAM, IPPROTO_TCP);
	} else {
	    snprintf(mkp.peerhook, sizeof(mkp.peerhook), "inet/stream/tcp");
	}
	if (NgSendMsg(pi->csock, path, NGM_GENERIC_COOKIE, NGM_MKPEER, &mkp,
	    sizeof(mkp)) < 0) {
		Log(LG_ERR, ("[%s] can't attach %s node: %s", l->name,
		    NG_KSOCKET_NODE_TYPE, strerror(errno)));
		goto fail;
	}

	strlcat(path, ".", sizeof(path));
	strlcat(path, NG_ASYNC_HOOK_ASYNC, sizeof(path));

	/* Give it a name */
	snprintf(nm.name, sizeof(nm.name), "mpd%d-%s", gPid, l->name);
	if (NgSendMsg(pi->csock, path,
	    NGM_GENERIC_COOKIE, NGM_NAME, &nm, sizeof(nm)) < 0) {
		Log(LG_ERR, ("[%s] can't name %s node: %s",
		    l->name, NG_BPF_NODE_TYPE, strerror(errno)));
	}

	/* Start connecting to peer. */
	u_addrtosockaddr(&pi->peer_addr, pi->peer_port, &addr);
	rval = NgSendMsg(pi->csock, path, NGM_KSOCKET_COOKIE,
	    NGM_KSOCKET_CONNECT, &addr, addr.ss_len);
	if (rval < 0 && errno != EINPROGRESS) {
		Log(LG_ERR, ("[%s] can't connect() %s node: %s", l->name,
		    NG_KSOCKET_NODE_TYPE, strerror(errno))); 
		goto fail;
	}

	l->state = PHYS_STATE_CONNECTING;

	if (rval == 0)	/* Can happen when peer is local. */
		TcpConnectEvent(EVENT_READ, l);
	else {
		assert(errno == EINPROGRESS);
		EventRegister(&pi->ev_connect, EVENT_READ, pi->csock,
		    0, TcpConnectEvent, l);
		Log(LG_PHYS, ("[%s] connecting to %s %u", l->name,
		    u_addrtoa(&pi->conf.peer_addr.addr, buf, sizeof(buf)), pi->conf.peer_port));
	}

	return;
fail:
	l->state = PHYS_STATE_DOWN;
	TcpDoClose(l);
	PhysDown(l, STR_ERROR, NULL);
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
	Link		l;
	TcpInfo		pi;
	char path[NG_PATHSIZ];

	/* Restore context. */
	l = (Link)cookie;
	pi = (TcpInfo)l->info;

	assert(type == EVENT_READ);

	/* Check whether the connection was successful or not. */
	if (NgRecvMsg(pi->csock, &cn.resp, sizeof(cn), path) < 0) {
		Log(LG_ERR, ("[%s] error reading message from \"%s\": %s",
		    l->name, path, strerror(errno)));
		goto failed;
	}

	assert(cn.resp.header.typecookie == NGM_KSOCKET_COOKIE);
	assert(cn.resp.header.cmd == NGM_KSOCKET_CONNECT);

	if (cn.rval != 0) {
		Log(LG_PHYS, ("[%s] failed to connect: %s", l->name,
		    strerror(cn.rval)));
		goto failed;
	}

	/* Report connected. */
	Log(LG_PHYS, ("[%s] connection established", l->name));

	l->state = PHYS_STATE_UP;
	PhysUp(l);

	return;
failed:
	l->state = PHYS_STATE_DOWN;
	TcpDoClose(l);
	PhysDown(l, STR_ERROR, NULL);

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
	struct ngm_name         nm;
	char path[NG_PATHSIZ];
	struct u_addr	addr;
	in_port_t	port;
	char		buf[64];
	int 		k;
	struct TcpIf 	*If=(struct TcpIf *)(cookie);
	Link		l = NULL;
	TcpInfo		pi = NULL;

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
		Log(LG_PHYS, ("Shutdown sequence in progress, ignoring request."));
		return;
	}

	if (OVERLOAD()) {
		Log(LG_PHYS, ("Daemon overloaded, ignoring request."));
		return;
	}

	/* Examine all TCP links. */
	for (k = 0; k < gNumLinks; k++) {
		Link l2;
	        TcpInfo pi2;

		if (!gLinks[k] || gLinks[k]->type != &gTcpPhysType)
			continue;

		l2 = gLinks[k];
		pi2 = (TcpInfo)l2->info;

		if ((!PhysIsBusy(l2)) &&
		    Enabled(&l2->conf.options, LINK_CONF_INCOMING) &&
		    (pi2->If == If) &&
		    IpAddrInRange(&pi2->conf.peer_addr, &addr) &&
		    (pi2->conf.peer_port == 0 || pi2->conf.peer_port == port)) {

			if (pi == NULL || pi2->conf.peer_addr.width > pi->conf.peer_addr.width) {
				l = l2;
				pi = pi2;
				if (u_rangehost(&pi->conf.peer_addr)) {
					break;	/* Nothing could be better */
				}
			}
		}
	}
	if (l != NULL && l->tmpl) {
    		l = LinkInst(l, NULL, 0, 0);
    		pi = (TcpInfo)l->info;
	}
	if (pi != NULL) {
		Log(LG_PHYS, ("[%s] Accepting TCP connection from %s %u",
		    l->name, u_addrtoa(&addr, buf, sizeof(buf)), port));

		sockaddrtou_addr(&ac.sin, &pi->peer_addr, &pi->peer_port);

		pi->node_id = ac.id;

		/* Give it a name */
		snprintf(nm.name, sizeof(nm.name), "mpd%d-%s", gPid, l->name);
		snprintf(path, sizeof(path), "[%x]:", ac.id);
		if (NgSendMsg(If->csock, path,
		    NGM_GENERIC_COOKIE, NGM_NAME, &nm, sizeof(nm)) < 0) {
			Log(LG_ERR, ("[%s] can't name %s node: %s",
			    l->name, NG_BPF_NODE_TYPE, strerror(errno)));
		}

		pi->incoming=1;
		l->state = PHYS_STATE_READY;

		PhysIncoming(l);
	} else {
	    Log(LG_PHYS, ("No free TCP link with requested parameters "
	        "was found"));
	    snprintf(path, sizeof(path), "[%x]:", ac.id);
	    NgFuncShutdownNode(If->csock, "", path);
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
TcpClose(Link l)
{
	TcpInfo const pi = (TcpInfo) l->info;

	TcpDoClose(l);

	if (l->state != PHYS_STATE_DOWN) {
	    pi->incoming=0;
	    l->state = PHYS_STATE_DOWN;

	    u_addrclear(&pi->peer_addr);
	    pi->peer_port=0;

	    PhysDown(l, 0, NULL);
	}
}

/*
 * TcpShutdown()
 */

static void
TcpShutdown(Link l)
{
	TcpDoClose(l);
	Freee(MB_PHYS, l->info);
}

/*
 * TcpDoClose()
 */

static void
TcpDoClose(Link l)
{
	char path[NG_PATHSIZ];
	TcpInfo const pi = (TcpInfo) l->info;

	EventUnRegister(&pi->ev_connect);

	if (pi->csock<=0) {
	    return;
	};

	if (pi->node_id != 0) {
	    snprintf(path, sizeof(path), "[%lx]:", (u_long)pi->node_id);
	    NgFuncShutdownNode(pi->csock, l->name, path);
	    pi->node_id = 0;
	}
	
	if (pi->async_node_id != 0) {
	    snprintf(path, sizeof(path), "[%lx]:", (u_long)pi->async_node_id);
	    NgFuncShutdownNode(pi->csock, l->name, path);
	    pi->async_node_id = 0;
	}
	
	close(pi->csock);
	pi->csock = -1;
	pi->node_id = 0;
}

/*
 * TcpOriginate()
 */

static int
TcpOriginate(Link l)
{
	TcpInfo const pi = (TcpInfo) l->info;

	return (pi->incoming ? LINK_ORIGINATE_REMOTE : LINK_ORIGINATE_LOCAL);
}

/*
 * TcpIsSync()
 */

static int
TcpIsSync(Link l)
{
	return (1);
}

static int
TcpPeerAddr(Link l, void *buf, int buf_len)
{
	TcpInfo const pi = (TcpInfo) l->info;

	if (u_addrtoa(&pi->peer_addr, buf, buf_len))
		return (0);
  	else
		return (-1);
}

static int
TcpPeerPort(Link l, void *buf, int buf_len)
{
	TcpInfo const pi = (TcpInfo) l->info;

	if (snprintf( buf, buf_len, "%d", pi->peer_port))
		return (0);
  	else
		return (-1);
}

static int
TcpCallingNum(Link l, void *buf, int buf_len)
{
	TcpInfo const pi = (TcpInfo) l->info;

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
TcpCalledNum(Link l, void *buf, int buf_len)
{
	TcpInfo const pi = (TcpInfo) l->info;

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
TcpStat(Context ctx)
{
	TcpInfo const pi = (TcpInfo) ctx->lnk->info;
	char	buf[64];

	Printf("TCP configuration:\r\n");
	Printf("\tSelf address : %s, port %u\r\n",
	    u_addrtoa(&pi->conf.self_addr, buf, sizeof(buf)), pi->conf.self_port);
	Printf("\tPeer address : %s, port %u\r\n",
	    u_rangetoa(&pi->conf.peer_addr, buf, sizeof(buf)), pi->conf.peer_port);
	Printf("TCP options:\r\n");
	OptStat(ctx, &pi->conf.options, gConfList);
	Printf("TCP state:\r\n");
	Printf("\tState        : %s\r\n", gPhysStateNames[ctx->lnk->state]);
	if (ctx->lnk->state != PHYS_STATE_DOWN) {
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
	for (k = 0; k < gNumLinks; k++) {
        	Link l;
        	TcpInfo pi;
		int i, j = -1;

		if (gLinks[k] == NULL ||
		    gLinks[k]->type != &gTcpPhysType)
			continue;

		l = gLinks[k];
		pi = (TcpInfo)l->info;

		if (!Enabled(&l->conf.options, LINK_CONF_INCOMING))
			continue;

		if (!pi->conf.self_port) {
			Log(LG_ERR, ("Tcp: Skipping link \"%s\" with undefined "
			    "port number", l->name));
			continue;
		}

		for (i = 0; i < TcpIfCount; i++)
			if ((u_addrcompare(&TcpIfs[i].self_addr, &pi->conf.self_addr) == 0) &&
			    (TcpIfs[i].self_port == pi->conf.self_port))
				j = i;

		if (j == -1) {
			if (TcpIfCount>=TCP_MAXPARENTIFS) {
			    Log(LG_ERR, ("[%s] TCP: Too many different parent interfaces! ", 
				l->name));
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
TcpNodeUpdate(Link l)
{
    if (Enabled(&l->conf.options, LINK_CONF_INCOMING) &&
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
TcpSetCommand(Context ctx, int ac, char *av[], void *arg)
{
	TcpInfo	const pi = (TcpInfo) ctx->lnk->info;
	struct u_range	rng;
	int		port;

	switch ((intptr_t)arg) {
	case SET_PEERADDR:
	case SET_SELFADDR:
    		if (ac < 1 || ac > 2 || !ParseRange(av[0], &rng, ALLOW_IPV4|ALLOW_IPV6))
			return(-1);
	        if (ac > 1) {
	    		if ((port = atoi(av[1])) < 0 || port > 0xffff)
				return(-1);
    		} else {
			port = 0;
    		}
    		if ((intptr_t)arg == SET_SELFADDR) {
			pi->conf.self_addr = rng.addr;
			pi->conf.self_port = port;
    		} else {
			pi->conf.peer_addr = rng;
			pi->conf.peer_port = port;
    		}
		break;
	case SET_ENABLE:
		EnableCommand(ac, av, &pi->conf.options, gConfList);
    	    	TcpNodeUpdate(ctx->lnk);
        	break;
        case SET_DISABLE:
    		DisableCommand(ac, av, &pi->conf.options, gConfList);
    		break;

	default:
		assert(0);
	}

	return (0);
}
