
/*
 * udp.c
 *
 * Written by  Alexander Motin <mav@FreeBSD.org>
 */

#include "ppp.h"
#include "phys.h"
#include "mbuf.h"
#include "udp.h"
#include "ngfunc.h"
#include "util.h"
#include "log.h"

#include <netgraph/ng_message.h>
#ifdef __DragonFly__
#include <netgraph/socket/ng_socket.h>
#include <netgraph/ksocket/ng_ksocket.h>
#else
#include <netgraph/ng_socket.h>
#include <netgraph/ng_ksocket.h>
#endif
#include <netgraph.h>

/*
 * XXX this device type not completely correct, 
 * as it can deliver out-of-order frames. This can make problems 
 * for different compression and encryption protocols.
 */

/*
 * DEFINITIONS
 */

  #define UDP_MTU		2048
  #define UDP_MRU		2048

  #define UDP_REOPEN_PAUSE	5

  #define UDP_MAXPARENTIFS	256

  struct udpinfo {
    struct {
	struct optinfo	options;
	struct u_addr	self_addr;	/* Configured local IP address */
	struct u_range	peer_addr;	/* Configured peer IP address */
	in_port_t	self_port;	/* Configured local port */
	in_port_t	peer_port;	/* Configured peer port */
    } conf;

    /* State */
    u_char		incoming:1;		/* incoming vs. outgoing */
    struct UdpIf 	*If;
    struct u_addr	peer_addr;
    in_port_t		peer_port;
    ng_ID_t		node_id;
  };
  typedef struct udpinfo	*UdpInfo;

/* Set menu options */

  enum {
    SET_PEERADDR,
    SET_SELFADDR,
    SET_ENABLE,
    SET_DISABLE,
  };

enum {
	UDP_CONF_ORIGINATE,	/* allow originating connections to peer */
	UDP_CONF_INCOMING,	/* allow accepting connections from peer */
};

/*
 * INTERNAL FUNCTIONS
 */

  static int	UdpInit(PhysInfo p);
  static void	UdpOpen(PhysInfo p);
  static void	UdpClose(PhysInfo p);
  static void	UdpStat(Context ctx);
  static int	UdpOrigination(PhysInfo p);
  static int	UdpIsSync(PhysInfo p);
  static int	UdpPeerAddr(PhysInfo p, void *buf, int buf_len);
  static int	UdpPeerPort(PhysInfo p, void *buf, int buf_len);
  static int	UdpCallingNum(PhysInfo p, void *buf, int buf_len);
  static int	UdpCalledNum(PhysInfo p, void *buf, int buf_len);

  static void	UdpDoClose(PhysInfo p);
  static int	UdpSetCommand(Context ctx, int ac, char *av[], void *arg);

/*
 * GLOBAL VARIABLES
 */

  const struct phystype gUdpPhysType = {
    .name		= "udp",
    .minReopenDelay	= UDP_REOPEN_PAUSE,
    .mtu		= UDP_MTU,
    .mru		= UDP_MRU,
    .init		= UdpInit,
    .open		= UdpOpen,
    .close		= UdpClose,
    .showstat		= UdpStat,
    .originate		= UdpOrigination,
    .issync		= UdpIsSync,
    .peeraddr		= UdpPeerAddr,
    .peerport		= UdpPeerPort,
    .callingnum		= UdpCallingNum,
    .callednum		= UdpCalledNum,
  };

  const struct cmdtab UdpSetCmds[] = {
    { "self ip [port]",			"Set local IP address",
	UdpSetCommand, NULL, (void *) SET_SELFADDR },
    { "peer ip [port]",			"Set remote IP address",
	UdpSetCommand, NULL, (void *) SET_PEERADDR },
    { "enable [opt ...]",		"Enable option",
	UdpSetCommand, NULL, (void *) SET_ENABLE },
    { "disable [opt ...]",		"Disable option",
	UdpSetCommand, NULL, (void *) SET_DISABLE },
    { NULL },
  };

static struct confinfo	gConfList[] = {
    { 0,	UDP_CONF_ORIGINATE,	"originate"	},
    { 0,	UDP_CONF_INCOMING,	"incoming"	},
    { 0,	0,			NULL		},
};

struct UdpIf {
    struct u_addr	self_addr;
    in_port_t	self_port;
    int		csock;                  /* netgraph Control socket */
    EventRef	ctrlEvent;		/* listen for ctrl messages */
};
int UdpIfCount=0;
struct UdpIf UdpIfs[UDP_MAXPARENTIFS];

int UdpListenUpdateSheduled=0;
struct pppTimer UdpListenUpdateTimer;

/*
 * UdpInit()
 */

static int
UdpInit(PhysInfo p)
{
    UdpInfo	pi;

    pi = (UdpInfo) (p->info = Malloc(MB_PHYS, sizeof(*pi)));

    u_addrclear(&pi->conf.self_addr);
    u_rangeclear(&pi->conf.peer_addr);
    pi->conf.self_port=0;
    pi->conf.peer_port=0;

    pi->incoming = 0;
    pi->If = NULL;

    u_addrclear(&pi->peer_addr);
    pi->peer_port=0;

    return(0);
}

/*
 * UdpOpen()
 */

static void
UdpOpen(PhysInfo p)
{
	UdpInfo			const pi = (UdpInfo) p->info;
	char        		path[NG_PATHLEN+1];
	char        		hook[NG_HOOKLEN+1];
	struct ngm_mkpeer	mkp;
	struct ngm_name         nm;
	struct sockaddr_storage	addr;
        union {
            u_char buf[sizeof(struct ng_ksocket_sockopt) + sizeof(int)];
            struct ng_ksocket_sockopt ksso;
        } u;
        struct ng_ksocket_sockopt *const ksso = &u.ksso;
	union {
    	    u_char buf[sizeof(struct ng_mesg) + sizeof(struct nodeinfo)];
    	    struct ng_mesg reply;
	} repbuf;
	struct ng_mesg *const reply = &repbuf.reply;
	struct nodeinfo *ninfo = (struct nodeinfo *)&reply->data;
	int			csock;

	/* Create a new netgraph node to control TCP ksocket node. */
	if (NgMkSockNode(NULL, &csock, NULL) < 0) {
		Log(LG_ERR, ("[%s] TCP can't create control socket: %s",
		    p->name, strerror(errno)));
		goto fail;
	}
	(void)fcntl(csock, F_SETFD, 1);

        if (!PhysGetUpperHook(p, path, hook)) {
		Log(LG_PHYS, ("[%s] UDP: can't get upper hook", p->name));
    		goto fail;
        }

	/* Attach ksocket node to PPP node */
	snprintf(mkp.type, sizeof(mkp.type), "%s", NG_KSOCKET_NODE_TYPE);
	snprintf(mkp.ourhook, sizeof(mkp.ourhook), hook);
	if ((pi->conf.self_addr.family==AF_INET6) || 
	    (pi->conf.self_addr.family==AF_UNSPEC && pi->conf.peer_addr.addr.family==AF_INET6)) {
	        snprintf(mkp.peerhook, sizeof(mkp.peerhook), "%d/%d/%d", PF_INET6, SOCK_DGRAM, IPPROTO_UDP);
	} else {
	    snprintf(mkp.peerhook, sizeof(mkp.peerhook), "inet/dgram/udp");
	}
	if (NgSendMsg(csock, path, NGM_GENERIC_COOKIE,
	    NGM_MKPEER, &mkp, sizeof(mkp)) < 0) {
	        Log(LG_ERR, ("[%s] can't attach %s node: %s",
	    	    p->name, NG_KSOCKET_NODE_TYPE, strerror(errno)));
		goto fail;
	}

	strlcat(path, ".", sizeof(path));
	strlcat(path, hook, sizeof(path));

	/* Give it a name */
	snprintf(nm.name, sizeof(nm.name), "mpd%d-%s", gPid, p->name);
	if (NgSendMsg(csock, path,
	    NGM_GENERIC_COOKIE, NGM_NAME, &nm, sizeof(nm)) < 0) {
		Log(LG_ERR, ("[%s] can't name %s node: %s",
		    p->name, NG_BPF_NODE_TYPE, strerror(errno)));
	}

	/* Get ksocket node ID */
	if (NgSendMsg(csock, path,
    	    NGM_GENERIC_COOKIE, NGM_NODEINFO, NULL, 0) != -1) {
		if (NgRecvMsg(csock, reply, sizeof(repbuf), NULL) != -1) {
	    	    pi->node_id = ninfo->id;
		}
	}

  if ((pi->incoming) || (pi->conf.self_port != 0)) {
    /* Setsockopt socket. */
    ksso->level=SOL_SOCKET;
    ksso->name=SO_REUSEPORT;
    ((int *)(ksso->value))[0]=1;
    if (NgSendMsg(csock, path, NGM_KSOCKET_COOKIE,
        NGM_KSOCKET_SETOPT, &u, sizeof(u)) < 0) {
    	Log(LG_ERR, ("[%s] can't setsockopt() %s node: %s",
    	    p->name, NG_KSOCKET_NODE_TYPE, strerror(errno)));
	goto fail;
    }

    /* Bind socket */
    u_addrtosockaddr(&pi->conf.self_addr, pi->conf.self_port, &addr);
    if (NgSendMsg(csock, path, NGM_KSOCKET_COOKIE,
	    NGM_KSOCKET_BIND, &addr, addr.ss_len) < 0) {
	Log(LG_ERR, ("[%s] can't bind() %s node: %s",
    	    p->name, NG_KSOCKET_NODE_TYPE, strerror(errno)));
	goto fail;
    }
  }

  if (!pi->incoming) {
    if ((!u_rangeempty(&pi->conf.peer_addr)) && (pi->conf.peer_port != 0)) {
	u_addrcopy(&pi->conf.peer_addr.addr,&pi->peer_addr);
	pi->peer_port = pi->conf.peer_port;
    } else {
	Log(LG_ERR, ("[%s] Can't connect without peer specified", p->name));
	goto fail;
    }
  }
  u_addrtosockaddr(&pi->peer_addr, pi->peer_port, &addr);

  /* Connect socket if peer address and port is specified */
  if (NgSendMsg(csock, path, NGM_KSOCKET_COOKIE,
	NGM_KSOCKET_CONNECT, &addr, addr.ss_len) < 0) {
    Log(LG_ERR, ("[%s] can't connect() %s node: %s",
	p->name, NG_KSOCKET_NODE_TYPE, strerror(errno)));
    goto fail;
  }
  
  close(csock);

  /* OK */
  p->state = PHYS_STATE_UP;
  PhysUp(p);
  return;

fail:
    UdpDoClose(p);
    pi->incoming=0;
    p->state = PHYS_STATE_DOWN;
    u_addrclear(&pi->peer_addr);
    pi->peer_port=0;
    PhysDown(p, STR_ERROR, NULL);

    if (csock>0)
	close(csock);
}

/*
 * UdpClose()
 */

static void
UdpClose(PhysInfo p)
{
  UdpInfo const pi = (UdpInfo) p->info;
  if (p->state != PHYS_STATE_DOWN) {
    UdpDoClose(p);
    pi->incoming=0;
    p->state = PHYS_STATE_DOWN;
    u_addrclear(&pi->peer_addr);
    pi->peer_port=0;
    PhysDown(p, 0, NULL);
  }
}

/*
 * UdpDoClose()
 */

static void
UdpDoClose(PhysInfo p)
{
	UdpInfo	const pi = (UdpInfo) p->info;
	char	path[NG_PATHLEN + 1];
	int	csock;

	if (pi->node_id == 0)
		return;

	/* Get a temporary netgraph socket node */
	if (NgMkSockNode(NULL, &csock, NULL) == -1) {
		Log(LG_ERR, ("UDP: NgMkSockNode: %s", strerror(errno)));
		return;
	}
	
	/* Disconnect session hook. */
	snprintf(path, sizeof(path), "[%lx]:", (u_long)pi->node_id);
	NgFuncShutdownNode(csock, p->name, path);
	
	close(csock);
	
	pi->node_id = 0;
}

/*
 * UdpOrigination()
 */

static int
UdpOrigination(PhysInfo p)
{
  UdpInfo	const pi = (UdpInfo) p->info;

  return (pi->incoming ? LINK_ORIGINATE_REMOTE : LINK_ORIGINATE_LOCAL);
}

/*
 * UdpIsSync()
 */

static int
UdpIsSync(PhysInfo p)
{
  return (1);
}

static int
UdpPeerAddr(PhysInfo p, void *buf, int buf_len)
{
  UdpInfo	const pi = (UdpInfo) p->info;

  if (u_addrtoa(&pi->peer_addr, buf, buf_len))
    return(0);
  else
    return(-1);
}

static int
UdpPeerPort(PhysInfo p, void *buf, int buf_len)
{
  UdpInfo	const pi = (UdpInfo) p->info;

  if (snprintf(buf, buf_len, "%d", pi->peer_port))
    return(0);
  else
    return(-1);
}

static int
UdpCallingNum(PhysInfo p, void *buf, int buf_len)
{
	UdpInfo const pi = (UdpInfo) p->info;

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
UdpCalledNum(PhysInfo p, void *buf, int buf_len)
{
	UdpInfo const pi = (UdpInfo) p->info;

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
 * UdpStat()
 */

void
UdpStat(Context ctx)
{
	UdpInfo const pi = (UdpInfo) ctx->phys->info;
	char	buf[64];

	Printf("UDP configuration:\r\n");
	Printf("\tSelf address : %s, port %u\r\n",
	    u_addrtoa(&pi->conf.self_addr, buf, sizeof(buf)), pi->conf.self_port);
	Printf("\tPeer address : %s, port %u\r\n",
	    u_rangetoa(&pi->conf.peer_addr, buf, sizeof(buf)), pi->conf.peer_port);
	Printf("UDP options:\r\n");
	OptStat(ctx, &pi->conf.options, gConfList);
	Printf("UDP state:\r\n");
	Printf("\tState        : %s\r\n", gPhysStateNames[ctx->phys->state]);
	if (ctx->phys->state != PHYS_STATE_DOWN) {
	    Printf("\tIncoming     : %s\r\n", (pi->incoming?"YES":"NO"));
	    Printf("\tCurrent peer : %s, port %u\r\n",
		u_addrtoa(&pi->peer_addr, buf, sizeof(buf)), pi->peer_port);
	}
}

/*
 * UdpAcceptEvent() triggers when we accept incoming connection.
 */

static void
UdpAcceptEvent(int type, void *cookie)
{
	struct sockaddr_storage saddr;
	socklen_t	saddrlen;
	struct u_addr	addr;
	in_port_t	port;
	char		buf[64];
	char		buf1[64];
	int 		k;
	struct UdpIf 	*If=(struct UdpIf *)(cookie);
	time_t const 	now = time(NULL);
	PhysInfo	p = NULL;
	UdpInfo		pi = NULL;

	char		pktbuf[UDP_MRU+100];
	char		pktlen;

	assert(type == EVENT_READ);

	saddrlen = sizeof(saddr);
	if ((pktlen = recvfrom(If->csock, pktbuf, sizeof(pktbuf), MSG_DONTWAIT, (struct sockaddr *)(&saddr), &saddrlen)) < 0) {
	    Log(LG_PHYS, ("recvfrom() error: %s", strerror(errno)));
	}

	sockaddrtou_addr(&saddr, &addr, &port);

	Log(LG_PHYS, ("Incoming UDP connection from %s %u to %s %u",
	    u_addrtoa(&addr, buf, sizeof(buf)), port,
	    u_addrtoa(&If->self_addr, buf1, sizeof(buf1)), If->self_port));

	if (gShutdownInProgress) {
		Log(LG_PHYS, ("Shutdown sequence in progress, ignoring request."));
		goto failed;
	}

	if (OVERLOAD()) {
		Log(LG_PHYS, ("Daemon overloaded, ignoring request."));
		goto failed;
	}

	/* Examine all UDP links. */
	for (k = 0; k < gNumPhyses; k++) {
		PhysInfo p2;
	        UdpInfo pi2;

		if (gPhyses[k] && gPhyses[k]->type != &gUdpPhysType)
			continue;

		p2 = gPhyses[k];
		pi2 = (UdpInfo)p2->info;

		if ((p2->state == PHYS_STATE_DOWN) &&
		    (now - p2->lastClose >= UDP_REOPEN_PAUSE) &&
		    Enabled(&pi2->conf.options, UDP_CONF_INCOMING) &&
		    (pi2->If == If) &&
		    IpAddrInRange(&pi2->conf.peer_addr, &addr) &&
		    (pi2->conf.peer_port == 0 || pi2->conf.peer_port == port)) {

			if (pi == NULL || pi2->conf.peer_addr.width > pi->conf.peer_addr.width) {
				p = p2;
				pi = pi2;
				if ((pi->conf.peer_addr.addr.family==AF_INET && 
					pi->conf.peer_addr.width == 32) ||
					pi->conf.peer_addr.width == 128) {
					break;	/* Nothing could be better */
				}
			}
		}
	}
	if (pi != NULL) {
		Log(LG_PHYS, ("[%s] Accepting UDP connection from %s %u to %s %u",
		    p->name, u_addrtoa(&addr, buf, sizeof(buf)), port,
		    u_addrtoa(&If->self_addr, buf1, sizeof(buf1)), If->self_port));

		sockaddrtou_addr(&saddr, &pi->peer_addr, &pi->peer_port);

		pi->incoming=1;
		p->state = PHYS_STATE_READY;

		PhysIncoming(p);
	} else {
		Log(LG_PHYS, ("No free UDP link with requested parameters "
	    	    "was found"));
	}

failed:
	EventRegister(&If->ctrlEvent, EVENT_READ, If->csock,
	    0, UdpAcceptEvent, If);
}

static int 
ListenUdpNode(struct UdpIf *If)
{
	struct sockaddr_storage addr;
	int error;
	char buf[64];
	int opt;
	
	/* Make listening UDP socket. */
	if (If->self_addr.family==AF_INET6) {
	    If->csock = socket(PF_INET6, SOCK_DGRAM, IPPROTO_UDP);
	} else {
	    If->csock = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
	}
	(void)fcntl(If->csock, F_SETFD, 1);

	/* Setsockopt socket. */
	opt = 1;
	if (setsockopt(If->csock, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt))) {
		Log(LG_ERR, ("UDP: can't setsockopt socket: %s",
		    strerror(errno)));
		error = errno;
		goto fail2;
	};

	/* Bind socket. */
	u_addrtosockaddr(&If->self_addr, If->self_port, &addr);
	if (bind(If->csock, (struct sockaddr *)(&addr), addr.ss_len)) {
		Log(LG_ERR, ("UDP: can't bind socket: %s",
		    strerror(errno)));
		error = errno;
		goto fail2;
	}

	Log(LG_PHYS, ("UDP: waiting for connection on %s %u",
	    u_addrtoa(&If->self_addr, buf, sizeof(buf)), If->self_port));
	EventRegister(&If->ctrlEvent, EVENT_READ, If->csock,
	    0, UdpAcceptEvent, If);

	return (1);
fail2:
	close(If->csock);
	If->csock = -1;
	return (0);
};

/*
 * UdpListenUpdate()
 */

static void
UdpListenUpdate(void *arg)
{
	int k;

	UdpListenUpdateSheduled = 0;

	/* Examine all UDP links. */
	for (k = 0; k < gNumPhyses; k++) {
        	PhysInfo p;
        	UdpInfo pi;
		int i, j = -1;

		if (gPhyses[k] == NULL ||
		    gPhyses[k]->type != &gUdpPhysType)
			continue;

		p = gPhyses[k];
		pi = (UdpInfo)p->info;

		if (!Enabled(&pi->conf.options, UDP_CONF_INCOMING))
			continue;

		if (!pi->conf.self_port) {
			Log(LG_ERR, ("UDP: Skipping link %s with undefined "
			    "port number", p->name));
			continue;
		}

		for (i = 0; i < UdpIfCount; i++)
			if ((u_addrcompare(&UdpIfs[i].self_addr, &pi->conf.self_addr) == 0) &&
			    (UdpIfs[i].self_port == pi->conf.self_port))
				j = i;

		if (j == -1) {
			if (UdpIfCount>=UDP_MAXPARENTIFS) {
			    Log(LG_ERR, ("[%s] UDP: Too many different listening ports! ", 
				p->name));
			    continue;
			}
			u_addrcopy(&pi->conf.self_addr,&UdpIfs[UdpIfCount].self_addr);
			UdpIfs[UdpIfCount].self_port=pi->conf.self_port;

			if (ListenUdpNode(&(UdpIfs[UdpIfCount]))) {

				pi->If=&UdpIfs[UdpIfCount];
				UdpIfCount++;
			}
		} else {
			pi->If=&UdpIfs[j];
		}
	}
}

/*
 * UdpNodeUpdate()
 */

static void
UdpNodeUpdate(PhysInfo p)
{
  UdpInfo pi = (UdpInfo)p->info;

  if (Enabled(&pi->conf.options, UDP_CONF_INCOMING) &&
        (!UdpListenUpdateSheduled)) {
    	    /* Set a timer to run UdpListenUpdate(). */
	    TimerInit(&UdpListenUpdateTimer, "UdpListenUpdate",
		0, UdpListenUpdate, NULL);
	    TimerStart(&UdpListenUpdateTimer);
	    UdpListenUpdateSheduled = 1;
  }
}

/*
 * UdpSetCommand()
 */

static int
UdpSetCommand(Context ctx, int ac, char *av[], void *arg)
{
	UdpInfo		const pi = (UdpInfo) ctx->phys->info;
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
    	UdpNodeUpdate(ctx->phys);
    	break;
    case SET_DISABLE:
	DisableCommand(ac, av, &pi->conf.options, gConfList);
	break;

    default:
      assert(0);
  }
  return(0);
}

