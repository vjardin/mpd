
/*
 * udp.c
 *
 * Written by  Alexander Motin <mav@alkar.net>
 */

#include "ppp.h"
#include "phys.h"
#include "mbuf.h"
#include "udp.h"
#include "ngfunc.h"
#include "util.h"
#include "log.h"
#include "msgdef.h"

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
 * We need to use a somw node type that prepends sequence numbers
 */

/*
 * DEFINITIONS
 */

  #define UDP_MTU		2048
  #define UDP_MRU		2048

  #define UDP_REOPEN_PAUSE	5

  #define UDP_MAXPARENTIFS	256

  struct udpinfo {
    struct optinfo	options;
    struct u_addr	self_addr;	/* Configured local IP address */
    struct u_addr	peer_addr;	/* Configured peer IP address */
    in_port_t		self_port;	/* Configured local port */
    in_port_t		peer_port;	/* Configured peer port */

    /* State */
    u_char		incoming:1;		/* incoming vs. outgoing */
    struct UdpIf 	*If;
    struct u_addr	real_peer_addr;
    in_port_t		real_peer_port;
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
  static void	UdpStat(PhysInfo p);
  static int	UdpOrigination(PhysInfo p);
  static int	UdpPeerAddr(PhysInfo p, void *buf, int buf_len);

  static void	UdpDoClose(UdpInfo pi);
  static int	UdpSetCommand(int ac, char *av[], void *arg);

/*
 * GLOBAL VARIABLES
 */

  const struct phystype gUdpPhysType = {
    .name		= "udp",
    .synchronous	= TRUE,
    .minReopenDelay	= UDP_REOPEN_PAUSE,
    .mtu		= UDP_MTU,
    .mru		= UDP_MRU,
    .init		= UdpInit,
    .open		= UdpOpen,
    .close		= UdpClose,
    .showstat		= UdpStat,
    .originate		= UdpOrigination,
    .peeraddr		= UdpPeerAddr,
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

    u_addrclear(&pi->self_addr);
    u_addrclear(&pi->peer_addr);
    pi->self_port=0;
    pi->peer_port=0;

    pi->incoming = 0;
    pi->If = NULL;

    u_addrclear(&pi->real_peer_addr);
    pi->real_peer_port=0;

    return(0);
}

/*
 * UdpOpen()
 */

static void
UdpOpen(PhysInfo p)
{
  UdpInfo		const pi = (UdpInfo) lnk->phys->info;
  char        		path[NG_PATHLEN+1];
  struct ngm_mkpeer	mkp;
  struct sockaddr_storage	addr;
    union {
        u_char buf[sizeof(struct ng_ksocket_sockopt) + sizeof(int)];
        struct ng_ksocket_sockopt ksso;
    } u;
    struct ng_ksocket_sockopt *const ksso = &u.ksso;

  /* Attach ksocket node to PPP node */
  snprintf(mkp.type, sizeof(mkp.type), "%s", NG_KSOCKET_NODE_TYPE);
  snprintf(mkp.ourhook, sizeof(mkp.ourhook),
    "%s%d", NG_PPP_HOOK_LINK_PREFIX, lnk->bundleIndex);
  if ((pi->self_addr.family==AF_INET6) || 
    (pi->self_addr.family==AF_UNSPEC && pi->peer_addr.family==AF_INET6)) {
    snprintf(mkp.peerhook, sizeof(mkp.peerhook), "%d/%d/%d", PF_INET6, SOCK_DGRAM, IPPROTO_UDP);
  } else {
    snprintf(mkp.peerhook, sizeof(mkp.peerhook), "inet/dgram/udp");
  }
  if (NgSendMsg(bund->csock, MPD_HOOK_PPP, NGM_GENERIC_COOKIE,
      NGM_MKPEER, &mkp, sizeof(mkp)) < 0) {
    Log(LG_ERR, ("[%s] can't attach %s node: %s",
      lnk->name, NG_KSOCKET_NODE_TYPE, strerror(errno)));
    goto fail;
  }
  snprintf(path, sizeof(path), "%s.%s", MPD_HOOK_PPP, mkp.ourhook);

  if ((pi->incoming) || (pi->self_port != 0)) {
    /* Setsockopt socket. */
    ksso->level=SOL_SOCKET;
    ksso->name=SO_REUSEPORT;
    ((int *)(ksso->value))[0]=1;
    if (NgSendMsg(bund->csock, path, NGM_KSOCKET_COOKIE,
        NGM_KSOCKET_SETOPT, &u, sizeof(u)) < 0) {
    	Log(LG_ERR, ("[%s] can't setsockopt() %s node: %s",
    	    lnk->name, NG_KSOCKET_NODE_TYPE, strerror(errno)));
	goto fail;
    }

    /* Bind socket */
    u_addrtosockaddr(&pi->self_addr, pi->self_port, &addr);
    if (NgSendMsg(bund->csock, path, NGM_KSOCKET_COOKIE,
	    NGM_KSOCKET_BIND, &addr, addr.ss_len) < 0) {
	Log(LG_ERR, ("[%s] can't bind() %s node: %s",
    	    lnk->name, NG_KSOCKET_NODE_TYPE, strerror(errno)));
	goto fail;
    }
  }

  if (!pi->incoming) {
    if ((!u_addrempty(&pi->peer_addr)) && (pi->peer_port != 0)) {
	u_addrcopy(&pi->peer_addr,&pi->real_peer_addr);
	pi->real_peer_port = pi->peer_port;
    } else {
	Log(LG_ERR, ("[%s] Can't connect without peer specified", lnk->name));
	goto fail;
    }
  }
  u_addrtosockaddr(&pi->real_peer_addr, pi->real_peer_port, &addr);

  /* Connect socket if peer address and port is specified */
  if (NgSendMsg(bund->csock, path, NGM_KSOCKET_COOKIE,
	NGM_KSOCKET_CONNECT, &addr, addr.ss_len) < 0) {
    Log(LG_ERR, ("[%s] can't connect() %s node: %s",
	lnk->name, NG_KSOCKET_NODE_TYPE, strerror(errno)));
    goto fail;
  }

  /* OK */
  p->state = PHYS_STATE_UP;
  PhysUp();
  return;

fail:
    UdpDoClose(pi);
    pi->incoming=0;
    p->state = PHYS_STATE_DOWN;
    u_addrclear(&pi->real_peer_addr);
    pi->real_peer_port=0;
    PhysDown(STR_ERROR, NULL);

}

/*
 * UdpClose()
 */

static void
UdpClose(PhysInfo p)
{
  UdpInfo const pi = (UdpInfo) lnk->phys->info;
  if (p->state != PHYS_STATE_DOWN) {
    UdpDoClose(pi);
    pi->incoming=0;
    p->state = PHYS_STATE_DOWN;
    u_addrclear(&pi->real_peer_addr);
    pi->real_peer_port=0;
    PhysDown(0, NULL);
  }
}

/*
 * UdpDoClose()
 */

static void
UdpDoClose(UdpInfo pi)
{
  char	hook[NG_HOOKLEN + 1];

  snprintf(hook, sizeof(hook),
    "%s%d", NG_PPP_HOOK_LINK_PREFIX, lnk->bundleIndex);
  NgFuncDisconnect(MPD_HOOK_PPP, hook);
}

/*
 * UdpOrigination()
 */

static int
UdpOrigination(PhysInfo p)
{
  UdpInfo	const pi = (UdpInfo) lnk->phys->info;

  return (pi->incoming ? LINK_ORIGINATE_REMOTE : LINK_ORIGINATE_LOCAL);
}

static int
UdpPeerAddr(PhysInfo p, void *buf, int buf_len)
{
  UdpInfo	const pi = (UdpInfo) p->info;

  if (u_addrtoa(&pi->real_peer_addr, buf, buf_len))
    return(0);
  else
    return(-1);
}

/*
 * UdpStat()
 */

void
UdpStat(PhysInfo p)
{
	UdpInfo const pi = (UdpInfo) lnk->phys->info;
	char	buf[64];

	Printf("UDP configuration:\r\n");
	Printf("\tSelf address : %s, port %u\r\n",
	    u_addrtoa(&pi->self_addr, buf, sizeof(buf)), pi->self_port);
	Printf("\tPeer address : %s, port %u\r\n",
	    u_addrtoa(&pi->peer_addr, buf, sizeof(buf)), pi->peer_port);
	Printf("UDP options:\r\n");
	OptStat(&pi->options, gConfList);
	Printf("UDP state:\r\n");
	Printf("\tState        : %s\r\n", gPhysStateNames[p->state]);
	Printf("\tIncoming     : %s\r\n", (pi->incoming?"YES":"NO"));
	Printf("\tCurrent peer : %s, port %u\r\n",
	    u_addrtoa(&pi->real_peer_addr, buf, sizeof(buf)), pi->real_peer_port);
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
		Log(LG_PHYS, ("Shutdown sequence in progress, ignoring"));
		goto failed;
	}

	/* Examine all UDP links. */
	for (k = 0; k < gNumLinks; k++) {
	        UdpInfo pi;
		PhysInfo ph;

		if (gLinks[k] && gLinks[k]->phys->type != &gUdpPhysType)
			continue;

		ph = gLinks[k]->phys;
		pi = (UdpInfo)ph->info;

		if ((If!=pi->If) ||
		    (ph->state != PHYS_STATE_DOWN) ||
		    (now-ph->lastClose < UDP_REOPEN_PAUSE) ||
		    !Enabled(&pi->options, UDP_CONF_INCOMING) ||
		    ((!u_addrempty(&pi->peer_addr)) && u_addrcompare(&pi->peer_addr, &addr)) ||
		    (pi->peer_port != 0 && pi->peer_port != port))
			continue;

		/* Restore context. */
		lnk = gLinks[k];
		bund = lnk->bund;

		Log(LG_PHYS, ("[%s] Accepting connection", lnk->name));

		sockaddrtou_addr(&saddr, &pi->real_peer_addr, &pi->real_peer_port);

		pi->incoming=1;
		ph->state = PHYS_STATE_READY;

		/* Report connected. */
		Log(LG_PHYS, ("[%s] connected with %s %u", lnk->name,
		    u_addrtoa(&addr, buf, sizeof(buf)), port));

		RecordLinkUpDownReason(NULL, 1, STR_INCOMING_CALL, "", NULL);
		BundOpenLink(lnk);

		break;
	}

	if (k == gNumLinks) {
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
	for (k = 0; k < gNumLinks; k++) {
        	UdpInfo pi;
		int i, j = -1;

		if (gLinks[k] == NULL ||
		    gLinks[k]->phys->type != &gUdpPhysType)
			continue;

		pi = (UdpInfo)gLinks[k]->phys->info;

		if (!Enabled(&pi->options, UDP_CONF_INCOMING))
			continue;

		if (!pi->self_port) {
			Log(LG_ERR, ("UDP: Skipping link %s with undefined "
			    "port number", gLinks[k]->name));
			continue;
		}

		for (i = 0; i < UdpIfCount; i++)
			if ((u_addrcompare(&UdpIfs[i].self_addr, &pi->self_addr) == 0) &&
			    (UdpIfs[i].self_port == pi->self_port))
				j = i;

		if (j == -1) {
			if (UdpIfCount>=UDP_MAXPARENTIFS) {
			    Log(LG_ERR, ("[%s] UDP: Too many different listening ports! ", 
				gLinks[k]->name));
			    continue;
			}
			u_addrcopy(&pi->self_addr,&UdpIfs[UdpIfCount].self_addr);
			UdpIfs[UdpIfCount].self_port=pi->self_port;

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

  if (Enabled(&pi->options, UDP_CONF_INCOMING) &&
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
UdpSetCommand(int ac, char *av[], void *arg)
{
  UdpInfo		const pi = (UdpInfo) lnk->phys->info;
  struct sockaddr_storage	*sin;

  switch ((intptr_t)arg) {
    case SET_PEERADDR:
      if ((sin = ParseAddrPort(ac, av, ALLOW_IPV4|ALLOW_IPV6)) == NULL)
	return (-1);
      sockaddrtou_addr(sin, &pi->peer_addr, &pi->peer_port);
      break;
    case SET_SELFADDR:
      if ((sin = ParseAddrPort(ac, av, ALLOW_IPV4|ALLOW_IPV6)) == NULL)
	return (-1);
      sockaddrtou_addr(sin, &pi->self_addr, &pi->self_port);
      break;
    case SET_ENABLE:
	EnableCommand(ac, av, &pi->options, gConfList);
    	UdpNodeUpdate(lnk->phys);
    	break;
    case SET_DISABLE:
	DisableCommand(ac, av, &pi->options, gConfList);
	break;

    default:
      assert(0);
  }
  return(0);
}

