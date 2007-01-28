
/*
 * l2tp.c
 *
 * Written by Alexander Motin <mav@alkar.net>
 */

#include "ppp.h"
#include "phys.h"
#include "mbuf.h"
#include "ngfunc.h"
#include "l2tp.h"
#include "l2tp_avp.h"
#include "l2tp_ctrl.h"
#include "log.h"
#include "msgdef.h"

#include <sys/types.h>
#include <pdel/util/ghash.h>

#include <netgraph/ng_message.h>
#ifdef __DragonFly__
#include <netgraph/socket/ng_socket.h>
#include <netgraph/ksocket/ng_ksocket.h>
#include <netgraph/l2tpgre/ng_l2tp.h>
#else
#include <netgraph/ng_socket.h>
#include <netgraph/ng_ksocket.h>
#include <netgraph/ng_l2tp.h>
#endif
#include <netgraph.h>

/*
 * DEFINITIONS
 */

  #define L2TP_MTU              1600
  #define L2TP_MRU		L2TP_MTU
  
  #define L2TP_PORT		1701

  #define L2TP_MAX_ERRORS	10
  #define L2TP_REOPEN_PAUSE	5

  #define MAX_IOVEC		32

  #define L2TP_CALL_MIN_BPS	56000
  #define L2TP_CALL_MAX_BPS	64000

  struct l2tp_server {
    struct u_addr	self_addr;	/* self IP address */
    in_port_t		self_port;	/* self port */
    int			sock;		/* server listen socket */
    EventRef		event;		/* listen for data messages */
  };
  
  struct l2tp_tun {
    struct u_addr	self_addr;	/* self IP address */
    in_port_t		self_port;	/* self port */
    struct u_addr	peer_addr;	/* peer IP address */
    in_port_t		peer_port;	/* peer port */
    u_char		connected;	/* control connection is connected */
    u_char		alive;		/* control connection is not dying */
    struct ppp_l2tp_ctrl *ctrl;		/* control connection for this tunnel */
  };
  
  struct l2tpinfo {
    struct {
	struct u_addr	self_addr;	/* self IP address */
	in_port_t	self_port;	/* self port */
	struct u_range	peer_addr_req;	/* Peer IP addresses allowed */
	in_port_t	peer_port_req;	/* Peer port required (or zero) */
	char		callingnum[64];	/* L2TP phone number to use */
	char		callednum[64];	/* L2TP phone number to use */
	struct optinfo	options;
    } conf;
    u_char		opened:1;	/* PPPoE opened by phys */
    u_char		incoming:1;	/* Call is incoming vs. outgoing */
    char		callingnum[64];	/* current L2TP phone number */
    char		callednum[64];	/* current L2TP phone number */
    struct l2tp_server	*server;	/* server associated with link */
    struct l2tp_tun	*tun;		/* tunnel associated with link */
    struct ppp_l2tp_sess *sess;		/* current session for this link */
  };
  typedef struct l2tpinfo	*L2tpInfo;

  /* Set menu options */
  enum {
    SET_SELFADDR,
    SET_PEERADDR,
    SET_CALLINGNUM,
    SET_CALLEDNUM,
    SET_ENABLE,
    SET_DISABLE,
  };

  /* Binary options */
  enum {
    L2TP_CONF_ORIGINATE,	/* allow originating connections to peer */
    L2TP_CONF_INCOMING,		/* allow accepting connections from peer */
    L2TP_CONF_OUTCALL,		/* when originating, calls are "outgoing" */
  };

/*
 * INTERNAL FUNCTIONS
 */

  static int	L2tpInit(PhysInfo p);
  static void	L2tpOpen(PhysInfo p);
  static void	L2tpClose(PhysInfo p);
  static void	L2tpShutdown(PhysInfo p);
  static void	L2tpStat(PhysInfo p);
  static int	L2tpOriginated(PhysInfo p);
  static int	L2tpPeerAddr(PhysInfo p, void *buf, int buf_len);
  static int	L2tpCallingNum(PhysInfo p, void *buf, int buf_len);
  static int	L2tpCalledNum(PhysInfo p, void *buf, int buf_len);

  static void	L2tpDoClose(PhysInfo l2tp);

  static void	L2tpNodeUpdate(PhysInfo p);
  static void	L2tpListenUpdate(void *arg);
  static int	L2tpSetCommand(int ac, char *av[], void *arg);

  /* L2TP control callbacks */
  static ppp_l2tp_ctrl_connected_t	ppp_l2tp_ctrl_connected_cb;
  static ppp_l2tp_ctrl_terminated_t	ppp_l2tp_ctrl_terminated_cb;
  static ppp_l2tp_ctrl_destroyed_t	ppp_l2tp_ctrl_destroyed_cb;
  static ppp_l2tp_initiated_t		ppp_l2tp_initiated_cb;
  static ppp_l2tp_connected_t		ppp_l2tp_connected_cb;
  static ppp_l2tp_terminated_t		ppp_l2tp_terminated_cb;

  static const struct ppp_l2tp_ctrl_cb ppp_l2tp_server_ctrl_cb = {
	ppp_l2tp_ctrl_connected_cb,
	ppp_l2tp_ctrl_terminated_cb,
	ppp_l2tp_ctrl_destroyed_cb,
	ppp_l2tp_initiated_cb,
	ppp_l2tp_connected_cb,
	ppp_l2tp_terminated_cb,
	NULL,
	NULL,
  };

/*
 * GLOBAL VARIABLES
 */

  const struct phystype	gL2tpPhysType = {
    .name		= "l2tp",
    .synchronous	= TRUE,
    .minReopenDelay	= L2TP_REOPEN_PAUSE,
    .mtu		= L2TP_MTU,
    .mru		= L2TP_MRU,
    .init		= L2tpInit,
    .open		= L2tpOpen,
    .close		= L2tpClose,
    .shutdown		= L2tpShutdown,
    .showstat		= L2tpStat,
    .originate		= L2tpOriginated,
    .peeraddr		= L2tpPeerAddr,
    .callingnum		= L2tpCallingNum,
    .callednum		= L2tpCalledNum,
  };

  const struct cmdtab	L2tpSetCmds[] = {
    { "self ip [port]",			"Set local IP address",
	L2tpSetCommand, NULL, (void *) SET_SELFADDR },
    { "peer ip [port]",			"Set remote IP address",
	L2tpSetCommand, NULL, (void *) SET_PEERADDR },
    { "callingnum number",		"Set calling L2TP telephone number",
	L2tpSetCommand, NULL, (void *) SET_CALLINGNUM },
    { "callednum number",		"Set called L2TP telephone number",
	L2tpSetCommand, NULL, (void *) SET_CALLEDNUM },
    { "enable [opt ...]",		"Enable option",
	L2tpSetCommand, NULL, (void *) SET_ENABLE },
    { "disable [opt ...]",		"Disable option",
	L2tpSetCommand, NULL, (void *) SET_DISABLE },
    { NULL },
  };

/*
 * INTERNAL VARIABLES
 */

  static struct confinfo	gConfList[] = {
    { 0,	L2TP_CONF_ORIGINATE,	"originate"	},
    { 0,	L2TP_CONF_INCOMING,	"incoming"	},
    { 0,	L2TP_CONF_OUTCALL,	"outcall"	},
    { 0,	0,			NULL		},
  };

int L2tpListenUpdateSheduled = 0;
struct pppTimer L2tpListenUpdateTimer;

static u_char	gInitialized = 0;
struct ghash	*gL2tpServers;
struct ghash	*gL2tpTuns;
int		one = 1;

/*
 * L2tpInit()
 */

static int
L2tpInit(PhysInfo p)
{
  L2tpInfo	l2tp;

  if (!gInitialized) {
    if ((gL2tpServers = ghash_create(NULL, 0, 0, MB_PHYS, NULL, NULL, NULL, NULL))
	== NULL)
	    return(-1);
    if ((gL2tpTuns = ghash_create(NULL, 0, 0, MB_PHYS, NULL, NULL, NULL, NULL))
	== NULL)
	    return(-1);
  }

  /* Initialize this link */
  l2tp = (L2tpInfo) (p->info = Malloc(MB_PHYS, sizeof(*l2tp)));
  
  u_addrclear(&l2tp->conf.self_addr);
  l2tp->conf.self_addr.family = AF_INET;
  l2tp->conf.self_port = 0;
  u_rangeclear(&l2tp->conf.peer_addr_req);
  l2tp->conf.peer_addr_req.addr.family = AF_INET;
  l2tp->conf.peer_addr_req.width = 0;
  l2tp->conf.peer_port_req = 0;
  Disable(&l2tp->conf.options, L2TP_CONF_OUTCALL);
  
  return(0);
}

/*
 * L2tpOpen()
 */

static void
L2tpOpen(PhysInfo p)
{
	L2tpInfo const pi = (L2tpInfo) lnk->phys->info;

	struct l2tp_tun *tun = NULL;
	struct ppp_l2tp_sess *sess;
	struct ppp_l2tp_avp_list *avps = NULL;
	union {
	    u_char buf[sizeof(struct ng_ksocket_sockopt) + sizeof(int)];
	    struct ng_ksocket_sockopt sockopt;
	} sockopt_buf;
	struct ng_ksocket_sockopt *const sockopt = &sockopt_buf.sockopt;
	union {
	    u_char	buf[sizeof(struct ng_mesg) + sizeof(struct sockaddr_storage)];
	    struct ng_mesg	reply;
	} ugetsas;
	struct sockaddr_storage	*const getsas = (struct sockaddr_storage *)(void *)ugetsas.reply.data;
	struct ngm_mkpeer mkpeer;
	struct sockaddr_storage peer_sas;
	struct sockaddr_storage sas;
	char hook[NG_HOOKLEN + 1];
	char namebuf[64];
	ng_ID_t node_id;
	int csock = -1;
	int dsock = -1;
	struct ghash_walk walk;

	pi->opened=1;
	
	if (pi->incoming == 1) {
		Log(LG_PHYS2, ("[%s] L2tpOpen() on incoming call", lnk->name));
		if (p->state==PHYS_STATE_READY) {
		    p->state = PHYS_STATE_UP;
		    PhysUp();
		}
		return;
	}

	/* Sanity check. */
	if (p->state != PHYS_STATE_DOWN) {
		Log(LG_PHYS, ("[%s] L2TP: allready active", lnk->name));
		return;
	};

	if (!Enabled(&pi->conf.options, L2TP_CONF_ORIGINATE)) {
		Log(LG_ERR, ("[%s] L2TP: originate option is not enabled",
		    lnk->name));
		PhysDown(STR_DEV_NOT_READY, NULL);
		return;
	};
	
	strlcpy(pi->callingnum, pi->conf.callingnum, sizeof(pi->callingnum));
	strlcpy(pi->callednum, pi->conf.callednum, sizeof(pi->callednum));

	ghash_walk_init(gL2tpTuns, &walk);
	while ((tun = ghash_walk_next(gL2tpTuns, &walk)) != NULL) {
	    if (tun->ctrl && tun->alive &&
		(IpAddrInRange(&pi->conf.peer_addr_req, &tun->peer_addr)) &&
		(pi->conf.peer_port_req == 0 || pi->conf.peer_port_req == tun->peer_port)) {
		    pi->tun = tun;
		    if (tun->connected) { /* if tun is connected then just initiate */
		    
			/* Create number AVPs */
			if ((avps = ppp_l2tp_avp_list_create()) == NULL) {
				Log(LG_ERR, ("[%s] ppp_l2tp_avp_list_create: %s", 
				    lnk->name, strerror(errno)));
			} else {
			 if (pi->conf.callingnum[0]) {
			  if (ppp_l2tp_avp_list_append(avps, 1, 0, AVP_CALLING_NUMBER,
	        	    pi->conf.callingnum, strlen(pi->conf.callingnum)) == -1) {
				Log(LG_ERR, ("[%s] ppp_l2tp_avp_list_append: %s", 
				    lnk->name, strerror(errno)));
			  }
			 }
			 if (pi->conf.callednum[0]) {
			  if (ppp_l2tp_avp_list_append(avps, 1, 0, AVP_CALLED_NUMBER,
	        	    pi->conf.callednum, strlen(pi->conf.callednum)) == -1) {
				Log(LG_ERR, ("[%s] ppp_l2tp_avp_list_append: %s", 
				    lnk->name, strerror(errno)));
			  }
			 }
			}
			if ((sess = ppp_l2tp_initiate(tun->ctrl, 
				Enabled(&pi->conf.options, L2TP_CONF_OUTCALL)?1:0,
				avps)) == NULL) {
			    Log(LG_ERR, ("[%s] ppp_l2tp_initiate: %s", 
				lnk->name, strerror(errno)));
			    PhysDown(STR_DROPPED, NULL);
			    ppp_l2tp_avp_list_destroy(&avps);
			    pi->sess = NULL;
			    pi->tun = NULL;
			    return;
			};
			ppp_l2tp_avp_list_destroy(&avps);
			Log(LG_PHYS, ("[%s] L2TP: Call %p initiated", lnk->name, sess));
			pi->sess = sess;
			ppp_l2tp_sess_set_cookie(sess, lnk);
			ppp_l2tp_connected(sess, NULL);
		    } /* Else wait while it will be connected */
		    return;
	    }
	}

	/* There is no tun which we need. Create a new one. */
	if ((tun = Malloc(MB_PHYS, sizeof(*tun))) == NULL) {
		Log(LG_ERR, ("[%s] malloc: %s", 
		    lnk->name, strerror(errno)));
		return;
	}
	memset(tun, 0, sizeof(*tun));
	sockaddrtou_addr(&peer_sas,&tun->peer_addr,&tun->peer_port);
	u_addrcopy(&pi->conf.peer_addr_req.addr, &tun->peer_addr);
	tun->peer_port = pi->conf.peer_port_req?pi->conf.peer_port_req:L2TP_PORT;
	u_addrcopy(&pi->conf.self_addr, &tun->self_addr);
	tun->self_port = pi->conf.self_port;
	tun->alive = 1;
	tun->connected = 0;

	/* Create vendor name AVP */
	if ((avps = ppp_l2tp_avp_list_create()) == NULL) {
		Log(LG_ERR, ("[%s] ppp_l2tp_avp_list_create: %s", 
		    lnk->name, strerror(errno)));
		goto fail;
	}
	if (ppp_l2tp_avp_list_append(avps, 1, 0, AVP_VENDOR_NAME,
	    MPD_VENDOR, strlen(MPD_VENDOR)) == -1) {
		Log(LG_ERR, ("[%s] ppp_l2tp_avp_list_append: %s", 
		    lnk->name, strerror(errno)));
		goto fail;
	}

	/* Create a new control connection */
	if ((tun->ctrl = ppp_l2tp_ctrl_create(gPeventCtx, &gGiantMutex,
	    &ppp_l2tp_server_ctrl_cb, 0,//XXX: ntohl(peer_sin.sin_addr.s_addr),
	    &node_id, hook, avps, NULL, 0)) == NULL) {
		Log(LG_ERR, ("[%s] ppp_l2tp_ctrl_create: %s", 
		    lnk->name, strerror(errno)));
		goto fail;
	}
	ppp_l2tp_ctrl_set_cookie(tun->ctrl, tun);

	/* Get a temporary netgraph socket node */
	if (NgMkSockNode(NULL, &csock, &dsock) == -1) {
		Log(LG_ERR, ("[%s] NgMkSockNode: %s", 
		    lnk->name, strerror(errno)));
		goto fail;
	}

	/* Attach a new UDP socket to "lower" hook */
	snprintf(namebuf, sizeof(namebuf), "[%lx]:", (u_long)node_id);
	memset(&mkpeer, 0, sizeof(mkpeer));
	strlcpy(mkpeer.type, NG_KSOCKET_NODE_TYPE, sizeof(mkpeer.type));
	strlcpy(mkpeer.ourhook, hook, sizeof(mkpeer.ourhook));
	if (tun->peer_addr.family==AF_INET6) {
		snprintf(mkpeer.peerhook, sizeof(mkpeer.peerhook), "%d/%d/%d", PF_INET6, SOCK_DGRAM, IPPROTO_UDP);
	} else {
	        snprintf(mkpeer.peerhook, sizeof(mkpeer.peerhook), "inet/dgram/udp");
	}
	if (NgSendMsg(csock, namebuf, NGM_GENERIC_COOKIE,
	    NGM_MKPEER, &mkpeer, sizeof(mkpeer)) == -1) {
		Log(LG_ERR, ("[%s] mkpeer: %s", 
		    lnk->name, strerror(errno)));
		goto fail;
	}

	/* Point name at ksocket node */
	strlcat(namebuf, hook, sizeof(namebuf));

	/* Make UDP port reusable */
	memset(&sockopt_buf, 0, sizeof(sockopt_buf));
	sockopt->level = SOL_SOCKET;
	sockopt->name = SO_REUSEADDR;
	memcpy(sockopt->value, &one, sizeof(int));
	if (NgSendMsg(csock, namebuf, NGM_KSOCKET_COOKIE,
	    NGM_KSOCKET_SETOPT, sockopt, sizeof(sockopt_buf)) == -1) {
		Log(LG_ERR, ("[%s] setsockopt: %s", 
		    lnk->name, strerror(errno)));
		goto fail;
	}
	sockopt->name = SO_REUSEPORT;
	if (NgSendMsg(csock, namebuf, NGM_KSOCKET_COOKIE,
	    NGM_KSOCKET_SETOPT, sockopt, sizeof(sockopt_buf)) == -1) {
		Log(LG_ERR, ("[%s] setsockopt: %s", 
		    lnk->name, strerror(errno)));
		goto fail;
	}

	if (!u_addrempty(&tun->self_addr)) {
	    /* Bind socket to a new port */
	    u_addrtosockaddr(&tun->self_addr,tun->self_port,&sas);
	    if (NgSendMsg(csock, namebuf, NGM_KSOCKET_COOKIE,
		NGM_KSOCKET_BIND, &sas, sas.ss_len) == -1) {
		    Log(LG_ERR, ("[%s] bind: %s", 
			lnk->name, strerror(errno)));
		    goto fail;
	    }
	}
	/* Connect socket to remote peer's IP and port */
	u_addrtosockaddr(&tun->peer_addr,tun->peer_port,&sas);
	if (NgSendMsg(csock, namebuf, NGM_KSOCKET_COOKIE,
	      NGM_KSOCKET_CONNECT, &sas, sas.ss_len) == -1
	    && errno != EINPROGRESS) {
		Log(LG_ERR, ("[%s] connect: %s", 
		    lnk->name, strerror(errno)));
		goto fail;
	}

	if (NgSendMsg(csock, namebuf, NGM_KSOCKET_COOKIE,
	    NGM_KSOCKET_GETNAME, NULL, 0) == -1) {
		Log(LG_ERR, ("[%s] getname send: %s", 
		    lnk->name, strerror(errno)));
	} else 
	if (NgRecvMsg(csock, &ugetsas.reply, sizeof(ugetsas), NULL) == -1) {
		Log(LG_ERR, ("[%s] getname recv: %s", 
		    lnk->name, strerror(errno)));
	} else {
	    sockaddrtou_addr(getsas,&tun->self_addr,&tun->self_port);
	}

	/* Add peer to our hash table */
	if (ghash_put(gL2tpTuns, tun) == -1) {
		Log(LG_ERR, ("[%s] ghash_put: %s", 
		    lnk->name, strerror(errno)));
		goto fail;
	}
	pi->tun = tun;
	ppp_l2tp_ctrl_initiate(tun->ctrl);
	Log(LG_PHYS, ("L2TP: Control connection %p initiated", tun->ctrl));

	/* Clean up and return */
	ppp_l2tp_avp_list_destroy(&avps);
	(void)close(csock);
	(void)close(dsock);
	return;

fail:
	/* Clean up after failure */
	if (csock != -1)
		(void)close(csock);
	if (dsock != -1)
		(void)close(dsock);
	if (tun != NULL) {
		ppp_l2tp_ctrl_destroy(&tun->ctrl);
		Freee(MB_PHYS, tun);
	}
	PhysDown(STR_DEV_NOT_READY, NULL);
};

/*
 * L2tpClose()
 */

static void
L2tpClose(PhysInfo p)
{
    L2tpInfo      const pi = (L2tpInfo) p->info;

    pi->opened = 0;
    pi->incoming = 0;
    if (p->state == PHYS_STATE_DOWN)
    	return;
    PhysDown(0, NULL);
    L2tpDoClose(p);
    if (pi->sess) {
	Log(LG_PHYS, ("[%s] L2TP: Call %p terminated", lnk->name, pi->sess));
	ppp_l2tp_terminate(pi->sess, L2TP_RESULT_ADMIN, 0, NULL);
	pi->sess = NULL;
    }
    pi->tun = NULL;
    pi->callingnum[0]=0;
    pi->callednum[0]=0;
    p->state = PHYS_STATE_DOWN;
}

/*
 * L2tpShutdown()
 */

static void
L2tpShutdown(PhysInfo p)
{
    struct ghash_walk walk;
    struct l2tp_tun *tun;

    ghash_walk_init(gL2tpTuns, &walk);
    while ((tun = ghash_walk_next(gL2tpTuns, &walk)) != NULL) {
	if (tun->ctrl) {
	    if (tun->alive)
		ppp_l2tp_ctrl_shutdown(tun->ctrl,
		    L2TP_RESULT_SHUTDOWN, 0, NULL);
	    ppp_l2tp_ctrl_destroy(&tun->ctrl);
	}
    }
}

/*
 * L2tpDoClose()
 */

static void
L2tpDoClose(PhysInfo p)
{
    L2tpInfo      const pi = (L2tpInfo) p->info;
    const char *hook;
    ng_ID_t node_id;
    char	path[NG_PATHLEN + 1];
	
    if (pi->sess) {		/* avoid double close */
	/* Get this link's node and hook */
	ppp_l2tp_sess_get_hook(pi->sess, &node_id, &hook);

	/* Disconnect session hook. */
	snprintf(path, sizeof(path), "[%lx]:", (u_long)node_id);
	NgFuncDisconnect(path, hook);
    }
}

/*
 * L2tpOriginated()
 */

static int
L2tpOriginated(PhysInfo p)
{
  L2tpInfo	const l2tp = (L2tpInfo) p->info;

  return(l2tp->incoming ? LINK_ORIGINATE_REMOTE : LINK_ORIGINATE_LOCAL);
}

static int
L2tpPeerAddr(PhysInfo p, void *buf, int buf_len)
{
    L2tpInfo	const l2tp = (L2tpInfo) p->info;

    if (l2tp->tun) {
	if (u_addrtoa(&l2tp->tun->peer_addr, buf, buf_len))
	    return(0);
	else {
	    ((char*)buf)[0]=0;
	    return(-1);
	}
    }
    ((char*)buf)[0]=0;
    return(0);
}

static int
L2tpCallingNum(PhysInfo p, void *buf, int buf_len)
{
    L2tpInfo	const l2tp = (L2tpInfo) p->info;

    strlcpy((char*)buf, l2tp->callingnum, buf_len);
    return(0);
}

static int
L2tpCalledNum(PhysInfo p, void *buf, int buf_len)
{
    L2tpInfo	const l2tp = (L2tpInfo) p->info;

    strlcpy((char*)buf, l2tp->callednum, buf_len);
    return(0);
}

/*
 * L2tpStat()
 */

void
L2tpStat(PhysInfo p)
{
  L2tpInfo	const l2tp = (L2tpInfo) lnk->phys->info;
  char		buf[32];

  Printf("L2TP configuration:\r\n");
  Printf("\tSelf addr    : %s, port %u",
    u_addrtoa(&l2tp->conf.self_addr, buf, sizeof(buf)), l2tp->conf.self_port);
  Printf("\r\n");
  Printf("\tPeer range   : %s",
    u_rangetoa(&l2tp->conf.peer_addr_req, buf, sizeof(buf)));
  if (l2tp->conf.peer_port_req)
    Printf(", port %u", l2tp->conf.peer_port_req);
  Printf("\r\n");
  Printf("\tCalling number: %s\r\n", l2tp->conf.callingnum);
  Printf("\tCalled number: %s\r\n", l2tp->conf.callednum);
  Printf("L2TP options:\r\n");
  OptStat(&l2tp->conf.options, gConfList);
  Printf("L2TP status:\r\n");
  Printf("\tState        : %s\r\n", gPhysStateNames[p->state]);
  if (p->state != PHYS_STATE_DOWN) {
    Printf("\tIncoming     : %s\r\n", (l2tp->incoming?"YES":"NO"));
    if (l2tp->tun) {
	Printf("\tCurrent self : %s, port %u\r\n",
	    u_addrtoa(&l2tp->tun->self_addr, buf, sizeof(buf)), l2tp->tun->self_port);
	Printf("\tCurrent peer : %s, port %u\r\n",
	    u_addrtoa(&l2tp->tun->peer_addr, buf, sizeof(buf)), l2tp->tun->peer_port);
    }
    Printf("\tCalling number: %s\r\n", l2tp->callingnum);
    Printf("\tCalled number: %s\r\n", l2tp->callednum);
  }
}

/*
 * This is called when a control connection gets opened.
 */
static void
ppp_l2tp_ctrl_connected_cb(struct ppp_l2tp_ctrl *ctrl)
{
	struct l2tp_tun *tun = ppp_l2tp_ctrl_get_cookie(ctrl);
	struct ppp_l2tp_sess *sess;
	struct ppp_l2tp_avp_list *avps = NULL;
	int	k;

	Log(LG_PHYS, ("L2TP: Control connection %p connected", ctrl));

	/* Examine all L2TP links. */
	for (k = 0; k < gNumLinks; k++) {
	        L2tpInfo pi;
		PhysInfo p;

		if (gLinks[k] && gLinks[k]->phys->type != &gL2tpPhysType)
			continue;

		p = gLinks[k]->phys;
		pi = (L2tpInfo)p->info;

		if (pi->tun != tun)
			continue;

		/* Restore context. */
		lnk = gLinks[k];
		bund = lnk->bund;

		tun->connected = 1;
		/* Create number AVPs */
		if ((avps = ppp_l2tp_avp_list_create()) == NULL) {
			Log(LG_ERR, ("[%s] ppp_l2tp_avp_list_create: %s", 
			    lnk->name, strerror(errno)));
		} else {
		  if (pi->conf.callingnum[0]) {
		   if (ppp_l2tp_avp_list_append(avps, 1, 0, AVP_CALLING_NUMBER,
	            pi->conf.callingnum, strlen(pi->conf.callingnum)) == -1) {
			Log(LG_ERR, ("[%s] ppp_l2tp_avp_list_append: %s", 
			    lnk->name, strerror(errno)));
		   }
		  }
		  if (pi->conf.callednum[0]) {
		   if (ppp_l2tp_avp_list_append(avps, 1, 0, AVP_CALLED_NUMBER,
	            pi->conf.callednum, strlen(pi->conf.callednum)) == -1) {
			Log(LG_ERR, ("[%s] ppp_l2tp_avp_list_append: %s", 
			    lnk->name, strerror(errno)));
		   }
		  }
		}
		if ((sess = ppp_l2tp_initiate(tun->ctrl,
			    Enabled(&pi->conf.options, L2TP_CONF_OUTCALL)?1:0, 
			    avps)) == NULL) {
			Log(LG_ERR, ("ppp_l2tp_initiate: %s", strerror(errno)));
			PhysDown(STR_DROPPED, NULL);
			pi->sess = NULL;
			pi->tun = NULL;
			continue;
		};
		ppp_l2tp_avp_list_destroy(&avps);
		Log(LG_PHYS, ("[%s] L2TP: call %p initiated", lnk->name, sess));
		pi->sess = sess;
		ppp_l2tp_sess_set_cookie(sess, lnk);
		ppp_l2tp_connected(sess, NULL);
	};
}

/*
 * This is called when a control connection is terminated for any reason
 * other than a call ppp_l2tp_ctrl_destroy().
 */
static void
ppp_l2tp_ctrl_terminated_cb(struct ppp_l2tp_ctrl *ctrl,
	u_int16_t result, u_int16_t error, const char *errmsg)
{
	struct l2tp_tun *tun = ppp_l2tp_ctrl_get_cookie(ctrl);
	int	k;

	Log(LG_PHYS, ("L2TP: Control connection %p terminated: %d (%s)", 
	    ctrl, error, errmsg));

	/* Examine all L2TP links. */
	for (k = 0; k < gNumLinks; k++) {
	        L2tpInfo pi;
		PhysInfo p;

		if (gLinks[k] && gLinks[k]->phys->type != &gL2tpPhysType)
			continue;

		p = gLinks[k]->phys;
		pi = (L2tpInfo)p->info;

		if (pi->tun != tun)
			continue;

		/* Restore context. */
		lnk = gLinks[k];
		bund = lnk->bund;

		p->state = PHYS_STATE_DOWN;
		PhysDown(STR_DROPPED, NULL);
		L2tpDoClose(p);
		pi->sess = NULL;
		pi->tun = NULL;
		pi->callingnum[0]=0;
	        pi->callednum[0]=0;
	};
	
	tun->alive = 0;
}

/*
 * This is called before control connection is destroyed for any reason
 * other than a call ppp_l2tp_ctrl_destroy().
 */
static void
ppp_l2tp_ctrl_destroyed_cb(struct ppp_l2tp_ctrl *ctrl)
{
	struct l2tp_tun *tun = ppp_l2tp_ctrl_get_cookie(ctrl);

	Log(LG_PHYS, ("L2TP: Control connection %p destroyed", ctrl));

	ghash_remove(gL2tpTuns, tun);
	Freee(MB_PHYS, tun);
}

/*
 * This callback is used to report the peer's initiating a new incoming
 * or outgoing call.
 */
static void
ppp_l2tp_initiated_cb(struct ppp_l2tp_ctrl *ctrl,
	struct ppp_l2tp_sess *sess, int out,
	const struct ppp_l2tp_avp_list *avps)
{
	struct l2tp_tun *const tun = ppp_l2tp_ctrl_get_cookie(ctrl);
	struct ppp_l2tp_avp_ptrs *ptrs = NULL;
	int	k;
	time_t  const now = time(NULL);

	/* Convert AVP's to friendly form */
	if ((ptrs = ppp_l2tp_avp_list2ptrs(avps)) == NULL) {
		Log(LG_ERR, ("L2TP: error decoding AVP list: %s", strerror(errno)));
		goto fail;
	}

	Log(LG_PHYS, ("L2TP: %s call via connection %p", 
	    (out?"Outgoing":"Incoming"), ctrl));

	/* Examine all L2TP links. */
	for (k = 0; k < gNumLinks; k++) {
	        L2tpInfo pi;
		PhysInfo p;

		if (gLinks[k] && gLinks[k]->phys->type != &gL2tpPhysType)
			continue;

		p = gLinks[k]->phys;
		pi = (L2tpInfo)p->info;

		if ((p->state != PHYS_STATE_DOWN) ||
		    (now-p->lastClose < L2TP_REOPEN_PAUSE) ||
		    !Enabled(&pi->conf.options, L2TP_CONF_INCOMING) ||
		    ((!u_addrempty(&pi->conf.self_addr)) && u_addrcompare(&pi->conf.self_addr, &tun->peer_addr)) ||
		    (pi->conf.self_port != 0 && pi->conf.self_port != tun->self_port) ||
		    (!IpAddrInRange(&pi->conf.peer_addr_req, &tun->peer_addr)) ||
		    (pi->conf.peer_port_req != 0 && pi->conf.peer_port_req != tun->peer_port))
			continue;

		/* Restore context. */
		lnk = gLinks[k];
		bund = lnk->bund;

		Log(LG_PHYS, ("[%s] L2TP: %s call %p via control connection %p accepted", 
		    lnk->name, (out?"Outgoing":"Incoming"), sess, ctrl));

		p->state = PHYS_STATE_CONNECTING;
		pi->incoming = 1;
		pi->tun = tun;
		pi->sess = sess;
		if (ptrs->callingnum->number)
		    strlcpy(pi->callingnum, ptrs->callingnum->number, sizeof(pi->callingnum));
		if (ptrs->callednum->number)
		    strlcpy(pi->callednum, ptrs->callednum->number, sizeof(pi->callednum));

		RecordLinkUpDownReason(NULL, 1, STR_INCOMING_CALL, "", NULL);
		BundOpenLink(lnk);

		ppp_l2tp_sess_set_cookie(sess, lnk);
		if (out)
		    ppp_l2tp_connected(sess, NULL);
		ppp_l2tp_avp_ptrs_destroy(&ptrs);
		return;
	}
fail:
	Log(LG_PHYS, ("L2TP: No free link with requested parameters "
	    "was found"));
	ppp_l2tp_terminate(sess, L2TP_RESULT_ERROR,
	    L2TP_ERROR_GENERIC, strerror(errno));
	ppp_l2tp_avp_ptrs_destroy(&ptrs);
}

/*
 * This callback is used to report successful connection of a remotely
 * initiated incoming call (see ppp_l2tp_initiated_t) or a locally initiated
 * outgoing call (see ppp_l2tp_initiate()).
 */
static void
ppp_l2tp_connected_cb(struct ppp_l2tp_sess *sess,
	const struct ppp_l2tp_avp_list *avps)
{
        const char *hook;
        ng_ID_t node_id;
	char path[NG_PATHLEN + 1];
	char linkHook[NG_HOOKLEN + 1];
	PhysInfo p;
	L2tpInfo pi;

	lnk = ppp_l2tp_sess_get_cookie(sess);
	bund = lnk->bund;
	
	p = lnk->phys;
	pi = (L2tpInfo)p->info;

	Log(LG_PHYS, ("[%s] L2TP: call %p connected", lnk->name, sess));

	/* Get this link's node and hook */
	ppp_l2tp_sess_get_hook(sess, &node_id, &hook);

	/* Connect our ng_ppp(4) node link hook and ng_l2tp(4) node. */
	snprintf(path, sizeof(path), "[%lx]:", (u_long)node_id);
	snprintf(linkHook, sizeof(linkHook), "%s%d",
	    NG_PPP_HOOK_LINK_PREFIX, lnk->bundleIndex);
	if (NgFuncConnect(MPD_HOOK_PPP, linkHook, path, hook) < 0) {
		Log(LG_ERR, ("[%s] can't connect to ppp: %s",
		    lnk->name, strerror(errno)));
		ppp_l2tp_terminate(sess, L2TP_RESULT_ERROR,
		    L2TP_ERROR_GENERIC, strerror(errno));
		return;
	}

	if (pi->opened) {
	    p->state = PHYS_STATE_UP;
	    PhysUp();
	} else {
	    p->state = PHYS_STATE_READY;
	}
}

/*
 * This callback is called when any call, whether successfully connected
 * or not, is terminated for any reason other than explict termination
 * from the link side (via a call to either ppp_l2tp_terminate() or
 * ppp_l2tp_ctrl_destroy()).
 */
static void
ppp_l2tp_terminated_cb(struct ppp_l2tp_sess *sess,
	u_int16_t result, u_int16_t error, const char *errmsg)
{
	char buf[128];
	PhysInfo p;
	L2tpInfo pi;

	lnk = ppp_l2tp_sess_get_cookie(sess);
	bund = lnk->bund;
        p = lnk->phys;
	pi = (L2tpInfo) p->info;

	/* Control side is notifying us session is down */
	snprintf(buf, sizeof(buf), "result=%u error=%u errmsg=\"%s\"",
	    result, error, (errmsg != NULL) ? errmsg : "");
	Log(LG_PHYS, ("[%s] L2TP: call %p terminated: %s", lnk->name, sess, buf));

	p->state = PHYS_STATE_DOWN;
	PhysDown(STR_DROPPED, NULL);
	L2tpDoClose(p);
	pi->sess = NULL;
	pi->tun = NULL;
	pi->callingnum[0]=0;
	pi->callednum[0]=0;
}

/*
 * Read an incoming packet that might be a new L2TP connection.
 */
 
static void
L2tpServerEvent(int type, void *arg)
{
	struct l2tp_server *const s = arg;
	struct ppp_l2tp_avp_list *avps = NULL;
	struct l2tp_tun *tun = NULL;
	union {
	    u_char buf[sizeof(struct ng_ksocket_sockopt) + sizeof(int)];
	    struct ng_ksocket_sockopt sockopt;
	} sockopt_buf;
	struct ng_ksocket_sockopt *const sockopt = &sockopt_buf.sockopt;
	struct ngm_connect connect;
	struct ngm_rmhook rmhook;
	struct ngm_mkpeer mkpeer;
	struct sockaddr_storage peer_sas;
	struct sockaddr_storage sas;
	const size_t bufsize = 8192;
	u_int16_t *buf = NULL;
	char hook[NG_HOOKLEN + 1];
	socklen_t sas_len;
	char namebuf[64];
	ng_ID_t node_id;
	int csock = -1;
	int dsock = -1;
	int len;

	/* Allocate buffer */
	if ((buf = Malloc(MB_PHYS, bufsize)) == NULL) {
		Log(LG_ERR, ("L2TP: malloc: %s", strerror(errno)));
		goto fail;
	}

	/* Read packet */
	sas_len = sizeof(peer_sas);
	if ((len = recvfrom(s->sock, buf, bufsize, 0,
	    (struct sockaddr *)&peer_sas, &sas_len)) == -1) {
		Log(LG_ERR, ("L2TP: recvfrom: %s", strerror(errno)));
		goto fail;
	}

	/* Drop it if it's not an initial L2TP packet */
	if (len < 12)
		goto fail;
	if ((ntohs(buf[0]) & 0xcb0f) != 0xc802 || ntohs(buf[1]) < 12
	    || buf[2] != 0 || buf[3] != 0 || buf[4] != 0 || buf[5] != 0)
		goto fail;

	/* Create a new tun */
	if ((tun = Malloc(MB_PHYS, sizeof(*tun))) == NULL) {
		Log(LG_ERR, ("L2TP: malloc: %s", strerror(errno)));
		return;
	}
	memset(tun, 0, sizeof(*tun));
	sockaddrtou_addr(&peer_sas,&tun->peer_addr,&tun->peer_port);
	u_addrcopy(&s->self_addr, &tun->self_addr);
	tun->self_port = s->self_port;
	tun->alive = 1;

	Log(LG_PHYS, ("Incoming L2TP packet from %s %d", 
		u_addrtoa(&tun->peer_addr, namebuf, sizeof(namebuf)), tun->peer_port));

	/* Create vendor name AVP */
	if ((avps = ppp_l2tp_avp_list_create()) == NULL) {
		Log(LG_ERR, ("L2TP: ppp_l2tp_avp_list_create: %s", strerror(errno)));
		goto fail;
	}
	if (ppp_l2tp_avp_list_append(avps, 1, 0, AVP_VENDOR_NAME,
	    MPD_VENDOR, strlen(MPD_VENDOR)) == -1) {
		Log(LG_ERR, ("L2TP: ppp_l2tp_avp_list_append: %s", strerror(errno)));
		goto fail;
	}

	/* Create a new control connection */
	if ((tun->ctrl = ppp_l2tp_ctrl_create(gPeventCtx, &gGiantMutex,
	    &ppp_l2tp_server_ctrl_cb, 0,//XXX: ntohl(peer_sin.sin_addr.s_addr),
	    &node_id, hook, avps, NULL, 0)) == NULL) {
		Log(LG_ERR, ("L2TP: ppp_l2tp_ctrl_create: %s", strerror(errno)));
		goto fail;
	}
	ppp_l2tp_ctrl_set_cookie(tun->ctrl, tun);

	/* Get a temporary netgraph socket node */
	if (NgMkSockNode(NULL, &csock, &dsock) == -1) {
		Log(LG_ERR, ("L2TP: NgMkSockNode: %s", strerror(errno)));
		goto fail;
	}

	/* Connect to l2tp netgraph node "lower" hook */
	snprintf(namebuf, sizeof(namebuf), "[%lx]:", (u_long)node_id);
	memset(&connect, 0, sizeof(connect));
	strlcpy(connect.path, namebuf, sizeof(connect.path));
	strlcpy(connect.ourhook, hook, sizeof(connect.ourhook));
	strlcpy(connect.peerhook, hook, sizeof(connect.peerhook));
	if (NgSendMsg(csock, ".", NGM_GENERIC_COOKIE,
	    NGM_CONNECT, &connect, sizeof(connect)) == -1) {
		Log(LG_ERR, ("L2TP: %s: %s", "connect", strerror(errno)));
		goto fail;
	}

	/* Write the received packet to the node */
	if (NgSendData(dsock, hook, (u_char *)buf, len) == -1) {
		Log(LG_ERR, ("L2TP: %s: %s", "NgSendData", strerror(errno)));
		goto fail;
	}

	/* Disconnect from netgraph node "lower" hook */
	memset(&rmhook, 0, sizeof(rmhook));
	strlcpy(rmhook.ourhook, hook, sizeof(rmhook.ourhook));
	if (NgSendMsg(csock, ".", NGM_GENERIC_COOKIE,
	    NGM_RMHOOK, &rmhook, sizeof(rmhook)) == -1) {
		Log(LG_ERR, ("L2TP: %s: %s", "rmhook", strerror(errno)));
		goto fail;
	}

	/* Attach a new UDP socket to "lower" hook */
	memset(&mkpeer, 0, sizeof(mkpeer));
	strlcpy(mkpeer.type, NG_KSOCKET_NODE_TYPE, sizeof(mkpeer.type));
	strlcpy(mkpeer.ourhook, hook, sizeof(mkpeer.ourhook));
	if (s->self_addr.family==AF_INET6) {
		snprintf(mkpeer.peerhook, sizeof(mkpeer.peerhook), "%d/%d/%d", PF_INET6, SOCK_DGRAM, IPPROTO_UDP);
	} else {
	        snprintf(mkpeer.peerhook, sizeof(mkpeer.peerhook), "inet/dgram/udp");
	}
	if (NgSendMsg(csock, namebuf, NGM_GENERIC_COOKIE,
	    NGM_MKPEER, &mkpeer, sizeof(mkpeer)) == -1) {
		Log(LG_ERR, ("L2TP: %s: %s", "mkpeer", strerror(errno)));
		goto fail;
	}

	/* Point name at ksocket node */
	strlcat(namebuf, hook, sizeof(namebuf));

	/* Make UDP port reusable */
	memset(&sockopt_buf, 0, sizeof(sockopt_buf));
	sockopt->level = SOL_SOCKET;
	sockopt->name = SO_REUSEADDR;
	memcpy(sockopt->value, &one, sizeof(int));
	if (NgSendMsg(csock, namebuf, NGM_KSOCKET_COOKIE,
	    NGM_KSOCKET_SETOPT, sockopt, sizeof(sockopt_buf)) == -1) {
		Log(LG_ERR, ("L2TP: setsockopt: %s", strerror(errno)));
		goto fail;
	}
	sockopt->name = SO_REUSEPORT;
	if (NgSendMsg(csock, namebuf, NGM_KSOCKET_COOKIE,
	    NGM_KSOCKET_SETOPT, sockopt, sizeof(sockopt_buf)) == -1) {
		Log(LG_ERR, ("L2TP: setsockopt: %s", strerror(errno)));
		goto fail;
	}

	/* Bind socket to a new port */
	u_addrtosockaddr(&s->self_addr,s->self_port,&sas);
	if (NgSendMsg(csock, namebuf, NGM_KSOCKET_COOKIE,
	    NGM_KSOCKET_BIND, &sas, sas.ss_len) == -1) {
		Log(LG_ERR, ("L2TP: bind: %s", strerror(errno)));
		goto fail;
	}

	/* Connect socket to remote peer's IP and port */
	if (NgSendMsg(csock, namebuf, NGM_KSOCKET_COOKIE,
	      NGM_KSOCKET_CONNECT, &peer_sas, peer_sas.ss_len) == -1
	    && errno != EINPROGRESS) {
		Log(LG_ERR, ("L2TP: connect: %s", strerror(errno)));
		goto fail;
	}

	/* Add peer to our hash table */
	if (ghash_put(gL2tpTuns, tun) == -1) {
		Log(LG_ERR, ("L2TP: %s: %s", "ghash_put", strerror(errno)));
		goto fail;
	}

	/* Clean up and return */
	ppp_l2tp_avp_list_destroy(&avps);
	(void)close(csock);
	(void)close(dsock);
	Freee(MB_PHYS, buf);
	return;

fail:
	/* Clean up after failure */
	if (csock != -1)
		(void)close(csock);
	if (dsock != -1)
		(void)close(dsock);
	if (tun != NULL) {
		ppp_l2tp_ctrl_destroy(&tun->ctrl);
		Freee(MB_PHYS, tun);
	}
	ppp_l2tp_avp_list_destroy(&avps);
	Freee(MB_PHYS, buf);
}


/*
 * L2tpServerCreate()
 */

static struct l2tp_server *
L2tpServerCreate(L2tpInfo const p)
{
	struct l2tp_server *s;
	struct sockaddr_storage sa;
	char buf[64];

	if ((s = Malloc(MB_PHYS, sizeof(struct l2tp_server))) == NULL) {
	    return (NULL);
	}
	
	memset(s, 0, sizeof(*s));
	u_addrcopy(&p->conf.self_addr, &s->self_addr);
	s->self_port = p->conf.self_port?p->conf.self_port:L2TP_PORT;
	
	/* Setup UDP socket that listens for new connections */
	if (s->self_addr.family==AF_INET6) {
		s->sock = socket(PF_INET6, SOCK_DGRAM, IPPROTO_UDP);
	} else {
		s->sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
	}
	if (s->sock == -1) {
		Log(LG_ERR, ("L2TP: socket: %s", strerror(errno)));
		goto fail;
	}
	if (setsockopt(s->sock, SOL_SOCKET,
	    SO_REUSEADDR, &one, sizeof(one)) == -1) {
		Log(LG_ERR, ("L2TP: setsockopt: %s", strerror(errno)));
		goto fail;
	}
	if (setsockopt(s->sock, SOL_SOCKET,
	    SO_REUSEPORT, &one, sizeof(one)) == -1) {
		Log(LG_ERR, ("L2TP: setsockopt: %s", strerror(errno)));
		goto fail;
	}
	u_addrtosockaddr(&s->self_addr, s->self_port, &sa);
	if (bind(s->sock, (struct sockaddr *)&sa, sa.ss_len) == -1) {
		Log(LG_ERR, ("L2TP: bind: %s", strerror(errno)));
		goto fail;
	}

	EventRegister(&s->event, EVENT_READ, s->sock,
	    EVENT_RECURRING, L2tpServerEvent, s);

	Log(LG_PHYS, ("L2TP: waiting for connection on %s %u",
	    u_addrtoa(&s->self_addr, buf, sizeof(buf)), s->self_port));
	
	return (s);
fail:
	if (s->sock)
	    close(s->sock);
	Freee(MB_PHYS, s);
	return (NULL);
}

/*
 * L2tpNodeUpdate()
 */

static void
L2tpNodeUpdate(PhysInfo p)
{
  L2tpInfo pe = (L2tpInfo)p->info;

  if (Enabled(&pe->conf.options, L2TP_CONF_INCOMING) &&
        (!L2tpListenUpdateSheduled)) {
    	    /* Set a timer to run PppoeListenUpdate(). */
	    TimerInit(&L2tpListenUpdateTimer, "L2tpListenUpdate",
		0, L2tpListenUpdate, NULL);
	    TimerStart(&L2tpListenUpdateTimer);
	    L2tpListenUpdateSheduled = 1;
  }
}

/*
 * L2tpListenUpdate()
 */

static void
L2tpListenUpdate(void *arg)
{
  int	k;

  /* Examine all L2TP links */
  for (k = 0; k < gNumLinks; k++) {
    if (gLinks[k] && gLinks[k]->phys->type == &gL2tpPhysType) {
        L2tpInfo	const p = (L2tpInfo)gLinks[k]->phys->info;

        if (Enabled(&p->conf.options, L2TP_CONF_INCOMING)) {
	    struct ghash_walk walk;
	    struct l2tp_server *srv;

	    ghash_walk_init(gL2tpServers, &walk);
	    while ((srv = ghash_walk_next(gL2tpServers, &walk)) != NULL) {
		if ((u_addrcompare(&srv->self_addr, &p->conf.self_addr) == 0) && 
		    srv->self_port == (p->conf.self_port?p->conf.self_port:L2TP_PORT)) {
			p->server = srv;
			break;
		}
	    }
	    if (srv == NULL) {
		if ((srv = L2tpServerCreate(p)) == NULL) {
		    Log(LG_ERR, ("L2tpServerCreate error"));
		    continue;
		}
		p->server = srv;
		ghash_put(gL2tpServers, srv);
	    }
        }
    }
  }
}

/*
 * L2tpSetCommand()
 */

static int
L2tpSetCommand(int ac, char *av[], void *arg)
{
  L2tpInfo		const l2tp = (L2tpInfo) lnk->phys->info;
  struct u_range	rng;
  int			port;

  switch ((intptr_t)arg) {
    case SET_SELFADDR:
    case SET_PEERADDR:
      if (ac < 1 || ac > 2 || !ParseRange(av[0], &rng, ALLOW_IPV4|ALLOW_IPV6))
	return(-1);
      if (ac > 1) {
	if ((port = atoi(av[1])) < 0 || port > 0xffff)
	  return(-1);
      } else {
	port = 0;
      }
      if ((intptr_t)arg == SET_SELFADDR) {
	l2tp->conf.self_addr = rng.addr;
	l2tp->conf.self_port = port;
      } else {
	l2tp->conf.peer_addr_req = rng;
	l2tp->conf.peer_port_req = port;
      }
      break;
    case SET_CALLINGNUM:
      if (ac != 1)
	return(-1);
      snprintf(l2tp->conf.callingnum, sizeof(l2tp->conf.callingnum), "%s", av[0]);
      break;
    case SET_CALLEDNUM:
      if (ac != 1)
	return(-1);
      snprintf(l2tp->conf.callednum, sizeof(l2tp->conf.callednum), "%s", av[0]);
      break;
    case SET_ENABLE:
      EnableCommand(ac, av, &l2tp->conf.options, gConfList);
      L2tpNodeUpdate(lnk->phys);
      break;
    case SET_DISABLE:
      DisableCommand(ac, av, &l2tp->conf.options, gConfList);
      L2tpNodeUpdate(lnk->phys);
      break;
    default:
      assert(0);
  }
  return(0);
}

