
/*
 * pppoe.c
 *
 * Written by Archie Cobbs <archie@freebsd.org>
 * Copyright (c) 1995-1999 Whistle Communications, Inc. All rights reserved.
 * See ``COPYRIGHT.whistle''
 */

#include "ppp.h"
#include "pppoe.h"
#include "ngfunc.h"

#include <net/ethernet.h>
#ifdef __DragonFly__
#include <netgraph/pppoe/ng_pppoe.h>
#include <netgraph/ether/ng_ether.h>
#include <netgraph/ng_message.h>
#include <netgraph/tee/ng_tee.h>
#else
#include <netgraph/ng_pppoe.h>
#include <netgraph/ng_ether.h>
#include <netgraph/ng_message.h>
#include <netgraph/ng_tee.h>
#endif
#include <netgraph.h>

#include <sys/param.h>
#include <sys/linker.h>

/*
 * DEFINITIONS
 */

#define PPPOE_MTU		1492	/* allow room for PPPoE overhead */
#define PPPOE_MRU		1492

#define PPPOE_REOPEN_PAUSE	5
#define PPPOE_CONNECT_TIMEOUT	9

#define ETHER_DEFAULT_HOOK	NG_ETHER_HOOK_ORPHAN

#define MAX_PATH		64	/* XXX should be NG_PATHLEN */
#define MAX_SESSION		64	/* max length of PPPoE session name */

/* Per link private info */
struct pppoeinfo {
	int		state;			/* link layer state */
	u_char		incoming:1;		/* Call is incoming vs. outgoing */
	int		csock;			/* netgraph Control socket */
	int		dsock;			/* netgraph Data socket */
	char		path[MAX_PATH + 1];	/* PPPoE node path */
	char		hook[NG_HOOKLEN + 1];	/* hook on that node */
	char		session[MAX_SESSION+1];	/* session name */
	u_char		peeraddr[6];		/* Peer MAC address for incoming connections */
	struct optinfo	options;
	Link		link;			/* our link */
	EventRef	ctrlEvent;		/* listen for ctrl messages */
	struct pppTimer	connectTimer;		/* connection timeout timer */
};
typedef struct pppoeinfo	*PppoeInfo;

/* Set menu options */
enum {
	SET_IFACE,
	SET_SESSION,
	SET_ENABLE,
	SET_DISABLE,
};

enum {
	PPPOE_CONF_ORIGINATE,		/* allow originating connections to peer */
	PPPOE_CONF_INCOMING,		/* allow accepting connections from peer */
};

/* Possible states */
#define PPPOE_DOWN		0
#define PPPOE_CONNECTING	1
#define PPPOE_UP		2

/*
   Invariants:
   ----------

   PPPOE_DOWN
	- ng_pppoe(4) node does not exist
	- pe->csock == -1
	- Connect timeout timer is not running

   PPPOE_CONNECTING
	- ng_pppoe(4) node exists and is connected to ether and ppp nodes
	- pe->csock != -1
	- Listening for control messages rec'd on pe->csock
	- Connect timeout timer is running
	- NGM_PPPOE_CONNECT has been sent to the ng_pppoe(4) node, and
	    no response has been received yet

   PPPOE_UP
	- ng_pppoe(4) node exists and is connected to ether and ppp nodes
	- pe->csock != -1
	- Listening for control messages rec'd on pe->csock
	- Connect timeout timer is not running
	- NGM_PPPOE_CONNECT has been sent to the ng_pppoe(4) node, and
	    a NGM_PPPOE_SUCCESS has been received
*/

/*
 * INTERNAL FUNCTIONS
 */

static int	PppoeInit(PhysInfo p);
static void	PppoeOpen(PhysInfo p);
static void	PppoeClose(PhysInfo p);
static void	PppoeShutdown(PhysInfo p);
static int	PppoePeerAddr(PhysInfo p, void *buf, int buf_len);
static void	PppoeCtrlReadEvent(int type, void *arg);
static void	PppoeConnectTimeout(void *arg);
static void	PppoeStat(PhysInfo p);
static int	PppoeSetCommand(int ac, char *av[], void *arg);
static int	PppoeOriginated(PhysInfo p);
static void	PppoeNodeUpdate(void);
static void	PppoeListenUpdate(void *arg);

/*
 * GLOBAL VARIABLES
 */

const struct phystype gPppoePhysType = {
	"pppoe",
	TRUE, PPPOE_REOPEN_PAUSE,
	PPPOE_MTU, PPPOE_MRU,
	PppoeInit,
	PppoeOpen,
	PppoeClose,
	NULL,
	PppoeShutdown,
	PppoeStat,
	PppoeOriginated,
	PppoePeerAddr,
};

const struct cmdtab PppoeSetCmds[] = {
      { "iface ifacename",	"Set ethernet interface to use",
	  PppoeSetCommand, NULL, (void *)SET_IFACE },
      { "service string",	"Set PPPoE session name",
	  PppoeSetCommand, NULL, (void *)SET_SESSION },
      { "enable [opt ...]",		"Enable option",
	  PppoeSetCommand, NULL, (void *)SET_ENABLE },
      { "disable [opt ...]",		"Disable option",
	  PppoeSetCommand, NULL, (void *)SET_DISABLE },
      { NULL },
};

/* 
 * INTERNAL VARIABLES 
 */

struct PppoeIf {
    char	ifnodepath[MAX_PATH+1];
    char	session[MAX_SESSION+1];
    int 	listen;
    int		csock;                  /* netgraph Control socket */
    int		dsock;                  /* netgraph Data socket */
    EventRef	ctrlEvent;		/* listen for ctrl messages */
};
int PppoeIfCount=0;
struct PppoeIf PppoeIfs[64];

int PppoeListenUpdateSheduled=0;
struct pppTimer PppoeListenUpdateTimer;

static struct confinfo	gConfList[] = {
    { 0,	PPPOE_CONF_ORIGINATE,	"originate"	},
    { 0,	PPPOE_CONF_INCOMING,	"incoming"	},
    { 0,	0,			NULL		},
};

/*
 * PppoeInit()
 *
 * Initialize device-specific data in physical layer info
 */
static int
PppoeInit(PhysInfo p)
{
	PppoeInfo pe;
	int i;

	/* Allocate private struct */
	pe = (PppoeInfo)(p->info = Malloc(MB_PHYS, sizeof(*pe)));
	pe->state = PPPOE_DOWN;
	pe->incoming = 0;
	snprintf(pe->path, sizeof(pe->path), "undefined:");
	snprintf(pe->hook, sizeof(pe->hook), "undefined");
	snprintf(pe->session, sizeof(pe->session), "*");
	for (i=0; i<6; i++)
	    pe->peeraddr[i]=0x00;
	pe->link = lnk;

	/* Done */
	return(0);
}

/*
 * PppoeOpen()
 */
static void
PppoeOpen(PhysInfo p)
{
	const PppoeInfo pe = (PppoeInfo)p->info;
	union {
	    u_char			buf[sizeof(struct ngpppoe_init_data) + MAX_SESSION];
	    struct ngpppoe_init_data	poeid;
	} u;
	struct ngpppoe_init_data *const idata = &u.poeid;
	char path[NG_PATHLEN + 1];
	char session_hook[NG_HOOKLEN + 1];
	char linkHook[NG_HOOKLEN + 1];
	int i;

	if (pe->incoming == 1) {
    	    Log(LG_PHYS, ("[%s] PppoeOpen() on incoming call", lnk->name));
	} else {
	
	    /* Sanity */
	    if (pe->state != PPPOE_DOWN) {
    		Log(LG_ERR, ("[%s] PPPoE allready active", lnk->name));
		return;
	    };

	    if (!Enabled(&pe->options, PPPOE_CONF_ORIGINATE)) {
    		Log(LG_ERR, ("[%s] PPPoE originate option is not enabled", lnk->name));
		PhysDown(STR_DEV_NOT_READY, NULL);
		return;
	    };

	    /* Create PPPOE node if necessary */
	    PppoeNodeUpdate();

	    /* Create a new netgraph node */
	    if (NgMkSockNode(NULL, &pe->csock, &pe->dsock) < 0) {
		Log(LG_ERR, ("[%s] PPPoE can't create ctrl socket: %s",
		    lnk->name, strerror(errno)));
		goto fail;
	    }
	    (void)fcntl(pe->csock, F_SETFD, 1);

	    /* Connect our ng_ppp(4) node link hook to the ng_pppoe(4) node */
	    snprintf(session_hook, sizeof(session_hook), "mpd%d-%s", getpid(), lnk->name);
	    snprintf(path, sizeof(path), "%s%s", pe->path, pe->hook);
	    snprintf(linkHook, sizeof(linkHook),
		"%s%d", NG_PPP_HOOK_LINK_PREFIX, lnk->bundleIndex);

	    if (NgFuncConnect(MPD_HOOK_PPP, linkHook, path, session_hook) < 0)
		goto fail2;

	    /* Tell the PPPoE node to try to connect to a server */
	    memset(idata, 0, sizeof(idata));
	    snprintf(idata->hook, sizeof(idata->hook), "%s", session_hook);
	    idata->data_len = strlen(pe->session);
	    strncpy(idata->data, pe->session, MAX_SESSION);
	    if (NgSendMsg(pe->csock, path, NGM_PPPOE_COOKIE, NGM_PPPOE_CONNECT,
		idata, sizeof(*idata) + idata->data_len) < 0) {
		    Log(LG_ERR, ("[%s] PPPoE can't request connection to server: %s",
			lnk->name, strerror(errno)));
		    goto fail2;
	    }
	    for (i=0; i<6; i++)
		pe->peeraddr[i]=0x00;

	    /* Set a timer to limit connection time */
	    TimerInit(&pe->connectTimer, "PPPoE-connect",
		PPPOE_CONNECT_TIMEOUT * SECONDS, PppoeConnectTimeout, pe);
	    TimerStart(&pe->connectTimer);
	};

	/* Register an event listening to the control socket */
	EventRegister(&pe->ctrlEvent, EVENT_READ, pe->csock,
	    EVENT_RECURRING, PppoeCtrlReadEvent, lnk);

	/* OK */
	pe->state = PPPOE_CONNECTING;
	return;

fail2:
	NgFuncDisconnect(path,session_hook);
fail:	
	PhysDown(STR_CON_FAILED0, NULL);
	return;
}

/*
 * PppoeConnectTimeout()
 */
static void
PppoeConnectTimeout(void *arg)
{
	const PppoeInfo pe = arg;

	/* Cancel connection */
	assert(pe->state == PPPOE_CONNECTING);
	Log(LG_ERR, ("[%s] PPPoE connection timeout after %d seconds",
	    lnk->name, PPPOE_CONNECT_TIMEOUT));
	PhysDown(STR_CON_FAILED0, NULL);
	PppoeShutdown(lnk->phys);
}

/*
 * PppoeClose()
 */
static void
PppoeClose(PhysInfo p)
{
	const PppoeInfo pe = (PppoeInfo)p->info;

	if (pe->state == PPPOE_DOWN)
		return;
	PhysDown(0, NULL);
	PppoeShutdown(p);
}

/*
 * PppoeShutdown()
 *
 * Shut everything down and go to the PPPOE_DOWN state
 */
static void
PppoeShutdown(PhysInfo p)
{
	const PppoeInfo pe = (PppoeInfo)p->info;
	char path[NG_PATHLEN + 1];
	char session_hook[NG_HOOKLEN + 1];

	if (pe->state == PPPOE_DOWN)
		return;

	snprintf(path, sizeof(path), "%s%s", pe->path, pe->hook);
	snprintf(session_hook, sizeof(session_hook), "mpd%d-%s", getpid(), lnk->name);
	NgFuncDisconnect(path,session_hook);

	EventUnRegister(&pe->ctrlEvent);
	(void)close(pe->csock);
	(void)close(pe->dsock);
	pe->csock = -1;
	pe->dsock = -1;
	TimerStop(&pe->connectTimer);
	pe->state = PPPOE_DOWN;
	pe->incoming = 0;
}

/*
 * PppoeCtrlReadEvent()
 *
 * Receive an incoming control message from the PPPoE node
 */
static void
PppoeCtrlReadEvent(int type, void *arg)
{
	union {
	    u_char buf[sizeof(struct ng_mesg) + sizeof(struct ngpppoe_sts)];
	    struct ng_mesg resp;
	} u;
	char path[NG_PATHLEN + 1];
	PppoeInfo pe;
	
	/* Restore context */
	lnk = arg;
	bund = lnk->bund;
	pe = (PppoeInfo)lnk->phys->info;
	assert(pe->state != PPPOE_DOWN);

	/* Read control message */
	if (NgRecvMsg(pe->csock, &u.resp, sizeof(u), path) < 0) {
		Log(LG_ERR, ("[%s] error reading message from \"%s\": %s",
		    lnk->name, path, strerror(errno)));
		PhysDown(STR_ERROR, NULL);
		PppoeShutdown(lnk->phys);
		return;
	}
	if (u.resp.header.typecookie != NGM_PPPOE_COOKIE) {
		Log(LG_ERR, ("[%s] rec'd cookie %lu from \"%s\"",
		    lnk->name, (u_long)u.resp.header.typecookie, path));
		return;
	}

	/* Decode message */
	switch (u.resp.header.cmd) {
	case NGM_PPPOE_SESSIONID: // I do not know what to do with this?
		break;
	case NGM_PPPOE_SUCCESS:
		Log(LG_PHYS, ("[%s] PPPoE connection successful", lnk->name));
		Disable(&lnk->conf.options, LINK_CONF_ACFCOMP);	/* RFC 2516 */
		Deny(&lnk->conf.options, LINK_CONF_ACFCOMP);	/* RFC 2516 */
		TimerStop(&pe->connectTimer);
		pe->state = PPPOE_UP;
		PhysUp();
		break;
	case NGM_PPPOE_FAIL:
		Log(LG_PHYS, ("[%s] PPPoE connection failed", lnk->name));
		PhysDown(STR_CON_FAILED0, NULL);
		PppoeShutdown(lnk->phys);
		break;
	case NGM_PPPOE_CLOSE:
		Log(LG_PHYS, ("[%s] PPPoE connection closed", lnk->name));
		PhysDown(STR_DROPPED, NULL);
		PppoeShutdown(lnk->phys);
		break;
	case NGM_PPPOE_ACNAME:
		Log(LG_PHYS, ("[%s] rec'd ACNAME \"%s\"", lnk->name, 
		  ((struct ngpppoe_sts *)u.resp.data)->hook));
		break;
	default:
		Log(LG_ERR, ("[%s] rec'd command %lu from \"%s\"",
		    lnk->name, (u_long)u.resp.header.cmd, path));
		break;
	}
}

/*
 * PppoeStat()
 */
void
PppoeStat(PhysInfo p)
{
	const PppoeInfo pe = (PppoeInfo)p->info;
	const char *ststr;

	Printf("PPPoE configuration:\r\n");
	Printf("\tNode    : %s\r\n", pe->path);
	Printf("\tHook    : %s\r\n", pe->hook);
	Printf("\tSession : %s\r\n", pe->session);
	Printf("PPPoE status:\r\n");
	switch (pe->state) {
	case PPPOE_DOWN:
		ststr = "DOWN";
		break;
	case PPPOE_CONNECTING:
		ststr = "CONNECTING";
		break;
	case PPPOE_UP:
		ststr = "UP";
		break;
	default:
		ststr = "???";
		break;
	}
	Printf("\tState   : %s\r\n", ststr);
}

/*
 * PppoeOriginated()
 */
static int
PppoeOriginated(PhysInfo p)
{
  PppoeInfo      const pppoe = (PppoeInfo)p->info;

  return(pppoe->incoming ? LINK_ORIGINATE_REMOTE : LINK_ORIGINATE_LOCAL);
}

static int
PppoePeerAddr(PhysInfo p, void *buf, int buf_len)
{
  PppoeInfo	const pppoe = (PppoeInfo) p;

  snprintf(buf, buf_len, "%02x%02x%02x%02x%02x%02x",
    pppoe->peeraddr[0], pppoe->peeraddr[1], pppoe->peeraddr[2], 
    pppoe->peeraddr[3], pppoe->peeraddr[4], pppoe->peeraddr[5]);
  return(0);
}

static int 
CreatePppoeNode(const char *path, const char *hook)
{
	u_char rbuf[2048];
	struct ng_mesg *resp;
	const struct typelist *tlist;
	const struct hooklist *hlist;
	const struct nodeinfo *ninfo;
	const struct linkinfo *nlink;
	int f;
	int csock;
	int kldload_tried = 0;
	static int check_ng_ether = 1;

	/* Make sure interface is up */
	char iface[IFNAMSIZ + 1];

	snprintf(iface, sizeof(iface), "%s", path);
	if (iface[strlen(iface) - 1] == ':')
		iface[strlen(iface) - 1] = '\0';
	if (ExecCmd(LG_PHYS, "%s %s up", PATH_IFCONFIG, iface) != 0) {
		Log(LG_ERR, ("[%s] can't bring up interface %s",
		    lnk->name, iface));
		return(0);
	}

	/* Create a new netgraph node */
	if (NgMkSockNode(NULL, &csock, NULL) < 0) {
		Log(LG_ERR, ("[%s] can't create ctrl socket: %s",
		    lnk->name, strerror(errno)));
		return(0);
	}
	(void)fcntl(csock, F_SETFD, 1);

	/* Check if NG_ETHER_NODE_TYPE is available */
	for (kldload_tried=0; check_ng_ether;) {
		/* Ask for a list of available node types */
		if (NgSendMsg(csock, "", NGM_GENERIC_COOKIE, NGM_LISTTYPES,				NULL, 0) < 0) {
			Log(LG_ERR, ("[%s] Cannot send a netgraph message: %s",
				lnk->name, strerror(errno)));
			close(csock);
			return(0);
		}

		/* Get response */
		resp = (struct ng_mesg *)rbuf;
		if (NgRecvMsg(csock, resp, sizeof rbuf, NULL) <= 0) {
			Log(LG_ERR, ("[%s] Cannot get netgraph response: %s",
				lnk->name, strerror(errno)));
			close(csock);
			return(0);
		}

		/* Look for NG_ETHER_NODE_TYPE */
		tlist = (const struct typelist*) resp->data;
		for (f=0; f<tlist->numtypes; ++f)
			if (!strncmp(tlist->typeinfo[f].type_name,
			    NG_ETHER_NODE_TYPE, sizeof NG_ETHER_NODE_TYPE - 1))
				break;

		/* If found do not run this check anymore */
		if (f < tlist->numtypes) {
			check_ng_ether=0;
			break;
		}

		/* If not found try to load ng_ether and repeat the check */
		if (kldload_tried) {
			Log(LG_ERR, ("[%s] Still no NG_ETHER_NODE_TYPE after kldload(\"ng_ether\")", lnk->name));
			close(csock);
			return(0);
		}

		if (kldload("ng_ether") < 0) {
			if (errno == EEXIST)
				Log(LG_ERR, ("[%s] ng_ether already loaded but NG_ETHER_NODE_TYPE is not available", lnk->name));
			else
				Log(LG_ERR, ("[%s] Cannot load ng_ether: %s", lnk->name, strerror(errno)));
			close(csock);
			return(0);
		}
		kldload_tried = 1;
	}

	/*
	* Ask for a list of hooks attached to the "ether" node.  This node should
	* magically exist as a way of hooking stuff onto an ethernet device
	*/
	if (NgSendMsg(csock, path, NGM_GENERIC_COOKIE, NGM_LISTHOOKS,
		NULL, 0) < 0) {
		Log(LG_ERR, ("[%s] Cannot send a netgraph message: %s:%s",
                  lnk->name, path, strerror(errno)));
		close(csock);
		return(0);
	}

	/* Get our list back */
	resp = (struct ng_mesg *)rbuf;
	if (NgRecvMsg(csock, resp, sizeof rbuf, NULL) <= 0) {
		Log(LG_ERR, ("[%s] Cannot get netgraph response: %s",
			lnk->name, strerror(errno)));
		close(csock);
		return(0);
	}

	hlist = (const struct hooklist *)resp->data;
	ninfo = &hlist->nodeinfo;

	/* Make sure we've got the right type of node */
	if (strncmp(ninfo->type, NG_ETHER_NODE_TYPE,
		sizeof NG_ETHER_NODE_TYPE - 1)) {
		Log(LG_ERR, ("[%s] Unexpected node type ``%s'' (wanted ``" NG_ETHER_NODE_TYPE "'') on %s", lnk->name, ninfo->type, path));
		close(csock);
		return(0);
	}

	/* look for a hook already attached.  */
	for (f = 0; f < ninfo->hooks; f++) {
	  nlink = &hlist->link[f];

	  if (!strcmp(nlink->ourhook, NG_ETHER_HOOK_ORPHAN) ||
		!strcmp(nlink->ourhook, NG_ETHER_HOOK_DIVERT)) {
	  /*
	   * Something is using the data coming out of this ``ether'' node.
	   * If it's a PPPoE node, we use that node, otherwise we complain that
	   * someone else is using the node.
	   */
	    if (strcmp(nlink->nodeinfo.type, NG_PPPOE_NODE_TYPE)) {
		Log(LG_ERR, ("%s Node type ``%s'' is currently using orphan hook\n",
                  path, nlink->nodeinfo.type));
		close(csock);
		return(0);
	    }
	    break;
	  }
	}

	if (f == ninfo->hooks) { /* Create new PPPoE node */

	struct ngm_mkpeer mp;

	/* Create new PPPoE node */
	snprintf(mp.type, sizeof(mp.type), "%s", NG_PPPOE_NODE_TYPE);
	snprintf(mp.ourhook, sizeof(mp.ourhook), "%s", hook);
	snprintf(mp.peerhook, sizeof(mp.peerhook),
	    "%s", NG_PPPOE_HOOK_ETHERNET);
	if (NgSendMsg(csock, path,
	    NGM_GENERIC_COOKIE, NGM_MKPEER, &mp, sizeof(mp)) < 0 && errno != EEXIST)
	{
		Log(LG_ERR, ("[%s] can't create %s peer to %s,%s: %s",
		    lnk->name, NG_PPPOE_NODE_TYPE,
		    path, hook, strerror(errno)));
		close(csock);
		return(0);
	}

	};
	
	close(csock);
	return(1);
};

static void
PppoeListenEvent(int type, void *arg)
{
	int i,k,sz;
	struct PppoeIf *PIf=(struct PppoeIf *)(arg);
	char rhook[NG_HOOKLEN + 1];
	unsigned char response[1024];

	char path[NG_PATHLEN + 1];
	char path1[NG_PATHLEN + 1];
	char session_hook[NG_HOOKLEN + 1];
	char linkHook[NG_HOOKLEN + 1];
	struct ngm_connect      cn;
	struct ngm_mkpeer 	mp;
	u_char *macaddr;
	time_t	const now = time(NULL);

	union {
	    u_char			buf[sizeof(struct ngpppoe_init_data) + MAX_SESSION];
	    struct ngpppoe_init_data	poeid;
	} u;
	struct ngpppoe_init_data *const idata = &u.poeid;

	switch (sz = NgRecvData(PIf->dsock, response, sizeof response, rhook)) { 
          case -1: 
	    Log(LG_ERR, ("NgRecvData: %d", sz));
            return;
          case 0: 
            Log(LG_ERR, ("NgRecvData: socket closed")); 
            return; 
        }

	if (sz >= sizeof(struct ether_header)) {
    	    macaddr = ((struct ether_header *)response)->ether_shost;
	    Log(LG_PHYS, ("Incoming PPPoE connection request via %s for service \"%s\" from %s", PIf->ifnodepath, PIf->session, ether_ntoa((const struct ether_addr *)macaddr)));
	} else {
	    Log(LG_PHYS, ("Incoming PPPoE connection request via %s for service \"%s\"", PIf->ifnodepath, PIf->session));
	    macaddr = (u_char *)NULL;
	}

	/* Examine all PPPoE links */
	for (k = 0; k < gNumLinks; k++) {
	    if (gLinks[k] && gLinks[k]->phys->type == &gPppoePhysType) {
		PhysInfo	const ph = gLinks[k]->phys;
	        PppoeInfo	const p = (PppoeInfo)ph->info;
		if ((strcmp(PIf->ifnodepath,p->path) == 0)
		     && (strcmp(PIf->session,p->session) == 0)
		     && (ph->state == PHYS_DOWN)
		     && (p->state == PPPOE_DOWN)
		     && (now-ph->lastClose >= PPPOE_REOPEN_PAUSE)) {
		     
		    /* Restore context */
		    lnk = gLinks[k];
		    bund = lnk->bund;

		    Log(LG_PHYS, ("[%s] Accepting PPPoE connection", lnk->name));

		    /* Create a new netgraph socket */
		    if (NgMkSockNode(NULL, &p->csock, &p->dsock) < 0) {
	    		Log(LG_ERR, ("[%s] can't create ctrl socket: %s",
			    lnk->name, strerror(errno)));
		    } else {
    			/* Create ng_tee(4) node and connect it to ng_pppoe(4) */
			snprintf(session_hook, sizeof(session_hook), "mpd%d-%s", getpid(), lnk->name);
			snprintf(path, sizeof(path), "%s%s", p->path, p->hook);

	    		snprintf(mp.type, sizeof(mp.type), "%s", NG_TEE_NODE_TYPE);
			snprintf(mp.ourhook, sizeof(mp.ourhook), session_hook);
			snprintf(mp.peerhook, sizeof(mp.peerhook), "left");
			if (NgSendMsg(p->csock, path, NGM_GENERIC_COOKIE, NGM_MKPEER, &mp, sizeof(mp)) < 0) {
	    		    Log(LG_ERR, ("[%s] can't create %s peer to %s,%s: %s",
				lnk->name, NG_TEE_NODE_TYPE,
				path, "left", strerror(errno)));
			} else {
			    snprintf(path1, sizeof(path), "%s%s.%s", p->path, p->hook,session_hook);
			    snprintf(linkHook, sizeof(linkHook),
		    		"%s%d", NG_PPP_HOOK_LINK_PREFIX, lnk->bundleIndex);
			
			    /* Connect our ng_ppp(4) node link hook to the ng_tee(4) node */
			    if (NgFuncConnect(MPD_HOOK_PPP, linkHook, path1, "right") < 0) {
	    			Log(LG_ERR, ("[%s] can't connect to ppp: %s",
				    lnk->name, strerror(errno)));
			    } else {
				/* Connect our socket node "data" hook to the ng_tee(4) node */
				snprintf(cn.path, sizeof(cn.path), "%s", path1);
				snprintf(cn.ourhook, sizeof(cn.ourhook), "data");
				snprintf(cn.peerhook, sizeof(cn.peerhook), "left2right");
  
				if (NgSendMsg(p->csock, ".:", NGM_GENERIC_COOKIE, NGM_CONNECT, &cn, sizeof(cn)) < 0) {
				    Log(LG_ERR, ("[%s] can't connect %s,%s and %s,%s: %s",
	    				bund->name, ".:", cn.ourhook, cn.path, cn.peerhook, strerror(errno)));
				} else {
	    			    /* Put the PPPoE node into OFFER mode */
				    memset(idata, 0, sizeof(idata));
				    snprintf(idata->hook, sizeof(idata->hook), "%s", session_hook);
				    if (gethostname(idata->data, MAX_SESSION) == -1) {
				        Log(LG_RADIUS, ("[%s] PPPOE: gethostname() failed", lnk->name));
				        idata->data[0]=0;
				    }
				    idata->data_len=strlen(idata->data);

				    if (NgSendMsg(p->csock, path, NGM_PPPOE_COOKIE, NGM_PPPOE_OFFER,
					    idata, sizeof(*idata) + idata->data_len) < 0) {
					Log(LG_ERR, ("[%s] can't send NGM_PPPOE_OFFER to %s,%s : %s",
					    lnk->name, path, idata->hook, strerror(errno)));
				    } else {
					memset(idata, 0, sizeof(idata));
					snprintf(idata->hook, sizeof(idata->hook), "%s", session_hook);
					idata->data_len = strlen(p->session);
					strncpy(idata->data, p->session, MAX_SESSION);

					if (NgSendMsg(p->csock, path, NGM_PPPOE_COOKIE, NGM_PPPOE_SERVICE,
						idata, sizeof(*idata) + idata->data_len) < 0) {
					    Log(LG_ERR, ("[%s] can't send NGM_PPPOE_SERVICE to %s,%s : %s",
						lnk->name, path, idata->hook, strerror(errno)));
					} else {
					    /* And send our request data to the waiting node */
    					    if (NgSendData(p->dsock, "data", response, sz) == -1) {
    						Log(LG_ERR, ("[%s] Cannot send original request: %s", lnk->name, strerror(errno)));
    					    } else {
						if (NgFuncShutdownNode(bund, lnk->name, path1)<0) {
    						    Log(LG_ERR, ("[%s] Shutdown ng_tee node %s error: %s", lnk->name, path1, strerror(errno)));
						} else {
						    p->state=PPPOE_CONNECTING;
						    p->incoming = 1;
					            /* Record the peer's MAC address */
    						    if (macaddr) {
							for (i=0;i<6;i++)
							    p->peeraddr[i]=macaddr[i];
    						    };
						    Log(LG_PHYS, ("[%s] PPPoE response sent", lnk->name));

						    /* Set a timer to limit connection time */
						    TimerInit(&p->connectTimer, "PPPoE-connect",
							PPPOE_CONNECT_TIMEOUT * SECONDS, PppoeConnectTimeout, p);
						    TimerStart(&p->connectTimer);
						    
						    RecordLinkUpDownReason(NULL, 1, STR_INCOMING_CALL, "", NULL);
						    IfaceOpenNcps();
						    break;
						};
					    };
					};
				    };
				};
				if (NgFuncDisconnect(MPD_HOOK_PPP,linkHook)<0) {
    				    Log(LG_ERR, ("[%s] Disconnect ng_ppp node error: %s", lnk->name, strerror(errno)));
				};
			    };
			    if (NgFuncShutdownNode(bund, lnk->name, path1)<0) {
    				Log(LG_ERR, ("[%s] Shutdown ng_tee node %s error: %s", lnk->name, path1, strerror(errno)));
			    };
			};
			close(p->csock);
			close(p->dsock);
			p->csock=-1;
			p->dsock=-1;
			Log(LG_PHYS, ("[%s] PPPoE connection not accepted due error", lnk->name));
		    };
		};
	    };
	};
	if (k == gNumLinks) {
	    Log(LG_PHYS, ("No free PPPoE link with requested parameters was found"));
	}
};

static int 
ListenPppoeNode(const char *path, const char *hook, struct PppoeIf *PIf, const char *session) {

	union {
	    u_char			buf[sizeof(struct ngpppoe_init_data) + MAX_SESSION];
	    struct ngpppoe_init_data	poeid;
	} u;
	struct ngpppoe_init_data *const idata = &u.poeid;
	char pat[NG_PATHLEN + 1];
	struct ngm_connect	cn;
	
	/* Create a new netgraph node */
	if (NgMkSockNode(NULL, &(PIf->csock), &(PIf->dsock)) < 0) {
		Log(LG_ERR, ("[%s] can't create ctrl socket: %s",
		    lnk->name, strerror(errno)));
		return(0);
	}
	(void)fcntl(PIf->csock, F_SETFD, 1);

	/* Connect our socket node link hook to the ng_pppoe(4) node */
	snprintf(cn.path, sizeof(cn.path), "%s%s", path, hook);
	snprintf(cn.ourhook, sizeof(cn.ourhook), "listen-hook");
	snprintf(cn.peerhook, sizeof(cn.peerhook), "listen-%s", session);
  
	if (NgSendMsg(PIf->csock, ".:", NGM_GENERIC_COOKIE, NGM_CONNECT, &cn, sizeof(cn)) < 0) {
	    Log(LG_ERR, ("[%s] can't connect %s,%s and %s,%s: %s",
	      bund->name, ".:", cn.ourhook, cn.path, cn.peerhook, strerror(errno)));
	    return(0);
	}

	/* Tell the PPPoE node to be a server */
	snprintf(pat, sizeof(pat), "%s%s", path, hook);

	memset(idata, 0, sizeof(idata));
	snprintf(idata->hook, sizeof(idata->hook), "listen-%s", session);
	idata->data_len = strlen(session);
	strncpy(idata->data, session, MAX_SESSION);

	Log(LG_ERR, ("[%s] PPPoE server listening on %s for service \"%s\"",
		lnk->name, path, idata->data));
	if (NgSendMsg(PIf->csock, pat, NGM_PPPOE_COOKIE, NGM_PPPOE_LISTEN,
	    idata, sizeof(*idata) + idata->data_len) < 0) {
		Log(LG_ERR, ("[%s] can't send NGM_PPPOE_LISTEN to %s hook %s : %s",
		    lnk->name, pat, idata->hook, strerror(errno)));
		return(0);
	}

	/* Register an event listening to the control socket */
	EventRegister(&(PIf->ctrlEvent), EVENT_RECURRING|EVENT_READ, PIf->dsock,
	    0, PppoeListenEvent, PIf);
	    
	return(1);
};

/*
 * PppoeNodeUpdate()
 */

static void
PppoeNodeUpdate(void)
{
  int	i,j,k;

  /* Examine all PPPoE links */
  for (k = 0; k < gNumLinks; k++) {
    if (gLinks[k] && gLinks[k]->phys->type == &gPppoePhysType) {
        PppoeInfo	const p = (PppoeInfo)gLinks[k]->phys->info;

	if (!strcmp(p->path, "undefined:")) {
		Log(LG_PHYS, ("[%s] Skipping link %s with undefined interface",
			lnk->name, gLinks[k]->name));
		continue;
	}

	j=-1;
	for (i=0;i<PppoeIfCount;i++) {
	    if (strcmp(PppoeIfs[i].ifnodepath,p->path)==0)
		j=i;
	};
	if (j==-1) {
	    if (CreatePppoeNode(p->path,p->hook)) {
		snprintf(PppoeIfs[PppoeIfCount].ifnodepath,sizeof(PppoeIfs[PppoeIfCount].ifnodepath),"%s",p->path);
		snprintf(PppoeIfs[PppoeIfCount].session,sizeof(PppoeIfs[PppoeIfCount].session),"%s",p->session);
		PppoeIfs[PppoeIfCount++].listen=0;
	    } else {
		Log(LG_ERR, ("[%s] Error in creation ng_pppoe node on %s", lnk->name, p->path));
		return;
	    };
	};
    	if (Enabled(&p->options, PPPOE_CONF_INCOMING)&&(!PppoeListenUpdateSheduled)) {
	    /* Set a timer to run PppoeListenUpdate */
	    TimerInit(&PppoeListenUpdateTimer, "PppoeListenUpdate",
		0, PppoeListenUpdate, NULL);
	    TimerStart(&PppoeListenUpdateTimer);
	    PppoeListenUpdateSheduled=1;
	};
    }
  }
}

/*
 * PppoeListenUpdate()
 */

static void
PppoeListenUpdate(void *arg)
{
  int	i,j,k;

  PppoeListenUpdateSheduled=0;

  /* Examine all PPPoE links */
  for (k = 0; k < gNumLinks; k++) {
    if (gLinks[k] && gLinks[k]->phys->type == &gPppoePhysType ) {
        PppoeInfo	const p = (PppoeInfo)gLinks[k]->phys->info;

	if (!strcmp(p->path, "undefined:")) {
		Log(LG_PHYS, ("[%s] Skipping link %s with undefined interface",
			lnk->name, gLinks[k]->name));
		continue;
	}

    	if (Enabled(&p->options, PPPOE_CONF_INCOMING)) {
	    j=-1;
	    for (i=0;i<PppoeIfCount;i++) {
		if ((strcmp(PppoeIfs[i].ifnodepath,p->path)==0)&&(strcmp(PppoeIfs[i].session,p->session)==0))
		    j=i;
	    };
	    if (j==-1) {
		if (ListenPppoeNode(p->path,p->hook,&(PppoeIfs[PppoeIfCount]),p->session)) {
		    snprintf(PppoeIfs[PppoeIfCount].ifnodepath,sizeof(PppoeIfs[PppoeIfCount].ifnodepath),"%s",p->path);
		    snprintf(PppoeIfs[PppoeIfCount].session,sizeof(PppoeIfs[PppoeIfCount].session),"%s",p->session);
		    PppoeIfs[PppoeIfCount].listen=1;
		    PppoeIfCount++;
		};
	    } else {
		if ((PppoeIfs[j].listen==0)&&(ListenPppoeNode(p->path,p->hook,&(PppoeIfs[j]),p->session))) {
		    PppoeIfs[j].listen=1;
		};
	    };
	};
    }
  }
}

/*
 * PppoeSetCommand()
 */
 
static int
PppoeSetCommand(int ac, char *av[], void *arg)
{
	const PppoeInfo pe = (PppoeInfo) lnk->phys->info;
	const char *hookname = ETHER_DEFAULT_HOOK;
	const char *colon;

	if (lnk->phys->type != &gPppoePhysType) {
		Log(LG_ERR, ("[%s] link type is not pppoe", lnk->name));
		return(0);
	}
	switch ((intptr_t)arg) {
	case SET_IFACE:
		switch (ac) {
		case 2:
			hookname = av[1];
			/* fall through */
		case 1:
			colon = (av[0][strlen(av[0]) - 1] == ':') ? "" : ":";
			snprintf(pe->path, sizeof(pe->path),
			    "%s%s", av[0], colon);
			snprintf(pe->hook, sizeof(pe->hook),
			    "%s", hookname);
			break;
		default:
			return(-1);
		}
		break;
	case SET_SESSION:
		if (ac != 1)
			return(-1);
		snprintf(pe->session, sizeof(pe->session), "%s", av[0]);
		break;
	case SET_ENABLE:
          EnableCommand(ac, av, &pe->options, gConfList);
    	  PppoeNodeUpdate();
          break;
        case SET_DISABLE:
          DisableCommand(ac, av, &pe->options, gConfList);
          PppoeNodeUpdate();
          break;
	default:
		assert(0);
	}
	return(0);
}

