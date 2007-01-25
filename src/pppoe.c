
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
#include "log.h"
#include "msgdef.h"
#include "util.h"

#include <net/ethernet.h>
#include <netgraph/ng_message.h>
#ifdef __DragonFly__
#include <netgraph/pppoe/ng_pppoe.h>
#include <netgraph/ether/ng_ether.h>
#include <netgraph/tee/ng_tee.h>
#else
#include <netgraph/ng_pppoe.h>
#include <netgraph/ng_ether.h>
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

#define PPPOE_MAXPARENTIFS	1024

#define MAX_PATH		64	/* XXX should be NG_PATHLEN */
#define MAX_SESSION		64	/* max length of PPPoE session name */

/* Per link private info */
struct pppoeinfo {
	u_char		incoming:1;		/* incoming vs. outgoing */
	u_char		opened:1;		/* PPPoE opened by phys */
	char		path[MAX_PATH + 1];	/* PPPoE node path */
	char		hook[NG_HOOKLEN + 1];	/* hook on that node */
	char		session[MAX_SESSION+1];	/* session name */
	u_char		peeraddr[6];		/* Peer MAC address */
	struct optinfo	options;
	Link		link;			/* our link */
	struct pppTimer	connectTimer;		/* connection timeout timer */
	struct PppoeIf  *PIf;			/* pointer on parent ng_pppoe info */
};
typedef struct pppoeinfo	*PppoeInfo;

static u_char gNgEtherLoaded = FALSE;

/* Set menu options */
enum {
	SET_IFACE,
	SET_SESSION,
	SET_ENABLE,
	SET_DISABLE,
};

enum {
	PPPOE_CONF_ORIGINATE,	/* allow originating connections to peer */
	PPPOE_CONF_INCOMING,	/* allow accepting connections from peer */
};

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
static void	PppoeNodeUpdate(PhysInfo p);
static void	PppoeListenUpdate(void *arg);

/*
 * GLOBAL VARIABLES
 */

const struct phystype gPppoePhysType = {
    .name		= "pppoe",
    .synchronous	= TRUE,
    .minReopenDelay 	= PPPOE_REOPEN_PAUSE,
    .mtu		= PPPOE_MTU,
    .mru		= PPPOE_MRU,
    .init		= PppoeInit,
    .open		= PppoeOpen,
    .close		= PppoeClose,
    .shutdown		= PppoeShutdown,
    .showstat		= PppoeStat,
    .originate		= PppoeOriginated,
    .peeraddr		= PppoePeerAddr,
    .callingnum		= NULL,
    .callednum		= NULL,
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
    EventRef	dataEvent;		/* listen for data messages */
};
int PppoeIfCount=0;
struct PppoeIf PppoeIfs[PPPOE_MAXPARENTIFS];

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

	/* Allocate private struct */
	pe = (PppoeInfo)(p->info = Malloc(MB_PHYS, sizeof(*pe)));
	pe->incoming = 0;
	pe->opened = 0;
	snprintf(pe->path, sizeof(pe->path), "undefined:");
	snprintf(pe->hook, sizeof(pe->hook), "undefined");
	snprintf(pe->session, sizeof(pe->session), "*");
	memset(pe->peeraddr, 0x00, ETHER_ADDR_LEN);
	pe->link = lnk;
	pe->PIf = NULL;

	/* Done */
	return(0);
}

/*
 * PppoeOpen()
 */
static void
PppoeOpen(PhysInfo p)
{
	PppoeInfo pe = (PppoeInfo)p->info;
	union {
	    u_char buf[sizeof(struct ngpppoe_init_data) + MAX_SESSION];
	    struct ngpppoe_init_data	poeid;
	} u;
	struct ngpppoe_init_data *const idata = &u.poeid;
	char path[NG_PATHLEN + 1];
	char session_hook[NG_HOOKLEN + 1];
	char linkHook[NG_HOOKLEN + 1];

	pe->opened=1;
	
	if (pe->incoming == 1) {
		Log(LG_PHYS2, ("[%s] PppoeOpen() on incoming call", lnk->name));
		if (p->state==PHYS_STATE_READY) {
		    Disable(&lnk->conf.options, LINK_CONF_ACFCOMP);	/* RFC 2516 */
		    Deny(&lnk->conf.options, LINK_CONF_ACFCOMP);	/* RFC 2516 */
		    TimerStop(&pe->connectTimer);
		    p->state = PHYS_STATE_UP;
		    PhysUp();
		}
		return;
	}

	/* Sanity check. */
	if (p->state != PHYS_STATE_DOWN) {
		Log(LG_PHYS, ("[%s] PPPoE allready active", lnk->name));
		return;
	};

	if (!Enabled(&pe->options, PPPOE_CONF_ORIGINATE)) {
		Log(LG_ERR, ("[%s] PPPoE originate option is not enabled",
		    lnk->name));
		PhysDown(STR_DEV_NOT_READY, NULL);
		return;
	};

	/* Create PPPoE node if necessary. */
	PppoeNodeUpdate(p);

	if (!pe->PIf) {
	    Log(LG_ERR, ("[%s] PPPoE node for link is not initialized",
	        lnk->name));
	    goto fail;
	}

	/* Connect our ng_ppp(4) node link hook to the ng_pppoe(4) node. */
	snprintf(session_hook, sizeof(session_hook), "mpd%d-%s", gPid,
	    lnk->name);
	snprintf(path, sizeof(path), "%s%s", pe->path, pe->hook);
	snprintf(linkHook, sizeof(linkHook), "%s%d", NG_PPP_HOOK_LINK_PREFIX,
	    lnk->bundleIndex);

	if (NgFuncConnect(MPD_HOOK_PPP, linkHook, path, session_hook) < 0)
		goto fail2;

	Log(LG_PHYS, ("[%s] PPPoE: Connecting to '%s'", lnk->name, pe->session));
	
	/* Tell the PPPoE node to try to connect to a server. */
	memset(idata, 0, sizeof(idata));
	snprintf(idata->hook, sizeof(idata->hook), "%s", session_hook);
	idata->data_len = strlen(pe->session);
	strncpy(idata->data, pe->session, MAX_SESSION);
	if (NgSendMsg(pe->PIf->csock, path, NGM_PPPOE_COOKIE, NGM_PPPOE_CONNECT,
	    idata, sizeof(*idata) + idata->data_len) < 0) {
		Log(LG_ERR, ("[%s] PPPoE can't request connection to server: "
		    "%s", lnk->name, strerror(errno)));
		goto fail2;
	}

	/* Set a timer to limit connection time. */
	TimerInit(&pe->connectTimer, "PPPoE-connect",
	    PPPOE_CONNECT_TIMEOUT * SECONDS, PppoeConnectTimeout, pe);
	TimerStart(&pe->connectTimer);

	/* OK */
	p->state = PHYS_STATE_CONNECTING;
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
	/* Cancel connection. */
	Log(LG_PHYS, ("[%s] PPPoE connection timeout after %d seconds",
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

	pe->opened = 0;
	if (p->state == PHYS_STATE_DOWN)
		return;
	PhysDown(0, NULL);
	PppoeShutdown(p);
}

/*
 * PppoeShutdown()
 *
 * Shut everything down and go to the PHYS_STATE_DOWN state.
 */
static void
PppoeShutdown(PhysInfo p)
{
	const PppoeInfo pe = (PppoeInfo)p->info;
	char path[NG_PATHLEN + 1];
	char session_hook[NG_HOOKLEN + 1];

	if (p->state == PHYS_STATE_DOWN)
		return;

	snprintf(path, sizeof(path), "%s%s", pe->path, pe->hook);
	snprintf(session_hook, sizeof(session_hook), "mpd%d-%s",
	    gPid, lnk->name);
	NgFuncDisconnect(path,session_hook);

	TimerStop(&pe->connectTimer);
	p->state = PHYS_STATE_DOWN;
	pe->incoming = 0;
	memset(pe->peeraddr, 0x00, ETHER_ADDR_LEN);
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
	PhysInfo p = NULL;
	PppoeInfo pe = NULL;
	int k;
	char ppphook[NG_HOOKLEN + 1];
	
	struct PppoeIf  *PIf=(struct PppoeIf*)arg;
	
	/* Read control message. */
	if (NgRecvMsg(PIf->csock, &u.resp, sizeof(u), path) < 0) {
		Log(LG_ERR, ("PPPoE: error reading message from \"%s\": %s",
		    path, strerror(errno)));
		PhysDown(STR_ERROR, NULL);
		PppoeShutdown(lnk->phys);
		return;
	}
	if (u.resp.header.typecookie != NGM_PPPOE_COOKIE) {
		Log(LG_ERR, ("PPPoE: rec'd cookie %lu from \"%s\"",
		    (u_long)u.resp.header.typecookie, path));
		return;
	}

	switch (u.resp.header.cmd) {
	    case NGM_PPPOE_SUCCESS:
	    case NGM_PPPOE_FAIL:
	    case NGM_PPPOE_CLOSE:
		/* Restore context. */
		for (k = 0; k < gNumLinks; k++) {
	    	    PppoeInfo p;
		    PhysInfo ph;

		    if (gLinks[k] && gLinks[k]->phys->type != &gPppoePhysType)
			continue;

		    ph = gLinks[k]->phys;
		    p = (PppoeInfo)ph->info;
		    
		    snprintf(ppphook, NG_HOOKLEN, "mpd%d-%s", gPid, p->link->name);
		
		    if ((PIf==p->PIf) &&
			(strcmp(ppphook, ((struct ngpppoe_sts *)u.resp.data)->hook) == 0))
			    break;
		}
		if (k == gNumLinks) {
		    Log(LG_ERR, ("PPPoE: message from unknown hook \"%s\"",
			((struct ngpppoe_sts *)u.resp.data)->hook));
		    return;
		}

		/* Restore context. */
		lnk = gLinks[k];
		bund = lnk->bund;
		
		p = lnk->phys;
		pe = (PppoeInfo)p->info;
		if (p->state == PHYS_STATE_DOWN) {
		    if (u.resp.header.cmd != NGM_PPPOE_CLOSE) 
			Log(LG_PHYS, ("[%s] PPPoE: message %d in DOWN state",
			    lnk->name, u.resp.header.cmd));
		    return;
		}
	}

	/* Decode message. */
	switch (u.resp.header.cmd) {
	    case NGM_PPPOE_SESSIONID: /* XXX: I do not know what to do with this? */
		break;
	    case NGM_PPPOE_SUCCESS:
		Log(LG_PHYS, ("[%s] PPPoE: connection successful", lnk->name));
		if (pe->opened) {
		    Disable(&lnk->conf.options, LINK_CONF_ACFCOMP);	/* RFC 2516 */
		    Deny(&lnk->conf.options, LINK_CONF_ACFCOMP);	/* RFC 2516 */
		    TimerStop(&pe->connectTimer);
		    p->state = PHYS_STATE_UP;
		    PhysUp();
		} else {
		    p->state = PHYS_STATE_READY;
		}
		break;
	    case NGM_PPPOE_FAIL:
		Log(LG_PHYS, ("[%s] PPPoE: connection failed", lnk->name));
		PhysDown(STR_CON_FAILED0, NULL);
		PppoeShutdown(lnk->phys);
		break;
	    case NGM_PPPOE_CLOSE:
		Log(LG_PHYS, ("[%s] PPPoE: connection closed", lnk->name));
		PhysDown(STR_DROPPED, NULL);
		PppoeShutdown(lnk->phys);
		break;
	    case NGM_PPPOE_ACNAME:
		Log(LG_PHYS, ("PPPoE: rec'd ACNAME \"%s\"",
		  ((struct ngpppoe_sts *)u.resp.data)->hook));
		break;
	    default:
		Log(LG_PHYS, ("PPPoE: rec'd command %lu from \"%s\"",
		    (u_long)u.resp.header.cmd, path));
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
	char	buf[64];

	Printf("PPPoE configuration:\r\n");
	Printf("\tIface Node   : %s\r\n", pe->path);
	Printf("\tIface Hook   : %s\r\n", pe->hook);
	Printf("\tSession      : %s\r\n", pe->session);
	Printf("PPPoE options:\r\n");
	OptStat(&pe->options, gConfList);
	Printf("PPPoE status:\r\n");
	Printf("\tState        : %s\r\n", gPhysStateNames[p->state]);
	Printf("\tOpened       : %s\r\n", (pe->opened?"YES":"NO"));
	Printf("\tIncoming     : %s\r\n", (pe->incoming?"YES":"NO"));
	PppoePeerAddr(p, buf, sizeof(buf));
	Printf("\tCurrent peer : %s\r\n", buf);
}

/*
 * PppoeOriginated()
 */
static int
PppoeOriginated(PhysInfo p)
{
	PppoeInfo      const pppoe = (PppoeInfo)p->info;

	return (pppoe->incoming ? LINK_ORIGINATE_REMOTE : LINK_ORIGINATE_LOCAL);
}

static int
PppoePeerAddr(PhysInfo p, void *buf, int buf_len)
{
	PppoeInfo	const pppoe = (PppoeInfo)p->info;

	snprintf(buf, buf_len, "%02x%02x%02x%02x%02x%02x",
	    pppoe->peeraddr[0], pppoe->peeraddr[1], pppoe->peeraddr[2], 
	    pppoe->peeraddr[3], pppoe->peeraddr[4], pppoe->peeraddr[5]);

	return (0);
}

static int 
CreatePppoeNode(const char *path, const char *hook, struct PppoeIf *PIf)
{
	u_char rbuf[2048];
	struct ng_mesg *resp;
	const struct hooklist *hlist;
	const struct nodeinfo *ninfo;
	int f;

	/* Make sure interface is up. */
	char iface[IFNAMSIZ + 1];

	snprintf(iface, sizeof(iface), "%s", path);
	if (iface[strlen(iface) - 1] == ':')
		iface[strlen(iface) - 1] = '\0';
	if (ExecCmd(LG_PHYS2, "%s %s up", PATH_IFCONFIG, iface) != 0) {
		Log(LG_ERR, ("[%s] can't bring up interface %s",
		    lnk->name, iface));
		return (0);
	}

	/* Create a new netgraph node */
	if (NgMkSockNode(NULL, &PIf->csock, &PIf->dsock) < 0) {
		Log(LG_ERR, ("[%s] PPPoE: can't create ctrl socket: %s",
		    lnk->name, strerror(errno)));
		return(0);
	}
	(void)fcntl(PIf->csock, F_SETFD, 1);
	(void)fcntl(PIf->dsock, F_SETFD, 1);

	/* Check if NG_ETHER_NODE_TYPE is available. */
	if (gNgEtherLoaded == FALSE) {
		const struct typelist *tlist;

		/* Ask for a list of available node types. */
		if (NgSendMsg(PIf->csock, "", NGM_GENERIC_COOKIE, NGM_LISTTYPES,
		    NULL, 0) < 0) {
			Log(LG_ERR, ("[%s] Cannot send a netgraph message: %s",
			    lnk->name, strerror(errno)));
			close(PIf->csock);
			close(PIf->dsock);
			return (0);
		}

		/* Get response. */
		resp = (struct ng_mesg *)rbuf;
		if (NgRecvMsg(PIf->csock, resp, sizeof rbuf, NULL) <= 0) {
			Log(LG_ERR, ("[%s] Cannot get netgraph response: %s",
			    lnk->name, strerror(errno)));
			close(PIf->csock);
			close(PIf->dsock);
			return (0);
		}

		/* Look for NG_ETHER_NODE_TYPE. */
		tlist = (const struct typelist*) resp->data;
		for (f = 0; f < tlist->numtypes; f++)
			if (strncmp(tlist->typeinfo[f].type_name,
			    NG_ETHER_NODE_TYPE,
			    sizeof NG_ETHER_NODE_TYPE - 1) == 0)
				gNgEtherLoaded = TRUE;

		/* If not found try to load ng_ether and repeat the check. */
		if (gNgEtherLoaded == FALSE && (kldload("ng_ether") < 0)) {
			Log(LG_ERR, ("PPPoE: Cannot load ng_ether: %s",
			    strerror(errno)));
			close(PIf->csock);
			close(PIf->dsock);
			assert (0);
		}
		gNgEtherLoaded = TRUE;
	}

	/*
	 * Ask for a list of hooks attached to the "ether" node. This node
	 * should magically exist as a way of hooking stuff onto an ethernet
	 * device.
	 */
	if (NgSendMsg(PIf->csock, path, NGM_GENERIC_COOKIE, NGM_LISTHOOKS,
	    NULL, 0) < 0) {
		Log(LG_ERR, ("[%s] Cannot send a netgraph message: %s:%s",
                    lnk->name, path, strerror(errno)));
		close(PIf->csock);
		close(PIf->dsock);
		return (0);
	}

	/* Get our list back. */
	resp = (struct ng_mesg *)rbuf;
	if (NgRecvMsg(PIf->csock, resp, sizeof rbuf, NULL) <= 0) {
		Log(LG_ERR, ("[%s] Cannot get netgraph response: %s",
		    lnk->name, strerror(errno)));
		close(PIf->csock);
		close(PIf->dsock);
		return (0);
	}

	hlist = (const struct hooklist *)resp->data;
	ninfo = &hlist->nodeinfo;

	/* Make sure we've got the right type of node. */
	if (strncmp(ninfo->type, NG_ETHER_NODE_TYPE,
	    sizeof NG_ETHER_NODE_TYPE - 1)) {
		Log(LG_ERR, ("[%s] Unexpected node type ``%s'' (wanted ``"
		    NG_ETHER_NODE_TYPE "'') on %s",
		    lnk->name, ninfo->type, path));
		close(PIf->csock);
		close(PIf->dsock);
		return (0);
	}

	/* Look for a hook already attached. */
	for (f = 0; f < ninfo->hooks; f++) {
		const struct linkinfo *nlink = &hlist->link[f];

		/* Search for "orphans" hook. */
		if (strcmp(nlink->ourhook, NG_ETHER_HOOK_ORPHAN) &&
		    strcmp(nlink->ourhook, NG_ETHER_HOOK_DIVERT))
			continue;

		/*
		 * Something is using the data coming out of this ``ether''
		 * node. If it's a PPPoE node, we use that node, otherwise
		 * we complain that someone else is using the node.
		 */
		if (strcmp(nlink->nodeinfo.type, NG_PPPOE_NODE_TYPE)) {
			Log(LG_ERR, ("%s Node type ``%s'' is currently "
			    " using orphan hook\n",
			    path, nlink->nodeinfo.type));
			close(PIf->csock);
			close(PIf->dsock);
			return (0);
		}
		break;
	}

	if (f == ninfo->hooks) {
		struct ngm_mkpeer mp;

		/* Create new PPPoE node. */
		snprintf(mp.type, sizeof(mp.type), "%s", NG_PPPOE_NODE_TYPE);
		snprintf(mp.ourhook, sizeof(mp.ourhook), "%s", hook);
		snprintf(mp.peerhook, sizeof(mp.peerhook), "%s",
		    NG_PPPOE_HOOK_ETHERNET);
		if (NgSendMsg(PIf->csock, path, NGM_GENERIC_COOKIE, NGM_MKPEER, &mp,
		    sizeof(mp)) < 0) {
			Log(LG_ERR, ("[%s] can't create %s peer to %s,%s: %s",
			    lnk->name, NG_PPPOE_NODE_TYPE,
			    path, hook, strerror(errno)));
			    close(PIf->csock);
			    close(PIf->dsock);
			    return (0);
		}
	};

	/* Register an event listening to the control socket. */
	EventRegister(&(PIf->ctrlEvent), EVENT_READ, PIf->csock,
	    EVENT_RECURRING, PppoeCtrlReadEvent, PIf);

	return (1);
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
	    u_char buf[sizeof(struct ngpppoe_init_data) + MAX_SESSION];
	    struct ngpppoe_init_data poeid;
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
		Log(LG_PHYS, ("Incoming PPPoE connection request via %s for "
		    "service \"%s\" from %s", PIf->ifnodepath, PIf->session,
		    ether_ntoa((const struct ether_addr *)macaddr)));
	} else {
		macaddr = NULL;
		Log(LG_PHYS, ("Incoming PPPoE connection request via %s for "
		    "service \"%s\"", PIf->ifnodepath, PIf->session));
	}

	if (gShutdownInProgress) {
		Log(LG_PHYS, ("Shutdown sequence in progress, ignoring"));
		return;
	}

	/* Examine all PPPoE links. */
	for (k = 0; k < gNumLinks; k++) {
	        PppoeInfo p;
		PhysInfo ph;

		if (gLinks[k] && gLinks[k]->phys->type != &gPppoePhysType)
			continue;

		ph = gLinks[k]->phys;
		p = (PppoeInfo)ph->info;

		if ((PIf!=p->PIf) ||
		    (ph->state != PHYS_STATE_DOWN) ||
		    (now-ph->lastClose < PPPOE_REOPEN_PAUSE) ||
		    !Enabled(&p->options, PPPOE_CONF_INCOMING))
			continue;

		/* Restore context. */
		lnk = gLinks[k];
		bund = lnk->bund;

		Log(LG_PHYS, ("[%s] Accepting PPPoE connection", lnk->name));

		/* Create ng_tee(4) node and connect it to ng_pppoe(4). */
		snprintf(session_hook, sizeof(session_hook), "mpd%d-%s",
		    gPid, lnk->name);
		snprintf(path, sizeof(path), "%s%s", p->path, p->hook);
		snprintf(mp.type, sizeof(mp.type), "%s", NG_TEE_NODE_TYPE);
		snprintf(mp.ourhook, sizeof(mp.ourhook), session_hook);
		snprintf(mp.peerhook, sizeof(mp.peerhook), "left");
		if (NgSendMsg(p->PIf->csock, path, NGM_GENERIC_COOKIE, NGM_MKPEER,
		    &mp, sizeof(mp)) < 0) {
			Log(LG_ERR, ("[%s] PPPoE: can't create %s peer to %s,%s: %s",
			    lnk->name, NG_TEE_NODE_TYPE,
			    path, "left", strerror(errno)));
			goto close_socket;
		}

		/* Connect our ng_ppp(4) node link hook and ng_tee(4) node. */
		snprintf(path1, sizeof(path), "%s%s.%s", p->path,
		    p->hook,session_hook);
		snprintf(linkHook, sizeof(linkHook), "%s%d",
		    NG_PPP_HOOK_LINK_PREFIX, lnk->bundleIndex);
		if (NgFuncConnect(MPD_HOOK_PPP, linkHook, path1, "right") < 0) {
			Log(LG_ERR, ("[%s] PPPoE: can't connect to ppp: %s",
			    lnk->name, strerror(errno)));
			goto shutdown_tee;
		}

		/* Connect our socket node link hook to the ng_tee(4) node. */
		snprintf(cn.path, sizeof(cn.path), "%s", path1);
		snprintf(cn.ourhook, sizeof(cn.ourhook), lnk->name);
		snprintf(cn.peerhook, sizeof(cn.peerhook), "left2right");
 
		if (NgSendMsg(p->PIf->csock, ".:", NGM_GENERIC_COOKIE, NGM_CONNECT,
		    &cn, sizeof(cn)) < 0) {
			Log(LG_ERR, ("[%s] PPPoE: can't connect \"%s\"->\"%s\" and \"%s\"->\"%s\": %s",
			    bund->name, ".:", cn.ourhook, cn.path,
			    cn.peerhook, strerror(errno)));
			goto disconnect_ppp;
		}

		/* Put the PPPoE node into OFFER mode. */
		memset(idata, 0, sizeof(idata));
		snprintf(idata->hook, sizeof(idata->hook), "%s", session_hook);
		if (gethostname(idata->data, MAX_SESSION) == -1) {
			Log(LG_ERR, ("[%s] PPPoE: gethostname() failed",
			    lnk->name));
			idata->data[0] = 0;
			/* XXXGL: fail? */
		}
		idata->data_len=strlen(idata->data);

		if (NgSendMsg(p->PIf->csock, path, NGM_PPPOE_COOKIE, NGM_PPPOE_OFFER,
		    idata, sizeof(*idata) + idata->data_len) < 0) {
			Log(LG_ERR, ("[%s] PPPoE: can't send NGM_PPPOE_OFFER to %s,%s "
			    ": %s",
			    lnk->name, path, idata->hook, strerror(errno)));
			goto disconnect_ppp;
		}

		memset(idata, 0, sizeof(idata));
		snprintf(idata->hook, sizeof(idata->hook), "%s", session_hook);
		idata->data_len = strlen(p->session);
		strncpy(idata->data, p->session, MAX_SESSION);

		if (NgSendMsg(p->PIf->csock, path, NGM_PPPOE_COOKIE,
		    NGM_PPPOE_SERVICE, idata,
		    sizeof(*idata) + idata->data_len) < 0) {
			Log(LG_ERR, ("[%s] PPPoE: can't send NGM_PPPOE_SERVICE to %s,"
			    "%s : %s",
			    lnk->name, path, idata->hook, strerror(errno)));
			goto disconnect_ppp;
		}

		/* And send our request data to the waiting node. */
		if (NgSendData(p->PIf->dsock, lnk->name, response, sz) == -1) {
			Log(LG_ERR, ("[%s] PPPoE: Cannot send original request: %s",
			    lnk->name, strerror(errno)));
			goto disconnect_ppp;
		}

		if (NgFuncShutdownNode(bund, lnk->name, path1) < 0) {
			Log(LG_ERR, ("[%s] PPPoE: Shutdown ng_tee node %s error: %s",
			    lnk->name, path1, strerror(errno)));
			goto disconnect_ppp;
		}

		ph->state = PHYS_STATE_CONNECTING;
		p->incoming = 1;
		/* Record the peer's MAC address */
		if (macaddr)
			for (i = 0; i < 6; i++)
				p->peeraddr[i] = macaddr[i];

		Log(LG_PHYS2, ("[%s] PPPoE response sent", lnk->name));

		/* Set a timer to limit connection time. */
		TimerInit(&p->connectTimer, "PPPoE-connect",
		    PPPOE_CONNECT_TIMEOUT * SECONDS, PppoeConnectTimeout, p);
		TimerStart(&p->connectTimer);

		RecordLinkUpDownReason(NULL, 1, STR_INCOMING_CALL, "", NULL);
		BundOpenLink(lnk);

		/* Done. */
		break;

disconnect_ppp:
		if (NgFuncDisconnect(MPD_HOOK_PPP,linkHook) < 0) {
			Log(LG_ERR, ("[%s] Disconnect ng_ppp node error: %s",
			    lnk->name, strerror(errno)));
		};

shutdown_tee:
		if (NgFuncShutdownNode(bund, lnk->name, path1) < 0) {
			Log(LG_ERR, ("[%s] Shutdown ng_tee node %s error: %s",
			    lnk->name, path1, strerror(errno)));
		};

close_socket:
		Log(LG_PHYS, ("[%s] PPPoE connection not accepted due to error",
			lnk->name));
	};

	if (k == gNumLinks)
		Log(LG_PHYS, ("No free PPPoE link with requested parameters "
		    "was found"));
};

static int 
ListenPppoeNode(const char *path, const char *hook, struct PppoeIf *PIf,
	const char *session, int n)
{
	union {
	    u_char buf[sizeof(struct ngpppoe_init_data) + MAX_SESSION];
	    struct ngpppoe_init_data	poeid;
	} u;
	struct ngpppoe_init_data *const idata = &u.poeid;
	char pat[NG_PATHLEN + 1];
	struct ngm_connect	cn;
	
	if (n) {
	    /* Create a new netgraph node */
	    if (NgMkSockNode(NULL, &PIf->csock, &PIf->dsock) < 0) {
		Log(LG_ERR, ("[%s] PPPoE: can't create ctrl socket: %s",
		    lnk->name, strerror(errno)));
		return(0);
	    }
	    (void)fcntl(PIf->csock, F_SETFD, 1);
	    (void)fcntl(PIf->dsock, F_SETFD, 1);
	}

	/* Connect our socket node link hook to the ng_pppoe(4) node. */
	snprintf(cn.path, sizeof(cn.path), "%s%s", path, hook);
	snprintf(cn.ourhook, sizeof(cn.ourhook), "listen-hook");
	snprintf(cn.peerhook, sizeof(cn.peerhook), "listen-%s", session);
  
	if (NgSendMsg(PIf->csock, ".:", NGM_GENERIC_COOKIE, NGM_CONNECT, &cn,
	    sizeof(cn)) < 0) {
		Log(LG_ERR, ("[%s] PPPoE: can't connect \"%s\"->\"%s\" and \"%s\"->\"%s\": %s",
		    bund->name, ".:", cn.ourhook, cn.path, cn.peerhook,
		    strerror(errno)));
		return(0);
	}

	/* Tell the PPPoE node to be a server. */
	snprintf(pat, sizeof(pat), "%s%s", path, hook);

	memset(idata, 0, sizeof(idata));
	snprintf(idata->hook, sizeof(idata->hook), "listen-%s", session);
	idata->data_len = strlen(session);
	strncpy(idata->data, session, MAX_SESSION);

	Log(LG_PHYS, ("[%s] PPPoE server listening on %s for service \"%s\"",
		lnk->name, path, idata->data));
	if (NgSendMsg(PIf->csock, pat, NGM_PPPOE_COOKIE, NGM_PPPOE_LISTEN,
	    idata, sizeof(*idata) + idata->data_len) < 0) {
		Log(LG_ERR, ("[%s] PPPoE: can't send NGM_PPPOE_LISTEN to %s hook "
		    "%s : %s", lnk->name, pat, idata->hook, strerror(errno)));
		return (0);
	}
	/* Register an event listening to the data socket. */
	EventRegister(&(PIf->dataEvent), EVENT_READ, PIf->dsock,
	    EVENT_RECURRING, PppoeListenEvent, PIf);
	
	if (n) {
	    /* Register an event listening to the control socket. */
	    EventRegister(&(PIf->ctrlEvent), EVENT_READ, PIf->csock,
		EVENT_RECURRING, PppoeCtrlReadEvent, PIf);
	}
	    
	return (1);
};

/*
 * PppoeNodeUpdate()
 */

static void
PppoeNodeUpdate(PhysInfo p)
{
  int i, j = -1;
  PppoeInfo pe = (PppoeInfo)p->info;

  if (!pe->PIf) { // Do this only once for interface

    if (!(strcmp(pe->path, "undefined:")
        &&strcmp(pe->session, "undefined:"))) {
    	    Log(LG_ERR, ("[%s] PPPoE: Skipping link %s with undefined "
	        "interface or session", pe->link->name, pe->link->name));
	    return;
    }

    for (i = 0; i < PppoeIfCount ; i++)
	if (strcmp(PppoeIfs[i].ifnodepath, pe->path) == 0) {
    	    j = i;
	    break;
	}
    if (j == -1) {
	if (PppoeIfCount>=PPPOE_MAXPARENTIFS) {
		Log(LG_ERR, ("[%s] PPPoE: Too many different parent interfaces! ", 
		    pe->link->name));
		return;
	}
	if (CreatePppoeNode(pe->path, pe->hook, &PppoeIfs[PppoeIfCount])) {
		snprintf(PppoeIfs[PppoeIfCount].ifnodepath,
		    sizeof(PppoeIfs[PppoeIfCount].ifnodepath),
		    "%s", pe->path);
		snprintf(PppoeIfs[PppoeIfCount].session,
		    sizeof(PppoeIfs[PppoeIfCount].session),
		    "%s", pe->session);
		PppoeIfs[PppoeIfCount].listen = 0;
		pe->PIf=&PppoeIfs[PppoeIfCount];
		PppoeIfCount++;
	} else {
		Log(LG_ERR, ("[%s] PPPoE: Error creating ng_pppoe "
		    "node on %s", pe->link->name, pe->path));
		return;
	}
    } else {
        pe->PIf=&PppoeIfs[j];
    }
  }
  
  if (Enabled(&pe->options, PPPOE_CONF_INCOMING) &&
        (!PppoeListenUpdateSheduled)) {
    	    /* Set a timer to run PppoeListenUpdate(). */
	    TimerInit(&PppoeListenUpdateTimer, "PppoeListenUpdate",
		0, PppoeListenUpdate, NULL);
	    TimerStart(&PppoeListenUpdateTimer);
	    PppoeListenUpdateSheduled = 1;
  }
}

/*
 * PppoeListenUpdate()
 */

static void
PppoeListenUpdate(void *arg)
{
	int k;

	PppoeListenUpdateSheduled = 0;

	/* Examine all PPPoE links. */
	for (k = 0; k < gNumLinks; k++) {
        	PppoeInfo p;
		int i, j = -1;

		if (gLinks[k] == NULL ||
		    gLinks[k]->phys->type != &gPppoePhysType)
			continue;

		p = (PppoeInfo)gLinks[k]->phys->info;

		if (!(strcmp(p->path, "undefined:")
		    &&strcmp(p->session, "undefined:"))) {
			Log(LG_ERR, ("PPPoE: Skipping link %s with undefined "
			    "interface or session", gLinks[k]->name));
			continue;
		}

		if (!Enabled(&p->options, PPPOE_CONF_INCOMING))
			continue;

		for (i = 0; i < PppoeIfCount; i++)
			if ((strcmp(PppoeIfs[i].ifnodepath, p->path) == 0) &&
			    (strcmp(PppoeIfs[i].session, p->session) == 0)) {
				j = i;
				break;
			}

		if (j == -1) {
			if (PppoeIfCount>=PPPOE_MAXPARENTIFS) {
			    Log(LG_ERR, ("[%s] PPPoE: Too many different parent interfaces! ", 
				p->link->name));
			    continue;
			}
			if (ListenPppoeNode(p->path, p->hook,
			    &(PppoeIfs[PppoeIfCount]), p->session, 1)) {
				snprintf(PppoeIfs[PppoeIfCount].ifnodepath,
				    sizeof(PppoeIfs[PppoeIfCount].ifnodepath),
				    "%s", p->path);
				snprintf(PppoeIfs[PppoeIfCount].session,
				    sizeof(PppoeIfs[PppoeIfCount].session),
				    "%s",p->session);
				PppoeIfs[PppoeIfCount].listen = 1;
				p->PIf=&PppoeIfs[PppoeIfCount];
				PppoeIfCount++;
			}
		} else {
			if ((PppoeIfs[j].listen == 0) &&
			    (ListenPppoeNode(p->path, p->hook, &(PppoeIfs[j]),
			    p->session, 0)))
				PppoeIfs[j].listen=1;
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
		Log(LG_ERR, ("[%s] PPPoE: Link type is not pppoe", lnk->name));
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
    	  PppoeNodeUpdate(lnk->phys);
          break;
        case SET_DISABLE:
          DisableCommand(ac, av, &pe->options, gConfList);
          break;
	default:
		assert(0);
	}
	return(0);
}
