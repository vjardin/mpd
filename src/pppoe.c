
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

#define MAX_PATH		64	/* XXX should be NG_PATHSIZ */
#define MAX_SESSION		64	/* max length of PPPoE session name */

/* Per link private info */
struct pppoeinfo {
	char		path[MAX_PATH];		/* PPPoE node path */
	char		hook[NG_HOOKSIZ];	/* hook on that node */
	char		session[MAX_SESSION];	/* session name */
	char		acname[PPPOE_SERVICE_NAME_SIZE];	/* AC name */
	u_char		peeraddr[6];		/* Peer MAC address */
	u_char		incoming;		/* incoming vs. outgoing */
	u_char		opened;			/* PPPoE opened by phys */
	struct optinfo	options;
	struct PppoeIf  *PIf;			/* pointer on parent ng_pppoe info */
	struct pppTimer	connectTimer;		/* connection timeout timer */
};
typedef struct pppoeinfo	*PppoeInfo;

static u_char gNgEtherLoaded = FALSE;

/* Set menu options */
enum {
	SET_IFACE,
	SET_SESSION,
	SET_ACNAME,
	SET_ENABLE,
	SET_DISABLE,
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

static int	PppoeInit(Link l);
static int	PppoeInst(Link l, Link lt);
static void	PppoeOpen(Link l);
static void	PppoeClose(Link l);
static void	PppoeShutdown(Link l);
static int	PppoePeerAddr(Link l, void *buf, int buf_len);
static int	PppoeCallingNum(Link l, void *buf, int buf_len);
static int	PppoeCalledNum(Link l, void *buf, int buf_len);
static void	PppoeCtrlReadEvent(int type, void *arg);
static void	PppoeConnectTimeout(void *arg);
static void	PppoeStat(Context ctx);
static int	PppoeSetCommand(Context ctx, int ac, char *av[], void *arg);
static int	PppoeOriginated(Link l);
static int	PppoeIsSync(Link l);
static void	PppoeNodeUpdate(Link l);
static void	PppoeListenUpdate(void *arg);

static void	PppoeDoClose(Link l);

/*
 * GLOBAL VARIABLES
 */

const struct phystype gPppoePhysType = {
    .name		= "pppoe",
    .descr		= "PPP over Ethernet",
    .minReopenDelay 	= PPPOE_REOPEN_PAUSE,
    .mtu		= PPPOE_MTU,
    .mru		= PPPOE_MRU,
    .tmpl		= 1,
    .init		= PppoeInit,
    .inst		= PppoeInst,
    .open		= PppoeOpen,
    .close		= PppoeClose,
    .update		= PppoeNodeUpdate,
    .shutdown		= PppoeShutdown,
    .showstat		= PppoeStat,
    .originate		= PppoeOriginated,
    .issync		= PppoeIsSync,
    .peeraddr		= PppoePeerAddr,
    .callingnum		= PppoeCallingNum,
    .callednum		= PppoeCalledNum,
};

const struct cmdtab PppoeSetCmds[] = {
      { "iface ifacename",	"Set ethernet interface to use",
	  PppoeSetCommand, NULL, (void *)SET_IFACE },
      { "service string",	"Set PPPoE session name",
	  PppoeSetCommand, NULL, (void *)SET_SESSION },
      { "acname string",	"Set PPPoE access concentrator name",
	  PppoeSetCommand, NULL, (void *)SET_ACNAME },
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
    char	ifnodepath[MAX_PATH];
    char	session[MAX_SESSION];
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
    { 0,	0,			NULL		},
};

/*
 * PppoeInit()
 *
 * Initialize device-specific data in physical layer info
 */
static int
PppoeInit(Link l)
{
	PppoeInfo pe;

	/* Allocate private struct */
	pe = (PppoeInfo)(l->info = Malloc(MB_PHYS, sizeof(*pe)));
	pe->incoming = 0;
	pe->opened = 0;
	snprintf(pe->path, sizeof(pe->path), "undefined:");
	snprintf(pe->hook, sizeof(pe->hook), "undefined");
	snprintf(pe->session, sizeof(pe->session), "*");
	memset(pe->peeraddr, 0x00, ETHER_ADDR_LEN);
	pe->PIf = NULL;

	/* Done */
	return(0);
}

/*
 * PppoeInst()
 *
 * Instantiate device
 */
static int
PppoeInst(Link l, Link lt)
{
	l->info = Mdup(MB_PHYS, lt->info, sizeof(struct pppoeinfo));

	/* Done */
	return(0);
}

/*
 * PppoeOpen()
 */
static void
PppoeOpen(Link l)
{
	PppoeInfo pe = (PppoeInfo)l->info;
	struct ngm_connect	cn;
	union {
	    u_char buf[sizeof(struct ngpppoe_init_data) + MAX_SESSION];
	    struct ngpppoe_init_data	poeid;
	} u;
	struct ngpppoe_init_data *const idata = &u.poeid;
	char path[NG_PATHSIZ];
	char session_hook[NG_HOOKSIZ];

	pe->opened=1;

	Disable(&l->conf.options, LINK_CONF_ACFCOMP);	/* RFC 2516 */
	Deny(&l->conf.options, LINK_CONF_ACFCOMP);	/* RFC 2516 */

	snprintf(session_hook, sizeof(session_hook), "mpd%d-%d", 
	    gPid, l->id);
	
	if (pe->incoming == 1) {
		Log(LG_PHYS2, ("[%s] PppoeOpen() on incoming call", l->name));

		/* Path to the ng_tee node */
		snprintf(path, sizeof(path), "%s%s.%s", 
		    pe->path, pe->hook, session_hook);
		    
		/* Connect ng_tee(4) node to the ng_ppp(4) node. */
		if (!PhysGetUpperHook(l, cn.path, cn.peerhook)) {
		    Log(LG_PHYS, ("[%s] PPPoE: can't get upper hook", l->name));
		    goto fail2;
		}
		snprintf(cn.ourhook, sizeof(cn.ourhook), "right");
		if (NgSendMsg(pe->PIf->csock, path, NGM_GENERIC_COOKIE, NGM_CONNECT, 
		    &cn, sizeof(cn)) < 0) {
			Log(LG_ERR, ("[%s] PPPoE: can't connect \"%s\"->\"%s\" and \"%s\"->\"%s\": %s",
	    		    l->name, path, cn.ourhook, cn.path, cn.peerhook, strerror(errno)));
			goto fail2;
		}

		/* Shutdown ng_tee node */
		if (NgFuncShutdownNode(pe->PIf->csock, l->name, path) < 0) {
			Log(LG_ERR, ("[%s] PPPoE: Shutdown ng_tee node %s error: %s",
			    l->name, path, strerror(errno)));
		}

		if (l->state==PHYS_STATE_READY) {
		    TimerStop(&pe->connectTimer);
		    l->state = PHYS_STATE_UP;
		    PhysUp(l);
		}
		return;
	}

	/* Sanity check. */
	if (l->state != PHYS_STATE_DOWN) {
		Log(LG_PHYS, ("[%s] PPPoE allready active", l->name));
		return;
	};

	/* Create PPPoE node if necessary. */
	PppoeNodeUpdate(l);

	if (!pe->PIf) {
	    Log(LG_ERR, ("[%s] PPPoE node for link is not initialized",
	        l->name));
	    goto fail;
	}

	/* Connect our ng_ppp(4) node link hook to the ng_pppoe(4) node. */
	snprintf(cn.ourhook, sizeof(cn.ourhook), "%s", session_hook);
	snprintf(path, sizeof(path), "%s%s", pe->path, pe->hook);

	if (!PhysGetUpperHook(l, cn.path, cn.peerhook)) {
	    Log(LG_PHYS, ("[%s] PPPoE: can't get upper hook", l->name));
	    goto fail2;
	}
	
	if (NgSendMsg(pe->PIf->csock, path, NGM_GENERIC_COOKIE, NGM_CONNECT, 
	    &cn, sizeof(cn)) < 0) {
		Log(LG_ERR, ("[%s] PPPoE: can't connect \"%s\"->\"%s\" and \"%s\"->\"%s\": %s",
    		    l->name, path, cn.ourhook, cn.path, cn.peerhook, strerror(errno)));
		goto fail2;
	}

	Log(LG_PHYS, ("[%s] PPPoE: Connecting to '%s'", l->name, pe->session));
	
	/* Tell the PPPoE node to try to connect to a server. */
	memset(idata, 0, sizeof(idata));
	snprintf(idata->hook, sizeof(idata->hook), "%s", session_hook);
	idata->data_len = strlen(pe->session);
	strncpy(idata->data, pe->session, MAX_SESSION);
	if (NgSendMsg(pe->PIf->csock, path, NGM_PPPOE_COOKIE, NGM_PPPOE_CONNECT,
	    idata, sizeof(*idata) + idata->data_len) < 0) {
		Log(LG_ERR, ("[%s] PPPoE can't request connection to server: "
		    "%s", l->name, strerror(errno)));
		goto fail2;
	}

	/* Set a timer to limit connection time. */
	TimerInit(&pe->connectTimer, "PPPoE-connect",
	    PPPOE_CONNECT_TIMEOUT * SECONDS, PppoeConnectTimeout, l);
	TimerStart(&pe->connectTimer);

	/* OK */
	l->state = PHYS_STATE_CONNECTING;
	return;

fail2:
	NgFuncDisconnect(pe->PIf->csock, l->name, path, session_hook);
fail:	
	PhysDown(l, STR_CON_FAILED0, NULL);
	return;
}

/*
 * PppoeConnectTimeout()
 */
static void
PppoeConnectTimeout(void *arg)
{
	const Link l = (Link)arg;

	/* Cancel connection. */
	Log(LG_PHYS, ("[%s] PPPoE connection timeout after %d seconds",
	    l->name, PPPOE_CONNECT_TIMEOUT));
	PppoeDoClose(l);
	PhysDown(l, STR_CON_FAILED0, NULL);
}

/*
 * PppoeClose()
 */
static void
PppoeClose(Link l)
{
	const PppoeInfo pe = (PppoeInfo)l->info;

	pe->opened = 0;
	if (l->state == PHYS_STATE_DOWN)
		return;
	PppoeDoClose(l);
	PhysDown(l, 0, NULL);
}

/*
 * PppoeShutdown()
 *
 * Shut everything down and go to the PHYS_STATE_DOWN state.
 */
static void
PppoeShutdown(Link l)
{
	PppoeDoClose(l);
	Freee(MB_PHYS, l->info);
}

/*
 * PppoeDoClose()
 *
 * Shut everything down and go to the PHYS_STATE_DOWN state.
 */
static void
PppoeDoClose(Link l)
{
	const PppoeInfo pi = (PppoeInfo)l->info;
	char path[NG_PATHSIZ];
	char session_hook[NG_HOOKSIZ];

	if (l->state == PHYS_STATE_DOWN)
		return;

	snprintf(path, sizeof(path), "%s%s", pi->path, pi->hook);
	snprintf(session_hook, sizeof(session_hook), "mpd%d-%d",
	    gPid, l->id);
	NgFuncDisconnect(pi->PIf->csock, l->name, path, session_hook);

	TimerStop(&pi->connectTimer);
	l->state = PHYS_STATE_DOWN;
	pi->incoming = 0;
	memset(pi->peeraddr, 0x00, ETHER_ADDR_LEN);
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
	char path[NG_PATHSIZ];
	Link l = NULL;
	PppoeInfo pi = NULL;
	
	struct PppoeIf  *PIf=(struct PppoeIf*)arg;
	
	/* Read control message. */
	if (NgRecvMsg(PIf->csock, &u.resp, sizeof(u), path) < 0) {
		Log(LG_ERR, ("PPPoE: error reading message from \"%s\": %s",
		    path, strerror(errno)));
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
	    {
		char	ppphook[NG_HOOKSIZ];
		char	*linkname, *rest;
		int	id;

		/* Check hook name prefix */
		snprintf(ppphook, NG_HOOKSIZ, "mpd%d-", gPid);
		linkname = ((struct ngpppoe_sts *)u.resp.data)->hook;
		if (strncmp(linkname, ppphook, strlen(ppphook))) {
		    Log(LG_ERR, ("PPPoE: message from unknown hook \"%s\"",
			((struct ngpppoe_sts *)u.resp.data)->hook));
		    return;
		}
		linkname += strlen(ppphook);
		id = strtol(linkname, &rest, 10);
		if (rest[0] != 0 ||
		  !gLinks[id] ||
		  gLinks[id]->type != &gPppoePhysType ||
		  PIf != ((PppoeInfo)gLinks[id]->info)->PIf) {
		    Log(LG_ERR, ("PPPoE: message from unknown hook \"%s\"",
			((struct ngpppoe_sts *)u.resp.data)->hook));
		    return;
		}
		
		l = gLinks[id];
		pi = (PppoeInfo)l->info;

		if (l->state == PHYS_STATE_DOWN) {
		    if (u.resp.header.cmd != NGM_PPPOE_CLOSE) 
			Log(LG_PHYS, ("[%s] PPPoE: message %d in DOWN state",
			    l->name, u.resp.header.cmd));
		    return;
		}
	    }
	}

	/* Decode message. */
	switch (u.resp.header.cmd) {
	    case NGM_PPPOE_SESSIONID: /* XXX: I do not know what to do with this? */
		break;
	    case NGM_PPPOE_SUCCESS:
		Log(LG_PHYS, ("[%s] PPPoE: connection successful", l->name));
		if (pi->opened) {
		    TimerStop(&pi->connectTimer);
		    l->state = PHYS_STATE_UP;
		    PhysUp(l);
		} else {
		    l->state = PHYS_STATE_READY;
		}
		break;
	    case NGM_PPPOE_FAIL:
		Log(LG_PHYS, ("[%s] PPPoE: connection failed", l->name));
		PppoeDoClose(l);
		PhysDown(l, STR_CON_FAILED0, NULL);
		break;
	    case NGM_PPPOE_CLOSE:
		Log(LG_PHYS, ("[%s] PPPoE: connection closed", l->name));
		PppoeDoClose(l);
		PhysDown(l, STR_DROPPED, NULL);
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
PppoeStat(Context ctx)
{
	const PppoeInfo pe = (PppoeInfo)ctx->lnk->info;
	char	buf[64];

	Printf("PPPoE configuration:\r\n");
	Printf("\tIface Node   : %s\r\n", pe->path);
	Printf("\tIface Hook   : %s\r\n", pe->hook);
	Printf("\tSession      : %s\r\n", pe->session);
	Printf("PPPoE options:\r\n");
	OptStat(ctx, &pe->options, gConfList);
	Printf("PPPoE status:\r\n");
	Printf("\tState        : %s\r\n", gPhysStateNames[ctx->lnk->state]);
	if (ctx->lnk->state != PHYS_STATE_DOWN) {
	    Printf("\tOpened       : %s\r\n", (pe->opened?"YES":"NO"));
	    Printf("\tIncoming     : %s\r\n", (pe->incoming?"YES":"NO"));
	    PppoePeerAddr(ctx->lnk, buf, sizeof(buf));
	    Printf("\tCurrent peer : %s\r\n", buf);
	}
}

/*
 * PppoeOriginated()
 */
static int
PppoeOriginated(Link l)
{
	PppoeInfo      const pppoe = (PppoeInfo)l->info;

	return (pppoe->incoming ? LINK_ORIGINATE_REMOTE : LINK_ORIGINATE_LOCAL);
}

/*
 * PppoeIsSync()
 */
static int
PppoeIsSync(Link l)
{
	return (1);
}

static int
PppoePeerAddr(Link l, void *buf, int buf_len)
{
	PppoeInfo	const pppoe = (PppoeInfo)l->info;

	snprintf(buf, buf_len, "%02x%02x%02x%02x%02x%02x",
	    pppoe->peeraddr[0], pppoe->peeraddr[1], pppoe->peeraddr[2], 
	    pppoe->peeraddr[3], pppoe->peeraddr[4], pppoe->peeraddr[5]);

	return (0);
}

static int
PppoeCallingNum(Link l, void *buf, int buf_len)
{
	PppoeInfo	const pppoe = (PppoeInfo)l->info;

	if (pppoe->incoming) {
	    snprintf(buf, buf_len, "%02x%02x%02x%02x%02x%02x",
		pppoe->peeraddr[0], pppoe->peeraddr[1], pppoe->peeraddr[2], 
		pppoe->peeraddr[3], pppoe->peeraddr[4], pppoe->peeraddr[5]);
	} else {
	    ((char*)buf)[0] = 0;
	}

	return (0);
}

static int
PppoeCalledNum(Link l, void *buf, int buf_len)
{
	PppoeInfo	const pppoe = (PppoeInfo)l->info;

	if (!pppoe->incoming) {
	    snprintf(buf, buf_len, "%02x%02x%02x%02x%02x%02x",
		pppoe->peeraddr[0], pppoe->peeraddr[1], pppoe->peeraddr[2], 
		pppoe->peeraddr[3], pppoe->peeraddr[4], pppoe->peeraddr[5]);
	} else {
	    strlcpy(buf, pppoe->session, buf_len);
	}

	return (0);
}

static int 
CreatePppoeNode(Link l, const char *path, const char *hook, struct PppoeIf *PIf)
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
	if (ExecCmdNosh(LG_PHYS2, l->name, "%s %s up", PATH_IFCONFIG, iface) != 0) {
		Log(LG_ERR, ("[%s] can't bring up interface %s",
		    l->name, iface));
		return (0);
	}

	/* Create a new netgraph node */
	if (NgMkSockNode(NULL, &PIf->csock, &PIf->dsock) < 0) {
		Log(LG_ERR, ("[%s] PPPoE: can't create ctrl socket: %s",
		    l->name, strerror(errno)));
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
			    l->name, strerror(errno)));
			close(PIf->csock);
			close(PIf->dsock);
			return (0);
		}

		/* Get response. */
		resp = (struct ng_mesg *)rbuf;
		if (NgRecvMsg(PIf->csock, resp, sizeof(rbuf), NULL) <= 0) {
			Log(LG_ERR, ("[%s] Cannot get netgraph response: %s",
			    l->name, strerror(errno)));
			close(PIf->csock);
			close(PIf->dsock);
			return (0);
		}

		/* Look for NG_ETHER_NODE_TYPE. */
		tlist = (const struct typelist*) resp->data;
		for (f = 0; f < tlist->numtypes; f++)
			if (strncmp(tlist->typeinfo[f].type_name,
			    NG_ETHER_NODE_TYPE,
			    sizeof(NG_ETHER_NODE_TYPE) - 1) == 0)
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
                    l->name, path, strerror(errno)));
		close(PIf->csock);
		close(PIf->dsock);
		return (0);
	}

	/* Get our list back. */
	resp = (struct ng_mesg *)rbuf;
	if (NgRecvMsg(PIf->csock, resp, sizeof(rbuf), NULL) <= 0) {
		Log(LG_ERR, ("[%s] Cannot get netgraph response: %s",
		    l->name, strerror(errno)));
		close(PIf->csock);
		close(PIf->dsock);
		return (0);
	}

	hlist = (const struct hooklist *)resp->data;
	ninfo = &hlist->nodeinfo;

	/* Make sure we've got the right type of node. */
	if (strncmp(ninfo->type, NG_ETHER_NODE_TYPE,
	    sizeof(NG_ETHER_NODE_TYPE) - 1)) {
		Log(LG_ERR, ("[%s] Unexpected node type ``%s'' (wanted ``"
		    NG_ETHER_NODE_TYPE "'') on %s",
		    l->name, ninfo->type, path));
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
			    l->name, NG_PPPOE_NODE_TYPE,
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
	int			i,k,sz;
	struct PppoeIf		*PIf=(struct PppoeIf *)(arg);
	char			rhook[NG_HOOKSIZ];
	unsigned char		response[1024];

	char			path[NG_PATHSIZ];
	char			path1[NG_PATHSIZ];
	char			session_hook[NG_HOOKSIZ];
	struct ngm_connect      cn;
	struct ngm_mkpeer 	mp;
	u_char 			*macaddr;
	Link 			l = NULL;
	PppoeInfo		pi = NULL;

	union {
	    u_char buf[sizeof(struct ngpppoe_init_data) + MAX_SESSION];
	    struct ngpppoe_init_data poeid;
	} u;
	struct ngpppoe_init_data *const idata = &u.poeid;

	switch (sz = NgRecvData(PIf->dsock, response, sizeof(response), rhook)) {
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
		Log(LG_PHYS, ("Shutdown sequence in progress, ignoring request."));
		return;
	}

	if (OVERLOAD()) {
		Log(LG_PHYS, ("Daemon overloaded, ignoring request."));
		return;
	}

	/* Examine all PPPoE links. */
	for (k = 0; k < gNumLinks; k++) {
		Link l2;
	        PppoeInfo pi2;

		if (!gLinks[k] || gLinks[k]->type != &gPppoePhysType)
			continue;

		l2 = gLinks[k];
		pi2 = (PppoeInfo)l2->info;

		if ((!PhysIsBusy(l2)) &&
		    (pi2->PIf == PIf) &&
		    Enabled(&l2->conf.options, LINK_CONF_INCOMING)) {
			l = l2;
			pi = pi2;
			break;
		}
	}
	
	if (l != NULL && l->tmpl) {
	    l = LinkInst(l, NULL, 0, 0);
	    pi = (PppoeInfo)l->info;
	}

	if (pi != NULL) {
		Log(LG_PHYS, ("[%s] Accepting PPPoE connection", l->name));

		/* Path to the ng_pppoe */
		snprintf(path, sizeof(path), "%s%s", pi->path, pi->hook);

		/* Name of ng_pppoe session hook */
		snprintf(session_hook, sizeof(session_hook), "mpd%d-%d",
		    gPid, l->id);
		
		/* Create ng_tee(4) node and connect it to ng_pppoe(4). */
		snprintf(mp.type, sizeof(mp.type), "%s", NG_TEE_NODE_TYPE);
		snprintf(mp.ourhook, sizeof(mp.ourhook), session_hook);
		snprintf(mp.peerhook, sizeof(mp.peerhook), "left");
		if (NgSendMsg(pi->PIf->csock, path, NGM_GENERIC_COOKIE, NGM_MKPEER,
		    &mp, sizeof(mp)) < 0) {
			Log(LG_ERR, ("[%s] PPPoE: can't create %s peer to %s,%s: %s",
			    l->name, NG_TEE_NODE_TYPE,
			    path, "left", strerror(errno)));
			goto close_socket;
		}

		/* Path to the ng_tee */
		snprintf(path1, sizeof(path), "%s.%s", path, session_hook);

		/* Connect our socket node link hook to the ng_tee(4) node. */
		snprintf(cn.ourhook, sizeof(cn.ourhook), l->name);
		snprintf(cn.path, sizeof(cn.path), "%s", path1);
		snprintf(cn.peerhook, sizeof(cn.peerhook), "left2right");
		if (NgSendMsg(pi->PIf->csock, ".:", NGM_GENERIC_COOKIE, NGM_CONNECT,
		    &cn, sizeof(cn)) < 0) {
			Log(LG_ERR, ("[%s] PPPoE: can't connect \"%s\"->\"%s\" and \"%s\"->\"%s\": %s",
			    l->name, ".:", cn.ourhook, cn.path,
			    cn.peerhook, strerror(errno)));
			goto shutdown_tee;
		}

		/* Put the PPPoE node into OFFER mode. */
		memset(idata, 0, sizeof(idata));
		snprintf(idata->hook, sizeof(idata->hook), "%s", session_hook);
		if (pi->acname[0] != 0) {
			strlcpy(idata->data, pi->acname, MAX_SESSION);
		} else {
			if (gethostname(idata->data, MAX_SESSION) == -1) {
				Log(LG_ERR, ("[%s] PPPoE: gethostname() failed",
				    l->name));
				idata->data[0] = 0;
			}
			if (idata->data[0] == 0)
				strlcpy(idata->data, "NONAME", MAX_SESSION);
		}
		idata->data_len=strlen(idata->data);

		if (NgSendMsg(pi->PIf->csock, path, NGM_PPPOE_COOKIE, NGM_PPPOE_OFFER,
		    idata, sizeof(*idata) + idata->data_len) < 0) {
			Log(LG_ERR, ("[%s] PPPoE: can't send NGM_PPPOE_OFFER to %s,%s "
			    ": %s",
			    l->name, path, idata->hook, strerror(errno)));
			goto shutdown_tee;
		}

		memset(idata, 0, sizeof(idata));
		snprintf(idata->hook, sizeof(idata->hook), "%s", session_hook);
		idata->data_len = strlen(pi->session);
		strncpy(idata->data, pi->session, MAX_SESSION);

		if (NgSendMsg(pi->PIf->csock, path, NGM_PPPOE_COOKIE,
		    NGM_PPPOE_SERVICE, idata,
		    sizeof(*idata) + idata->data_len) < 0) {
			Log(LG_ERR, ("[%s] PPPoE: can't send NGM_PPPOE_SERVICE to %s,"
			    "%s : %s",
			    l->name, path, idata->hook, strerror(errno)));
			goto shutdown_tee;
		}

		/* And send our request data to the waiting node. */
		if (NgSendData(pi->PIf->dsock, l->name, response, sz) == -1) {
			Log(LG_ERR, ("[%s] PPPoE: Cannot send original request: %s",
			    l->name, strerror(errno)));
			goto shutdown_tee;
		}
		
	        if (NgFuncDisconnect(pi->PIf->csock, l->name, ".:", l->name) < 0) {
			Log(LG_ERR, ("[%s] PPPoE: can't remove hook %s: %s", 
			    l->name, l->name, strerror(errno)));
			goto shutdown_tee;
    		}

		l->state = PHYS_STATE_CONNECTING;
		pi->incoming = 1;
		/* Record the peer's MAC address */
		if (macaddr)
			for (i = 0; i < 6; i++)
				pi->peeraddr[i] = macaddr[i];

		Log(LG_PHYS2, ("[%s] PPPoE response sent", l->name));

		/* Set a timer to limit connection time. */
		TimerInit(&pi->connectTimer, "PPPoE-connect",
		    PPPOE_CONNECT_TIMEOUT * SECONDS, PppoeConnectTimeout, l);
		TimerStart(&pi->connectTimer);

		PhysIncoming(l);
	} else {
		Log(LG_PHYS, ("No free PPPoE link with requested parameters "
		    "was found"));
	}

	return;

shutdown_tee:
	if (NgFuncShutdownNode(pi->PIf->csock, l->name, path1) < 0) {
		Log(LG_ERR, ("[%s] Shutdown ng_tee node %s error: %s",
		    l->name, path1, strerror(errno)));
	};

close_socket:
	Log(LG_PHYS, ("[%s] PPPoE connection not accepted due to error",
		l->name));
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
	char pat[NG_PATHSIZ];
	struct ngm_connect	cn;
	
	if (n) {
	    /* Create a new netgraph node */
	    if (NgMkSockNode(NULL, &PIf->csock, &PIf->dsock) < 0) {
		Log(LG_ERR, ("PPPoE: Can't create listening ctrl socket: %s",
		    strerror(errno)));
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
		Log(LG_ERR, ("PPPoE: Can't connect \"%s\"->\"%s\" and \"%s\"->\"%s\": %s",
		    ".:", cn.ourhook, cn.path, cn.peerhook,
		    strerror(errno)));
		return(0);
	}

	/* Tell the PPPoE node to be a server. */
	snprintf(pat, sizeof(pat), "%s%s", path, hook);

	memset(idata, 0, sizeof(idata));
	snprintf(idata->hook, sizeof(idata->hook), "listen-%s", session);
	idata->data_len = strlen(session);
	strncpy(idata->data, session, MAX_SESSION);

	if (NgSendMsg(PIf->csock, pat, NGM_PPPOE_COOKIE, NGM_PPPOE_LISTEN,
	    idata, sizeof(*idata) + idata->data_len) < 0) {
		Log(LG_ERR, ("PPPoE: Can't send NGM_PPPOE_LISTEN to %s hook "
		    "%s : %s", pat, idata->hook, strerror(errno)));
		return (0);
	}

	Log(LG_PHYS, ("PPPoE: waiting for connection on %s, service \"%s\"",
		path, idata->data));

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
PppoeNodeUpdate(Link l)
{
  int i, j = -1;
  PppoeInfo pi = (PppoeInfo)l->info;

  if (!pi->PIf) { // Do this only once for interface

    if (!(strcmp(pi->path, "undefined:")
        &&strcmp(pi->session, "undefined:"))) {
    	    Log(LG_ERR, ("[%s] PPPoE: Skipping link \"%s\" with undefined "
	        "interface or session", l->name, l->name));
	    return;
    }

    for (i = 0; i < PppoeIfCount ; i++)
	if (strcmp(PppoeIfs[i].ifnodepath, pi->path) == 0) {
    	    j = i;
	    break;
	}
    if (j == -1) {
	if (PppoeIfCount>=PPPOE_MAXPARENTIFS) {
		Log(LG_ERR, ("[%s] PPPoE: Too many different parent interfaces! ", 
		    l->name));
		return;
	}
	if (CreatePppoeNode(l, pi->path, pi->hook, &PppoeIfs[PppoeIfCount])) {
		strlcpy(PppoeIfs[PppoeIfCount].ifnodepath,
		    pi->path,
		    sizeof(PppoeIfs[PppoeIfCount].ifnodepath));
		strlcpy(PppoeIfs[PppoeIfCount].session,
		    pi->session,
		    sizeof(PppoeIfs[PppoeIfCount].session));
		PppoeIfs[PppoeIfCount].listen = 0;
		pi->PIf=&PppoeIfs[PppoeIfCount];
		PppoeIfCount++;
	} else {
		Log(LG_ERR, ("[%s] PPPoE: Error creating ng_pppoe "
		    "node on %s", l->name, pi->path));
		return;
	}
    } else {
        pi->PIf=&PppoeIfs[j];
    }
  }
  
  if (Enabled(&l->conf.options, LINK_CONF_INCOMING) &&
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
        	PppoeInfo pi;
        	Link l;
		int i, j = -1;

		if (gLinks[k] == NULL ||
		    gLinks[k]->type != &gPppoePhysType)
			continue;

		l = gLinks[k];
		pi = (PppoeInfo)l->info;

		if (!Enabled(&l->conf.options, LINK_CONF_INCOMING))
			continue;

		if (!(strcmp(pi->path, "undefined:")
		    &&strcmp(pi->session, "undefined:"))) {
			Log(LG_ERR, ("PPPoE: Skipping link \"%s\" with undefined "
			    "interface or session", l->name));
			continue;
		}

		for (i = 0; i < PppoeIfCount; i++)
			if ((strcmp(PppoeIfs[i].ifnodepath, pi->path) == 0) &&
			    (strcmp(PppoeIfs[i].session, pi->session) == 0)) {
				j = i;
				break;
			}

		if (j == -1) {
			if (PppoeIfCount>=PPPOE_MAXPARENTIFS) {
			    Log(LG_ERR, ("[%s] PPPoE: Too many different parent interfaces! ", 
				l->name));
			    continue;
			}
			if (ListenPppoeNode(pi->path, pi->hook,
			    &(PppoeIfs[PppoeIfCount]), pi->session, 1)) {
				strlcpy(PppoeIfs[PppoeIfCount].ifnodepath,
				    pi->path,
				    sizeof(PppoeIfs[PppoeIfCount].ifnodepath));
				strlcpy(PppoeIfs[PppoeIfCount].session,
				    pi->session,
				    sizeof(PppoeIfs[PppoeIfCount].session));
				PppoeIfs[PppoeIfCount].listen = 1;
				pi->PIf=&PppoeIfs[PppoeIfCount];
				PppoeIfCount++;
			}
		} else {
			if ((PppoeIfs[j].listen == 0) &&
			    (ListenPppoeNode(pi->path, pi->hook, &(PppoeIfs[j]),
			    pi->session, 0))) {
				PppoeIfs[j].listen=1;
			}
			pi->PIf=&PppoeIfs[j];
		}
	}
}

/*
 * PppoeSetCommand()
 */
 
static int
PppoeSetCommand(Context ctx, int ac, char *av[], void *arg)
{
	const PppoeInfo pi = (PppoeInfo) ctx->lnk->info;
	const char *hookname = ETHER_DEFAULT_HOOK;
	const char *colon;

	switch ((intptr_t)arg) {
	case SET_IFACE:
		switch (ac) {
		case 2:
			hookname = av[1];
			/* fall through */
		case 1:
			colon = (av[0][strlen(av[0]) - 1] == ':') ? "" : ":";
			snprintf(pi->path, sizeof(pi->path),
			    "%s%s", av[0], colon);
			snprintf(pi->hook, sizeof(pi->hook),
			    "%s", hookname);
			break;
		default:
			return(-1);
		}
		break;
	case SET_SESSION:
		if (ac != 1)
			return(-1);
		snprintf(pi->session, sizeof(pi->session), "%s", av[0]);
		break;
	case SET_ACNAME:
		if (ac != 1)
			return(-1);
		snprintf(pi->acname, sizeof(pi->acname), "%s", av[0]);
		break;
	case SET_ENABLE:
          EnableCommand(ac, av, &pi->options, gConfList);
    	  PppoeNodeUpdate(ctx->lnk);
          break;
        case SET_DISABLE:
          DisableCommand(ac, av, &pi->options, gConfList);
          break;
	default:
		assert(0);
	}
	return(0);
}
