
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
#include <netgraph/ng_pppoe.h>
#include <netgraph/ng_ether.h>
#include <netgraph/ng_message.h>
#include <netgraph.h>

/* XXX Answer (i.e., server) mode is not supported yet */

/*
 * DEFINITIONS
 */

#define PPPOE_MTU		1492	/* allow room for PPPoE overhead */
#define PPPOE_MRU		1492

#define PPPOE_REOPEN_PAUSE	5
#define PPPOE_CONNECT_TIMEOUT	9

#define ETHER_DEFAULT_HOOK	NG_ETHER_HOOK_ORPHAN
#define PPPOE_SESSION_HOOK	"session"

#define MAX_PATH		64	/* XXX should be NG_PATHLEN */
#define MAX_SESSION		64	/* max length of PPPoE session name */

/* Per link private info */
struct nginfo {
	int		state;			/* link layer state */
	int		csock;			/* netgraph Control socket */
	int		ifaceUp:1;		/* interface is up */
	char		path[MAX_PATH + 1];	/* node that takes PPP frames */
	char		hook[NG_HOOKLEN + 1];	/* hook on that node */
	char		session[MAX_SESSION+1];	/* session name */
	Link		link;			/* our link */
	EventRef	ctrlEvent;		/* listen for ctrl messages */
	struct pppTimer	connectTimer;		/* connection timeout timer */
};
typedef struct nginfo	*PppoeInfo;

/* Set menu options */
enum {
	SET_IFACE,
	SET_SESSION,
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
static void	PppoeCtrlReadEvent(int type, void *arg);
static void	PppoeConnectTimeout(void *arg);
static void	PppoeStat(PhysInfo p);
static int	PppoeSetCommand(int ac, char *av[], void *arg);
static int	PppoeOriginated(PhysInfo p);

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
};

const struct cmdtab PppoeSetCmds[] = {
      { "iface ifacename",	"Set ethernet interface to use",
	  PppoeSetCommand, NULL, (void *)SET_IFACE },
      { "service string",	"Set PPPoE session name",
	  PppoeSetCommand, NULL, (void *)SET_SESSION },
      { NULL },
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
	pe->state = PPPOE_DOWN;
	snprintf(pe->path, sizeof(pe->path), "undefined:");
	snprintf(pe->hook, sizeof(pe->hook), "undefined");
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
	char session_hook[NG_HOOKLEN + 1];
	const PppoeInfo pe = (PppoeInfo)p->info;
	union {
	    u_char			buf[sizeof(struct ngpppoe_init_data)
						+ MAX_SESSION];
	    struct ngpppoe_init_data	poeid;
	} u;
	struct ngpppoe_init_data *const idata = &u.poeid;
	char path[NG_PATHLEN + 1];
	char linkHook[NG_HOOKLEN + 1];

	/* Sanity */
	if (pe->state != PPPOE_DOWN)
		return;

	/* Make sure interface is up */
	if (!pe->ifaceUp) {
		char iface[IFNAMSIZ + 1];

		snprintf(iface, sizeof(iface), "%s", pe->path);
		if (iface[strlen(iface) - 1] == ':')
			iface[strlen(iface) - 1] = '\0';
		if (ExecCmd(LG_PHYS, "%s %s up", PATH_IFCONFIG, iface) != 0) {
			Log(LG_ERR, ("[%s] can't bring up interface %s",
			    lnk->name, iface));
			goto fail;
		}
		pe->ifaceUp = 1;
	}

	/* Create a new netgraph node */
	if (NgMkSockNode(NULL, &pe->csock, NULL) < 0) {
		Log(LG_ERR, ("[%s] can't create ctrl socket: %s",
		    lnk->name, strerror(errno)));
		goto fail;
	}
	(void)fcntl(pe->csock, F_SETFD, 1);

#if 0	/**** BUG IN NgSendAsciiMsg(), fixed in rev. 1.3 ****/
	/* Attach a new ng_pppoe(4) node to the Ethernet node */
	if (NgSendAsciiMsg(bund->csock, pe->path,
	    "mkpeer { type=\"%s\" ourhook=\"%s\" peerhook=\"%s\" }",
	    NG_PPPOE_NODE_TYPE, pe->hook, NG_PPPOE_HOOK_ETHERNET) < 0) {
		Log(LG_ERR, ("[%s] can't create %s peer to %s,%s: %s",
		    lnk->name, NG_PPPOE_NODE_TYPE,
		    pe->path, pe->hook, strerror(errno)));
		goto fail2;
	}
#else
    {
	struct ngm_mkpeer mp;

	/* Create new PPPoE node */
	snprintf(mp.type, sizeof(mp.type), "%s", NG_PPPOE_NODE_TYPE);
	snprintf(mp.ourhook, sizeof(mp.ourhook), "%s", pe->hook);
	snprintf(mp.peerhook, sizeof(mp.peerhook),
	    "%s", NG_PPPOE_HOOK_ETHERNET);
	if (NgSendMsg(bund->csock, pe->path,
	    NGM_GENERIC_COOKIE, NGM_MKPEER, &mp, sizeof(mp)) < 0
	  && errno != EEXIST) {
		Log(LG_ERR, ("[%s] can't create %s peer to %s,%s: %s",
		    lnk->name, NG_PPPOE_NODE_TYPE,
		    pe->path, pe->hook, strerror(errno)));
		goto fail2;
	}
    }
#endif

	/* Connect our ng_ppp(4) node link hook to the ng_pppoe(4) node */
	snprintf(path, sizeof(path), "%s%s", pe->path, pe->hook);
	snprintf(linkHook, sizeof(linkHook),
	    "%s%d", NG_PPP_HOOK_LINK_PREFIX, lnk->bundleIndex);
	snprintf(session_hook, sizeof(session_hook),
	  "%s-%s", PPPOE_SESSION_HOOK, bund->name);
	if (NgFuncConnect(MPD_HOOK_PPP, linkHook, path, session_hook) < 0)
		goto fail3;

	/* Tell the PPPoE node to try to connect to a server */
	memset(idata, 0, sizeof(idata));
	snprintf(idata->hook, sizeof(idata->hook), "%s", session_hook);
	idata->data_len = strlen(pe->session);
	strncpy(idata->data, pe->session, MAX_SESSION);
	if (NgSendMsg(pe->csock, path, NGM_PPPOE_COOKIE, NGM_PPPOE_CONNECT,
	    idata, sizeof(*idata) + idata->data_len) < 0) {
		Log(LG_ERR, ("[%s] can't connect to server: %s",
		    lnk->name, strerror(errno)));
		goto fail3;
	}

	/* Set a timer to limit connection time */
	TimerInit(&pe->connectTimer, "PPPoE-connect",
	    PPPOE_CONNECT_TIMEOUT * SECONDS, PppoeConnectTimeout, pe);
	TimerStart(&pe->connectTimer);

	/* Register an event listening to the control socket */
	EventRegister(&pe->ctrlEvent, EVENT_READ, pe->csock,
	    DEV_PRIO, PppoeCtrlReadEvent, lnk);

	/* OK */
	pe->state = PPPOE_CONNECTING;
	return;

fail3:
	NgFuncShutdownNode(bund, lnk->name, path);
fail2:
	(void)close(pe->csock);
	pe->csock = -1;
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
	Log(LG_ERR, ("[%s] connection timeout after %d seconds",
	    lnk->name, PPPOE_CONNECT_TIMEOUT));
	PppoeShutdown(lnk->phys);
	PhysDown(STR_ERROR, lcats(STR_CON_FAILED0));
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
	PppoeShutdown(p);
	PhysDown(0, NULL);
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

	if (pe->state == PPPOE_DOWN)
		return;
	snprintf(path, sizeof(path), "%s%s", pe->path, pe->hook);
	NgFuncShutdownNode(bund, lnk->name, path);
	EventUnRegister(&pe->ctrlEvent);
	(void)close(pe->csock);
	pe->csock = -1;
	TimerStop(&pe->connectTimer);
	pe->state = PPPOE_DOWN;
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

	/* Register new event */
	EventRegister(&pe->ctrlEvent, EVENT_READ, pe->csock,
	    DEV_PRIO, PppoeCtrlReadEvent, lnk);

	/* Read control message */
	if (NgRecvMsg(pe->csock, &u.resp, sizeof(u), path) < 0) {
		Log(LG_ERR, ("[%s] error reading message from \"%s\": %s",
		    lnk->name, path, strerror(errno)));
		goto fail;
	}
	if (u.resp.header.typecookie != NGM_PPPOE_COOKIE) {
		Log(LG_ERR, ("[%s] rec'd cookie %lu from \"%s\"",
		    lnk->name, (u_long)u.resp.header.typecookie, path));
		return;
	}

	/* Decode message */
	switch (u.resp.header.cmd) {
	case NGM_PPPOE_SUCCESS:
		Log(LG_PHYS, ("[%s] connection successful", lnk->name));
		Disable(&lnk->conf.options, LINK_CONF_ACFCOMP);	/* RFC 2516 */
		Deny(&lnk->conf.options, LINK_CONF_ACFCOMP);	/* RFC 2516 */
		TimerStop(&pe->connectTimer);
		pe->state = PPPOE_UP;
		PhysUp();
		return;
	case NGM_PPPOE_FAIL:
	case NGM_PPPOE_CLOSE:
		Log(LG_PHYS, ("[%s] connection %s", lnk->name,
		    u.resp.header.cmd == NGM_PPPOE_FAIL ? "failed" : "closed"));
		break;
	case NGM_PPPOE_ACNAME:
		Log(LG_PHYS, ("[%s] rec'd ACNAME \"%s\"", lnk->name, 
		  ((struct ngpppoe_sts *)u.resp.data)->hook));
		return;
	default:
		Log(LG_ERR, ("[%s] rec'd command %lu from \"%s\"",
		    lnk->name, (u_long)u.resp.header.cmd, path));
		return;
	}

fail:
	/* Failure of connection */
	PppoeShutdown(lnk->phys);
	PhysDown(0, NULL);
}

/*
 * PppoeStat()
 */
void
PppoeStat(PhysInfo p)
{
	const PppoeInfo pe = (PppoeInfo)p->info;
	const char *ststr;

	printf("PPPoE configuration:\n");
	printf("\tNode    : %s\n", pe->path);
	printf("\tHook    : %s\n", pe->hook);
	printf("\tSession : %s\n", pe->session);
	printf("PPPoE status:\n");
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
	printf("\tState   : %s\n", ststr);
}

/*
 * PppoeOriginated()
 */
static int
PppoeOriginated(PhysInfo p)
{
	return LINK_ORIGINATE_LOCAL;			/* XXX */
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
			pe->ifaceUp = 0;
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
	default:
		assert(0);
	}
	return(0);
}

