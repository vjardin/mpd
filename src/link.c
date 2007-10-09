
/*
 * link.c
 *
 * Written by Archie Cobbs <archie@freebsd.org>
 * Copyright (c) 1995-1999 Whistle Communications, Inc. All rights reserved.
 * See ``COPYRIGHT.whistle''
 */

#include "ppp.h"
#include "link.h"
#include "msg.h"
#include "lcp.h"
#include "phys.h"
#include "command.h"
#include "input.h"
#include "ngfunc.h"
#include "util.h"

#include <netgraph.h>
#include <netgraph/ng_message.h>
#ifdef __DragonFly__
#include <netgraph/socket/ng_socket.h>
#include <netgraph/tee/ng_tee.h>
#else
#include <netgraph/ng_socket.h>
#include <netgraph/ng_tee.h>
#endif

/*
 * DEFINITIONS
 */

  /* Set menu options */
  enum {
    SET_BUNDLE,
    SET_FORWARD,
    SET_BANDWIDTH,
    SET_LATENCY,
    SET_ACCMAP,
    SET_MRU,
    SET_MTU,
    SET_FSM_RETRY,
    SET_MAX_RETRY,
    SET_KEEPALIVE,
    SET_IDENT,
    SET_ACCEPT,
    SET_DENY,
    SET_ENABLE,
    SET_DISABLE,
    SET_YES,
    SET_NO,
  };

  #define RBUF_SIZE		100

/*
 * INTERNAL FUNCTIONS
 */

  static int	LinkSetCommand(Context ctx, int ac, char *av[], void *arg);
  static void	LinkMsg(int type, void *cookie);
  static void	LinkNgDataEvent(int type, void *cookie);
/*
 * GLOBAL VARIABLES
 */

  const struct cmdtab LinkSetActionCmds[] = {
    { "bundle {bundle} [{regex}]",	"Terminate incomings locally",
	LinkSetCommand, NULL, (void *) SET_BUNDLE },
    { "forward {link} [{regex}]",	"Forward incomings",
	LinkSetCommand, NULL, (void *) SET_FORWARD },
    { NULL },
  };

  const struct cmdtab LinkSetCmds[] = {
    { "action ...",			"Set action on incoming",
	CMD_SUBMENU,	NULL, (void *) LinkSetActionCmds },
    { "bandwidth {bps}",		"Link bandwidth",
	LinkSetCommand, NULL, (void *) SET_BANDWIDTH },
    { "latency {microsecs}",		"Link latency",
	LinkSetCommand, NULL, (void *) SET_LATENCY },
    { "accmap {hex-value}",		"Accmap value",
	LinkSetCommand, NULL, (void *) SET_ACCMAP },
    { "mru {value}",			"Link MRU value",
	LinkSetCommand, NULL, (void *) SET_MRU },
    { "mtu {value}",			"Link MTU value",
	LinkSetCommand, NULL, (void *) SET_MTU },
    { "fsm-timeout {seconds}",		"FSM retry timeout",
	LinkSetCommand, NULL, (void *) SET_FSM_RETRY },
    { "max-redial {num}",		"Max connect attempts",
	LinkSetCommand, NULL, (void *) SET_MAX_RETRY },
    { "keep-alive {secs} {max}",	"LCP echo keep-alives",
	LinkSetCommand, NULL, (void *) SET_KEEPALIVE },
    { "ident {string}",			"LCP ident string",
	LinkSetCommand, NULL, (void *) SET_IDENT },
    { "accept {opt ...}",		"Accept option",
	LinkSetCommand, NULL, (void *) SET_ACCEPT },
    { "deny {opt ...}",			"Deny option",
	LinkSetCommand, NULL, (void *) SET_DENY },
    { "enable {opt ...}",		"Enable option",
	LinkSetCommand, NULL, (void *) SET_ENABLE },
    { "disable {opt ...}",		"Disable option",
	LinkSetCommand, NULL, (void *) SET_DISABLE },
    { "yes {opt ...}",			"Enable and accept option",
	LinkSetCommand, NULL, (void *) SET_YES },
    { "no {opt ...}",			"Disable and deny option",
	LinkSetCommand, NULL, (void *) SET_NO },
    { NULL },
  };

/*
 * INTERNAL VARIABLES
 */

  static struct confinfo	gConfList[] = {
    { 0,	LINK_CONF_INCOMING,	"incoming"	},
    { 1,	LINK_CONF_PAP,		"pap"		},
    { 1,	LINK_CONF_CHAPMD5,	"chap-md5"	},
    { 1,	LINK_CONF_CHAPMSv1,	"chap-msv1"	},
    { 1,	LINK_CONF_CHAPMSv2,	"chap-msv2"	},
    { 1,	LINK_CONF_EAP,		"eap"		},
    { 1,	LINK_CONF_ACFCOMP,	"acfcomp"	},
    { 1,	LINK_CONF_PROTOCOMP,	"protocomp"	},
    { 0,	LINK_CONF_MSDOMAIN,	"keep-ms-domain"},
    { 0,	LINK_CONF_MAGICNUM,	"magicnum"	},
    { 0,	LINK_CONF_PASSIVE,	"passive"	},
    { 0,	LINK_CONF_CHECK_MAGIC,	"check-magic"	},
    { 0,	LINK_CONF_NO_ORIG_AUTH,	"no-orig-auth"	},
    { 0,	LINK_CONF_CALLBACK,	"callback"	},
    { 0,	LINK_CONF_MULTILINK,	"multilink"	},
    { 1,	LINK_CONF_SHORTSEQ,	"shortseq"	},
    { 0,	0,			NULL		},
  };

/*
 * LinkOpenCmd()
 */

void
LinkOpenCmd(Context ctx)
{
    if (ctx->lnk->tmpl) {
	Log(LG_ERR, ("[%s] link: impossible to open template", ctx->lnk->name));
	return;
    }
    RecordLinkUpDownReason(NULL, ctx->lnk, 1, STR_MANUALLY, NULL);
    LinkOpen(ctx->lnk);
}

/*
 * LinkCloseCmd()
 */

void
LinkCloseCmd(Context ctx)
{
    if (ctx->lnk->tmpl) {
	Log(LG_ERR, ("[%s] link: impossible to close template", ctx->lnk->name));
	return;
    }
    RecordLinkUpDownReason(NULL, ctx->lnk, 0, STR_MANUALLY, NULL);
    LinkClose(ctx->lnk);
}

/*
 * LinkOpen()
 */

void
LinkOpen(Link l)
{
    REF(l);
    MsgSend(l->msgs, MSG_OPEN, l);
}

/*
 * LinkClose()
 */

void
LinkClose(Link l)
{
    REF(l);
    MsgSend(l->msgs, MSG_CLOSE, l);
}

/*
 * LinkUp()
 */

void
LinkUp(Link l)
{
    Log(LG_LINK, ("[%s] link: UP event", l->name));

    l->originate = PhysGetOriginate(l);
    Log(LG_LINK, ("[%s] link: origination is %s",
	l->name, LINK_ORIGINATION(l->originate)));
    LcpUp(l);
}

/*
 * LinkDown()
 */

void
LinkDown(Link l)
{
    Log(LG_LINK, ("[%s] link: DOWN event", l->name));

    if (OPEN_STATE(l->lcp.fsm.state)) {
	if ((l->conf.max_redial != 0) && (l->num_redial >= l->conf.max_redial)) {
	    if (l->conf.max_redial >= 0) {
		Log(LG_LINK, ("[%s] link: giving up after %d reconnection attempts",
		  l->name, l->num_redial));
	    }
	    if (!l->stay)
		l->die = 1;
	    LcpClose(l);
            LcpDown(l);
	} else {
	    l->num_redial++;
	    Log(LG_LINK, ("[%s] link: reconnection attempt %d",
	      l->name, l->num_redial));
	    RecordLinkUpDownReason(NULL, l, 1, STR_REDIAL, NULL);
    	    LcpDown(l);
	    if (!gShutdownInProgress) {	/* Giveup on shutdown */
		PhysOpen(l);		/* Try again */
	    };
	}
    } else {
	if (!l->stay)
	    l->die = 1;
        LcpDown(l);
    }
}

/*
 * LinkMsg()
 *
 * Deal with incoming message to this link
 */

static void
LinkMsg(int type, void *arg)
{
    Link	l = (Link)arg;

    if (l->dead) {
	UNREF(l);
	return;
    }
    Log(LG_LINK, ("[%s] link: %s event", l->name, MsgName(type)));
    switch (type) {
	case MSG_OPEN:
    	    l->last_open = time(NULL);
    	    l->num_redial = 0;
    	    LcpOpen(l);
    	    break;
	case MSG_CLOSE:
    	    LcpClose(l);
    	    break;
	case MSG_SHUTDOWN:
    	    LinkShutdown(l);
    	    break;
	default:
    	    assert(FALSE);
    }
    UNREF(l);
}

/*
 * LinkCreate()
 */

int
LinkCreate(Context ctx, int ac, char *av[], void *arg)
{
    Link 	l, lt = NULL;
    PhysType    pt = NULL;
    int 	tmpl = 0;
    int 	stay = 0;
    int 	k;

    RESETREF(ctx->lnk, NULL);
    RESETREF(ctx->bund, NULL);
    RESETREF(ctx->rep, NULL);

    if (ac < 1)
	return(-1);

    if (strcmp(av[0], "template") == 0) {
	tmpl = 1;
	stay = 1;
    } else if (strcmp(av[0], "static") == 0)
	stay = 1;

    if (ac - stay < 1 || ac - stay > 2)
	return(-1);

    if (strlen(av[0 + stay])>16) {
	Log(LG_ERR, ("Link name \"%s\" is too long", av[0 + stay]));
	return(0);
    }

    /* See if link name already taken */
    if ((l = LinkFind(av[0 + stay])) != NULL) {
	Log(LG_ERR, ("Link \"%s\" already exists", av[0 + stay]));
	return (0);
    }

    for (k = 0; (pt = gPhysTypes[k]); k++) {
        if (!strcmp(pt->name, av[0 + stay])) {
	    Log(LG_ERR, ("Name \"%s\" is reserved by device type", av[0 + stay]));
	    return (0);
	}
    }

    if (ac - stay == 2) {
	/* Locate type */
	for (k = 0; (pt = gPhysTypes[k]); k++) {
	    if (!strcmp(pt->name, av[1 + stay]))
    		break;
	}
	if (pt != NULL) {
	    if (!pt->tmpl && tmpl) {
		Log(LG_ERR, ("Link type \"%s\" does not support templating", av[1 + stay]));
		return (0);
	    }

	} else {
	    /* See if template name specified */
	    if ((lt = LinkFind(av[1 + stay])) == NULL) {
		Log(LG_ERR, ("Link template \"%s\" not found", av[2 + tmpl]));
		return (0);
	    }
	    if (!lt->tmpl) {
		Log(LG_ERR, ("Link \"%s\" is not a template", av[2 + stay]));
		return (0);
	    }
	}
    }

    /* Create and initialize new link */
    if (lt) {
	l = LinkInst(lt, av[0 + stay], tmpl, stay);
    } else {
	l = Malloc(MB_LINK, sizeof(*l));
	snprintf(l->name, sizeof(l->name), "%s", av[0 + stay]);
	l->type = pt;
	l->tmpl = tmpl;
	l->stay = stay;
	l->csock = -1;
	l->dsock = -1;
	SLIST_INIT(&l->actions);

	/* Initialize link configuration with defaults */
	l->conf.mru = LCP_DEFAULT_MRU;
        l->conf.mtu = LCP_DEFAULT_MRU;
	l->conf.mrru = MP_DEFAULT_MRRU;
        l->conf.accmap = 0x000a0000;
        l->conf.max_redial = -1;
        l->conf.retry_timeout = LINK_DEFAULT_RETRY;
        l->bandwidth = LINK_DEFAULT_BANDWIDTH;
        l->latency = LINK_DEFAULT_LATENCY;
        l->upReason = NULL;
        l->upReasonValid = 0;
        l->downReason = NULL;
        l->downReasonValid = 0;

        Disable(&l->conf.options, LINK_CONF_CHAPMD5);
        Accept(&l->conf.options, LINK_CONF_CHAPMD5);

        Disable(&l->conf.options, LINK_CONF_CHAPMSv1);
        Deny(&l->conf.options, LINK_CONF_CHAPMSv1);

        Disable(&l->conf.options, LINK_CONF_CHAPMSv2);
        Accept(&l->conf.options, LINK_CONF_CHAPMSv2);

        Disable(&l->conf.options, LINK_CONF_PAP);
	Accept(&l->conf.options, LINK_CONF_PAP);

        Disable(&l->conf.options, LINK_CONF_EAP);
        Accept(&l->conf.options, LINK_CONF_EAP);

        Disable(&l->conf.options, LINK_CONF_MSDOMAIN);

        Enable(&l->conf.options, LINK_CONF_ACFCOMP);
        Accept(&l->conf.options, LINK_CONF_ACFCOMP);

        Enable(&l->conf.options, LINK_CONF_PROTOCOMP);
        Accept(&l->conf.options, LINK_CONF_PROTOCOMP);

        Enable(&l->conf.options, LINK_CONF_MAGICNUM);
        Disable(&l->conf.options, LINK_CONF_PASSIVE);
        Enable(&l->conf.options, LINK_CONF_CHECK_MAGIC);

	Disable(&l->conf.options, LINK_CONF_MULTILINK);
	Enable(&l->conf.options, LINK_CONF_SHORTSEQ);
	Accept(&l->conf.options, LINK_CONF_SHORTSEQ);

        PhysInit(l);
        LcpInit(l);
        EapInit(l);
	
	if (!tmpl)
	    l->msgs = MsgRegister(LinkMsg);

	/* Find a free link pointer */
        for (k = 0; k < gNumLinks && gLinks[k] != NULL; k++);
        if (k == gNumLinks)			/* add a new link pointer */
    	    LengthenArray(&gLinks, sizeof(*gLinks), &gNumLinks, MB_LINK);
	    
	l->id = k;
	gLinks[k] = l;
	REF(l);
    }

    RESETREF(ctx->lnk, l);

    return (0);
}

/*
 * LinkDestroy()
 */

int
LinkDestroy(Context ctx, int ac, char *av[], void *arg)
{
    Link 	l;

    if (ac > 1)
	return(-1);

    if (ac == 1) {
	if ((l = LinkFind(av[0])) == NULL) {
	    Log(LG_ERR, ("Link \"%s\" not found", av[0]));
	    return (0);
	}
    } else {
	if (ctx->lnk) {
	    l = ctx->lnk;
	} else {
	    Log(LG_ERR, ("No link selected to destroy"));
	    return (0);
	}
    }
    
    if (l->tmpl) {
	l->tmpl = 0;
	l->stay = 0;
	LinkShutdown(l);
    } else {
	l->stay = 0;
	if (l->rep) {
	    PhysClose(l);
	} else if (l->lcp.fsm.state != ST_INITIAL) {
	    LcpClose(l);
	} else {
	    LinkShutdown(l);
	}
    }

    return (0);
}

/*
 * LinkInst()
 */

Link
LinkInst(Link lt, char *name, int tmpl, int stay)
{
    Link 	l;
    int		k;
    struct linkaction	*a, *ap, *at;

    /* Create and initialize new link */
    l = Mdup(MB_LINK, lt, sizeof(*l));
    
    ap = NULL;
    SLIST_INIT(&l->actions);
    SLIST_FOREACH(at, &lt->actions, next) {
	a = Mdup(MB_AUTH, at, sizeof(*a));
	regcomp(&a->regexp, a->regex, REG_EXTENDED);
	if (!ap)
	    SLIST_INSERT_HEAD(&l->actions, a, next);
	else
	    SLIST_INSERT_AFTER(ap, a, next);
	ap = a;
    }
    if (!tmpl)
	l->msgs = MsgRegister(LinkMsg);
    l->tmpl = tmpl;
    l->stay = stay;
    l->refs = 0;

    /* Find a free link pointer */
    for (k = 0; k < gNumLinks && gLinks[k] != NULL; k++);
    if (k == gNumLinks)			/* add a new link pointer */
	LengthenArray(&gLinks, sizeof(*gLinks), &gNumLinks, MB_LINK);

    l->id = k;

    if (name)
	strlcpy(l->name, name, sizeof(l->name));
    else
	snprintf(l->name, sizeof(l->name), "%s-%d", lt->name, k);
    gLinks[k] = l;
    REF(l);

    PhysInst(l, lt);
    LcpInst(l, lt);

    return (l);
}

/*
 * LinkShutdown()
 *
 */

void
LinkShutdown(Link l)
{
    struct linkaction	*a;

    /* Late divorce for DoD case */
    if (l->bund) {
	l->bund->links[l->bundleIndex] = NULL;
	l->bund->n_links--;
	l->bund = NULL;
    }
    gLinks[l->id] = NULL;
    MsgUnRegister(&l->msgs);
    if (l->csock >= 0)
	LinkNgShutdown(l, 1);
    PhysShutdown(l);
    l->dead = 1;
    while ((a = SLIST_FIRST(&l->actions)) != NULL) {
	SLIST_REMOVE_HEAD(&l->actions, next);
	if (a->regex[0])
	    regfree(&a->regexp);
	Freee(MB_LINK, a);
    }
    if (l->upReason)
	Freee(MB_LINK, l->upReason);
    if (l->downReason)
	Freee(MB_LINK, l->downReason);
    UNREF(l);
}

/*
 * LinkNgInit()
 *
 * Setup the initial link framework. Initializes these fields
 * in the supplied bundle structure:
 *
 *	csock		- Control socket for socket netgraph node
 *	dsock		- Data socket for socket netgraph node
 *
 * Returns -1 if error.
 */

int
LinkNgInit(Link l)
{
  union {
      u_char		buf[sizeof(struct ng_mesg) + sizeof(struct nodeinfo)];
      struct ng_mesg	reply;
  }			u;
  struct nodeinfo	*const ni = (struct nodeinfo *)(void *)u.reply.data;
  struct ngm_mkpeer	mp;
  struct ngm_name	nm;
  int			newTee = 0;

  /* Create a netgraph socket node */
  if (NgMkSockNode(NULL, &l->csock, &l->dsock) < 0) {
    Log(LG_ERR, ("[%s] can't create %s node: %s",
      l->name, NG_SOCKET_NODE_TYPE, strerror(errno)));
    return(-1);
  }
  (void) fcntl(l->csock, F_SETFD, 1);
  (void) fcntl(l->dsock, F_SETFD, 1);

  /* Give it a name */
  snprintf(nm.name, sizeof(nm.name), "mpd%d-%s-lso", gPid, l->name);
  if (NgSendMsg(l->csock, ".",
      NGM_GENERIC_COOKIE, NGM_NAME, &nm, sizeof(nm)) < 0) {
    Log(LG_ERR, ("[%s] can't name %s node: %s",
      l->name, NG_SOCKET_NODE_TYPE, strerror(errno)));
    goto fail;
  }

  /* Create TEE node */
  snprintf(mp.type, sizeof(mp.type), "%s", NG_TEE_NODE_TYPE);
  snprintf(mp.ourhook, sizeof(mp.ourhook), "%s", MPD_HOOK_PPP);
  snprintf(mp.peerhook, sizeof(mp.peerhook), "%s", NG_TEE_HOOK_LEFT2RIGHT);
  if (NgSendMsg(l->csock, ".",
      NGM_GENERIC_COOKIE, NGM_MKPEER, &mp, sizeof(mp)) < 0) {
    Log(LG_ERR, ("[%s] can't create %s node at \"%s\"->\"%s\": %s",
      l->name, mp.type, ".", mp.ourhook, strerror(errno)));
    goto fail;
  }
  newTee = 1;

  /* Give it a name */
  snprintf(nm.name, sizeof(nm.name), "mpd%d-%s-lt", gPid, l->name);
  if (NgSendMsg(l->csock, MPD_HOOK_PPP,
      NGM_GENERIC_COOKIE, NGM_NAME, &nm, sizeof(nm)) < 0) {
    Log(LG_ERR, ("[%s] can't name %s node \"%s\": %s",
      l->name, NG_PPP_NODE_TYPE, MPD_HOOK_PPP, strerror(errno)));
    goto fail;
  }

  /* Get PPP node ID */
  if (NgSendMsg(l->csock, MPD_HOOK_PPP,
      NGM_GENERIC_COOKIE, NGM_NODEINFO, NULL, 0) < 0) {
    Log(LG_ERR, ("[%s] ppp nodeinfo: %s", l->name, strerror(errno)));
    goto fail;
  }
  if (NgRecvMsg(l->csock, &u.reply, sizeof(u), NULL) < 0) {
    Log(LG_ERR, ("[%s] node \"%s\" reply: %s",
      l->name, MPD_HOOK_PPP, strerror(errno)));
    goto fail;
  }
  l->nodeID = ni->id;

  /* Listen for happenings on our node */
  EventRegister(&l->dataEvent, EVENT_READ,
    l->dsock, EVENT_RECURRING, LinkNgDataEvent, l);
  /* Control events used only by CCP so Register events there */

  /* OK */
  return(0);

fail:
  LinkNgShutdown(l, newTee);
  return(-1);
}

/*
 * LinkNgJoin()
 */

int
LinkNgJoin(Link l)
{
    char		path[NG_PATHSIZ];
    struct ngm_connect	cn;

    snprintf(path, sizeof(path), "[%lx]:", (u_long)l->nodeID);

    snprintf(cn.path, sizeof(cn.path), "[%lx]:", (u_long)l->bund->nodeID);
    snprintf(cn.ourhook, sizeof(cn.ourhook), "%s", NG_TEE_HOOK_RIGHT);
    snprintf(cn.peerhook, sizeof(cn.peerhook), "%s%d", 
	NG_PPP_HOOK_LINK_PREFIX, l->bundleIndex);
    if (NgSendMsg(l->csock, path,
      NGM_GENERIC_COOKIE, NGM_CONNECT, &cn, sizeof(cn)) < 0) {
	Log(LG_ERR, ("[%s] can't connect \"%s\"->\"%s\" and \"%s\"->\"%s\": %s",
    	    l->name, path, cn.ourhook, cn.path, cn.peerhook, strerror(errno)));
	return(-1);
    }
    
    NgFuncDisconnect(l->csock, l->name, path, NG_TEE_HOOK_LEFT2RIGHT);
    return (0);
}

/*
 * LinkNgLeave()
 */

int
LinkNgLeave(Link l)
{
    char		path[NG_PATHSIZ];
    struct ngm_connect	cn;

    snprintf(cn.path, sizeof(cn.path), "[%lx]:", (u_long)l->nodeID);
    snprintf(cn.ourhook, sizeof(cn.ourhook), "%s", MPD_HOOK_PPP);
    snprintf(cn.peerhook, sizeof(cn.peerhook), "%s", NG_TEE_HOOK_LEFT2RIGHT);
    if (NgSendMsg(l->csock, ".",
      NGM_GENERIC_COOKIE, NGM_CONNECT, &cn, sizeof(cn)) < 0) {
	Log(LG_ERR, ("[%s] can't connect \"%s\"->\"%s\" and \"%s\"->\"%s\": %s",
    	    l->name, ".", cn.ourhook, cn.path, cn.peerhook, strerror(errno)));
	return(-1);
    }

    snprintf(path, sizeof(path), "[%lx]:", (u_long)l->nodeID);
    NgFuncDisconnect(l->csock, l->name, path, NG_TEE_HOOK_RIGHT);
    return (0);
}

/*
 * LinkNgToRep()
 */

int
LinkNgToRep(Link l)
{
    char		path[NG_PATHSIZ];
    struct ngm_connect	cn;

    /* Connect link to repeater */
    snprintf(path, sizeof(path), "[%lx]:", (u_long)l->nodeID);
    snprintf(cn.ourhook, sizeof(cn.ourhook), "%s", NG_TEE_HOOK_RIGHT);
    if (!PhysGetUpperHook(l, cn.path, cn.peerhook)) {
        Log(LG_PHYS, ("[%s] Link: can't get repeater hook", l->name));
        return (-1);
    }
    if (NgSendMsg(l->csock, path,
      NGM_GENERIC_COOKIE, NGM_CONNECT, &cn, sizeof(cn)) < 0) {
	Log(LG_ERR, ("[%s] can't connect \"%s\"->\"%s\" and \"%s\"->\"%s\": %s",
    	    l->name, path, cn.ourhook, cn.path, cn.peerhook, strerror(errno)));
	return(-1);
    }

    /* Shutdown link tee node */
    NgFuncShutdownNode(l->csock, l->name, path);

    close(l->csock);
    l->csock = -1;
    EventUnRegister(&l->dataEvent);
    close(l->dsock);
    l->dsock = -1;
    return (0);
}

/*
 * LinkNgShutdown()
 */

void
LinkNgShutdown(Link l, int tee)
{
    if (tee)
	NgFuncShutdownNode(l->csock, l->name, MPD_HOOK_PPP);
    close(l->csock);
    l->csock = -1;
    EventUnRegister(&l->dataEvent);
    close(l->dsock);
    l->dsock = -1;
}

/*
 * LinkNgDataEvent()
 */

static void
LinkNgDataEvent(int type, void *cookie)
{
    Link		l = (Link)cookie;
    u_char		buf[8192];
    int			nread;
    u_int16_t		proto;
    int			ptr;

    /* Read data */
    if ((nread = recv(l->dsock, buf, sizeof(buf), 0)) < 0) {
	if (errno == EAGAIN)
    	    return;
	Log(LG_LINK, ("[%s] socket read: %s", l->name, strerror(errno)));
	LinkClose(l);
	return;
    }

    /* Extract protocol */
    ptr = 0;
    if ((buf[0] == 0xff) && (buf[1] == 0x03))
	ptr = 2;
    proto = buf[ptr++];
    if ((proto & 0x01) == 0)
	proto = (proto << 8) + buf[ptr++];

    /* Debugging */
    LogDumpBuf(LG_FRAME, buf, nread,
      "[%s] rec'd frame from link proto=0x%04x",
      l->name, proto);

    /* Input frame */
    InputFrame(l->bund, l, proto,
      mbufise(MB_FRAME_IN, buf + ptr, nread - ptr));
}

/*
 * LinkFind()
 *
 * Find a link structure
 */

Link
LinkFind(char *name)
{
    int		k;

    k = gNumLinks;
    if ((sscanf(name, "[%x]", &k) != 1) || (k < 0) || (k >= gNumLinks)) {
        /* Find link */
	for (k = 0;
	    k < gNumLinks && (gLinks[k] == NULL ||
		strcmp(gLinks[k]->name, name));
	    k++);
    };
    if (k == gNumLinks) {
	return (NULL);
    }

    return (gLinks[k]);
}

/*
 * LinkCommand()
 */

int
LinkCommand(Context ctx, int ac, char *av[], void *arg)
{
    Link	l;
    int		k;

    switch (ac) {
    case 0:

        Printf("Defined links:\r\n");

        for (k = 0; k < gNumLinks; k++) {
	    if ((l = gLinks[k]) != NULL) {
		if (l && l->bund)
		    Printf("\t\"%s\" (%s%s) -> bundle \"%s\"\r\n", 
			l->name, l->type->name, l->tmpl?", template":(l->stay?", static":""), l->bund->name);
		else if (l->rep)
		    Printf("\t\"%s\" (%s%s) -> repeater \"%s\"\r\n",
			 l->name, l->type->name, l->tmpl?", template":(l->stay?", static":""), l->rep->name);
		else
		    Printf("\t\"%s\" (%s%s)\r\n", 
			l->name, l->type->name, l->tmpl?", template":(l->stay?", static":""));
	    }
	}
      break;

    case 1:
        if ((l = LinkFind(av[0])) == NULL) {
    	    Printf("Link \"%s\" is not defined\r\n", av[0]);
	    RESETREF(ctx->lnk, NULL);
	    RESETREF(ctx->bund, NULL);
	    RESETREF(ctx->rep, NULL);
	    return(0);
	}

	/* Change default link and bundle */
	RESETREF(ctx->lnk, l);
	RESETREF(ctx->bund, l->bund);
	RESETREF(ctx->rep, NULL);
	break;
    default:
	return (-1);
    }
    return(0);
}

/*
 * SessionCommand()
 */

int
SessionCommand(Context ctx, int ac, char *av[], void *arg)
{
    int		k;

    if (ac != 1)
	return(-1);

    /* Find link */
    for (k = 0;
	k < gNumLinks && (gLinks[k] == NULL || 
	    strcmp(gLinks[k]->session_id, av[0]));
	k++);
    if (k == gNumLinks) {
	Printf("Session \"%s\" is not found\r\n", av[0]);
	/* Change default link and bundle */
	RESETREF(ctx->lnk, NULL);
	RESETREF(ctx->bund, NULL);
	RESETREF(ctx->rep, NULL);
    } else {
	/* Change default link and bundle */
	RESETREF(ctx->lnk, gLinks[k]);
	RESETREF(ctx->bund, ctx->lnk->bund);
	RESETREF(ctx->rep, NULL);
    }

    return(0);
}

/*
 * RecordLinkUpDownReason()
 *
 * This is called whenever a reason for the link going up or
 * down has just become known. Record this reason so that when
 * the link actually goes up or down, we can record it.
 *
 * If this gets called more than once in the "down" case,
 * the first call prevails.
 */
static void
RecordLinkUpDownReason2(Link l, int up, const char *key, const char *fmt, va_list args)
{
  char	**const cpp = up ? &l->upReason : &l->downReason;
  char	*buf;

  /* First reason overrides later ones */
  if (up) {
    if (l->upReasonValid) {
	return;
    } else {
	l->upReasonValid = 1;
    }
  } else {
    if (l->downReasonValid) {
	return;
    } else {
	l->downReasonValid = 1;
    }
  }

  /* Allocate buffer if necessary */
  if (!*cpp)
    *cpp = Malloc(MB_UTIL, RBUF_SIZE);
  buf = *cpp;

  /* Record reason */
  if (fmt) {
    snprintf(buf, RBUF_SIZE, "%s:", key);
    vsnprintf(buf + strlen(buf), RBUF_SIZE - strlen(buf), fmt, args);
  } else 
    snprintf(buf, RBUF_SIZE, "%s", key);
}

void
RecordLinkUpDownReason(Bund b, Link l, int up, const char *key, const char *fmt, ...)
{
  va_list	args;
  int		k;

  if (l != NULL) {
    va_start(args, fmt);
    RecordLinkUpDownReason2(l, up, key, fmt, args);
    va_end(args);

  } else if (b != NULL) {
    for (k = 0; k < NG_PPP_MAX_LINKS; k++) {
      if (b->links[k]) {
	va_start(args, fmt);
	RecordLinkUpDownReason2(b->links[k], up, key, fmt, args);
	va_end(args);
      }
    }
  }

}

char *
LinkMatchAction(Link l, int stage, char *login)
{
    struct linkaction *a;

    a = SLIST_FIRST(&l->actions);
    if (!a) {
	Log(LG_LINK, ("[%s] No link actions defined", l->name));
	return (NULL);
    }
    if (stage == 1) {
	if (SLIST_NEXT(a, next) == NULL &&
	  a->action == LINK_ACTION_FORWARD && !a->regex[0]) {
	    Log(LG_LINK, ("[%s] Matched link action 'forward \"%s\"'",
		l->name, a->arg));
	    return (a->arg);
	}
	return (NULL);
    }
    SLIST_FOREACH(a, &l->actions, next) {
	if (!a->regex[0] || !regexec(&a->regexp, login, 0, NULL, 0))
	    break;
    }
    if (a) {
	if ((stage == 2 && a->action == LINK_ACTION_FORWARD) ||
	    (stage == 3 && a->action == LINK_ACTION_BUNDLE)) {
	    Log(LG_LINK, ("[%s] Matched link action '%s \"%s\" \"%s\"'",
		l->name, (a->action == LINK_ACTION_FORWARD)?"forward":"bundle",
		a->arg, a->regex));
	    return (a->arg);
	}
    }
    return (NULL);
}

/*
 * LinkStat()
 */

int
LinkStat(Context ctx, int ac, char *av[], void *arg)
{
    Link 	l = ctx->lnk;
    struct linkaction *a;

  Printf("Link %s%s:\r\n", l->name, l->tmpl?" (template)":(l->stay?" (static)":""));

  Printf("Configuration\r\n");
  Printf("\tMRU            : %d bytes\r\n", l->conf.mru);
  Printf("\tMRRU           : %d bytes\r\n", l->conf.mrru);
  Printf("\tCtrl char map  : 0x%08x bytes\r\n", l->conf.accmap);
  Printf("\tRetry timeout  : %d seconds\r\n", l->conf.retry_timeout);
  Printf("\tMax redial     : ");
  if (l->conf.max_redial < 0)
    Printf("no redial\r\n");
  else if (l->conf.max_redial == 0) 
    Printf("unlimited\r\n");
  else
    Printf("%d connect attempts\r\n", l->conf.max_redial);
  Printf("\tBandwidth      : %d bits/sec\r\n", l->bandwidth);
  Printf("\tLatency        : %d usec\r\n", l->latency);
  Printf("\tKeep-alive     : ");
  if (l->lcp.fsm.conf.echo_int == 0)
    Printf("disabled\r\n");
  else
    Printf("every %d secs, timeout %d\r\n",
      l->lcp.fsm.conf.echo_int, l->lcp.fsm.conf.echo_max);
  Printf("\tIdent string   : \"%s\"\r\n", l->conf.ident ? l->conf.ident : "");
  Printf("\tSession-Id     : %s\r\n", l->session_id);
    Printf("Link incoming actions:\r\n");
    SLIST_FOREACH(a, &l->actions, next) {
	Printf("\t%s\t%s\t%s\r\n", 
	    (a->action == LINK_ACTION_FORWARD)?"Forward":"Bundle",
	    a->arg, a->regex);
    }
  Printf("Link level options\r\n");
  OptStat(ctx, &l->conf.options, gConfList);

    if (!l->tmpl) {
	Printf("Up/Down stats:\r\n");
	if (l->downReason && (!l->downReasonValid))
	    Printf("\tDown Reason    : %s\r\n", l->downReason);
	if (l->upReason)
	    Printf("\tUp Reason      : %s\r\n", l->upReason);
	if (l->downReason && l->downReasonValid)
	    Printf("\tDown Reason    : %s\r\n", l->downReason);
  
	if (l->bund) {
	    LinkUpdateStats(l);
	    Printf("Traffic stats:\r\n");

	    Printf("\tOctets input   : %llu\r\n", (unsigned long long)l->stats.recvOctets);
	    Printf("\tFrames input   : %llu\r\n", (unsigned long long)l->stats.recvFrames);
	    Printf("\tOctets output  : %llu\r\n", (unsigned long long)l->stats.xmitOctets);
	    Printf("\tFrames output  : %llu\r\n", (unsigned long long)l->stats.xmitFrames);
	    Printf("\tBad protocols  : %llu\r\n", (unsigned long long)l->stats.badProtos);
	    Printf("\tRunts          : %llu\r\n", (unsigned long long)l->stats.runts);
	    Printf("\tDup fragments  : %llu\r\n", (unsigned long long)l->stats.dupFragments);
	    Printf("\tDrop fragments : %llu\r\n", (unsigned long long)l->stats.dropFragments);
	}
    }
    return(0);
}

/* 
 * LinkUpdateStats()
 */

void
LinkUpdateStats(Link l)
{
#ifndef NG_PPP_STATS64
  struct ng_ppp_link_stat	stats;

  if (NgFuncGetStats(l->bund, l->bundleIndex, &stats) != -1) {
    l->stats.xmitFrames += abs(stats.xmitFrames - l->oldStats.xmitFrames);
    l->stats.xmitOctets += abs(stats.xmitOctets - l->oldStats.xmitOctets);
    l->stats.recvFrames += abs(stats.recvFrames - l->oldStats.recvFrames);
    l->stats.recvOctets += abs(stats.recvOctets - l->oldStats.recvOctets);
    l->stats.badProtos  += abs(stats.badProtos - l->oldStats.badProtos);
    l->stats.runts	  += abs(stats.runts - l->oldStats.runts);
    l->stats.dupFragments += abs(stats.dupFragments - l->oldStats.dupFragments);
    l->stats.dropFragments += abs(stats.dropFragments - l->oldStats.dropFragments);
  }

  l->oldStats = stats;
#else
    NgFuncGetStats64(l->bund, l->bundleIndex, &l->stats);
#endif
}

/*
 * LinkResetStats()
 */

void
LinkResetStats(Link l)
{
    if (l->bund)
	NgFuncClrStats(l->bund, l->bundleIndex);
    memset(&l->stats, 0, sizeof(l->stats));
#ifndef NG_PPP_STATS64
    memset(&l->oldStats, 0, sizeof(l->oldStats));
#endif
}

/*
 * LinkSetCommand()
 */

static int
LinkSetCommand(Context ctx, int ac, char *av[], void *arg)
{
    Link	l = ctx->lnk;
  int		val, nac = 0;
  const char	*name;
  char		*nav[ac];
  const char	*av2[] = { "chap-md5", "chap-msv1", "chap-msv2" };

  if (ac == 0)
    return(-1);

  /* make "chap" as an alias for all chap-variants, this should keep BC */
  switch ((intptr_t)arg) {
    case SET_ACCEPT:
    case SET_DENY:
    case SET_ENABLE:
    case SET_DISABLE:
    case SET_YES:
    case SET_NO:
    {
      int	i = 0;
      for ( ; i < ac; i++)
      {
	if (strcasecmp(av[i], "chap") == 0) {
	  LinkSetCommand(ctx, 3, (char **)av2, arg);
	} else {
	  nav[nac++] = av[i];
	} 
      }
      av = nav;
      ac = nac;
      break;
    }
  }

  switch ((intptr_t)arg) {
    case SET_BANDWIDTH:
      val = atoi(*av);
      if (val <= 0)
	Log(LG_ERR, ("[%s] Bandwidth must be positive", l->name));
      else if (val > NG_PPP_MAX_BANDWIDTH * 10 * 8) {
	l->bandwidth = NG_PPP_MAX_BANDWIDTH * 10 * 8;
	Log(LG_ERR, ("[%s] Bandwidth truncated to %d bit/s", l->name, 
	    l->bandwidth));
      } else
	l->bandwidth = val;
      break;

    case SET_LATENCY:
      val = atoi(*av);
      if (val < 0)
	Log(LG_ERR, ("[%s] Latency must be not negative", l->name));
      else if (val > NG_PPP_MAX_LATENCY * 1000) {
	Log(LG_ERR, ("[%s] Latency truncated to %d usec", l->name, 
	    NG_PPP_MAX_LATENCY * 1000));
	l->latency = NG_PPP_MAX_LATENCY * 1000;
      } else
        l->latency = val;
      break;

    case SET_BUNDLE:
    case SET_FORWARD:
	{
	    struct linkaction	*n, *a;
	    
	    if (ac < 1 || ac > 2)
		return(-1);

	    n = Malloc(MB_LINK, sizeof(struct linkaction));
	    n->action = ((intptr_t)arg == SET_BUNDLE)?
		LINK_ACTION_BUNDLE:LINK_ACTION_FORWARD;
	    strlcpy(n->arg, av[0], sizeof(n->arg));
	    if (ac == 2 && av[1][0]) {
		strlcpy(n->regex, av[1], sizeof(n->regex));
		if (regcomp(&n->regexp, n->regex, REG_EXTENDED)) {
		    Log(LG_ERR, ("[%s] regexp \"%s\" compilation error", l->name, n->regex));
		    Freee(MB_LINK, n);
		    return (0);
		}
	    }
	    
	    a = SLIST_FIRST(&ctx->lnk->actions);
	    if (a) {
		while (SLIST_NEXT(a, next))
		    a = SLIST_NEXT(a, next);
		SLIST_INSERT_AFTER(a, n, next);
	    } else {
		SLIST_INSERT_HEAD(&ctx->lnk->actions, n, next);
	    }
	}
        break;

    case SET_MRU:
    case SET_MTU:
      val = atoi(*av);
      name = ((intptr_t)arg == SET_MTU) ? "MTU" : "MRU";
      if (!l->type)
	Log(LG_ERR, ("[%s] this link has no type set", l->name));
      else if (val < LCP_MIN_MRU)
	Log(LG_ERR, ("[%s] the min %s is %d", l->name, name, LCP_MIN_MRU));
      else if (l->type && (val > l->type->mru))
	Log(LG_ERR, ("[%s] the max %s on type \"%s\" links is %d",
	  l->name, name, l->type->name, l->type->mru));
      else if ((intptr_t)arg == SET_MTU)
	l->conf.mtu = val;
      else
	l->conf.mru = val;
      break;

    case SET_FSM_RETRY:
      l->conf.retry_timeout = atoi(*av);
      if (l->conf.retry_timeout < 1 || l->conf.retry_timeout > 10)
	l->conf.retry_timeout = LINK_DEFAULT_RETRY;
      break;

    case SET_MAX_RETRY:
      l->conf.max_redial = atoi(*av);
      break;

    case SET_ACCMAP:
      sscanf(*av, "%x", &val);
      l->conf.accmap = val;
      break;

    case SET_KEEPALIVE:
      if (ac != 2)
	return(-1);
      l->lcp.fsm.conf.echo_int = atoi(av[0]);
      l->lcp.fsm.conf.echo_max = atoi(av[1]);
      break;

    case SET_IDENT:
      if (ac != 1)
	return(-1);
      if (l->conf.ident != NULL) {
	Freee(MB_FSM, l->conf.ident);
	l->conf.ident = NULL;
      }
      if (*av[0] != '\0')
	strcpy(l->conf.ident = Malloc(MB_FSM, strlen(av[0]) + 1), av[0]);
      break;

    case SET_ACCEPT:
        AcceptCommand(ac, av, &l->conf.options, gConfList);
	if (ctx->lnk->type->update) {
	    (ctx->lnk->type->update)(ctx->lnk);
	}
        break;

    case SET_DENY:
        DenyCommand(ac, av, &l->conf.options, gConfList);
	if (ctx->lnk->type->update) {
	    (ctx->lnk->type->update)(ctx->lnk);
	}
        break;

    case SET_ENABLE:
        EnableCommand(ac, av, &l->conf.options, gConfList);
	if (ctx->lnk->type->update) {
	    (ctx->lnk->type->update)(ctx->lnk);
	}
        break;

    case SET_DISABLE:
        DisableCommand(ac, av, &l->conf.options, gConfList);
	if (ctx->lnk->type->update) {
	    (ctx->lnk->type->update)(ctx->lnk);
	}
        break;

    case SET_YES:
        YesCommand(ac, av, &l->conf.options, gConfList);
	if (ctx->lnk->type->update) {
	    (ctx->lnk->type->update)(ctx->lnk);
	}
        break;

    case SET_NO:
        NoCommand(ac, av, &l->conf.options, gConfList);
	if (ctx->lnk->type->update) {
	    (ctx->lnk->type->update)(ctx->lnk);
	}
        break;

    default:
      assert(0);
  }

  return(0);
}

