
/*
 * ng.c
 *
 * Written by Archie Cobbs <archie@freebsd.org>
 * Copyright (c) 1995-1999 Whistle Communications, Inc. All rights reserved.
 * See ``COPYRIGHT.whistle''
 */

#include "ppp.h"
#include "ng.h"
#include "phys.h"
#include "ngfunc.h"
#include "log.h"

#include <netgraph/ng_message.h>
#ifdef __DragonFly__
#include <netgraph/socket/ng_socket.h>
#else
#include <netgraph/ng_socket.h>
#endif
#include <netgraph.h>

/*
 * DEFINITIONS
 */

  #define NG_MTU		1600
  #define NG_MRU		1600

  #define NG_REOPEN_PAUSE	5

  #define MAX_PATH		64	/* XXX should be NG_PATHLEN */

  struct nginfo {
    char	path[MAX_PATH + 1];	/* Node that takes PPP frames */
    char	hook[NG_HOOKLEN + 1];	/* Hook on that node */
  };
  typedef struct nginfo	*NgInfo;

  /* Set menu options */
  enum {
    SET_NODE,
    SET_HOOK,
  };

/*
 * INTERNAL FUNCTIONS
 */

  static int	NgInit(PhysInfo p);
  static void	NgOpen(PhysInfo p);
  static void	NgClose(PhysInfo p);
  static void	NgStat(Context ctx);
  static int	NgSetCommand(Context ctx, int ac, char *av[], void *arg);
  static int	NgPeerAddr(PhysInfo p, void *buf, int buf_len);

/*
 * GLOBAL VARIABLES
 */

  const struct phystype gNgPhysType = {
    .name		= "ng",
    .synchronous	= TRUE,
    .minReopenDelay	= NG_REOPEN_PAUSE,
    .mtu		= NG_MTU,
    .mru		= NG_MRU,
    .init		= NgInit,
    .open		= NgOpen,
    .close		= NgClose,
    .showstat		= NgStat,
    .peeraddr		= NgPeerAddr,
    .callingnum		= NULL,
    .callednum		= NULL,
  };

  const struct cmdtab NgSetCmds[] = {
    { "node path",		"Set node to attach to",
	NgSetCommand, NULL, (void *) SET_NODE },
    { "hook hook",		"Set hook to attach to",
	NgSetCommand, NULL, (void *) SET_HOOK },
    { NULL },
  };

/*
 * NgInit()
 *
 * Initialize device-specific data in physical layer info
 */

static int
NgInit(PhysInfo p)
{
  NgInfo	ng;

  /* Allocate private struct */
  ng = (NgInfo) (p->info = Malloc(MB_PHYS, sizeof(*ng)));
  snprintf(ng->path, sizeof(ng->path), "undefined:");
  snprintf(ng->hook, sizeof(ng->hook), "undefined");

  /* Done */
  return(0);
}

/*
 * NgOpen()
 */

static void
NgOpen(PhysInfo p)
{
    NgInfo	const ng = (NgInfo) p->info;
    char	path[NG_PATHLEN + 1];
    int		csock = -1;
    struct ngm_connect	cn;

    if (!PhysGetUpperHook(p, path, cn.ourhook)) {
        Log(LG_PHYS, ("[%s] NG: can't get upper hook", p->name));
	goto fail;
    }
    
    /* Get a temporary netgraph socket node */
    if (NgMkSockNode(NULL, &csock, NULL) == -1) {
	Log(LG_ERR, ("[%s] NG: NgMkSockNode: %s", 
	    p->name, strerror(errno)));
	goto fail;
    }

    snprintf(cn.path, sizeof(cn.path), "%s", ng->path);
    snprintf(cn.peerhook, sizeof(cn.peerhook), "%s", ng->hook);
    if (NgSendMsg(csock, path, NGM_GENERIC_COOKIE, NGM_CONNECT, &cn, sizeof(cn)) < 0) {
	Log(LG_ERR, ("[%s] NG: can't connect \"%s\"->\"%s\" and \"%s\"->\"%s\": %s",
    	    p->name, path, cn.ourhook, cn.path, cn.peerhook, strerror(errno)));
	goto fail;
    }
    
    close(csock);
    p->state = PHYS_STATE_UP;
    PhysUp(p);
    return;

fail:
    if (csock>=0) {
	close(csock);
	csock = -1;
    }
    p->state = PHYS_STATE_DOWN;
    PhysDown(p, STR_CON_FAILED0, NULL);
}

/*
 * NgClose()
 */

static void
NgClose(PhysInfo p)
{
    NgInfo	const ng = (NgInfo) p->info;
    int		csock = -1;

    /* Get a temporary netgraph socket node */
    if (NgMkSockNode(NULL, &csock, NULL) == -1) {
	Log(LG_ERR, ("[%s] NG: NgMkSockNode: %s", 
	    p->name, strerror(errno)));
	goto fail;
    }

    NgFuncDisconnect(csock, p->name, ng->path, ng->hook);

    close(csock);
    /* FALL */

fail:
    p->state = PHYS_STATE_DOWN;
    PhysDown(p, 0, NULL);
}

/*
 * NgStat()
 */

void
NgStat(Context ctx)
{
  NgInfo	const ng = (NgInfo) ctx->phys->info;

  Printf("Netgraph node configuration:\r\n");
  Printf("\tNode : %s\r\n", ng->path);
  Printf("\tHook : %s\r\n", ng->hook);
}

/*
 * NgSetCommand()
 */

static int
NgSetCommand(Context ctx, int ac, char *av[], void *arg)
{
  NgInfo	const ng = (NgInfo) ctx->phys->info;

  switch ((intptr_t)arg) {
    case SET_NODE:
      if (ac != 1)
	return(-1);
      snprintf(ng->path, sizeof(ng->path), "%s", av[0]);
      break;
    case SET_HOOK:
      if (ac != 1)
	return(-1);
      snprintf(ng->hook, sizeof(ng->hook), "%s", av[0]);
      break;
    default:
      assert(0);
  }
  return(0);
}

/*
 * NgPeerAddr()
 */

static int
NgPeerAddr(PhysInfo p, void *buf, int buf_len)
{
  NgInfo	const ng = (NgInfo) p->info;

  if (buf_len < sizeof(ng->path))
    return(-1);

  memcpy(buf, ng->path, sizeof(ng->path));

  return(0);
}
