
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

#ifdef __DragonFly__
#include <netgraph/socket/ng_socket.h>
#else
#include <netgraph/ng_socket.h>
#endif
#include <netgraph/ng_message.h>
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
    u_int	ok:1;			/* Netgraph nodes are setup */
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
  static void	NgStat(PhysInfo p);
  static int	NgSetCommand(int ac, char *av[], void *arg);
  static int	NgPeerAddr(PhysInfo p, void *buf, int buf_len);

/*
 * GLOBAL VARIABLES
 */

  const struct phystype gNgPhysType = {
    "ng",
    TRUE, NG_REOPEN_PAUSE,
    NG_MTU, NG_MRU,
    NgInit,
    NgOpen,
    NgClose,
    NULL,
    NULL,
    NgStat,
    NULL,
    NgPeerAddr,
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
  char		linkHook[NG_HOOKLEN + 1];

  snprintf(linkHook, sizeof(linkHook),
    "%s%d", NG_PPP_HOOK_LINK_PREFIX, lnk->bundleIndex);
  if (NgFuncConnect(MPD_HOOK_PPP, linkHook, ng->path, ng->hook) < 0)
    PhysDown(STR_CON_FAILED0, NULL);
  else
    PhysUp();
}

/*
 * NgClose()
 */

static void
NgClose(PhysInfo p)
{
  NgInfo	const ng = (NgInfo) p->info;

  NgFuncDisconnect(ng->path, ng->hook);
  PhysDown(0, NULL);
}

/*
 * NgStat()
 */

void
NgStat(PhysInfo p)
{
  NgInfo	const ng = (NgInfo) p->info;

  Printf("Netgraph node configuration:\r\n");
  Printf("\tNode : %s\r\n", ng->path);
  Printf("\tHook : %s\r\n", ng->hook);
}

/*
 * NgSetCommand()
 */

static int
NgSetCommand(int ac, char *av[], void *arg)
{
  NgInfo	const ng = (NgInfo) lnk->phys->info;

  if (lnk->phys->type != &gNgPhysType) {
    Log(LG_ERR, ("[%s] link type is not netgraph", lnk->name));
    return(0);
  }
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
  NgInfo	const ng = (NgInfo) p;

  if (buf_len < sizeof(ng->path))
    return(-1);

  memcpy(buf, ng->path, sizeof(ng->path));

  return(0);
}
