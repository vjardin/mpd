
/*
 * ngfunc.h
 *
 * Written by Archie Cobbs <archie@freebsd.org>
 * Copyright (c) 1995-1999 Whistle Communications, Inc. All rights reserved.
 * See ``COPYRIGHT.whistle''
 */

#ifndef _NGFUNC_H_
#define _NGFUNC_H_

#include "defs.h"
#include "bund.h"

#include <netgraph/ng_message.h>
#include <netgraph/ng_ppp.h>

/*
 * DEFINITIONS
 */

  #define MPD_HOOK_PPP		"bypass"
  #define MPD_HOOK_DEMAND_TAP	"demand"

  #define BPF_HOOK_PPP		"ppp"
  #define BPF_HOOK_IFACE	"iface"
  #define BPF_HOOK_MPD		"mpd"

  #define BPF_MODE_OFF		0	/* no BPF node traffic gets through */
  #define BPF_MODE_ON		1	/* normal BPF node traffic flow */
  #define BPF_MODE_DEMAND	2	/* block traffic; redirect demand */

/*
 * FUNCTIONS
 */

  extern int	NgFuncInit(Bund b, const char *reqIface);
  extern void	NgFuncShutdown(Bund b);
  extern void	NgFuncSetConfig(void);
  extern void	NgFuncConfigBPF(Bund b, int mode);
  extern int	NgFuncWritePppFrame(int linkNum, int proto, Mbuf bp);
  extern int	NgFuncWriteFrame(const char *label, const char *hook, Mbuf bp);
  extern int	NgFuncGetStats(u_int16_t linkNum,
			int clear, struct ng_ppp_link_stat *s);

  extern int	NgFuncConnect(const char *path, const char *hook,
			const char *path2, const char *hook2);
  extern int	NgFuncDisconnect(const char *path, const char *hook);
  extern int	NgFuncShutdownNode(Bund b, const char *label, const char *path);

#endif

