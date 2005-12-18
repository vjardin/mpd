
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
#ifdef __DragonFly__
#include <netgraph/ppp/ng_ppp.h>
#else
#include <netgraph/ng_ppp.h>
#endif

/*
 * DEFINITIONS
 */

  /*
   * The "bypass" hook is used to read PPP control frames.
   * The "demand" hook is a bit hacky - in closed state it is
   * used to snoop outgoing frames, that can initiate UP event
   * on interface. In opened state "demand" hook is used to
   * snoop incoming TCP SYN segments, if userland tcpmssfix is on.
   * The "mssfix-out" hook is used for outgoing TCP SYN segments,
   * if userland tcpmssfix is on.
   */
  #define MPD_HOOK_PPP		"bypass"
  #define MPD_HOOK_DEMAND_TAP	"demand"
  #ifndef USE_NG_TCPMSS
  #define MPD_HOOK_MSSFIX_OUT	"mssfix-out"
  #endif

  #define BPF_HOOK_PPP		"ppp"
  #define BPF_HOOK_IFACE	"iface"
  #define BPF_HOOK_MPD		"mpd"
  #ifdef USE_NG_TCPMSS
  #define BPF_HOOK_TCPMSS_IN	"tcpmss-in"
  #define BPF_HOOK_TCPMSS_OUT	"tcpmss-out"
  #else
  #define BPF_HOOK_MPD_OUT	"mpd-out"
  #endif

  #define BPF_MODE_OFF		0	/* no BPF node traffic gets through */
  #define BPF_MODE_ON		1	/* normal BPF node traffic flow */
  #define BPF_MODE_DEMAND	2	/* block traffic; redirect demand */
  #define BPF_MODE_MSSFIX	3	/* redirect all TCP SYN packets */
  #define BPF_MODE_MSSFIX_IN	4	/* redirect incoming TCP SYN packets */
  #define BPF_MODE_MSSFIX_OUT	5	/* redirect outgoing TCP SYN packets */

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
  extern int	NgFuncSendQuery(const char *path, int cookie, int cmd,
			const void *args, size_t arglen, struct ng_mesg *rbuf,
			size_t replen, char *raddr);

  extern int	NgFuncConnect(const char *path, const char *hook,
			const char *path2, const char *hook2);
  extern int	NgFuncDisconnect(const char *path, const char *hook);
  extern int	NgFuncShutdownNode(Bund b, const char *label, const char *path);
  #ifdef USE_NG_TCPMSS
  extern void	NgFuncConfigTCPMSS(Bund b, uint16_t maxMSS);
  #endif

#endif

