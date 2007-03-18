
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
  #define MPD_HOOK_TCPMSS_IN	"tcpmss-in"
  #define MPD_HOOK_TCPMSS_OUT	"tcpmss-out"
  #endif

  #define BPF_HOOK_PPP		"ppp"
  #define BPF_HOOK_IFACE	"iface"
  #define BPF_HOOK_MPD		"mpd"

  #define BPF_MODE_OFF		0	/* no BPF node traffic gets through */
  #define BPF_MODE_ON		1	/* normal BPF node traffic flow */
  #define BPF_MODE_DEMAND	2	/* block traffic; redirect demand */
  #define BPF_MODE_MSSFIX	3	/* redirect all TCP SYN packets */
  #define BPF_MODE_MSSFIX_IN	4	/* redirect incoming TCP SYN packets */
  #define BPF_MODE_MSSFIX_OUT	5	/* redirect outgoing TCP SYN packets */

/*
 * VARIABLES
 */

  #ifdef USE_NG_TCPMSS
  extern u_char gTcpMSSNode;
  #endif
  #ifdef USE_NG_NETFLOW
  extern const struct cmdtab NetflowSetCmds[];
  
  extern u_char gNetflowNode;
  extern u_char gNetflowNodeShutdown;
  extern u_char gNetflowNodeName[64];
  extern u_int gNetflowIface;
  extern struct sockaddr_storage gNetflowExport;
  extern struct sockaddr_storage gNetflowSource;
  extern uint32_t gNetflowInactive;
  extern uint32_t gNetflowActive;
  #endif
  
/*
 * FUNCTIONS
 */

  extern void	NgFuncShutdownGlobal(Bund b);
  extern void	NgFuncSetConfig(Bund b);
  extern int	NgFuncWritePppFrame(Bund b, int linkNum, int proto, Mbuf bp);
  extern int	NgFuncWriteFrame(Bund b, const char *hook, Mbuf bp);
  extern int	NgFuncGetStats(Bund b, u_int16_t linkNum,
			int clear, struct ng_ppp_link_stat *s);
  extern int	NgFuncSendQuery(const char *path, int cookie, int cmd,
			const void *args, size_t arglen, struct ng_mesg *rbuf,
			size_t replen, char *raddr);

  extern int	NgFuncConnect(int csock, char *label, const char *path, const char *hook,
			const char *path2, const char *hook2);
  extern int	NgFuncDisconnect(int csock, char *label, const char *path, const char *hook);
  extern int	NgFuncShutdownNode(int csock, const char *label, const char *path);

  extern void	NgFuncErrx(const char *fmt, ...);
  extern void	NgFuncErr(const char *fmt, ...);

  #ifdef USE_NG_NETFLOW
  extern int	NgFuncInitGlobalNetflow(Bund b);
  #endif
  
  extern int	NgFuncCreateIface(Bund b,
			const char *ifname, char *buf, int max);
  extern int	NgFuncIfaceExists(Bund b,
			const char *ifname, char *buf, int max);

#endif

