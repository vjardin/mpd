
/*
 * defs.h
 *
 * Written by Archie Cobbs <archie@freebsd.org>
 * Copyright (c) 1995-1999 Whistle Communications, Inc. All rights reserved.
 * See ``COPYRIGHT.whistle''
 */

#ifndef _DEFS_H_
#define _DEFS_H_

#include <sys/types.h>
#include <sysexits.h>

/*
 * DEFINITIONS
 */

  /* Boolean */
#ifndef TRUE
  #define TRUE 			1
#endif
#ifndef FALSE
  #define FALSE 		0
#endif

  /* Exit codes */
  #define EX_NORMAL		EX_OK
  #define EX_ERRDEAD		EX_SOFTWARE
  #define EX_TERMINATE		99	/* pseudo-code */

  /* Event priorities */
  #define CONSOLE_PRIO		100	/* Console I/O */
  #define BUND_PRIO		50	/* Bundle events */
  #define LINK_PRIO		40	/* Link events */
  #define PHYS_PRIO		30	/* Device events */
  #define TIMER_PRIO		20	/* Misc. timers */
  #define DEV_PRIO		10	/* Device I/O */

  /* Pathnames */
  #define CONF_FILE 		"mpd.conf"
  #define SECRET_FILE		"mpd.secret"
  #define LINKS_FILE		"mpd.links"
  #define SCRIPT_FILE		"mpd.script"

#ifndef PATH_CONF_DIR
  #define PATH_CONF_DIR		"/etc/ppp"
#endif

  #define LG_FILE		"/var/log/mpd"
  #define PID_FILE		"/var/run/mpd.pid"
  #define PATH_LOCKFILENAME	"/var/spool/lock/LCK..%s"

  #define PATH_IFCONFIG		"/sbin/ifconfig"
  #define PATH_ARP		"/usr/sbin/arp"
  #define PATH_ROUTE		"/sbin/route"
  #define PATH_NETSTAT		"/usr/bin/netstat"

  #define AUTH_MAX_AUTHNAME	64
  #define AUTH_MAX_PASSWORD	64

  /* Forward decl's */
  struct linkst;
  typedef struct linkst *Link;
  struct bundle;
  typedef struct bundle *Bund;

#endif

