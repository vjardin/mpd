
/*
 * defs.h
 *
 * Written by Archie Cobbs <archie@freebsd.org>
 * Copyright (c) 1995-1999 Whistle Communications, Inc. All rights reserved.
 * See ``COPYRIGHT.whistle''
 */

#ifndef _DEFS_H_
#define _DEFS_H_

#include <sys/param.h>
#include <sys/types.h>
#include <sysexits.h>
#include "config.h"

/*
 * DEFINITIONS
 */

  /* Compile time configuring. */
#ifdef HAVE_NG_CAR
  #define      USE_NG_CAR
#endif
#ifdef HAVE_NG_DEFLATE
  #define      USE_NG_DEFLATE
#endif
#ifdef HAVE_NG_NAT
  #define      USE_NG_NAT
#endif
#ifdef HAVE_NG_NETFLOW
  #define      USE_NG_NETFLOW
#endif
#ifdef HAVE_NG_PRED1
  #define      USE_NG_PRED1
#endif
#ifdef HAVE_NG_TCPMSS
  #define      USE_NG_TCPMSS
#endif

  /* Boolean */
#ifndef TRUE
  #define TRUE 			1
#endif
#ifndef FALSE
  #define FALSE 		0
#endif

#ifndef MPD_VENDOR
#ifdef __DragonFly__
  #define MPD_VENDOR		"DragonFlyBSD MPD"
#else
  #define MPD_VENDOR		"FreeBSD MPD"
#endif
#endif

  /* Exit codes */
  #define EX_NORMAL		EX_OK
  #define EX_ERRDEAD		EX_SOFTWARE
  #define EX_TERMINATE		99	/* pseudo-code */

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
  #define PATH_IPFW		"/sbin/ipfw"
  #define PATH_NETSTAT		"/usr/bin/netstat"

  #define AUTH_MAX_AUTHNAME	64
  #define AUTH_MAX_PASSWORD	64
  #define AUTH_MAX_EXTCMD	128
  #define AUTH_MAX_SESSIONID	32

  #define LINK_MAX_NAME		16

  #define DEFAULT_CONSOLE_PORT	5005
  #define DEFAULT_CONSOLE_IP	"127.0.0.1"

  #define DEFAULT_WEB_PORT	5006
  #define DEFAULT_WEB_IP	"127.0.0.1"

  /* Forward decl's */
  struct linkst;
  typedef struct linkst *Link;
  struct bundle;
  typedef struct bundle *Bund;
  struct rep;
  typedef struct rep *Rep;

  struct context;
  typedef struct context *Context;

#endif

