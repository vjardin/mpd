
/*
 * auth.h
 *
 * Written by Archie Cobbs <archie@whistle.com>
 * Copyright (c) 1995-1999 Whistle Communications, Inc. All rights reserved.
 * See ``COPYRIGHT.whistle''
 */

#ifndef _AUTH_H_
#define	_AUTH_H_

#include "pap.h"
#include "chap.h"
#include "timer.h"

/*
 * DEFINITIONS
 */

  #define AUTH_RETRIES		3

  #define AUTH_MSG_WELCOME	"Welcome\r\n"
  #define AUTH_MSG_INVALID	"Login incorrect\r\n"
  #define AUTH_MSG_BAD_PACKET	"Incorrectly formatted packet\r\n"
  #define AUTH_MSG_NOT_ALLOWED	"Login not allowed for this account\r\n"
  #define AUTH_MSG_NOT_EXPECTED	"Unexpected packet\r\n"
  #define AUTH_MSG_ACCT_DISAB	"Account disabled\r\n"
  #define AUTH_MSG_RESTR_HOURS	"Login hours restricted\r\n"

  #define AUTH_PEER_TO_SELF	0
  #define AUTH_SELF_TO_PEER	1

  #define AUTH_FAIL_INVALID_LOGIN	0
  #define AUTH_FAIL_ACCT_DISABLED	1
  #define AUTH_FAIL_NO_PERMISSION	2
  #define AUTH_FAIL_RESTRICTED_HOURS	3
  #define AUTH_FAIL_INVALID_PACKET	4
  #define AUTH_FAIL_NOT_EXPECTED	5

  /* State of authorization process during authorization phase */
  struct auth {
    u_short		peer_to_self;	/* What I need from peer */
    u_short		self_to_peer;	/* What peer needs from me */
    struct pppTimer	timer;		/* Max time to spend doing auth */
    struct papinfo	pap;		/* PAP state */
    struct chapinfo	chap;		/* CHAP state */
  };
  typedef struct auth	*Auth;

  /* For returning a secrets file entry */
  struct authdata {
    char		authname[AUTH_MAX_AUTHNAME];
    char		password[AUTH_MAX_PASSWORD];
    struct in_range	range;
    u_int		range_valid:1;
  };
  typedef struct authdata	*AuthData;

/*
 * FUNCTIONS
 */

  extern void	AuthStart(void);
  extern void	AuthStop(void);
  extern void	AuthFinish(int which, int ok, AuthData auth);
  extern int	AuthGetData(const char *name, AuthData auth,
			int complain, int *whyFail);
  extern const	char *AuthFailMsg(int proto, int alg, int whyFail);

#endif

