
/*
 * auth.c
 *
 * Written by Archie Cobbs <archie@freebsd.org>
 * Copyright (c) 1995-1999 Whistle Communications, Inc. All rights reserved.
 * See ``COPYRIGHT.whistle''
 */

#include "ppp.h"
#include "auth.h"
#include "pap.h"
#include "chap.h"
#include "lcp.h"
#include "custom.h"
#include "log.h"

/*
 * INTERNAL FUNCTIONS
 */

  static void	AuthTimeout(void *arg);

/*
 * AuthStart()
 *
 * Initialize authorization info for a link
 */

void
AuthStart(void)
{
  Auth	a = &lnk->lcp.auth;

  /* What auth protocols were negotiated by LCP? */
  a->self_to_peer = lnk->lcp.peer_auth;
  a->peer_to_self = lnk->lcp.want_auth;
  a->chap.recv_alg = lnk->lcp.want_chap_alg;
  a->chap.xmit_alg = lnk->lcp.peer_chap_alg;

  Log(LG_AUTH, ("%s: auth: peer wants %s, I want %s",
    Pref(&lnk->lcp.fsm),
    a->self_to_peer ? ProtoName(a->self_to_peer) : "nothing",
    a->peer_to_self ? ProtoName(a->peer_to_self) : "nothing"));

  /* Is there anything to do? */
  if (!a->self_to_peer && !a->peer_to_self) {
    LcpAuthResult(TRUE);
    return;
  }

  /* Start global auth timer */
  TimerInit(&a->timer, "AuthTimer",
    LCP_AUTH_TIMEOUT * SECONDS, AuthTimeout, NULL);
  TimerStart(&a->timer);

  /* Start my auth to him */
  switch (a->self_to_peer) {
    case 0:
      break;
    case PROTO_PAP:
      PapStart(&a->pap, AUTH_SELF_TO_PEER);
      break;
    case PROTO_CHAP:
      ChapStart(&a->chap, AUTH_SELF_TO_PEER);
      break;
    default:
      assert(0);
  }

  /* Start his auth to me */
  switch (a->peer_to_self) {
    case 0:
      break;
    case PROTO_PAP:
      PapStart(&a->pap, AUTH_PEER_TO_SELF);
      break;
    case PROTO_CHAP:
      ChapStart(&a->chap, AUTH_PEER_TO_SELF);
      break;
    default:
      assert(0);
  }
}

/*
 * AuthFinish()
 *
 * Authorization is finished, so continue one way or the other
 */

void
AuthFinish(int which, int ok, AuthData auth)
{
  Auth	const a = &lnk->lcp.auth;

  switch (which) {
    case AUTH_SELF_TO_PEER:
      a->self_to_peer = 0;
      break;

    case AUTH_PEER_TO_SELF:
      a->peer_to_self = 0;
      if (ok) {

	/* Save authorization name */
	snprintf(lnk->peer_authname, sizeof(lnk->peer_authname),
	  "%s", auth->authname);

	/* Save IP address info for this peer */
	lnk->peer_allow = auth->range;
	lnk->range_valid = auth->range_valid;
      }
      break;

    default:
      assert(0);
  }

  /* Did auth fail (in either direction)? */
  if (!ok) {
    AuthStop();
    LcpAuthResult(FALSE);
    return;
  }

  /* Did auth succeed (in both directions)? */
  if (!a->peer_to_self && !a->self_to_peer) {
    AuthStop();
    LcpAuthResult(TRUE);
    return;
  }
}

/*
 * AuthStop()
 *
 * Stop the authorization process
 */

void
AuthStop(void)
{
  Auth	a = &lnk->lcp.auth;

  TimerStop(&a->timer);
  PapStop(&a->pap);
  ChapStop(&a->chap);
}

/*
 * AuthGetData()
 *
 * Returns -1 if not found and sets *whyFail to the failure code
 */

int
AuthGetData(const char *authname, AuthData auth, int complain, int *whyFail)
{
  FILE		*fp;
  int		ac;
  char		*av[20];
  char		*line;

  /* Default to generic failure reason */
  if (whyFail)
    *whyFail = AUTH_FAIL_INVALID_LOGIN;

  /* Check authname, must be non-empty */
  if (!authname || *authname == 0) {
    if (complain)
      Log(LG_AUTH, ("mpd: empty auth name"));
    return(-1);
  }

  /* Use manually configured login and password, if given */
  if (*bund->conf.password && !strcmp(authname, bund->conf.authname)) {
    snprintf(auth->authname, sizeof(auth->authname), "%s", authname);
    snprintf(auth->password, sizeof(auth->password), "%s", bund->conf.password);
    memset(&auth->range, 0, sizeof(auth->range));
    auth->range_valid = FALSE;
    return(0);
  }

  /* Search secrets file */
  if ((fp = OpenConfFile(SECRET_FILE)) == NULL)
    return(-1);
  while ((line = ReadFullLine(fp, NULL)) != NULL) {
    memset(av, 0, sizeof(av));
    ac = ParseLine(line, av, sizeof(av) / sizeof(*av));
    Freee(line);
    if (ac >= 2 && !strcmp(av[0], authname)) {
      snprintf(auth->authname, sizeof(auth->authname), "%s", av[0]);
      snprintf(auth->password, sizeof(auth->password), "%s", av[1]);
      memset(&auth->range, 0, sizeof(auth->range));
      auth->range_valid = FALSE;
      if (ac >= 3)
	auth->range_valid = ParseAddr(av[2], &auth->range);
      FreeArgs(ac, av);
      fclose(fp);
      return(0);
    }
    FreeArgs(ac, av);
  }
  fclose(fp);

#ifdef IA_CUSTOM
  return(CustomAuthData(authname, auth, whyFail));
#else
  return(-1);		/* Invalid */
#endif
}

/*
 * AuthTimeout()
 *
 * Timer expired for the whole authorization process
 */

static void
AuthTimeout(void *ptr)
{
  Log(LG_AUTH, ("%s: authorization timer expired", Pref(&lnk->lcp.fsm)));
  AuthStop();
  LcpAuthResult(FALSE);
}

/* 
 * AuthFailMsg()
 */

const char *
AuthFailMsg(int proto, int alg, int whyFail)
{
  static char	buf[64];
  char		*mesg;

  if (proto == PROTO_CHAP && alg == CHAP_ALG_MSOFT) {
    int	mscode;

    switch (whyFail) {
      case AUTH_FAIL_ACCT_DISABLED:
	mscode = MSCHAP_ERROR_ACCT_DISABLED;
	break;
      case AUTH_FAIL_NO_PERMISSION:
	mscode = MSCHAP_ERROR_NO_DIALIN_PERMISSION;
	break;
      case AUTH_FAIL_RESTRICTED_HOURS:
	mscode = MSCHAP_ERROR_RESTRICTED_LOGON_HOURS;
	break;
      case AUTH_FAIL_INVALID_PACKET:
      case AUTH_FAIL_INVALID_LOGIN:
      case AUTH_FAIL_NOT_EXPECTED:
      default:
	mscode = MSCHAP_ERROR_AUTHENTICATION_FAILURE;
	break;
    }
    snprintf(buf, sizeof(buf), "E=%d R=0", mscode);
    mesg = buf;
  } else {
    switch (whyFail) {
      case AUTH_FAIL_ACCT_DISABLED:
	mesg = AUTH_MSG_ACCT_DISAB;
	break;
      case AUTH_FAIL_NO_PERMISSION:
	mesg = AUTH_MSG_NOT_ALLOWED;
	break;
      case AUTH_FAIL_RESTRICTED_HOURS:
	mesg = AUTH_MSG_RESTR_HOURS;
	break;
      case AUTH_FAIL_NOT_EXPECTED:
	mesg = AUTH_MSG_NOT_EXPECTED;
	break;
      case AUTH_FAIL_INVALID_PACKET:
	mesg = AUTH_MSG_BAD_PACKET;
	break;
      case AUTH_FAIL_INVALID_LOGIN:
      default:
	mesg = AUTH_MSG_INVALID;
	break;
    }
  }
  return(mesg);
}

