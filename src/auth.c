
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
#include "ngfunc.h"

/*
 * INTERNAL FUNCTIONS
 */

  static void	AuthTimeout(void *arg);
  static int	AuthGetExternalPassword(AuthData auth);
  static const char *AuthCode(int proto, u_char code);

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
    case PROTO_EAP:
      EapStart(&a->eap, AUTH_SELF_TO_PEER);
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
    case PROTO_EAP:
      EapStart(&a->eap, AUTH_PEER_TO_SELF);
      break;
    default:
      assert(0);
  }
}

/*
 * AuthInput()
 *
 * Deal with PAP/CHAP/EAP packet
 */

void
AuthInput(int proto, Mbuf bp)
{
  int			len;
  struct fsmheader	fsmh;
  u_char		*pkt;

  /* Sanity check */
  if (lnk->lcp.phase != PHASE_AUTHENTICATE && lnk->lcp.phase != PHASE_NETWORK) {
    Log(LG_AUTH, ("[%s] AUTH: rec'd stray packet", lnk->name));
    PFREE(bp);
    return;
  }

  /* Make packet a single mbuf */
  len = plength(bp = mbunify(bp));

  /* Sanity check length */
  if (len < sizeof(fsmh)) {
    Log(LG_AUTH, ("[%s] AUTH: rec'd runt packet: %d bytes",
      lnk->name, len));
    PFREE(bp);
    return;
  }

  bp = mbread(bp, (u_char *) &fsmh, sizeof(fsmh), NULL);
  len -= sizeof(fsmh);
  if (len > ntohs(fsmh.length))
    len = ntohs(fsmh.length);

  if (bp == NULL && proto != PROTO_EAP)
  {
    const char	*failMesg;
    u_char	code = 0;

    Log(LG_AUTH, (" Bad packet"));
    failMesg = AuthFailMsg(proto, 0, AUTH_FAIL_INVALID_PACKET);
    if (proto == PROTO_PAP)
      code = PAP_NAK;
    else if (proto == PROTO_CHAP)
      code = CHAP_FAILURE;
    else
      assert(0);
    AuthOutput(proto, code, fsmh.id, failMesg, strlen(failMesg), 1, 0);
    AuthFinish(AUTH_PEER_TO_SELF, FALSE, NULL);
    return;
  }

  pkt = MBDATA(bp);

  switch (proto) {
    case PROTO_PAP:
      PapInput(fsmh.code, fsmh.id, pkt, len);
      break;
    case PROTO_CHAP:
      ChapInput(proto, fsmh.code, fsmh.id, pkt, len);
      break;
    case PROTO_EAP:
      EapInput(fsmh.code, fsmh.id, pkt, len);
      break;
    default:
      assert(0);
  }

  PFREE(bp);
}

/*
 * AuthOutput()
 *
 */

void
AuthOutput(int proto, u_int code, u_int id, const u_char *ptr,
	int len, int add_len, u_char eap_type)
{
  struct fsmheader	lh;
  Mbuf			bp;
  int			plen;

  add_len = !!add_len;
  /* Setup header */
  if (proto == PROTO_EAP)
    plen = sizeof(lh) + len + add_len + 1;
  else
    plen = sizeof(lh) + len + add_len;
  lh.code = code;
  lh.id = id;
  lh.length = htons(plen);

  /* Build packet */
  bp = mballoc(MB_AUTH, plen);
  memcpy(MBDATA(bp), &lh, sizeof(lh));
  if (proto == PROTO_EAP)
    memcpy(MBDATA(bp) + sizeof(lh), &eap_type, 1);

  if (add_len)
    *(MBDATA(bp) + sizeof(lh)) = (u_char)len;

  if (proto == PROTO_EAP) {
    memcpy(MBDATA(bp) + sizeof(lh) + add_len + 1, ptr, len);
    Log(LG_AUTH, ("[%s] %s: sending %s Type %s len:%d", lnk->name,
      ProtoName(proto), AuthCode(proto, code), EapType(eap_type), len));
  } else {
    memcpy(MBDATA(bp) + sizeof(lh) + add_len, ptr, len);
    Log(LG_AUTH, ("[%s] %s: sending %s len:%d", lnk->name,
      ProtoName(proto), AuthCode(proto, code), len));
  }

  /* Send it out */

  NgFuncWritePppFrame(lnk->bundleIndex, proto, bp);
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

  if (auth != NULL) {
    /* Notify external auth program if needed */
    if (which == AUTH_PEER_TO_SELF && auth->external) {
      ExecCmd(LG_AUTH, "%s %s %s", auth->extcmd,
        ok ? "-y" : "-n", auth->authname);
    }
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
AuthGetData(AuthData auth, int complain, int *whyFail)
{
  FILE		*fp;
  int		ac;
  char		*av[20];
  char		*line;

  /* Default to generic failure reason */
  if (whyFail)
    *whyFail = AUTH_FAIL_INVALID_LOGIN;

  /* Check authname, must be non-empty */
  if (*auth->authname == 0) {
    if (complain)
      Log(LG_AUTH, ("mpd: empty auth name"));
    return(-1);
  }

  /* Use manually configured login and password, if given */
  if (*bund->conf.password && !strcmp(auth->authname, bund->conf.authname)) {
    snprintf(auth->password, sizeof(auth->password), "%s", bund->conf.password);
    memset(&auth->range, 0, sizeof(auth->range));
    auth->range_valid = auth->external = FALSE;
    return(0);
  }

  /* Search secrets file */
  if ((fp = OpenConfFile(SECRET_FILE)) == NULL)
    return(-1);
  while ((line = ReadFullLine(fp, NULL)) != NULL) {
    memset(av, 0, sizeof(av));
    ac = ParseLine(line, av, sizeof(av) / sizeof(*av));
    Freee(MB_UTIL, line);
    if (ac >= 2
	&& (strcmp(av[0], auth->authname) == 0
	 || (av[1][0] == '!' && strcmp(av[0], "*") == 0))) {
      if (av[1][0] == '!') {		/* external auth program */
	snprintf(auth->extcmd, sizeof(auth->extcmd), "%s", av[1] + 1);
	auth->external = TRUE;
	if (AuthGetExternalPassword(auth) == -1) {
	  FreeArgs(ac, av);
	  fclose(fp);
	  return(-1);
	}
      } else {
	snprintf(auth->password, sizeof(auth->password), "%s", av[1]);
	*auth->extcmd = '\0';
	auth->external = FALSE;
      }
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
  return(CustomAuthData(auth, whyFail));
#else
  return(-1);		/* Invalid */
#endif
}

/*
 * AuthPreChecks()
 *
 */

int
AuthPreChecks(AuthData auth, int complain, int *whyFail)
{
  /* check max. number of logins */
  if (bund->conf.max_logins != 0) {
    int		ac;
    u_long	num = 0;
    for(ac = 0; ac < gNumBundles; ac++)
      if (gBundles[ac]->open)
	if (!strcmp(gBundles[ac]->peer_authname, auth->authname))
	  num++;

    if (num >= bund->conf.max_logins) {
      if (complain) {
	Log(LG_AUTH, (" Name: \"%s\" max. number of logins exceeded",
	  auth->authname));
      }
      *whyFail = AUTH_FAIL_ACCT_DISABLED;
      return (-1);
    }
  }
  return (0);
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
  const char	*mesg;

  if (proto == PROTO_CHAP
      && (alg == CHAP_ALG_MSOFT || alg == CHAP_ALG_MSOFTv2)) {
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

    if (bund->radius.mschap_error != NULL) {
      snprintf(buf, sizeof(buf), bund->radius.mschap_error);
    } else {
      snprintf(buf, sizeof(buf), "E=%d R=0", mscode);
    }
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

/*
 * AuthGetExternalPassword()
 *
 * Run the named external program to fill in the password for the user
 * mentioned in the AuthData
 * -1 on error (can't fork, no data read, whatever)
 */
static int
AuthGetExternalPassword(AuthData a)
{
  char cmd[AUTH_MAX_PASSWORD + 5 + AUTH_MAX_AUTHNAME];
  int ok = 0;
  FILE *fp;
  int len;

  snprintf(cmd, sizeof(cmd), "%s %s", a->extcmd, a->authname);
  Log(LG_AUTH, ("Invoking external auth program: %s", cmd));
  if ((fp = popen(cmd, "r")) == NULL) {
    Perror("Popen");
    return (-1);
  }
  if (fgets(a->password, sizeof(a->password), fp) != NULL) {
    len = strlen(a->password);		/* trim trailing newline */
    if (len > 0 && a->password[len - 1] == '\n')
      a->password[len - 1] = '\0';
    ok = (*a->password != '\0');
  } else {
    if (ferror(fp))
      Perror("Error reading from external auth program");
  }
  if (!ok)
    Log(LG_AUTH, ("External auth program failed for user \"%s\"", a->authname));
  pclose(fp);
  return (ok ? 0 : -1);
}

/*
 * AuthCode()
 */

static const char *
AuthCode(int proto, u_char code)
{
  static char	buf[12];

  switch (proto) {
    case PROTO_EAP:
      return EapCode(code);

    case PROTO_CHAP:
      return ChapCode(code);

    case PROTO_PAP:
      return PapCode(code);

    default:
      snprintf(buf, sizeof(buf), "code %d", code);
      return(buf);
  }
}
