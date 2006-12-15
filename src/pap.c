
/*
 * pap.c
 *
 * Written by Toshiharu OHNO <tony-o@iij.ad.jp>
 * Copyright (c) 1993, Internet Initiative Japan, Inc. All rights reserved.
 * See ``COPYRIGHT.iij''
 * 
 * Rewritten by Archie Cobbs <archie@freebsd.org>
 * Copyright (c) 1995-1999 Whistle Communications, Inc. All rights reserved.
 * See ``COPYRIGHT.whistle''
 */

#include "ppp.h"
#include "auth.h"
#include "util.h"

/*
 * INTERNAL FUNCTIONS
 */

  static void	PapSendRequest(PapInfo pap);
  static void	PapTimeout(void *ptr);

/*
 * PapStart()
 */

void
PapStart(PapInfo pap, int which)
{
  switch (which) {
    case AUTH_PEER_TO_SELF:	/* Just wait for peer's request */
      break;

    case AUTH_SELF_TO_PEER:

      /* Initialize retry counter and timer */
      pap->next_id = 1;
      pap->retry = AUTH_RETRIES;

      TimerInit(&pap->timer, "PapTimer",
	lnk->conf.retry_timeout * SECONDS, PapTimeout, (void *) pap);
      TimerStart(&pap->timer);

      /* Send first request */
      PapSendRequest(pap);
      break;

    default:
      assert(0);
  }
}

/*
 * PapStop()
 */

void
PapStop(PapInfo pap)
{
  TimerStop(&pap->timer);
}

/*
 * PapSendRequest()
 *
 * Send a PAP packet to peer.
 */

static void
PapSendRequest(PapInfo pap)
{
  struct authdata	auth;    
  int			name_len, pass_len;
  u_char		*pkt;

  /* Get password corresponding to my authname */
  memset(&auth, 0, sizeof(auth));
  auth.conf = bund->conf.auth;
  strlcpy(auth.params.authname, bund->conf.auth.authname, sizeof(auth.params.authname));
  Log(LG_AUTH, ("[%s] PAP: using authname \"%s\"", lnk->name, auth.params.authname));
  if (AuthGetData(&auth, 1) < 0)
    Log(LG_AUTH, (" Warning: no secret for \"%s\" found", auth.params.authname));

  /* Build response packet */
  name_len = strlen(auth.params.authname);
  pass_len = strlen(auth.params.password);

  pkt = Malloc(MB_AUTH, 1 + name_len + 1 + pass_len);
  pkt[0] = name_len;
  memcpy(pkt + 1, auth.params.authname, name_len);
  pkt[1 + name_len] = pass_len;
  memcpy(pkt + 1 + name_len + 1, auth.params.password, pass_len);

  /* Send it off */
  AuthOutput(PROTO_PAP, PAP_REQUEST, pap->next_id++, pkt,
    1 + name_len + 1 + pass_len, 0, 0);
  Freee(MB_AUTH, pkt);
}

/*
 * PapInput()
 *
 * Accept an incoming PAP packet
 */

void
PapInput(AuthData auth, const u_char *pkt, u_short len)
{
  Auth			const a = &lnk->lcp.auth;
  PapInfo		const pap = &a->pap;

  /* Deal with packet */
  Log(LG_AUTH, ("[%s] PAP: rec'd %s #%d",
    lnk->name, PapCode(auth->code), auth->id));
  switch (auth->code) {
    case PAP_REQUEST:
      {
	char		*name_ptr, name[256];
	char		*pass_ptr, pass[256];
	int		name_len, pass_len;

	/* Is this appropriate? */
	if (a->peer_to_self != PROTO_PAP) {
	  Log(LG_AUTH, ("[%s] PAP: %s not expected",
	    lnk->name, PapCode(auth->code)));
	  auth->why_fail = AUTH_FAIL_NOT_EXPECTED;
	  PapInputFinish(auth);
	  break;
	}

	name_len = pkt[0];
	name_ptr = (char *)pkt + 1;

	/* Sanity check packet and extract fields */
	if (1 + name_len >= len
	  || ((pass_len = pkt[1 + name_len]) && FALSE)
	  || ((pass_ptr = (char *)pkt + 1 + name_len + 1) && FALSE)
	  || name_len + 1 + pass_len + 1 > len)
	{
	  Log(LG_AUTH, (" Bad packet"));
	  auth->why_fail = AUTH_FAIL_INVALID_PACKET;
	  PapInputFinish(auth);
	  break;
	}
	memcpy(name, name_ptr, name_len);
	name[name_len] = 0;
	memcpy(pass, pass_ptr, pass_len);
	pass[pass_len] = 0;

	strlcpy(pap->peer_name, name, sizeof(pap->peer_name));
	strlcpy(pap->peer_pass, pass, sizeof(pap->peer_pass));
	strlcpy(auth->params.authname, name, sizeof(auth->params.authname));

	auth->finish = PapInputFinish;
	AuthAsyncStart(auth);

      }
      break;

    case PAP_ACK:
    case PAP_NAK:
      {
	char	*msg;
	int	msg_len;

	/* Is this appropriate? */
	if (a->self_to_peer != PROTO_PAP) {
	  Log(LG_AUTH, ("[%s] PAP: %s not expected",
	    lnk->name, PapCode(auth->code)));
	  break;
	}

	/* Stop resend timer */
	TimerStop(&pap->timer);

	/* Show reply message */
	msg_len = pkt[0];
	msg = (char *) &pkt[1];
	if (msg_len < len - 1)
	  msg_len = len - 1;
	ShowMesg(LG_AUTH, msg, msg_len);

	/* Done with my auth to peer */
	AuthFinish(AUTH_SELF_TO_PEER, auth->code == PAP_ACK);	
	AuthDataDestroy(auth);
      }
      break;

    default:
      Log(LG_AUTH, ("[%s] PAP: unknown code", lnk->name));
      AuthDataDestroy(auth);
      break;
  }
}

/*
 * ChapInputFinish()
 *
 * Possible return point from the asynch auth handler.
 * 
 */
 
void PapInputFinish(AuthData auth)
{
  PapInfo	pap = &lnk->lcp.auth.pap;
  const char	*Mesg;
  
  Log(LG_AUTH, ("[%s] PAP: PapInputFinish: status %s", 
    lnk->name, AuthStatusText(auth->status)));

  if (auth->status == AUTH_STATUS_FAIL)
    goto badRequest;
  else if (auth->status == AUTH_STATUS_SUCCESS)
    goto goodRequest;
  
  /* Do name & password match? */
  if (strcmp(auth->params.authname, pap->peer_name) ||
      strcmp(auth->params.password, pap->peer_pass)) {
    Log(LG_AUTH, (" Invalid response"));
    auth->why_fail = AUTH_FAIL_INVALID_LOGIN;
    goto badRequest;
  }
  
  goto goodRequest;

badRequest:
  if (auth->reply_message) {
    Log(LG_AUTH, (" Reply message: %s", auth->reply_message));
    Mesg = auth->reply_message;
  } else {
    Mesg = AuthFailMsg(auth, 0);
  }
  AuthOutput(PROTO_PAP, PAP_NAK, auth->id, Mesg, strlen(Mesg), 1, 0);
  AuthFinish(AUTH_PEER_TO_SELF, FALSE);
  AuthDataDestroy(auth);  
  return;
  
goodRequest:
  /* Login accepted */
  Log(LG_AUTH, (" Response is valid"));
  if (auth->reply_message) {
    Log(LG_AUTH, (" Reply message: %s", auth->reply_message));
    Mesg = auth->reply_message;
  } else {
    Mesg = AUTH_MSG_WELCOME;
  }
  AuthOutput(PROTO_PAP, PAP_ACK, auth->id, Mesg, strlen(Mesg), 1, 0);
  AuthFinish(AUTH_PEER_TO_SELF, TRUE);  
  AuthDataDestroy(auth);
}

/*
 * PapTimeout()
 *
 * Timer expired for reply to our request
 */

static void
PapTimeout(void *ptr)
{
  PapInfo	const pap = (PapInfo) ptr;

  TimerStop(&pap->timer);
  if (--pap->retry > 0) {
    TimerStart(&pap->timer);
    PapSendRequest(pap);
  }
}

/*
 * PapCode()
 */

const char *
PapCode(int code)
{
  static char	buf[12];

  switch (code) {
    case PAP_REQUEST:
      return("REQUEST");
    case PAP_ACK:
      return("ACK");
    case PAP_NAK:
      return("NAK");
    default:
      snprintf(buf, sizeof(buf), "code%d", code);
      return(buf);
  }
}

