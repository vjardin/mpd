
/*
 * chap.c
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
#include "chap.h"
#include "auth.h"
#include "msoft.h"
#include "ngfunc.h"
#include "radius.h"
#include <openssl/md5.h>

/*
 * DEFINITIONS
 */

  #define CHAP_CHALLENGE	1
  #define CHAP_RESPONSE		2
  #define CHAP_SUCCESS		3
  #define CHAP_FAILURE		4
  #define CHAP_MS_V1_CHANGE_PW	5
  #define CHAP_MS_V2_CHANGE_PW	7

/*
 * INTERNAL FUNCTIONS
 */

  static void	ChapSendChallenge(ChapInfo chap);
  static void	ChapOutput(u_int code, u_int id, const u_char *ptr, int cnt);
  static int	ChapParsePkt(Mbuf bp, const int pkt_len,
		  char *peer_name, u_char *chap_value,
		  int *chap_value_size);
  static void	ChapGenRandom(u_char *buf, int len);
  static int	ChapHash(int alg, u_char *hash_value, u_char id,
		  const char *username, const char *secret,
		  const u_char *challenge, int clen, int local);
  static int	ChapHashAgree(int alg, const u_char *self, int slen,
		  const u_char *peer, int plen);
  static void	ChapChalTimeout(void *ptr);
  static const	char *ChapCode(int code);

/*
 * INTERNAL VARIABLES
 */

  static const u_char	gMsoftZeros[32];
  static const u_char	gIdBytes[] = { 0x3b, 0x1e, 0x68 };

/*
 * ChapStart()
 */

void
ChapStart(ChapInfo chap, int which)
{
  switch (which)
  {
    case AUTH_SELF_TO_PEER:	/* Just wait for peer's challenge */
      break;

    case AUTH_PEER_TO_SELF:

      /* Invalidate any old challenge data */
      chap->chal_len = 0;

      /* Initialize retry counter and timer */
      chap->next_id = 1;
      chap->retry = AUTH_RETRIES;

      TimerInit(&chap->chalTimer, "ChalTimer",
	lnk->conf.retry_timeout * SECONDS, ChapChalTimeout, (void *) chap);
      TimerStart(&chap->chalTimer);

      /* Send first challenge */
      ChapSendChallenge(chap);
      break;

    default:
      assert(0);
  }
}

/*
 * ChapStop()
 */

void
ChapStop(ChapInfo chap)
{
  TimerStop(&chap->chalTimer);
  TimerStop(&chap->respTimer);
  if (chap->resp) {
    Freee(chap->resp);
    chap->resp = NULL;
  }
}

/*
 * ChapSendChallenge()
 */

static void
ChapSendChallenge(ChapInfo chap)
{
  u_char	*pkt;

  /* Put random challenge data in buffer (only once for Microsoft CHAP) */
  switch (chap->recv_alg) {
    case CHAP_ALG_MSOFT: {
	chap->chal_len = CHAP_MSOFT_CHAL_LEN;
	if (!memcmp(bund->self_msChal, gMsoftZeros, chap->chal_len)) {
	  ChapGenRandom(chap->chal_data, chap->chal_len);
	  memcpy(bund->self_msChal, chap->chal_data, chap->chal_len);
	}
      }
      break;
    case CHAP_ALG_MSOFTv2:
      chap->chal_len = CHAP_MSOFTv2_CHAL_LEN;
      if (!memcmp(bund->self_msChal, gMsoftZeros, chap->chal_len)) {
	ChapGenRandom(chap->chal_data, chap->chal_len);
	memcpy(bund->self_msChal, chap->chal_data, chap->chal_len);
      }
      break;
    case CHAP_ALG_MD5:
      chap->chal_len = random() % 32 + 16;
      ChapGenRandom(chap->chal_data, chap->chal_len);
      break;
    default:
      assert(0);
  }
  assert(chap->chal_len <= sizeof(chap->chal_data));

  /* Build a challenge packet */
  pkt = Malloc(MB_AUTH, 1 + chap->chal_len + strlen(bund->conf.authname) + 1);
  pkt[0] = chap->chal_len;
  memcpy(pkt + 1, chap->chal_data, chap->chal_len);
  memcpy(pkt + 1 + chap->chal_len,
    bund->conf.authname, strlen(bund->conf.authname));

  /* Send it off */
  ChapOutput(CHAP_CHALLENGE, chap->next_id++,
    pkt, 1 + chap->chal_len + strlen(bund->conf.authname));
  Freee(pkt);
}

/*
 * ChapSendResponse()
 */

static void
ChapSendResponse(ChapInfo chap)
{

  /* Stop response timer */
  TimerStop(&chap->respTimer);

  /* Send response (possibly again) */
  assert(chap->resp);
  ChapOutput(CHAP_RESPONSE, chap->resp_id, chap->resp, chap->resp_len);

  /* Start re-send timer (only during authenticate phase where the
     authentication timer is still running) */
  if (lnk->lcp.phase == PHASE_AUTHENTICATE) {
    TimerInit(&chap->respTimer, "RespTimer",
      lnk->conf.retry_timeout * SECONDS,
      (void (*)(void *)) ChapSendResponse, (void *) chap);
    TimerStart(&chap->respTimer);
  }
}

/*
 * ChapOutput()
 */

static void
ChapOutput(u_int code, u_int id, const u_char *ptr, int count)
{
  struct fsmheader	lh;
  Mbuf			bp;
  int			plen;

  /* Setup header */
  plen = sizeof(lh) + count;
  lh.code = code;
  lh.id = id;
  lh.length = htons(plen);

  /* Build packet */
  bp = mballoc(MB_AUTH, plen);
  memcpy(MBDATA(bp), &lh, sizeof(lh));
  memcpy(MBDATA(bp) + sizeof(lh), ptr, count);

  /* Send it out */
  Log(LG_AUTH, ("[%s] CHAP: sending %s", lnk->name, ChapCode(code)));
  NgFuncWritePppFrame(lnk->bundleIndex, PROTO_CHAP, bp);
}

/*
 * ChapParsePkt()
 *
 * Note assumption that "bp" is a single mbuf, not a chain.
 */

static int
ChapParsePkt(Mbuf bp, const int pkt_len,
  char *peer_name, u_char *chap_value, int *chap_value_size)
{
  int		val_len, name_len;
  u_char	*const pkt = bp ? MBDATA(bp) : NULL;

  /* Compute and check lengths */
  if (pkt == NULL
      || pkt_len < 1
      || (val_len = pkt[0]) < 1
      || val_len > CHAP_MAX_VAL
      || (name_len = (pkt_len - val_len - 1)) < 0
      || name_len > CHAP_MAX_NAME) {
    Log(LG_AUTH, (" Bogus packet"));
    return(-1);
  }

  /* Extract stuff */
  memcpy(peer_name, pkt + 1 + val_len, name_len);
  peer_name[name_len] = 0;
  memcpy(chap_value, pkt + 1, val_len);
  *chap_value_size = val_len;
  Log(LG_AUTH, (" Name: \"%s\"", peer_name));
#if 0
  Log(LG_AUTH, (" Value: %d bytes", *chap_value_size));
#endif
  return(0);
}

/*
 * ChapChalTimeout()
 *
 * Timer expired for reply to challenge packet
 */

static void
ChapChalTimeout(void *ptr)
{
  ChapInfo	const chap = (ChapInfo) ptr;

  TimerStop(&chap->chalTimer);
  if (--chap->retry > 0) {
    TimerStart(&chap->chalTimer);
    ChapSendChallenge(chap);
  }
}

/*
 * ChapInput()
 */

void
ChapInput(Mbuf bp)
{
  Auth			const a = &lnk->lcp.auth;
  ChapInfo		const chap = &a->chap;
  struct fsmheader	chp;
  struct authdata	auth;
  char			peer_name[CHAP_MAX_NAME + 1];
  u_char		chap_value[CHAP_MAX_VAL];
  u_char		hash_value[CHAP_MAX_VAL];
  int			len, chap_value_size, hash_value_size;

  /* Sanity check */
  if (lnk->lcp.phase != PHASE_AUTHENTICATE && lnk->lcp.phase != PHASE_NETWORK) {
    Log(LG_AUTH, ("[%s] CHAP: rec'd stray packet", lnk->name));
    PFREE(bp);
    return;
  }

  /* Make packet a single mbuf */
  len = plength(bp = mbunify(bp));

  /* Sanity check length */
  if (len < sizeof(chp)) {
    Log(LG_AUTH, ("[%s] CHAP: rec'd runt packet: %d bytes",
      lnk->name, len));
    PFREE(bp);
    return;
  }
  bp = mbread(bp, (u_char *) &chp, sizeof(chp), NULL);
  len -= sizeof(chp);
  if (len > ntohs(chp.length))
    len = ntohs(chp.length);

  /* Deal with packet */
  Log(LG_AUTH, ("[%s] CHAP: rec'd %s #%d",
    lnk->name, ChapCode(chp.code), chp.id));
  switch (chp.code) {
    case CHAP_CHALLENGE:
      {
	char	*name;
	int	name_len, idFail;

	/* Check packet */
	if (a->self_to_peer != PROTO_CHAP
	    || lnk->lcp.phase != PHASE_AUTHENTICATE)
	  Log(LG_AUTH, (" Not expected, but that's OK"));
	if (ChapParsePkt(bp, len, peer_name, chap_value, &chap_value_size) < 0)
	  break;

	/* Never respond to our own outstanding challenge */
	if (chap_value_size == chap->chal_len
	    && !memcmp(chap_value, chap->chal_data, chap->chal_len)) {
	  Log(LG_AUTH, (" SECURITY: peer sent same challenge! Ignoring."));
	  break;
	}

	/* Don't respond to a challenge that looks like it came from
	   us and has the wrong origination value embedded in it. This
	   avoids a security hole associated with using the same CHAP
	   password to authenticate in both directions on a link. */
	idFail = 0;
	do {
	  char	buf[sizeof(gIdBytes)];
	  int	chalOrig;

	  /* Check challenge length */
	  if (chap_value_size < sizeof(buf))
	    break;

	  /* Copy challenge bits and extract origination value */
	  memcpy(buf, chap_value, sizeof(buf));
	  chalOrig = (buf[0] >> 6) & 0x03;
	  buf[0] &= 0x3f;

	  /* Check for same ID bytes in the challenge */
	  if (memcmp(buf, gIdBytes, sizeof(gIdBytes)) != 0)
	    break;

	  /* ID bytes match; origination value must be opposite. Note this
	     assumes that if we can tell the origination direction of a link,
	     then so can the peer. */
	  switch (lnk->originate) {
	    case LINK_ORIGINATE_LOCAL:
	      idFail = (chalOrig != LINK_ORIGINATE_REMOTE);
	      break;
	    case LINK_ORIGINATE_REMOTE:
	      idFail = (chalOrig != LINK_ORIGINATE_LOCAL);
	      break;
	    case LINK_ORIGINATE_UNKNOWN:
	    default:
	      idFail = 0;	/* XXX assumes leased line, etc is secure */
	      break;
	  }

	  /* Log failure */
	  if (idFail) {
	    Log(LG_AUTH,
	      (" SECURITY: origination value check failed (%s,%s). Ignoring.",
		LINK_ORIGINATION(lnk->originate),
		LINK_ORIGINATION(chalOrig)));
	    break;
	  }
	} while (0);
	if (idFail)
	  break;

	/*
	 * Name we use to authenticate ourselves:
	 *
	 * 1. The manually configured authname ("set authname ...")
	 * 2. The peer's supplied name
	 */
	if (*bund->conf.authname)
	  name = bund->conf.authname;
	else
	  name = peer_name;
	name_len = strlen(name);
	Log(LG_AUTH, (" Using authname \"%s\"", name));

	/* Initialize 'auth' info */
	memset(&auth, 0, sizeof(auth));
	strlcpy(auth.authname, name, sizeof(auth.authname));

	/* Get the corresponding secret */
	if (AuthGetData(&auth, 1, NULL) < 0) {
	  Log(LG_AUTH, (" Warning: no secret for \"%s\" found", auth.authname));
	  break;
	}

	/* Get hash value */
	if ((hash_value_size = ChapHash(chap->xmit_alg, hash_value, chp.id,
	    name, auth.password, chap_value, chap_value_size, 1)) < 0) {
	  Log(LG_AUTH, (" Hash failure"));
	  break;
	}

	/* Need to remember MS-CHAP stuff for use with MPPE encryption */
	switch (chap->xmit_alg) {
	case CHAP_ALG_MSOFT:
	  if (!memcmp(bund->peer_msChal, gMsoftZeros, CHAP_MSOFT_CHAL_LEN))
	    memcpy(bund->peer_msChal, chap_value, CHAP_MSOFT_CHAL_LEN);
	  strlcpy(bund->msPassword, auth.password, sizeof(bund->msPassword));
	  break;
	case CHAP_ALG_MSOFTv2:
	  if (!memcmp(bund->peer_msChal, gMsoftZeros, CHAP_MSOFTv2_CHAL_LEN))
	    memcpy(bund->peer_msChal, chap_value, CHAP_MSOFTv2_CHAL_LEN);
	  if (!memcmp(bund->self_ntResp, gMsoftZeros, CHAP_MSOFTv2_RESP_LEN)) {
	    memcpy(bund->self_ntResp,
	      hash_value + offsetof(struct mschapv2value, ntHash),
	      CHAP_MSOFTv2_RESP_LEN);
	  }
	  strlcpy(bund->msPassword, auth.password, sizeof(bund->msPassword));
	  break;
	}

	/* Build response packet */
	if (chap->resp)
	  Freee(chap->resp);
	chap->resp = Malloc(MB_AUTH, 1 + hash_value_size + name_len);
	chap->resp[0] = hash_value_size;
	memcpy(&chap->resp[1], hash_value, hash_value_size);
	memcpy(&chap->resp[1 + hash_value_size], name, name_len);
	chap->resp_len = 1 + hash_value_size + name_len;
	chap->resp_id = chp.id;

	/* Send response to peer */
	ChapSendResponse(chap);
      }
      break;

    case CHAP_RESPONSE:
      {
	const char	*failMesg;
	char		ackMesg[128];
	int		whyFail;
	int		radRes = RAD_NACK;

	/* Stop challenge timer */
	TimerStop(&chap->chalTimer);

	/* Check response */
	if (a->peer_to_self != PROTO_CHAP
	    || lnk->lcp.phase != PHASE_AUTHENTICATE)
	  Log(LG_AUTH, (" Not expected, but that's OK"));
	if (ChapParsePkt(bp, len,
	    peer_name, chap_value, &chap_value_size) < 0) {
	  whyFail = AUTH_FAIL_INVALID_PACKET;
	  goto badResponse;
	}

	/* Strip MS domain if any */
	if (chap->recv_alg == CHAP_ALG_MSOFT
	    || chap->recv_alg == CHAP_ALG_MSOFTv2) {
	  char	*s;

	  if ((s = strrchr(peer_name, '\\')))
	    memmove(peer_name, s + 1, strlen(s) + 1);
	}

	/* Copy in peer challenge for MS-CHAPv2 */
	if (chap->recv_alg == CHAP_ALG_MSOFTv2)
	  memcpy(hash_value, chap_value, 16);

	/* Initialize 'auth' info */
	memset(&auth, 0, sizeof(auth));
	strlcpy(auth.authname, peer_name, sizeof(auth.authname));

	/* perform pre authentication checks (single-login, etc.) */
        if (AuthPreChecks(&auth, 1, &whyFail) < 0) {
          Log(LG_AUTH, (" AuthPreCheck failed for \"%s\"", auth.authname));
          goto badResponse;
        }

	/* Try RADIUS auth if configured */
	if (Enabled(&bund->conf.options, BUND_CONF_RADIUSAUTH)) {
	  radRes = RadiusCHAPAuthenticate(peer_name, chap_value,
	    chap_value_size, chap->chal_data, chap->chal_len, chp.id,
	    chap->recv_alg);
	  if (radRes == RAD_ACK) {
	    RadiusSetAuth(&auth);
	    goto goodResponse;
	  }
	  if (!Enabled(&bund->conf.options, BUND_CONF_RADIUSFALLBACK)) {
	    whyFail = AUTH_FAIL_INVALID_LOGIN;
	    goto badResponse;
	  }
	}

	/* Get peer's secret key */
	Log(LG_AUTH, (" Peer name: \"%s\"", auth.authname));
	if (AuthGetData(&auth, 1, &whyFail) < 0) {
	  Log(LG_AUTH, (" Can't get credentials for \"%s\"", auth.authname));
	  goto badResponse;
	}

	/* Get expected hash value */
	if ((hash_value_size = ChapHash(chap->recv_alg, hash_value, chp.id,
	    peer_name, auth.password, chap->chal_data, chap->chal_len,
	    0)) < 0) {
	  Log(LG_AUTH, (" Hash failure"));
	  whyFail = AUTH_FAIL_INVALID_PACKET;
	  goto badResponse;
	}

	/* Compare with peer's response */
	if (chap->chal_len == 0
	    || !ChapHashAgree(chap->recv_alg, hash_value, hash_value_size,
	      chap_value, chap_value_size)) {
	  Log(LG_AUTH, (" Invalid response"));
	  whyFail = AUTH_FAIL_INVALID_LOGIN;
badResponse:
	  failMesg = AuthFailMsg(PROTO_CHAP, chap->recv_alg, whyFail);
	  ChapOutput(CHAP_FAILURE, chp.id, failMesg, strlen(failMesg));
/* XXX mbretter: HACK look if the peer should change the password 
          if (strstr(failMesg, "E=648") != NULL) {
	    Log(LG_AUTH, (" Password change requested"));
          } else {*/
	    AuthFinish(AUTH_PEER_TO_SELF, FALSE, &auth);
/*          }*/
	  break;
	}

goodResponse:
	/* Need to remember MS-CHAP stuff for use with MPPE encryption */
	if (chap->recv_alg == CHAP_ALG_MSOFT
	    || chap->recv_alg == CHAP_ALG_MSOFTv2)
	  strlcpy(bund->msPassword, auth.password, sizeof(bund->msPassword));
	if (chap->recv_alg == CHAP_ALG_MSOFTv2) {
	  if (!memcmp(bund->peer_ntResp, gMsoftZeros, CHAP_MSOFTv2_RESP_LEN)) {
	    memcpy(bund->peer_ntResp,
	      chap_value + offsetof(struct mschapv2value, ntHash),
	      CHAP_MSOFTv2_RESP_LEN);
	  }
	}

	/* Response is good */
	Log(LG_AUTH, (" Response is valid"));
	snprintf(ackMesg, sizeof(ackMesg), "%s", AUTH_MSG_WELCOME);

	if (chap->recv_alg == CHAP_ALG_MSOFTv2) {
	  struct mschapv2value *const pv = (struct mschapv2value *)chap_value;
	  u_char authresp[20];
	  char hex[41];
	  int i;

	  /* Generate MS-CHAPv2 'authenticator response' */
	  if (radRes == RAD_ACK) {
	    strcpy(ackMesg, bund->radius.mschapv2resp);
	  } else {
	    GenerateAuthenticatorResponse(auth.password, pv->ntHash,
	      pv->peerChal, chap->chal_data, peer_name, authresp);
	    for (i = 0; i < 20; i++)
	      sprintf(hex + (i * 2), "%02X", authresp[i]);
	    snprintf(ackMesg, sizeof(ackMesg), "S=%s", hex);
	  }
	}

	ChapOutput(CHAP_SUCCESS, chp.id, ackMesg, strlen(ackMesg));
	AuthFinish(AUTH_PEER_TO_SELF, TRUE, &auth);
      }
      break;

    case CHAP_SUCCESS:
    case CHAP_FAILURE:

      /* Stop response timer */
      TimerStop(&chap->respTimer);
      if (chap->resp) {
	Freee(chap->resp);
	chap->resp = NULL;
      }

      /* Appropriate? */
      if (a->self_to_peer != PROTO_CHAP
	  || lnk->lcp.phase != PHASE_AUTHENTICATE) {
	Log(LG_AUTH, (" Not expected, but that's OK"));
	break;
      }

      /* Log message */
      if (bp)
	ShowMesg(LG_AUTH, (char *) MBDATA(bp), len);
      AuthFinish(AUTH_SELF_TO_PEER, chp.code == CHAP_SUCCESS, NULL);
      break;
      
    case CHAP_MS_V1_CHANGE_PW:
      Log(LG_AUTH, ("[%s] CHAP: Sorry changing passwords using MS-CHAPv1 is not yet implemented", lnk->name));
      goto badResponse;
      break;

    case CHAP_MS_V2_CHANGE_PW:
      {
/* XXX mbretter: HACK */
/*        u_char	*const mschap_cpw = bp ? MBDATA(bp) : NULL;
        int	res;
	int	whyFail;        
*/

	Log(LG_AUTH, ("[%s] CHAP: Sorry changing passwords using MS-CHAPv2 is not yet implemented", lnk->name));
        goto badResponse;
        
/*	res = RadiusMSCHAPChangePassword(mschap_cpw, len, chap->chal_data, chap->chal_len, chp.id, chap->recv_alg);
        if (res == RAD_NACK) {
	  whyFail = AUTH_FAIL_INVALID_LOGIN;
	  goto badResponse;
        } else {
	  RadiusSetAuth(&auth);
	  goto goodResponse;
        }*/

      }

      break;

    default:
      Log(LG_AUTH, ("[%s] CHAP: unknown code %d", lnk->name, chp.code));
      break;
  }

  /* Done with packet */
  PFREE(bp);
}

/*
 * ChapGenRandom()
 */

static void
ChapGenRandom(u_char *buf, int len)
{
  int	k;

  /* Prefix with our unique ID plus origination value */
  for (k = 0; k < sizeof(gIdBytes) && k < len; k++)
    buf[k] = gIdBytes[k];
  buf[0] |= (lnk->originate & 0x03) << 6;

  /* Fill the rest with semi-random bytes */
  for (; k < len; k++)
    buf[k] = random() & 0xff;
}

/*
 * ChapHash()
 */

static int
ChapHash(int alg, u_char *hash_value, u_char id, const char *username,
	const char *secret, const u_char *challenge, int clen, int local)
{
  int	hash_size;

  switch (alg) {
    case CHAP_ALG_MD5:
      {
	MD5_CTX	md5ctx;

	MD5_Init(&md5ctx);
	MD5_Update(&md5ctx, &id, 1);
	MD5_Update(&md5ctx, secret, strlen(secret));
	MD5_Update(&md5ctx, challenge, clen);
	MD5_Final(hash_value, &md5ctx);
	hash_size = 16;
      }
      break;

    case CHAP_ALG_MSOFT:
      {
	struct mschapvalue	*const val = (struct mschapvalue *) hash_value;

	/* We don't generate the LANManager hash because it's too insecure */
	memset(val->lmHash, 0, sizeof(val->lmHash));
	NTChallengeResponse(challenge, secret, val->ntHash);
	val->useNT = 1;
	hash_size = 49;
      }
      break;
    case CHAP_ALG_MSOFTv2:
      {
	struct mschapv2value *const val = (struct mschapv2value *) hash_value;
	const char *s;

	if ((s = strrchr(username, '\\')) != NULL)
	  username = s + 1;
	if (local) {			/* generate reverse 'peer challenge' */
	  ChapGenRandom(val->peerChal, sizeof(val->peerChal));
	  memset(val->reserved, 0, sizeof(val->reserved));
	}
	GenerateNTResponse(challenge,
	  val->peerChal, username, secret, val->ntHash);

	hash_size = 49;
      }
      break;

    default:
      return(-1);
  }

  /* Done */
  return(hash_size);
}

/*
 * ChapHashAgree()
 */

static int
ChapHashAgree(int alg, const u_char *self, int slen,
	const u_char *peer, int plen)
{
  switch (alg)
  {
    case CHAP_ALG_MD5:
      return(slen == plen && !memcmp(self, peer, slen));

    case CHAP_ALG_MSOFT:
      {
	struct mschapvalue	*const sv = (struct mschapvalue *) self;
	struct mschapvalue	*const pv = (struct mschapvalue *) peer;

	if (slen != 49 || plen != 49)
	  return(0);
	if (sv->useNT != 1 || pv->useNT != 1)
	  return(0);
	return(!memcmp(&sv->ntHash, &pv->ntHash, sizeof(sv->ntHash)));
      }
    case CHAP_ALG_MSOFTv2:
      {
	struct mschapv2value	*const sv =(struct mschapv2value *) self;
	struct mschapv2value	*const pv =(struct mschapv2value *) peer;

	if (slen != 49 || plen != 49)
	  return(0);
	return(!memcmp(&sv->ntHash, &pv->ntHash, sizeof(sv->ntHash)));
      }

    default:
      return(0);
  }
}

/*
 * ChapCode()
 */

static const char *
ChapCode(int code)
{
  static char	buf[12];

  switch (code) {
    case CHAP_CHALLENGE:
      return("CHALLENGE");
    case CHAP_RESPONSE:
      return("RESPONSE");
    case CHAP_SUCCESS:
      return("SUCCESS");
    case CHAP_FAILURE:
      return("FAILURE");
    default:
      snprintf(buf, sizeof(buf), "code%d", code);
      return(buf);
  }
}

