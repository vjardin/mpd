/*
 * See ``COPYRIGHT.mpd''
 *
 * $Id$
 *
 */

#include "ppp.h"
#include "eap.h"
#include "radius.h"
#include "auth.h"
#include "ngfunc.h"

/*
 * INTERNAL FUNCTIONS
 */

  static void   EapSendRequest(u_char type);
  static void	EapSendNak(u_char id, u_char type);
  static void	EapSendIdentRequest(EapInfo pap);
  static void	EapIdentTimeout(void *ptr);
  static char	EapTypeSupported(u_char type);



/*
 * EapStart()
 */

void
EapStart(EapInfo eap, int which)
{

  switch (which) {
    case AUTH_PEER_TO_SELF:
      /* fill a list of requestable auth types */
      eap->types[0] = EAP_TYPE_MD5CHAL;
      eap->types[1] = EAP_TYPE_MSCHAP_V2;

      /* Initialize retry counter and timer */
      eap->next_id = 1;
      eap->retry = AUTH_RETRIES;

      TimerInit(&eap->identTimer, "EapTimer",
	lnk->conf.retry_timeout * SECONDS, EapIdentTimeout, (void *) eap);
      TimerStart(&eap->identTimer);

      /* Send first request */
      EapSendIdentRequest(eap);
      break;

    case AUTH_SELF_TO_PEER:	/* Just wait for authenitcaor's request */
      break;

    default:
      assert(0);
  }
}

/*
 * EapStop()
 */

void
EapStop(EapInfo eap)
{
  TimerStop(&eap->identTimer);
}

/*
 * EapSendRequest()
 *
 * Send an EAP request to peer.
 */
static void
EapSendRequest(u_char type)
{
  Auth		const a = &lnk->lcp.auth;
  EapInfo	const eap = &a->eap;
  ChapInfo	const chap = &a->chap;
  int		i = 0;
  u_char	req_type = 0;

  if (type == 0) {
    for (i = 0; i < EAP_NUM_AUTH_PROTOS; i++) {
      if (eap->types[i] != 0) {
        req_type = eap->types[i];
        break;
      }
    }
  } else {
    req_type = type;
  }

  if (req_type == 0) {
    Log(LG_AUTH, ("[%s] EAP: ran out of EAP Types", lnk->name));
    AuthFinish(AUTH_PEER_TO_SELF, FALSE, NULL);
    return;
  }

  /* don't request this type again */
  eap->types[i] = 0;

  switch (req_type) {

    case EAP_TYPE_MD5CHAL:
    case EAP_TYPE_MSCHAP_V2:

      /* Invalidate any old challenge data */
      chap->chal_len = 0;
      /* Initialize retry counter and timer */
      chap->next_id = 1;
      chap->retry = AUTH_RETRIES;
      chap->proto = PROTO_EAP;

      if (type == EAP_TYPE_MD5CHAL) {
	chap->recv_alg = CHAP_ALG_MD5;
      } else {
	chap->recv_alg = CHAP_ALG_MSOFTv2;
      }

      TimerInit(&chap->chalTimer, "ChalTimer",
        lnk->conf.retry_timeout * SECONDS, ChapChalTimeout, (void *) chap);
      TimerStart(&chap->chalTimer);

      /* Send first challenge */
      ChapSendChallenge(chap);
      break;

    default:
      Log(LG_AUTH, ("[%s] EAP: Type %d is currently un-implemented",
	lnk->name, eap->types[i]));
      AuthFinish(AUTH_PEER_TO_SELF, FALSE, NULL);
  }

  return;
}

/*
 * EapSendNak()
 *
 * Send an EAP Nak to peer.
 */
static void
EapSendNak(u_char id, u_char type)
{
  Auth		const a = &lnk->lcp.auth;
  EapInfo	const eap = &a->eap;
  int		i = 0;
  u_char	nak_type = 0;

  for (i = 0; i < EAP_NUM_AUTH_PROTOS; i++) {
    if (eap->types[i] != 0) {
      nak_type = eap->types[i];
      break;
    }
  }

  if (nak_type == 0) {
    Log(LG_AUTH, ("[%s] EAP: ran out of EAP Types", lnk->name));
    AuthFinish(AUTH_SELF_TO_PEER, FALSE, NULL);
    return;
  }

  /* don't nak this proto again */
  eap->types[i] = 0;

  AuthOutput(PROTO_EAP, EAP_RESPONSE, id, &nak_type, 1, 0, EAP_TYPE_NAK);
  return;
}

/*
 * EapSendIdentRequest()
 *
 * Send an Ident Request to the peer.
 */

static void
EapSendIdentRequest(EapInfo eap)
{
  /* Send the initial Identity request */
  AuthOutput(PROTO_EAP, EAP_REQUEST,  eap->next_id++, NULL, 0, 0, EAP_TYPE_IDENT);
}

/*
 * EapInput()
 *
 * Accept an incoming EAP packet
 */

void
EapInput(u_char code, u_char id, const u_char *pkt, u_short len)
{
  int		data_len = len - 1;
  u_char	*data = NULL, type = 0;
  Auth		const a = &lnk->lcp.auth;
  EapInfo	const eap = &a->eap;
  ChapInfo	const chap = &a->chap;

  if (pkt != NULL) {
    data = data_len > 0 ? (u_char *) &pkt[1] : NULL;
    type = pkt[0];
    Log(LG_AUTH, ("[%s] EAP: rec'd %s Type %s #%d len:%d",
      lnk->name, EapCode(code), EapType(type), id, len));
  } else {
    Log(LG_AUTH, ("[%s] EAP: rec'd %s #%d len:%d",
      lnk->name, EapCode(code), id, len));
  }

  switch (code) {
    case EAP_REQUEST:
      switch (type) {
	case EAP_TYPE_IDENT:
	  AuthOutput(PROTO_EAP, EAP_RESPONSE, id, bund->conf.authname,
	    strlen(bund->conf.authname), 0, EAP_TYPE_IDENT);
	  break;

	case EAP_TYPE_NAK:
	case EAP_TYPE_NOTIF:
	  Log(LG_AUTH, ("[%s] EAP: Type %s is invalid in Request messages",
	    lnk->name, EapType(type)));
	  break;

	/* deal with Auth Types */
	default:
	  if (EapTypeSupported(type)) {
	    switch (type) {
	      case EAP_TYPE_MD5CHAL:
	      case EAP_TYPE_MSCHAP_V2:
		chap->xmit_alg = type == EAP_TYPE_MD5CHAL ? CHAP_ALG_MD5 : CHAP_ALG_MSOFTv2;
		ChapInput(PROTO_EAP, CHAP_CHALLENGE, id, &pkt[1], len - 1);
		break;

	      default:
		assert(0);
	    }
	  } else {
	    Log(LG_AUTH, ("[%s] EAP: Type %s not supported", lnk->name, EapType(type)));
	    EapSendNak(id, type);
	  }
      }
      break;

    case EAP_RESPONSE:
      switch (type) {
	case EAP_TYPE_IDENT:
	  TimerStop(&eap->identTimer);
	  Log(LG_AUTH, ("[%s] EAP: Identity:%*.*s", lnk->name,
	    data_len, data_len, data));
	  EapSendRequest(0);
	  break;

	case EAP_TYPE_NOTIF:
	  Log(LG_AUTH, ("[%s] EAP: Notify:%*.*s ", lnk->name,
	    data_len, data_len, data));
	  break;

	case EAP_TYPE_NAK:
	  Log(LG_AUTH, ("[%s] EAP: Nak desired Type %s ", lnk->name,
	    EapType(data[0])));
	  if (EapTypeSupported(data[0]))
	    EapSendRequest(data[0]);
	  else
	    EapSendRequest(0);
	  break;

	case EAP_TYPE_MD5CHAL:
	case EAP_TYPE_MSCHAP_V2:
	  ChapInput(PROTO_EAP, CHAP_RESPONSE, id, &pkt[1], len - 1);
	  break;

	default:
	  Log(LG_AUTH, ("[%s] EAP: unknown type %d", lnk->name, type));
	  AuthFinish(AUTH_PEER_TO_SELF, FALSE, NULL);
      }
      break;

    case EAP_SUCCESS:
      AuthFinish(AUTH_SELF_TO_PEER, TRUE, NULL);
      break;

    case EAP_FAILURE:
      AuthFinish(AUTH_SELF_TO_PEER, FALSE, NULL);
      break;

    default:
      Log(LG_AUTH, ("[%s] EAP: unknown code %d", lnk->name, code));
      AuthFinish(AUTH_SELF_TO_PEER, FALSE, NULL);
      break;
  }
}

/*
 * EapIdentTimeout()
 *
 * Timer expired for reply to our request
 */

static void
EapIdentTimeout(void *ptr)
{
  EapInfo	const eap = (EapInfo) ptr;

  TimerStop(&eap->identTimer);
  if (--eap->retry > 0) {
    TimerStart(&eap->identTimer);
    EapSendIdentRequest(eap);
  }
}

/*
 * EapCode()
 */

const char *
EapCode(u_char code)
{
  static char	buf[12];

  switch (code) {
    case EAP_REQUEST:
      return("REQUEST");
    case EAP_RESPONSE:
      return("RESPONSE");
    case EAP_SUCCESS:
      return("SUCCESS");
    case EAP_FAILURE:
      return("FAILURE");
    default:
      snprintf(buf, sizeof(buf), "code %d", code);
      return(buf);
  }
}

/*
 * EapType()
 */

const char *
EapType(u_char type)
{
  static char	buf[12];

  switch (type) {
    case EAP_TYPE_IDENT:
      return("Identity");
    case EAP_TYPE_NOTIF:
      return("Notification");
    case EAP_TYPE_NAK:
      return("Nak");
    case EAP_TYPE_MD5CHAL:
      return("MD5 Challenge");
    case EAP_TYPE_OTP:
      return("One Time Password");
    case EAP_TYPE_GTC:
      return("Generic Token Card");
    case EAP_TYPE_MSCHAP_V2:
      return("MS-CHAPv2");
    default:
      snprintf(buf, sizeof(buf), "type %d", type);
      return(buf);
  }
}

/*
 * EapTypeSupported()
 */

static char
EapTypeSupported(u_char type)
{
  switch (type) {
    case EAP_TYPE_IDENT:
    case EAP_TYPE_NOTIF:
    case EAP_TYPE_NAK:
    case EAP_TYPE_MD5CHAL:
    case EAP_TYPE_MSCHAP_V2:
      return 1;

    default:
      return 0;
  }
}

