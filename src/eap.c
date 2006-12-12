/*
 * See ``COPYRIGHT.mpd''
 *
 * $Id$
 *
 */

#include "ppp.h"
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
  static void	EapRadiusProxy(AuthData auth, const u_char *pkt, u_short len);
  static void	EapRadiusProxyFinish(AuthData auth);
  static void	EapRadiusSendMsg(void *ptr);
  static void	EapRadiusSendMsgTimeout(void *ptr);
  static int	EapSetCommand(int ac, char *av[], void *arg);

  /* Set menu options */
  enum {
    SET_ACCEPT,
    SET_DENY,
    SET_ENABLE,
    SET_DISABLE,
    SET_YES,
    SET_NO,
  };

/*
 * GLOBAL VARIABLES
 */

  const struct cmdtab EapSetCmds[] = {
    { "accept [opt ...]",		"Accept option",
	EapSetCommand, NULL, (void *) SET_ACCEPT },
    { "deny [opt ...]",			"Deny option",
	EapSetCommand, NULL, (void *) SET_DENY },
    { "enable [opt ...]",		"Enable option",
	EapSetCommand, NULL, (void *) SET_ENABLE },
    { "disable [opt ...]",		"Disable option",
	EapSetCommand, NULL, (void *) SET_DISABLE },
    { "yes [opt ...]",			"Enable and accept option",
	EapSetCommand, NULL, (void *) SET_YES },
    { "no [opt ...]",			"Disable and deny option",
	EapSetCommand, NULL, (void *) SET_NO },
    { NULL },
  };

/*
 * INTERNAL VARIABLES
 */

  static struct confinfo	gConfList[] = {
    { 0,	EAP_CONF_RADIUS,	"radius-proxy"	},
    { 1,	EAP_CONF_MD5,		"md5"		},
    { 0,	0,			NULL		},
  };



/*
 * EapInit()
 */

void
EapInit()
{
  EapInfo	eap;

  eap = &lnk->lcp.auth.eap;
  Disable(&eap->conf.options, EAP_CONF_MD5);
  Accept(&eap->conf.options, EAP_CONF_MD5);
}

/*
 * EapStart()
 */

void
EapStart(EapInfo eap, int which)
{
  int	i;

  for (i = 0; i < EAP_NUM_TYPES; i++)
    eap->peer_types[i] = eap->want_types[i] = 0;

  /* fill a list of requestable auth types */
  if (Enabled(&eap->conf.options, EAP_CONF_MD5))
    eap->want_types[0] = EAP_TYPE_MD5CHAL;

  /* fill a list of acceptable auth types */
  if (Acceptable(&eap->conf.options, EAP_CONF_MD5))
    eap->peer_types[0] = EAP_TYPE_MD5CHAL;

  switch (which) {
    case AUTH_PEER_TO_SELF:

      /* Initialize retry counter and timer */
      eap->next_id = 1;
      eap->retry = AUTH_RETRIES;

      TimerInit(&eap->reqTimer, "EapRadiusSendMsgTimer",
	lnk->conf.retry_timeout * SECONDS, EapRadiusSendMsgTimeout, (void *) eap);

      TimerInit(&eap->identTimer, "EapTimer",
	lnk->conf.retry_timeout * SECONDS, EapIdentTimeout, (void *) eap);
      TimerStart(&eap->identTimer);

      /* Send first request
       * Send the request even, if the Radius-Eap-Proxy feature is active,
       * this saves on roundtrip.
       */
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
  TimerStop(&eap->reqTimer);
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
    for (i = 0; i < EAP_NUM_TYPES; i++) {
      if (eap->want_types[i] != 0) {
        req_type = eap->want_types[i];
        break;
      }
    }
  } else {
    req_type = type;
  }

  if (req_type == 0) {
    Log(LG_AUTH, ("[%s] EAP: ran out of EAP Types", lnk->name));
    AuthFinish(AUTH_PEER_TO_SELF, FALSE);
    return;
  }

  /* don't request this type again */
  eap->want_types[i] = 0;

  switch (req_type) {

    case EAP_TYPE_MD5CHAL:

      /* Invalidate any old challenge data */
      chap->chal_len = 0;
      /* Initialize retry counter and timer */
      chap->next_id = 1;
      chap->retry = AUTH_RETRIES;
      chap->proto = PROTO_EAP;

      if (req_type == EAP_TYPE_MD5CHAL) {
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
	lnk->name, eap->want_types[i]));
      AuthFinish(AUTH_PEER_TO_SELF, FALSE);
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

  for (i = 0; i < EAP_NUM_TYPES; i++) {
    if (eap->peer_types[i] != 0) {
      nak_type = eap->peer_types[i];
      break;
    }
  }

  if (nak_type == 0) {
    Log(LG_AUTH, ("[%s] EAP: ran out of EAP Types", lnk->name));
    AuthFinish(AUTH_SELF_TO_PEER, FALSE);
    return;
  }

  /* don't nak this proto again */
  eap->peer_types[i] = 0;

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
EapInput(AuthData auth, const u_char *pkt, u_short len)
{
  Auth		const a = &lnk->lcp.auth;
  EapInfo	const eap = &a->eap;
  ChapInfo	const chap = &a->chap;
  int		data_len = len - 1, i, acc_type;
  u_char	*data = NULL, type = 0;
  
  if (pkt != NULL) {
    data = data_len > 0 ? (u_char *) &pkt[1] : NULL;
    type = pkt[0];
    Log(LG_AUTH, ("[%s] EAP: rec'd %s Type %s #%d len:%d",
      lnk->name, EapCode(auth->code), EapType(type), auth->id, len));
  } else {
    Log(LG_AUTH, ("[%s] EAP: rec'd %s #%d len:%d",
      lnk->name, EapCode(auth->code), auth->id, len));
  }
  
  if (Enabled(&eap->conf.options, EAP_CONF_RADIUS))
    return EapRadiusProxy(auth, pkt, len);

  switch (auth->code) {
    case EAP_REQUEST:
      switch (type) {
	case EAP_TYPE_IDENT:
	  AuthOutput(PROTO_EAP, EAP_RESPONSE, auth->id, auth->conf.authname,
	    strlen(auth->conf.authname), 0, EAP_TYPE_IDENT);
	  break;

	case EAP_TYPE_NAK:
	case EAP_TYPE_NOTIF:
	  Log(LG_AUTH, ("[%s] EAP: Type %s is invalid in Request messages",
	    lnk->name, EapType(type)));
	  AuthFinish(AUTH_SELF_TO_PEER, FALSE);
	  break;

	/* deal with Auth Types */
	default:
	  acc_type = 0;
	  if (EapTypeSupported(type)) {
	    for (i = 0; i < EAP_NUM_TYPES; i++) {
	      if (eap->peer_types[i] == type) {
		acc_type = eap->peer_types[i];
		break;
	      }
	    }

	    if (acc_type == 0) {
	      Log(LG_AUTH, ("[%s] EAP: Type %s not acceptable", lnk->name,
	        EapType(type)));
	      EapSendNak(auth->id, type);
	      break;
	    }

	    switch (type) {
	      case EAP_TYPE_MD5CHAL:
		chap->xmit_alg = CHAP_ALG_MD5;
		auth->code = CHAP_CHALLENGE;
		ChapInput(auth, &pkt[1], len - 1);
		break;

	      default:
		assert(0);
	    }
	  } else {
	    Log(LG_AUTH, ("[%s] EAP: Type %s not supported", lnk->name, EapType(type)));
	    EapSendNak(auth->id, type);
	  }
      }
      break;

    case EAP_RESPONSE:
      switch (type) {
	case EAP_TYPE_IDENT:
	  TimerStop(&eap->identTimer);
	  Log(LG_AUTH, ("[%s] EAP: Identity:%*.*s",
	    lnk->name, data_len, data_len, data));
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
	  auth->code = CHAP_RESPONSE;
	  ChapInput(auth, &pkt[1], len - 1);
	  break;

	default:
	  Log(LG_AUTH, ("[%s] EAP: unknown type %d", lnk->name, type));
	  AuthFinish(AUTH_PEER_TO_SELF, FALSE);
      }
      break;

    case EAP_SUCCESS:
      AuthFinish(AUTH_SELF_TO_PEER, TRUE);
      return;

    case EAP_FAILURE:
      AuthFinish(AUTH_SELF_TO_PEER, FALSE);
      return;

    default:
      Log(LG_AUTH, ("[%s] EAP: unknown code %d", lnk->name, auth->code));
      AuthFinish(AUTH_PEER_TO_SELF, FALSE);
  }

}

/*
 * EapRadiusProxy()
 *
 * Proxy EAP Requests from/to the RADIUS server
 */

static void
EapRadiusProxy(AuthData auth, const u_char *pkt, u_short len)
{
  int		data_len = len - 1;
  u_char	*data = NULL, type = 0;
  Auth		const a = &lnk->lcp.auth;
  EapInfo	const eap = &a->eap;
  struct fsmheader	lh;

  if (pkt != NULL) {
    data = data_len > 0 ? (u_char *) &pkt[1] : NULL;
    type = pkt[0];
  }

  if (auth->code == EAP_RESPONSE && type == EAP_TYPE_IDENT) {
    TimerStop(&eap->identTimer);
    if (data_len >= AUTH_MAX_AUTHNAME) {
      Log(LG_AUTH, ("[%s] EAP-RADIUS: Identity to big (%d), truncating",
	lnk->name, data_len));
        data_len = AUTH_MAX_AUTHNAME - 1;
    }
    memset(eap->identity, 0, sizeof(eap->identity));
    strncpy(eap->identity, data, data_len);
    Log(LG_AUTH, ("[%s] EAP-RADIUS: Identity:%s", lnk->name, eap->identity));
  }

  TimerStop(&eap->reqTimer);

  /* prepare packet */
  lh.code = auth->code;
  lh.id = auth->id;
  lh.length = htons(len + sizeof(lh));

  auth->params.eapmsg = Malloc(MB_AUTH, len + sizeof(lh));
  memcpy(auth->params.eapmsg, &lh, sizeof(lh));
  memcpy(&auth->params.eapmsg[sizeof(lh)], pkt, len);

  auth->params.eapmsg_len = len + sizeof(lh);
  strlcpy(auth->params.authname, eap->identity, sizeof(auth->params.authname));

  auth->finish = EapRadiusProxyFinish;
  AuthAsyncStart(auth);
  
}

/*
 * RadiusEapProxyFinish()
 *
 * Return point from the asynch RADIUS EAP Proxy Handler.
 * 
 */
 
static void
EapRadiusProxyFinish(AuthData auth)
{
  Auth		const a = &lnk->lcp.auth;
  EapInfo	eap = &a->eap;
  
  Log(LG_AUTH, ("[%s] EAP-RADIUS: RadiusEapProxyFinish: status %s", 
    lnk->name, AuthStatusText(auth->status)));

  /* this shouldn't happen normally, however be liberal */
  if (a->params.eapmsg == NULL) {
    struct fsmheader	lh;

    Log(LG_AUTH, ("[%s] EAP-RADIUS: Warning, rec'd empty EAP-Message", 
      lnk->name));
    /* prepare packet */
    lh.code = auth->status == AUTH_STATUS_SUCCESS ? EAP_SUCCESS : EAP_FAILURE;
    lh.id = auth->id;
    lh.length = htons(sizeof(lh));

    a->params.eapmsg = Malloc(MB_AUTH, sizeof(lh));
    memcpy(a->params.eapmsg, &lh, sizeof(lh));
    a->params.eapmsg_len = sizeof(lh);
  }

  if (a->params.eapmsg != NULL) {
    eap->retry = AUTH_RETRIES;
    
    EapRadiusSendMsg(eap);    
    if (auth->status == AUTH_STATUS_UNDEF)
      TimerStart(&eap->reqTimer);
  }

  if (auth->status == AUTH_STATUS_FAIL) {
    AuthFinish(AUTH_PEER_TO_SELF, FALSE);
  } else if (auth->status == AUTH_STATUS_SUCCESS) {
    AuthFinish(AUTH_PEER_TO_SELF, TRUE);
  } 

  AuthDataDestroy(auth);  
}

/*
 * EapRadiusSendMsg()
 *
 * Send an EAP Message to the peer
 */

static void
EapRadiusSendMsg(void *ptr)
{
  Mbuf		bp;
  Auth		const a = &lnk->lcp.auth;
  FsmHeader	const f = (FsmHeader)a->params.eapmsg;

  if (a->params.eapmsg_len > 4) {
    Log(LG_AUTH, ("[%s] EAP-RADIUS: send  %s  Type %s #%d len:%d ",
      lnk->name, EapCode(f->code), EapType(a->params.eapmsg[4]),
      f->id, htons(f->length)));
  } else {
    Log(LG_AUTH, ("[%s] EAP-RADIUS: send  %s  #%d len:%d ",
      lnk->name, EapCode(f->code), f->id, htons(f->length)));
  } 

  bp = mballoc(MB_AUTH, a->params.eapmsg_len);
  memcpy(MBDATA(bp), a->params.eapmsg, a->params.eapmsg_len);
  NgFuncWritePppFrame(lnk->bundleIndex, PROTO_EAP, bp);
}

/*
 * EapRadiusSendMsgTimeout()
 *
 * Timer expired for reply to our request
 */

static void
EapRadiusSendMsgTimeout(void *ptr)
{
  EapInfo	const eap = (EapInfo) ptr;

  TimerStop(&eap->reqTimer);
  if (--eap->retry > 0) {
    TimerStart(&eap->reqTimer);
    EapRadiusSendMsg(eap);
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
 * EapStat()
 */

int
EapStat(int ac, char *av[], void *arg)
{
  EapInfo	const eap = &lnk->lcp.auth.eap;

  Printf("\tIdentity     : %s\r\n", eap->identity);
  Printf("EAP options\r\n");
  OptStat(&eap->conf.options, gConfList);

  return (0);
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
    case EAP_TYPE_EAP_TLS:
      return("TLS");
    case EAP_TYPE_MSCHAP_V2:
      return("MS-CHAPv2");
    case EAP_TYPE_EAP_TTLS:
      return("TTLS");
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
      return 1;

    default:
      return 0;
  }
}

/*
 * EapSetCommand()
 */

static int
EapSetCommand(int ac, char *av[], void *arg)
{
  EapInfo	const eap = &lnk->lcp.auth.eap;

  if (ac == 0)
    return(-1);

  switch ((intptr_t)arg) {

    case SET_ACCEPT:
      AcceptCommand(ac, av, &eap->conf.options, gConfList);
      break;

    case SET_DENY:
      DenyCommand(ac, av, &eap->conf.options, gConfList);
      break;

    case SET_ENABLE:
      EnableCommand(ac, av, &eap->conf.options, gConfList);
      break;

    case SET_DISABLE:
      DisableCommand(ac, av, &eap->conf.options, gConfList);
      break;

    case SET_YES:
      YesCommand(ac, av, &eap->conf.options, gConfList);
      break;

    case SET_NO:
      NoCommand(ac, av, &eap->conf.options, gConfList);
      break;

    default:
      assert(0);
  }

  return(0);
}
