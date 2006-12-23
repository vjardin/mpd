
/*
 * ccp.c
 *
 * Written by Archie Cobbs <archie@freebsd.org>
 * Copyright (c) 1995-1999 Whistle Communications, Inc. All rights reserved.
 * See ``COPYRIGHT.whistle''
 */

#include "ppp.h"
#include "ccp.h"
#include "fsm.h"
#include "ngfunc.h"

#include <netgraph/ng_message.h>
#ifdef __DragonFly__
#include <netgraph/ppp/ng_ppp.h>
#include <netgraph/socket/ng_socket.h>
#else
#include <netgraph/ng_ppp.h>
#include <netgraph/ng_socket.h>
#endif
#include <netgraph.h>

/*
 * DEFINITIONS
 */

  #define CCP_MAXFAILURE	7

  #define CCP_KNOWN_CODES	(   (1 << CODE_CONFIGREQ)	\
				  | (1 << CODE_CONFIGACK)	\
				  | (1 << CODE_CONFIGNAK)	\
				  | (1 << CODE_CONFIGREJ)	\
				  | (1 << CODE_TERMREQ)		\
				  | (1 << CODE_TERMACK)		\
				  | (1 << CODE_CODEREJ)		\
				  | (1 << CODE_RESETREQ)	\
				  | (1 << CODE_RESETACK)	)

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
 * INTERNAL FUNCTIONS
 */

  static void		CcpConfigure(Fsm fp);
  static u_char		*CcpBuildConfigReq(Fsm fp, u_char *cp);
  static void		CcpDecodeConfig(Fsm f, FsmOption a, int num, int mode);
  static void		CcpLayerUp(Fsm fp);
  static void		CcpLayerDown(Fsm fp);
  static void		CcpFailure(Fsm f, enum fsmfail reason);
  static void		CcpRecvResetReq(Fsm fp, int id, Mbuf bp);
  static void		CcpRecvResetAck(Fsm fp, int id, Mbuf bp);

  static int		CcpCheckEncryption(void);
  static int		CcpSetCommand(int ac, char *av[], void *arg);
  static CompType	CcpFindComp(int type, int *indexp);
  static const char	*CcpTypeName(int type);

/*
 * GLOBAL VARIABLES
 */

  const struct cmdtab CcpSetCmds[] = {
    { "accept [opt ...]",		"Accept option",
	CcpSetCommand, NULL, (void *) SET_ACCEPT },
    { "deny [opt ...]",			"Deny option",
	CcpSetCommand, NULL, (void *) SET_DENY },
    { "enable [opt ...]",		"Enable option",
	CcpSetCommand, NULL, (void *) SET_ENABLE },
    { "disable [opt ...]",		"Disable option",
	CcpSetCommand, NULL, (void *) SET_DISABLE },
    { "yes [opt ...]",			"Enable and accept option",
	CcpSetCommand, NULL, (void *) SET_YES },
    { "no [opt ...]",			"Disable and deny option",
	CcpSetCommand, NULL, (void *) SET_NO },
    { NULL },
  };

  /* MPPE option indicies */
  int		gMppcCompress;
  int		gMppe40;
  int		gMppe56;
  int		gMppe128;
  int		gMppcStateless;
  

/*
 * INTERNAL VARIABLES
 */

  /* MPPE options */
  static const struct {
    const char	*name;
    int		*indexp;
  } gMppcOptions[] = {
    { "mpp-compress",	&gMppcCompress },
    { "mpp-e40",	&gMppe40 },
    { "mpp-e56",	&gMppe56 },
    { "mpp-e128",	&gMppe128 },
    { "mpp-stateless",	&gMppcStateless },
  };
  #define CCP_NUM_MPPC_OPT	(sizeof(gMppcOptions) / sizeof(*gMppcOptions))

  /* These should be listed in order of preference */
  static const CompType		gCompTypes[] = {
    &gCompMppcInfo,
#ifdef COMPRESSION_STAC
    &gCompStacInfo,
#endif
#ifdef COMPRESSION_DEFLATE
    &gCompDeflateInfo,
#endif
#ifdef COMPRESSION_PRED1
    &gCompPred1Info,
#endif
  };
  #define CCP_NUM_PROTOS	(sizeof(gCompTypes) / sizeof(*gCompTypes))

  /* Corresponding option list */
  static const struct confinfo	*gConfList;

  /* FSM Initializer */
  static const struct fsmtype gCcpFsmType = {
    "CCP",
    PROTO_CCP,
    CCP_KNOWN_CODES,
    LG_CCP, LG_CCP2,
    FALSE,
    NULL,
    CcpLayerUp,
    CcpLayerDown,
    NULL,
    NULL,
    CcpBuildConfigReq,
    CcpDecodeConfig,
    CcpConfigure,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    CcpFailure,
    CcpRecvResetReq,
    CcpRecvResetAck,
    NULL,
  };

  /* Names for different types of compression */
  static const struct ccpname {
    u_char	type;
    const char	*name;
  } gCcpTypeNames[] = {
    { CCP_TY_OUI,		"OUI" },
    { CCP_TY_PRED1,		"PRED1" },
    { CCP_TY_PRED2,		"PRED2" },
    { CCP_TY_PUDDLE,		"PUDDLE" },
    { CCP_TY_HWPPC,		"HWPPC" },
    { CCP_TY_STAC,		"STAC" },
    { CCP_TY_MPPC,		"MPPC" },
    { CCP_TY_GAND,		"GAND" },
    { CCP_TY_V42BIS,		"V42BIS" },
    { CCP_TY_BSD,		"BSD" },
    { CCP_TY_LZS_DCP,		"LZS-DCP" },
    { CCP_TY_DEFLATE24,		"DEFLATE24" },
    { CCP_TY_DCE,		"DCE" },
    { CCP_TY_DEFLATE,		"DEFLATE" },
    { CCP_TY_V44,		"V.44/LZJH" },
    { 0,			NULL },
  };

/*
 * CcpInit()
 */

void
CcpInit(void)
{
  CcpState	ccp = &bund->ccp;

  /* Init CCP state for this bundle */
  memset(ccp, 0, sizeof(*ccp));
  FsmInit(&ccp->fsm, &gCcpFsmType);
  ccp->fsm.conf.maxfailure = CCP_MAXFAILURE;

  /* Construct options list if we haven't done so already */
  if (gConfList == NULL) {
    struct confinfo	*ci;
    int			j, k;

    ci = Malloc(MB_COMP, (CCP_NUM_PROTOS + CCP_NUM_MPPC_OPT + 1) * sizeof(*ci));
    for (k = 0; k < CCP_NUM_PROTOS; k++) {
      ci[k].option = k;
      ci[k].peered = TRUE;
      ci[k].name = gCompTypes[k]->name;
    }

    /* Add MPPE options (YAMCH: yet another microsoft compatibility hack) */
    for (j = 0; j < CCP_NUM_MPPC_OPT; j++, k++) {
      ci[k].option = k;
      ci[k].peered = TRUE;
      ci[k].name = gMppcOptions[j].name;
      *gMppcOptions[j].indexp = k;
    }

    /* Terminate list */
    ci[k].name = NULL;
    gConfList = (const struct confinfo *) ci;
  }
}

/*
 * CcpConfigure()
 */

static void
CcpConfigure(Fsm fp)
{
  CcpState	const ccp = &bund->ccp;
  int		k;

  /* Reset state */
  ccp->self_reject = 0;
  ccp->peer_reject = 0;
  ccp->crypt_check = 0;
  ccp->xmit = NULL;
  ccp->recv = NULL;
  for (k = 0; k < CCP_NUM_PROTOS; k++) {
    CompType	const ct = gCompTypes[k];

    if (ct->Configure)
      (*ct->Configure)();
  }
}

/*
 * CcpRecvMsg()
 */

void
CcpRecvMsg(struct ng_mesg *msg, int len)
{
  CcpState	const ccp = &bund->ccp;
  Fsm		const fp = &ccp->fsm;

  switch (msg->header.typecookie) {
    case NGM_MPPC_COOKIE:
      switch (msg->header.cmd) {
	case NGM_MPPC_RESETREQ: {
	    CcpSendResetReq();
	    return;
	  }
	default:
	  break;
      }
      break;
#ifdef COMPRESSION_DEFLATE
    case NGM_DEFLATE_COOKIE:
      switch (msg->header.cmd) {
	case NGM_DEFLATE_RESETREQ: {
	    CcpSendResetReq();
	    return;
	  }
	default:
	  break;
      }
      break;
#endif
    default:
      break;
  }

  /* Unknown! */
  Log(LG_ERR, ("%s: rec'd unknown netgraph message: cookie=%d, cmd=%d",
    Pref(fp), msg->header.typecookie, msg->header.cmd));
}

/*
 * CcpUp()
 */

void
CcpUp(void)
{
  FsmUp(&bund->ccp.fsm);
}

/*
 * CcpDown()
 */

void
CcpDown(void)
{
  FsmDown(&bund->ccp.fsm);
}

/*
 * CcpOpen()
 */

void
CcpOpen(void)
{
  FsmOpen(&bund->ccp.fsm);
}

/*
 * CcpClose()
 */

void
CcpClose(void)
{
  FsmClose(&bund->ccp.fsm);
}

/*
 * CcpFailure()
 *
 * If we fail, just shut down and stop trying. However, if encryption
 * was required and MPPE encryption was enabled, then die here as well.
 */

static void
CcpFailure(Fsm f, enum fsmfail reason)
{
  CcpClose();
  CcpCheckEncryption();
}

/*
 * CcpStat()
 */

int
CcpStat(int ac, char *av[], void *arg)
{
  CcpState	const ccp = &bund->ccp;

  Printf("%s [%s]\r\n", Pref(&ccp->fsm), FsmStateName(ccp->fsm.state));
  Printf("Enabled protocols:\r\n");
  OptStat(&ccp->options, gConfList);

  Printf("Incoming decompression:\r\n");
  Printf("\tProtocol: %s (%s)\r\n", !ccp->xmit ? "none" : ccp->xmit->name,
    (ccp->xmit && ccp->xmit->Describe) ? (*ccp->xmit->Describe)(COMP_DIR_XMIT) : "");

  Printf("Outgoing compression:\r\n");
  Printf("\tProtocol: %s (%s)\r\n", !ccp->recv ? "none" : ccp->recv->name,
    (ccp->recv && ccp->recv->Describe) ? (*ccp->recv->Describe)(COMP_DIR_RECV) : "");

  return(0);
}

/*
 * CcpSendResetReq()
 */

void
CcpSendResetReq(void)
{
  CcpState	const ccp = &bund->ccp;
  CompType	const ct = ccp->recv;
  Fsm		const fp = &ccp->fsm;
  Mbuf		bp = NULL;

  assert(ct);
  if (ct->SendResetReq)
    bp = (*ct->SendResetReq)();
  Log(LG_CCP, ("%s: SendResetReq #%d link %d (%s)", 
    Pref(fp), fp->reqid, 0, FsmStateName(fp->state)));
  FsmOutputMbuf(fp, CODE_RESETREQ, fp->reqid++, bp);
}

/*
 * CcpRecvResetReq()
 */

static void
CcpRecvResetReq(Fsm fp, int id, Mbuf bp)
{
  CcpState	const ccp = &bund->ccp;
  CompType	const ct = ccp->xmit;
  int		noAck = 0;

  bp = (ct && ct->RecvResetReq) ? (*ct->RecvResetReq)(id, bp, &noAck) : NULL;
  if (!noAck) {
    Log(LG_CCP, ("%s: SendResetAck #%d link %d (%s)",
	Pref(fp), fp->reqid, 0, FsmStateName(fp->state)));
    FsmOutputMbuf(fp, CODE_RESETACK, id, bp);
  }
}

/*
 * CcpRecvResetAck()
 */

static void
CcpRecvResetAck(Fsm fp, int id, Mbuf bp)
{
  CcpState	const ccp = &bund->ccp;
  CompType	const ct = ccp->recv;

  if (ct && ct->RecvResetAck)
    (*ct->RecvResetAck)(id, bp);
}

/*
 * CcpInput()
 */

void
CcpInput(Mbuf bp, int linkNum)
{
  FsmInput(&bund->ccp.fsm, bp, linkNum);
}

/*
 * CcpDataOutput()
 *
 * Compress a frame. Consumes the original packet.
 */

Mbuf
CcpDataOutput(Mbuf plain)
{
  CcpState	const ccp = &bund->ccp;
  Mbuf		comp;

  LogDumpBp(LG_CCP3, plain, "%s: xmit plain", Pref(&ccp->fsm));

/* Compress packet */

  if ((!ccp->xmit) || (!ccp->xmit->Compress))
  {
    Log(LG_ERR, ("%s: no encryption for xmit", Pref(&ccp->fsm)));
    PFREE(plain);
    return(NULL);
  }
  comp = (*ccp->xmit->Compress)(plain);
  LogDumpBp(LG_CCP3, comp, "%s: xmit comp", Pref(&ccp->fsm));

  return(comp);
}

/*
 * CcpDataInput()
 *
 * Decompress incoming packet. If packet got garbled, return NULL.
 * In any case, we consume the packet passed to us.
 */

Mbuf
CcpDataInput(Mbuf comp)
{
  CcpState	const ccp = &bund->ccp;
  Mbuf		plain;

  LogDumpBp(LG_CCP3, comp, "%s: recv comp", Pref(&ccp->fsm));

/* Decompress packet */

  if ((!ccp->recv) || (!ccp->recv->Decompress))
  {
    Log(LG_ERR, ("%s: no compression for recv", Pref(&ccp->fsm)));
    PFREE(comp);
    return(NULL);
  }

  plain = (*ccp->recv->Decompress)(comp);

/* Encrypted ok? */

  if (plain == NULL)
  {
    Log(LG_CCP, ("%s: decompression failed", Pref(&ccp->fsm)));
    return(NULL);
  }
  LogDumpBp(LG_CCP3, plain, "%s: recv plain", Pref(&ccp->fsm));

  return(plain);
}

/*
 * CcpBuildConfigReq()
 */

static u_char *
CcpBuildConfigReq(Fsm fp, u_char *cp)
{
  CcpState	const ccp = &bund->ccp;
  int		type;
  int		ok;

  /* Put in all options that peer hasn't rejected in preferred order */
  for (ccp->xmit = NULL, type = 0; type < CCP_NUM_PROTOS; type++) {
    CompType	const ct = gCompTypes[type];

    if (Enabled(&ccp->options, type) && !CCP_PEER_REJECTED(ccp, type)) {
      cp = (*ct->BuildConfigReq)(cp, &ok);
      if (ok && (!ccp->xmit))
	ccp->xmit = ct;
    }
  }
  return(cp);
}

/*
 * CcpLayerUp()
 */

static void
CcpLayerUp(Fsm fp)
{
  CcpState	const ccp = &bund->ccp;
  struct ngm_connect    cn;

  /* If nothing was negotiated in either direction, close CCP */
  if ((!ccp->recv || !(*ccp->recv->Negotiated)(COMP_DIR_RECV))
      && (!ccp->xmit || !(*ccp->xmit->Negotiated)(COMP_DIR_XMIT))) {
    Log(LG_CCP, ("%s: No compression negotiated", Pref(fp)));
    FsmFailure(fp, FAIL_NEGOT_FAILURE);
    return;
  }

  /* Check for required encryption */
  if (CcpCheckEncryption() < 0) {
    return;
  }

  /* Initialize each direction */
  if (ccp->xmit != NULL && ccp->xmit->Init != NULL
      && (*ccp->xmit->Init)(COMP_DIR_XMIT) < 0) {
    Log(LG_CCP, ("%s: %scompression init failed", Pref(fp), ""));
    FsmFailure(fp, FAIL_NEGOT_FAILURE);		/* XXX */
    return;
  }
  if (ccp->recv != NULL && ccp->recv->Init != NULL
      && (*ccp->recv->Init)(COMP_DIR_RECV) < 0) {
    Log(LG_CCP, ("%s: %scompression init failed", Pref(fp), "de"));
    FsmFailure(fp, FAIL_NEGOT_FAILURE);		/* XXX */
    return;
  }

  if (ccp->xmit != NULL && ccp->xmit->Compress != NULL) {
    /* Connect a hook from the bpf node to our socket node */
    snprintf(cn.path, sizeof(cn.path), "%s", MPD_HOOK_PPP);
    snprintf(cn.ourhook, sizeof(cn.ourhook), "%s", NG_PPP_HOOK_COMPRESS);
    snprintf(cn.peerhook, sizeof(cn.peerhook), "%s", NG_PPP_HOOK_COMPRESS);
    if (NgSendMsg(bund->csock, ".",
	    NGM_GENERIC_COOKIE, NGM_CONNECT, &cn, sizeof(cn)) < 0) {
	Log(LG_ERR, ("[%s] can't connect %s hook: %s",
        bund->name, NG_PPP_HOOK_COMPRESS, strerror(errno)));
    }
  }

  if (ccp->recv != NULL && ccp->recv->Decompress != NULL) {
    /* Connect a hook from the bpf node to our socket node */
    snprintf(cn.path, sizeof(cn.path), "%s", MPD_HOOK_PPP);
    snprintf(cn.ourhook, sizeof(cn.ourhook), "%s", NG_PPP_HOOK_DECOMPRESS);
    snprintf(cn.peerhook, sizeof(cn.peerhook), "%s", NG_PPP_HOOK_DECOMPRESS);
    if (NgSendMsg(bund->csock, ".",
	    NGM_GENERIC_COOKIE, NGM_CONNECT, &cn, sizeof(cn)) < 0) {
	Log(LG_ERR, ("[%s] can't connect %s hook: %s",
        bund->name, NG_PPP_HOOK_DECOMPRESS, strerror(errno)));
    }
  }

  /* Report what we're doing */
  Log(LG_CCP, ("  Compress using: %s (%s)", !ccp->xmit ? "none" : ccp->xmit->name,
    (ccp->xmit && ccp->xmit->Describe) ? (*ccp->xmit->Describe)(COMP_DIR_XMIT) : ""));
  Log(LG_CCP, ("Decompress using: %s (%s)", !ccp->recv ? "none" : ccp->recv->name,
    (ccp->recv && ccp->recv->Describe) ? (*ccp->recv->Describe)(COMP_DIR_RECV) : ""));

  /* Update PPP node config */
#if NGM_PPP_COOKIE < 940897794
  bund->pppConfig.enableCompression = (ccp->xmit != NULL);
  bund->pppConfig.enableDecompression = (ccp->recv != NULL);
#else
  bund->pppConfig.bund.enableCompression = (ccp->xmit != NULL)?ccp->xmit->mode:0;
  bund->pppConfig.bund.enableDecompression = (ccp->recv != NULL)?ccp->recv->mode:0;
#endif
  NgFuncSetConfig();

  /* Update interface MTU */
  BundUpdateParams();
}

/*
 * CcpLayerDown()
 */

static void
CcpLayerDown(Fsm fp)
{
  CcpState	const ccp = &bund->ccp;
  struct ngm_rmhook rm;

  if (ccp->xmit != NULL && ccp->xmit->Compress != NULL) {
    /* Disconnect hook. */
    snprintf(rm.ourhook, sizeof(rm.ourhook), "%s", NG_PPP_HOOK_COMPRESS);
    if (NgSendMsg(bund->csock, ".",
	    NGM_GENERIC_COOKIE, NGM_RMHOOK, &rm, sizeof(rm)) < 0) {
	Log(LG_ERR, ("can't remove hook %s: %s", NG_PPP_HOOK_COMPRESS, strerror(errno)));
    }
  }
  
  if (ccp->recv != NULL && ccp->recv->Decompress != NULL) {
    /* Disconnect hook. */
    snprintf(rm.ourhook, sizeof(rm.ourhook), "%s", NG_PPP_HOOK_DECOMPRESS);
    if (NgSendMsg(bund->csock, ".",
	    NGM_GENERIC_COOKIE, NGM_RMHOOK, &rm, sizeof(rm)) < 0) {
	Log(LG_ERR, ("can't remove hook %s: %s", NG_PPP_HOOK_DECOMPRESS, strerror(errno)));
    }
  }
  if (ccp->recv && ccp->recv->Cleanup)
    (*ccp->recv->Cleanup)(COMP_DIR_RECV);
  if (ccp->xmit && ccp->xmit->Cleanup)
    (*ccp->xmit->Cleanup)(COMP_DIR_XMIT);
}

/*
 * CcpDecodeConfig()
 */

static void
CcpDecodeConfig(Fsm fp, FsmOption list, int num, int mode)
{
  CcpState	const ccp = &bund->ccp;
  u_int		ackSizeSave, rejSizeSave;
  int		k, rej;

  /* Forget our previous choice on new request */
  if (mode == MODE_REQ)
    ccp->recv = NULL;

  /* Decode each config option */
  for (k = 0; k < num; k++) {
    FsmOption	const opt = &list[k];
    int		index;
    CompType	ct;

    Log(LG_CCP, (" %s", CcpTypeName(opt->type)));
    if ((ct = CcpFindComp(opt->type, &index)) == NULL) {
      if (mode == MODE_REQ) {
	Log(LG_CCP, ("   Not supported"));
	FsmRej(fp, opt);
      }
      continue;
    }
    switch (mode) {
      case MODE_REQ:
	ackSizeSave = gAckSize;
	rejSizeSave = gRejSize;
	rej = (!Acceptable(&ccp->options, index)
	  || CCP_SELF_REJECTED(ccp, index)
	  || (ccp->recv && ccp->recv != ct));
	if (rej) {
	  (*ct->DecodeConfig)(fp, opt, MODE_NOP);
	  FsmRej(fp, opt);
	  break;
	}
	(*ct->DecodeConfig)(fp, opt, mode);
	if (gRejSize != rejSizeSave) {		/* we rejected it */
	  CCP_SELF_REJ(ccp, index);
	  break;
	}
	if (gAckSize != ackSizeSave)		/* we accepted it */
	  ccp->recv = ct;
	break;

      case MODE_REJ:
	(*ct->DecodeConfig)(fp, opt, mode);
	CCP_PEER_REJ(ccp, index);
	break;

      case MODE_NAK:
      case MODE_NOP:
	(*ct->DecodeConfig)(fp, opt, mode);
	break;
    }
  }
}

/*
 * CcpSubtractBloat()
 *
 * Given that "size" is our MTU, return the maximum length frame
 * we can compress without the result being longer than "size".
 */

int
CcpSubtractBloat(int size)
{
  CcpState	const ccp = &bund->ccp;

  /* Account for CCP's protocol number overhead */
  if (OPEN_STATE(ccp->fsm.state))
    size -= CCP_OVERHEAD;

  /* Account for transmit compression overhead */
  if (OPEN_STATE(ccp->fsm.state) && ccp->xmit && ccp->xmit->SubtractBloat)
    size = (*ccp->xmit->SubtractBloat)(size);

  /* Done */
  return(size);
}

/*
 * CcpCheckEncryption()
 *
 * Because MPPE is negotiated as an option to MPPC compression,
 * we have to check for encryption required when CCP comes up.
 */

static int
CcpCheckEncryption(void)
{
  CcpState	const ccp = &bund->ccp;

  /* Already checked? */
  if (ccp->crypt_check)
    return(0);
  ccp->crypt_check = 1;

  /* Is encryption required? */
  if (Enabled(&bund->conf.auth.options, AUTH_CONF_MPPC_POL)) {
    if (bund->params.msoft.policy != MPPE_POLICY_REQUIRED) 
      return(0);
  } else {
    if (!Enabled(&bund->conf.options, BUND_CONF_CRYPT_REQD))
      return(0);
  }

  /* Was MPPE encryption enabled? If not, ignore requirement */
  if (!Enabled(&ccp->options, gMppe40)
      && !Enabled(&ccp->options, gMppe56)
      && !Enabled(&ccp->options, gMppe128)
      && !Enabled(&bund->conf.auth.options, AUTH_CONF_MPPC_POL))
    return(0);

  /* Make sure MPPE was negotiated in both directions */
  if (!OPEN_STATE(ccp->fsm.state)
      || !ccp->xmit || ccp->xmit->type != CCP_TY_MPPC
      || !ccp->recv || ccp->recv->type != CCP_TY_MPPC
      || !(ccp->mppc.recv_bits & MPPE_BITS)
      || !(ccp->mppc.xmit_bits & MPPE_BITS))
    goto fail;

  /* Looks OK */
  return(0);

fail:
  Log(LG_ERR, ("%s: encryption required, but MPPE was not"
    " negotiated in both directions", Pref(&ccp->fsm)));
  FsmFailure(&ccp->fsm, FAIL_CANT_ENCRYPT);
  FsmFailure(&bund->ipcp.fsm, FAIL_CANT_ENCRYPT);
  return(-1);
}

/*
 * CcpSetCommand()
 */

static int
CcpSetCommand(int ac, char *av[], void *arg)
{
  CcpState	const ccp = &bund->ccp;

  if (ac == 0)
    return(-1);
  switch ((intptr_t)arg) {
    case SET_ACCEPT:
      AcceptCommand(ac, av, &ccp->options, gConfList);
      break;

    case SET_DENY:
      DenyCommand(ac, av, &ccp->options, gConfList);
      break;

    case SET_ENABLE:
      EnableCommand(ac, av, &ccp->options, gConfList);
      break;

    case SET_DISABLE:
      DisableCommand(ac, av, &ccp->options, gConfList);
      break;

    case SET_YES:
      YesCommand(ac, av, &ccp->options, gConfList);
      break;

    case SET_NO:
      NoCommand(ac, av, &ccp->options, gConfList);
      break;

    default:
      assert(0);
  }
  return(0);
}

/*
 * CcpFindComp()
 */

static CompType
CcpFindComp(int type, int *indexp)
{
  int	k;

  for (k = 0; k < CCP_NUM_PROTOS; k++) {
    if (gCompTypes[k]->type == type) {
      if (indexp)
	*indexp = k;
      return(gCompTypes[k]);
    }
  }
  return(NULL);
}

/*
 * CcpTypeName()
 */

static const char *
CcpTypeName(int type)
{
  const struct ccpname	*p;
  static char		buf[20];

  for (p = gCcpTypeNames; p->name; p++) {
    if (p->type == type)
      return(p->name);
  }
  snprintf(buf, sizeof(buf), "UNKNOWN[%d]", type);
  return(buf);
}

