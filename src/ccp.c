
/*
 * ccp.c
 *
 * Written by Archie Cobbs <archie@freebsd.org>
 * Copyright (c) 1995-1999 Whistle Communications, Inc. All rights reserved.
 * See ``COPYRIGHT.whistle''
 */

#include "defs.h"
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
  static void		CcpUnConfigure(Fsm fp);
  static u_char		*CcpBuildConfigReq(Fsm fp, u_char *cp);
  static void		CcpDecodeConfig(Fsm f, FsmOption a, int num, int mode);
  static void		CcpLayerUp(Fsm fp);
  static void		CcpLayerDown(Fsm fp);
  static void		CcpFailure(Fsm f, enum fsmfail reason);
  static void		CcpRecvResetReq(Fsm fp, int id, Mbuf bp);
  static void		CcpRecvResetAck(Fsm fp, int id, Mbuf bp);

  static int		CcpCheckEncryption(Bund b);
  static int		CcpSetCommand(Context ctx, int ac, char *av[], void *arg);
  static CompType	CcpFindComp(int type, int *indexp);
  static const char	*CcpTypeName(int type, char *buf, size_t len);

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
  int		gMppePolicy;
  

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
    { "mppe-policy",	&gMppePolicy },
  };
  #define CCP_NUM_MPPC_OPT	(sizeof(gMppcOptions) / sizeof(*gMppcOptions))

  /* These should be listed in order of preference */
  static const CompType		gCompTypes[] = {
    &gCompMppcInfo,
#ifdef COMPRESSION_DEFLATE
#ifdef USE_NG_DEFLATE
    &gCompDeflateInfo,
#endif
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
    CcpUnConfigure,
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
CcpInit(Bund b)
{
  CcpState	ccp = &b->ccp;

  /* Init CCP state for this bundle */
  memset(ccp, 0, sizeof(*ccp));
  FsmInit(&ccp->fsm, &gCcpFsmType, b);
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
    Bund 	b = (Bund)fp->arg;
  CcpState	const ccp = &b->ccp;
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
      (*ct->Configure)(b);
  }
}

/*
 * CcpUnConfigure()
 */

static void
CcpUnConfigure(Fsm fp)
{
    Bund 	b = (Bund)fp->arg;
  CcpState	const ccp = &b->ccp;
  int		k;

  /* Reset state */
  ccp->self_reject = 0;
  ccp->peer_reject = 0;
  ccp->crypt_check = 0;
  ccp->xmit = NULL;
  ccp->recv = NULL;
  for (k = 0; k < CCP_NUM_PROTOS; k++) {
    CompType	const ct = gCompTypes[k];

    if (ct->UnConfigure)
      (*ct->UnConfigure)(b);
  }
}

/*
 * CcpRecvMsg()
 */

void
CcpRecvMsg(Bund b, struct ng_mesg *msg, int len)
{
  CcpState	const ccp = &b->ccp;
  Fsm		const fp = &ccp->fsm;

  switch (msg->header.typecookie) {
    case NGM_MPPC_COOKIE:
      switch (msg->header.cmd) {
	case NGM_MPPC_RESETREQ: {
	    CcpSendResetReq(b);
	    return;
	  }
	default:
	  break;
      }
      break;
#ifdef COMPRESSION_DEFLATE
#ifdef USE_NG_DEFLATE
    case NGM_DEFLATE_COOKIE:
      switch (msg->header.cmd) {
	case NGM_DEFLATE_RESETREQ: {
	    CcpSendResetReq(b);
	    return;
	  }
	default:
	  break;
      }
      break;
#endif
#endif
#ifdef COMPRESSION_PRED1
#ifdef USE_NG_PRED1
    case NGM_PRED1_COOKIE:
      switch (msg->header.cmd) {
	case NGM_PRED1_RESETREQ: {
	    CcpSendResetReq(b);
	    return;
	  }
	default:
	  break;
      }
      break;
#endif
#endif
    default:
      break;
  }

  /* Unknown! */
  Log(LG_ERR, ("[%s] %s: rec'd unknown netgraph message: cookie=%d, cmd=%d",
    Pref(fp), Fsm(fp), msg->header.typecookie, msg->header.cmd));
}

/*
 * CcpUp()
 */

void
CcpUp(Bund b)
{
  FsmUp(&b->ccp.fsm);
}

/*
 * CcpDown()
 */

void
CcpDown(Bund b)
{
  FsmDown(&b->ccp.fsm);
}

/*
 * CcpOpen()
 */

void
CcpOpen(Bund b)
{
  FsmOpen(&b->ccp.fsm);
}

/*
 * CcpClose()
 */

void
CcpClose(Bund b)
{
  FsmClose(&b->ccp.fsm);
}

/*
 * CcpOpenCmd()
 */

void
CcpOpenCmd(Context ctx)
{
  FsmOpen(&ctx->bund->ccp.fsm);
}

/*
 * CcpCloseCmd()
 */

void
CcpCloseCmd(Context ctx)
{
  FsmClose(&ctx->bund->ccp.fsm);
}

/*
 * CcpFailure()
 *
 * If we fail, just shut down and stop trying. However, if encryption
 * was required and MPPE encryption was enabled, then die here as well.
 */

static void
CcpFailure(Fsm fp, enum fsmfail reason)
{
    Bund 	b = (Bund)fp->arg;
  CcpClose(b);
  CcpCheckEncryption(b);
}

/*
 * CcpStat()
 */

int
CcpStat(Context ctx, int ac, char *av[], void *arg)
{
  CcpState	const ccp = &ctx->bund->ccp;
  char		buf[64];

  Printf("[%s] %s [%s]\r\n", Pref(&ccp->fsm), Fsm(&ccp->fsm), FsmStateName(ccp->fsm.state));
  Printf("Enabled protocols:\r\n");
  OptStat(ctx, &ccp->options, gConfList);

  Printf("Outgoing compression:\r\n");
  Printf("\tProto\t: %s (%s)\r\n", !ccp->xmit ? "none" : ccp->xmit->name,
    (ccp->xmit && ccp->xmit->Describe) ? (*ccp->xmit->Describe)(ctx->bund, COMP_DIR_XMIT, buf, sizeof(buf)) : "");
  if (ccp->xmit && ccp->xmit->Stat)
    ccp->xmit->Stat(ctx, COMP_DIR_XMIT);
  Printf("\tResets\t: %d\r\n", ccp->xmit_resets);

  Printf("Incoming decompression:\r\n");
  Printf("\tProto\t: %s (%s)\r\n", !ccp->recv ? "none" : ccp->recv->name,
    (ccp->recv && ccp->recv->Describe) ? (*ccp->recv->Describe)(ctx->bund, COMP_DIR_RECV, buf, sizeof(buf)) : "");
  if (ccp->recv && ccp->recv->Stat)
    ccp->recv->Stat(ctx, COMP_DIR_RECV);
  Printf("\tResets\t: %d\r\n", ccp->recv_resets);

  return(0);
}

/*
 * CcpSendResetReq()
 */

void
CcpSendResetReq(Bund b)
{
  CcpState	const ccp = &b->ccp;
  CompType	const ct = ccp->recv;
  Fsm		const fp = &ccp->fsm;
  Mbuf		bp = NULL;

  if (ct == NULL) {
    Log(LG_ERR, ("[%s] %s: CcpSendResetReq() call from undefined decompressor!", 
	Pref(fp), Fsm(fp)));
    return;
  }
  
  ccp->recv_resets++;
  if (ct->SendResetReq)
    bp = (*ct->SendResetReq)(b);
  Log(LG_CCP, ("[%s] %s: SendResetReq #%d link %d (%s)", 
    Pref(fp), Fsm(fp), fp->reqid, 0, FsmStateName(fp->state)));
  FsmOutputMbuf(fp, CODE_RESETREQ, fp->reqid++, bp);
}

/*
 * CcpRecvResetReq()
 */

static void
CcpRecvResetReq(Fsm fp, int id, Mbuf bp)
{
    Bund 	b = (Bund)fp->arg;
  CcpState	const ccp = &b->ccp;
  CompType	const ct = ccp->xmit;
  int		noAck = 0;

  ccp->xmit_resets++;
  bp = (ct && ct->RecvResetReq) ? (*ct->RecvResetReq)(b, id, bp, &noAck) : NULL;
  if (!noAck) {
    Log(LG_CCP, ("[%s] %s: SendResetAck #%d link %d (%s)",
	Pref(fp), Fsm(fp), id, 0, FsmStateName(fp->state)));
    FsmOutputMbuf(fp, CODE_RESETACK, id, bp);
  }
}

/*
 * CcpRecvResetAck()
 */

static void
CcpRecvResetAck(Fsm fp, int id, Mbuf bp)
{
    Bund 	b = (Bund)fp->arg;
  CcpState	const ccp = &b->ccp;
  CompType	const ct = ccp->recv;

  if (ct && ct->RecvResetAck)
    (*ct->RecvResetAck)(b, id, bp);
}

/*
 * CcpInput()
 */

void
CcpInput(Bund b, Mbuf bp)
{
  FsmInput(&b->ccp.fsm, bp);
}

/*
 * CcpDataOutput()
 *
 * Compress a frame. Consumes the original packet.
 */

Mbuf
CcpDataOutput(Bund b, Mbuf plain)
{
  CcpState	const ccp = &b->ccp;
  Mbuf		comp;

  LogDumpBp(LG_CCP3, plain, "[%s] %s: xmit plain", Pref(&ccp->fsm), Fsm(&ccp->fsm));

/* Compress packet */

  if ((!ccp->xmit) || (!ccp->xmit->Compress))
  {
    Log(LG_ERR, ("[%s] %s: no encryption for xmit", Pref(&ccp->fsm), Fsm(&ccp->fsm)));
    PFREE(plain);
    return(NULL);
  }
  comp = (*ccp->xmit->Compress)(b, plain);
  LogDumpBp(LG_CCP3, comp, "[%s] %s: xmit comp", Pref(&ccp->fsm), Fsm(&ccp->fsm));

  return(comp);
}

/*
 * CcpDataInput()
 *
 * Decompress incoming packet. If packet got garbled, return NULL.
 * In any case, we consume the packet passed to us.
 */

Mbuf
CcpDataInput(Bund b, Mbuf comp)
{
  CcpState	const ccp = &b->ccp;
  Mbuf		plain;

  LogDumpBp(LG_CCP3, comp, "[%s] %s: recv comp", Pref(&ccp->fsm), Fsm(&ccp->fsm));

/* Decompress packet */

  if ((!ccp->recv) || (!ccp->recv->Decompress))
  {
    Log(LG_ERR, ("[%s] %s: no compression for recv", Pref(&ccp->fsm), Fsm(&ccp->fsm)));
    PFREE(comp);
    return(NULL);
  }

  plain = (*ccp->recv->Decompress)(b, comp);

/* Encrypted ok? */

  if (plain == NULL)
  {
    Log(LG_CCP, ("[%s] %s: decompression failed", Pref(&ccp->fsm), Fsm(&ccp->fsm)));
    return(NULL);
  }
  LogDumpBp(LG_CCP3, plain, "[%s] %s: recv plain", Pref(&ccp->fsm), Fsm(&ccp->fsm));

  return(plain);
}

/*
 * CcpBuildConfigReq()
 */

static u_char *
CcpBuildConfigReq(Fsm fp, u_char *cp)
{
    Bund 	b = (Bund)fp->arg;
  CcpState	const ccp = &b->ccp;
  int		type;
  int		ok;

  /* Put in all options that peer hasn't rejected in preferred order */
  for (ccp->xmit = NULL, type = 0; type < CCP_NUM_PROTOS; type++) {
    CompType	const ct = gCompTypes[type];

    if (Enabled(&ccp->options, type) && !CCP_PEER_REJECTED(ccp, type)) {
      cp = (*ct->BuildConfigReq)(b, cp, &ok);
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
    Bund 	b = (Bund)fp->arg;
  CcpState	const ccp = &b->ccp;
  struct ngm_connect    cn;
  char		buf[64];

  /* If nothing was negotiated in either direction, close CCP */
  if ((!ccp->recv || !(*ccp->recv->Negotiated)(b, COMP_DIR_RECV))
      && (!ccp->xmit || !(*ccp->xmit->Negotiated)(b, COMP_DIR_XMIT))) {
    Log(LG_CCP, ("[%s] %s: No compression negotiated", Pref(fp), Fsm(fp)));
    FsmFailure(fp, FAIL_NEGOT_FAILURE);
    return;
  }

  /* Check for required encryption */
  if (CcpCheckEncryption(b) < 0) {
    return;
  }

  /* Register control messages event as it used only by CCP */
  EventRegister(&b->ctrlEvent, EVENT_READ,
    b->csock, EVENT_RECURRING, BundNgCtrlEvent, b);

  /* Initialize each direction */
  if (ccp->xmit != NULL && ccp->xmit->Init != NULL
      && (*ccp->xmit->Init)(b, COMP_DIR_XMIT) < 0) {
    Log(LG_CCP, ("[%s] %s: %scompression init failed", Pref(fp), Fsm(fp), ""));
    FsmFailure(fp, FAIL_NEGOT_FAILURE);		/* XXX */
    return;
  }
  if (ccp->recv != NULL && ccp->recv->Init != NULL
      && (*ccp->recv->Init)(b, COMP_DIR_RECV) < 0) {
    Log(LG_CCP, ("[%s] %s: %scompression init failed", Pref(fp), Fsm(fp), "de"));
    FsmFailure(fp, FAIL_NEGOT_FAILURE);		/* XXX */
    return;
  }

  if (ccp->xmit != NULL && ccp->xmit->Compress != NULL) {
    /* Connect a hook from the bpf node to our socket node */
    snprintf(cn.path, sizeof(cn.path), "%s", MPD_HOOK_PPP);
    snprintf(cn.ourhook, sizeof(cn.ourhook), "%s", NG_PPP_HOOK_COMPRESS);
    snprintf(cn.peerhook, sizeof(cn.peerhook), "%s", NG_PPP_HOOK_COMPRESS);
    if (NgSendMsg(b->csock, ".",
	    NGM_GENERIC_COOKIE, NGM_CONNECT, &cn, sizeof(cn)) < 0) {
	Log(LG_ERR, ("[%s] can't connect \"%s\"->\"%s\" and \"%s\"->\"%s\": %s",
        b->name, ".", cn.ourhook, cn.path, cn.peerhook, strerror(errno)));
    }
  }

  if (ccp->recv != NULL && ccp->recv->Decompress != NULL) {
    /* Connect a hook from the bpf node to our socket node */
    snprintf(cn.path, sizeof(cn.path), "%s", MPD_HOOK_PPP);
    snprintf(cn.ourhook, sizeof(cn.ourhook), "%s", NG_PPP_HOOK_DECOMPRESS);
    snprintf(cn.peerhook, sizeof(cn.peerhook), "%s", NG_PPP_HOOK_DECOMPRESS);
    if (NgSendMsg(b->csock, ".",
	    NGM_GENERIC_COOKIE, NGM_CONNECT, &cn, sizeof(cn)) < 0) {
	Log(LG_ERR, ("[%s] can't connect \"%s\"->\"%s\" and \"%s\"->\"%s\": %s",
        b->name, ".", cn.ourhook, cn.path, cn.peerhook, strerror(errno)));
    }
  }

  /* Report what we're doing */
  Log(LG_CCP, ("  Compress using: %s (%s)", !ccp->xmit ? "none" : ccp->xmit->name,
    (ccp->xmit && ccp->xmit->Describe) ? (*ccp->xmit->Describe)(b, COMP_DIR_XMIT, buf, sizeof(buf)) : ""));
  Log(LG_CCP, ("Decompress using: %s (%s)", !ccp->recv ? "none" : ccp->recv->name,
    (ccp->recv && ccp->recv->Describe) ? (*ccp->recv->Describe)(b, COMP_DIR_RECV, buf, sizeof(buf)) : ""));

  /* Update PPP node config */
#if NGM_PPP_COOKIE < 940897794
  b->pppConfig.enableCompression = (ccp->xmit != NULL);
  b->pppConfig.enableDecompression = (ccp->recv != NULL);
#else
  b->pppConfig.bund.enableCompression = (ccp->xmit != NULL)?ccp->xmit->mode:0;
  b->pppConfig.bund.enableDecompression = (ccp->recv != NULL)?ccp->recv->mode:0;
#endif
  NgFuncSetConfig(b);

  /* Update interface MTU */
  BundUpdateParams(b);
}

/*
 * CcpLayerDown()
 */

static void
CcpLayerDown(Fsm fp)
{
    Bund 	b = (Bund)fp->arg;
  CcpState	const ccp = &b->ccp;
  struct ngm_rmhook rm;

  /* Update PPP node config */
#if NGM_PPP_COOKIE < 940897794
  b->pppConfig.enableCompression = 0;
  b->pppConfig.enableDecompression = 0;
#else
  b->pppConfig.bund.enableCompression = 0;
  b->pppConfig.bund.enableDecompression = 0;
#endif
  NgFuncSetConfig(b);

  /* Update interface MTU */
  BundUpdateParams(b);
  
  if (ccp->xmit != NULL && ccp->xmit->Compress != NULL) {
    /* Disconnect hook. */
    snprintf(rm.ourhook, sizeof(rm.ourhook), "%s", NG_PPP_HOOK_COMPRESS);
    if (NgSendMsg(b->csock, ".",
	    NGM_GENERIC_COOKIE, NGM_RMHOOK, &rm, sizeof(rm)) < 0) {
	Log(LG_ERR, ("can't remove hook %s: %s", NG_PPP_HOOK_COMPRESS, strerror(errno)));
    }
  }
  
  if (ccp->recv != NULL && ccp->recv->Decompress != NULL) {
    /* Disconnect hook. */
    snprintf(rm.ourhook, sizeof(rm.ourhook), "%s", NG_PPP_HOOK_DECOMPRESS);
    if (NgSendMsg(b->csock, ".",
	    NGM_GENERIC_COOKIE, NGM_RMHOOK, &rm, sizeof(rm)) < 0) {
	Log(LG_ERR, ("can't remove hook %s: %s", NG_PPP_HOOK_DECOMPRESS, strerror(errno)));
    }
  }
  if (ccp->recv && ccp->recv->Cleanup)
    (*ccp->recv->Cleanup)(b, COMP_DIR_RECV);
  if (ccp->xmit && ccp->xmit->Cleanup)
    (*ccp->xmit->Cleanup)(b, COMP_DIR_XMIT);

  ccp->xmit_resets = 0;
  ccp->recv_resets = 0;

  /* Unregister control messages event as it used only by CCP */
  EventUnRegister(&b->ctrlEvent);
}

/*
 * CcpDecodeConfig()
 */

static void
CcpDecodeConfig(Fsm fp, FsmOption list, int num, int mode)
{
    Bund 	b = (Bund)fp->arg;
  CcpState	const ccp = &b->ccp;
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
    char	buf[32];

    Log(LG_CCP, (" %s", CcpTypeName(opt->type, buf, sizeof(buf))));
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
CcpSubtractBloat(Bund b, int size)
{
  CcpState	const ccp = &b->ccp;

  /* Account for transmit compression overhead */
  if (OPEN_STATE(ccp->fsm.state) && ccp->xmit && ccp->xmit->SubtractBloat)
    size = (*ccp->xmit->SubtractBloat)(b, size);

  /* Account for CCP's protocol number overhead */
  if (OPEN_STATE(ccp->fsm.state))
    size -= CCP_OVERHEAD;

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
CcpCheckEncryption(Bund b)
{
  CcpState	const ccp = &b->ccp;

  /* Already checked? */
  if (ccp->crypt_check)
    return(0);
  ccp->crypt_check = 1;

  /* Is encryption required? */
  if (Enabled(&ccp->options, gMppePolicy)) {
    if (b->params.msoft.policy != MPPE_POLICY_REQUIRED) 
      return(0);
  } else {
    if (!Enabled(&b->conf.options, BUND_CONF_CRYPT_REQD))
      return(0);
  }

  /* Was MPPE encryption enabled? If not, ignore requirement */
  if (!Enabled(&ccp->options, gMppe40)
      && !Enabled(&ccp->options, gMppe56)
      && !Enabled(&ccp->options, gMppe128)
      && !Enabled(&ccp->options, gMppePolicy))
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
  Log(LG_ERR, ("[%s] %s: encryption required, but MPPE was not"
    " negotiated in both directions", Pref(&ccp->fsm), Fsm(&ccp->fsm)));
  FsmFailure(&ccp->fsm, FAIL_CANT_ENCRYPT);
  FsmFailure(&b->ipcp.fsm, FAIL_CANT_ENCRYPT);
  FsmFailure(&b->ipv6cp.fsm, FAIL_CANT_ENCRYPT);
  return(-1);
}

/*
 * CcpSetCommand()
 */

static int
CcpSetCommand(Context ctx, int ac, char *av[], void *arg)
{
  CcpState	const ccp = &ctx->bund->ccp;

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
CcpTypeName(int type, char *buf, size_t len)
{
  const struct ccpname	*p;

  for (p = gCcpTypeNames; p->name; p++) {
    if (p->type == type) {
	strlcpy(buf, p->name, len);
        return (buf);
    }
  }
  snprintf(buf, sizeof(buf), "UNKNOWN[%d]", type);
  return(buf);
}

