
/*
 * ecp.c
 *
 * Written by Archie Cobbs <archie@freebsd.org>
 * Copyright (c) 1998-1999 Whistle Communications, Inc. All rights reserved.
 * See ``COPYRIGHT.whistle''
 */

#include "ppp.h"
#include "bund.h"
#include "ecp.h"
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

  #define ECP_MAXFAILURE	7

  #define ECP_KNOWN_CODES	(   (1 << CODE_CONFIGREQ)	\
				  | (1 << CODE_CONFIGACK)	\
				  | (1 << CODE_CONFIGNAK)	\
				  | (1 << CODE_CONFIGREJ)	\
				  | (1 << CODE_TERMREQ)		\
				  | (1 << CODE_TERMACK)		\
				  | (1 << CODE_CODEREJ)		\
				  | (1 << CODE_RESETREQ)	\
				  | (1 << CODE_RESETACK)	)

  #define ECP_OVERHEAD		2

  #define ECP_PEER_REJECTED(p,x)	((p)->peer_reject & (1<<(x)))
  #define ECP_SELF_REJECTED(p,x)	((p)->self_reject & (1<<(x)))

  #define ECP_PEER_REJ(p,x)	do{(p)->peer_reject |= (1<<(x));}while(0)
  #define ECP_SELF_REJ(p,x)	do{(p)->self_reject |= (1<<(x));}while(0)

/* Set menu options */

  enum
  {
    SET_KEY,
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

  static void		EcpConfigure(Fsm fp);
  static u_char		*EcpBuildConfigReq(Fsm fp, u_char *cp);
  static void		EcpDecodeConfig(Fsm fp, FsmOption a, int num, int mode);
  static void		EcpLayerUp(Fsm fp);
  static void		EcpLayerDown(Fsm fp);
  static void		EcpFailure(Fsm f, enum fsmfail reason);
  static void		EcpRecvResetReq(Fsm fp, int id, Mbuf bp);
  static void		EcpRecvResetAck(Fsm fp, int id, Mbuf bp);

  static int		EcpSetCommand(int ac, char *av[], void *arg);
  static EncType	EcpFindType(int type, int *indexp);
  static const char	*EcpTypeName(int type);

/*
 * GLOBAL VARIABLES
 */

  const struct cmdtab EcpSetCmds[] =
  {
    { "key string",			"Set encryption key",
	EcpSetCommand, NULL, (void *) SET_KEY },
    { "accept [opt ...]",		"Accept option",
	EcpSetCommand, NULL, (void *) SET_ACCEPT },
    { "deny [opt ...]",			"Deny option",
	EcpSetCommand, NULL, (void *) SET_DENY },
    { "enable [opt ...]",		"Enable option",
	EcpSetCommand, NULL, (void *) SET_ENABLE },
    { "disable [opt ...]",		"Disable option",
	EcpSetCommand, NULL, (void *) SET_DISABLE },
    { "yes [opt ...]",			"Enable and accept option",
	EcpSetCommand, NULL, (void *) SET_YES },
    { "no [opt ...]",			"Disable and deny option",
	EcpSetCommand, NULL, (void *) SET_NO },
    { NULL },
  };

/*
 * INTERNAL VARIABLES
 */

/* These should be listed in order of preference */

  static const EncType gEncTypes[] =
  {
#ifdef ENCRYPTION_DES
    &gDeseBisEncType,
    &gDeseEncType,
#endif
  };
  #define ECP_NUM_PROTOS	(sizeof(gEncTypes) / sizeof(*gEncTypes))

/* Corresponding option list */

  static const struct confinfo *gConfList;

/* Initializer for struct fsm fields */

  static const struct fsmtype gEcpFsmType =
  {
    "ECP",
    PROTO_ECP,
    ECP_KNOWN_CODES,
    LG_ECP, LG_ECP2,
    FALSE,
    NULL,
    EcpLayerUp,
    EcpLayerDown,
    NULL,
    NULL,
    EcpBuildConfigReq,
    EcpDecodeConfig,
    EcpConfigure,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    EcpFailure,
    EcpRecvResetReq,
    EcpRecvResetAck,
  };

/* Names for different types of encryption */

  static const struct ecpname
  {
    u_char	type;
    const char	*name;
  }
  gEcpTypeNames[] =
  {
    { ECP_TY_OUI,	"OUI" },
    { ECP_TY_DESE,	"DESE" },
    { ECP_TY_3DESE,	"3DESE" },
    { ECP_TY_DESE_bis,	"DESE-bis" },
    { 0,		NULL },
  };

/*
 * EcpInit()
 */

void
EcpInit(void)
{
  EcpState	ecp = &bund->ecp;

/* Init ECP state for this bundle */

  memset(ecp, 0, sizeof(*ecp));
  FsmInit(&ecp->fsm, &gEcpFsmType);
  ecp->fsm.conf.maxfailure = ECP_MAXFAILURE;

/* Construct options list if we haven't done so already */

  if (gConfList == NULL)
  {
    struct confinfo	*ci;
    int			k;

    ci = Malloc(MB_CRYPT, (ECP_NUM_PROTOS + 1) * sizeof(*ci));
    for (k = 0; k < ECP_NUM_PROTOS; k++)
    {
      ci[k].option = k;
      ci[k].peered = TRUE;
      ci[k].name = gEncTypes[k]->name;
    }
    ci[k].name = NULL;
    gConfList = (const struct confinfo *) ci;
  }
}

/*
 * EcpConfigure()
 */

static void
EcpConfigure(Fsm fp)
{
  EcpState	const ecp = &bund->ecp;
  int		k;

  for (k = 0; k < ECP_NUM_PROTOS; k++)
  {
    EncType	const et = gEncTypes[k];

    if (et->Configure)
      (*et->Configure)();
  }
  ecp->xmit = NULL;
  ecp->recv = NULL;
  ecp->self_reject = 0;
  ecp->peer_reject = 0;
}

/*
 * EcpDataOutput()
 *
 * Encrypt a frame. Consumes the original packet.
 */

Mbuf
EcpDataOutput(Mbuf plain)
{
  EcpState	const ecp = &bund->ecp;
  Mbuf		cypher;

  LogDumpBp(LG_ECP2, plain, "%s: xmit plain", Pref(&ecp->fsm));

/* Encrypt packet */

  if ((!ecp->xmit) || (!ecp->xmit->Encrypt))
  {
    Log(LG_ERR, ("%s: no encryption for xmit", Pref(&ecp->fsm)));
    PFREE(plain);
    return(NULL);
  }
  cypher = (*ecp->xmit->Encrypt)(plain);
  LogDumpBp(LG_ECP2, cypher, "%s: xmit cypher", Pref(&ecp->fsm));

/* Return result, with new protocol number */

  return(cypher);
}

/*
 * EcpDataInput()
 *
 * Decrypt incoming packet. If packet got garbled, return NULL.
 * In any case, we consume the packet passed to us.
 */

Mbuf
EcpDataInput(Mbuf cypher)
{
  EcpState	const ecp = &bund->ecp;
  Mbuf		plain;

  LogDumpBp(LG_ECP2, cypher, "%s: recv cypher", Pref(&ecp->fsm));

/* Decrypt packet */

  if ((!ecp->recv) || (!ecp->recv->Decrypt))
  {
    Log(LG_ERR, ("%s: no encryption for recv", Pref(&ecp->fsm)));
    PFREE(cypher);
    return(NULL);
  }

  plain = (*ecp->recv->Decrypt)(cypher);

/* Decrypted ok? */

  if (plain == NULL)
  {
    Log(LG_ECP, ("%s: decryption failed", Pref(&ecp->fsm)));
    return(NULL);
  }

  LogDumpBp(LG_ECP2, plain, "%s: recv plain", Pref(&ecp->fsm));
/* Done */

  return(plain);
}

/*
 * EcpUp()
 */

void
EcpUp(void)
{
  FsmUp(&bund->ecp.fsm);
}

/*
 * EcpDown()
 */

void
EcpDown(void)
{
  FsmDown(&bund->ecp.fsm);
}

/*
 * EcpOpen()
 */

void
EcpOpen(void)
{
  FsmOpen(&bund->ecp.fsm);
}

/*
 * EcpClose()
 */

void
EcpClose(void)
{
  FsmClose(&bund->ecp.fsm);
}

/*
 * EcpFailure()
 *
 * This is fatal to the entire link if encryption is required.
 */

static void
EcpFailure(Fsm f, enum fsmfail reason)
{
  if (Enabled(&bund->conf.options, BUND_CONF_CRYPT_REQD))
    FsmFailure(&bund->ipcp.fsm, FAIL_CANT_ENCRYPT);
}

/*
 * EcpStat()
 */

int
EcpStat(int ac, char *av[], void *arg)
{
  EcpState	const ecp = &bund->ecp;

  Printf("%s [%s]\r\n", Pref(&ecp->fsm), FsmStateName(ecp->fsm.state));
  Printf("Enabled protocols:\r\n");
  OptStat(&ecp->options, gConfList);
  Printf("Outgoing encryption:\r\n");
  Printf("\tProto\t: %s\r\n", ecp->xmit ? ecp->xmit->name : "none");
  if (ecp->xmit && ecp->xmit->Stat)
    ecp->xmit->Stat(ECP_DIR_XMIT);
  Printf("\tResets\t: %d\r\n", ecp->xmit_resets);
  Printf("Incoming decryption:\r\n");
  Printf("\tProto\t: %s\r\n", ecp->recv ? ecp->recv->name : "none");
  if (ecp->recv && ecp->recv->Stat)
    ecp->recv->Stat(ECP_DIR_RECV);
  Printf("\tResets\t: %d\r\n", ecp->recv_resets);
  return(0);
}

/*
 * EcpSendResetReq()
 */

void
EcpSendResetReq(Fsm fp)
{
  EcpState	const ecp = &bund->ecp;
  EncType	const et = ecp->recv;
  Mbuf		bp = NULL;

  assert(et);
  ecp->recv_resets++;
  if (et->SendResetReq)
    bp = (*et->SendResetReq)();
  Log(LG_ECP, ("%s: SendResetReq", Pref(fp)));
  FsmOutputMbuf(fp, CODE_RESETREQ, fp->reqid++, bp);
}

/*
 * EcpRecvResetReq()
 */

void
EcpRecvResetReq(Fsm fp, int id, Mbuf bp)
{
  EcpState	const ecp = &bund->ecp;
  EncType	const et = ecp->xmit;

  ecp->xmit_resets++;
  bp = (et && et->RecvResetReq) ? (*et->RecvResetReq)(id, bp) : NULL;
  Log(fp->log, ("%s: SendResetAck", Pref(fp)));
  FsmOutputMbuf(fp, CODE_RESETACK, id, bp);
}

/*
 * EcpRecvResetAck()
 */

static void
EcpRecvResetAck(Fsm fp, int id, Mbuf bp)
{
  EcpState	const ecp = &bund->ecp;
  EncType	const et = ecp->recv;

  if (et && et->RecvResetAck)
    (*et->RecvResetAck)(id, bp);
}

/*
 * EcpInput()
 */

void
EcpInput(Mbuf bp, int linkNum)
{
  FsmInput(&bund->ecp.fsm, bp, linkNum);
}

/*
 * EcpBuildConfigReq()
 */

static u_char *
EcpBuildConfigReq(Fsm fp, u_char *cp)
{
  EcpState	const ecp = &bund->ecp;
  int		type;

/* Put in all options that peer hasn't rejected */

  for (ecp->xmit = NULL, type = 0; type < ECP_NUM_PROTOS; type++)
  {
    EncType	const et = gEncTypes[type];

    if (Enabled(&ecp->options, type) && !ECP_PEER_REJECTED(ecp, type))
    {
      cp = (*et->BuildConfigReq)(cp);
      if (!ecp->xmit)
	ecp->xmit = et;
    }
  }
  return(cp);
}

/*
 * EcpLayerUp()
 *
 * Called when ECP has reached the OPENED state
 */

static void
EcpLayerUp(Fsm fp)
{
  EcpState	const ecp = &bund->ecp;
  struct ngm_connect    cn;

  /* Initialize */
  if (ecp->xmit && ecp->xmit->Init)
    (*ecp->xmit->Init)(ECP_DIR_XMIT);
  if (ecp->recv && ecp->recv->Init)
    (*ecp->recv->Init)(ECP_DIR_RECV);

  if (ecp->recv && ecp->recv->Decrypt) 
  {
    /* Connect a hook from the bpf node to our socket node */
    snprintf(cn.path, sizeof(cn.path), "%s", MPD_HOOK_PPP);
    snprintf(cn.ourhook, sizeof(cn.ourhook), "%s", NG_PPP_HOOK_DECRYPT);
    snprintf(cn.peerhook, sizeof(cn.peerhook), "%s", NG_PPP_HOOK_DECRYPT);
    if (NgSendMsg(bund->csock, ".",
	    NGM_GENERIC_COOKIE, NGM_CONNECT, &cn, sizeof(cn)) < 0) {
	Log(LG_ERR, ("[%s] can't connect \"%s\"->\"%s\" and \"%s\"->\"%s\": %s",
        bund->name, ".", cn.ourhook, cn.path, cn.peerhook,  strerror(errno)));
    }
  }
  if (ecp->xmit && ecp->xmit->Encrypt)
  {
    /* Connect a hook from the bpf node to our socket node */
    snprintf(cn.path, sizeof(cn.path), "%s", MPD_HOOK_PPP);
    snprintf(cn.ourhook, sizeof(cn.ourhook), "%s", NG_PPP_HOOK_ENCRYPT);
    snprintf(cn.peerhook, sizeof(cn.peerhook), "%s", NG_PPP_HOOK_ENCRYPT);
    if (NgSendMsg(bund->csock, ".",
	    NGM_GENERIC_COOKIE, NGM_CONNECT, &cn, sizeof(cn)) < 0) {
	Log(LG_ERR, ("[%s] can't connect \"%s\"->\"%s\" and \"%s\"->\"%s\": %s",
        bund->name, ".", cn.ourhook, cn.path, cn.peerhook, strerror(errno)));
    }
  }

  Log(LG_ECP, ("  Encrypt using: %s", !ecp->xmit ? "none" : ecp->xmit->name));
  Log(LG_ECP, ("  Decrype using: %s", !ecp->recv ? "none" : ecp->recv->name));

  /* Update PPP node config */
#if NGM_PPP_COOKIE < 940897794
  bund->pppConfig.enableEncryption = (ecp->xmit != NULL);
  bund->pppConfig.enableDecryption = (ecp->recv != NULL);
#else
  bund->pppConfig.bund.enableEncryption = (ecp->xmit != NULL);
  bund->pppConfig.bund.enableDecryption = (ecp->recv != NULL);
#endif
  NgFuncSetConfig();

  /* Update interface MTU */
  BundUpdateParams();
}

/*
 * EcpLayerDown()
 *
 * Called when ECP leaves the OPENED state
 */

static void
EcpLayerDown(Fsm fp)
{
  EcpState	const ecp = &bund->ecp;
  struct ngm_rmhook rm;

  if (ecp->xmit != NULL && ecp->xmit->Encrypt != NULL) {
    /* Disconnect hook. */
    snprintf(rm.ourhook, sizeof(rm.ourhook), "%s", NG_PPP_HOOK_ENCRYPT);
    if (NgSendMsg(bund->csock, ".",
	    NGM_GENERIC_COOKIE, NGM_RMHOOK, &rm, sizeof(rm)) < 0) {
	Log(LG_ERR, ("can't remove hook %s: %s", NG_PPP_HOOK_ENCRYPT, strerror(errno)));
    }
  }
  
  if (ecp->recv != NULL && ecp->recv->Decrypt != NULL) {
    /* Disconnect hook. */
    snprintf(rm.ourhook, sizeof(rm.ourhook), "%s", NG_PPP_HOOK_DECRYPT);
    if (NgSendMsg(bund->csock, ".",
	    NGM_GENERIC_COOKIE, NGM_RMHOOK, &rm, sizeof(rm)) < 0) {
	Log(LG_ERR, ("can't remove hook %s: %s", NG_PPP_HOOK_DECRYPT, strerror(errno)));
    }
  }

  if (ecp->xmit && ecp->xmit->Cleanup)
    (ecp->xmit->Cleanup)(ECP_DIR_XMIT);
  if (ecp->recv && ecp->recv->Cleanup)
    (ecp->recv->Cleanup)(ECP_DIR_RECV);
    
  ecp->xmit_resets = 0;
  ecp->recv_resets = 0;
}

/*
 * EcpDecodeConfig()
 */

static void
EcpDecodeConfig(Fsm fp, FsmOption list, int num, int mode)
{
  EcpState	const ecp = &bund->ecp;
  u_int		ackSizeSave, rejSizeSave;
  int		k, rej;

  /* Forget our previous choice on new request */
  if (mode == MODE_REQ)
    ecp->recv = NULL;

/* Decode each config option */

  for (k = 0; k < num; k++)
  {
    FsmOption	const opt = &list[k];
    int		index;
    EncType	et;

    Log(LG_ECP, (" %s", EcpTypeName(opt->type)));
    if ((et = EcpFindType(opt->type, &index)) == NULL)
    {
      if (mode == MODE_REQ)
      {
	Log(LG_ECP, ("   Not supported"));
	FsmRej(fp, opt);
      }
      continue;
    }
    switch (mode)
    {
      case MODE_REQ:
	ackSizeSave = gAckSize;
	rejSizeSave = gRejSize;
	rej = (!Acceptable(&ecp->options, index)
	  || ECP_SELF_REJECTED(ecp, index)
	  || (ecp->recv && ecp->recv != et));
	if (rej)
	{
	  (*et->DecodeConfig)(fp, opt, MODE_NOP);
	  FsmRej(fp, opt);
	  break;
	}
	(*et->DecodeConfig)(fp, opt, mode);
	if (gRejSize != rejSizeSave)		/* we rejected it */
	{
	  ECP_SELF_REJ(ecp, index);
	  break;
	}
	if (gAckSize != ackSizeSave)		/* we accepted it */
	  ecp->recv = et;
	break;

      case MODE_NAK:
	(*et->DecodeConfig)(fp, opt, mode);
	break;

      case MODE_REJ:
	(*et->DecodeConfig)(fp, opt, mode);
	ECP_PEER_REJ(ecp, index);
	break;

      case MODE_NOP:
	(*et->DecodeConfig)(fp, opt, mode);
	break;
    }
  }
}

/*
 * EcpSubtractBloat()
 *
 * Given that "size" is our MTU, return the maximum length frame
 * we can encrypt without the result being longer than "size".
 */

int
EcpSubtractBloat(int size)
{
  EcpState	const ecp = &bund->ecp;

  /* Account for ECP's protocol number overhead */
  if (OPEN_STATE(ecp->fsm.state))
    size -= ECP_OVERHEAD;

  /* Check transmit encryption */
  if (OPEN_STATE(ecp->fsm.state) && ecp->xmit && ecp->xmit->SubtractBloat)
    size = (*ecp->xmit->SubtractBloat)(size);

  /* Done */
  return(size);
}

/*
 * EcpSetCommand()
 */

static int
EcpSetCommand(int ac, char *av[], void *arg)
{
  EcpState	const ecp = &bund->ecp;

  if (ac == 0)
    return(-1);
  switch ((intptr_t)arg)
  {
    case SET_KEY:
      if (ac != 1)
	return(-1);
      snprintf(ecp->key, sizeof(ecp->key), "%s", av[0]);
      break;

    case SET_ACCEPT:
      AcceptCommand(ac, av, &ecp->options, gConfList);
      break;

    case SET_DENY:
      DenyCommand(ac, av, &ecp->options, gConfList);
      break;

    case SET_ENABLE:
      EnableCommand(ac, av, &ecp->options, gConfList);
      break;

    case SET_DISABLE:
      DisableCommand(ac, av, &ecp->options, gConfList);
      break;

    case SET_YES:
      YesCommand(ac, av, &ecp->options, gConfList);
      break;

    case SET_NO:
      NoCommand(ac, av, &ecp->options, gConfList);
      break;

    default:
      assert(0);
  }
  return(0);
}

/*
 * EcpFindType()
 */

static EncType
EcpFindType(int type, int *indexp)
{
  int	k;

  for (k = 0; k < ECP_NUM_PROTOS; k++)
    if (gEncTypes[k]->type == type)
    {
      if (indexp)
	*indexp = k;
      return(gEncTypes[k]);
    }
  return(NULL);
}

/*
 * EcpTypeName()
 */

static const char *
EcpTypeName(int type)
{
  const struct ecpname	*p;
  static char		buf[20];

  for (p = gEcpTypeNames; p->name; p++)
    if (p->type == type)
      return(p->name);
  snprintf(buf, sizeof(buf), "UNKNOWN[%d]", type);
  return(buf);
}


