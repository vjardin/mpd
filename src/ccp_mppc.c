
/*
 * ccp_mppc.c
 *
 * Written by Archie Cobbs <archie@freebsd.org>
 * Copyright (c) 1998-1999 Whistle Communications, Inc. All rights reserved.
 * See ``COPYRIGHT.whistle''
 */

#include "ppp.h"
#include "ccp.h"
#include "msoft.h"
#include "ngfunc.h"
#include "bund.h"
#include <md4.h>

#include <netgraph/ng_message.h>
#include <netgraph.h>

/*
 * This implements both MPPC compression and MPPE encryption.
 */

/*
 * DEFINITIONS
 */

  /* #define DEBUG_KEYS */

#define MPPC_SUPPORTED	(MPPC_BIT | MPPE_BITS | MPPE_STATELESS)

/*
 * INTERNAL FUNCTIONS
 */

  static int	MppcInit(Bund b, int dir);
  static int	MppcConfigure(Bund b);
  static char	*MppcDescribe(Bund b, int xmit, char *buf, size_t len);
  static int	MppcSubtractBloat(Bund b, int size);
  static void	MppcCleanup(Bund b, int dir);
  static u_char	*MppcBuildConfigReq(Bund b, u_char *cp, int *ok);
  static void	MppcDecodeConfigReq(Fsm fp, FsmOption opt, int mode);
  static Mbuf	MppcRecvResetReq(Bund b, int id, Mbuf bp, int *noAck);
  static char	*MppcDescribeBits(u_int32_t bits, char *buf, size_t len);
  static int	MppcNegotiated(Bund b, int xmit);

  /* Encryption stuff */
  static void	MppeInitKey(Bund b, MppcInfo mppc, int dir);
  static void	MppeInitKeyv2(Bund b, MppcInfo mppc, int dir);
  static short	MppcEnabledMppeType(Bund b, short type);
  static short	MppcAcceptableMppeType(Bund b, short type);
  static int	MppcKeyAvailable(Bund b, short type);

#ifdef DEBUG_KEYS
  static void	KeyDebug(const u_char *data, int len, const char *fmt, ...);
  #define KEYDEBUG(x)	KeyDebug x
#else
  #define KEYDEBUG(x)
#endif

/*
 * GLOBAL VARIABLES
 */

  const struct comptype	gCompMppcInfo = {
    "mppc",
    CCP_TY_MPPC,
    1,
    MppcInit,
    MppcConfigure,
    NULL,
    MppcDescribe,
    MppcSubtractBloat,
    MppcCleanup,
    MppcBuildConfigReq,
    MppcDecodeConfigReq,
    NULL,
    MppcRecvResetReq,
    NULL,
    MppcNegotiated,
    NULL,
    NULL,
    NULL,
  };
  int	MPPCPresent = 0;
  int	MPPEPresent = 0;

/*
 * MppcInit()
 */

static int
MppcInit(Bund b, int dir)
{
  MppcInfo		const mppc = &b->ccp.mppc;
  struct ng_mppc_config	conf;
  struct ngm_mkpeer	mp;
  char			path[NG_PATHSIZ];
  const char		*mppchook, *ppphook;
  int			mschap;
  int			cmd;

  /* Which type of MS-CHAP did we do? */
  mschap = b->params.msoft.chap_alg;

  /* Initialize configuration structure */
  memset(&conf, 0, sizeof(conf));
  conf.enable = 1;
  switch (dir) {
    case COMP_DIR_XMIT:
      cmd = NGM_MPPC_CONFIG_COMP;
      ppphook = NG_PPP_HOOK_COMPRESS;
      mppchook = NG_MPPC_HOOK_COMP;
      conf.bits = mppc->xmit_bits;
      if (conf.bits & MPPE_BITS) {
        if (mschap == CHAP_ALG_MSOFT)
	    MppeInitKey(b, mppc, dir);
        else
    	    MppeInitKeyv2(b, mppc, dir);
        memcpy(conf.startkey, mppc->xmit_key0, sizeof(conf.startkey));
      }
      break;
    case COMP_DIR_RECV:
      cmd = NGM_MPPC_CONFIG_DECOMP;
      ppphook = NG_PPP_HOOK_DECOMPRESS;
      mppchook = NG_MPPC_HOOK_DECOMP;
      conf.bits = mppc->recv_bits;
      if (conf.bits & MPPE_BITS) {
        if (mschap == CHAP_ALG_MSOFT)
	    MppeInitKey(b, mppc, dir);
        else
	    MppeInitKeyv2(b, mppc, dir);
        memcpy(conf.startkey, mppc->recv_key0, sizeof(conf.startkey));
      }
      break;
    default:
      assert(0);
      return(-1);
  }

  /* Attach a new MPPC node to the PPP node */
  snprintf(mp.type, sizeof(mp.type), "%s", NG_MPPC_NODE_TYPE);
  snprintf(mp.ourhook, sizeof(mp.ourhook), "%s", ppphook);
  snprintf(mp.peerhook, sizeof(mp.peerhook), "%s", mppchook);
  if (NgSendMsg(b->csock, MPD_HOOK_PPP,
      NGM_GENERIC_COOKIE, NGM_MKPEER, &mp, sizeof(mp)) < 0) {
    Log(LG_ERR, ("[%s] can't create %s node: %s",
      b->name, mp.type, strerror(errno)));
    return(-1);
  }

  /* Configure MPPC node */
  snprintf(path, sizeof(path), "%s.%s", MPD_HOOK_PPP, ppphook);
  if (NgSendMsg(b->csock, path,
      NGM_MPPC_COOKIE, cmd, &conf, sizeof(conf)) < 0) {
    Log(LG_ERR, ("[%s] can't config %s node at %s: %s",
      b->name, NG_MPPC_NODE_TYPE, path, strerror(errno)));
    NgFuncDisconnect(b->csock, b->name, MPD_HOOK_PPP, ppphook);
    return(-1);
  }

  /* Done */
  return(0);
}

static int
MppcConfigure(Bund b)
{
    CcpState	const ccp = &b->ccp;

    if (Enabled(&ccp->options, gMppcCompress)
      && MPPCPresent)
	return (0);

    if ((MppcEnabledMppeType(b, 40) || MppcAcceptableMppeType(b, 40))
      && MPPEPresent) 
	return (0);
#ifndef MPPE_56_UNSUPPORTED
    if ((MppcEnabledMppeType(b, 56) || MppcAcceptableMppeType(b, 40))
      && MPPEPresent) 
	return (0);
#endif
    if ((MppcEnabledMppeType(b, 128) || MppcAcceptableMppeType(b, 40))
      && MPPEPresent) 
	return (0);
    
    return (-1);
}

/*
 * MppcDescribe()
 */

static char *
MppcDescribe(Bund b, int dir, char *buf, size_t len)
{
  MppcInfo	const mppc = &b->ccp.mppc;

  switch (dir) {
    case COMP_DIR_XMIT:
      return(MppcDescribeBits(mppc->xmit_bits, buf, len));
    case COMP_DIR_RECV:
      return(MppcDescribeBits(mppc->recv_bits, buf, len));
    default:
      assert(0);
      return(NULL);
  }
}

/*
 * MppcSubtractBloat()
 */

static int
MppcSubtractBloat(Bund b, int size)
{

  /* Account for MPPC header */
  size -= 2;

  /* Account for possible expansion with MPPC compression */
  if ((b->ccp.mppc.xmit_bits & MPPC_BIT) != 0) {
    int	l, h, size0 = size;

    while (1) {
      l = MPPC_MAX_BLOWUP(size0);
      h = MPPC_MAX_BLOWUP(size0 + 1);
      if (l > size) {
	size0 -= 20;
      } else if (h > size) {
	size = size0;
	break;
      } else {
	size0++;
      }
    }
  }

  /* Done */
  return(size);
}

/*
 * MppcNegotiated()
 */

static int
MppcNegotiated(Bund b, int dir)
{
  MppcInfo	const mppc = &b->ccp.mppc;

  switch (dir) {
    case COMP_DIR_XMIT:
      return(mppc->xmit_bits != 0);
    case COMP_DIR_RECV:
      return(mppc->recv_bits != 0);
    default:
      assert(0);
      return(0);
  }
}

/*
 * MppcCleanup()
 */

static void
MppcCleanup(Bund b, int dir)
{
  const char	*ppphook;
  char		path[NG_PATHSIZ];

  /* Remove node */
  switch (dir) {
    case COMP_DIR_XMIT:
      ppphook = NG_PPP_HOOK_COMPRESS;
      break;
    case COMP_DIR_RECV:
      ppphook = NG_PPP_HOOK_DECOMPRESS;
      break;
    default:
      assert(0);
      return;
  }
  snprintf(path, sizeof(path), "%s.%s", MPD_HOOK_PPP, ppphook);
  (void)NgFuncShutdownNode(b->csock, b->name, path);
}

/*
 * MppcBuildConfigReq()
 */

static u_char *
MppcBuildConfigReq(Bund b, u_char *cp, int *ok)
{
  CcpState	const ccp = &b->ccp;
  MppcInfo	const mppc = &ccp->mppc;
  u_int32_t	bits = 0;

  /* Compression */
  if (Enabled(&ccp->options, gMppcCompress)
      && !CCP_PEER_REJECTED(ccp, gMppcCompress)
      && MPPCPresent)
    bits |= MPPC_BIT;

  /* Encryption */
  if (MppcEnabledMppeType(b, 40)
      && !CCP_PEER_REJECTED(ccp, gMppe40)
      && MPPEPresent) 
    bits |= MPPE_40;
#ifndef MPPE_56_UNSUPPORTED
  if (MppcEnabledMppeType(b, 56)
      && !CCP_PEER_REJECTED(ccp, gMppe56)
      && MPPEPresent) 
    bits |= MPPE_56;
#endif
  if (MppcEnabledMppeType(b, 128)
      && !CCP_PEER_REJECTED(ccp, gMppe128)
      && MPPEPresent) 
    bits |= MPPE_128;

  /* Stateless mode */
  if (Enabled(&ccp->options, gMppcStateless)
      && !CCP_PEER_REJECTED(ccp, gMppcStateless)
      && bits != 0)
    bits |= MPPE_STATELESS;

  /* Ship it */
  mppc->xmit_bits = bits;
  if (bits != 0) {
    cp = FsmConfValue(cp, CCP_TY_MPPC, -4, &bits);
    *ok = 1;
  } else {
    *ok = 0;
  }
  return(cp);
}

/*
 * MppcDecodeConfigReq()
 */

static void
MppcDecodeConfigReq(Fsm fp, FsmOption opt, int mode)
{
    Bund 	b = (Bund)fp->arg;
  CcpState	const ccp = &b->ccp;
  MppcInfo	const mppc = &ccp->mppc;
  u_int32_t	orig_bits;
  u_int32_t	bits;
  char		buf[64];

  /* Get bits */
  memcpy(&orig_bits, opt->data, 4);
  orig_bits = ntohl(orig_bits);
  bits = orig_bits;

  /* Sanity check */
  if (opt->len != 6) {
    Log(LG_CCP, ("   bogus length %d", opt->len));
    if (mode == MODE_REQ)
      FsmRej(fp, opt);
    return;
  }

  /* Display it */
  Log(LG_CCP, ("   0x%08x:%s", bits, MppcDescribeBits(bits, buf, sizeof(buf))));

  /* Deal with it */
  switch (mode) {
    case MODE_REQ:

      /* Check for supported bits */
      if (bits & ~MPPC_SUPPORTED) {
	Log(LG_CCP, ("   Bits 0x%08x not supported", bits & ~MPPC_SUPPORTED));
	bits &= MPPC_SUPPORTED;
      }

      /* Check compression */
      if (!Acceptable(&ccp->options, gMppcCompress) || !MPPCPresent)
	bits &= ~MPPC_BIT;

      /* Check encryption */
      if (!MppcAcceptableMppeType(b, 40) || !MPPEPresent)
	bits &= ~MPPE_40;
#ifndef MPPE_56_UNSUPPORTED
      if (!MppcAcceptableMppeType(b, 56) || !MPPEPresent)
#endif
	bits &= ~MPPE_56;
      if (!MppcAcceptableMppeType(b, 128) || !MPPEPresent)
	bits &= ~MPPE_128;

      /* Choose the strongest encryption available */
      if (bits & MPPE_128)
	bits &= ~(MPPE_40|MPPE_56);
      else if (bits & MPPE_56)
	bits &= ~MPPE_40;

      /* It doesn't really make sense to encrypt in only one direction.
	 Also, Win95/98 PPTP can't handle uni-directional encryption. So
	 if the remote side doesn't request encryption, try to prompt it.
	 This is broken wrt. normal PPP negotiation: typical Microsoft. */
      if ((bits & MPPE_BITS) == 0) {
	if (MppcAcceptableMppeType(b, 40)) bits |= MPPE_40;
#ifndef MPPE_56_UNSUPPORTED
	if (MppcAcceptableMppeType(b, 56)) bits |= MPPE_56;
#endif
	if (MppcAcceptableMppeType(b, 128)) bits |= MPPE_128;
      }

      /* Stateless mode */
      if ((bits & MPPE_STATELESS) && 
    	  (!Acceptable(&ccp->options, gMppcStateless)
	    || (bits & (MPPE_BITS|MPPC_BIT)) == 0))
	bits &= ~MPPE_STATELESS;

      /* See if what we want equals what was sent */
      mppc->recv_bits = bits;
      if (bits) {
        if (bits != orig_bits) {
	    bits = htonl(bits);
	    memcpy(opt->data, &bits, 4);
	    FsmNak(fp, opt);
        }
        else
	    FsmAck(fp, opt);
      }
      else
        FsmRej(fp, opt);
      break;

    case MODE_NAK:
      if (!(bits & MPPC_BIT))
	CCP_PEER_REJ(ccp, gMppcCompress);
      if (!(bits & MPPE_40))
	CCP_PEER_REJ(ccp, gMppe40);
      if (!(bits & MPPE_56))
	CCP_PEER_REJ(ccp, gMppe56);
      if (!(bits & MPPE_128))
	CCP_PEER_REJ(ccp, gMppe128);
      if (!(bits & MPPE_STATELESS))
	CCP_PEER_REJ(ccp, gMppcStateless);
      break;
  }
}

/*
 * MppcRecvResetReq()
 */

static Mbuf
MppcRecvResetReq(Bund b, int id, Mbuf bp, int *noAck)
{
  char	path[NG_PATHSIZ];

  /* Forward ResetReq to the MPPC compression node */
  snprintf(path, sizeof(path), "%s.%s", MPD_HOOK_PPP, NG_PPP_HOOK_COMPRESS);
  if (NgSendMsg(b->csock, path,
      NGM_MPPC_COOKIE, NGM_MPPC_RESETREQ, NULL, 0) < 0) {
    Log(LG_ERR, ("[%s] reset-req to %s node: %s",
      b->name, NG_MPPC_NODE_TYPE, strerror(errno)));
  }

  /* No ResetAck required for MPPC */
  if (noAck)
    *noAck = 1;
  return(NULL);
}

/*
 * MppcDescribeBits()
 */

static char *
MppcDescribeBits(u_int32_t bits, char *buf, size_t len)
{
  *buf = 0;
  if (bits & MPPC_BIT)
    snprintf(buf + strlen(buf), len - strlen(buf), "MPPC, ");
  if (bits & MPPE_BITS) {
    snprintf(buf + strlen(buf), len - strlen(buf), "MPPE(");
    if (bits & MPPE_40) {
      snprintf(buf + strlen(buf), len - strlen(buf), "40");
      if (bits & (MPPE_56|MPPE_128))
        snprintf(buf + strlen(buf), len - strlen(buf), ", ");
    }
    if (bits & MPPE_56) {
      snprintf(buf + strlen(buf), len - strlen(buf), "56");
      if ((bits & MPPE_128))
        snprintf(buf + strlen(buf), len - strlen(buf), ", ");
    }
    if (bits & MPPE_128)
      snprintf(buf + strlen(buf), len - strlen(buf), "128");
    snprintf(buf + strlen(buf), len - strlen(buf), " bits), ");
  }
  if (bits & MPPE_STATELESS)
    snprintf(buf + strlen(buf), len - strlen(buf), "stateless");
  return(buf);
}

static short
MppcEnabledMppeType(Bund b, short type)
{
    CcpState	const ccp = &b->ccp;
    short	ret;

    /* Check if we are able to calculate key */
    if (!MppcKeyAvailable(b, type))
	return (0);

  switch (type) {
  case 40:
    if (Enabled(&ccp->options, gMppePolicy)) {
      ret = (b->params.msoft.types & MPPE_TYPE_40BIT) && !CCP_PEER_REJECTED(ccp, gMppe40);
    } else {
      ret = Enabled(&ccp->options, gMppe40) && !CCP_PEER_REJECTED(ccp, gMppe40);
    }
    break;

#ifndef MPPE_56_UNSUPPORTED
  case 56:
    if (Enabled(&ccp->options, gMppePolicy)) {
      ret = (b->params.msoft.types & MPPE_TYPE_56BIT) && !CCP_PEER_REJECTED(ccp, gMppe56);
    } else {
      ret = Enabled(&ccp->options, gMppe56) && !CCP_PEER_REJECTED(ccp, gMppe56);
    }

    break;
#endif
      
  case 128:
  default:
    if (Enabled(&ccp->options, gMppePolicy)) {
      ret = (b->params.msoft.types & MPPE_TYPE_128BIT) && !CCP_PEER_REJECTED(ccp, gMppe128);
    } else {
      ret = Enabled(&ccp->options, gMppe128) && !CCP_PEER_REJECTED(ccp, gMppe128);
    }
  }

  return ret;
}

static short
MppcAcceptableMppeType(Bund b, short type)
{
    CcpState	const ccp = &b->ccp;
    short	ret;
  
    /* Check if we are able to calculate key */
    if (!MppcKeyAvailable(b, type))
	return (0);

  switch (type) {
  case 40:
    if (Enabled(&ccp->options, gMppePolicy)) {
      ret = b->params.msoft.types & MPPE_TYPE_40BIT;
    } else {
      ret = Acceptable(&ccp->options, gMppe40);
    }
    break;

#ifndef MPPE_56_UNSUPPORTED
  case 56:
    if (Enabled(&ccp->options, gMppePolicy)) {
      ret = b->params.msoft.types & MPPE_TYPE_56BIT;
    } else {
      ret = Acceptable(&ccp->options, gMppe56);
    }

    break;
#endif
      
  case 128:
  default:
    if (Enabled(&ccp->options, gMppePolicy)) {
      ret = b->params.msoft.types & MPPE_TYPE_128BIT;
    } else {
      ret = Acceptable(&ccp->options, gMppe128);
    }
  }

  return ret;
}

#define KEYLEN(b)	(((b) & MPPE_128) ? 16 : 8)

/*
 * MppeInitKey()
 */

static void
MppeInitKey(Bund b, MppcInfo mppc, int dir)
{
  CcpState	const ccp = &b->ccp;
  u_int32_t	const bits = (dir == COMP_DIR_XMIT) ?
			mppc->xmit_bits : mppc->recv_bits;
  u_char	*const key0 = (dir == COMP_DIR_XMIT) ?
			mppc->xmit_key0 : mppc->recv_key0;
  u_char	hash[MPPE_KEY_LEN];
  u_char	*chal;

  /* The secret comes from the originating caller's credentials */
  chal = b->params.msoft.msChal;

  /* Compute basis for the session key (ie, "start key" or key0) */
  if (bits & MPPE_128) {
    if (!b->params.msoft.has_nt_hash) {
      Log(LG_ERR, ("[%s] The NT-Hash is not set, but needed for MS-CHAPv1 and MPPE 128", 
        b->name));
      goto fail;
    }
    memcpy(hash, b->params.msoft.nt_hash_hash, sizeof(hash));
    KEYDEBUG((hash, sizeof(hash), "NT Password Hash Hash"));
    KEYDEBUG((chal, CHAP_MSOFT_CHAL_LEN, "Challenge"));
    MsoftGetStartKey(chal, hash);
    KEYDEBUG((hash, sizeof(hash), "NT StartKey"));
  } else {
    if (!b->params.msoft.has_lm_hash) {
      Log(LG_ERR, ("[%s] The LM-Hash is not set, but needed for MS-CHAPv1 and MPPE 40, 56", 
        b->name));
      goto fail;
    }

    memcpy(hash, b->params.msoft.lm_hash, 8);
    KEYDEBUG((hash, sizeof(hash), "LM StartKey"));
  }
  memcpy(key0, hash, MPPE_KEY_LEN);
  KEYDEBUG((key0, (bits & MPPE_128) ? 16 : 8, "InitialKey"));
  return;

fail:
  FsmFailure(&ccp->fsm, FAIL_CANT_ENCRYPT);
  FsmFailure(&b->ipcp.fsm, FAIL_CANT_ENCRYPT);
}

/*
 * MppeInitKeyv2()
 */

static void
MppeInitKeyv2(Bund b, MppcInfo mppc, int dir)
{
  CcpState	const ccp = &b->ccp;
  u_char	*const key0 = (dir == COMP_DIR_XMIT) ?
			mppc->xmit_key0 : mppc->recv_key0;
  u_char	hash[MPPE_KEY_LEN];
  u_char	*resp;

  if (b->params.msoft.has_keys)
  { 
    memcpy(mppc->xmit_key0, b->params.msoft.xmit_key, MPPE_KEY_LEN);
    memcpy(mppc->recv_key0, b->params.msoft.recv_key, MPPE_KEY_LEN);
    return;
  }

  /* The secret comes from the originating caller's credentials */
  resp = b->params.msoft.ntResp;

  if (!b->params.msoft.has_nt_hash) {
    Log(LG_ERR, ("[%s] The NT-Hash is not set, but needed for MS-CHAPv2 and MPPE", 
      b->name));
    goto fail;
  }

  /* Compute basis for the session key (ie, "start key" or key0) */
  memcpy(hash, b->params.msoft.nt_hash_hash, sizeof(hash));
  KEYDEBUG((hash, sizeof(hash), "NT Password Hash Hash"));
  KEYDEBUG((resp, CHAP_MSOFTv2_CHAL_LEN, "Response"));
  MsoftGetMasterKey(resp, hash);
  KEYDEBUG((hash, sizeof(hash), "GetMasterKey"));
  MsoftGetAsymetricStartKey(hash,
    (dir == COMP_DIR_RECV) ^
      (b->originate == LINK_ORIGINATE_LOCAL));
  KEYDEBUG((hash, sizeof(hash), "GetAsymmetricKey"));
  memcpy(key0, hash, MPPE_KEY_LEN);
  KEYDEBUG((key0, MPPE_KEY_LEN, "InitialKey"));
  return;

fail:
  FsmFailure(&ccp->fsm, FAIL_CANT_ENCRYPT);
  FsmFailure(&b->ipcp.fsm, FAIL_CANT_ENCRYPT);
}

#ifdef DEBUG_KEYS

/*
 * KeyDebug()
 */

static void
KeyDebug(const u_char *data, int len, const char *fmt, ...)
{
  char		buf[100];
  int		k;
  va_list	args;

  va_start(args, fmt);
  vsnprintf(buf, sizeof(buf), fmt, args);
  va_end(args);
  snprintf(buf + strlen(buf), sizeof(buf) - strlen(buf), ":");
  for (k = 0; k < len; k++) {
    snprintf(buf + strlen(buf), sizeof(buf) - strlen(buf),
      " %02x", (u_char) data[k]);
  }
  Log(LG_ERR, ("%s", buf));
}

#endif	/* DEBUG_KEYS */

static int
MppcKeyAvailable(Bund b, short type) {

    if (b->params.msoft.chap_alg == CHAP_ALG_MSOFT) {
	if (((type == 128) && (!b->params.msoft.has_nt_hash)) ||
	    ((type != 128) && (!b->params.msoft.has_lm_hash))) {
		return (0);
	}
    } else {
	if (!b->params.msoft.has_keys && !b->params.msoft.has_nt_hash) {
	    return (0);
	}
    }
    return (1);
}

/*
 * MppcTestCap()
 */

int
MppcTestCap(void)
{
    struct ng_mppc_config	conf;
    struct ngm_mkpeer		mp;
    char			path[NG_PATHSIZ];
    int				cs, ds;

    /* Create a netgraph socket node */
    if (NgMkSockNode(NULL, &cs, &ds) < 0) {
	Log(LG_ERR, ("MppcTestCap: can't create socket node: %s",
    	    strerror(errno)));
    	return(-1);
    }

    /* Attach a new MPPC node */
    snprintf(mp.type, sizeof(mp.type), "%s", NG_MPPC_NODE_TYPE);
    snprintf(mp.ourhook, sizeof(mp.ourhook), "mppc");
    snprintf(mp.peerhook, sizeof(mp.peerhook), "%s", NG_MPPC_HOOK_COMP);
    if (NgSendMsg(cs, ".",
      NGM_GENERIC_COOKIE, NGM_MKPEER, &mp, sizeof(mp)) < 0) {
	Log(LG_ERR, ("MppcTestCap: can't create %s node: %s",
    	    mp.type, strerror(errno)));
	goto done;
    }

    /* Initialize configuration structure */
    memset(&conf, 0, sizeof(conf));
    conf.enable = 1;
    conf.bits = MPPC_BIT;

    /* Configure MPPC node */
    if (NgSendMsg(cs, "mppc",
      NGM_MPPC_COOKIE, NGM_MPPC_CONFIG_COMP, &conf, sizeof(conf)) < 0) {
        if (errno != EPROTONOSUPPORT) {
	    Log(LG_ERR, ("MppcTestCap: can't config %s node at %s: %s",
    		NG_MPPC_NODE_TYPE, path, strerror(errno)));
	}
    } else 
	MPPCPresent = 1;

    conf.bits = MPPE_128;

    /* Configure MPPC node */
    if (NgSendMsg(cs, "mppc",
      NGM_MPPC_COOKIE, NGM_MPPC_CONFIG_COMP, &conf, sizeof(conf)) < 0) {
        if (errno != EPROTONOSUPPORT) {
	    Log(LG_ERR, ("MppcTestCap: can't config %s node at %s: %s",
    		NG_MPPC_NODE_TYPE, path, strerror(errno)));
	}
    } else 
	MPPEPresent = 1;

    /* Done */
done:
    close(cs);
    close(ds);
    return(0);
}

