
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
#include <md4.h>

#include <netgraph/ng_message.h>
#include <netgraph/ng_ppp.h>
#include <netgraph.h>

/*
 * This implements both MPPC compression and MPPE encryption.
 */

/*
 * DEFINITIONS
 */

  /* #define DEBUG_KEYS */

#ifdef ENCRYPTION_MPPE
#define MPPC_SUPPORTED	(MPPC_BIT | MPPE_BITS | MPPE_STATELESS)
#else
#define MPPC_SUPPORTED	(MPPC_BIT | MPPE_STATELESS)
#endif

/*
 * INTERNAL FUNCTIONS
 */

  static int	MppcInit(int dir);
  static char	*MppcDescribe(int xmit);
  static int	MppcSubtractBloat(int size);
  static void	MppcCleanup(int dir);
  static u_char	*MppcBuildConfigReq(u_char *cp);
  static void	MppcDecodeConfigReq(Fsm fp, FsmOption opt, int mode);
  static Mbuf	MppcRecvResetReq(int id, Mbuf bp, int *noAck);
  static char	*MppcDescribeBits(u_int32_t bits);
  static int	MppcNegotiated(int xmit);

  /* Encryption stuff */
#ifdef ENCRYPTION_MPPE
  static void	MppeInitKey(MppcInfo mppc, int dir);
  static int	MppeGetKeyInfo(char **secretp, u_char **challengep);
  static void	MppeInitKeyv2(MppcInfo mppc, int dir);
  static int	MppeGetKeyInfov2(char **secretp, u_char **responsep);

#ifdef DEBUG_KEYS
  static void	KeyDebug(const u_char *data, int len, const char *fmt, ...);
  #define KEYDEBUG(x)	KeyDebug x
#else
  #define KEYDEBUG(x)
#endif

#endif	/* ENCRYPTION_MPPE */

/*
 * GLOBAL VARIABLES
 */

  const struct comptype	gCompMppcInfo = {
    "mppc",
    CCP_TY_MPPC,
    MppcInit,
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
  };

/*
 * MppcInit()
 */

static int
MppcInit(int dir)
{
  MppcInfo		const mppc = &bund->ccp.mppc;
  struct ng_mppc_config	conf;
  struct ngm_mkpeer	mp;
  char			path[NG_PATHLEN + 1];
  const char		*mppchook, *ppphook;
  int			mschap;
  int			cmd;

  /* Which type of MS-CHAP did we do? */
  if (bund->links[0]->originate == LINK_ORIGINATE_LOCAL)
    mschap = lnk->lcp.peer_chap_alg;
  else
    mschap = lnk->lcp.want_chap_alg;

  /* Initialize configuration structure */
  memset(&conf, 0, sizeof(conf));
  conf.enable = 1;
  switch (dir) {
    case COMP_DIR_XMIT:
      cmd = NGM_MPPC_CONFIG_COMP;
      ppphook = NG_PPP_HOOK_COMPRESS;
      mppchook = NG_MPPC_HOOK_COMP;
      conf.bits = mppc->xmit_bits;
#ifdef ENCRYPTION_MPPE
      if (mschap == CHAP_ALG_MSOFTv2) {
        MppeInitKeyv2(mppc, dir);
      } else {
        MppeInitKey(mppc, dir);
      }
      memcpy(conf.startkey, mppc->xmit_key0, sizeof(conf.startkey));
#endif
      break;
    case COMP_DIR_RECV:
      cmd = NGM_MPPC_CONFIG_DECOMP;
      ppphook = NG_PPP_HOOK_DECOMPRESS;
      mppchook = NG_MPPC_HOOK_DECOMP;
      conf.bits = mppc->recv_bits;
#ifdef ENCRYPTION_MPPE
      if (mschap == CHAP_ALG_MSOFTv2) {
        MppeInitKeyv2(mppc, dir);
      } else {
        MppeInitKey(mppc, dir);
      }
      memcpy(conf.startkey, mppc->recv_key0, sizeof(conf.startkey));
#endif
      break;
    default:
      assert(0);
      return(-1);
  }

  /* Attach a new MPPC node to the PPP node */
  snprintf(mp.type, sizeof(mp.type), "%s", NG_MPPC_NODE_TYPE);
  snprintf(mp.ourhook, sizeof(mp.ourhook), "%s", ppphook);
  snprintf(mp.peerhook, sizeof(mp.peerhook), "%s", mppchook);
  if (NgSendMsg(bund->csock, MPD_HOOK_PPP,
      NGM_GENERIC_COOKIE, NGM_MKPEER, &mp, sizeof(mp)) < 0) {
    Log(LG_ERR, ("[%s] can't create %s node: %s",
      bund->name, mp.type, strerror(errno)));
    return(-1);
  }

  /* Configure MPPC node */
  snprintf(path, sizeof(path), "%s.%s", MPD_HOOK_PPP, ppphook);
  if (NgSendMsg(bund->csock, path,
      NGM_MPPC_COOKIE, cmd, &conf, sizeof(conf)) < 0) {
    Log(LG_ERR, ("[%s] can't config %s node at %s: %s",
      bund->name, NG_MPPC_NODE_TYPE, path, strerror(errno)));
    NgFuncDisconnect(MPD_HOOK_PPP, ppphook);
    return(-1);
  }

  /* Done */
  return(0);
}

/*
 * MppcDescribe()
 */

static char *
MppcDescribe(int dir)
{
  MppcInfo	const mppc = &bund->ccp.mppc;

  switch (dir) {
    case COMP_DIR_XMIT:
      return(MppcDescribeBits(mppc->xmit_bits));
    case COMP_DIR_RECV:
      return(MppcDescribeBits(mppc->recv_bits));
    default:
      assert(0);
      return(NULL);
  }
}

/*
 * MppcSubtractBloat()
 */

static int
MppcSubtractBloat(int size)
{
  if ((bund->ccp.mppc.xmit_bits & MPPC_BIT) != 0) {
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
  return(size);
}

/*
 * MppcNegotiated()
 */

static int
MppcNegotiated(int dir)
{
  MppcInfo	const mppc = &bund->ccp.mppc;

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
MppcCleanup(int dir)
{
  const char	*ppphook;
  char		path[NG_PATHLEN + 1];

  /* Remove node */
  switch (dir) {
    case COMP_DIR_XMIT:
      ppphook = NG_PPP_HOOK_DECOMPRESS;
      break;
    case COMP_DIR_RECV:
      ppphook = NG_PPP_HOOK_COMPRESS;
      break;
    default:
      assert(0);
      return;
  }
  snprintf(path, sizeof(path), "%s.%s", MPD_HOOK_PPP, ppphook);
  (void)NgFuncShutdownNode(bund, bund->name, path);
}

/*
 * MppcBuildConfigReq()
 */

static u_char *
MppcBuildConfigReq(u_char *cp)
{
  CcpState	const ccp = &bund->ccp;
  MppcInfo	const mppc = &ccp->mppc;
  u_int32_t	bits = 0;

  /* Compression */
  if (Enabled(&ccp->options, gMppcCompress)
      && !CCP_PEER_REJECTED(ccp, gMppcCompress))
    bits |= MPPC_BIT;

#ifdef ENCRYPTION_MPPE
  /* Encryption */
  if (Enabled(&ccp->options, gMppe40) && !CCP_PEER_REJECTED(ccp, gMppe40))
    bits |= MPPE_40;
  if (Enabled(&ccp->options, gMppe128) && !CCP_PEER_REJECTED(ccp, gMppe128))
    bits |= MPPE_128;
#endif

  /* Stateless mode */
  if (Enabled(&ccp->options, gMppcStateless)
      && !CCP_PEER_REJECTED(ccp, gMppcStateless)
      && bits != 0)
    bits |= MPPE_STATELESS;

  /* Ship it */
  mppc->recv_bits = bits;
  if (bits != 0)
    cp = FsmConfValue(cp, CCP_TY_MPPC, -4, &bits);
  return(cp);
}

/*
 * MppcDecodeConfigReq()
 */

static void
MppcDecodeConfigReq(Fsm fp, FsmOption opt, int mode)
{
  CcpState	const ccp = &bund->ccp;
  MppcInfo	const mppc = &ccp->mppc;
  u_int32_t	*const bitsp = (u_int32_t *) opt->data;
  u_int32_t	bits = ntohl(*bitsp);

  /* Sanity check */
  if (opt->len != 6) {
    Log(LG_CCP, ("   bogus length %d", opt->len));
    if (mode == MODE_REQ)
      FsmRej(fp, opt);
    return;
  }

  /* Display it */
  Log(LG_CCP, ("   0x%08x:%s", bits, MppcDescribeBits(bits)));

  /* Deal with it */
  switch (mode) {
    case MODE_REQ:

      /* Check for supported bits */
      if (bits & ~MPPC_SUPPORTED) {
	Log(LG_CCP, ("   Bits 0x%08x not supported", bits & ~MPPC_SUPPORTED));
	bits &= MPPC_SUPPORTED;
      }

      /* Check compression */
      if ((bits & MPPC_BIT) && !Acceptable(&ccp->options, gMppcCompress))
	bits &= ~MPPC_BIT;

#ifdef ENCRYPTION_MPPE

      /* Check encryption */
      if ((bits & MPPE_40) && !Acceptable(&ccp->options, gMppe40))
	bits &= ~MPPE_40;
      if ((bits & MPPE_128) && !Acceptable(&ccp->options, gMppe128))
	bits &= ~MPPE_128;

      /* Choose the strongest encryption available */
      if (bits & MPPE_128)
	bits &= ~MPPE_40;
      else if (bits & MPPE_40)
	bits &= ~MPPE_128;

      /* It doesn't really make sense to encrypt in only one direction.
	 Also, Win95/98 PPTP can't handle uni-directional encryption. So
	 if the remote side doesn't request encryption, try to prompt it.
	 This is broken wrt. normal PPP negotiation: typical Microsoft. */
      if (!(bits & MPPE_BITS)) {
	if (Enabled(&ccp->options, gMppe40)
	    && !CCP_PEER_REJECTED(ccp, gMppe40))
	  bits |= MPPE_40;
	if (Enabled(&ccp->options, gMppe128)
	    && !CCP_PEER_REJECTED(ccp, gMppe128))
	  bits |= MPPE_128;
      }
#endif

      /* Stateless mode */
      if ((bits & MPPE_STATELESS) && !Acceptable(&ccp->options, gMppcStateless))
	bits &= ~MPPE_STATELESS;

      /* See if what we want equals what was sent */
      mppc->xmit_bits = bits;
      if (bits != ntohl(*bitsp)) {
	*bitsp = htonl(bits);
	FsmNak(fp, opt);
      }
      else
	FsmAck(fp, opt);
      break;

    case MODE_NAK:
      if (!(bits & MPPC_BIT))
	CCP_PEER_REJ(ccp, gMppcCompress);
#ifdef ENCRYPTION_MPPE
      if (!(bits & MPPE_40))
	CCP_PEER_REJ(ccp, gMppe40);
      if (!(bits & MPPE_128))
	CCP_PEER_REJ(ccp, gMppe128);
#endif
      if (!(bits & MPPE_STATELESS))
	CCP_PEER_REJ(ccp, gMppcStateless);
      break;
  }
}

/*
 * MppcRecvResetReq()
 */

static Mbuf
MppcRecvResetReq(int id, Mbuf bp, int *noAck)
{
  char	path[NG_PATHLEN + 1];

  /* Forward ResetReq to the MPPC compression node */
  snprintf(path, sizeof(path), "%s.%s", MPD_HOOK_PPP, NG_PPP_HOOK_COMPRESS);
  if (NgSendMsg(bund->csock, path,
      NGM_MPPC_COOKIE, NGM_MPPC_RESETREQ, NULL, 0) < 0) {
    Log(LG_ERR, ("[%s] reset-req to %s node: %s",
      bund->name, NG_MPPC_NODE_TYPE, strerror(errno)));
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
MppcDescribeBits(u_int32_t bits)
{
  static char	buf[100];

  *buf = 0;
  if (bits & MPPC_BIT)
    snprintf(buf + strlen(buf), sizeof(buf) - strlen(buf), " MPPC");
  if (bits & MPPE_BITS) {
    snprintf(buf + strlen(buf), sizeof(buf) - strlen(buf), " MPPE");
    if (bits & MPPE_40)
      snprintf(buf + strlen(buf), sizeof(buf) - strlen(buf), ", 40 bit");
    if (bits & MPPE_128)
      snprintf(buf + strlen(buf), sizeof(buf) - strlen(buf), ", 128 bit");
    if (bits & MPPE_STATELESS)
      snprintf(buf + strlen(buf), sizeof(buf) - strlen(buf), ", stateless");
  }
  return(buf);
}

#ifdef ENCRYPTION_MPPE

#define KEYLEN(b)	(((b) & MPPE_128) ? 16 : 8)

/*
 * MppeInitKey()
 */

static void
MppeInitKey(MppcInfo mppc, int dir)
{
  u_int32_t	const bits = (dir == COMP_DIR_XMIT) ?
			mppc->xmit_bits : mppc->recv_bits;
  u_char	*const key0 = (dir == COMP_DIR_XMIT) ?
			mppc->xmit_key0 : mppc->recv_key0;
  u_char	hash[16];
  char		*pass;
  u_char	*chal;

  /* Get credential info */
  if (MppeGetKeyInfo(&pass, &chal) < 0)
    return;

  /* Compute basis for the session key (ie, "start key" or key0) */
  if (bits & MPPE_128) {
    MD4_CTX	c;

    NTPasswordHash(pass, hash);
    KEYDEBUG((hash, sizeof(hash), "NTPasswordHash"));
    MD4Init(&c);
    MD4Update(&c, hash, 16);
    MD4Final(hash, &c);
    KEYDEBUG((hash, sizeof(hash), "MD4 of that"));
    KEYDEBUG((chal, CHAP_MSOFT_CHAL_LEN, "Challenge"));
    MsoftGetStartKey(chal, hash);
    KEYDEBUG((hash, sizeof(hash), "GetStartKey"));
  } else {
    LMPasswordHash(pass, hash);
    KEYDEBUG((hash, sizeof(hash), "LMPasswordHash"));
  }
  memcpy(key0, hash, MPPE_KEY_LEN);
  KEYDEBUG((key0, (bits & MPPE_128) ? 16 : 8, "InitialKey"));
}

/*
 * MppeGetKeyInfo()
 *
 * This is described in:
 *   draft-ietf-pppext-mschapv1-keys-00.txt
 */

static int
MppeGetKeyInfo(char **secretp, u_char **challengep)
{
  CcpState		const ccp = &bund->ccp;
  static char		password[AUTH_MAX_PASSWORD];
  char			*authname;
  u_char		*challenge;
  struct authdata	auth;

  /* The secret comes from the originating caller's credentials */
  switch (lnk->originate) {
    case LINK_ORIGINATE_LOCAL:
      if (lnk->lcp.peer_auth != PROTO_CHAP
	  || (lnk->lcp.peer_chap_alg != CHAP_ALG_MSOFT
	    && lnk->lcp.peer_chap_alg != CHAP_ALG_MSOFTv2)) {
	Log(LG_ERR,
	  ("[%s] \"%s chap\" required for MPPE", lnk->name, "accept"));
	goto fail;
      }
      authname = bund->conf.authname;
      challenge = bund->peer_msChal;
      break;
    case LINK_ORIGINATE_REMOTE:
      if (lnk->lcp.want_auth != PROTO_CHAP
	  || (lnk->lcp.want_chap_alg != CHAP_ALG_MSOFT
	    && lnk->lcp.want_chap_alg != CHAP_ALG_MSOFTv2)) {
	Log(LG_ERR,
	  ("[%s] \"%s chap\" required for MPPE", lnk->name, "enable"));
	goto fail;
      }
      authname = bund->peer_authname;
      challenge = bund->self_msChal;
      break;
    case LINK_ORIGINATE_UNKNOWN:
    default:
      Log(LG_ERR, ("[%s] can't determine link direction for MPPE", lnk->name));
      goto fail;
  }

  /* Get password corresponding to whichever account name */
  if (AuthGetData(authname, &auth, 1, NULL) >= 0) {
    snprintf(password, sizeof(password), "%s", auth.password);
  } else {
    LogPrintf("[%s] unable to get data for authname \"%s\"",
      bund->name, authname);
    goto fail;
  }

  /* Return info */
  *secretp = password;
  *challengep = challenge;
  return(0);

fail:
  Log(LG_ERR, ("[%s] can't determine credentials for MPPE", bund->name));
  FsmFailure(&ccp->fsm, FAIL_CANT_ENCRYPT);
  return(-1);
}

/*
 * MppeInitKeyv2()
 */

static void
MppeInitKeyv2(MppcInfo mppc, int dir)
{
  u_char	*const key0 = (dir == COMP_DIR_XMIT) ?
			mppc->xmit_key0 : mppc->recv_key0;
  u_char	hash[16];
  char		*pass;
  u_char	*resp;

  MD4_CTX	c;

  /* Get credential info */
  if (MppeGetKeyInfov2(&pass, &resp) < 0)
    return;

  /* Compute basis for the session key (ie, "start key" or key0) */
  NTPasswordHash(pass, hash);
  KEYDEBUG((hash, sizeof(hash), "NTPasswordHash"));
  MD4Init(&c);
  MD4Update(&c, hash, 16);
  MD4Final(hash, &c);
  KEYDEBUG((hash, sizeof(hash), "MD4 of that"));
  KEYDEBUG((resp, CHAP_MSOFTv2_CHAL_LEN, "Response"));
  MsoftGetMasterKey(resp, hash);
  KEYDEBUG((hash, sizeof(hash), "GetMasterKey"));
  MsoftGetAsymetricStartKey(hash,
    (dir == COMP_DIR_RECV) ^
      (bund->links[0]->originate == LINK_ORIGINATE_LOCAL));
  KEYDEBUG((hash, sizeof(hash), "GetAsymmetricKey"));
  memcpy(key0, hash, MPPE_KEY_LEN);
  KEYDEBUG((key0, MPPE_KEY_LEN, "InitialKey"));
}

/*
 * MppeGetKeyInfov2()
 */

static int
MppeGetKeyInfov2(char **secretp, u_char **responsep)
{
  CcpState		const ccp = &bund->ccp;
  static char		password[AUTH_MAX_PASSWORD];
  char			*authname;
  u_char		*response;
  struct authdata	auth;

  /* The secret comes from the originating caller's credentials */
  switch (lnk->originate) {
    case LINK_ORIGINATE_LOCAL:
      if (lnk->lcp.peer_auth != PROTO_CHAP
	  || (lnk->lcp.peer_chap_alg != CHAP_ALG_MSOFT
	    && lnk->lcp.peer_chap_alg != CHAP_ALG_MSOFTv2)) {
	Log(LG_ERR,
	  ("[%s] \"%s chap\" required for MPPE", lnk->name, "accept"));
	goto fail;
      }
      authname = bund->conf.authname;
      response = bund->msNTresponse;
      break;
    case LINK_ORIGINATE_REMOTE:
      if (lnk->lcp.want_auth != PROTO_CHAP
	  || (lnk->lcp.want_chap_alg != CHAP_ALG_MSOFT
	    && lnk->lcp.want_chap_alg != CHAP_ALG_MSOFTv2)) {
	Log(LG_ERR,
	  ("[%s] \"%s chap\" required for MPPE", lnk->name, "enable"));
	goto fail;
      }
      authname = bund->peer_authname;
      response = bund->msNTresponse;
      break;
    case LINK_ORIGINATE_UNKNOWN:
    default:
      Log(LG_ERR, ("[%s] can't determine link direction for MPPE", lnk->name));
      goto fail;
  }

  /* Get password corresponding to whichever account name */
  if (AuthGetData(authname, &auth, 1, NULL) >= 0) {
    snprintf(password, sizeof(password), "%s", auth.password);
  } else {
    LogPrintf("[%s] unable to get data for authname \"%s\"",
      bund->name, authname);
    goto fail;
  }

  /* Return info */
  *secretp = password;
  *responsep = response;
  return(0);

fail:
  Log(LG_ERR, ("[%s] can't determine credentials for MPPE", bund->name));
  FsmFailure(&ccp->fsm, FAIL_CANT_ENCRYPT);
  return(-1);
}

#endif	/* ENCRYPTION_MPPE */

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

