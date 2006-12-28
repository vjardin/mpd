
/*
 * ecp_des.c
 *
 * Rewritten by Alexander Motin <mav@alkar.net>
 * Written by Archie Cobbs <archie@freebsd.org>
 * Copyright (c) 1998-1999 Whistle Communications, Inc. All rights reserved.
 * See ``COPYRIGHT.whistle''
 */

#include "ppp.h"
#include "ecp.h"
#include "log.h"

/*
 * DEFINITIONS
 */

  #define DES_OVERHEAD		2

/*
 * INTERNAL FUNCTIONS
 */

  static int	DesInit(int dir);
  static void	DesConfigure(void);
  static int	DesSubtractBloat(int size);
  static Mbuf	DesEncrypt(Mbuf plain);
  static Mbuf	DesDecrypt(Mbuf cypher);
  static void	DesCleanup(int dir);
  static int	DesStat(int dir);

  static u_char	*DesBuildConfigReq(u_char *cp);
  static void	DesDecodeConfigReq(Fsm fp, FsmOption opt, int mode);

/*
 * GLOBAL VARIABLES
 */

  const struct enctype	gDeseEncType =
  {
    "dese-old",
    ECP_TY_DESE,
    DesInit,
    DesConfigure,
    DesSubtractBloat,
    DesCleanup,
    DesBuildConfigReq,
    DesDecodeConfigReq,
    NULL,
    NULL,
    NULL,
    DesStat,
    DesEncrypt,
    DesDecrypt,
  };

/*
 * DesInit()
 */

static int
DesInit(int dir)
{
  EcpState	const ecp = &bund->ecp;
  DesInfo	const des = &ecp->des;

  switch (dir) {
    case ECP_DIR_XMIT:
	des->xmit_seq = 0;
      break;
    case ECP_DIR_RECV:
	des->recv_seq = 0;
      break;
    default:
      assert(0);
      return(-1);
  }
  return(0);
}

/*
 * DesConfigure()
 */

static void
DesConfigure(void)
{
  EcpState	const ecp = &bund->ecp;
  DesInfo	const des = &ecp->des;
  des_cblock	key;

  des_check_key = FALSE;
  des_string_to_key(ecp->key, &key);
  des_set_key(&key, des->ks);
  des->xmit_seq = 0;
  des->recv_seq = 0;
}

/*
 * DesSubtractBloat()
 */

static int
DesSubtractBloat(int size)
{
  size -= DES_OVERHEAD;	/* reserve space for header */
  size &= ~0x7;
  return(size);
}

static int
DesStat(int dir) 
{
    EcpState	const ecp = &bund->ecp;
    DesInfo	const des = &ecp->des;
    
    switch (dir) {
	case ECP_DIR_XMIT:
	    Printf("\tBytes\t: %llu -> %llu (%+lld%%)\r\n",
		des->xmit_stats.OctetsIn,
		des->xmit_stats.OctetsOut,
		((des->xmit_stats.OctetsIn!=0)?
		    ((int64_t)(des->xmit_stats.OctetsOut - des->xmit_stats.OctetsIn)*100/(int64_t)des->xmit_stats.OctetsIn):
		    0));
	    Printf("\tFrames\t: %llu -> %llu\r\n",
		des->xmit_stats.FramesIn,
		des->xmit_stats.FramesOut);
	    Printf("\tErrors\t: %llu\r\n",
		des->xmit_stats.Errors);
	    break;
	case ECP_DIR_RECV:
	    Printf("\tBytes\t: %llu <- %llu (%+lld%%)\r\n",
		des->recv_stats.OctetsOut,
		des->recv_stats.OctetsIn,
		((des->recv_stats.OctetsOut!=0)?
		    ((int64_t)(des->recv_stats.OctetsIn - des->recv_stats.OctetsOut)*100/(int64_t)des->recv_stats.OctetsOut):
		    0));
	    Printf("\tFrames\t: %llu <- %llu\r\n",
		des->xmit_stats.FramesOut,
		des->xmit_stats.FramesIn);
	    Printf("\tErrors\t: %llu\r\n",
		des->recv_stats.Errors);
    	    break;
	default:
    	    assert(0);
    }
    return (0);
}

/*
 * DesEncrypt()
 */

Mbuf
DesEncrypt(Mbuf plain)
{
  EcpState	const ecp = &bund->ecp;
  DesInfo	const des = &ecp->des;
  const int	plen = plength(plain);
  int		padlen = roundup2(plen, 8) - plen;
  int		clen = plen + padlen;
  Mbuf		cypher;
  int		k;

  des->xmit_stats.FramesIn++;
  des->xmit_stats.OctetsIn += plen;

/* Get mbuf for encrypted frame */

  cypher = mballoc(MB_CRYPT, DES_OVERHEAD + clen);

/* Copy in sequence number */

  MBDATA(cypher)[0] = des->xmit_seq >> 8;
  MBDATA(cypher)[1] = des->xmit_seq & 0xff;
  des->xmit_seq++;

/* Copy in plaintext */

  mbcopy(plain, MBDATA(cypher) + DES_OVERHEAD, plen);
  
  cypher->cnt = DES_OVERHEAD + clen;
  
/* Copy in plaintext and encrypt it */
  
  for (k = 0; k < clen; k += 8)
  {
    u_char	*const block = MBDATA(cypher) + DES_OVERHEAD + k;

    des_cbc_encrypt(block, block, 8, des->ks, &des->xmit_ivec, TRUE);
    memcpy(des->xmit_ivec, block, 8);
  }

  des->xmit_stats.FramesOut++;
  des->xmit_stats.OctetsOut += clen;

/* Return cyphertext */

  PFREE(plain);
  return(cypher);
}

/*
 * DesDecrypt()
 */

Mbuf
DesDecrypt(Mbuf cypher)
{
  EcpState	const ecp = &bund->ecp;
  DesInfo	des = &ecp->des;
  const int	clen = plength(cypher) - DES_OVERHEAD;
  u_int16_t	seq;
  Mbuf		plain;
  int		k;

  des->recv_stats.FramesIn++;
  des->recv_stats.OctetsIn += clen + DES_OVERHEAD;

/* Get mbuf for plaintext */

  if (clen < 8 || (clen & 0x7))
  {
    Log(LG_ECP, ("[%s] DESE: rec'd bogus DES cypher: len=%d",
      bund->name, clen + DES_OVERHEAD));
    des->recv_stats.Errors++;
    return(NULL);
  }

/* Check sequence number */

  cypher = mbread(cypher, (u_char *) &seq, DES_OVERHEAD, NULL);
  seq = ntohs(seq);
  if (seq != des->recv_seq)
  {
    Mbuf	tail;

  /* Recover from dropped packet */

    Log(LG_ECP, ("[%s] DESE: rec'd wrong seq=%u, expected %u",
      bund->name, seq, des->recv_seq));
    tail = mbsplit(cypher, clen - 8);
    PFREE(cypher);
    tail = mbread(tail, (u_char *) &des->recv_ivec, 8, NULL);
    assert(!tail);
    des->recv_seq = seq + 1;
    des->recv_stats.Errors++;
    return(NULL);
  }
  des->recv_seq++;

/* Decrypt frame */

  plain = mbunify(cypher);
  for (k = 0; k < clen; k += 8)
  {
    u_char	*const block = MBDATA(plain) + k;
    des_cblock	next_ivec;

    memcpy(next_ivec, block, 8);
    des_cbc_encrypt(block, block, 8, des->ks, &des->recv_ivec, FALSE);
    memcpy(des->recv_ivec, next_ivec, 8);
  }

  des->recv_stats.FramesOut++;
  des->recv_stats.OctetsOut += clen;

/* Done */

  return(plain);
}

/*
 * DesCleanup()
 */

static void
DesCleanup(int dir)
{
  EcpState	const ecp = &bund->ecp;
  DesInfo	const des = &ecp->des;
  
  if (dir == ECP_DIR_RECV)
  {
    memset(&des->recv_stats, 0, sizeof(des->recv_stats));
  }
  if (dir == ECP_DIR_XMIT)
  {
    memset(&des->xmit_stats, 0, sizeof(des->xmit_stats));
  }
}

/*
 * DesBuildConfigReq()
 */

static u_char *
DesBuildConfigReq(u_char *cp)
{
  EcpState	const ecp = &bund->ecp;
  DesInfo	const des = &ecp->des;

  ((u_int32_t *) des->xmit_ivec)[0] = random();
  ((u_int32_t *) des->xmit_ivec)[1] = random();
  return(FsmConfValue(cp, ECP_TY_DESE, 8, des->xmit_ivec));
}

/*
 * DesDecodeConfigReq()
 */

static void
DesDecodeConfigReq(Fsm fp, FsmOption opt, int mode)
{
  DesInfo	const des = &bund->ecp.des;

  if (opt->len != 10)
  {
    Log(LG_ECP, ("   bogus length %d", opt->len));
    if (mode == MODE_REQ)
      FsmRej(fp, opt);
    return;
  }
  Log(LG_ECP, ("   nonce 0x%08lx%08lx",
    (unsigned long)ntohl(((u_int32_t *) opt->data)[0]),
    (unsigned long)ntohl(((u_int32_t *) opt->data)[1])));
  switch (mode)
  {
    case MODE_REQ:
      memcpy(des->recv_ivec, opt->data, 8);
      FsmAck(fp, opt);
      break;
    case MODE_NAK:
      break;
  }
}

