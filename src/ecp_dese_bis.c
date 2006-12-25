
/*
 * ecp_dese.c
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

  static int	DeseBisInit(int dir);
  static void	DeseBisConfigure(void);
  static int	DeseBisSubtractBloat(int size);
  static Mbuf	DeseBisEncrypt(Mbuf plain);
  static Mbuf	DeseBisDecrypt(Mbuf cypher);
  static void	DeseBisCleanup(int dir);

  static u_char	*DeseBisBuildConfigReq(u_char *cp);
  static void	DeseBisDecodeConfigReq(Fsm fp, FsmOption opt, int mode);

/*
 * GLOBAL VARIABLES
 */

  const struct enctype	gDeseBisEncType =
  {
    "dese-bis",
    ECP_TY_DESE_bis,
    DeseBisInit,
    DeseBisConfigure,
    DeseBisSubtractBloat,
    DeseBisEncrypt,
    DeseBisDecrypt,
    DeseBisCleanup,
    DeseBisBuildConfigReq,
    DeseBisDecodeConfigReq,
    NULL,
    NULL,
    NULL,
  };

/*
 * DeseBisInit()
 */

static int
DeseBisInit(int dir)
{
  EcpState	const ecp = &bund->ecp;
  DeseBisInfo	const des = &ecp->desebis;

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
 * DeseBisConfigure()
 */

static void
DeseBisConfigure(void)
{
  EcpState	const ecp = &bund->ecp;
  DeseBisInfo	const des = &ecp->desebis;
  des_cblock	key;

  des_check_key = FALSE;
  des_string_to_key(ecp->key, &key);
  des_set_key(&key, des->ks);
  des->xmit_seq = 0;
  des->recv_seq = 0;
}

/*
 * DeseBisSubtractBloat()
 */

static int
DeseBisSubtractBloat(int size)
{
  size -= DES_OVERHEAD;	/* reserve space for header */
  size--;	 	/* reserve space for possible padding */
  size &= ~0x7;
  return(size);
}

/*
 * DeseBisEncrypt()
 */

Mbuf
DeseBisEncrypt(Mbuf plain)
{
  EcpState	const ecp = &bund->ecp;
  DeseBisInfo	const des = &ecp->desebis;
  const int	plen = plength(plain);
  int		padlen = roundup2(plen + 1, 8) - plen;
  int		clen = plen + padlen;
  Mbuf		cypher;
  int		k;

/* Get mbuf for encrypted frame */

  cypher = mballoc(MB_CRYPT, DES_OVERHEAD + clen);

/* Copy in sequence number */

  MBDATA(cypher)[0] = des->xmit_seq >> 8;
  MBDATA(cypher)[1] = des->xmit_seq & 0xff;
  des->xmit_seq++;

/* Copy in plaintext */

  mbcopy(plain, MBDATA(cypher) + DES_OVERHEAD, plen);

/* Correct and add padding */

  if ((padlen>7) &&
    ((MBDATA(cypher)[plen-1]==0) ||
     (MBDATA(cypher)[plen-1]>8))) {
        padlen -=8;
	clen = plen + padlen;
  }
  for (k = 0; k < padlen; k++) {
    MBDATA(cypher)[DES_OVERHEAD + plen + k] = k + 1;
  }
  
  cypher->cnt = DES_OVERHEAD + clen;
  
/* Copy in plaintext and encrypt it */
  
  for (k = 0; k < clen; k += 8)
  {
    u_char	*const block = MBDATA(cypher) + DES_OVERHEAD + k;

    des_cbc_encrypt(block, block, 8, des->ks, &des->xmit_ivec, TRUE);
    memcpy(des->xmit_ivec, block, 8);
  }

/* Return cyphertext */

  PFREE(plain);
  return(cypher);
}

/*
 * DeseBisDecrypt()
 */

Mbuf
DeseBisDecrypt(Mbuf cypher)
{
  EcpState	const ecp = &bund->ecp;
  DeseBisInfo	des = &ecp->desebis;
  const int	clen = plength(cypher) - DES_OVERHEAD;
  u_int16_t	seq;
  Mbuf		plain;
  int		k;

/* Get mbuf for plaintext */

  if (clen < 8 || (clen & 0x7))
  {
    Log(LG_ECP, ("[%s] EDES: rec'd bogus DES cypher: len=%d",
      bund->name, clen + DES_OVERHEAD));
    return(NULL);
  }

/* Check sequence number */

  cypher = mbread(cypher, (u_char *) &seq, DES_OVERHEAD, NULL);
  seq = ntohs(seq);
  if (seq != des->recv_seq)
  {
    Mbuf	tail;

  /* Recover from dropped packet */

    Log(LG_ECP, ("[%s] EDES: rec'd wrong seq=%u, expected %u",
      bund->name, seq, des->recv_seq));
    tail = mbsplit(cypher, clen - 8);
    PFREE(cypher);
    tail = mbread(tail, (u_char *) &des->recv_ivec, 8, NULL);
    assert(!tail);
    des->recv_seq = seq + 1;
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

/* Strip padding */
  if (MBDATA(plain)[clen-1]>0 &&
    MBDATA(plain)[clen-1]<=8) {
      mbtrunc(plain, clen - MBDATA(plain)[clen-1]);
  }

/* Done */

  return(plain);
}

/*
 * DeseBisCleanup()
 */

static void
DeseBisCleanup(int dir)
{
}

/*
 * DeseBisBuildConfigReq()
 */

static u_char *
DeseBisBuildConfigReq(u_char *cp)
{
  EcpState	const ecp = &bund->ecp;
  DeseBisInfo	const des = &ecp->desebis;

  ((u_int32_t *) des->xmit_ivec)[0] = random();
  ((u_int32_t *) des->xmit_ivec)[1] = random();
  return(FsmConfValue(cp, ECP_TY_DESE_bis, 8, des->xmit_ivec));
}

/*
 * DeseBisDecodeConfigReq()
 */

static void
DeseBisDecodeConfigReq(Fsm fp, FsmOption opt, int mode)
{
  DeseBisInfo	const des = &bund->ecp.desebis;

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

