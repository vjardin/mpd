
/*
 * ecp_des.c
 *
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

  static int	DesSubtractBloat(int size);
  static void	DesConfigure(void);
  static Mbuf	DesEncrypt(Mbuf plain);
  static Mbuf	DesDecrypt(Mbuf cypher);

  static u_char	*DesBuildConfigReq(u_char *cp);
  static void	DesDecodeConfigReq(Fsm fp, FsmOption opt, int mode);

/*
 * GLOBAL VARIABLES
 */

  const struct enctype	gDesEncType =
  {
    "des",
    ECP_TY_DES,
    NULL,
    DesConfigure,
    DesSubtractBloat,
    DesEncrypt,
    DesDecrypt,
    NULL,
    DesBuildConfigReq,
    DesDecodeConfigReq,
    NULL,
    NULL,
    NULL,
  };

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
  size -= DES_OVERHEAD;
  size &= ~0x7;
  return(size);
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
  const int	clen = roundup2(plen, 8);
  Mbuf		cypher;
  int		k;

/* Get mbuf for encrypted frame */

  cypher = mballoc(MB_CRYPT, DES_OVERHEAD + clen);
  cypher->cnt = DES_OVERHEAD + clen;

/* Copy in sequence number */

  MBDATA(cypher)[0] = des->xmit_seq >> 8;
  MBDATA(cypher)[1] = des->xmit_seq & 0xff;
  des->xmit_seq++;

/* Copy in plaintext and encrypt it */

  mbcopy(plain, MBDATA(cypher) + DES_OVERHEAD, plen);
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

/* Done */

  return(plain);
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
  return(FsmConfValue(cp, ECP_TY_DES, 8, des->xmit_ivec));
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

