
/*
 * chap.h
 *
 * Written by Toshiharu OHNO <tony-o@iij.ad.jp>
 * Copyright (c) 1993, Internet Initiative Japan, Inc. All rights reserved.
 * See ``COPYRIGHT.iij''
 * 
 * Rewritten by Archie Cobbs <archie@whistle.com>
 * Copyright (c) 1995-1999 Whistle Communications, Inc. All rights reserved.
 * See ``COPYRIGHT.whistle''
 */

#ifndef _CHAP_H_
#define	_CHAP_H_

#include "mbuf.h"
#include "timer.h"

/*
 * DEFINITIONS
 */

  #define CHAP_MAX_NAME		64
  #define CHAP_MAX_VAL		64

  #define CHAP_ALG_MD5		0x05
  #define CHAP_ALG_MSOFT	0x80
  #define CHAP_ALG_MSOFTv2	0x81

  #define CHAP_MSOFT_CHAL_LEN	8

  #define MSCHAP_ERROR_RESTRICTED_LOGON_HOURS	646 
  #define MSCHAP_ERROR_ACCT_DISABLED		647 
  #define MSCHAP_ERROR_PASSWD_EXPIRED		648 
  #define MSCHAP_ERROR_NO_DIALIN_PERMISSION	649 
  #define MSCHAP_ERROR_AUTHENTICATION_FAILURE	691 
  #define MSCHAP_ERROR_CHANGING_PASSWORD	709 

  struct chapinfo
  {
    short		next_id;			/* Packet id */
    short		retry;				/* Resend count */
    struct pppTimer	chalTimer;			/* Challenge timer */
    struct pppTimer	respTimer;			/* Reponse timer */
    char		chal_data[CHAP_MAX_VAL];	/* Challenge sent */
    u_char		xmit_alg;			/* Peer auth us with */
    u_char		recv_alg;			/* We auth peer with */
    u_char		resp_id;			/* Response ID */
    short		chal_len;			/* Challenge length */
    short		resp_len;			/* Response length */
    u_char		*resp;				/* Response packet */
  };
  typedef struct chapinfo	*ChapInfo;

/*
 * FUNCTIONS
 */

  extern void	ChapStart(ChapInfo chap, int which);
  extern void	ChapStop(ChapInfo chap);
  extern void	ChapInput(Mbuf bp);

#endif

