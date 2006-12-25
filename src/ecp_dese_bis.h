
/*
 * ecp_des.h
 *
 * Rewritten by Alexander Motin <mav@alkar.net>
 * Written by Archie Cobbs <archie@freebsd.org>
 * Copyright (c) 1998-1999 Whistle Communications, Inc. All rights reserved.
 * See ``COPYRIGHT.whistle''
 */

#ifndef _ECP_DESE_BIS_H_
#define _ECP_DESE_BIS_H_

#include "defs.h"
#include "mbuf.h"
#include <openssl/des.h>

/*
 * DEFINITIONS
 */

  struct desebisinfo
  {
    des_cblock		xmit_ivec;	/* Xmit initialization vector */
    des_cblock		recv_ivec;	/* Recv initialization vector */
    u_int16_t		xmit_seq;	/* Transmit sequence number */
    u_int16_t		recv_seq;	/* Receive sequence number */
    des_key_schedule	ks;		/* Key schedule */
  };
  typedef struct desebisinfo	*DeseBisInfo;

/*
 * VARIABLES
 */

  extern const struct enctype	gDeseBisEncType;

#endif

