
/*
 * ecp_des.h
 *
 * Written by Archie Cobbs <archie@freebsd.org>
 * Copyright (c) 1998-1999 Whistle Communications, Inc. All rights reserved.
 * See ``COPYRIGHT.whistle''
 */

#ifndef _ECP_DES_H_
#define _ECP_DES_H_

#include "defs.h"
#include "mbuf.h"
#include <des.h>

/*
 * DEFINITIONS
 */

  struct desinfo
  {
    des_cblock		xmit_ivec;	/* Xmit initialization vector */
    des_cblock		recv_ivec;	/* Recv initialization vector */
    u_int16_t		xmit_seq;	/* Transmit sequence number */
    u_int16_t		recv_seq;	/* Receive sequence number */
    des_key_schedule	ks;		/* Key schedule */
  };
  typedef struct desinfo	*DesInfo;

/*
 * VARIABLES
 */

  extern const struct enctype	gDesEncType;

#endif

