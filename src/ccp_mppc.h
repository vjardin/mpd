
/*
 * ccp_mppc.h
 *
 * Written by Archie Cobbs <archie@freebsd.org>
 * Copyright (c) 1998-1999 Whistle Communications, Inc. All rights reserved.
 * See ``COPYRIGHT.whistle''
 */

#ifndef _CCP_MPPC_H_
#define _CCP_MPPC_H_

#include "defs.h"
#include "mbuf.h"
#include "comp.h"

#include <netgraph/ng_message.h>
#include <netgraph/ng_mppc.h>

/* 56 bit MPPE support was only added in FreeBSD 4.5 */
#ifndef MPPE_56
#define MPPE_56_UNSUPPORTED
#define MPPE_56		0x00000080
#undef MPPE_BITS
#define MPPE_BITS	0x000000e0
#endif

/*
 * DEFINITIONS
 */

  struct mppcinfo {
    u_int32_t	recv_bits;			/* recv config bits */
    u_int32_t	xmit_bits;			/* xmit config bits */
    u_char	xmit_key0[MPPE_KEY_LEN];	/* xmit start key */
    u_char	recv_key0[MPPE_KEY_LEN];	/* recv start key */
  };
  typedef struct mppcinfo	*MppcInfo;

/*
 * VARIABLES
 */

  extern const struct comptype	gCompMppcInfo;

#endif

