
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

/*
 * DEFINITIONS
 */

  struct mppcinfo {
    u_int32_t	recv_bits;			/* recv config bits */
    u_int32_t	xmit_bits;			/* xmit config bits */
#ifdef ENCRYPTION_MPPE
    u_char	xmit_key0[MPPE_KEY_LEN];	/* xmit start key */
    u_char	recv_key0[MPPE_KEY_LEN];	/* recv start key */
#endif
  };
  typedef struct mppcinfo	*MppcInfo;

/*
 * VARIABLES
 */

  extern const struct comptype	gCompMppcInfo;

#endif

