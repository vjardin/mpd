
/*
 * ccp_pred1.h
 *
 * Rewritten by Alexander Motin <mav@alkar.net>
 * Written by Archie Cobbs <archie@freebsd.org>
 * Copyright (c) 1995-1999 Whistle Communications, Inc. All rights reserved.
 * See ``COPYRIGHT.whistle''
 */

#ifndef _PRED_H_
#define _PRED_H_

#include "defs.h"
#include "mbuf.h"
#include "comp.h"

#ifdef USE_NG_PRED1
#ifdef __DragonFly__
#include <netgraph/pred1/ng_pred1.h>
#else
#include <netgraph/ng_pred1.h>
#endif
#endif

/*
 * DEFINITIONS
 */

  #define PRED1_TABLE_SIZE	0x10000

  struct pred1info
  {
#ifndef USE_NG_PRED1
    u_short	iHash;
    u_short	oHash;
    u_char	*InputGuessTable;
    u_char	*OutputGuessTable;
#endif
  };
  typedef struct pred1info	*Pred1Info;

/*
 * VARIABLES
 */

  extern const struct comptype	gCompPred1Info;

#endif

