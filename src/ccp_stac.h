
/*
 * ccp_stac.h
 *
 * Written by Archie Cobbs <archie@freebsd.org>
 * Copyright (c) 1995-1999 Whistle Communications, Inc. All rights reserved.
 * See ``COPYRIGHT.whistle''
 */

#ifndef _CCP_STAC_H_
#define _CCP_STAC_H_

#include "defs.h"
#include "mbuf.h"
#include "comp.h"

/*
 * DEFINITIONS
 */

  struct stacinfo
  {
    u_char	*history;
    u_int	in_active:1;
    u_int	out_active:1;
  };
  typedef struct stacinfo	*StacInfo;

/*
 * VARIABLES
 */

  extern const struct comptype	gCompStacInfo;

#endif

