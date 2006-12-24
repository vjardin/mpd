
/*
 * ccp_deflate.h
 *
 * Written by Alexander Motin <mav@alkar.net>
 */

#ifndef _CCP_DEFLATE_H_
#define _CCP_DEFLATE_H_

#include <netgraph/ng_message.h>
#ifdef __DragonFly__
#include <netgraph/mppc/ng_deflate.h>
#else
#include <netgraph/ng_deflate.h>
#endif

#include "defs.h"
#include "mbuf.h"
#include "comp.h"

/*
 * DEFINITIONS
 */

  struct deflateinfo {
	int	xmit_windowBits;
	int	recv_windowBits;
  };
  typedef struct deflateinfo	*DeflateInfo;

/*
 * VARIABLES
 */

  extern const struct comptype	gCompDeflateInfo;

#endif

