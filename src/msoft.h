
/*
 * msoft.h
 *
 * Rewritten by Archie Cobbs <archie@whistle.com>
 * Copyright (c) 1998-1999 Whistle Communications, Inc. All rights reserved.
 * See ``COPYRIGHT.whistle''
 */

#ifndef _MSOFT_H_
#define _MSOFT_H_

#include <sys/types.h>

/*
 * FUNCTIONS
 */

  extern void	NTChallengeResponse(const u_char *chal,
		  const char *password, u_char *hash);

  extern void	NTPasswordHash(const char *password, u_char *hash);
  extern void	LMPasswordHash(const char *password, u_char *hash);

  extern void	MsoftGetKey(const u_char *h, u_char *h2, int len);
  extern void	MsoftGetStartKey(u_char *chal, u_char *h);

#endif

