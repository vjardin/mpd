
/*
 * console.h
 *
 * Written by Archie Cobbs <archie@freebsd.org>
 * Copyright (c) 1998-1999 Whistle Communications, Inc. All rights reserved.
 * See ``COPYRIGHT.whistle''
 */

#ifndef _CONSOLE_H_
#define	_CONSOLE_H_

#include "defs.h"

/*
 * VARIABLES
 */

  extern Link		gConsoleLink;
  extern Bund		gConsoleBund;

/*
 * FUNCTIONS
 */

  extern void	ConsoleInit(int cfd, int lfd);

#endif

