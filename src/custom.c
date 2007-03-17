
/*
 * custom.c
 *
 * Copyright (c) 1995-1999 Whistle Communications Corp.
 * All rights reserved. 
 */

#include "ppp.h"
#include "custom.h"

/*
 * DEFINITIONS
 */

/*
 * INTERNAL FUNCTIONS
 */

  static int	CustomDoWhatever(int ac, char *av[], void *arg);

/*
 * GLOBAL VARIABLES
 */

  const struct cmdtab CustomCmds[] =
  {
    { "whatever [...]",		"Do whatever",
	CustomDoWhatever, NULL, NULL },
    { NULL },
  };
  struct u_range	gIpcpExcludeRange;

/*
 * CustomDoWhatever()
 */

static int
CustomDoWhatever(int ac, char *av[], void *arg)
{
  /* XXX do whatever */
  return(0);
}
