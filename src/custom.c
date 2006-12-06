
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

/*
 * SetStatus()
 *
 * Log port status to activity log
 */

void
SetStatus(int code, const char *key, ...)
{
  char		buf[100];
  va_list	args;

  /* Set code depending on state of other links (if any) */
  if (bund && bund->n_links > 1) {
    int	k;

    lnk->lastStatus = code;
    for (k = 0; k < bund->n_links; k++)
      if (bund->links[k] != lnk
	  && bund->links[k]->lastStatus == ADLG_WAN_CONNECTED)
	break;
    if (k < bund->n_links)
      code = ADLG_WAN_MESSAGE;
  }

/* XXX do whatever */

  va_start(args, key);
  vsnlcatf(buf, sizeof(buf), key, args);
  va_end(args);
}

