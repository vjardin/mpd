
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

  #define RBUF_SIZE		100

/*
 * INTERNAL FUNCTIONS
 */

  static int	CustomDoWhatever(int ac, char *av[], void *arg);
  static void	RecordLinkUpDownReason2(Link l, int up,
			const char *key, const char *fmt, va_list args);

/*
 * GLOBAL VARIABLES
 */

  const struct cmdtab CustomCmds[] =
  {
    { "whatever [...]",		"Do whatever",
	CustomDoWhatever, NULL, NULL },
    { NULL },
  };
  struct in_range	gIpcpExcludeRange;

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

/*
 * RecordLinkUpDown()
 *
 * This is called whenever the link itself goes up or down.
 * Its purpose is to follow more or less what telco usage charges would.
 *
 * We kludge here to make multiple links look like a single link.
 *
 * Argument:
 *
 *	-1	The link went from up to down
 *	 0	The link failed to connect
 *	 1	The link has successfully connected
 */

void
RecordLinkUpDown(int which)
{
  char	*const buf = (which == 1) ? lnk->upReason : lnk->downReason;

/* For logging purposes, treat all links as a single link */

  bund->numRecordUp += which;
  switch (which) {
    case -1:
    case 0:
      if (bund->numRecordUp != 0)
	return;
      break;
    case 1:
      if (bund->numRecordUp != 1)
	return;
      break;
  }

/* XXX do whatever */

/* Reset this buffer in case next time we fail to put a reason in there */

  if (buf)
    *buf = 0;
}

/*
 * RecordLinkUpDownReason()
 *
 * This is called whenever a reason for the link going up or
 * down has just become known. Record this reason so that when
 * the link actually goes up or down, we can record it.
 *
 * If this gets called more than once in the "down" case,
 * the first call prevails.
 */

void
RecordLinkUpDownReason(Link l, int up, const char *key, const char *fmt, ...)
{
  va_list	args;
  int		k;

  va_start(args, fmt);
  if (l == NULL) {
    for (k = 0; k < bund->n_links; k++) {
      if (bund && bund->links[k])
	RecordLinkUpDownReason2(bund->links[k], up, key, fmt, args);
    }
  } else {
    RecordLinkUpDownReason2(l, up, key, fmt, args);
  }
  va_end(args);
}

static void
RecordLinkUpDownReason2(Link l, int up, const char *key, const char *fmt, va_list args)
{
  char	**const cpp = up ? &l->upReason : &l->downReason;
  char	*buf;

  /* Allocate buffer if necessary */
  if (!*cpp)
    *cpp = Malloc(MB_UTIL, RBUF_SIZE);
  buf = *cpp;

  /* First "down" reason overrides later ones */
  if (!up && *buf)
    return;

  /* Record reason */
  snprintf(buf, RBUF_SIZE, "%s:", lcats(key));
  if (fmt)
    vsnprintf(buf + strlen(buf), RBUF_SIZE - strlen(buf), fmt, args);
}

