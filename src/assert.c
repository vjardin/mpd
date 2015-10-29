
/*
 * assert.c
 *
 * Written by Archie Cobbs <archie@freebsd.org>
 * Copyright (c) 1995-1999 Whistle Communications, Inc. All rights reserved.
 * See ``COPYRIGHT.whistle''
 */

#include "ppp.h"
#include "log.h"

void
DoAssert(const char *file, int line, const char *failedexpr)
{
#ifdef USE_BACKTRACE
  void	*buffer[100];
  char	**strings;
  int	n, k;

  n = backtrace(buffer, 100);
  strings = backtrace_symbols(buffer, n);
  if (strings == NULL) {
    Log(LG_ERR, ("No backtrace symbols found"));
  } else {
    for (k = 0; k < n; k++) {
      Log(LG_ERR, ("%s", strings[k]));
    }
    free(strings);
  }
#endif
  Log(LG_ERR, ("ASSERT \"%s\" failed: file \"%s\", line %d",
    failedexpr, file, line));

  DoExit(EX_ERRDEAD);
}

