
/*
 * command.h
 *
 * Written by Archie Cobbs <archie@whistle.com>
 * Copyright (c) 1995-1999 Whistle Communications, Inc. All rights reserved.
 * See ``COPYRIGHT.whistle''
 */

#ifndef _COMMAND_H_
#define _COMMAND_H_

/*
 * DEFINITIONS
 */

  #define CMD_UNIMPL	((int (*)(int ac, char *av[], void *arg)) 0)
  #define CMD_SUBMENU	((int (*)(int ac, char *av[], void *arg)) 1)

  struct cmdtab;
  typedef const struct cmdtab	*CmdTab;
  struct cmdtab
  {
    char	*name;
    char	*desc;
    int		(*func)(int ac, char *av[], void *arg);
    int		(*admit)(CmdTab cmd);
    void	*arg;
  };

/*
 * FUNCTIONS
 */

  extern int	DoConsole(void);
  extern int	DoCommand(int ac, char *av[]);
  extern int	AdmitBund(CmdTab cmd);
  extern int	AdmitDev(CmdTab cmd);

#endif

