
/*
 * command.h
 *
 * Written by Archie Cobbs <archie@freebsd.org>
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

  /* Configuration options */
  enum {
    GLOBAL_CONF_TCPWRAPPER,	/* enable tcp-wrapper */
  };

  struct globalconf {
    struct optinfo	options;
  };

  extern const struct cmdtab gCommands[];

  struct cmdtab;
  typedef const struct cmdtab	*CmdTab;
  struct cmdtab
  {
    const char	*name;
    const char	*desc;
    int		(*func)(int ac, char *av[], void *arg);
    int		(*admit)(CmdTab cmd);
    void	*arg;
  };

/*
 * FUNCTIONS
 */

  extern int	DoConsole(void);
  extern int	DoCommand(int ac, char *av[]);
  extern int	HelpCommand(int ac, char *av[], void *arg);
  const	char	*FindCommand(CmdTab cmds, char* str, CmdTab *cp, int complain);
  extern int	AdmitBund(CmdTab cmd);
  extern int	AdmitDev(CmdTab cmd);

#endif

