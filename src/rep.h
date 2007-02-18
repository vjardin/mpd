
/*
 * rep.h
 *
 * Written by Alexander Motin <mav@alkar.net>
 */

#ifndef _REP_H_
#define _REP_H_

#include "defs.h"
#include "msg.h"
#include "command.h"
#include <netgraph/ng_message.h>

/*
 * DEFINITIONS
 */

  /* Total state of a repeater */
  struct rep {
    char		name[LINK_MAX_NAME];	/* Name of this repeater */
    PhysInfo		physes[2];		/* Physes used by repeater */
    struct optinfo	options;		/* Configured options */
    int			csock;			/* Socket node control socket */
    int			p_open;			/* Opened phys */
    int			p_up;			/* Up phys */
    int			initiator;		/* Number of phys initiator */
    ng_ID_t		node_id;		/* ng_tee node ID */
  };
  
/*
 * VARIABLES
 */

  extern const struct cmdtab	RepSetCmds[];

/*
 * FUNCTIONS
 */

  extern void	RepOpen(void);
  extern void	RepClose(void);
  extern int	RepStat(int ac, char *av[], void *arg);
  extern int	RepCommand(int ac, char *av[], void *arg);
  extern int	RepCreateCmd(int ac, char *av[], void *arg);
  extern void	RepShutdown(Rep r);

  extern void	RepIncoming(PhysInfo p);
  extern void	RepUp(PhysInfo p);
  extern void	RepDown(PhysInfo p);
  extern int	RepGetHook(PhysInfo p, char *path, char *hook);

#endif

