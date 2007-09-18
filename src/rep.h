
/*
 * rep.h
 *
 * Written by Alexander Motin <mav@FreeBSD.org>
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
    int			id;			/* Index of this link in gReps */
    int			tmpl;			/* This is template, not an instance */
    char		linkt[LINK_MAX_NAME];	/* Link template name */
    Link		links[2];		/* Links used by repeater */
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
  extern int	RepStat(Context ctx, int ac, char *av[], void *arg);
  extern int	RepCommand(Context ctx, int ac, char *av[], void *arg);
  extern int	RepCreate(Context ctx, int ac, char *av[], void *arg);
  extern Rep	RepInst(Rep rt, char *name);
  extern void	RepShutdown(Rep r);

  extern void	RepIncoming(Link l);
  extern int	RepIsSync(Link l); /* Is pair link is synchronous */
  extern void	RepSetAccm(Link l, u_int32_t xmit, u_int32_t recv); /* Set async accm */
  extern void	RepUp(Link l);
  extern void	RepDown(Link l);
  extern int	RepGetHook(Link l, char *path, char *hook);
  extern Rep	RepFind(char *name);

#endif

