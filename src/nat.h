
/*
 * nat.h
 *
 * Written by Alexander Motin <mav@FreeBSD.org>
 */

#ifndef _NAT_H_
#define _NAT_H_

/* Configuration options */

  enum {
    NAT_CONF_LOG,
    NAT_CONF_INCOMING,
    NAT_CONF_SAME_PORTS,
    NAT_CONF_UNREG_ONLY
  };

  struct natstate {
    struct optinfo	options;		/* Configuration options */
    struct u_addr	alias_addr;		/* Alias IP address */
    struct u_addr	target_addr;		/* Target IP address */
  };
  typedef struct natstate	*NatState;

/*
 * VARIABLES
 */

  extern const struct cmdtab	NatSetCmds[];

  extern void	NatInit(Bund b);
  extern int	NatStat(Context ctx, int ac, char *av[], void *arg);

#endif

