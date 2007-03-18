
/*
 * ipv6cp.h
 *
 * Written by Alexander Motin <mav@alkar.net>
 */

#ifndef _IPV6CP_H_
#define _IPV6CP_H_

#include <sys/types.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>

/*
 * DEFINITONS
 */
 
   /* Configuration options */
/*  enum {
  };*/

  struct ipv6cpconf {
    struct optinfo	options;	/* Configuraion options */
  };
  typedef struct ipv6cpconf	*Ipv6cpConf;

  struct ipv6cpstate {
    struct ipv6cpconf	conf;		/* Configuration */

    u_char 		myintid[8];
    u_char 		hisintid[8];

    u_long		peer_reject;	/* Request codes rejected by peer */

    struct fsm		fsm;
  };
  typedef struct ipv6cpstate	*Ipv6cpState;

/*
 * VARIABLES
 */

  extern const struct cmdtab	Ipv6cpSetCmds[];

/*
 * FUNCTIONS
 */

  extern void	Ipv6cpInit(void);
  extern void	Ipv6cpUp(void);
  extern void	Ipv6cpDown(void);
  extern void	Ipv6cpOpen(void);
  extern void	Ipv6cpClose(void);
  extern void	Ipv6cpInput(Bund b, Mbuf bp);
  extern void	Ipv6cpDefAddress(void);
  extern int	Ipv6cpStat(int ac, char *av[], void *arg);

#endif


