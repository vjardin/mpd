
/*
 * phys.h
 *
 * Written by Archie Cobbs <archie@freebsd.org>
 * Copyright (c) 1995-1999 Whistle Communications, Inc. All rights reserved.
 * See ``COPYRIGHT.whistle''
 */

#ifndef _PHYS_H_
#define _PHYS_H_

#include "mbuf.h"
#include "msg.h"

/*
 * DEFINITIONS
 */

  enum {
    PHYS_STATE_DOWN = 0,
    PHYS_STATE_CONNECTING,
    PHYS_STATE_READY,
    PHYS_STATE_UP,
  };

  /* Descriptor for a given type of physical layer */
  struct physinfo;
  typedef struct physinfo	*PhysInfo;

  struct phystype {
    const char	*name;				/* Name of device type */
    u_char	synchronous:1;			/* Link is synchronous */
    short	minReopenDelay;			/* Min seconds between opens */
    u_short	mtu, mru;			/* Not incl. addr/ctrl/fcs */
    int		(*init)(PhysInfo p);		/* Initialize device info */
    void	(*open)(PhysInfo p);		/* Initiate connection */
    void	(*close)(PhysInfo p);		/* Disconnect */
    void	(*update)(PhysInfo p);		/* Update config when LCP up */
    void	(*shutdown)(PhysInfo p);	/* Destroy all nodes */
    void	(*showstat)(PhysInfo p);	/* Shows type specific stats */
    int		(*originate)(PhysInfo p);	/* We originated connection? */
    int		(*peeraddr)(PhysInfo p, void *buf, int buf_len); 
						/* returns the peer-address (IP, MAC, whatever) */
  };
  typedef struct phystype	*PhysType;

  struct physinfo {
    PhysType		type;			/* Device type descriptor */
    void		*info;			/* Type specific info */
    u_char		state;			/* Device current state */
    u_char		want_open;		/* What upper layer wants */
    time_t		lastClose;		/* Time of last close */
    MsgHandler		msgs;			/* Message channel */
    struct pppTimer	openTimer;		/* Open retry timer */
  };

/*
 * VARIABLES
 */

  extern const PhysType	gPhysTypes[];
  extern const char *gPhysStateNames[];

/*
 * FUNCTIONS
 */

  extern void		PhysOpen(void);
  extern void		PhysClose(void);
  extern void		PhysUpdate(void);
  extern void		PhysUp(void);
  extern void		PhysDown(const char *reason, const char *details, ...);

  extern PhysInfo	PhysInit(void);
  extern void		PhysSetDeviceType(char *typename);
  extern int		PhysGetOriginate(void);
  extern int		PhysStat(int ac, char *av[], void *arg);

#endif

