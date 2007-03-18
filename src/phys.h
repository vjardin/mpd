
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
    int		(*setaccm)(PhysInfo p, u_int32_t accm);	/* Set async accm */
    int		(*setcallingnum)(PhysInfo p, void *buf); 
						/* sets the calling number */
    int		(*setcallednum)(PhysInfo p, void *buf); 
						/* sets the called number */
    int		(*peeraddr)(PhysInfo p, void *buf, int buf_len); 
						/* returns the peer-address (IP, MAC, whatever) */
    int		(*callingnum)(PhysInfo p, void *buf, int buf_len); 
						/* returns the calling number (IP, MAC, whatever) */
    int		(*callednum)(PhysInfo p, void *buf, int buf_len); 
						/* returns the called number (IP, MAC, whatever) */
  };
  typedef struct phystype	*PhysType;

  struct physinfo {
    char		name[LINK_MAX_NAME];	/* Human readable name */
    PhysType		type;			/* Device type descriptor */
    void		*info;			/* Type specific info */
    u_char		state;			/* Device current state */
    u_char		want_open;		/* What upper layer wants */
    time_t		lastClose;		/* Time of last close */
    MsgHandler		msgs;			/* Message channel */
    struct pppTimer	openTimer;		/* Open retry timer */
    Link		link;			/* Link connected to the device */
    Rep			rep;			/* Rep connected to the device */
  };

/*
 * VARIABLES
 */

  extern const PhysType	gPhysTypes[];
  extern const char *gPhysStateNames[];
  extern const struct cmdtab	PhysSetCmds[];

/*
 * FUNCTIONS
 */

  extern void		PhysOpenCmd(Context ctx);
  extern void		PhysOpen(PhysInfo p);
  extern void		PhysCloseCmd(Context ctx);
  extern void		PhysClose(PhysInfo p);
  extern void		PhysUp(PhysInfo p);
  extern void		PhysDown(PhysInfo p, const char *reason, const char *details, ...);
  extern void		PhysIncoming(PhysInfo p);
  extern int		PhysGetUpperHook(PhysInfo p, char *path, char *hook);

  extern int		PhysSetAccm(PhysInfo p, uint32_t accm);
  extern int		PhysSetCallingNum(PhysInfo p, char *buf);
  extern int		PhysSetCalledNum(PhysInfo p, char *buf);
  extern int		PhysGetPeerAddr(PhysInfo p, char *buf, int buf_len);
  extern int		PhysGetCallingNum(PhysInfo p, char *buf, int buf_len);
  extern int		PhysGetCalledNum(PhysInfo p, char *buf, int buf_len);

  extern PhysInfo	PhysInit(char *name, Link l, Rep r);
  extern void		PhysShutdown(PhysInfo p);
  extern void		PhysSetDeviceType(PhysInfo p, char *typename);
  extern int		PhysGetOriginate(PhysInfo p);
  extern int		PhysCommand(Context ctx, int ac, char *av[], void *arg);
  extern int		PhysStat(Context ctx, int ac, char *av[], void *arg);

#endif

