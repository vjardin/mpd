
/*
 * ecp.h
 *
 * Written by Archie Cobbs <archie@whistle.com>
 * Copyright (c) 1998-1999 Whistle Communications, Inc. All rights reserved.
 * See ``COPYRIGHT.whistle''
 */

#ifndef _ECP_H_
#define	_ECP_H_

#include "fsm.h"
#include "mbuf.h"
#include "encrypt.h"
#include "command.h"

#ifdef ENCRYPTION_DES
#include "ecp_des.h"
#endif

/*
 * DEFINITIONS
 */

/* Encryption types */

  #define ECP_TY_OUI		0
  #define ECP_TY_DES		1

/* Max supported key length */

  #define ECP_MAX_KEY	32

/* Stats */

  struct ecpstat
  {
    int	outPackets;
    int	inPackets;
    int	inPacketDrops;
  };

/* ECP state */

  struct ecpstate
  {
    char		key[ECP_MAX_KEY];	/* Encryption key */
    EncType		xmit;		/* Xmit encryption type */
    EncType		recv;		/* Recv encryption type */
    u_short		self_reject;
    u_short		peer_reject;
    struct fsm		fsm;		/* PPP FSM */
    struct ecpstat	stat;		/* Statistics */
    struct optinfo	options;	/* Configured options */
#ifdef ENCRYPTION_DES
    struct desinfo	des;		/* DES info */
#endif
  };
  typedef struct ecpstate	*EcpState;

/*
 * VARIABLES
 */

  extern const struct cmdtab	EcpSetCmds[];

/*
 * FUNCTIONS
 */

  extern void	EcpInit(void);
  extern void	EcpUp(void);
  extern void	EcpDown(void);
  extern void	EcpOpen(void);
  extern void	EcpClose(void);
  extern int	EcpSubtractBloat(int size);
  extern void	EcpInput(Mbuf bp, int linkNum);
  extern Mbuf	EcpDataInput(Mbuf bp, int *protop);
  extern Mbuf	EcpDataOutput(Mbuf bp, int *protop);
  extern void	EcpSendResetReq(Fsm fp);
  extern int	EcpStat(int ac, char *av[], void *arg);

#endif

