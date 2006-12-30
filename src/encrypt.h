
/*
 * encrypt.h
 *
 * Written by Archie Cobbs <archie@freebsd.org>
 * Copyright (c) 1998-1999 Whistle Communications, Inc. All rights reserved.
 * See ``COPYRIGHT.whistle''
 */

#ifndef _ENCRYPT_H_
#define	_ENCRYPT_H_

/*
 * DEFINITIONS
 */

/* Descriptor for one type of encryption */

  struct ecpstate;

  struct enctype
  {
    const char	*name;
    u_char	type;
    int		(*Init)(int dir);
    void	(*Configure)(void);
    void	(*UnConfigure)(void);
    int		(*SubtractBloat)(int size);
    void	(*Cleanup)(int dir);
    u_char	*(*BuildConfigReq)(u_char *cp);
    void	(*DecodeConfig)(Fsm fp, FsmOption opt, int mode);
    Mbuf	(*SendResetReq)(void);
    Mbuf	(*RecvResetReq)(int id, Mbuf bp);
    void	(*RecvResetAck)(int id, Mbuf bp);
    int         (*Stat)(int dir);
    Mbuf	(*Encrypt)(Mbuf plain);
    Mbuf	(*Decrypt)(Mbuf cypher);
  };
  typedef const struct enctype	*EncType;

#endif

