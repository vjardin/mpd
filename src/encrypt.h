
/*
 * encrypt.h
 *
 * Written by Archie Cobbs <archie@whistle.com>
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
    void	*(*Init)(int encrypt);
    void	(*Configure)(void);
    int		(*SubtractBloat)(int size);
    Mbuf	(*Encrypt)(Mbuf plain);
    Mbuf	(*Decrypt)(Mbuf cypher);
    void	(*Cleanup)(int encrypt);
    u_char	*(*BuildConfigReq)(u_char *cp);
    void	(*DecodeConfig)(Fsm fp, FsmOption opt, int mode);
    Mbuf	(*SendResetReq)(void);
    Mbuf	(*RecvResetReq)(int id, Mbuf bp);
    void	(*RecvResetAck)(int id, Mbuf bp);
  };
  typedef const struct enctype	*EncType;

#endif

