
/*
 * comp.h
 *
 * Written by Archie Cobbs <archie@freebsd.org>
 * Copyright (c) 1995-1999 Whistle Communications, Inc. All rights reserved.
 * See ``COPYRIGHT.whistle''
 */

#ifndef _COMP_H_
#define	_COMP_H_

/*
 * DEFINITIONS
 */

  #define COMP_DIR_XMIT		1
  #define COMP_DIR_RECV		2

  /* Compression type descriptor */
  struct ccpstate;

  struct comptype {
    const char	*name;
    u_char	type;
    /*
     * This function should initialize internal state according
     * to the direction parameter (recv or xmit or both).
     */
    int		(*Init)(int dir);
    /*
     * Reset any type-specific configuration options to their defaults.
     */
    void	(*Configure)(void);
    /*
     * This returns a string describing the configuration (optional).
     */
    char	*(*Describe)(int dir);
    /*
     * Given that "size" is our MTU, return the maximum length frame
     * we can compress without the result being longer than "size".
     */
    int		(*SubtractBloat)(int size);
    /*
     * Do the opposite of Init: ie., free memory, etc.
     */
    void	(*Cleanup)(int dir);
    /*
     * This should add the type-specific stuff for a config-request
     * to the building config-request packet
     */
    u_char	*(*BuildConfigReq)(u_char *cp);
    /*
     * This should decode type-specific config request stuff.
     */
    void	(*DecodeConfig)(Fsm fp, FsmOption opt, int mode);
    /*
     * This should return an mbuf containing type-specific reset-request
     * contents if any, or else NULL.
     */
    Mbuf	(*SendResetReq)(void);
    /*
     * Receive type-specific reset-request contents (possibly NULL).
     * Should return contents of reset-ack (NULL for empty). If no
     * reset-ack is desired, set *noAck to non-zero.
     */
    Mbuf	(*RecvResetReq)(int id, Mbuf bp, int *noAck);
    /*
     * Receive type-specific reset-ack contents (possibly NULL).
     */
    void	(*RecvResetAck)(int id, Mbuf bp);
    /*
     * Return true if compression was successfully negotiated in
     * the indicated direction.
     */
    int		(*Negotiated)(int dir);
    void	(*Compress)(u_char *uncomp, int orglen, u_char *comp, int *newlen);
    void	(*Decompress)(u_char *uncomp, int orglen, u_char *comp, int *newlen);
  };
  typedef const struct comptype	*CompType;

#endif

