
/*
 * lcp.h
 *
 * Written by Toshiharu OHNO <tony-o@iij.ad.jp>
 * Copyright (c) 1993, Internet Initiative Japan, Inc. All rights reserved.
 * See ``COPYRIGHT.iij''
 * 
 * Rewritten by Archie Cobbs <archie@freebsd.org>
 * Copyright (c) 1995-1999 Whistle Communications, Inc. All rights reserved.
 * See ``COPYRIGHT.whistle''
 */

#ifndef _LCP_H_
#define _LCP_H_

#include "fsm.h"
#include "timer.h"
#include "auth.h"

/*
 * DEFINITIONS
 */

  /* MRU defs */
  #define LCP_DEFAULT_MRU	1500	/* Per RFC 1661 */
  #define LCP_MRU_MARGIN	20	/* Negotiate with this margin */
  #define LCP_MIN_MRU		296

  /* Authorization timeout in seconds */
  #define LCP_AUTH_TIMEOUT	20

  /* Link state */
  struct lcpstate {

    /* LCP phase of this link */
    u_short	phase;			/* PPP phase */

    /* Authorization info */
    struct auth	auth;			/* Used during authorization phase */

    /* Peers negotiated parameters */
    u_int32_t	peer_accmap;		/* Characters peer needs escaped */
    u_int32_t	peer_magic;		/* Peer's magic number */
    u_int16_t	peer_mru;		/* Peer's max reception packet size */
    u_int16_t	peer_auth;		/* Auth requested by peer, or zero */
    u_int16_t	peer_mrru;		/* MRRU set by peer, or zero */
    u_char	peer_chap_alg;		/* Peer's CHAP algorithm */

    /* My negotiated parameters */
    u_char	want_chap_alg;		/* My CHAP algorithm */
    u_int32_t	want_accmap;		/* Control chars I want escaped */
    u_int32_t	want_magic;		/* My magic number */
    u_int16_t	want_mru;		/* My MRU */
    u_int16_t	want_auth;		/* Auth I require of peer, or zero */
    u_int16_t	want_mrru;		/* My MRRU, or zero if no MP */

    /* More params */
    u_char	want_protocomp:1;	/* I want protocol compression */
    u_char	want_acfcomp:1;		/* I want a&c field compression */
    u_char	want_multilink:1;	/* I accept multi-link */
    u_char	want_shortseq:1;	/* I want short seq numbers */
    u_char	want_callback:1;	/* I want to be called back */

    u_char	peer_protocomp:1;	/* Peer wants protocol field comp */
    u_char	peer_acfcomp:1;		/* Peer wants addr & ctrl field comp */
    u_char	peer_multilink:1;	/* Peer accepts multi-link */
    u_char	peer_shortseq:1;	/* Peer gets ML short seq numbers */

    /* Misc */
    u_long		peer_reject;	/* Request codes rejected by peer */
    struct fsm		fsm;		/* Finite state machine */
  };
  typedef struct lcpstate	*LcpState;

  #define PHASE_DEAD		0
  #define PHASE_ESTABLISH	1
  #define PHASE_AUTHENTICATE	2
  #define PHASE_NETWORK		3
  #define PHASE_TERMINATE	4

  #define TY_VENDOR		0	/* Vendor specific */
  #define TY_MRU		1	/* Maximum-Receive-Unit */
  #define TY_ACCMAP		2	/* Async-Control-Character-Map */
  #define TY_AUTHPROTO		3	/* Authentication-Protocol */
  #define TY_QUALPROTO		4	/* Quality-Protocol */
  #define TY_MAGICNUM		5	/* Magic-Number */
  #define TY_RESERVED		6	/* RESERVED */
  #define TY_PROTOCOMP		7	/* Protocol-Field-Compression */
  #define TY_ACFCOMP		8	/* Address+Control-Field-Compression */
  #define TY_FCSALT		9	/* FCS-Alternatives */
  #define TY_SDP		10	/* Self-Dscribing-Padding */
  #define TY_NUMMODE		11	/* Numbered-Mode */
  #define TY_MULTILINK		12	/* Multi-link procedure (?) */
  #define TY_CALLBACK		13	/* Callback */
  #define TY_CONNECTTIME	14	/* Connect time */
  #define TY_COMPFRAME		15	/* Compound-Frames */
  #define TY_NDS		16	/* Nominal-Data-Encapsulation */
  #define TY_MRRU		17	/* Multi-link MRRU size */
  #define TY_SHORTSEQNUM	18	/* Short seq number header format */
  #define TY_ENDPOINTDISC	19	/* Unique endpoint discrimiator */
  #define TY_PROPRIETARY	20	/* Proprietary */
  #define TY_DCEIDENTIFIER	21	/* DCE-Identifier */

/*
 * FUNCTIONS
 */

  extern void	LcpInit(void);
  extern void	LcpInput(Mbuf bp, int linkNum);
  extern void	LcpUp(void);
  extern void	LcpOpen(void);
  extern void	LcpClose(void);
  extern void	LcpDown(void);
  extern int	LcpStat(int ac, char *av[], void *arg);
  extern void	LcpAuthResult(int success);

#endif

