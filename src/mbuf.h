
/*
 * mbuf.c
 *
 * Written by Toshiharu OHNO <tony-o@iij.ad.jp>
 * Copyright (c) 1993, Internet Initiative Japan, Inc. All rights reserved.
 * See ``COPYRIGHT.iij''
 * 
 * Rewritten by Archie Cobbs <archie@freebsd.org>
 * Copyright (c) 1995-1999 Whistle Communications, Inc. All rights reserved.
 * See ``COPYRIGHT.whistle''
 */

#ifndef _MBUF_H_
#define _MBUF_H_

/*
 * DEFINITIONS
 */

  struct mpdmbuf {
    u_char		*base;		/* pointer to top of buffer space */
    int			size;		/* size allocated from base */
    int			offset;		/* offset to start position */
    int			cnt;		/* available byte count in buffer */
    u_char		type;		/* type of mbuf (see below) */
    struct mpdmbuf	*next;		/* link to next mbuf in chain */
  };

  typedef struct mpdmbuf	*Mbuf;

  /* Macros */
  #define MBDATA(bp)	((bp) ? ((bp)->base + (bp)->offset) : NULL)
  #define MBLEN(bp)	((bp) ? (bp)->cnt : 0)

  #define PFREE(bp)	do {			\
			    while (bp)		\
			      bp = mbfree(bp);	\
			  } while (0)

  /* Types of allocated memory */
  enum {
    MB_FSM = 0,
    MB_PHYS,
    MB_FRAME_IN,
    MB_FRAME_OUT,
    MB_BUND,
    MB_ECHO,
    MB_VJCOMP,
    MB_LOG,
    MB_IPQ,
    MB_MP,
    MB_AUTH,
    MB_UTIL,
    MB_CHAT,
    MB_COMP,
    MB_CRYPT,
    MB_PPTP,
    MB_RADIUS,
  };

/*
 * FUNCTIONS
 */

/* Replacements for malloc() & free() */

  extern void	*Malloc(int type, int size);
  extern void	Freee(const void *ptr);

/* Mbuf manipulation */

  extern Mbuf	mballoc(int type, int size);
  extern Mbuf	mbfree(Mbuf bp);
  extern Mbuf	mbwrite(Mbuf bp, const u_char *ptr, int cnt);
  extern Mbuf	mbread(Mbuf bp, u_char *ptr, int cnt, int *lenp);
  extern int	mbcopy(Mbuf bp, u_char *buf, int remain);
  extern Mbuf	mbtrunc(Mbuf bp, int max);
  extern Mbuf	mbunify(Mbuf bp);
  extern Mbuf	mbsplit(Mbuf bp, int cnt);
  extern Mbuf	mbclean(Mbuf bp);

/* Etc */

  extern int	MemStat(int ac, char *av[], void *arg);
  extern void	DumpBp(Mbuf bp);
  extern char	*Asprintf(int type, const char *format, ...);

/*
 * INLINE FUNCTIONS
 */

/*
 * plength()
 *
 * Return total length in an mbuf chain
 */

static inline int
plength(Mbuf bp)
{
  int len;

  for (len = 0; bp; bp = bp->next)
    len += bp->cnt;
  return(len);
}

#endif

