
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

#include "ppp.h"

/*
 * DEFINITIONS
 */

  #define MBUF_CHECK_OVERRUNS

  #define MBUF_MAGIC_1	0x99999999
  #define MBUF_MAGIC_2	0xaaaaaaaa

  struct typestat
  {
    const short	type;
    const char	*name;
    int		count;
  };

/*
 * INTERNAL VARIABLES
 */

  static int		total_alloced;

/* This list must correspond exactly with array in mbuf.h */

  static struct typestat	gMbufStats[] =
  {
    { MB_FSM,		"FSM" },
    { MB_PHYS,		"PHYS" },
    { MB_FRAME_IN,	"FRAME_IN" },
    { MB_FRAME_OUT,	"FRAME_OUT" },
    { MB_BUND,		"BUND" },
    { MB_ECHO,		"ECHO" },
    { MB_VJCOMP,	"VJCOMP" },
    { MB_LOG,		"LOG" },
    { MB_IPQ,		"IPQ" },
    { MB_MP,		"MP" },
    { MB_AUTH,		"AUTH" },
    { MB_UTIL,		"UTIL" },
    { MB_CHAT,		"CHAT" },
    { MB_COMP,		"COMP" },
    { MB_CRYPT,		"CRYPT" },
    { MB_PPTP,		"PPTP" },
  };

  #define NUM_TYPE_STATS	(sizeof(gMbufStats) / sizeof(*gMbufStats))

/*
 * INTERNAL FUNCTIONS
 */

  static void		MbufTypeCount(int type, int change);

/*
 * Malloc()
 *
 * Replacement for the ususal malloc()
 */

void *
Malloc(int type, int size)
{
  Mbuf	bp;

  bp = mballoc(type, size + sizeof(Mbuf));
  *((Mbuf *) MBDATA(bp)) = bp;
  return(MBDATA(bp) + sizeof(Mbuf));
}

/*
 * Freee()
 *
 * Replacement for the ususal free()
 */

void
Freee(const void *ptr)
{
  Mbuf	bp;

  if (ptr == NULL)
    return;
  bp = *((Mbuf *) ptr - 1);
  PFREE(bp);
}

/*
 * Asprintf()
 */

char *
Asprintf(int type, const char *format, ...)
{
  char *s;
  va_list args;

  va_start(args, format);
  vasprintf(&s, format, args);
  va_end(args);
  if (s == NULL) {
    Perror("%s", __FUNCTION__);
    DoExit(EX_ERRDEAD);
  }
  return strcpy(Malloc(type, strlen(s) + 1), s);
}

/*
 * mballoc()
 *
 * Allocate an mbuf with memory
 */

Mbuf
mballoc(int type, int size)
{
  u_char	*memory;
  u_long	amount;
  Mbuf		bp;

/* Sanity */

  assert(size < ((1 << ((sizeof(short) * 8) - 1)) - 1));

/* Get memory */

  #ifdef MBUF_CHECK_OVERRUNS
    amount = sizeof(*bp) + size + (2 * sizeof(u_long));
  #else
    amount = sizeof(*bp) + size;
  #endif

  if ((memory = malloc(amount)) == NULL)
  {
    Perror("mballoc: malloc");
    DoExit(EX_ERRDEAD);
  }
  memset(memory, 0, amount);

/* Put mbuf at front of memory region */

  bp = (Mbuf) memory;
  bp->size = bp->cnt = size;
  bp->type = type;

  #ifdef MBUF_CHECK_OVERRUNS
    bp->base = memory + sizeof(*bp) + sizeof(u_long);
  #else
    bp->base = memory + sizeof(*bp);
  #endif

/* Straddle buffer with magic values to detect overruns */

  #ifdef MBUF_CHECK_OVERRUNS
    *((u_long *) (memory + sizeof(*bp))) = MBUF_MAGIC_1;
    *((u_long *) (memory + sizeof(*bp) + sizeof(u_long) + size)) = MBUF_MAGIC_2;
  #endif

/* Keep tabs on who's got how much memory */

  MbufTypeCount(bp->type, bp->size);

/* Done */

  return(bp);
}

/*
 * mbfree()
 *
 * Free head of chain, return next
 */

Mbuf
mbfree(Mbuf bp)
{
  Mbuf	next;

  if (bp)
  {

  /* Sanity checks */

    assert(bp->base);
    #ifdef MBUF_CHECK_OVERRUNS
      assert(bp == (Mbuf) (bp->base - sizeof(u_long) - sizeof(*bp)));
    #else
      assert(bp == (Mbuf) (bp->base - sizeof(*bp)));
    #endif

    #ifdef MBUF_CHECK_OVERRUNS
      assert(*((u_long *) (bp->base - sizeof(u_long))) == MBUF_MAGIC_1);
      assert(*((u_long *) (bp->base + bp->size)) == MBUF_MAGIC_2);
    #endif

  /* Keep tabs on who's got how much memory */

    MbufTypeCount(bp->type, -bp->size);

  /* Free it */

    next = bp->next;
    bp->base = NULL;
    free(bp);
    return(next);
  }
  return(NULL);
}

/*
 * mbread()
 *
 * Read contents of an mbuf chain into buffer, consuming len bytes.
 * If all of the chain is consumed, return NULL.
 *
 * This should ALWAYS be called like this:
 *	bp = mbread(bp, ... );
 */

Mbuf
mbread(Mbuf bp, u_char *buf, int remain, int *nreadp)
{
  int	nread, total;

  for (total = 0; bp && remain > 0; total += nread)
  {
    if (remain > bp->cnt)
      nread = bp->cnt;
    else
      nread = remain;
    memcpy(buf, MBDATA(bp), nread);
    buf += nread;
    remain -= nread;
    bp->offset += nread;
    bp->cnt -= nread;
    while (bp != NULL && bp->cnt == 0)
      bp = mbfree(bp);
  }
  if (nreadp != NULL)
    *nreadp = total;
  return(bp);
}

/*
 * mbcopy()
 *
 * Copy contents of an mbuf chain into buffer, up to "remain" bytes.
 * This does not consume any of the mbuf chain. Returns number copied.
 */

int
mbcopy(Mbuf bp, u_char *buf, int remain)
{
  int	nread, total;

  for (total = 0; bp && remain > 0; total += nread, bp = bp->next)
  {
    if (remain > bp->cnt)
      nread = bp->cnt;
    else
      nread = remain;
    memcpy(buf, MBDATA(bp), nread);
    buf += nread;
    remain -= nread;
  }
  return(total);
}

/*
 * mbwrite()
 *
 * Write bytes from buffer into an mbuf chain. Returns first argument.
 */

Mbuf
mbwrite(Mbuf bp, const u_char *buf, int len)
{
  Mbuf	wp;
  int	chunk;

  for (wp = bp; wp && len > 0; wp = wp->next) {
    chunk = (len > wp->cnt) ? wp->cnt : len;
    memcpy(MBDATA(wp), buf, chunk);
    buf += chunk;
    len -= chunk;
  }
  return(bp);
}

/*
 * mbtrunc()
 *
 * Truncate mbuf chain to total of "max" bytes. If max is zero
 * then a zero length mbuf is returned (rather than a NULL mbuf).
 */

Mbuf
mbtrunc(Mbuf bp, int max)
{
  Mbuf	wp;
  int	sum;

/* Find mbuf in chain where truncation point happens */

  for (sum = 0, wp = bp;
    wp && sum + wp->cnt <= max;
    sum += wp->cnt, wp = wp->next);

/* Shorten this mbuf and nuke others after this one */

  if (wp)
  {
    wp->cnt = max - sum;
    PFREE(wp->next);
  }

/* Done */

  return(bp);
}

/*
 * mbunify()
 *
 * Collect all of a chain into a single mbuf
 *
 * This should ALWAYS be called like this:
 *	bp = mbunify(bp);
 */

Mbuf
mbunify(Mbuf bp)
{
  Mbuf	new;
  int	len;

  if (!bp || !bp->next)
    return(bp);
  new = mballoc(bp->type, len = plength(bp));
  assert(mbread(bp, MBDATA(new), len, NULL) == NULL);
  return(new);
}

/*
 * mbclean()
 *
 * Remove zero (and negative!?) length mbufs from a chain
 */

Mbuf
mbclean(Mbuf bp)
{
  Mbuf	*pp;

  pp = &bp;
  while (*pp)
    if ((*pp)->cnt <= 0)
      *pp = mbfree(*pp);
    else
      pp = &(*pp)->next;
  return(bp);
}

/*
 * mbsplit()
 *
 * Break an mbuf chain after "cnt" bytes.
 * Return the newly created mbuf chain that
 * starts after "cnt" bytes. If plength(bp) <= cnt,
 * then returns NULL.  The first part of
 * the chain remains pointed to by "bp".
 */

Mbuf
mbsplit(Mbuf bp, int cnt)
{
  int	seen, extra, tail;
  Mbuf	mextra, next;

/* Find mbuf in chain containing the breakpoint */

  for (seen = 0; bp && seen + bp->cnt < cnt; seen += bp->cnt, bp = bp->next);
  if (bp == NULL)
    return(NULL);

/* "tail" is how much stays in first part, "extra" goes into second part */

  tail = cnt - seen;
  extra = bp->cnt - tail;

/* Split in the middle of "bp" if necessary, creating "mextra" */

  if (extra > 0)
  {
    mextra = mballoc(bp->type, extra);
    memcpy(MBDATA(mextra), MBDATA(bp) + tail, extra);
    bp->cnt = tail;
    mextra->next = bp->next;
    bp->next = mextra;
  }

/* Now break point is just after "bp", so break the chain there */

  next = bp->next;
  bp->next = NULL;
  return(next);
}

/*
 * MbufTypeCount()
 */

static void
MbufTypeCount(int type, int change)
{
  int	index;

/* Find structure for this type */

  for (index = 0;
    index < NUM_TYPE_STATS && gMbufStats[index].type != type;
    index++);
  assert(index < NUM_TYPE_STATS);

/* Update counters */

  gMbufStats[index].count += change;
  total_alloced += change;
  assert(total_alloced >= 0);
}

/*
 * MemStat()
 */

int
MemStat(int ac, char *av[], void *arg)
{
  int	index;

  for (index = 0; index < NUM_TYPE_STATS; index++)
    printf("%12s: %8d%c",
      gMbufStats[index].name, gMbufStats[index].count,
	(index & 1) ? '\n' : ' ');
  if (index & 1)
    printf("\n");
  printf("Total bytes allocated: %d\n", total_alloced);
  return(0);
}

