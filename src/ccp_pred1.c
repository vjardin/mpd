
/*
 * ccp_pred1.c
 *
 * Copyright (c) 1997-1999 Whistle Communications, Inc.
 * All rights reserved.
 */

/*
 * pred1.c
 *
 * Test program for Dave Rand's rendition of the predictor algorithm
 *
 * Updated by: archie@whistle.com (Archie Cobbs)
 * Updated by: iand@labtam.labtam.oz.au (Ian Donaldson)
 * Updated by: Carsten Bormann <cabo@cs.tu-berlin.de>
 * Original  : Dave Rand <dlr@bungi.com>/<dave_rand@novell.com>
 */

#include "ppp.h"
#include "ccp.h"

/*
 * DEFINITIONS
 */

  #define PRED1_COMP_BUF_SIZE	2048
  #define PRED1_DECOMP_BUF_SIZE	1600

  #define PRED1_MAX_BLOWUP(n)	((n) * 9 / 8 + 24)

/*
 * The following hash code is the heart of the algorithm:
 * It builds a sliding hash sum of the previous 3-and-a-bit characters
 * which will be used to index the guess table.
 * A better hash function would result in additional compression,
 * at the expense of time.
 */

  #define IHASH(x) p->iHash = (p->iHash << 4) ^ (x)
  #define OHASH(x) p->oHash = (p->oHash << 4) ^ (x)

/*
 * INTERNAL FUNCTIONS
 */

  static void	Pred1Init(int direction);
  static void	Pred1Cleanup(int direction);
  static Mbuf	Pred1Compress(int proto, Mbuf bp);
  static Mbuf	Pred1Decompress(Mbuf bp, int *proto);

  static u_char	*Pred1BuildConfigReq(CompInfo comp, u_char *cp);
  static Mbuf	Pred1RecvResetReq(int id, Mbuf bp);
  static Mbuf	Pred1SendResetReq(void);

  static int	Compress(u_char *source, u_char *dest, int len);
  static int	Decompress(u_char *source, u_char *dest, int slen, int dlen);
  static void	SyncTable(u_char *source, u_char *dest, int len);

/*
 * GLOBAL VARIABLES
 */

  const struct compinfo	gCompPred1Info =
  {
    TY_PRED1,
    Pred1Init,
    Pred1Cleanup,
    Pred1Compress,
    Pred1Decompress,
    NULL,
    Pred1BuildConfigReq,
    NULL,
    Pred1RecvResetReq,
    Pred1SendResetReq,
    NULL,
  };

/*
 * Pred1Init()
 */

void
Pred1Init(int directions)
{
  Pred1Info	p = &bund->ccp.pred1;

  if (directions & CCP_DIR_INPUT)
  {
    p->iHash = 0;
    if (p->InputGuessTable == NULL)
      p->InputGuessTable = Malloc(MB_COMP, PRED1_TABLE_SIZE);
    memset(p->InputGuessTable, 0, PRED1_TABLE_SIZE);
  }
  if (directions & CCP_DIR_OUTPUT)
  {
    p->oHash = 0;
    if (p->OutputGuessTable == NULL)
      p->OutputGuessTable = Malloc(MB_COMP, PRED1_TABLE_SIZE);
    memset(p->OutputGuessTable, 0, PRED1_TABLE_SIZE);
  }
}

/*
 * Pred1Cleanup()
 */

void
Pred1Cleanup(int direction)
{
  Pred1Info	p = &bund->ccp.pred1;

  if (direction & CCP_DIR_INPUT)
  {
    assert(p->InputGuessTable);
    Freee(p->InputGuessTable);
    p->InputGuessTable = NULL;
  }
  if (direction & CCP_DIR_OUTPUT)
  {
    assert(p->OutputGuessTable);
    Freee(p->OutputGuessTable);
    p->OutputGuessTable = NULL;
  }
}

/*
 * Pred1Compress()
 *
 * Compress a packet and return a compressed version.
 * The original is untouched.
 */

Mbuf
Pred1Compress(int proto, Mbuf uncomp)
{
  Mbuf		comp;
  u_char	*cp, *wp, *hp;
  int		orglen, len;
  u_char	bufp[PRED1_COMP_BUF_SIZE];
  u_short	fcs;

  orglen = plength(uncomp) + 2;			/* add count of proto */
  comp = mballoc(MB_FRAME_OUT, PRED1_MAX_BLOWUP(orglen + 2));
  comp->prio = uncomp->prio;
  hp = wp = MBDATA(comp);

/* Stick in original length and protocol */

  cp = bufp;
  *wp++ = *cp++ = orglen >> 8;
  *wp++ = *cp++ = orglen & 0377;
  *cp++ = proto >> 8;
  *cp++ = proto & 0xff;

/* Copy data into buffer and compute FCS */

  mbcopy(uncomp, cp, orglen - 2);
  fcs = Crc16(INITFCS, bufp, orglen + 2);
  fcs = ~fcs;

/* Compress data */

  len = Compress(bufp + 2, wp, orglen);

  #ifdef DEBUG
    Log(LG_CCP2, ("orglen (%d) --> len (%d)", orglen, len));
  #endif

/* What happened? */

  if (len < orglen)
  {
    *hp |= 0x80;
    wp += len;
  }
  else
  {
    memcpy(wp, bufp + 2, orglen);
    wp += orglen;
  }

/* Add FCS */

  *wp++ = fcs & 0377;
  *wp++ = fcs >> 8;
  comp->cnt = wp - MBDATA(comp);

/* Done */

  return(comp);
}

/*
 * Pred1Decompress()
 *
 * Decompress packet, set *protop accordingly. Returns NULL if
 * packet failed to decompress. In any case, it doesn't alter "comp".
 */

Mbuf
Pred1Decompress(Mbuf comp, int *protop)
{
  u_char	*cp, *pp;
  int		len, olen, len1;
  Mbuf		uncomp;
  u_char	*bufp;
  u_short	fcs, proto;

/* "comp" is compressed data */

  olen = plength(comp);
  cp = MBDATA(comp);

/* "uncomp" is uncompressed data */

  uncomp = mballoc(MB_IPIN, PRED1_DECOMP_BUF_SIZE);
  uncomp->prio = comp->prio;
  pp = bufp = MBDATA(uncomp);

/* Get initial length value */

  *pp++ = *cp & 0x7F;
  len = *cp++ << 8;
  *pp++ = *cp;
  len += *cp++;

/* Is data compressed or not really? */

  if (len & 0x8000)
  {
    len &= 0x7fff;
    len1 = Decompress(cp, pp, olen - 4, PRED1_DECOMP_BUF_SIZE);
    if (len != len1)	/* Error is detected. Send reset request */
    {
      PFREE(uncomp);
      return(NULL);
    }
    cp += olen - 4;
    pp += len1;
  }
  else
  {
    SyncTable(cp, pp, len);
    cp += len;
    pp += len;
  }

/* Copy CRC value */

  *pp++ = *cp++;	/* CRC */
  *pp++ = *cp++;

/* Check CRC */

  fcs = Crc16(INITFCS, bufp, (uncomp->cnt = pp - bufp));

  #ifdef DEBUG
    if (fcs != GOODFCS)
      Log(LG_CCP2, ("fcs = %04x (%s), len = %x, olen = %x",
	   fcs, (fcs == GOODFCS)? "good" : "bad", len, olen));
  #endif

  if (fcs != GOODFCS)
  {
    PFREE(uncomp);
    return(NULL);
  }

/* Get protocol */

  uncomp->offset += 2;		/* skip length */
  uncomp->cnt -= 4;		/* skip length & CRC */
  pp = MBDATA(uncomp);
  proto = *pp++;
  if (proto & 1)
  {
    uncomp->offset++;
    uncomp->cnt--;
  }
  else
  {
    uncomp->offset += 2;
    uncomp->cnt -= 2;
    proto = (proto << 8) | *pp++;
  }

/* Return decompressed packet */

  *protop = proto;
  return(uncomp);
}


/*
 * Pred1RecvResetReq()
 */

static Mbuf
Pred1RecvResetReq(int id, Mbuf bp)
{
  Pred1Init(CCP_DIR_OUTPUT);
  return(NULL);
}

/*
 * Pred1SendResetReq()
 */

static Mbuf
Pred1SendResetReq(void)
{
  Pred1Init(CCP_DIR_INPUT);
  return(NULL);
}

/*
 * Pred1BuildConfigReq()
 */

static u_char *
Pred1BuildConfigReq(CompInfo comp, u_char *cp)
{
  return(FsmConfValue(cp, comp->proto, 0, NULL));
}

/*
 * Compress()
 */

static int
Compress(u_char *source, u_char *dest, int len)
{
  Pred1Info	p = &bund->ccp.pred1;
  int		i, bitmask;
  u_char	flags;
  u_char	*flagdest, *orgdest;

  orgdest = dest;
  while (len)
  {
    flagdest = dest++; flags = 0;   /* All guess wrong initially */
    for (bitmask=1, i=0; i < 8 && len; i++, bitmask <<= 1) {
      if (p->OutputGuessTable[p->oHash] == *source)
	flags |= bitmask;       /* Guess was right - don't output */
      else
      {
	p->OutputGuessTable[p->oHash] = *source;
	*dest++ = *source;      /* Guess wrong, output char */
      }
      OHASH(*source++);
      len--;
    }
    *flagdest = flags;
  }
  return(dest - orgdest);
}

/*
 * Decompress()
 *
 * Returns decompressed size, or -1 if we ran out of space
 */

static int
Decompress(u_char *source, u_char *dest, int slen, int dlen)
{
  Pred1Info	p = &bund->ccp.pred1;
  int		i, bitmask;
  u_char	flags, *orgdest;

  orgdest = dest;
  while (slen)
  {
    flags = *source++;
    slen--;
    for (i=0, bitmask = 1; i < 8; i++, bitmask <<= 1)
    {
      if (dlen <= 0)
	return(-1);
      if (flags & bitmask)
	*dest = p->InputGuessTable[p->iHash];		/* Guess correct */
      else
      {
	if (!slen)
	  break;			/* we seem to be really done -- cabo */
	p->InputGuessTable[p->iHash] = *source;		/* Guess wrong */
	*dest = *source++;				/* Read from source */
	slen--;
      }
      IHASH(*dest++);
      dlen--;
    }
  }
  return(dest - orgdest);
}

/*
 * SyncTable()
 */

static void
SyncTable(u_char *source, u_char *dest, int len)
{
  Pred1Info	p = &bund->ccp.pred1;

  while (len--)
  {
    if (p->InputGuessTable[p->iHash] != *source)
      p->InputGuessTable[p->iHash] = *source;
    IHASH(*dest++ = *source++);
  }
}

