
/*
 * ccp_pred1.c
 *
 * Written by Alexander Motin <mav@alkar.net>
 */

/*
 * pred1.c
 *
 * Test program for Dave Rand's rendition of the predictor algorithm
 *
 * Updated by: archie@freebsd.org (Archie Cobbs)
 * Updated by: iand@labtam.labtam.oz.au (Ian Donaldson)
 * Updated by: Carsten Bormann <cabo@cs.tu-berlin.de>
 * Original  : Dave Rand <dlr@bungi.com>/<dave_rand@novell.com>
 */

#include "ppp.h"
#include "ccp.h"
#include "util.h"
#include "ngfunc.h"

#include <netgraph/ng_message.h>
#ifdef __DragonFly__
#include <netgraph/ppp/ng_ppp.h>
#include <netgraph/socket/ng_socket.h>
#else
#include <netgraph/ng_ppp.h>
#include <netgraph/ng_socket.h>
#endif
#include <netgraph.h>

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

  static int	Pred1Init(int direction);
  static void	Pred1Cleanup(int direction);
  static void	Pred1Compress(u_char *uncomp, int orglen, u_char *comp, int *newlen);
  static void	Pred1Decompress(u_char *uncomp, int orglen, u_char *comp, int *newlen);

  static u_char	*Pred1BuildConfigReq(u_char *cp);
  static void   Pred1DecodeConfigReq(Fsm fp, FsmOption opt, int mode);
  static Mbuf	Pred1RecvResetReq(int id, Mbuf bp, int *noAck);
  static Mbuf	Pred1SendResetReq(void);
  static int    Pred1Negotiated(int xmit);
  static int    Pred1SubtractBloat(int size);

  static int	Compress(u_char *source, u_char *dest, int len);
  static int	Decompress(u_char *source, u_char *dest, int slen, int dlen);
  static void	SyncTable(u_char *source, u_char *dest, int len);

/*
 * GLOBAL VARIABLES
 */

  const struct comptype	gCompPred1Info =
  {
    "pred1",
    CCP_TY_PRED1,
    Pred1Init,
    NULL,
    NULL,
    Pred1SubtractBloat,
    Pred1Cleanup,
    Pred1BuildConfigReq,
    Pred1DecodeConfigReq,
    Pred1SendResetReq,
    Pred1RecvResetReq,
    NULL,
    Pred1Negotiated,
    Pred1Compress,
    Pred1Decompress,
  };

/*
 * Pred1Init()
 */

static int
Pred1Init(int directions)
{
  Pred1Info	p = &bund->ccp.pred1;

  struct ngm_connect    cn;

  if (directions == COMP_DIR_RECV)
  {
    p->iHash = 0;
    if (p->InputGuessTable == NULL)
      p->InputGuessTable = Malloc(MB_COMP, PRED1_TABLE_SIZE);
    memset(p->InputGuessTable, 0, PRED1_TABLE_SIZE);

    /* Connect a hook from the bpf node to our socket node */
    snprintf(cn.path, sizeof(cn.path), "%s", MPD_HOOK_PPP);
    snprintf(cn.ourhook, sizeof(cn.ourhook), "%s", NG_PPP_HOOK_DECOMPRESS);
    snprintf(cn.peerhook, sizeof(cn.peerhook), "%s", NG_PPP_HOOK_DECOMPRESS);
    if (NgSendMsg(bund->csock, ".",
	    NGM_GENERIC_COOKIE, NGM_CONNECT, &cn, sizeof(cn)) < 0) {
	Log(LG_ERR, ("[%s] can't connect %s hook: %s",
        bund->name, NG_PPP_HOOK_DECOMPRESS, strerror(errno)));
	return -1;
    }
  }
  if (directions == COMP_DIR_XMIT)
  {
    p->oHash = 0;
    if (p->OutputGuessTable == NULL)
      p->OutputGuessTable = Malloc(MB_COMP, PRED1_TABLE_SIZE);
    memset(p->OutputGuessTable, 0, PRED1_TABLE_SIZE);

    /* Connect a hook from the bpf node to our socket node */
    snprintf(cn.path, sizeof(cn.path), "%s", MPD_HOOK_PPP);
    snprintf(cn.ourhook, sizeof(cn.ourhook), "%s", NG_PPP_HOOK_COMPRESS);
    snprintf(cn.peerhook, sizeof(cn.peerhook), "%s", NG_PPP_HOOK_COMPRESS);
    if (NgSendMsg(bund->csock, ".",
	    NGM_GENERIC_COOKIE, NGM_CONNECT, &cn, sizeof(cn)) < 0) {
	Log(LG_ERR, ("[%s] can't connect %s hook: %s",
        bund->name, NG_PPP_HOOK_COMPRESS, strerror(errno)));
	return -1;
    }
  }
  return 0;
}

/*
 * Pred1Cleanup()
 */

void
Pred1Cleanup(int direction)
{
  Pred1Info	p = &bund->ccp.pred1;
  struct ngm_rmhook rm;

  if (direction == COMP_DIR_RECV)
  {
    assert(p->InputGuessTable);
    Freee(MB_COMP, p->InputGuessTable);
    p->InputGuessTable = NULL;

    /* Disconnect hook. */
    snprintf(rm.ourhook, sizeof(rm.ourhook), "%s", NG_PPP_HOOK_DECOMPRESS);
    if (NgSendMsg(bund->csock, ".",
	    NGM_GENERIC_COOKIE, NGM_RMHOOK, &rm, sizeof(rm)) < 0) {
	Log(LG_ERR, ("can't remove hook %s: %s", NG_PPP_HOOK_DECOMPRESS, strerror(errno)));
    }
  }
  if (direction == COMP_DIR_XMIT)
  {
    assert(p->OutputGuessTable);
    Freee(MB_COMP, p->OutputGuessTable);
    p->OutputGuessTable = NULL;

    /* Disconnect hook. */
    snprintf(rm.ourhook, sizeof(rm.ourhook), "%s", NG_PPP_HOOK_COMPRESS);
    if (NgSendMsg(bund->csock, ".",
	    NGM_GENERIC_COOKIE, NGM_RMHOOK, &rm, sizeof(rm)) < 0) {
	Log(LG_ERR, ("can't remove hook %s: %s", NG_PPP_HOOK_DECOMPRESS, strerror(errno)));
    }
  }
}

/*
 * Pred1Compress()
 *
 * Compress a packet and return a compressed version.
 * The original is untouched.
 */

void
Pred1Compress(u_char *uncomp, int orglen, u_char *comp, int *newlen)
{
  u_char	*wp;
  u_int16_t	fcs;
  int		len;

  wp = comp;

  *wp++ = (orglen >> 8) & 0x7F;
  *wp++ = orglen & 0xFF;

/* Compute FCS */

  fcs = Crc16(PPP_INITFCS, comp, 2);
  fcs = Crc16(fcs, uncomp, orglen);
  fcs = ~fcs;

/* Compress data */

  len = Compress(uncomp, wp, orglen);

/* What happened? */

  if (len < orglen)
  {
    *comp |= 0x80;
    wp += len;
  }
  else
  {
    memcpy(wp, uncomp, orglen);
    wp += orglen;
  }

/* Add FCS */

  *wp++ = fcs & 0xFF;
  *wp++ = fcs >> 8;

  *newlen = (wp - comp);

  Log(LG_CCP2, ("[%s] Pred1: orig (%d) --> comp (%d)", bund->name, orglen, *newlen));
}

/*
 * Pred1Decompress()
 *
 * Decompress a packet and return a compressed version.
 * The original is untouched.
 */

void
Pred1Decompress(u_char *comp, int orglen, u_char *uncomp, int *newlen)
{
  u_char	*cp = comp;
  int		len, len1;
  u_int16_t	fcs;
  u_int16_t	lenn;

/* Get initial length value */
  len = *cp++ << 8;
  len += *cp++;
  
/* Is data compressed or not really? */
  if (len & 0x8000)
  {
    len &= 0x7fff;
    len1 = Decompress(cp, uncomp, orglen - 4, PRED1_DECOMP_BUF_SIZE);
    if (len != len1)	/* Error is detected. Send reset request */
    {
      Log(LG_CCP2, ("[%s] Length error (%d) --> len (%d)", bund->name, len, len1));
      *newlen = 0;
      return;
    }
    cp += orglen - 4;
  }
  else
  {
    SyncTable(cp, uncomp, len);
    cp += len;
  }

  *newlen = len;

  /* Check CRC */
  lenn = htons(len & 0x7fff);
  fcs = Crc16(PPP_INITFCS, (u_char *)&lenn, 2);
  fcs = Crc16(fcs, uncomp, len);
  fcs = Crc16(fcs, cp, 2);

#ifdef DEBUG
    if (fcs != PPP_GOODFCS)
      Log(LG_CCP2, ("fcs = %04x (%s), len = %x, olen = %x",
	   fcs, (fcs == PPP_GOODFCS)? "good" : "bad", len, orglen));
#endif

  if (fcs != PPP_GOODFCS)
  {
    Log(LG_CCP2, ("[%s] Pred1: Bad CRC-16", bund->name));
    *newlen = 0;
    return;
  }

  Log(LG_CCP2, ("[%s] Pred1: orig (%d) <-- comp (%d)", bund->name, *newlen, orglen));
}


/*
 * Pred1RecvResetReq()
 */

static Mbuf
Pred1RecvResetReq(int id, Mbuf bp, int *noAck)
{
  Pred1Init(COMP_DIR_XMIT);
  return(NULL);
}

/*
 * Pred1SendResetReq()
 */

static Mbuf
Pred1SendResetReq(void)
{
  Pred1Init(COMP_DIR_RECV);
  return(NULL);
}

/*
 * Pred1BuildConfigReq()
 */

static u_char *
Pred1BuildConfigReq(u_char *cp)
{
  cp = FsmConfValue(cp, CCP_TY_PRED1, 0, NULL);
  return (cp);
}

/*
 * Pred1DecodeConfigReq()
 */

static void
Pred1DecodeConfigReq(Fsm fp, FsmOption opt, int mode)
{
  /* Deal with it */
  switch (mode) {
    case MODE_REQ:
	FsmAck(fp, opt);
      break;

    case MODE_NAK:
      break;
  }
}

/*
 * Pred1Negotiated()
 */

static int
Pred1Negotiated(int dir)
{
  return 1;
}

/*
 * Pred1SubtractBloat()
 */

static int
Pred1SubtractBloat(int size)
{
  return(size - 2);
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

