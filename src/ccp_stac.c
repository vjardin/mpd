
/*
 * ccp_stac.c
 *
 * Written by Archie Cobbs <archie@freebsd.org>
 * Copyright (c) 1995-1999 Whistle Communications, Inc. All rights reserved.
 * See ``COPYRIGHT.whistle''
 */

#include "ppp.h"
#include "ccp.h"
#include "lzsc.h"

/*
 * DEFINITIONS
 */

  #define STAC_DECOMP_BUF_SIZE	(1600 + LZS_DEST_MIN)
  #define STAC_MAX_BLOWUP(n)	((n) * 9 / 8 + 24)
  #define STAC_OVERHEAD		2

  struct stacparam
  {
    u_int16_t	histories;
    u_int8_t	checkmode;
  };
  typedef struct stacparam	*StacParam;

/*
 * INTERNAL FUNCTIONS
 */

  static void	StacInit(int xmit);
  static char	*StacDescribe(int xmit);
  static int	StacSubtractBloat(int size);
  static Mbuf	StacCompress(Mbuf *bp);
  static Mbuf	StacDecompress(Mbuf bp);
  static void	StacCleanup(int direction);
  static u_char	*StacBuildConfigReq(u_char *cp);
  static void	StacDecodeConfigReq(Fsm fp, FsmOption opt, int mode);
  static Mbuf	StacSendResetReq(void);
  static Mbuf	StacRecvResetReq(int id, Mbuf bp, int *noAck);
  static int	StacNegotiated(int xmit);

/*
 * GLOBAL VARIABLES
 */

  const struct comptype	gCompStacInfo =
  {
    "stac",
    CCP_TY_STAC,
    StacInit,
    NULL,
    StacDescribe,
    StacSubtractBloat,
    StacCompress,
    StacDecompress,
    StacCleanup,
    StacBuildConfigReq,
    StacDecodeConfigReq,
    StacSendResetReq,
    StacRecvResetReq,
    NULL,
    StacNegotiated,
  };

/*
 * StacInit()
 */

static void
StacInit(int xmit)
{
  StacInfo	stac = &bund->ccp.stac;

/* Allocate */

  if (stac->history == NULL)
    stac->history = Malloc(MB_COMP, LZS_HISTORY_SIZE);
  if (xmit)
    stac->out_active = TRUE;
  else
    stac->in_active = TRUE;

/* Initialize: this initializes both directions! But that's OK... */

  LZS_InitHistory(stac->history);
}

/*
 * StacDescribe()
 */

static char *
StacDescribe(int xmit)
{
  static char	buf[64];

  snprintf(buf, sizeof(buf),
    "STAC: histories %d, checkmode %d", 0, 0);		/* XXX */
  return(buf);
}

/*
 * StacSubtractBloat()
 */

static int
StacSubtractBloat(int size)
{
  int	l, h, size0;

  size0 = (size -= STAC_OVERHEAD);
  while (1) {
    l = STAC_MAX_BLOWUP(size0);
    h = STAC_MAX_BLOWUP(size0 + 1);
    if (l > size) {
      size0 -= 20;
    } else if (h > size) {
      size = size0;
      break;
    } else {
      size0++;
    }
  }
  return(size);
}

/*
 * StacCompress()
 *
 * Compress a packet and return a compressed version.
 * The original is untouched.
 */

static Mbuf
StacCompress(Mbuf *ucomp)
{
  StacInfo	stac = &bund->ccp.stac;
  u_char	*source, *dest;
  u_long	sourceCnt, destCnt;
  Mbuf		wp, comp;
  int		rtn;

/* Get mbuf for compressed frame */

  comp = mballoc(MB_COMP, STAC_MAX_BLOWUP(plength(*ucomp)) + STAC_OVERHEAD);
  dest = MBDATA(comp);
  destCnt = comp->cnt;

/* Compress "ucomp" into "comp" */

  for (wp = *ucomp; wp; wp = wp->next)
  {
    source = MBDATA(wp);
    sourceCnt = wp->cnt;
    rtn = LZS_Compress(&source, &dest, &sourceCnt, &destCnt,
      stac->history, (wp->next ? 0 : LZS_SOURCE_FLUSH), LZS_PERF_MODE_0);
    if (rtn != (LZS_SOURCE_EXHAUSTED | (wp->next ? 0 : LZS_FLUSHED)))
    {
      Log(LG_ERR, ("%s: STAC compress returned 0x%x",
	Pref(&bund->ccp.fsm), rtn));
      DoExit(EX_ERRDEAD);
    }
  }
  comp->cnt -= destCnt;

/* it */

  return(comp);
}

/*
 * StacDecompress()
 *
 * Decompress packet. Returns NULL if packet failed to decompress.
 */

static Mbuf
StacDecompress(Mbuf comp)
{
  StacInfo	stac = &bund->ccp.stac;
  u_char	*source, *dest;
  u_long	sourceCnt, destCnt;
  Mbuf		wp, ucomp;
  int		rtn;

/* Get mbuf for uncompressed frame */

  ucomp = mballoc(MB_COMP, STAC_DECOMP_BUF_SIZE);
  dest = MBDATA(ucomp);
  destCnt = ucomp->cnt;

/* Uncompress packet data into "ucomp" */

  for (wp = comp; wp; wp = wp->next)
  {
    source = MBDATA(wp);
    sourceCnt = wp->cnt;
    rtn = LZS_Decompress(&source, &dest, &sourceCnt, &destCnt,
      stac->history, (wp == comp ? LZS_RESET : 0));
    if ((!wp->next && !(rtn & LZS_END_MARKER))
      || (wp->next && rtn != LZS_SOURCE_EXHAUSTED))
    {
      Log(LG_ERR, ("%s: STAC decompress returned 0x%x",
	Pref(&bund->ccp.fsm), rtn));
      PFREE(comp);
      PFREE(ucomp);
      return(NULL);
    }
  }
  PFREE(comp);
  if ((ucomp->cnt -= destCnt) <= 0)
  {
    PFREE(ucomp);
    return(NULL);
  }

/* Done */

  return(ucomp);
}

/*
 * StacCleanup()
 */

static void
StacCleanup(int xmit)
{
  StacInfo	stac = &bund->ccp.stac;

  if (xmit)
    stac->out_active = FALSE;
  else
    stac->in_active = FALSE;
  if (!stac->in_active && !stac->out_active)
  {
    Freee(stac->history);
    stac->history = NULL;
  }
}

/*
 * StacBuildConfigReq()
 */

static u_char *
StacBuildConfigReq(u_char *cp)
{
  struct stacparam	params;

  params.histories = htons(0);		/* Zero histories */
  params.checkmode = 0;			/* Null check mode */
  return(FsmConfValue(cp, CCP_TY_STAC, 3, &params));
}

/*
 * StacDecodeConfigReq()
 */

static void
StacDecodeConfigReq(Fsm fp, FsmOption opt, int mode)
{
  StacParam	const sp = (StacParam) opt->data;

  if (opt->len != 5 && opt->len != 6)
  {
    Log(LG_CCP, ("   bogus length %d", opt->len));
    if (mode == MODE_REQ)
      FsmRej(fp, opt);
    return;
  }
  Log(LG_CCP, ("   histories %d, checkmode %d", sp->histories, sp->checkmode));
  switch (mode)
  {
    case MODE_REQ:
      if (sp->histories != 0 || sp->checkmode != 0)
      {
	sp->histories = 0;
	sp->checkmode = 0;
	FsmNak(fp, opt);
	break;
      }
      FsmAck(fp, opt);
      break;
    case MODE_NAK:		/* We can only do it one way */
      break;
  }
}

/*
 * StacSendResetReq()
 */

static Mbuf
StacSendResetReq(void)
{
  StacInit(0);
  return(NULL);
}

/*
 * StacRecvResetReq()
 */

static Mbuf
StacRecvResetReq(int id, Mbuf bp, int *noAck)
{
  StacInit(1);
  return(NULL);
}

/*
 * StacNegotiated()
 */

static int
StacNegotiated(int xmit)
{
  StacInfo	stac = &bund->ccp.stac;

  if (xmit)
    return(stac->out_active);
  else
    return(stac->in_active);
}

