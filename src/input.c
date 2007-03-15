
/*
 * input.c
 *
 * Written by Archie Cobbs <archie@freebsd.org>
 * Copyright (c) 1995-1999 Whistle Communications, Inc. All rights reserved.
 * See ``COPYRIGHT.whistle''
 */

#include "ppp.h"
#include "input.h"
#include "ipcp.h"
#include "chap.h"
#include "pap.h"
#include "eap.h"
#include "lcp.h"
#include "ip.h"
#include "ccp.h"
#include "ecp.h"
#include "ngfunc.h"

/*
 * INTERNAL FUNCTIONS
 */

  static int	InputLinkCheck(int linkNum, int proto);
  static void	InputMPLinkCheck(int proto, Mbuf pkt);
  static int	InputDispatch(const char *name,
			int linkNum, int proto, Mbuf bp);

/*
 * InputFrame()
 *
 * Input a PPP frame having protocol "proto" from link "linkNum",
 * which may be either a link number or NG_PPP_BUNDLE_LINKNUM.
 * This always consumes the mbuf.
 */

void
InputFrame(int linkNum, int proto, Mbuf bp)
{
  Link		theLink, linkSave;
  Mbuf		protoRej;
  const char	*label;
  u_int16_t	nprot;
  int		k;

  /* Check the link */
  if (linkNum == NG_PPP_BUNDLE_LINKNUM) {

    /* Set link and label */
    label = bund->name;
    lnk = bund->links[0];		/* just pick one */

    /* Only limited link-layer stuff allowed over the MP bundle */
    if (PROT_LINK_LAYER(proto)) {
      InputMPLinkCheck(proto, bp);
      return;
    }
  } else {

    /* Sanity check link number */
    if (linkNum < 0 || linkNum > bund->n_links) {
      Log(LG_ERR, ("[%s] invalid link # %d proto %s",
	bund->name, linkNum, ProtoName(proto)));
      PFREE(bp);
      return;
    }

    /* Set link and label */
    lnk = bund->links[linkNum];
    label = bund->name;

    /* Check protocol vs. link state */
    if (!InputLinkCheck(linkNum, proto)) {
      PFREE(bp);
      return;
    }
  }

  /* Dispatch frame to the appropriate protocol engine */
  if (InputDispatch(label, linkNum, proto, bp) >= 0)
    return;

  /* Unknown protocol, so find a link to send protocol reject on */
  if (linkNum != NG_PPP_BUNDLE_LINKNUM)
    theLink = lnk;
  else {
    for (k = 0;
      k < bund->n_links && bund->links[k]->lcp.phase != PHASE_NETWORK;
      k++);
    if (k == bund->n_links) {
      PFREE(bp);
      return;
    }
    theLink = bund->links[k];
  }

  /* Send a protocol reject on the chosen link */
  linkSave = lnk;
  lnk = theLink;
  nprot = htons((u_int16_t) proto);
  protoRej = mbwrite(mballoc(MB_FRAME_OUT, 2), (u_char *) &nprot, 2);
  protoRej->next = bp;
  FsmOutputMbuf(&lnk->lcp.fsm, CODE_PROTOREJ, lnk->lcp.fsm.rejid++, protoRej);
  lnk = linkSave;
}

/*
 * InputDispatch()
 *
 * Given an unwrapped PPP frame of type "proto", dispatch to wherever.
 * Returns negative if protocol was unknown, otherwise returns zero
 * and consumes packet. Any packets we expect the peer to send but
 * shouldn't be received by this daemon are logged and dropped.
 */

static int
InputDispatch(const char *label, int linkNum, int proto, Mbuf bp)
{
  int reject = 0;

  switch (proto) {
    case PROTO_LCP:
      LcpInput(bp, linkNum);
      return(0);
    case PROTO_PAP:
    case PROTO_CHAP:
    case PROTO_EAP:
      AuthInput(proto, bp);
      return(0);
    case PROTO_IPCP:
    case PROTO_IP:
    case PROTO_VJUNCOMP:
    case PROTO_VJCOMP:
      if (!Enabled(&bund->conf.options, BUND_CONF_IPCP))
	reject = 1;
      else if (proto == PROTO_IPCP) {
        IpcpInput(bp, linkNum);
        return(0);
      }
      break;
    case PROTO_IPV6CP:
    case PROTO_IPV6:
      if (!Enabled(&bund->conf.options, BUND_CONF_IPV6CP))
	reject = 1;
      else if (proto == PROTO_IPV6CP) {
        Ipv6cpInput(bp, linkNum);
        return(0);
      }
      break;
    case PROTO_CCP:
    case PROTO_COMPD:
      if (!Enabled(&bund->conf.options, BUND_CONF_COMPRESSION))
	reject = 1;
      else if (proto == PROTO_CCP) {
	CcpInput(bp, linkNum);
	return(0);
      }
      break;
    case PROTO_ECP:
    case PROTO_CRYPT:
      if (!Enabled(&bund->conf.options, BUND_CONF_ENCRYPTION))
	reject = 1;
      else if (proto == PROTO_ECP) {
	EcpInput(bp, linkNum);
	return(0);
      }
      break;
    case PROTO_MP:
      if (!Enabled(&bund->conf.options, BUND_CONF_MULTILINK))
	reject = 1;
      break;
    default:			/* completely unknown protocol, reject it */
      reject = 1;
      break;
  }

  /* Protocol unexpected, so either reject or drop */
  Log(LG_LINK|LG_BUND, ("[%s] rec'd unexpected protocol %s on link %d%s",
    label, ProtoName(proto), (short)linkNum, reject ? ", rejecting" : ""));
  if (!reject)
    PFREE(bp);
  return(reject ? -1 : 0);
}

/*
 * InputLinkCheck()
 *
 * Make sure this protocol is acceptable and makes sense on this link.
 * Returns TRUE if so and the frame should be handled further.
 * The "linkNum" should be real and not equal to NG_PPP_BUNDLE_LINKNUM.
 */

static int
InputLinkCheck(int linkNum, int proto)
{
  assert(linkNum != NG_PPP_BUNDLE_LINKNUM);

  /* Check link LCP state */
  switch (lnk->lcp.phase) {
    case PHASE_DEAD:
      Log(LG_ERR, ("[%s] rec'd proto %s while dead",
	lnk->name, ProtoName(proto)));
      return(FALSE);
    case PHASE_ESTABLISH:
      if (proto != PROTO_LCP) {
	Log(LG_ERR, ("[%s] rec'd proto %s during establishment phase",
	  lnk->name, ProtoName(proto)));
	return(FALSE);
      }
      break;
    case PHASE_AUTHENTICATE:
      if (!PROT_LINK_LAYER(proto)) {
	Log(LG_ERR, ("[%s] rec'd proto %s during authenticate phase",
	  lnk->name, ProtoName(proto)));
	return(FALSE);
      }
      break;
    case PHASE_NETWORK:
      break;
    case PHASE_TERMINATE:
      if (proto != PROTO_LCP) {
	Log(LG_ERR, ("[%s] rec'd proto %s during terminate phase",
	  lnk->name, ProtoName(proto)));
	return(FALSE);
      }
      break;
    default:
      assert(0);
  }

  /* OK */
  return(TRUE);
}

/*
 * InputMPLinkCheck()
 *
 * Deal with an incoming link-level packet on the virtual link (!)
 * Only certain link-level packets make sense coming over the bundle.
 * In any case, this consumes the mbuf.
 */

static void
InputMPLinkCheck(int proto, Mbuf pkt)
{
  struct fsmheader	hdr;	

  mbcopy(pkt, (u_char *) &hdr, sizeof(hdr));
  switch (proto) {
    case PROTO_LCP:
      switch (hdr.code) {
        default:
	  Log(LG_ERR, ("[%s] rec'd LCP %s #%d on MP link! (ignoring)",
	    bund->name, FsmCodeName(hdr.code), hdr.id));
	  PFREE(pkt);
	  break;

	case CODE_CODEREJ:		/* these two are OK */
	case CODE_PROTOREJ:
	  InputFrame(0, proto, pkt);
	  break;

	case CODE_ECHOREQ:
	  Log(LG_ECHO, ("[%s] rec'd %s #%d, replying...",
	    bund->name, FsmCodeName(hdr.code), hdr.id));
	  MBDATAU(pkt)[0] = CODE_ECHOREP;
	  NgFuncWritePppFrame(NG_PPP_BUNDLE_LINKNUM, PROTO_LCP, pkt);
	  break;

	case CODE_ECHOREP:
	  Log(LG_ECHO, ("[%s] rec'd %s #%d",
	    bund->name, FsmCodeName(hdr.code), hdr.id));
	  PFREE(pkt);
	  break;
      }
      break;

    default:
      Log(LG_ERR, ("[%s] rec'd proto %s on MP link! (ignoring)",
	bund->name, ProtoName(proto)));
      PFREE(pkt);
      break;
  }
}

