
/*
 * fsm.h
 *
 * Written by Toshiharu OHNO <tony-o@iij.ad.jp>
 * Copyright (c) 1993, Internet Initiative Japan, Inc. All rights reserved.
 * See ``COPYRIGHT.iij''
 * 
 * Rewritten by Archie Cobbs <archie@freebsd.org>
 * Copyright (c) 1995-1999 Whistle Communications, Inc. All rights reserved.
 * See ``COPYRIGHT.whistle''
 */

#ifndef _FSM_H_
#define _FSM_H_

#include <netinet/in.h>
#include "mbuf.h"
#include "timer.h"

/*
 * DEFINITIONS
 */

  /* States: don't change these! */
  #define ST_INITIAL	0
  #define ST_STARTING	1
  #define ST_CLOSED	2
  #define ST_STOPPED	3
  #define ST_CLOSING	4
  #define ST_STOPPING	5
  #define ST_REQSENT	6
  #define ST_ACKRCVD	7
  #define ST_ACKSENT	8
  #define ST_OPENED	9

  #define OPEN_STATE(s)		((s) > ST_CLOSING || ((s) & 1))

  #define MODE_REQ	0
  #define MODE_NAK	1
  #define MODE_REJ	2
  #define MODE_NOP	3

  /* Codes */
  #define CODE_VENDOR		0
  #define CODE_CONFIGREQ	1
  #define CODE_CONFIGACK	2
  #define CODE_CONFIGNAK	3
  #define CODE_CONFIGREJ	4
  #define CODE_TERMREQ		5
  #define CODE_TERMACK		6
  #define CODE_CODEREJ		7
  #define CODE_PROTOREJ		8
  #define CODE_ECHOREQ		9
  #define CODE_ECHOREP		10
  #define CODE_DISCREQ		11
  #define CODE_IDENT		12
  #define CODE_TIMEREM		13
  #define CODE_RESETREQ		14
  #define CODE_RESETACK		15

  /* All the various ways that the FSM can fail */
  /* XXX This should be extended to contain more descriptive information
     XXX about the cause of the failure, like what the rejected protocol
     XXX or option was, etc. */
  enum fsmfail {
    FAIL_NEGOT_FAILURE,		/* option negotiation failed */
    FAIL_RECD_BADMAGIC,		/* rec'd bad magic number */
    FAIL_RECD_CODEREJ,		/* rec'd fatal code reject */
    FAIL_RECD_PROTREJ,		/* rec'd fatal protocol reject */
    FAIL_WAS_PROTREJ,		/* protocol was rejected */
    FAIL_ECHO_TIMEOUT,		/* peer not responding to echo requests */
    FAIL_CANT_ENCRYPT,		/* failed to negotiate required encryption */
  };

  /* FSM descriptor */
  struct fsm;
  typedef struct fsm			*Fsm;
  struct fsmoption;
  typedef struct fsmoption		*FsmOption;
  struct fsmoptinfo;
  typedef const struct fsmoptinfo	*FsmOptInfo;

  struct fsmconf {
    short	maxconfig;	/* "Max-Configure" initial value */
    short	maxterminate;	/* "Max-Terminate" initial value */
    short	maxfailure;	/* "Max-Failure" initial value */
    short	echo_int;	/* LCP echo interval (zero disables) */
    short	echo_max;	/* LCP max quiet timeout */
    u_char	check_magic:1;	/* Validate any magic numbers seen */
    u_char	passive:1;	/* Passive option (see rfc 1661) */
  };
  typedef struct fsmconf	*FsmConf;

  struct fsmtype {
    const char		*name;		/* Name of protocol */
    u_short		proto;		/* Protocol number */
    u_long		known_codes;	/* Accepted FSM codes */
    short		log, log2;	/* Log levels for FSM events */
    u_char		link_layer:1;	/* One FSM for each link */

    void		(*NewState)(Fsm f, int old, int new);
    void		(*LayerUp)(Fsm f);
    void		(*LayerDown)(Fsm f);
    void		(*LayerStart)(Fsm f);
    void		(*LayerFinish)(Fsm f);
    u_char *		(*BuildConfigReq)(Fsm f, u_char *cp);
    void		(*DecodeConfig)(Fsm f, FsmOption a, int num, int mode);
    void		(*Configure)(Fsm f);
    void		(*UnConfigure)(Fsm f);
    void		(*SendTerminateReq)(Fsm f);
    void		(*SendTerminateAck)(Fsm f);
    int			(*RecvCodeRej)(Fsm f, int code, Mbuf bp);
    int			(*RecvProtoRej)(Fsm f, int proto, Mbuf bp);
    void		(*Failure)(Fsm f, enum fsmfail reason);
    void		(*RecvResetReq)(Fsm f, int id, Mbuf bp);
    void		(*RecvResetAck)(Fsm f, int id, Mbuf bp);
    void		(*RecvIdent)(Fsm f, Mbuf bp);
    void		(*RecvDiscReq)(Fsm f, Mbuf bp);
    void		(*RecvTimeRemain)(Fsm f, Mbuf bp);
    void		(*RecvVendor)(Fsm f, Mbuf bp);
  };
  typedef const struct fsmtype	*FsmType;

  struct fsm {
    FsmType		type;		/* FSM constant stuff */
    short		log;		/* Current log level */
    struct fsmconf	conf;		/* FSM parameters */
    short		state;		/* State of the machine */
    u_char		reqid;		/* Next request id */
    u_char		rejid;		/* Next reject id */
    u_char		echoid;		/* Next echo request id */
    short		restart;	/* Restart counter value */
    short		failure;	/* How many failures left */
    short		config;		/* How many configs left */
    short		quietCount;	/* How long peer has been silent */
    struct pppTimer	timer;		/* Restart Timer */
    struct pppTimer	echoTimer;	/* Keep-alive timer */
    struct ng_ppp_link_stat
			idleStats;	/* Stats for echo timeout */
  };

  /* Packet header */
  struct fsmheader {
    u_char	code;		/* Request code */
    u_char	id;		/* Identification */
    u_short	length;		/* Length of packet */
  };
  typedef struct fsmheader	*FsmHeader;

  /* One config option */
  struct fsmoption {
    u_char	type;
    u_char	len;
    u_char	*data;
  };

  /* Fsm option descriptor */
  struct fsmoptinfo {
    const char	*name;
    u_char	type;
    u_char	minLen;
    u_char	maxLen;
    u_char	supported;
  };

/*
 * VARIABLES
 */

  extern u_int		gAckSize, gNakSize, gRejSize;

/*
 * FUNCTIONS
 */

  extern void		FsmInit(Fsm f, FsmType t);
  extern void		FsmOpen(Fsm f);
  extern void		FsmClose(Fsm f);
  extern void		FsmUp(Fsm f);
  extern void		FsmDown(Fsm f);
  extern void		FsmInput(Fsm f, Mbuf bp, int linkNum);
  extern void		FsmOutput(Fsm, u_int, u_int, u_char *, int);
  extern void		FsmOutputMbuf(Fsm, u_int, u_int, Mbuf);
  extern void		FsmOutputMbuf2(u_short proto, int linklayer,
				u_int code, u_int id, Mbuf payload);
  extern void		FsmSendEchoReq(Fsm fp, Mbuf payload);
  extern void		FsmSendIdent(Fsm fp, const char *ident);
  extern u_char		*FsmConfValue(u_char *cp, int ty,
				int len, const void *data);
  extern void		FsmFailure(Fsm fp, enum fsmfail reason);
  extern const char	*FsmFailureStr(enum fsmfail reason);

  extern void		FsmAck(Fsm fp, const struct fsmoption *opt);
  extern void		FsmNak(Fsm fp, const struct fsmoption *opt);
  extern void		FsmRej(Fsm fp, const struct fsmoption *opt);

  extern FsmOptInfo	FsmFindOptInfo(FsmOptInfo list, u_char type);
  extern const char	*FsmStateName(int state);
  extern const char	*FsmCodeName(int code);
  extern char		*Pref(Fsm fp);

#endif	/* _FSM_H_ */

