
/*
 * auth.h
 *
 * Written by Archie Cobbs <archie@freebsd.org>
 * Copyright (c) 1995-1999 Whistle Communications, Inc. All rights reserved.
 * See ``COPYRIGHT.whistle''
 */

#ifndef _AUTH_H_
#define	_AUTH_H_

#include "timer.h"
#include "pap.h"
#include "chap.h"
#include "eap.h"
#include "radius.h"
  
/*
 * DEFINITIONS
 */

  #define AUTH_RETRIES		3

  #define AUTH_MSG_WELCOME	"Welcome\r\n"
  #define AUTH_MSG_INVALID	"Login incorrect\r\n"
  #define AUTH_MSG_BAD_PACKET	"Incorrectly formatted packet\r\n"
  #define AUTH_MSG_NOT_ALLOWED	"Login not allowed for this account\r\n"
  #define AUTH_MSG_NOT_EXPECTED	"Unexpected packet\r\n"
  #define AUTH_MSG_ACCT_DISAB	"Account disabled\r\n"
  #define AUTH_MSG_RESTR_HOURS	"Login hours restricted\r\n"

  #define AUTH_PEER_TO_SELF	0
  #define AUTH_SELF_TO_PEER	1

  #define AUTH_FAIL_INVALID_LOGIN	0
  #define AUTH_FAIL_ACCT_DISABLED	1
  #define AUTH_FAIL_NO_PERMISSION	2
  #define AUTH_FAIL_RESTRICTED_HOURS	3
  #define AUTH_FAIL_INVALID_PACKET	4
  #define AUTH_FAIL_NOT_EXPECTED	5
  
  #define AUTH_STATUS_UNDEF		0
  #define AUTH_STATUS_FAIL		1
  #define AUTH_STATUS_SUCCESS		2
  
  #define AUTH_PW_HASH_NONE		0
  #define AUTH_PW_HASH_NT		1
  
  #define AUTH_ACCT_START		1
  #define AUTH_ACCT_STOP		2
  #define AUTH_ACCT_UPDATE		3
  
  /* State of authorization process during authorization phase,
   * contains params set by the auth-backend */
  struct auth {
    u_short		peer_to_self;	/* What I need from peer */
    u_short		self_to_peer;	/* What peer needs from me */
    struct pppTimer	timer;		/* Max time to spend doing auth */
    struct pppTimer	acct_timer;	/* Timer for accounting updates */
    struct papinfo	pap;		/* PAP state */
    struct chapinfo	chap;		/* CHAP state */
    struct eapinfo	eap;		/* EAP state */
    struct paction	*thread;	/* async auth thread */
    struct paction	*acct_thread;	/* async accounting auth thread */
    struct {
      int		authentic;	/* whether RADIUS auth was used */
      unsigned long	class;      	/* Class */
      char		*eapmsg;	/* recvd EAP Msg for forwarding to the peer */
      int		eapmsg_len;
      char		*state;
      int		state_len;      
      struct radius_acl	*acl_rule;
      struct radius_acl	*acl_pipe;
      struct radius_acl	*acl_queue;
    } radius;
    struct {
      int	policy;		/* MPPE_POLICY_* */
      int	types;		/* MPPE_TYPE_*BIT bitmask */
      int	has_keys;
      int	has_lm_key;
      u_char	lm_key[8];	/* LAN-Manager Hash */
      int	has_nt_hash;
      u_char	nt_hash[16];	/* NT-Hash */
      u_char	padding[8];	/* Padding to fit in 16 byte boundary */
    } mppc;
    struct {
      unsigned long	mtu;			/* MTU */
      unsigned long	session_timeout;	/* Session-Timeout */
      unsigned long	idle_timeout;		/* Idle-Timeout */
      unsigned long	interim_interval;	/* interval for accouting updates */
      char		*msdomain;		/* Microsoft domain */
      short		n_routes;
      struct ifaceroute	routes[IFACE_MAX_ROUTES];
    } params;
  };
  typedef struct auth	*Auth;

  struct authconf {
    struct radiusconf	radius;		/* RADIUS configuration */
    char		authname[AUTH_MAX_AUTHNAME];	/* Configured username */
    char		password[AUTH_MAX_PASSWORD];	/* Configured password */
    struct optinfo	options;	/* Configured options */
  };
  typedef struct authconf	*AuthConf;

  struct radiusconf	radius;			/* RADIUS configuration */
  /* Interface between the auth-backend (secret file, RADIUS, etc.)
   * and Mpd's internal structs.
   */
  struct authdata {
    Link		lnk;		/* a copy of the link */
    struct authconf	conf;		/* a copy of bundle's authconf */
    struct mppcinfo	mppc;		/* key-material for MPPE */
    int			proto;		/* wich proto are we using, PAP, CHAP, ... */
    u_int		id;		/* Actual, packet id */    
    u_int		code;		/* Proto specific code */
    char		authname[AUTH_MAX_AUTHNAME];
    char		password[AUTH_MAX_PASSWORD];
    char		extcmd[AUTH_MAX_EXTCMD];
    struct in_range	range;
    u_int		range_valid:1;
    u_int		external:1;
    u_short		status;
    int			why_fail;
    u_char		ack_mesg[128];
    char		*reply_message;	/* Text wich may displayed to the user */
    char		*mschap_error;	/* MSCHAP Error Message */
    char		*mschapv2resp;	/* Response String for MSCHAPv2 */
    void		(*finish)(struct authdata *auth);
    int			acct_type;	/* Accounting type, Start, Stop, Update */
    struct {
      struct rad_handle	*handle;	/* the RADIUS handle */
      char		*eapmsg;	/* EAP Msg for forwarding to RADIUS server */
      int		eapmsg_len;
    } radius;
    struct {		/* list of params obtained from the auth-backend */
      struct in_addr	ip;		/* IP Address */
      struct in_addr	mask;		/* IP Netmask */
    } params;
  };
  typedef struct authdata	*AuthData;
  
/*
 * GLOBAL VARIABLES
 */
  const u_char	gMsoftZeros[32];

/*
 * FUNCTIONS
 */

  extern void	AuthStart(void);
  extern void	AuthStop(void);
  extern void	AuthInput(int proto, Mbuf bp);
  extern void	AuthOutput(int proto, u_int code, u_int id,
	const u_char *ptr, int len, int add_len, u_char eap_type);
  extern void	AuthFinish(int which, int ok, AuthData auth);
  extern void	AuthCleanup(void);
  extern void	AuthAccountStart(int type);
  extern void	AuthDataDestroy(AuthData auth);
  extern int	AuthGetData(AuthData auth, int complain);
  extern void	AuthAsyncStart(AuthData auth);
  extern const char	*AuthFailMsg(AuthData auth, int alg);
  extern const char	*AuthStatusText(int status);


#endif
