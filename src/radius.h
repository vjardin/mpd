/*
 * See ``COPYRIGHT.mpd''
 *
 * $Id$
 *
 */

#include "ppp.h"
#include "auth.h"
#include "ccp_mppc.h"
#include <radlib.h>

#ifndef _RADIUS_H_
#define _RADIUS_H_

/*
 * DEFINITIONS
 */

  #define RADIUS_CHAP		1
  #define RADIUS_PAP		2
  #define RADIUS_EAP		3
  #define RADIUS_MAX_SERVERS	10

  #define RAD_NACK		0
  #define RAD_ACK		1

  #ifndef RAD_UPDATE
  #define RAD_UPDATE 3
  #endif

  #ifndef RAD_ACCT_INPUT_GIGAWORDS
  #define RAD_ACCT_INPUT_GIGAWORDS 52
  #endif

  #ifndef RAD_ACCT_OUTPUT_GIGAWORDS
  #define RAD_ACCT_OUTPUT_GIGAWORDS 53
  #endif

  #ifndef RAD_ACCT_INTERIM_INTERVAL
  #define RAD_ACCT_INTERIM_INTERVAL 85
  #endif

  #ifndef RAD_EAP_MESSAGE
  #define RAD_EAP_MESSAGE 79
  #endif

  #ifndef RAD_MESSAGE_AUTHENTIC
  #define RAD_MESSAGE_AUTHENTIC 80
  #endif

  /* for mppe-keys */
  #define AUTH_LEN		16
  #define SALT_LEN		2

  #define MPPE_POLICY_NONE	0
  #define MPPE_POLICY_ALLOWED	1
  #define MPPE_POLICY_REQUIRED	2

  #define MPPE_TYPE_0BIT		0	/* No encryption required */
  #define MPPE_TYPE_40BIT		2
  #define MPPE_TYPE_128BIT	4
  #define MPPE_TYPE_56BIT		8

  /* max. length of RAD_ACCT_SESSION_ID, RAD_ACCT_MULTI_SESSION_ID */
  #define RAD_ACCT_MAX_SESSIONID	256

  /* max. length of acl rule, */
  #define ACL_LEN	256

  #define RAD_VENDOR_MPD	12341
  #define RAD_MPD_RULE		1
  #define RAD_MPD_PIPE		2
  #define RAD_MPD_QUEUE		3

  /* Configuration options */
  enum {
    RADIUS_CONF_MESSAGE_AUTHENTIC,
  };

  extern const	struct cmdtab RadiusSetCmds[];

  struct radiusserver_conf {
    char	*hostname;
    char	*sharedsecret;
    int		auth_port;
    int		acct_port;
    struct	radiusserver_conf *next;
  };
  typedef struct radiusserver_conf *RadServe_Conf;

  /* Configuration for a radius server */
  struct radiusconf {
    int		radius_timeout;
    int		radius_retries;
    int 	acct_update;		/* Accounting Update Interval */
    struct	in_addr radius_me;
    char	file[PATH_MAX];
    struct radiusserver_conf *server;
    struct optinfo	options;	/* Configured options */
  };
  typedef struct radiusconf *RadConf;

  struct radius_acl {	/* List of ACLs received from RADIUS */
    int number;		/* ACL number given by RADIUS server */
    char rule[ACL_LEN]; /* Text of ACL */
    struct radius_acl *next;
  };

  /* persistent info, not free'd before making a new request */
  struct radius_persistent {
    int		state_len;
    char	*state;
  };

  struct radius {
    /* internal vars */
    struct rad_handle	*radh;		/* RadLib Handle */
    struct pppTimer 	radUpdate;	/* Accounting Update Timer */
    short		valid;		/* Auth was successful */
    int			authentic;	/* whether RADIUS authentication was used */
    int			response_type;	/* Type of response, i.e. Reject, Access, Challenge, ... */
    short		auth_type;	/* PAP, CHAP, MS-CHAP, EAP */
    char		authname[AUTH_MAX_AUTHNAME];
    char		*reply_message;	/* Text wich may displayed to the user */
    char		multi_session_id[RAD_ACCT_MAX_SESSIONID];	/* Multi-Session-Id needed for accounting */
    char		session_id[RAD_ACCT_MAX_SESSIONID];
    char		*eapmsg;
    int			eapmsg_len;
    /* RADIUS attributes */
    unsigned		vj:1;		/* FRAMED Compression */
    struct in_addr	ip;		/* FRAMED IP */
    struct in_addr	mask;		/* FRAMED Netmask */
    short		n_routes;
    struct ifaceroute	routes[IFACE_MAX_ROUTES];
    unsigned long	class;			/* Class */
    unsigned long	mtu;			/* FRAMED MTU */
    unsigned long	session_timeout;	/* Session-Timeout */
    unsigned long	idle_timeout;		/* Idle-Timeout */
    unsigned long	protocol;		/* FRAMED Protocol */
    unsigned long	service_type;		/* Service Type */
    unsigned long	interim_interval;	/* interval for accouting updates */
    char		*filterid;		/* FRAMED Filter Id */
    char		*msdomain;		/* Microsoft domain */
    char		*mschap_error;		/* MSCHAP Error Message */
    char		*mschapv2resp;		/* Response String for MSCHAPv2 */
    struct {
      int	policy;			/* MPPE_POLICY_* */
      int	types;			/* MPPE_TYPE_*BIT bitmask */
      u_char	recvkey[MPPE_KEY_LEN];	/* MS-CHAP v2 Keys */
      size_t	recvkeylen;
      u_char	sendkey[MPPE_KEY_LEN];
      size_t	sendkeylen;
      u_char	lm_key[8];		/* MS-CHAP v1 Keys 40 or 56 Bit */
      u_char	nt_hash[MPPE_KEY_LEN];	/* MS-CHAP v1 calculating 128 Bit Key */
      u_char	padding[8];		/* Padding to fit in 16 byte boundary */
    } mppe;
    struct radius_acl 	*acl_rule;
    struct radius_acl 	*acl_pipe;
    struct radius_acl 	*acl_queue;
    /* Only free'd after the link-down, not freed between
     * multiple RADIUS requests */
    struct radius_persistent	pers;
  };

  struct rad_chapvalue {
    u_char	ident;
    u_char	response[CHAP_MAX_VAL];
  };

  struct rad_mschapvalue {
    u_char	ident;
    u_char	flags;
    u_char	lm_response[24];
    u_char	nt_response[24];
  };

  struct rad_mschapv2value {
    u_char	ident;
    u_char	flags;
    u_char	pchallenge[16];
    u_char	reserved[8];
    u_char	response[24];
  };
  
  struct rad_mschapv2value_cpw {
    u_char	code;
    u_char	ident;
    u_char	encryptedHash[16];
    u_char	pchallenge[16];
    u_char	reserved[8];    
    u_char	nt_response[24];
    u_char	flags[2]; 
  };
  
  struct rad_mschap_new_nt_pw {
    u_char	ident;
    short	chunk;
    u_char	data[129];
  };

/*
 * FUNCTIONS
 */

  extern int	RadiusPAPAuthenticate(const char *name, const char *password);
  extern int	RadiusCHAPAuthenticate(const char *name, const char *password,
			int passlen, const char *challenge, int challenge_size,
			u_char chapid, int chap_type);
  extern int	RadiusStart(short request_type);
  extern int	RadiusPutAuth(const char *name, const char *password,
			int passlen, const char *challenge, int challenge_size,
			u_char chapid, int auth_type);
  extern int	RadiusSendRequest(void);
  extern int	RadiusGetParams(int eap_proxy);
  extern int	RadiusAccount(short acct_type);
  extern void	RadiusSetAuth(AuthData auth);
  extern int	RadStat(int ac, char *av[], void *arg);
  extern void	RadiusDestroy(void);
  extern void	RadiusDown(void);
  extern void	RadiusAcctUpdate(void *a);
  extern int	RadiusEAPProxy(const char *identity, const char *pkt, int len);

#endif
