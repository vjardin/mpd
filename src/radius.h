/*
 * See ``COPYRIGHT.mpd''
 *
 * $Id$
 *
 */

#include <netgraph/ng_mppc.h>
#include <radlib.h>

#include <net/if.h>
#include <net/if_types.h>

#include "iface.h"

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

  #define MPPE_TYPE_0BIT	0	/* No encryption required */
  #define MPPE_TYPE_40BIT	2
  #define MPPE_TYPE_128BIT	4
  #define MPPE_TYPE_56BIT	8

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

  struct authdata;

/*
 * FUNCTIONS
 */

  extern int	RadiusAuthenticate(struct authdata *auth);
  extern void	RadiusAccount(struct authdata *auth);
  extern void	RadiusClose(struct authdata *auth);
  extern void	RadiusEapProxy(void *arg);
  extern int	RadStat(int ac, char *av[], void *arg);

#endif
