
/*
 * radius.h
 *
 * Written by Michael Bretterklieber <mbretter@inode.at>
 * Written by Brendan Bank <brendan@gnarst.net>
 */

#include "ppp.h"
#include "auth.h"
#include "ccp_mppc.h"
#include <radlib.h>

#ifndef _RADIUS_H_
#define _RADIUS_H_

#define RADIUS_CHAP		1
#define RADIUS_PAP		2
#define RADIUS_MAX_SERVERS	10

#define RAD_NACK		0
#define RAD_ACK			1

/* for mppe-keys */
#define AUTH_LEN		16
#define SALT_LEN		2

#define MPPE_POLICY_ALLOWED	1
#define MPPE_POLICY_REQUIRED	2

#define MPPE_TYPE_0BIT		0	/* No encryption required */
#define MPPE_TYPE_40BIT		2
#define MPPE_TYPE_128BIT	4
#define MPPE_TYPE_56BIT		8

/*
 * FUNCTIONS
 */

extern int	RadiusAuthenticate(const char *name, const char *password,
			int passlen, const char *challenge, int challenge_size,
			u_char chapid, int auth_type);
extern int	RadiusPAPAuthenticate(const char *name, const char *password);
extern int	RadiusCHAPAuthenticate(const char *name, const char *password,
			int passlen, const char *challenge, int challenge_size,
			u_char chapid, int chap_type);
extern int	RadiusGetParams(void);
extern void	RadiusSetAuth(AuthData auth);
extern int	RadStat(int ac, char *av[], void *arg);

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
    char	file[PATH_MAX];
    struct radiusserver_conf *server;
  };
  typedef struct radiusconf *RadConf;

  struct radius {
    struct rad_handle	*radh;		/* RadLib Handle */
    short		valid;		/* Auth was successful */
    char		authname[AUTH_MAX_AUTHNAME];
    unsigned		vj:1;		/* FRAMED Compression */
    struct in_addr	ip;		/* FRAMED IP */
    struct in_addr	mask;	/* FRAMED Netmask */
    unsigned long	mtu;		/* FRAMED MTU */
    unsigned long	sessiontime;	/* Session-Timeout */
    char		*filterid;	/* FRAMED Filter Id */
    char		*mschapv2resp;	/* Response String for MSCHAPv2 */
    struct {
      int	policy;			/* MPPE_POLICY_* */
      int	types;			/* MPPE_TYPE_*BIT bitmask */
      u_char	recvkey[MPPE_KEY_LEN];
      size_t	recvkeylen;
      u_char	sendkey[MPPE_KEY_LEN];
      size_t	sendkeylen;
    }			mppe;
    struct radiusconf	conf;
  };

  struct chap_response {
    u_char	ident;
    u_char	response[CHAP_MAX_VAL];
  };

  struct mschap_response {
    u_char	ident;
    u_char	flags;
    u_char	lm_response[24];
    u_char	nt_response[24];
  };

  struct mschapv2_response {
    u_char	ident;
    u_char	flags;
    u_char	pchallenge[16];
    u_char	reserved[8];
    u_char	response[24];
  };

#endif
