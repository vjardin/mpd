
/*
 * web.h
 *
 * Written by Alexander Motin <mav@FreeBSD.org>
 */

#ifndef _WEB_H_
#define	_WEB_H_

#include "defs.h"
#include <openssl/ssl.h>
#include <pdel/http/http_defs.h>
#include <pdel/http/http_server.h>
#include <pdel/http/http_servlet.h>
#include <pdel/http/servlet/basicauth.h>

/*
 * DEFINITIONS
 */

  /* Configuration options */
  enum {
    WEB_AUTH,	/* enable auth */
  };

  struct web {
    struct optinfo	options;
    struct u_addr 	addr;
    in_port_t		port;
    struct http_server *srv;
    struct http_servlet srvlet;
    struct http_servlet *srvlet_auth;
    struct ghash	*users;		/* allowed users */
    EventRef		event;		/* connect-event */
  };

  typedef struct web *Web;

  struct web_user {
    char	*username;
    char	*password;
  };

  typedef struct web_user *WebUser;

/*
 * VARIABLES
 */

  extern const struct cmdtab WebSetCmds[];


/*
 * FUNCTIONS
 */

  extern int	WebInit(Web c);
  extern int	WebOpen(Web c);
  extern int	WebClose(Web c);
  extern int	WebStat(Context ctx, int ac, char *av[], void *arg);


#endif

