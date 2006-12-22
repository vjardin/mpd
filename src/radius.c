/*
 * See ``COPYRIGHT.mpd''
 *
 * $Id$
 *
 */

#include "ppp.h"
#ifdef PHYSTYPE_PPPOE
#include "pppoe.h"
#endif
#ifdef PHYSTYPE_MODEM
#include "modem.h"
#endif
#ifdef PHYSTYPE_NG_SOCKET
#include "ng.h"
#endif
#include "msgdef.h"
#include "util.h"

#include <sys/types.h>

#include <radlib.h>
#include <radlib_vs.h>


/* Global variables */

  static int	RadiusSetCommand(int ac, char *av[], void *arg);
  static int	RadiusAddServer(AuthData auth, short request_type);
  static int	RadiusInit(AuthData auth, short request_type);
  static int	RadiusStart(AuthData auth, short request_type);  
  static int	RadiusPutAuth(AuthData auth);
  static int	RadiusGetParams(AuthData auth, int eap_proxy);
  static int	RadiusSendRequest(AuthData auth);

/* Set menu options */

  enum {
    SET_SERVER,
    SET_ME,
    SET_MEV6,
    SET_TIMEOUT,
    SET_RETRIES,
    SET_CONFIG,
    SET_ENABLE,
    SET_DISABLE,
  };

/*
 * GLOBAL VARIABLES
 */

  const struct cmdtab RadiusSetCmds[] = {
    { "server <name> <secret> [auth port] [acct port]", "Set radius server parameters" ,
	RadiusSetCommand, NULL, (void *) SET_SERVER },
    { "me <ip>",			"Set NAS IP address" ,
	RadiusSetCommand, NULL, (void *) SET_ME },
    { "v6me <ip>",			"Set NAS IPv6 address" ,
	RadiusSetCommand, NULL, (void *) SET_MEV6 },
    { "timeout <seconds>",		"Set timeout in seconds",
	RadiusSetCommand, NULL, (void *) SET_TIMEOUT },
    { "retries <# retries>",		"set number of retries",
	RadiusSetCommand, NULL, (void *) SET_RETRIES },
    { "config <path to radius.conf>",	"set path to config file for libradius",
	RadiusSetCommand, NULL, (void *) SET_CONFIG },
    { "enable [opt ...]",		"Enable option",
	RadiusSetCommand, NULL, (void *) SET_ENABLE },
    { "disable [opt ...]",		"Disable option",
	RadiusSetCommand, NULL, (void *) SET_DISABLE },
    { NULL },
  };

/*
 * INTERNAL VARIABLES
 */

  static struct confinfo	gConfList[] = {
    { 0,	RADIUS_CONF_MESSAGE_AUTHENTIC,	"message-authentic"	},
    { 0,	0,				NULL			},
  };

  
int
RadiusAuthenticate(AuthData auth) 
{
  Log(LG_RADIUS, ("[%s] RADIUS: %s for: %s", 
    auth->lnk->name, __func__, auth->params.authname));

  if (RadiusStart(auth, RAD_ACCESS_REQUEST) == RAD_NACK)
    return RAD_NACK;

  if (RadiusPutAuth(auth) == RAD_NACK)
    return RAD_NACK;
  
  if (RadiusSendRequest(auth) == RAD_NACK)
    return RAD_NACK;
  
  return RAD_ACK;
}

/*
 * RadiusEapProxy()
 *
 * paction handler for RADIUS EAP Proxy requests.
 * Thread-Safety is needed here
 * auth->status must be set to AUTH_STATUS_FAIL, if the 
 * request couldn't sent, because for EAP a successful
 * RADIUS request is mandatory
 */
 
void
RadiusEapProxy(void *arg)
{
  AuthData	auth = (AuthData)arg;
  Link		lnk = auth->lnk;	/* hide the global "lnk" */
  int		pos = 0, mlen = RAD_MAX_ATTR_LEN;

  if (RadiusStart(auth, RAD_ACCESS_REQUEST) == RAD_NACK) {
    auth->status = AUTH_STATUS_FAIL;  
    return;
  }

  if (rad_put_string(auth->radius.handle, RAD_USER_NAME, auth->params.authname) == -1) {
    Log(LG_RADIUS, ("[%s] RADIUS-EAP: %s: rad_put_string(RAD_USER_NAME) failed %s", 
      lnk->name, __func__, rad_strerror(auth->radius.handle)));
    auth->status = AUTH_STATUS_FAIL;    
    return;
  }

  for (pos = 0; pos <= auth->params.eapmsg_len; pos += RAD_MAX_ATTR_LEN) {
    char	chunk[RAD_MAX_ATTR_LEN];

    if (pos + RAD_MAX_ATTR_LEN > auth->params.eapmsg_len)
      mlen = auth->params.eapmsg_len - pos;

    memcpy(chunk, &auth->params.eapmsg[pos], mlen);
    if (rad_put_attr(auth->radius.handle, RAD_EAP_MESSAGE, chunk, mlen) == -1) {
      Log(LG_RADIUS, ("[%s] RADIUS-EAP: %s: rad_put_attr(RAD_EAP_MESSAGE) failed %s",
	lnk->name, __func__, rad_strerror(auth->radius.handle)));
      auth->status = AUTH_STATUS_FAIL;      
      return;
    }
#ifdef DEBUG
    Log(LG_RADIUS, ("[%s] RADIUS-EAP: chunk:%d len:%d",
      lnk->name, pos / RAD_MAX_ATTR_LEN, mlen));
#endif
  }

  if (RadiusSendRequest(auth) == RAD_NACK) {
    auth->status = AUTH_STATUS_FAIL;
    return;
  }

  return;
}

/*
 * RadiusAccount()
 *
 * Do RADIUS accounting
 * NOTE: thread-safety is needed here
 */
 
void 
RadiusAccount(AuthData auth) 
{
  char  *username;
  Link	const lnk = auth->lnk;		/* hide the global "lnk" */
  int	authentic;

  Log(LG_RADIUS, ("[%s] RADIUS: %s for: %s (Type: %d)", 
    lnk->name, __func__, auth->params.authname, auth->acct_type));

  if (auth->params.authentic == AUTH_CONF_RADIUS_AUTH) {
    authentic = RAD_AUTH_RADIUS;
  } else {
    authentic = RAD_AUTH_LOCAL;
  }

  /*
   * Suppress sending of accounting update, if byte threshold
   * is configured, and delta since last update doesn't exceed it.
   */
  if (auth->acct_type == AUTH_ACCT_UPDATE &&
      (auth->conf.acct_update_lim_recv > 0 ||
       auth->conf.acct_update_lim_xmit > 0)) {
    if (lnk->stats.recvOctets - lnk->stats.old_recvOctets <
        auth->conf.acct_update_lim_recv &&
        lnk->stats.xmitOctets - lnk->stats.old_xmitOctets <
        auth->conf.acct_update_lim_xmit) {
      Log(LG_RADIUS, ("[%s] RADIUS: %s: shouldn't send Interim-Update",
        lnk->name, __func__));
      return;
     } else {
	/* Save old statistics. */
	lnk->stats.old_recvOctets = lnk->stats.recvOctets;
	lnk->stats.old_xmitOctets = lnk->stats.xmitOctets;
     }
  }

  if (RadiusStart(auth, RAD_ACCOUNTING_REQUEST) == RAD_NACK)
    return;

  if (auth->acct_type == AUTH_ACCT_START) {
    Log(LG_RADIUS2, ("[%s] RADIUS: %s: rad_put_int(RAD_ACCT_STATUS_TYPE): RAD_START", 
      lnk->name, __func__));
    if (rad_put_int(auth->radius.handle, RAD_ACCT_STATUS_TYPE, RAD_START)) {
      Log(LG_RADIUS, ("[%s] RADIUS: %s: rad_put_int(STATUS_TYPE): %s", 
	lnk->name, __func__, rad_strerror(auth->radius.handle)));
      return;
    }
  }

  Log(LG_RADIUS2, ("[%s] RADIUS: %s: rad_put_addr(RAD_FRAMED_IP_ADDRESS): %s", 
    lnk->name, __func__, inet_ntoa(auth->info.peer_addr)));
  if (rad_put_addr(auth->radius.handle, RAD_FRAMED_IP_ADDRESS, auth->info.peer_addr)) {
    Log(LG_RADIUS, ("[%s] RADIUS: %s: rad_put_addr(RAD_FRAMED_IP_ADDRESS): %s", 
      lnk->name, __func__, rad_strerror(auth->radius.handle)));
    return;
  }

#if 0
  Log(LG_RADIUS2, ("[%s] RADIUS: %s: rad_put_addr(RAD_FRAMED_IP_NETMASK): %s", 
    lnk->name, __func__, inet_ntoa(ac->mask)));
  if (rad_put_addr(auth->radius.handle, RAD_FRAMED_IP_NETMASK, ac->mask) != 0) {
    Log(LG_RADIUS, ("[%s] RADIUS: %s: rad_put_addr(RAD_FRAMED_IP_NETMASK): %s",
      lnk->name, __func__, rad_strerror(auth->radius.handle)));
    return;
  }
#endif

  username = auth->params.authname;
  Log(LG_RADIUS2, ("[%s] RADIUS: %s: rad_put_string(RAD_USER_NAME): %s", 
    lnk->name, __func__, username));
  if (rad_put_string(auth->radius.handle, RAD_USER_NAME, username) != 0) {
    Log(LG_RADIUS, ("[%s] RADIUS: %s: rad_put_string(RAD_USER_NAME): %s", 
      lnk->name, __func__, rad_strerror(auth->radius.handle)));
    return;
  }

  Log(LG_RADIUS2, ("[%s] RADIUS: %s: rad_put_string(RAD_ACCT_SESSION_ID): %s", 
    lnk->name, __func__, lnk->session_id));
  Log(LG_RADIUS2, ("[%s] RADIUS: %s: rad_put_string(RAD_ACCT_MULTI_SESSION_ID): %s", 
    lnk->name, __func__, auth->info.session_id));
  if (rad_put_string(auth->radius.handle, RAD_ACCT_SESSION_ID, lnk->session_id) != 0 ||
      rad_put_string(auth->radius.handle, RAD_ACCT_MULTI_SESSION_ID, auth->info.session_id) != 0) {
    Log(LG_RADIUS, ("[%s] RADIUS: %s: put (SESSION_ID, MULTI_SESSION_ID): %s", 
      lnk->name, __func__, rad_strerror(auth->radius.handle)));
    return;
  }

  Log(LG_RADIUS2, ("[%s] RADIUS: %s: rad_put_int(RAD_ACCT_LINK_COUNT): %d", 
    lnk->name, __func__, auth->info.n_links));
  if (rad_put_int(auth->radius.handle, RAD_ACCT_LINK_COUNT, auth->info.n_links) != 0) {
    Log(LG_RADIUS, ("[%s] RADIUS: %s: rad_put_int(RAD_ACCT_LINK_COUNT) failed: %s", 
      lnk->name, __func__, rad_strerror(auth->radius.handle)));
    return;
  }

  Log(LG_RADIUS2, ("[%s] RADIUS: %s: rad_put_int(RAD_ACCT_AUTHENTIC): %d", 
    lnk->name, __func__, authentic));
  if (rad_put_int(auth->radius.handle, RAD_ACCT_AUTHENTIC, authentic) != 0) {
    Log(LG_RADIUS, ("[%s] RADIUS: %s: rad_put_int(RAD_ACCT_AUTHENTIC) failed: %s",
      lnk->name, __func__, rad_strerror(auth->radius.handle)));
    return;
  }

  if (auth->acct_type == AUTH_ACCT_STOP 
      || auth->acct_type == AUTH_ACCT_UPDATE) {

    if (auth->acct_type == AUTH_ACCT_STOP) {
      int	termCause = RAD_TERM_PORT_ERROR;

      Log(LG_RADIUS2, ("[%s] RADIUS: %s: rad_put_int(RAD_ACCT_STATUS_TYPE): RAD_STOP", 
	lnk->name, __func__));
      if (rad_put_int(auth->radius.handle, RAD_ACCT_STATUS_TYPE, RAD_STOP)) {
	Log(LG_RADIUS, ("[%s] RADIUS: %s: rad_put_int(RAD_ACCT_STATUS_TYPE): %s", 
	  lnk->name, __func__, rad_strerror(auth->radius.handle)));
	return;
      }

      if (lnk->downReason != NULL) {
	if (!strcmp(lnk->downReason, "")) {
	  termCause = RAD_TERM_NAS_REQUEST;
	} else if (!strncmp(lnk->downReason, STR_PEER_DISC, strlen(STR_PEER_DISC))) {
	  termCause = RAD_TERM_USER_REQUEST;
	} else if (!strncmp(lnk->downReason, STR_QUIT, strlen(STR_QUIT))) {
	  termCause = RAD_TERM_ADMIN_REBOOT;
	} else if (!strncmp(lnk->downReason, STR_PORT_SHUTDOWN, strlen(STR_PORT_SHUTDOWN))) {
	  termCause = RAD_TERM_NAS_REBOOT;
	} else if (!strncmp(lnk->downReason, STR_IDLE_TIMEOUT, strlen(STR_IDLE_TIMEOUT))) {
	  termCause = RAD_TERM_IDLE_TIMEOUT;
	} else if (!strncmp(lnk->downReason, STR_SESSION_TIMEOUT, strlen(STR_SESSION_TIMEOUT))) {
	  termCause = RAD_TERM_SESSION_TIMEOUT;
	} else if (!strncmp(lnk->downReason, STR_DROPPED, strlen(STR_DROPPED))) {
	  termCause = RAD_TERM_LOST_CARRIER;
	} else if (!strncmp(lnk->downReason, STR_ECHO_TIMEOUT, strlen(STR_ECHO_TIMEOUT))) {
	  termCause = RAD_TERM_LOST_SERVICE;
	} else if (!strncmp(lnk->downReason, STR_PROTO_ERR, strlen(STR_PROTO_ERR))) {
	  termCause = RAD_TERM_SERVICE_UNAVAILABLE;
	} else if (!strncmp(lnk->downReason, STR_LOGIN_FAIL, strlen(STR_LOGIN_FAIL))) {
	  termCause = RAD_TERM_USER_ERROR;
	};
	Log(LG_RADIUS, ("[%s] RADIUS: Termination cause: %s, RADIUS: %d",
	  lnk->name, lnk->downReason, termCause));
      }

      if (rad_put_int(auth->radius.handle, RAD_ACCT_TERMINATE_CAUSE, termCause) != 0) {
	Log(LG_RADIUS, ("[%s] RADIUS: %s: rad_put_int(RAD_ACCT_TERMINATE_CAUSE) failed: %s",
	  lnk->name, __func__, rad_strerror(auth->radius.handle)));
	return;
      } 
    } else {
      Log(LG_RADIUS2, ("[%s] RADIUS: %s: rad_put_int(RAD_ACCT_STATUS_TYPE): RAD_UPDATE", 
	lnk->name, __func__));
      if (rad_put_int(auth->radius.handle, RAD_ACCT_STATUS_TYPE, RAD_UPDATE)) {
	Log(LG_RADIUS, ("[%s] RADIUS: %s: rad_put_int(STATUS_TYPE): %s", 
	  lnk->name, __func__, rad_strerror(auth->radius.handle)));
	return;
      }
    }

    Log(LG_RADIUS2, ("[%s] RADIUS: %s: rad_put_int(RAD_ACCT_SESSION_TIME): %ld", 
      lnk->name, __func__, (long int)(time(NULL) - lnk->bm.last_open)));
    if (rad_put_int(auth->radius.handle, RAD_ACCT_SESSION_TIME, time(NULL) - lnk->bm.last_open) != 0) {
      Log(LG_RADIUS, ("[%s] RADIUS: %s: rad_put_int(RAD_ACCT_SESSION_TIME) failed: %s",
	lnk->name, __func__, rad_strerror(auth->radius.handle)));
      return;
    }

    Log(LG_RADIUS2, ("[%s] RADIUS: %s: rad_put_int(RAD_ACCT_INPUT_OCTETS): %lu", 
      lnk->name, __func__, (long unsigned int)(lnk->stats.recvOctets % MAX_U_INT32)));
    Log(LG_RADIUS2, ("[%s] RADIUS: %s: rad_put_int(RAD_ACCT_INPUT_PACKETS): %lu", 
      lnk->name, __func__, (long unsigned int)(lnk->stats.recvFrames)));
    Log(LG_RADIUS2, ("[%s] RADIUS: %s: rad_put_int(RAD_ACCT_OUTPUT_OCTETS): %lu", 
      lnk->name, __func__, (long unsigned int)(lnk->stats.xmitOctets % MAX_U_INT32)));
    Log(LG_RADIUS2, ("[%s] RADIUS: %s: rad_put_int(RAD_ACCT_OUTPUT_PACKETS): %lu", 
      lnk->name, __func__, (long unsigned int)(lnk->stats.xmitFrames)));
    Log(LG_RADIUS2, ("[%s] RADIUS: %s: rad_put_int(RAD_ACCT_INPUT_GIGAWORDS): %lu", 
      lnk->name, __func__, (long unsigned int)(lnk->stats.recvOctets / MAX_U_INT32)));
    Log(LG_RADIUS2, ("[%s] RADIUS: %s: rad_put_int(RAD_ACCT_OUTPUT_GIGAWORDS): %lu", 
      lnk->name, __func__, (long unsigned int)(lnk->stats.xmitOctets / MAX_U_INT32)));
    if (rad_put_int(auth->radius.handle, RAD_ACCT_INPUT_OCTETS, lnk->stats.recvOctets % MAX_U_INT32) != 0 ||
	rad_put_int(auth->radius.handle, RAD_ACCT_INPUT_PACKETS, lnk->stats.recvFrames) != 0 ||
	rad_put_int(auth->radius.handle, RAD_ACCT_OUTPUT_OCTETS, lnk->stats.xmitOctets % MAX_U_INT32) != 0 ||
	rad_put_int(auth->radius.handle, RAD_ACCT_OUTPUT_PACKETS, lnk->stats.xmitFrames) != 0 ||
	rad_put_int(auth->radius.handle, RAD_ACCT_INPUT_GIGAWORDS, lnk->stats.recvOctets / MAX_U_INT32) != 0 ||
	rad_put_int(auth->radius.handle, RAD_ACCT_OUTPUT_GIGAWORDS, lnk->stats.xmitOctets / MAX_U_INT32) != 0) {
      Log(LG_RADIUS, ("[%s] RADIUS: %s: put stats: %s", lnk->name, __func__,
	rad_strerror(auth->radius.handle)));
      return;
    }
  }

  Log(LG_RADIUS2, ("[%s] RADIUS: %s: Sending accounting data (Type: %d)",
    lnk->name, __func__, auth->acct_type));
  RadiusSendRequest(auth);

}

void
RadiusClose(AuthData auth) 
{
  if (auth->radius.handle != NULL)
    rad_close(auth->radius.handle);  
  auth->radius.handle = NULL;
}

int
RadStat(int ac, char *av[], void *arg)
{
  RadConf	const conf = &bund->conf.auth.radius;
  Auth		const a = &lnk->lcp.auth;
  int		i;
  char		*buf;
  RadServe_Conf	server;
  char		buf1[64];

  Printf("Configuration:\r\n");
  Printf("\tTimeout      : %d\r\n", conf->radius_timeout);
  Printf("\tRetries      : %d\r\n", conf->radius_retries);
  Printf("\tConfig-file  : %s\r\n", conf->file);
  Printf("\tMe (NAS-IP)  : %s\r\n", inet_ntoa(conf->radius_me));
  Printf("\tv6Me (NAS-IP): %s\r\n", u_addrtoa(&conf->radius_mev6, buf1, sizeof(buf1)));
  
  if (conf->server != NULL) {

    server = conf->server;
    i = 1;

    while (server) {
      Printf("\t---------------  Radius Server %d ---------------\r\n", i);
      Printf("\thostname   : %s\r\n", server->hostname);
      Printf("\tsecret     : *********\r\n");
      Printf("\tauth port  : %d\r\n", server->auth_port);
      Printf("\tacct port  : %d\r\n", server->acct_port);
      i++;
      server = server->next;
    }

  }

  Printf("RADIUS options\r\n");
  OptStat(&conf->options, gConfList);

  Printf("Data:\r\n");
  Printf("\tAuthenticated  : %s\r\n", a->params.authentic == AUTH_CONF_RADIUS_AUTH ? 
  	"yes" : "no");
  Printf("\tClass          : %ld\r\n", a->params.class);
  
  buf = Bin2Hex(a->params.state, a->params.state_len); 
  Printf("\tState          : %s\r\n", buf);
  Freee(MB_UTIL, buf);
  
  return (0);
}

static int
RadiusAddServer(AuthData auth, short request_type)
{
  int		i;
  RadConf	const c = &bund->conf.auth.radius;
  RadServe_Conf	s;

  if (c->server == NULL)
    return (RAD_ACK);

  s = c->server;
  i = 1;
  while (s) {

    Log(LG_RADIUS2, ("[%s] RADIUS: %s Adding %s", lnk->name, __func__, s->hostname));
    if (request_type == RAD_ACCESS_REQUEST) {
      if (rad_add_server (auth->radius.handle, s->hostname,
	s->auth_port,
	s->sharedsecret,
	c->radius_timeout,
	c->radius_retries) == -1) {
	  Log(LG_RADIUS, ("[%s] RADIUS: %s error: %s", lnk->name, __func__, 
	    rad_strerror(auth->radius.handle)));
	  return (RAD_NACK);
      }
    } else {
      if (rad_add_server (auth->radius.handle, s->hostname,
	s->acct_port,
	s->sharedsecret,
	c->radius_timeout,
	c->radius_retries) == -1) {
	  Log(LG_RADIUS, ("[%s] RADIUS: %s error: %s", lnk->name, __func__, 
	    rad_strerror(auth->radius.handle)));
	  return (RAD_NACK);
      }
    }

    s = s->next;
  }

  return (RAD_ACK);
}
  
/* Set menu options */
static int
RadiusSetCommand(int ac, char *av[], void *arg) 
{
  RadConf	const conf = &bund->conf.auth.radius;
  RadServe_Conf	server;
  RadServe_Conf	t_server;
  int		val, count;
  struct u_addr t;

  if (ac == 0)
      return(-1);

    switch ((int) arg) {

      case SET_SERVER:
	if (ac > 4 || ac < 2) {
	  return(-1);
	}

	count = 0;
	for ( t_server = conf->server ; t_server ;
	  t_server = t_server->next) {
	  count++;
	}
	if (count > RADIUS_MAX_SERVERS) {
	  Log(LG_RADIUS, ("[%s] %s: cannot configure more than %d servers",
	    lnk->name, __func__, RADIUS_MAX_SERVERS));
	  return (-1);
	}

	server = Malloc(MB_RADIUS, sizeof(*server));
	server->auth_port = 1812;
	server->acct_port = 1813;
	server->next = NULL;

	if (strlen(av[0]) > 255) {
	  Log(LG_ERR, ("RADIUS: Hostname too long. > 255 char."));
	  return(-1);
	}

	if (strlen(av[1]) > 127) {
	  Log(LG_ERR, ("RADIUS: Shared Secret too long. > 127 char."));
	  return(-1);
	}

	if (ac > 2 && atoi(av[2]) < 65535 && atoi(av[2]) > 1) {
	  server->auth_port = atoi (av[2]);

	} else if ( ac > 2 ) {
	  Log(LG_ERR, ("RADIUS: Auth Port number too high. > 65535"));
	  return(-1);
	}

	if (ac > 3 && atoi(av[3]) < 65535 && atoi(av[3]) > 1) {
	  server->acct_port = atoi (av[3]);
	} else if ( ac > 3 ) {
	  Log(LG_ERR, ("RADIUS: Acct Port number too high > 65535"));
	  return(-1);
	}

	server->hostname = Malloc(MB_RADIUS, strlen(av[0]) + 1);
	server->sharedsecret = Malloc(MB_RADIUS, strlen(av[1]) + 1);

	sprintf(server->hostname, "%s" , av[0]);
	sprintf(server->sharedsecret, "%s" , av[1]);

	if (conf->server != NULL)
	  server->next = conf->server;

	conf->server = server;

	break;

      case SET_ME:
        if (ParseAddr(*av, &t, ALLOW_IPV4)) {
	    u_addrtoin_addr(&t,&conf->radius_me);
	} else {
	    Log(LG_ERR, ("RADIUS: Bad NAS address '%s'.", *av));
	}
	break;

      case SET_MEV6:
        if (!ParseAddr(*av, &conf->radius_mev6, ALLOW_IPV6)) {
	    Log(LG_ERR, ("RADIUS: Bad NAS address '%s'.", *av));
	}
	break;

      case SET_TIMEOUT:
	val = atoi(*av);
	  if (val <= 0)
	    Log(LG_ERR, ("RADIUS: Timeout must be positive."));
	  else
	    conf->radius_timeout = val;
	break;

      case SET_RETRIES:
	val = atoi(*av);
	if (val <= 0)
	  Log(LG_ERR, ("RADIUS: Retries must be positive."));
	else
	  conf->radius_retries = val;
	break;

      case SET_CONFIG:
	if (strlen(av[0]) > PATH_MAX)
	  Log(LG_ERR, ("RADIUS: Config file name too long."));
	else
	  strcpy(conf->file, av[0]);
	break;

    case SET_ENABLE:
      EnableCommand(ac, av, &conf->options, gConfList);
      break;

    case SET_DISABLE:
      DisableCommand(ac, av, &conf->options, gConfList);
      break;

      default:
	assert(0);
    }

    return 0;
}

static int
RadiusInit(AuthData auth, short request_type)
{
  Link		lnk = auth->lnk;	/* hide the global "lnk" */
  RadConf 	const conf = &auth->conf.radius;

  if (request_type == RAD_ACCESS_REQUEST) {
  
    auth->radius.handle = rad_open();
    if (auth->radius.handle == NULL) {
      Log(LG_RADIUS, ("[%s] RADIUS: rad_open failed", lnk->name));
      return (RAD_NACK);
    }

  /* RAD_ACCOUNTING_REQUEST */
  } else {
  
    auth->radius.handle = rad_acct_open();
    if (auth->radius.handle == NULL) {
      Log(LG_RADIUS, ("[%s] RADIUS: rad_acct_open failed", lnk->name));
      return (RAD_NACK);
    }

  }
  
  if (strlen(conf->file)) {
    Log(LG_RADIUS2, ("[%s] RADIUS: using %s", lnk->name, conf->file));
    if (rad_config(auth->radius.handle, conf->file) != 0) {
      Log(LG_RADIUS, ("[%s] RADIUS: rad_config: %s", lnk->name, 
        rad_strerror(auth->radius.handle)));
      return (RAD_NACK);
    }
  }

  if (RadiusAddServer(auth, request_type) == RAD_NACK)
    return (RAD_NACK);
  
  return RAD_ACK;

}

static int 
GetLinkID(Link lnk) {
    int port, i;
    
    port =- 1;    
    for (i = 0; i < gNumLinks; i++) {
      if (gLinks[i] && !strcmp(gLinks[i]->name, lnk->name)) {
	port = i;
      }
    }
    return port;
};

static int
RadiusStart(AuthData auth, short request_type)
{
  Link		lnk = auth->lnk;	/* hide the global "lnk" */
  RadConf 	const conf = &auth->conf.radius;  
  char		host[MAXHOSTNAMELEN];
  int		porttype;
  char		buf[64];

  if (RadiusInit(auth, request_type) == RAD_NACK) 
    return RAD_NACK;

  if (rad_create_request(auth->radius.handle, request_type) == -1) {
    Log(LG_RADIUS, ("[%s] RADIUS: rad_create_request: %s", 
      lnk->name, rad_strerror(auth->radius.handle)));
    return (RAD_NACK);
  }

  if (gethostname(host, sizeof (host)) == -1) {
    Log(LG_RADIUS, ("[%s] RADIUS: %s: gethostname() failed", 
      lnk->name, __func__));
    return (RAD_NACK);
  }
  Log(LG_RADIUS2, ("[%s] RADIUS: %s: rad_put_string(RAD_NAS_IDENTIFIER): %s", 
    lnk->name, __func__, host));
  if (rad_put_string(auth->radius.handle, RAD_NAS_IDENTIFIER, host) == -1)  {
    Log(LG_RADIUS, ("[%s] RADIUS: %s: rad_put_string(RAD_NAS_IDENTIFIER) failed %s", lnk->name,
      __func__, rad_strerror(auth->radius.handle)));
    return (RAD_NACK);
  }
  
  if (conf->radius_me.s_addr != 0) {
    Log(LG_RADIUS2, ("[%s] RADIUS: %s: rad_put_addr(RAD_NAS_IP_ADDRESS): %s", 
      lnk->name, __func__, inet_ntoa(conf->radius_me)));
    if (rad_put_addr(auth->radius.handle, RAD_NAS_IP_ADDRESS, conf->radius_me) == -1) {
      Log(LG_RADIUS, ("[%s] RADIUS: %s: rad_put_addr(RAD_NAS_IP_ADDRESS) failed %s", 
	lnk->name, __func__, rad_strerror(auth->radius.handle)));
      return (RAD_NACK);
    }
  }

  if (!u_addrempty(&conf->radius_mev6)) {
    Log(LG_RADIUS2, ("[%s] RADIUS: %s: rad_put_addr(RAD_NAS_IPV6_ADDRESS): %s", 
      lnk->name, __func__, u_addrtoa(&conf->radius_mev6,buf,sizeof(buf))));
    if (rad_put_attr(auth->radius.handle, RAD_NAS_IPV6_ADDRESS, &conf->radius_mev6.u.ip6, sizeof(conf->radius_mev6.u.ip6)) == -1) {
      Log(LG_RADIUS, ("[%s] RADIUS: %s: rad_put_addr(RAD_NAS_IPV6_ADDRESS) failed %s", 
	lnk->name, __func__, rad_strerror(auth->radius.handle)));
      return (RAD_NACK);
    }
  }

#if (!defined(__FreeBSD__) || __FreeBSD_version >= 530000)
  /* Insert the Message Authenticator RFC 3579
   * If using EAP this is mandatory
   */
  if ((Enabled(&conf->options, RADIUS_CONF_MESSAGE_AUTHENTIC)
	|| auth->proto == PROTO_EAP)
	&& request_type != RAD_ACCOUNTING_REQUEST) {
    Log(LG_RADIUS2, ("[%s] RADIUS: Adding Message Authenticator", lnk->name));
    if (rad_put_message_authentic(auth->radius.handle) == -1) {
      Log(LG_RADIUS, ("[%s] RADIUS: %s: rad_put_message_authentic failed %s", 
        lnk->name, __func__, rad_strerror(auth->radius.handle)));
      return (RAD_NACK);
    }
  }
#endif

  Log(LG_RADIUS2, ("[%s] RADIUS: %s: rad_put_int(RAD_NAS_PORT): %d", 
    lnk->name, __func__, GetLinkID(lnk)));
  if (rad_put_int(auth->radius.handle, RAD_NAS_PORT, GetLinkID(lnk)) == -1)  {
    Log(LG_RADIUS, ("[%s] RADIUS: %s: rad_put_int(RAD_NAS_PORT) failed %s", 
      lnk->name, __func__, rad_strerror(auth->radius.handle)));
    return (RAD_NACK);
  }

#ifdef PHYSTYPE_MODEM
  if (lnk->phys->type == &gModemPhysType) {
    porttype = RAD_ASYNC;
  } else 
#endif
#ifdef PHYSTYPE_NG_SOCKET
  if (lnk->phys->type == &gNgPhysType) {
    porttype = RAD_SYNC;
  } else 
#endif
#ifdef PHYSTYPE_PPPOE
  if (lnk->phys->type == &gPppoePhysType) {
    porttype = RAD_ETHERNET;
  } else 
#endif
  {
    porttype = RAD_VIRTUAL;
  };
  Log(LG_RADIUS2, ("[%s] RADIUS: %s: rad_put_int(RAD_NAS_PORT_TYPE): %d", 
    lnk->name, __func__, porttype));
  if (rad_put_int(auth->radius.handle, RAD_NAS_PORT_TYPE, porttype) == -1) {
    Log(LG_RADIUS, ("[%s] RADIUS: %s: rad_put_int(RAD_NAS_PORT_TYPE) failed %s", 
      lnk->name, __func__, rad_strerror(auth->radius.handle)));
    return (RAD_NACK);
  }

  Log(LG_RADIUS2, ("[%s] RADIUS: %s: rad_put_int(RAD_SERVICE_TYPE): RAD_FRAMED", 
    lnk->name, __func__));
  if (rad_put_int(auth->radius.handle, RAD_SERVICE_TYPE, RAD_FRAMED) == -1) {
    Log(LG_RADIUS, ("[%s] RADIUS: %s: rad_put_int(RAD_SERVICE_TYPE) failed %s", 
      lnk->name, __func__, rad_strerror(auth->radius.handle)));
    return (RAD_NACK);
  }
  
  Log(LG_RADIUS2, ("[%s] RADIUS: %s: rad_put_int(RAD_FRAMED_PROTOCOL): RAD_PPP", 
    lnk->name, __func__));
  if (rad_put_int(auth->radius.handle, RAD_FRAMED_PROTOCOL, RAD_PPP) == -1) {
    Log(LG_RADIUS, ("[%s] RADIUS: %s: rad_put_int(RAD_FRAMED_PROTOCOL) failed %s", 
      lnk->name, __func__, rad_strerror(auth->radius.handle)));
    return (RAD_NACK);
  }

  if (auth->params.state != NULL) {
    Log(LG_RADIUS2, ("[%s] RADIUS: putting RAD_STATE", lnk->name));
    if (rad_put_attr(auth->radius.handle, RAD_STATE, auth->params.state, auth->params.state_len) == -1) {
      Log(LG_RADIUS, ("[%s] RADIUS: %s: rad_put_int(RAD_STATE) failed %s", 
        lnk->name, __func__, rad_strerror(auth->radius.handle)));
      return (RAD_NACK);
    }
  }

  if (strlen(auth->params.peeraddr)) {
    Log(LG_RADIUS2, ("[%s] RADIUS: %s: rad_put_string(RAD_CALLING_STATION_ID) %s", 
      lnk->name, __func__, auth->params.peeraddr));
    if (rad_put_string(auth->radius.handle, RAD_CALLING_STATION_ID, 
        auth->params.peeraddr) == -1) {
      Log(LG_RADIUS, ("[%s] RADIUS: %s: rad_put_string(RAD_CALLING_STATION_ID) failed %s", 
	lnk->name, __func__, rad_strerror(auth->radius.handle)));
      return (RAD_NACK);
    }  
  }
  return RAD_ACK;
}

static int 
RadiusPutAuth(AuthData auth)
{
  Link			lnk = auth->lnk;	/* hide the global "lnk" */
  ChapInfo		const chap = &lnk->lcp.auth.chap;
  PapInfo		const pap = &lnk->lcp.auth.pap;
  
  struct rad_chapvalue		rad_chapval;
  struct rad_mschapvalue	rad_mschapval;
  struct rad_mschapv2value	rad_mschapv2val;
  struct mschapvalue		*mschapval;
  struct mschapv2value		*mschapv2val;  

  if (rad_put_string(auth->radius.handle, RAD_USER_NAME, auth->params.authname) == -1) {
    Log(LG_RADIUS, ("[%s] RADIUS: %s: rad_put_string(username) failed %s", 
      lnk->name, __func__, rad_strerror(auth->radius.handle)));
    return (RAD_NACK);
  }

  if (auth->proto == PROTO_CHAP || auth->proto == PROTO_EAP) {
    switch (chap->recv_alg) {

      case CHAP_ALG_MSOFT:
	Log(LG_RADIUS2, ("[%s] RADIUS: %s: RADIUS_CHAP (MSOFTv1) peer name: %s", 
	  lnk->name, __func__, auth->params.authname));
	if (chap->value_len != 49) {
	  Log(LG_RADIUS, ("[%s] RADIUS: %s: RADIUS_CHAP (MSOFTv1) unrecognised key length %d/%d",
	    lnk->name, __func__, chap->value_len, 49));
	return RAD_NACK;
	}

	if (rad_put_vendor_attr(auth->radius.handle, RAD_VENDOR_MICROSOFT, RAD_MICROSOFT_MS_CHAP_CHALLENGE,
	    chap->chal_data, chap->chal_len) == -1)  {
	  Log(LG_RADIUS, ("[%s] RADIUS: %s: rad_put_vendor_attr(RAD_MICROSOFT_MS_CHAP_CHALLENGE) failed %s",
	    lnk->name, __func__, rad_strerror(auth->radius.handle)));
	  return (RAD_NACK);
	}

	mschapval = (struct mschapvalue *)chap->value;
	rad_mschapval.ident = auth->id;
	rad_mschapval.flags = 0x01;
	memcpy(rad_mschapval.lm_response, mschapval->lmHash, 24);
	memcpy(rad_mschapval.nt_response, mschapval->ntHash, 24);

	if (rad_put_vendor_attr(auth->radius.handle, RAD_VENDOR_MICROSOFT, RAD_MICROSOFT_MS_CHAP_RESPONSE,
	    &rad_mschapval, sizeof rad_mschapval) == -1)  {
	  Log(LG_RADIUS, ("[%s] RADIUS: %s: rad_put_vendor_attr(RAD_MICROSOFT_MS_CHAP_RESPONSE) failed %s",
	    lnk->name, __func__, rad_strerror(auth->radius.handle)));
	  return (RAD_NACK);
	}
	break;

      case CHAP_ALG_MSOFTv2:
      
	Log(LG_RADIUS2, ("[%s] RADIUS: %s: RADIUS_CHAP (MSOFTv2) peer name: %s",
	  lnk->name, __func__, auth->params.authname));
	if (rad_put_vendor_attr(auth->radius.handle, RAD_VENDOR_MICROSOFT,
	    RAD_MICROSOFT_MS_CHAP_CHALLENGE, chap->chal_data, chap->chal_len) == -1) {
	  Log(LG_RADIUS, ("[%s] RADIUS: %s: rad_put_vendor_attr(RAD_MICROSOFT_MS_CHAP_CHALLENGE) failed %s",
	    lnk->name, __func__, rad_strerror(auth->radius.handle)));
	  return (RAD_NACK);
	}

	if (chap->value_len != sizeof(*mschapv2val)) {
	  Log(LG_RADIUS, ("[%s] RADIUS: %s: RADIUS_CHAP (MSOFTv2) unrecognised key length %d/%d", lnk->name,
	    __func__, chap->value_len, sizeof(*mschapv2val)));
	  return RAD_NACK;
	}
      
	mschapv2val = (struct mschapv2value *)chap->value;
	rad_mschapv2val.ident = auth->id;
	rad_mschapv2val.flags = mschapv2val->flags;
	memcpy(rad_mschapv2val.response, mschapv2val->ntHash,
	  sizeof rad_mschapv2val.response);
	memset(rad_mschapv2val.reserved, '\0',
	  sizeof rad_mschapv2val.reserved);
	memcpy(rad_mschapv2val.pchallenge, mschapv2val->peerChal,
	  sizeof rad_mschapv2val.pchallenge);

	if (rad_put_vendor_attr(auth->radius.handle, RAD_VENDOR_MICROSOFT, RAD_MICROSOFT_MS_CHAP2_RESPONSE,
	    &rad_mschapv2val, sizeof rad_mschapv2val) == -1)  {
	  Log(LG_RADIUS, ("[%s] RADIUS: %s: rad_put_vendor_attr(RAD_MICROSOFT_MS_CHAP2_RESPONSE) failed %s",
	    lnk->name, __func__, rad_strerror(auth->radius.handle)));
	  return (RAD_NACK);
	}
	break;

      case CHAP_ALG_MD5:
	/* RADIUS requires the CHAP Ident in the first byte of the CHAP-Password */
	rad_chapval.ident = auth->id;
	memcpy(rad_chapval.response, chap->value, chap->value_len);
	Log(LG_RADIUS2, ("[%s] RADIUS: %s: RADIUS_CHAP (MD5) peer name: %s", 
	  lnk->name, __func__, auth->params.authname));
	if (rad_put_attr(auth->radius.handle, RAD_CHAP_PASSWORD, &rad_chapval, chap->value_len + 1) == -1 ||
	    rad_put_attr(auth->radius.handle, RAD_CHAP_CHALLENGE, chap->chal_data, chap->chal_len) == -1) {
	  Log(LG_RADIUS, ("[%s] RADIUS: %s: rad_put_string(password) failed %s",
	    lnk->name, __func__, rad_strerror(auth->radius.handle)));
	  return (RAD_NACK);
	}
	break;
      
      default:
	Log(LG_RADIUS, ("[%s] RADIUS: %s: RADIUS unkown CHAP ALG %d", 
	  lnk->name, __func__, chap->recv_alg));
	return (RAD_NACK);
    }
  } else if (auth->proto == PROTO_PAP) {
        
    Log(LG_RADIUS2, ("[%s] RADIUS: %s: RADIUS_PAP peer name: %s",
      lnk->name, __func__, auth->params.authname));
    if (rad_put_string(auth->radius.handle, RAD_USER_PASSWORD, pap->peer_pass) == -1) {
      Log(LG_RADIUS, ("[%s] RADIUS: %s: rad_put_string(password) failed %s", 
	lnk->name, __func__, rad_strerror(auth->radius.handle)));
      return (RAD_NACK);
    }
    
  } else {
    Log(LG_RADIUS, ("[%s] RADIUS: %s: RADIUS unkown Proto %d", 
      lnk->name, __func__, auth->proto));
    return (RAD_NACK);
  }
  
  return RAD_ACK;

}

static int 
RadiusSendRequest(AuthData auth)
{
  Link			const lnk = auth->lnk;	/* hide the global "lnk" */  
  struct timeval	timelimit;
  struct timeval	tv;
  int 			fd, n;

  Log(LG_RADIUS2, ("[%s] RADIUS: %s: username: %s", 
    lnk->name, __func__, auth->params.authname));
  n = rad_init_send_request(auth->radius.handle, &fd, &tv);
  if (n != 0) {
    Log(LG_RADIUS, ("[%s] RADIUS: rad_init_send_request failed: %d %s",
      lnk->name, n, rad_strerror(auth->radius.handle)));
     return RAD_NACK;
  }

  gettimeofday(&timelimit, NULL);
  timeradd(&tv, &timelimit, &timelimit);

  for ( ; ; ) {
    struct pollfd fds[1];

    fds[0].fd = fd;
    fds[0].events = POLLIN;
    fds[0].revents = 0;

    n = poll(fds,1,tv.tv_sec*1000+tv.tv_usec/1000);

    if (n == -1) {
      Log(LG_RADIUS, ("[%s] RADIUS: poll failed %s", lnk->name, 
        strerror(errno)));
      return RAD_NACK;
    }

    if ((fds[0].revents&POLLIN)!=POLLIN) {
      /* Compute a new timeout */
      gettimeofday(&tv, NULL);
      timersub(&timelimit, &tv, &tv);
      if (tv.tv_sec > 0 || (tv.tv_sec == 0 && tv.tv_usec > 0))
	/* Continue the select */
	continue;
    }

    Log(LG_RADIUS2, ("[%s] RADIUS: %s: username: %s trying", 
      lnk->name, __func__, auth->params.authname));
    n = rad_continue_send_request(auth->radius.handle, n, &fd, &tv);
    if (n != 0)
      break;

    gettimeofday(&timelimit, NULL);
    timeradd(&tv, &timelimit, &timelimit);
  }

  switch (n) {

    case RAD_ACCESS_ACCEPT:
      Log(LG_RADIUS, ("[%s] RADIUS: rec'd RAD_ACCESS_ACCEPT for user %s", 
        lnk->name, auth->params.authname));
      auth->status = AUTH_STATUS_SUCCESS;
      auth->params.authentic = AUTH_CONF_RADIUS_AUTH;
      break;

    case RAD_ACCESS_CHALLENGE:
      Log(LG_RADIUS, ("[%s] RADIUS: rec'd RAD_ACCESS_CHALLENGE for user %s", 
        lnk->name, auth->params.authname));
      break;

    case RAD_ACCESS_REJECT:
      Log(LG_RADIUS, ("[%s] RADIUS: rec'd RAD_ACCESS_REJECT for user %s", 
        lnk->name, auth->params.authname));
      auth->status = AUTH_STATUS_FAIL;
      break;

    case RAD_ACCOUNTING_RESPONSE:
      Log(LG_RADIUS, ("[%s] RADIUS: rec'd RAD_ACCOUNTING_RESPONSE for user %s", 
        lnk->name, auth->params.authname));
      return RAD_ACK;

    case -1:
      Log(LG_RADIUS, ("[%s] RADIUS: rad_send_request failed: %s", 
        lnk->name, rad_strerror(auth->radius.handle)));
      return(RAD_NACK);
      break;
      
    default:
      Log(LG_RADIUS, ("[%s] RADIUS: rad_send_request: unexpected return value: %d", 
        lnk->name, n));
      return(RAD_NACK);
  }

  RadiusGetParams(auth, n == RAD_ACCESS_CHALLENGE);
  return RAD_ACK;
}

static int
RadiusGetParams(AuthData auth, int eap_proxy)
{
  Link		lnk = auth->lnk;	/* hide the global "lnk" */
  ChapInfo	const chap = &lnk->lcp.auth.chap;
  int		res, i, j, tmpkey_len;
  size_t	len;
  const void	*data;
  u_int32_t	vendor;
  char		*route, *acl1, *acl2;
  u_char	*tmpkey, *tmpval;
  short		got_mppe_keys = FALSE;
  struct in_addr	ip;
  struct acl		**acls, *acls1;
  struct ifaceroute	r;
  struct u_range	range;

  Freee(MB_AUTH, auth->params.eapmsg);
  auth->params.eapmsg = NULL;
  
  while ((res = rad_get_attr(auth->radius.handle, &data, &len)) > 0) {

    switch (res) {

      case RAD_STATE:
	Log(LG_RADIUS2, ("[%s] RADIUS: %s: RAD_STATE", lnk->name, __func__));
	auth->params.state_len = len;
	if (auth->params.state != NULL)
	  Freee(MB_AUTH, auth->params.state);
	auth->params.state = Malloc(MB_AUTH, len);
	memcpy(auth->params.state, data, len);
	continue;

	/* libradius already checks the message-authenticator, so simply ignore it */
      case RAD_MESSAGE_AUTHENTIC:
	Log(LG_RADIUS, ("[%s] RADIUS: %s: RAD_MESSAGE_AUTHENTIC", lnk->name, __func__));
	continue;

      case RAD_EAP_MESSAGE:
	if (auth->params.eapmsg != NULL) {
	  char *tbuf;
#ifdef DEBUG
	  Log(LG_RADIUS2, ("[%s] RADIUS: %s: RAD_EAP_MESSAGE (continued) Len:%d",
	    lnk->name, __func__, auth->params.eapmsg_len + len));
#endif
	  tbuf = Malloc(MB_AUTH, auth->params.eapmsg_len + len);
	  memcpy(tbuf, auth->params.eapmsg, auth->params.eapmsg_len);
	  memcpy(&tbuf[auth->params.eapmsg_len], data, len);
	  auth->params.eapmsg_len += len;
	  Freee(MB_AUTH, auth->params.eapmsg);
	  auth->params.eapmsg = tbuf;
	} else {
	  Log(LG_RADIUS2, ("[%s] RADIUS: %s: RAD_EAP_MESSAGE", lnk->name, __func__));
	  auth->params.eapmsg = Malloc(MB_AUTH, len);
	  memcpy(auth->params.eapmsg, data, len);
	  auth->params.eapmsg_len = len;
	}
	continue;
    }

    if (!eap_proxy)
      switch (res) {

      case RAD_FRAMED_IP_ADDRESS:
        ip = rad_cvt_addr(data);
        Log(LG_RADIUS2, ("[%s] RADIUS: %s: RAD_FRAMED_IP_ADDRESS: %s ",
          lnk->name, __func__, inet_ntoa(ip)));
	  
	if (strcmp(inet_ntoa(ip), "255.255.255.255") == 0) {
	  /* the peer can choose an address */
	  Log(LG_RADIUS2, (" the peer can choose an address"));
	  ip.s_addr=0;
	  in_addrtou_range(&ip, 0, &auth->params.range);
	  auth->params.range_valid = 1;
	} else if (strcmp(inet_ntoa(ip), "255.255.255.254") == 0) {
	  /* we should choose the ip */
	  Log(LG_RADIUS2, (" we should choose an address"));
	  auth->params.range_valid = 0;
	} else {
	  /* or use IP from Radius-server */
	  in_addrtou_range(&ip, 32, &auth->params.range);
	  auth->params.range_valid = 1;
	}  
        break;

      case RAD_USER_NAME:
	tmpval = rad_cvt_string(data, len);
	/* copy it into the persistent data struct */
	strcpy(auth->params.authname, tmpval);
	free(tmpval);
	Log(LG_RADIUS2, ("[%s] RADIUS: %s: RAD_USER_NAME: %s ",
	  lnk->name, __func__, auth->params.authname));
        break;

      case RAD_FRAMED_IP_NETMASK:
	auth->params.mask = rad_cvt_addr(data);
	Log(LG_RADIUS2, ("[%s] RADIUS: %s: RAD_FRAMED_IP_NETMASK: %s ",
	  lnk->name, __func__, inet_ntoa(auth->params.mask)));
	break;

      case RAD_FRAMED_ROUTE:
	route = rad_cvt_string(data, len);
	Log(LG_RADIUS2, ("[%s] RADIUS: %s: RAD_FRAMED_ROUTE: %s ",
	  lnk->name, __func__, route));
	if (!ParseRange(route, &range, ALLOW_IPV4)) {
	  Log(LG_RADIUS, ("[%s] RADIUS: %s: RAD_FRAMED_ROUTE: Bad route \"%s\"", lnk->name, __func__, route));
	  free(route);
	  break;
	}
	free(route);
	r.dest=range;
	r.ok=0;
	j = 0;
	for (i = 0;i < auth->params.n_routes; i++) {
	  if (!u_rangecompare(&r.dest, &auth->params.routes[i].dest)) {
	    Log(LG_RADIUS, ("[%s] RADIUS: %s: Duplicate route", lnk->name, __func__));
	    j = 1;
	  }
	};
	if (j == 0)
	  auth->params.routes[auth->params.n_routes++] = r;
	break;

      case RAD_FRAMED_IPV6_ROUTE:
	route = rad_cvt_string(data, len);
	Log(LG_RADIUS2, ("[%s] RADIUS: %s: RAD_FRAMED_IPV6_ROUTE: %s ",
	  lnk->name, __func__, route));
	if (!ParseRange(route, &range, ALLOW_IPV6)) {
	  Log(LG_RADIUS, ("[%s] RADIUS: %s: RAD_FRAMED_IPV6_ROUTE: Bad route \"%s\"", lnk->name, __func__, route));
	  free(route);
	  break;
	}
	free(route);
	r.dest=range;
	r.ok=0;
	j = 0;
	for (i = 0;i < auth->params.n_routes; i++) {
	  if (!u_rangecompare(&r.dest, &auth->params.routes[i].dest)) {
	    Log(LG_RADIUS, ("[%s] RADIUS: %s: Duplicate route", lnk->name, __func__));
	    j = 1;
	  }
	};
	if (j == 0)
	  auth->params.routes[auth->params.n_routes++] = r;
	break;

      case RAD_SESSION_TIMEOUT:
        auth->params.session_timeout = rad_cvt_int(data);
        Log(LG_RADIUS2, ("[%s] RADIUS: %s: RAD_SESSION_TIMEOUT: %lu ",
          lnk->name, __func__, auth->params.session_timeout));
        break;

      case RAD_IDLE_TIMEOUT:
        auth->params.idle_timeout = rad_cvt_int(data);
        Log(LG_RADIUS2, ("[%s] RADIUS: %s: RAD_IDLE_TIMEOUT: %lu ",
          lnk->name, __func__, auth->params.idle_timeout));
        break;

     case RAD_ACCT_INTERIM_INTERVAL:
	auth->params.acct_update = rad_cvt_int(data);
        Log(LG_RADIUS2, ("[%s] RADIUS: %s: RAD_ACCT_INTERIM_INTERVAL: %lu ",
          lnk->name, __func__, auth->params.acct_update));
	break;

      case RAD_FRAMED_MTU:
	auth->params.mtu = rad_cvt_int(data);
	Log(LG_RADIUS2, ("[%s] RADIUS: %s: RAD_FRAMED_MTU: %lu ",
	  lnk->name, __func__, auth->params.mtu));
	if (auth->params.mtu < IFACE_MIN_MTU || auth->params.mtu > IFACE_MAX_MTU) {
	  Log(LG_RADIUS, ("[%s] RADIUS: %s: RAD_FRAMED_MTU: invalid MTU: %lu ",
	    lnk->name, __func__, auth->params.mtu));
	  auth->params.mtu = 0;
	  break;
	}
        break;

      case RAD_FRAMED_COMPRESSION:
	Log(LG_RADIUS2, ("[%s] RADIUS: %s: (RAD_FRAMED_COMPRESSION: %d)",
	  lnk->name, __func__, rad_cvt_int(data)));
        break;

      case RAD_FRAMED_PROTOCOL:
	Log(LG_RADIUS2, ("[%s] RADIUS: %s: (RAD_FRAMED_PROTOCOL: %d)",
	  lnk->name, __func__, rad_cvt_int(data)));
        break;

      case RAD_FRAMED_ROUTING:
	Log(LG_RADIUS2, ("[%s] RADIUS: %s: (RAD_FRAMED_ROUTING: %d)",
	  lnk->name, __func__, rad_cvt_int(data)));
        break;

      case RAD_FILTER_ID:
	tmpval = rad_cvt_string(data, len);
	Log(LG_RADIUS2, ("[%s] RADIUS: %s: (RAD_FILTER_ID: %s)",
	  lnk->name, __func__, tmpval));
	free(tmpval);
        break;

      case RAD_SERVICE_TYPE:
	Log(LG_RADIUS2, ("[%s] RADIUS: %s: (RAD_SERVICE_TYPE: %d)",
	  lnk->name, __func__, rad_cvt_int(data)));
        break;

      case RAD_CLASS:
	auth->params.class = rad_cvt_int(data);
	Log(LG_RADIUS2, ("[%s] RADIUS: %s: RAD_CLASS: %lu ",
	  lnk->name, __func__, auth->params.class));
        break;

      case RAD_REPLY_MESSAGE:
	tmpval = rad_cvt_string(data, len);
	Log(LG_RADIUS2, ("[%s] RADIUS: %s: RAD_REPLY_MESSAGE: %s ",
	  lnk->name, __func__, auth->reply_message));
	auth->reply_message = Malloc(MB_AUTH, len + 1);
	memcpy(auth->reply_message, tmpval, len + 1);
	free(tmpval);
        break;

      case RAD_VENDOR_SPECIFIC:
	if ((res = rad_get_vendor_attr(&vendor, &data, &len)) == -1) {
	  Log(LG_RADIUS, ("[%s] RADIUS: %s: rad_get_vendor_attr failed: %s ",
	    lnk->name, __func__, rad_strerror(auth->radius.handle)));
	  return RAD_NACK;
	}

	switch (vendor) {

	  case RAD_VENDOR_MICROSOFT:
	    switch (res) {

	      case RAD_MICROSOFT_MS_CHAP_ERROR:
		/* there is a nullbyte on the first pos, don't know why */
		if (((const char *)data)[0] == '\0') {
		  data = (const char *)data + 1;
		  len--;
		}
		tmpval = rad_cvt_string(data, len);
		auth->mschap_error = Malloc(MB_AUTH, len + 1);
		memcpy(auth->mschap_error, tmpval, len + 1);
		free(tmpval);

		Log(LG_RADIUS2, ("[%s] RADIUS: %s: MS-CHAP-Error: %s",
		  lnk->name, __func__, auth->mschap_error));
		break;

	      /* this was taken from userland ppp */
	      case RAD_MICROSOFT_MS_CHAP2_SUCCESS:
		if (len < 3 || ((const char *)data)[1] != '=') {
		  /*
		   * Only point at the String field if we don't think the
		   * peer has misformatted the response.
		   */
		  data = (const char *)data + 1;
		  len--;
		} else
		  Log(LG_RADIUS, ("[%s] RADIUS: %s: Warning: The MS-CHAP2-Success attribute is mis-formatted. Compensating",
		    lnk->name, __func__));
		  if ((tmpval = rad_cvt_string((const char *)data, len)) == NULL) {
		  Log(LG_RADIUS, ("[%s] RADIUS: %s: rad_cvt_string failed: %s",
		    lnk->name, __func__, rad_strerror(auth->radius.handle)));
		  return RAD_NACK;
		}
		auth->mschapv2resp = Malloc(MB_AUTH, len + 1);
		memcpy(auth->mschapv2resp, tmpval, len + 1);
		free(tmpval);
		Log(LG_RADIUS2, ("[%s] RADIUS: %s: RAD_MICROSOFT_MS_CHAP2_SUCCESS: %s",
		  lnk->name, __func__, auth->mschapv2resp));
		break;

	      case RAD_MICROSOFT_MS_CHAP_DOMAIN:
		Freee(MB_AUTH, auth->params.msdomain);
		tmpval = rad_cvt_string(data, len);
		auth->params.msdomain = Malloc(MB_AUTH, len + 1);
		memcpy(auth->params.msdomain, tmpval, len + 1);
		free(tmpval);
		Log(LG_RADIUS2, ("[%s] RADIUS: %s: RAD_MICROSOFT_MS_CHAP_DOMAIN: %s",
		  lnk->name, __func__, auth->params.msdomain));
		break;

#if (!defined(__FreeBSD__) || __FreeBSD_version >= 530000)
              /* MPPE Keys MS-CHAPv2 and EAP-TLS */
	      case RAD_MICROSOFT_MS_MPPE_RECV_KEY:
		got_mppe_keys = TRUE;
		Log(LG_RADIUS2, ("[%s] RADIUS: %s: RAD_MICROSOFT_MS_MPPE_RECV_KEY",
		  lnk->name, __func__));
		tmpkey = rad_demangle_mppe_key(auth->radius.handle, data, len, &tmpkey_len);
		if (!tmpkey) {
		  Log(LG_RADIUS, ("[%s] RADIUS: %s: rad_demangle_mppe_key failed: %s",
		    lnk->name, __func__, rad_strerror(auth->radius.handle)));
		  return RAD_NACK;
		}

		memcpy(auth->params.msoft.recv_key, tmpkey, MPPE_KEY_LEN);
		free(tmpkey);
		auth->params.msoft.has_keys = TRUE;
		break;

	      case RAD_MICROSOFT_MS_MPPE_SEND_KEY:
		got_mppe_keys = TRUE;
		Log(LG_RADIUS2, ("[%s] RADIUS: %s: RAD_MICROSOFT_MS_MPPE_SEND_KEY",
		  lnk->name, __func__));
		tmpkey = rad_demangle_mppe_key(auth->radius.handle, data, len, &tmpkey_len);
		if (!tmpkey) {
		  Log(LG_RADIUS, ("[%s] RADIUS: %s: rad_demangle_mppe_key failed: %s",
		    lnk->name, __func__, rad_strerror(auth->radius.handle)));
		  return RAD_NACK;
		}
		memcpy(auth->params.msoft.xmit_key, tmpkey, MPPE_KEY_LEN);
		free(tmpkey);
		auth->params.msoft.has_keys = TRUE;
		break;

              /* MPPE Keys MS-CHAPv1 */
	      case RAD_MICROSOFT_MS_CHAP_MPPE_KEYS:
		got_mppe_keys = TRUE;
		Log(LG_RADIUS2, ("[%s] RADIUS: %s: RAD_MICROSOFT_MS_CHAP_MPPE_KEYS",
		  lnk->name, __func__));

		if (len != 32) {
		  Log(LG_RADIUS, ("[%s] RADIUS: %s: Server returned garbage %d of expected %d Bytes",
		    lnk->name, __func__, len, 32));
		  return RAD_NACK;
		}

		tmpkey = rad_demangle(auth->radius.handle, data, len);
		if (tmpkey == NULL) {
		  Log(LG_RADIUS, ("[%s] RADIUS: %s: rad_demangle failed: %s",
		    lnk->name, __func__, rad_strerror(auth->radius.handle)));
		  return RAD_NACK;
		}
		memcpy(auth->params.msoft.lm_hash, tmpkey, sizeof(auth->params.msoft.lm_hash));
		auth->params.msoft.has_lm_hash = TRUE;
		memcpy(auth->params.msoft.nt_hash_hash, &tmpkey[8], sizeof(auth->params.msoft.nt_hash_hash));
		free(tmpkey);
		break;
#endif

	      case RAD_MICROSOFT_MS_MPPE_ENCRYPTION_POLICY:
		auth->params.msoft.policy = rad_cvt_int(data);
		Log(LG_RADIUS2, ("[%s] RADIUS: %s: RAD_MICROSOFT_MS_MPPE_ENCRYPTION_POLICY: %d (%s)",
		  lnk->name, __func__, auth->params.msoft.policy, AuthMPPEPolicyname(auth->params.msoft.policy)));
		break;

	      case RAD_MICROSOFT_MS_MPPE_ENCRYPTION_TYPES:
		auth->params.msoft.types = rad_cvt_int(data);
		Log(LG_RADIUS2, ("[%s] RADIUS: %s: RAD_MICROSOFT_MS_MPPE_ENCRYPTION_TYPES: %d (%s)",
		  lnk->name, __func__, auth->params.msoft.types, AuthMPPETypesname(auth->params.msoft.types)));
		break;

	      default:
		Log(LG_RADIUS2, ("[%s] RADIUS: %s: Dropping MICROSOFT vendor specific attribute: %d ",
		  lnk->name, __func__, res));
		break;
	    }
	    break;

	  case RAD_VENDOR_MPD:

	    if (res == RAD_MPD_RULE) {
	      acl2 = rad_cvt_string(data, len);
	      Log(LG_RADIUS2, ("[%s] RADIUS: %s: RAD_MPD_RULE: %s",
		lnk->name, __func__, acl2));
	      acls = &(auth->params.acl_rule);
	    } else if (res == RAD_MPD_PIPE) {
	      acl2 = rad_cvt_string(data, len);
	      Log(LG_RADIUS2, ("[%s] RADIUS: %s: RAD_MPD_PIPE: %s",
	        lnk->name, __func__, acl2));
	      acls = &(auth->params.acl_pipe);
	    } else if (res == RAD_MPD_QUEUE) {
	      acl2 = rad_cvt_string(data, len);
	      Log(LG_RADIUS2, ("[%s] RADIUS: %s: RAD_MPD_QUEUE: %s",
	        lnk->name, __func__, acl2));
	      acls = &(auth->params.acl_queue);
	    } else if (res == RAD_MPD_TABLE) {
	      acl2 = rad_cvt_string(data, len);
	      Log(LG_RADIUS2, ("[%s] RADIUS: %s: RAD_MPD_TABLS: %s",
	        lnk->name, __func__, acl2));
	      acls = &(auth->params.acl_table);
	    } else if (res == RAD_MPD_TABLE_STATIC) {
	      acl2 = rad_cvt_string(data, len);
	      Log(LG_RADIUS2, ("[%s] RADIUS: %s: RAD_MPD_TABLS_STATIC: %s",
	        lnk->name, __func__, acl2));
	      acls = &(auth->params.acl_table);
	    } else {
	      Log(LG_RADIUS2, ("[%s] RADIUS: %s: Dropping MPD vendor specific attribute: %d ",
		lnk->name, __func__, res));
	      break;
	    }

	    acl1 = strsep(&acl2, "=");
	    i = atol(acl1);
	    if (i <= 0) {
	      Log(LG_RADIUS, ("[%s] RADIUS: %s: wrong acl number: %i",
		lnk->name, __func__, i));
	      free(acl1);
	      break;
	    }
	    if ((acl2 == NULL) && (acl2[0] == 0)) {
	      Log(LG_RADIUS, ("[%s] RADIUS: %s: wrong acl", lnk->name, __func__));
	      free(acl1);
	      break;
	    }
	    acls1 = Malloc(MB_AUTH, sizeof(struct acl));
	    if (res != RAD_MPD_TABLE_STATIC) {
		    acls1->number = i;
		    acls1->real_number = 0;
	    } else {
		    acls1->number = 0;
		    acls1->real_number = i;
	    }
	    strncpy(acls1->rule, acl2, ACL_LEN);
	    while ((*acls != NULL) && ((*acls)->number < acls1->number))
	      acls = &((*acls)->next);

	    if (*acls == NULL) {
	      acls1->next = NULL;
	    } else if (((*acls)->number == acls1->number) &&
		(res != RAD_MPD_TABLE) &&
		(res != RAD_MPD_TABLE_STATIC)) {
	      Log(LG_RADIUS, ("[%s] RADIUS: %s: duplicate acl",
		lnk->name, __func__));
	      free(acl1);
	      break;
	    } else {
	      acls1->next = *acls;
	    }
	    *acls = acls1;

	    free(acl1);
	    break;

	  default:
	    Log(LG_RADIUS2, ("[%s] RADIUS: %s: Dropping vendor %d  attribute: %d ", 
	      lnk->name, __func__, vendor, res));
	    break;
	}
	break;

      default:
	Log(LG_RADIUS2, ("[%s] RADIUS: %s: Dropping attribute: %d ", 
	  lnk->name, __func__, res));
	break;
    }
  }

  /* sanity check, this happens when FreeRADIUS has no msoft-dictionary loaded */
  if (auth->proto == PROTO_CHAP && chap->recv_alg == CHAP_ALG_MSOFTv2
    && auth->mschapv2resp == NULL && auth->mschap_error == NULL) {
    Log(LG_RADIUS, ("[%s] RADIUS: %s: PANIC no MS-CHAPv2 response received",
      lnk->name, __func__));
    return RAD_NACK;
  }
  
  /* MPPE allowed or required, but no MPPE keys returned */
  /* print warning, because MPPE doesen't work */
  if (!got_mppe_keys && auth->params.msoft.policy != MPPE_POLICY_NONE) {
    Log(LG_RADIUS, ("[%s] RADIUS: %s: WARNING no MPPE-Keys received, MPPE will not work",
      lnk->name, __func__));
  }

  /* If no MPPE-Infos are returned by the RADIUS server, then allow all */
  /* MSoft IAS sends no Infos if all MPPE-Types are enabled and if encryption is optional */
  if (auth->params.msoft.policy == MPPE_POLICY_NONE &&
      auth->params.msoft.types == MPPE_TYPE_0BIT &&
      got_mppe_keys) {
    auth->params.msoft.policy = MPPE_POLICY_ALLOWED;
    auth->params.msoft.types = MPPE_TYPE_40BIT | MPPE_TYPE_128BIT | MPPE_TYPE_56BIT;
    Log(LG_RADIUS, ("[%s] RADIUS: %s: MPPE-Keys, but no MPPE-Infos received => allowing MPPE with all types",
      lnk->name, __func__));
  }
  
  return RAD_ACK;
}


