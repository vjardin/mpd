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
#include "util.h"

#include <sys/types.h>

#include <radlib.h>
#include <radlib_vs.h>


/* Global variables */

  static int	RadiusSetCommand(Context ctx, int ac, char *av[], void *arg);
  static int	RadiusAddServer(AuthData auth, short request_type);
  static int	RadiusOpen(AuthData auth, short request_type);
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
    { "server {name} {secret} [{auth port}] [{acct port}]", "Set radius server parameters" ,
	RadiusSetCommand, NULL, 2, (void *) SET_SERVER },
    { "me {ip}",			"Set NAS IP address" ,
	RadiusSetCommand, NULL, 2, (void *) SET_ME },
    { "v6me {ip}",			"Set NAS IPv6 address" ,
	RadiusSetCommand, NULL, 2, (void *) SET_MEV6 },
    { "timeout {seconds}",		"Set timeout in seconds",
	RadiusSetCommand, NULL, 2, (void *) SET_TIMEOUT },
    { "retries {# retries}",		"set number of retries",
	RadiusSetCommand, NULL, 2, (void *) SET_RETRIES },
    { "config {path to radius.conf}",	"set path to config file for libradius",
	RadiusSetCommand, NULL, 2, (void *) SET_CONFIG },
    { "enable [opt ...]",		"Enable option",
	RadiusSetCommand, NULL, 2, (void *) SET_ENABLE },
    { "disable [opt ...]",		"Disable option",
	RadiusSetCommand, NULL, 2, (void *) SET_DISABLE },
    { NULL },
  };

/*
 * INTERNAL VARIABLES
 */

  static struct confinfo	gConfList[] = {
    { 0,	RADIUS_CONF_MESSAGE_AUTHENTIC,	"message-authentic"	},
    { 0,	RADIUS_CONF_PEER_AS_CALLING,	"peer-as-calling"	},
    { 0,	0,				NULL			},
  };

/*
 * RadiusInit()
 */

void
RadiusInit(Link l)
{
    RadConf       const conf = &l->lcp.auth.conf.radius;

    memset(conf, 0, sizeof(*conf));
    Enable(&conf->options, RADIUS_CONF_PEER_AS_CALLING);
    conf->radius_retries = 3;
    conf->radius_timeout = 5;
}

int
RadiusAuthenticate(AuthData auth) 
{
    Log(LG_RADIUS, ("[%s] RADIUS: %s for: %s", 
	auth->info.lnkname, __func__, auth->params.authname));

    if ((RadiusStart(auth, RAD_ACCESS_REQUEST) == RAD_NACK) ||
	(RadiusPutAuth(auth) == RAD_NACK) ||
	(RadiusSendRequest(auth) == RAD_NACK)) {
	    return RAD_NACK;
    }
  
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
  int		pos = 0, mlen = RAD_MAX_ATTR_LEN;

  if (RadiusStart(auth, RAD_ACCESS_REQUEST) == RAD_NACK) {
    auth->status = AUTH_STATUS_FAIL;  
    return;
  }

  if (rad_put_string(auth->radius.handle, RAD_USER_NAME, auth->params.authname) == -1) {
    Log(LG_RADIUS, ("[%s] RADIUS-EAP: %s: rad_put_string(RAD_USER_NAME) failed %s", 
      auth->info.lnkname, __func__, rad_strerror(auth->radius.handle)));
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
	auth->info.lnkname, __func__, rad_strerror(auth->radius.handle)));
      auth->status = AUTH_STATUS_FAIL;      
      return;
    }
#ifdef DEBUG
    Log(LG_RADIUS, ("[%s] RADIUS-EAP: chunk:%d len:%d",
      auth->info.lnkname, pos / RAD_MAX_ATTR_LEN, mlen));
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
  int	authentic;

  Log(LG_RADIUS, ("[%s] RADIUS: %s for: %s (Type: %d)", 
    auth->info.lnkname, __func__, auth->params.authname, auth->acct_type));

  if (auth->params.authentic == AUTH_CONF_RADIUS_AUTH) {
    authentic = RAD_AUTH_RADIUS;
  } else {
    authentic = RAD_AUTH_LOCAL;
  }

  if (RadiusStart(auth, RAD_ACCOUNTING_REQUEST) == RAD_NACK)
    return;

  if (auth->acct_type == AUTH_ACCT_START) {
    Log(LG_RADIUS2, ("[%s] RADIUS: %s: rad_put_int(RAD_ACCT_STATUS_TYPE): RAD_START", 
      auth->info.lnkname, __func__));
    if (rad_put_int(auth->radius.handle, RAD_ACCT_STATUS_TYPE, RAD_START)) {
      Log(LG_RADIUS, ("[%s] RADIUS: %s: rad_put_int(STATUS_TYPE): %s", 
	auth->info.lnkname, __func__, rad_strerror(auth->radius.handle)));
      return;
    }
  }

  Log(LG_RADIUS2, ("[%s] RADIUS: %s: rad_put_addr(RAD_FRAMED_IP_ADDRESS): %s", 
    auth->info.lnkname, __func__, inet_ntoa(auth->info.peer_addr)));
  if (rad_put_addr(auth->radius.handle, RAD_FRAMED_IP_ADDRESS, auth->info.peer_addr)) {
    Log(LG_RADIUS, ("[%s] RADIUS: %s: rad_put_addr(RAD_FRAMED_IP_ADDRESS): %s", 
      auth->info.lnkname, __func__, rad_strerror(auth->radius.handle)));
    return;
  }

  if (auth->params.netmask != 0) {
    struct in_addr	ip;
    widthtoin_addr(auth->params.netmask, &ip);
    Log(LG_RADIUS2, ("[%s] RADIUS: %s: rad_put_addr(RAD_FRAMED_IP_NETMASK): %s", 
	auth->info.lnkname, __func__, inet_ntoa(ip)));
    if (rad_put_addr(auth->radius.handle, RAD_FRAMED_IP_NETMASK, ip)) {
	Log(LG_RADIUS, ("[%s] RADIUS: %s: rad_put_addr(RAD_FRAMED_IP_NETMASK): %s", 
    	    auth->info.lnkname, __func__, rad_strerror(auth->radius.handle)));
	return;
    }
  }

#if 0
  Log(LG_RADIUS2, ("[%s] RADIUS: %s: rad_put_addr(RAD_FRAMED_IP_NETMASK): %s", 
    auth->info.lnkname, __func__, inet_ntoa(ac->mask)));
  if (rad_put_addr(auth->radius.handle, RAD_FRAMED_IP_NETMASK, ac->mask) != 0) {
    Log(LG_RADIUS, ("[%s] RADIUS: %s: rad_put_addr(RAD_FRAMED_IP_NETMASK): %s",
      auth->info.lnkname, __func__, rad_strerror(auth->radius.handle)));
    return;
  }
#endif

  username = auth->params.authname;
  Log(LG_RADIUS2, ("[%s] RADIUS: %s: rad_put_string(RAD_USER_NAME): %s", 
    auth->info.lnkname, __func__, username));
  if (rad_put_string(auth->radius.handle, RAD_USER_NAME, username) != 0) {
    Log(LG_RADIUS, ("[%s] RADIUS: %s: rad_put_string(RAD_USER_NAME): %s", 
      auth->info.lnkname, __func__, rad_strerror(auth->radius.handle)));
    return;
  }

  Log(LG_RADIUS2, ("[%s] RADIUS: %s: rad_put_string(RAD_ACCT_MULTI_SESSION_ID): %s", 
    auth->info.lnkname, __func__, auth->info.msession_id));
  if (rad_put_string(auth->radius.handle, RAD_ACCT_MULTI_SESSION_ID, auth->info.msession_id) != 0) {
    Log(LG_RADIUS, ("[%s] RADIUS: %s: put (RAD_ACCT_MULTI_SESSION_ID): %s", 
      auth->info.lnkname, __func__, rad_strerror(auth->radius.handle)));
    return;
  }

  Log(LG_RADIUS2, ("[%s] RADIUS: %s: rad_put_int(RAD_ACCT_LINK_COUNT): %d", 
    auth->info.lnkname, __func__, auth->info.n_links));
  if (rad_put_int(auth->radius.handle, RAD_ACCT_LINK_COUNT, auth->info.n_links) != 0) {
    Log(LG_RADIUS, ("[%s] RADIUS: %s: rad_put_int(RAD_ACCT_LINK_COUNT) failed: %s", 
      auth->info.lnkname, __func__, rad_strerror(auth->radius.handle)));
    return;
  }

  Log(LG_RADIUS2, ("[%s] RADIUS: %s: rad_put_int(RAD_ACCT_AUTHENTIC): %d", 
    auth->info.lnkname, __func__, authentic));
  if (rad_put_int(auth->radius.handle, RAD_ACCT_AUTHENTIC, authentic) != 0) {
    Log(LG_RADIUS, ("[%s] RADIUS: %s: rad_put_int(RAD_ACCT_AUTHENTIC) failed: %s",
      auth->info.lnkname, __func__, rad_strerror(auth->radius.handle)));
    return;
  }

  if (auth->acct_type == AUTH_ACCT_STOP 
      || auth->acct_type == AUTH_ACCT_UPDATE) {
    struct svcstatrec *ssr;

    if (auth->acct_type == AUTH_ACCT_STOP) {
        int	termCause = RAD_TERM_PORT_ERROR;

        Log(LG_RADIUS2, ("[%s] RADIUS: %s: rad_put_int(RAD_ACCT_STATUS_TYPE): RAD_STOP", 
	    auth->info.lnkname, __func__));
        if (rad_put_int(auth->radius.handle, RAD_ACCT_STATUS_TYPE, RAD_STOP)) {
	    Log(LG_RADIUS, ("[%s] RADIUS: %s: rad_put_int(RAD_ACCT_STATUS_TYPE): %s", 
		auth->info.lnkname, __func__, rad_strerror(auth->radius.handle)));
	    return;
        }

	if ((auth->info.downReason == NULL) || (!strcmp(auth->info.downReason, ""))) {
	  termCause = RAD_TERM_NAS_REQUEST;
	} else if (!strncmp(auth->info.downReason, STR_MANUALLY, strlen(STR_MANUALLY))) {
	  termCause = RAD_TERM_ADMIN_RESET;
	} else if (!strncmp(auth->info.downReason, STR_PEER_DISC, strlen(STR_PEER_DISC))) {
	  termCause = RAD_TERM_USER_REQUEST;
	} else if (!strncmp(auth->info.downReason, STR_ADMIN_SHUTDOWN, strlen(STR_ADMIN_SHUTDOWN))) {
	  termCause = RAD_TERM_ADMIN_REBOOT;
	} else if (!strncmp(auth->info.downReason, STR_FATAL_SHUTDOWN, strlen(STR_FATAL_SHUTDOWN))) {
	  termCause = RAD_TERM_NAS_REBOOT;
	} else if (!strncmp(auth->info.downReason, STR_IDLE_TIMEOUT, strlen(STR_IDLE_TIMEOUT))) {
	  termCause = RAD_TERM_IDLE_TIMEOUT;
	} else if (!strncmp(auth->info.downReason, STR_SESSION_TIMEOUT, strlen(STR_SESSION_TIMEOUT))) {
	  termCause = RAD_TERM_SESSION_TIMEOUT;
	} else if (!strncmp(auth->info.downReason, STR_DROPPED, strlen(STR_DROPPED))) {
	  termCause = RAD_TERM_LOST_CARRIER;
	} else if (!strncmp(auth->info.downReason, STR_ECHO_TIMEOUT, strlen(STR_ECHO_TIMEOUT))) {
	  termCause = RAD_TERM_LOST_SERVICE;
	} else if (!strncmp(auth->info.downReason, STR_PROTO_ERR, strlen(STR_PROTO_ERR))) {
	  termCause = RAD_TERM_SERVICE_UNAVAILABLE;
	} else if (!strncmp(auth->info.downReason, STR_LOGIN_FAIL, strlen(STR_LOGIN_FAIL))) {
	  termCause = RAD_TERM_USER_ERROR;
	} else if (!strncmp(auth->info.downReason, STR_PORT_UNNEEDED, strlen(STR_PORT_UNNEEDED))) {
	  termCause = RAD_TERM_PORT_UNNEEDED;
	};
	Log(LG_RADIUS, ("[%s] RADIUS: Termination cause: %s, RADIUS: %d",
	  auth->info.lnkname, auth->info.downReason, termCause));

        if (rad_put_int(auth->radius.handle, RAD_ACCT_TERMINATE_CAUSE, termCause) != 0) {
	    Log(LG_RADIUS, ("[%s] RADIUS: %s: rad_put_int(RAD_ACCT_TERMINATE_CAUSE) failed: %s",
		auth->info.lnkname, __func__, rad_strerror(auth->radius.handle)));
	    return;
        } 
    } else {
      Log(LG_RADIUS2, ("[%s] RADIUS: %s: rad_put_int(RAD_ACCT_STATUS_TYPE): RAD_UPDATE", 
	auth->info.lnkname, __func__));
      if (rad_put_int(auth->radius.handle, RAD_ACCT_STATUS_TYPE, RAD_UPDATE)) {
	Log(LG_RADIUS, ("[%s] RADIUS: %s: rad_put_int(STATUS_TYPE): %s", 
	  auth->info.lnkname, __func__, rad_strerror(auth->radius.handle)));
	return;
      }
    }

    Log(LG_RADIUS2, ("[%s] RADIUS: %s: rad_put_int(RAD_ACCT_SESSION_TIME): %ld", 
      auth->info.lnkname, __func__, (long int)(time(NULL) - auth->info.last_open)));
    if (rad_put_int(auth->radius.handle, RAD_ACCT_SESSION_TIME, time(NULL) - auth->info.last_open) != 0) {
      Log(LG_RADIUS, ("[%s] RADIUS: %s: rad_put_int(RAD_ACCT_SESSION_TIME) failed: %s",
	auth->info.lnkname, __func__, rad_strerror(auth->radius.handle)));
      return;
    }

    Log(LG_RADIUS2, ("[%s] RADIUS: %s: rad_put_int(RAD_ACCT_INPUT_OCTETS): %lu", 
      auth->info.lnkname, __func__, (long unsigned int)(auth->info.stats.recvOctets % MAX_U_INT32)));
    Log(LG_RADIUS2, ("[%s] RADIUS: %s: rad_put_int(RAD_ACCT_INPUT_PACKETS): %lu", 
      auth->info.lnkname, __func__, (long unsigned int)(auth->info.stats.recvFrames)));
    Log(LG_RADIUS2, ("[%s] RADIUS: %s: rad_put_int(RAD_ACCT_OUTPUT_OCTETS): %lu", 
      auth->info.lnkname, __func__, (long unsigned int)(auth->info.stats.xmitOctets % MAX_U_INT32)));
    Log(LG_RADIUS2, ("[%s] RADIUS: %s: rad_put_int(RAD_ACCT_OUTPUT_PACKETS): %lu", 
      auth->info.lnkname, __func__, (long unsigned int)(auth->info.stats.xmitFrames)));
    Log(LG_RADIUS2, ("[%s] RADIUS: %s: rad_put_int(RAD_ACCT_INPUT_GIGAWORDS): %lu", 
      auth->info.lnkname, __func__, (long unsigned int)(auth->info.stats.recvOctets / MAX_U_INT32)));
    Log(LG_RADIUS2, ("[%s] RADIUS: %s: rad_put_int(RAD_ACCT_OUTPUT_GIGAWORDS): %lu", 
      auth->info.lnkname, __func__, (long unsigned int)(auth->info.stats.xmitOctets / MAX_U_INT32)));
    if (rad_put_int(auth->radius.handle, RAD_ACCT_INPUT_OCTETS, auth->info.stats.recvOctets % MAX_U_INT32) != 0 ||
	rad_put_int(auth->radius.handle, RAD_ACCT_INPUT_PACKETS, auth->info.stats.recvFrames) != 0 ||
	rad_put_int(auth->radius.handle, RAD_ACCT_OUTPUT_OCTETS, auth->info.stats.xmitOctets % MAX_U_INT32) != 0 ||
	rad_put_int(auth->radius.handle, RAD_ACCT_OUTPUT_PACKETS, auth->info.stats.xmitFrames) != 0 ||
	rad_put_int(auth->radius.handle, RAD_ACCT_INPUT_GIGAWORDS, auth->info.stats.recvOctets / MAX_U_INT32) != 0 ||
	rad_put_int(auth->radius.handle, RAD_ACCT_OUTPUT_GIGAWORDS, auth->info.stats.xmitOctets / MAX_U_INT32) != 0) {
      Log(LG_RADIUS, ("[%s] RADIUS: %s: put stats: %s", auth->info.lnkname, __func__,
	rad_strerror(auth->radius.handle)));
      return;
    }
    SLIST_FOREACH(ssr, &auth->info.ss.stat[0], next) {
	char str[64];
	snprintf(str, sizeof(str), "%s:%llu",
	    ssr->name, (long long unsigned)ssr->Octets);
	Log(LG_RADIUS2, ("[%s] RADIUS: %s: rad_put_string(RAD_MPD_INPUT_OCTETS): %s", 
    	    auth->info.lnkname, __func__, str));
	if (rad_put_vendor_attr(auth->radius.handle, RAD_VENDOR_MPD, RAD_MPD_INPUT_OCTETS, str, strlen(str)) != 0) {
    	    Log(LG_RADIUS, ("[%s] RADIUS: %s: put stats: %s", auth->info.lnkname, __func__,
		rad_strerror(auth->radius.handle)));
	}
	snprintf(str, sizeof(str), "%s:%llu",
	    ssr->name, (long long unsigned)ssr->Packets);
	Log(LG_RADIUS2, ("[%s] RADIUS: %s: rad_put_string(RAD_MPD_INPUT_PACKETS): %s", 
    	    auth->info.lnkname, __func__, str));
	if (rad_put_vendor_attr(auth->radius.handle, RAD_VENDOR_MPD, RAD_MPD_INPUT_PACKETS, str, strlen(str)) != 0) {
    	    Log(LG_RADIUS, ("[%s] RADIUS: %s: put stats: %s", auth->info.lnkname, __func__,
		rad_strerror(auth->radius.handle)));
	}
    }
    SLIST_FOREACH(ssr, &auth->info.ss.stat[1], next) {
	char str[64];
	snprintf(str, sizeof(str), "%s:%llu",
	    ssr->name, (long long unsigned)ssr->Octets);
	Log(LG_RADIUS2, ("[%s] RADIUS: %s: rad_put_string(RAD_MPD_OUTPUT_OCTETS): %s", 
    	    auth->info.lnkname, __func__, str));
	if (rad_put_vendor_attr(auth->radius.handle, RAD_VENDOR_MPD, RAD_MPD_OUTPUT_OCTETS, str, strlen(str)) != 0) {
    	    Log(LG_RADIUS, ("[%s] RADIUS: %s: put stats: %s", auth->info.lnkname, __func__,
		rad_strerror(auth->radius.handle)));
	}
	snprintf(str, sizeof(str), "%s:%llu",
	    ssr->name, (long long unsigned)ssr->Packets);
	Log(LG_RADIUS2, ("[%s] RADIUS: %s: rad_put_string(RAD_MPD_OUTPUT_PACKETS): %s", 
    	    auth->info.lnkname, __func__, str));
	if (rad_put_vendor_attr(auth->radius.handle, RAD_VENDOR_MPD, RAD_MPD_OUTPUT_PACKETS, str, strlen(str)) != 0) {
    	    Log(LG_RADIUS, ("[%s] RADIUS: %s: put stats: %s", auth->info.lnkname, __func__,
		rad_strerror(auth->radius.handle)));
	}
    }

  }

  Log(LG_RADIUS2, ("[%s] RADIUS: %s: Sending accounting data (Type: %d)",
    auth->info.lnkname, __func__, auth->acct_type));
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
RadStat(Context ctx, int ac, char *av[], void *arg)
{
  Auth		const a = &ctx->lnk->lcp.auth;
  RadConf	const conf = &a->conf.radius;
  int		i;
  char		*buf;
  RadServe_Conf	server;
  char		buf1[64];

  Printf("Configuration:\r\n");
  Printf("\tTimeout      : %d\r\n", conf->radius_timeout);
  Printf("\tRetries      : %d\r\n", conf->radius_retries);
  Printf("\tConfig-file  : %s\r\n", (conf->file ? conf->file : "none"));
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
  OptStat(ctx, &conf->options, gConfList);

  Printf("Data:\r\n");
  Printf("\tAuthenticated  : %s\r\n", a->params.authentic == AUTH_CONF_RADIUS_AUTH ? 
  	"yes" : "no");
  
  buf = Bin2Hex(a->params.state, a->params.state_len); 
  Printf("\tState          : 0x%s\r\n", buf);
  Freee(MB_UTIL, buf);
  
  buf = Bin2Hex(a->params.class, a->params.class_len);
  Printf("\tClass          : 0x%s\r\n", buf);
  Freee(MB_UTIL, buf);
  
  return (0);
}

static int
RadiusAddServer(AuthData auth, short request_type)
{
  int		i;
  RadConf	const c = &auth->conf.radius;
  RadServe_Conf	s;

  if (c->server == NULL)
    return (RAD_ACK);

  s = c->server;
  i = 1;
  while (s) {

    Log(LG_RADIUS2, ("[%s] RADIUS: %s Adding %s", auth->info.lnkname, __func__, s->hostname));
    if (request_type == RAD_ACCESS_REQUEST) {
      if (rad_add_server (auth->radius.handle, s->hostname,
	s->auth_port,
	s->sharedsecret,
	c->radius_timeout,
	c->radius_retries) == -1) {
	  Log(LG_RADIUS, ("[%s] RADIUS: %s error: %s", auth->info.lnkname, __func__, 
	    rad_strerror(auth->radius.handle)));
	  return (RAD_NACK);
      }
    } else {
      if (rad_add_server (auth->radius.handle, s->hostname,
	s->acct_port,
	s->sharedsecret,
	c->radius_timeout,
	c->radius_retries) == -1) {
	  Log(LG_RADIUS, ("[%s] RADIUS: %s error: %s", auth->info.lnkname, __func__, 
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
RadiusSetCommand(Context ctx, int ac, char *av[], void *arg) 
{
  RadConf	const conf = &ctx->lnk->lcp.auth.conf.radius;
  RadServe_Conf	server;
  RadServe_Conf	t_server;
  int		val, count;
  struct u_addr t;

  if (ac == 0)
      return(-1);

    switch ((intptr_t)arg) {

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
	  Error("cannot configure more than %d servers",
	    RADIUS_MAX_SERVERS);
	}

	server = Malloc(MB_RADIUS, sizeof(*server));
	server->auth_port = 1812;
	server->acct_port = 1813;
	server->next = NULL;

	if (strlen(av[0]) > 255)
	  Error("Hostname too long. > 255 char.");

	if (strlen(av[1]) > 127)
	  Error("Shared Secret too long. > 127 char.");

	if (ac > 2 && atoi(av[2]) < 65535 && atoi(av[2]) > 1) {
	  server->auth_port = atoi (av[2]);

	} else if ( ac > 2 )
	  Error("Auth Port number too high. > 65535");

	if (ac > 3 && atoi(av[3]) < 65535 && atoi(av[3]) > 1) {
	  server->acct_port = atoi (av[3]);
	} else if ( ac > 3 )
	  Error("Acct Port number too high > 65535");

	server->hostname = Mdup(MB_RADIUS, av[0], strlen(av[0]) + 1);
	server->sharedsecret = Mdup(MB_RADIUS, av[1], strlen(av[1]) + 1);

	if (conf->server != NULL)
	  server->next = conf->server;

	conf->server = server;

	break;

      case SET_ME:
        if (ParseAddr(*av, &t, ALLOW_IPV4)) {
	    u_addrtoin_addr(&t,&conf->radius_me);
	} else
	    Error("Bad NAS address '%s'.", *av);
	break;

      case SET_MEV6:
        if (!ParseAddr(*av, &conf->radius_mev6, ALLOW_IPV6))
	    Error("Bad NAS address '%s'.", *av);
	break;

      case SET_TIMEOUT:
	val = atoi(*av);
	  if (val <= 0)
	    Error("Timeout must be positive.");
	  else
	    conf->radius_timeout = val;
	break;

      case SET_RETRIES:
	val = atoi(*av);
	if (val <= 0)
	  Error("Retries must be positive.");
	else
	  conf->radius_retries = val;
	break;

      case SET_CONFIG:
	if (strlen(av[0]) > PATH_MAX) {
	  Error("RADIUS: Config file name too long.");
	} else {
	  if (conf->file)
		Freee(MB_RADIUS, conf->file);
	  conf->file = Mdup(MB_RADIUS, av[0], strlen(av[0])+1);
	}
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
RadiusOpen(AuthData auth, short request_type)
{
  RadConf 	const conf = &auth->conf.radius;

  if (request_type == RAD_ACCESS_REQUEST) {
  
    auth->radius.handle = rad_open();
    if (auth->radius.handle == NULL) {
      Log(LG_RADIUS, ("[%s] RADIUS: rad_open failed", auth->info.lnkname));
      return (RAD_NACK);
    }

  /* RAD_ACCOUNTING_REQUEST */
  } else {
  
    auth->radius.handle = rad_acct_open();
    if (auth->radius.handle == NULL) {
      Log(LG_RADIUS, ("[%s] RADIUS: rad_acct_open failed", auth->info.lnkname));
      return (RAD_NACK);
    }

  }
  
  if (conf->file && strlen(conf->file)) {
    Log(LG_RADIUS2, ("[%s] RADIUS: using %s", auth->info.lnkname, conf->file));
    if (rad_config(auth->radius.handle, conf->file) != 0) {
      Log(LG_RADIUS, ("[%s] RADIUS: rad_config: %s", auth->info.lnkname, 
        rad_strerror(auth->radius.handle)));
      return (RAD_NACK);
    }
  }

  if (RadiusAddServer(auth, request_type) == RAD_NACK)
    return (RAD_NACK);
  
  return RAD_ACK;

}

static int
RadiusStart(AuthData auth, short request_type)
{
  RadConf 	const conf = &auth->conf.radius;  
  char		host[MAXHOSTNAMELEN];
  int		porttype;
  char		buf[64];
  char		*tmpval;

  if (RadiusOpen(auth, request_type) == RAD_NACK) 
    return RAD_NACK;

  if (rad_create_request(auth->radius.handle, request_type) == -1) {
    Log(LG_RADIUS, ("[%s] RADIUS: rad_create_request: %s", 
      auth->info.lnkname, rad_strerror(auth->radius.handle)));
    return (RAD_NACK);
  }

  if (gethostname(host, sizeof(host)) == -1) {
    Log(LG_RADIUS, ("[%s] RADIUS: %s: gethostname() failed", 
      auth->info.lnkname, __func__));
    return (RAD_NACK);
  }
  Log(LG_RADIUS2, ("[%s] RADIUS: %s: rad_put_string(RAD_NAS_IDENTIFIER): %s", 
    auth->info.lnkname, __func__, host));
  if (rad_put_string(auth->radius.handle, RAD_NAS_IDENTIFIER, host) == -1)  {
    Log(LG_RADIUS, ("[%s] RADIUS: %s: rad_put_string(RAD_NAS_IDENTIFIER) failed %s", auth->info.lnkname,
      __func__, rad_strerror(auth->radius.handle)));
    return (RAD_NACK);
  }
  
  if (conf->radius_me.s_addr != 0) {
    Log(LG_RADIUS2, ("[%s] RADIUS: %s: rad_put_addr(RAD_NAS_IP_ADDRESS): %s", 
      auth->info.lnkname, __func__, inet_ntoa(conf->radius_me)));
    if (rad_put_addr(auth->radius.handle, RAD_NAS_IP_ADDRESS, conf->radius_me) == -1) {
      Log(LG_RADIUS, ("[%s] RADIUS: %s: rad_put_addr(RAD_NAS_IP_ADDRESS) failed %s", 
	auth->info.lnkname, __func__, rad_strerror(auth->radius.handle)));
      return (RAD_NACK);
    }
  }

  if (!u_addrempty(&conf->radius_mev6)) {
    Log(LG_RADIUS2, ("[%s] RADIUS: %s: rad_put_addr(RAD_NAS_IPV6_ADDRESS): %s", 
      auth->info.lnkname, __func__, u_addrtoa(&conf->radius_mev6,buf,sizeof(buf))));
    if (rad_put_attr(auth->radius.handle, RAD_NAS_IPV6_ADDRESS, &conf->radius_mev6.u.ip6, sizeof(conf->radius_mev6.u.ip6)) == -1) {
      Log(LG_RADIUS, ("[%s] RADIUS: %s: rad_put_addr(RAD_NAS_IPV6_ADDRESS) failed %s", 
	auth->info.lnkname, __func__, rad_strerror(auth->radius.handle)));
      return (RAD_NACK);
    }
  }

#if (!defined(__FreeBSD__) || __FreeBSD_version >= 503100)
  /* Insert the Message Authenticator RFC 3579
   * If using EAP this is mandatory
   */
  if ((Enabled(&conf->options, RADIUS_CONF_MESSAGE_AUTHENTIC)
	|| auth->proto == PROTO_EAP)
	&& request_type != RAD_ACCOUNTING_REQUEST) {
    Log(LG_RADIUS2, ("[%s] RADIUS: Adding Message Authenticator", auth->info.lnkname));
    if (rad_put_message_authentic(auth->radius.handle) == -1) {
      Log(LG_RADIUS, ("[%s] RADIUS: %s: rad_put_message_authentic failed %s", 
        auth->info.lnkname, __func__, rad_strerror(auth->radius.handle)));
      return (RAD_NACK);
    }
  }
#endif

  Log(LG_RADIUS2, ("[%s] RADIUS: %s: rad_put_string(RAD_ACCT_SESSION_ID): %s", 
    auth->info.lnkname, __func__, auth->info.session_id));
  if (rad_put_string(auth->radius.handle, RAD_ACCT_SESSION_ID, auth->info.session_id) != 0) {
    Log(LG_RADIUS, ("[%s] RADIUS: %s: put (RAD_ACCT_SESSION_ID): %s", 
      auth->info.lnkname, __func__, rad_strerror(auth->radius.handle)));
    return (RAD_NACK);
  }

  Log(LG_RADIUS2, ("[%s] RADIUS: %s: rad_put_int(RAD_NAS_PORT): %d", 
    auth->info.lnkname, __func__, auth->info.linkID));
  if (rad_put_int(auth->radius.handle, RAD_NAS_PORT, auth->info.linkID) == -1)  {
    Log(LG_RADIUS, ("[%s] RADIUS: %s: rad_put_int(RAD_NAS_PORT) failed %s", 
      auth->info.lnkname, __func__, rad_strerror(auth->radius.handle)));
    return (RAD_NACK);
  }

#ifdef PHYSTYPE_MODEM
  if (auth->info.phys_type == &gModemPhysType) {
    porttype = RAD_ASYNC;
  } else 
#endif
#ifdef PHYSTYPE_NG_SOCKET
  if (auth->info.phys_type == &gNgPhysType) {
    porttype = RAD_SYNC;
  } else 
#endif
#ifdef PHYSTYPE_PPPOE
  if (auth->info.phys_type == &gPppoePhysType) {
    porttype = RAD_ETHERNET;
  } else 
#endif
  {
    porttype = RAD_VIRTUAL;
  };
  Log(LG_RADIUS2, ("[%s] RADIUS: %s: rad_put_int(RAD_NAS_PORT_TYPE): %d", 
    auth->info.lnkname, __func__, porttype));
  if (rad_put_int(auth->radius.handle, RAD_NAS_PORT_TYPE, porttype) == -1) {
    Log(LG_RADIUS, ("[%s] RADIUS: %s: rad_put_int(RAD_NAS_PORT_TYPE) failed %s", 
      auth->info.lnkname, __func__, rad_strerror(auth->radius.handle)));
    return (RAD_NACK);
  }

  Log(LG_RADIUS2, ("[%s] RADIUS: %s: rad_put_int(RAD_SERVICE_TYPE): RAD_FRAMED", 
    auth->info.lnkname, __func__));
  if (rad_put_int(auth->radius.handle, RAD_SERVICE_TYPE, RAD_FRAMED) == -1) {
    Log(LG_RADIUS, ("[%s] RADIUS: %s: rad_put_int(RAD_SERVICE_TYPE) failed %s", 
      auth->info.lnkname, __func__, rad_strerror(auth->radius.handle)));
    return (RAD_NACK);
  }
  
  Log(LG_RADIUS2, ("[%s] RADIUS: %s: rad_put_int(RAD_FRAMED_PROTOCOL): RAD_PPP", 
    auth->info.lnkname, __func__));
  if (rad_put_int(auth->radius.handle, RAD_FRAMED_PROTOCOL, RAD_PPP) == -1) {
    Log(LG_RADIUS, ("[%s] RADIUS: %s: rad_put_int(RAD_FRAMED_PROTOCOL) failed %s", 
      auth->info.lnkname, __func__, rad_strerror(auth->radius.handle)));
    return (RAD_NACK);
  }

  if (auth->params.state != NULL) {
    tmpval = Bin2Hex(auth->params.state, auth->params.state_len);
    Log(LG_RADIUS2, ("[%s] RADIUS: %s: rad_put_attr(RAD_STATE): 0x%s", auth->info.lnkname, __func__, tmpval));
    Freee(MB_UTIL, tmpval);
    if (rad_put_attr(auth->radius.handle, RAD_STATE, auth->params.state, auth->params.state_len) == -1) {
      Log(LG_RADIUS, ("[%s] RADIUS: %s: rad_put_attr(RAD_STATE) failed %s", 
        auth->info.lnkname, __func__, rad_strerror(auth->radius.handle)));
      return (RAD_NACK);
    }
  }

  if (auth->params.class != NULL) {
    tmpval = Bin2Hex(auth->params.class, auth->params.class_len);
    Log(LG_RADIUS2, ("[%s] RADIUS: %s: rad_put_attr(RAD_CLASS): 0x%s", auth->info.lnkname, __func__, tmpval));
    Freee(MB_UTIL, tmpval);
    if (rad_put_attr(auth->radius.handle, RAD_CLASS, auth->params.class, auth->params.class_len) == -1) {
      Log(LG_RADIUS, ("[%s] RADIUS: %s: rad_put_attr(RAD_CLASS) failed %s", 
        auth->info.lnkname, __func__, rad_strerror(auth->radius.handle)));
      return (RAD_NACK);
    }
  }

    /* For compatibility and for untrusted peers use peeraddr as calling */
    if (Enabled(&conf->options, RADIUS_CONF_PEER_AS_CALLING)) {
	Log(LG_RADIUS2, ("[%s] RADIUS: %s: rad_put_string(RAD_CALLING_STATION_ID): %s",
    	    auth->info.lnkname, __func__, auth->params.peeraddr));
	if (rad_put_string(auth->radius.handle, RAD_CALLING_STATION_ID,
    	    auth->params.peeraddr) == -1) {
    	        Log(LG_RADIUS, ("[%s] RADIUS: %s: rad_put_string(RAD_CALLING_STATION_ID) failed %s",
	    	    auth->info.lnkname, __func__, rad_strerror(auth->radius.handle)));
    		return (RAD_NACK);
	}
    } else {
	Log(LG_RADIUS2, ("[%s] RADIUS: %s: rad_put_string(RAD_CALLING_STATION_ID): %s",
    	    auth->info.lnkname, __func__, auth->params.callingnum));
	if (rad_put_string(auth->radius.handle, RAD_CALLING_STATION_ID,
    	    auth->params.callingnum) == -1) {
    	        Log(LG_RADIUS, ("[%s] RADIUS: %s: rad_put_string(RAD_CALLING_STATION_ID) failed %s",
	    	    auth->info.lnkname, __func__, rad_strerror(auth->radius.handle)));
    		return (RAD_NACK);
	}
    }
    Log(LG_RADIUS2, ("[%s] RADIUS: %s: rad_put_string(RAD_CALLED_STATION_ID): %s",
	auth->info.lnkname, __func__, auth->params.callednum));
    if (rad_put_string(auth->radius.handle, RAD_CALLED_STATION_ID,
    	auth->params.callednum) == -1) {
    	    Log(LG_RADIUS, ("[%s] RADIUS: %s: rad_put_string(RAD_CALLED_STATION_ID) failed %s",
	        auth->info.lnkname, __func__, rad_strerror(auth->radius.handle)));
    	    return (RAD_NACK);
    }
    return RAD_ACK;
}

static int 
RadiusPutAuth(AuthData auth)
{
  ChapParams		const cp = &auth->params.chap;
  PapParams		const pp = &auth->params.pap;
  
  struct rad_chapvalue		rad_chapval;
  struct rad_mschapvalue	rad_mschapval;
  struct rad_mschapv2value	rad_mschapv2val;
  struct mschapvalue		*mschapval;
  struct mschapv2value		*mschapv2val;  

  if (rad_put_string(auth->radius.handle, RAD_USER_NAME, auth->params.authname) == -1) {
    Log(LG_RADIUS, ("[%s] RADIUS: %s: rad_put_string(username) failed %s", 
      auth->info.lnkname, __func__, rad_strerror(auth->radius.handle)));
    return (RAD_NACK);
  }

  if (auth->proto == PROTO_CHAP || auth->proto == PROTO_EAP) {
    switch (cp->recv_alg) {

      case CHAP_ALG_MSOFT:
	Log(LG_RADIUS2, ("[%s] RADIUS: %s: RADIUS_CHAP (MSOFTv1) peer name: %s", 
	  auth->info.lnkname, __func__, auth->params.authname));
	if (cp->value_len != 49) {
	  Log(LG_RADIUS, ("[%s] RADIUS: %s: RADIUS_CHAP (MSOFTv1) unrecognised key length %d/%d",
	    auth->info.lnkname, __func__, cp->value_len, 49));
	  return (RAD_NACK);
	}

	if (rad_put_vendor_attr(auth->radius.handle, RAD_VENDOR_MICROSOFT, RAD_MICROSOFT_MS_CHAP_CHALLENGE,
	    cp->chal_data, cp->chal_len) == -1)  {
	  Log(LG_RADIUS, ("[%s] RADIUS: %s: rad_put_vendor_attr(RAD_MICROSOFT_MS_CHAP_CHALLENGE) failed %s",
	    auth->info.lnkname, __func__, rad_strerror(auth->radius.handle)));
	  return (RAD_NACK);
	}

	mschapval = (struct mschapvalue *)cp->value;
	rad_mschapval.ident = auth->id;
	rad_mschapval.flags = 0x01;
	memcpy(rad_mschapval.lm_response, mschapval->lmHash, 24);
	memcpy(rad_mschapval.nt_response, mschapval->ntHash, 24);

	if (rad_put_vendor_attr(auth->radius.handle, RAD_VENDOR_MICROSOFT, RAD_MICROSOFT_MS_CHAP_RESPONSE,
	    &rad_mschapval, sizeof(rad_mschapval)) == -1)  {
	  Log(LG_RADIUS, ("[%s] RADIUS: %s: rad_put_vendor_attr(RAD_MICROSOFT_MS_CHAP_RESPONSE) failed %s",
	    auth->info.lnkname, __func__, rad_strerror(auth->radius.handle)));
	  return (RAD_NACK);
	}
	break;

      case CHAP_ALG_MSOFTv2:
      
	Log(LG_RADIUS2, ("[%s] RADIUS: %s: RADIUS_CHAP (MSOFTv2) peer name: %s",
	  auth->info.lnkname, __func__, auth->params.authname));
	if (rad_put_vendor_attr(auth->radius.handle, RAD_VENDOR_MICROSOFT,
	    RAD_MICROSOFT_MS_CHAP_CHALLENGE, cp->chal_data, cp->chal_len) == -1) {
	  Log(LG_RADIUS, ("[%s] RADIUS: %s: rad_put_vendor_attr(RAD_MICROSOFT_MS_CHAP_CHALLENGE) failed %s",
	    auth->info.lnkname, __func__, rad_strerror(auth->radius.handle)));
	  return (RAD_NACK);
	}

	if (cp->value_len != sizeof(*mschapv2val)) {
	  Log(LG_RADIUS, ("[%s] RADIUS: %s: RADIUS_CHAP (MSOFTv2) unrecognised key length %d/%d", auth->info.lnkname,
	    __func__, cp->value_len, (int)sizeof(*mschapv2val)));
	  return (RAD_NACK);
	}
      
	mschapv2val = (struct mschapv2value *)cp->value;
	rad_mschapv2val.ident = auth->id;
	rad_mschapv2val.flags = mschapv2val->flags;
	memcpy(rad_mschapv2val.response, mschapv2val->ntHash,
	  sizeof(rad_mschapv2val.response));
	memset(rad_mschapv2val.reserved, '\0',
	  sizeof(rad_mschapv2val.reserved));
	memcpy(rad_mschapv2val.pchallenge, mschapv2val->peerChal,
	  sizeof(rad_mschapv2val.pchallenge));

	if (rad_put_vendor_attr(auth->radius.handle, RAD_VENDOR_MICROSOFT, RAD_MICROSOFT_MS_CHAP2_RESPONSE,
	    &rad_mschapv2val, sizeof(rad_mschapv2val)) == -1)  {
	  Log(LG_RADIUS, ("[%s] RADIUS: %s: rad_put_vendor_attr(RAD_MICROSOFT_MS_CHAP2_RESPONSE) failed %s",
	    auth->info.lnkname, __func__, rad_strerror(auth->radius.handle)));
	  return (RAD_NACK);
	}
	break;

      case CHAP_ALG_MD5:
	/* RADIUS requires the CHAP Ident in the first byte of the CHAP-Password */
	rad_chapval.ident = auth->id;
	memcpy(rad_chapval.response, cp->value, cp->value_len);
	Log(LG_RADIUS2, ("[%s] RADIUS: %s: RADIUS_CHAP (MD5) peer name: %s", 
	  auth->info.lnkname, __func__, auth->params.authname));
	if (rad_put_attr(auth->radius.handle, RAD_CHAP_PASSWORD, &rad_chapval, cp->value_len + 1) == -1 ||
	    rad_put_attr(auth->radius.handle, RAD_CHAP_CHALLENGE, cp->chal_data, cp->chal_len) == -1) {
	  Log(LG_RADIUS, ("[%s] RADIUS: %s: rad_put_string(password) failed %s",
	    auth->info.lnkname, __func__, rad_strerror(auth->radius.handle)));
	  return (RAD_NACK);
	}
	break;
      
      default:
	Log(LG_RADIUS, ("[%s] RADIUS: %s: RADIUS unkown CHAP ALG %d", 
	  auth->info.lnkname, __func__, cp->recv_alg));
	return (RAD_NACK);
    }
  } else if (auth->proto == PROTO_PAP) {
        
    Log(LG_RADIUS2, ("[%s] RADIUS: %s: RADIUS_PAP peer name: %s",
      auth->info.lnkname, __func__, auth->params.authname));
    if (rad_put_string(auth->radius.handle, RAD_USER_PASSWORD, pp->peer_pass) == -1) {
      Log(LG_RADIUS, ("[%s] RADIUS: %s: rad_put_string(password) failed %s", 
	auth->info.lnkname, __func__, rad_strerror(auth->radius.handle)));
      return (RAD_NACK);
    }
    
  } else {
    Log(LG_RADIUS, ("[%s] RADIUS: %s: RADIUS unkown Proto %d", 
      auth->info.lnkname, __func__, auth->proto));
    return (RAD_NACK);
  }
  
  return (RAD_ACK);

}

static int 
RadiusSendRequest(AuthData auth)
{
  struct timeval	timelimit;
  struct timeval	tv;
  int 			fd, n;

  Log(LG_RADIUS2, ("[%s] RADIUS: %s: username: %s", 
    auth->info.lnkname, __func__, auth->params.authname));
  n = rad_init_send_request(auth->radius.handle, &fd, &tv);
  if (n != 0) {
    Log(LG_RADIUS, ("[%s] RADIUS: rad_init_send_request failed: %d %s",
      auth->info.lnkname, n, rad_strerror(auth->radius.handle)));
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
      Log(LG_RADIUS, ("[%s] RADIUS: poll failed %s", auth->info.lnkname, 
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
      auth->info.lnkname, __func__, auth->params.authname));
    n = rad_continue_send_request(auth->radius.handle, n, &fd, &tv);
    if (n != 0)
      break;

    gettimeofday(&timelimit, NULL);
    timeradd(&tv, &timelimit, &timelimit);
  }

  switch (n) {

    case RAD_ACCESS_ACCEPT:
      Log(LG_RADIUS, ("[%s] RADIUS: rec'd RAD_ACCESS_ACCEPT for user %s", 
        auth->info.lnkname, auth->params.authname));
      auth->status = AUTH_STATUS_SUCCESS;
      break;

    case RAD_ACCESS_CHALLENGE:
      Log(LG_RADIUS, ("[%s] RADIUS: rec'd RAD_ACCESS_CHALLENGE for user %s", 
        auth->info.lnkname, auth->params.authname));
      break;

    case RAD_ACCESS_REJECT:
      Log(LG_RADIUS, ("[%s] RADIUS: rec'd RAD_ACCESS_REJECT for user %s", 
        auth->info.lnkname, auth->params.authname));
      auth->status = AUTH_STATUS_FAIL;
      break;

    case RAD_ACCOUNTING_RESPONSE:
      Log(LG_RADIUS, ("[%s] RADIUS: rec'd RAD_ACCOUNTING_RESPONSE for user %s", 
        auth->info.lnkname, auth->params.authname));
      break;

    case -1:
      Log(LG_RADIUS, ("[%s] RADIUS: rad_send_request failed: %s", 
        auth->info.lnkname, rad_strerror(auth->radius.handle)));
      return(RAD_NACK);
      
    default:
      Log(LG_RADIUS, ("[%s] RADIUS: rad_send_request: unexpected return value: %d", 
        auth->info.lnkname, n));
      return(RAD_NACK);
  }

  RadiusGetParams(auth, n == RAD_ACCESS_CHALLENGE);
  return RAD_ACK;
}

static int
RadiusGetParams(AuthData auth, int eap_proxy)
{
  ChapParams	const cp = &auth->params.chap;
  int		res, i, j;
  size_t	len;
  const void	*data;
  u_int32_t	vendor;
  char		*route, *acl, *acl1, *acl2, *acl3;
  char		*tmpval;
  short		got_mppe_keys = FALSE;
  struct in_addr	ip;
  struct acl		**acls, *acls1;
  struct ifaceroute	*r, *r1;
  struct u_range	range;
#if (!defined(__FreeBSD__) || __FreeBSD_version >= 503100)
  u_char	*tmpkey;
  size_t	tmpkey_len;
#endif

  Freee(MB_AUTH, auth->params.eapmsg);
  auth->params.eapmsg = NULL;
  
  while ((res = rad_get_attr(auth->radius.handle, &data, &len)) > 0) {

    switch (res) {

      case RAD_STATE:
	tmpval = Bin2Hex(data, len);
	Log(LG_RADIUS2, ("[%s] RADIUS: %s: RAD_STATE: 0x%s", auth->info.lnkname, __func__, tmpval));
	Freee(MB_UTIL, tmpval);
	auth->params.state_len = len;
	if (auth->params.state != NULL)
	  Freee(MB_AUTH, auth->params.state);
	auth->params.state = Mdup(MB_AUTH, data, len);
	continue;

      case RAD_CLASS:
	tmpval = Bin2Hex(data, len);
	Log(LG_RADIUS2, ("[%s] RADIUS: %s: RAD_CLASS: 0x%s", auth->info.lnkname, __func__, tmpval));
	Freee(MB_UTIL, tmpval);
	auth->params.class_len = len;
	if (auth->params.class != NULL)
	  Freee(MB_AUTH, auth->params.class);
	auth->params.class = Mdup(MB_AUTH, data, len);
	continue;

	/* libradius already checks the message-authenticator, so simply ignore it */
      case RAD_MESSAGE_AUTHENTIC:
	Log(LG_RADIUS, ("[%s] RADIUS: %s: RAD_MESSAGE_AUTHENTIC", auth->info.lnkname, __func__));
	continue;

      case RAD_EAP_MESSAGE:
	if (auth->params.eapmsg != NULL) {
	  char *tbuf;
#ifdef DEBUG
	  Log(LG_RADIUS2, ("[%s] RADIUS: %s: RAD_EAP_MESSAGE (continued) Len:%d",
	    auth->info.lnkname, __func__, auth->params.eapmsg_len + len));
#endif
	  tbuf = Malloc(MB_AUTH, auth->params.eapmsg_len + len);
	  memcpy(tbuf, auth->params.eapmsg, auth->params.eapmsg_len);
	  memcpy(&tbuf[auth->params.eapmsg_len], data, len);
	  auth->params.eapmsg_len += len;
	  Freee(MB_AUTH, auth->params.eapmsg);
	  auth->params.eapmsg = tbuf;
	} else {
	  Log(LG_RADIUS2, ("[%s] RADIUS: %s: RAD_EAP_MESSAGE", auth->info.lnkname, __func__));
	  auth->params.eapmsg = Mdup(MB_AUTH, data, len);
	  auth->params.eapmsg_len = len;
	}
	continue;
    }

    if (!eap_proxy)
      switch (res) {

      case RAD_FRAMED_IP_ADDRESS:
        ip = rad_cvt_addr(data);
        Log(LG_RADIUS2, ("[%s] RADIUS: %s: RAD_FRAMED_IP_ADDRESS: %s ",
          auth->info.lnkname, __func__, inet_ntoa(ip)));
	  
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
	  auth->info.lnkname, __func__, auth->params.authname));
        break;

      case RAD_FRAMED_IP_NETMASK:
        ip = rad_cvt_addr(data);
	auth->params.netmask = in_addrtowidth(&ip);
	Log(LG_RADIUS2, ("[%s] RADIUS: %s: RAD_FRAMED_IP_NETMASK: %s (/%d) ",
	  auth->info.lnkname, __func__, inet_ntoa(ip), auth->params.netmask));
	break;

      case RAD_FRAMED_ROUTE:
	route = rad_cvt_string(data, len);
	Log(LG_RADIUS2, ("[%s] RADIUS: %s: RAD_FRAMED_ROUTE: %s ",
	  auth->info.lnkname, __func__, route));
	if (!ParseRange(route, &range, ALLOW_IPV4)) {
	  Log(LG_RADIUS, ("[%s] RADIUS: %s: RAD_FRAMED_ROUTE: Bad route \"%s\"", auth->info.lnkname, __func__, route));
	  free(route);
	  break;
	}
	free(route);
	r = Malloc(MB_AUTH, sizeof(struct ifaceroute));
	r->dest = range;
	r->ok = 0;
	j = 0;
	SLIST_FOREACH(r1, &auth->params.routes, next) {
	  if (!u_rangecompare(&r->dest, &r1->dest)) {
	    Log(LG_RADIUS, ("[%s] RADIUS: %s: Duplicate route", auth->info.lnkname, __func__));
	    j = 1;
	  }
	};
	if (j == 0) {
	    SLIST_INSERT_HEAD(&auth->params.routes, r, next);
	} else {
	    Freee(MB_AUTH, r);
	}
	break;

      case RAD_FRAMED_IPV6_ROUTE:
	route = rad_cvt_string(data, len);
	Log(LG_RADIUS2, ("[%s] RADIUS: %s: RAD_FRAMED_IPV6_ROUTE: %s ",
	  auth->info.lnkname, __func__, route));
	if (!ParseRange(route, &range, ALLOW_IPV6)) {
	  Log(LG_RADIUS, ("[%s] RADIUS: %s: RAD_FRAMED_IPV6_ROUTE: Bad route \"%s\"", auth->info.lnkname, __func__, route));
	  free(route);
	  break;
	}
	free(route);
	r = Malloc(MB_AUTH, sizeof(struct ifaceroute));
	r->dest = range;
	r->ok = 0;
	j = 0;
	SLIST_FOREACH(r1, &auth->params.routes, next) {
	  if (!u_rangecompare(&r->dest, &r1->dest)) {
	    Log(LG_RADIUS, ("[%s] RADIUS: %s: Duplicate route", auth->info.lnkname, __func__));
	    j = 1;
	  }
	};
	if (j == 0) {
	    SLIST_INSERT_HEAD(&auth->params.routes, r, next);
	} else {
	    Freee(MB_AUTH, r);
	}
	break;

      case RAD_SESSION_TIMEOUT:
        auth->params.session_timeout = rad_cvt_int(data);
        Log(LG_RADIUS2, ("[%s] RADIUS: %s: RAD_SESSION_TIMEOUT: %u ",
          auth->info.lnkname, __func__, auth->params.session_timeout));
        break;

      case RAD_IDLE_TIMEOUT:
        auth->params.idle_timeout = rad_cvt_int(data);
        Log(LG_RADIUS2, ("[%s] RADIUS: %s: RAD_IDLE_TIMEOUT: %u ",
          auth->info.lnkname, __func__, auth->params.idle_timeout));
        break;

     case RAD_ACCT_INTERIM_INTERVAL:
	auth->params.acct_update = rad_cvt_int(data);
        Log(LG_RADIUS2, ("[%s] RADIUS: %s: RAD_ACCT_INTERIM_INTERVAL: %u ",
          auth->info.lnkname, __func__, auth->params.acct_update));
	break;

      case RAD_FRAMED_MTU:
	i = rad_cvt_int(data);
	Log(LG_RADIUS2, ("[%s] RADIUS: %s: RAD_FRAMED_MTU: %u ",
	  auth->info.lnkname, __func__, i));
	if (i < IFACE_MIN_MTU || i > IFACE_MAX_MTU) {
	  Log(LG_RADIUS, ("[%s] RADIUS: %s: RAD_FRAMED_MTU: invalid MTU: %u ",
	    auth->info.lnkname, __func__, i));
	  auth->params.mtu = 0;
	  break;
	}
	auth->params.mtu = i;
        break;

      case RAD_FRAMED_COMPRESSION:
        i = rad_cvt_int(data);
	Log(LG_RADIUS2, ("[%s] RADIUS: %s: RAD_FRAMED_COMPRESSION: %d",
	  auth->info.lnkname, __func__, i));
	if (i == RAD_COMP_VJ)
	    auth->params.vjc_enable = 1;
        break;

      case RAD_FRAMED_PROTOCOL:
	Log(LG_RADIUS2, ("[%s] RADIUS: %s: (RAD_FRAMED_PROTOCOL: %d)",
	  auth->info.lnkname, __func__, rad_cvt_int(data)));
        break;

      case RAD_FRAMED_ROUTING:
	Log(LG_RADIUS2, ("[%s] RADIUS: %s: (RAD_FRAMED_ROUTING: %d)",
	  auth->info.lnkname, __func__, rad_cvt_int(data)));
        break;

      case RAD_FILTER_ID:
	tmpval = rad_cvt_string(data, len);
	Log(LG_RADIUS2, ("[%s] RADIUS: %s: (RAD_FILTER_ID: %s)",
	  auth->info.lnkname, __func__, tmpval));
	free(tmpval);
        break;

      case RAD_SERVICE_TYPE:
	Log(LG_RADIUS2, ("[%s] RADIUS: %s: (RAD_SERVICE_TYPE: %d)",
	  auth->info.lnkname, __func__, rad_cvt_int(data)));
        break;

      case RAD_REPLY_MESSAGE:
	tmpval = rad_cvt_string(data, len);
	Log(LG_RADIUS2, ("[%s] RADIUS: %s: RAD_REPLY_MESSAGE: %s ",
	  auth->info.lnkname, __func__, auth->reply_message));
	auth->reply_message = Mdup(MB_AUTH, tmpval, len + 1);
	free(tmpval);
        break;

      case RAD_FRAMED_POOL:
	tmpval = rad_cvt_string(data, len);
	/* copy it into the persistent data struct */
	strcpy(auth->params.ippool, tmpval);
	free(tmpval);
	Log(LG_RADIUS2, ("[%s] RADIUS: %s: RAD_FRAMED_POOL: %s ",
	  auth->info.lnkname, __func__, auth->params.ippool));
        break;

      case RAD_VENDOR_SPECIFIC:
	if ((res = rad_get_vendor_attr(&vendor, &data, &len)) == -1) {
	  Log(LG_RADIUS, ("[%s] RADIUS: %s: rad_get_vendor_attr failed: %s ",
	    auth->info.lnkname, __func__, rad_strerror(auth->radius.handle)));
	  return RAD_NACK;
	}

	switch (vendor) {

	  case RAD_VENDOR_MICROSOFT:
	    switch (res) {

	      case RAD_MICROSOFT_MS_CHAP_ERROR:
	        if (auth->mschap_error != NULL) {
	    	    Freee(MB_AUTH, auth->mschap_error);
		    auth->mschap_error = NULL;
		}
		if (len == 0)
		    break;

		/* there is a nullbyte on the first pos, don't know why */
		if (((const char *)data)[0] == '\0') {
		  data = (const char *)data + 1;
		  len--;
		}
		tmpval = rad_cvt_string(data, len);
		auth->mschap_error = Mdup(MB_AUTH, tmpval, len + 1);
		free(tmpval);

		Log(LG_RADIUS2, ("[%s] RADIUS: %s: MS-CHAP-Error: %s",
		  auth->info.lnkname, __func__, auth->mschap_error));
		break;

	      /* this was taken from userland ppp */
	      case RAD_MICROSOFT_MS_CHAP2_SUCCESS:
	        if (auth->mschapv2resp != NULL) {
	    	    Freee(MB_AUTH, auth->mschapv2resp);
		    auth->mschapv2resp = NULL;
		}
		if (len == 0)
		    break;
		if (len < 3 || ((const char *)data)[1] != '=') {
		  /*
		   * Only point at the String field if we don't think the
		   * peer has misformatted the response.
		   */
		  data = (const char *)data + 1;
		  len--;
		} else {
		  Log(LG_RADIUS, ("[%s] RADIUS: %s: Warning: The MS-CHAP2-Success attribute is mis-formatted. Compensating",
		    auth->info.lnkname, __func__));
		}
		if ((tmpval = rad_cvt_string((const char *)data, len)) == NULL) {
		    Log(LG_RADIUS, ("[%s] RADIUS: %s: rad_cvt_string failed: %s",
			auth->info.lnkname, __func__, rad_strerror(auth->radius.handle)));
		    return RAD_NACK;
		}
		auth->mschapv2resp = Mdup(MB_AUTH, tmpval, len + 1);
		free(tmpval);
		Log(LG_RADIUS2, ("[%s] RADIUS: %s: RAD_MICROSOFT_MS_CHAP2_SUCCESS: %s",
		  auth->info.lnkname, __func__, auth->mschapv2resp));
		break;

	      case RAD_MICROSOFT_MS_CHAP_DOMAIN:
		Freee(MB_AUTH, auth->params.msdomain);
		tmpval = rad_cvt_string(data, len);
		auth->params.msdomain = Mdup(MB_AUTH, tmpval, len + 1);
		free(tmpval);
		Log(LG_RADIUS2, ("[%s] RADIUS: %s: RAD_MICROSOFT_MS_CHAP_DOMAIN: %s",
		  auth->info.lnkname, __func__, auth->params.msdomain));
		break;

#if (!defined(__FreeBSD__) || __FreeBSD_version >= 503100)
              /* MPPE Keys MS-CHAPv2 and EAP-TLS */
	      case RAD_MICROSOFT_MS_MPPE_RECV_KEY:
		got_mppe_keys = TRUE;
		Log(LG_RADIUS2, ("[%s] RADIUS: %s: RAD_MICROSOFT_MS_MPPE_RECV_KEY",
		  auth->info.lnkname, __func__));
		tmpkey = rad_demangle_mppe_key(auth->radius.handle, data, len, &tmpkey_len);
		if (!tmpkey) {
		  Log(LG_RADIUS, ("[%s] RADIUS: %s: rad_demangle_mppe_key failed: %s",
		    auth->info.lnkname, __func__, rad_strerror(auth->radius.handle)));
		  return RAD_NACK;
		}

		memcpy(auth->params.msoft.recv_key, tmpkey, MPPE_KEY_LEN);
		free(tmpkey);
		auth->params.msoft.has_keys = TRUE;
		break;

	      case RAD_MICROSOFT_MS_MPPE_SEND_KEY:
		got_mppe_keys = TRUE;
		Log(LG_RADIUS2, ("[%s] RADIUS: %s: RAD_MICROSOFT_MS_MPPE_SEND_KEY",
		  auth->info.lnkname, __func__));
		tmpkey = rad_demangle_mppe_key(auth->radius.handle, data, len, &tmpkey_len);
		if (!tmpkey) {
		  Log(LG_RADIUS, ("[%s] RADIUS: %s: rad_demangle_mppe_key failed: %s",
		    auth->info.lnkname, __func__, rad_strerror(auth->radius.handle)));
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
		  auth->info.lnkname, __func__));

		if (len != 32) {
		  Log(LG_RADIUS, ("[%s] RADIUS: %s: Server returned garbage %d of expected %d Bytes",
		    auth->info.lnkname, __func__, (int)len, 32));
		  return RAD_NACK;
		}

		tmpkey = rad_demangle(auth->radius.handle, data, len);
		if (tmpkey == NULL) {
		  Log(LG_RADIUS, ("[%s] RADIUS: %s: rad_demangle failed: %s",
		    auth->info.lnkname, __func__, rad_strerror(auth->radius.handle)));
		  return RAD_NACK;
		}
		memcpy(auth->params.msoft.lm_hash, tmpkey, sizeof(auth->params.msoft.lm_hash));
		auth->params.msoft.has_lm_hash = TRUE;
		memcpy(auth->params.msoft.nt_hash_hash, &tmpkey[8], sizeof(auth->params.msoft.nt_hash_hash));
		auth->params.msoft.has_nt_hash = TRUE;
		free(tmpkey);
		break;
#endif

	      case RAD_MICROSOFT_MS_MPPE_ENCRYPTION_POLICY:
		auth->params.msoft.policy = rad_cvt_int(data);
		Log(LG_RADIUS2, ("[%s] RADIUS: %s: RAD_MICROSOFT_MS_MPPE_ENCRYPTION_POLICY: %d (%s)",
		  auth->info.lnkname, __func__, auth->params.msoft.policy, AuthMPPEPolicyname(auth->params.msoft.policy)));
		break;

	      case RAD_MICROSOFT_MS_MPPE_ENCRYPTION_TYPES:
	        {
		    char	buf[64];
		    auth->params.msoft.types = rad_cvt_int(data);
		    Log(LG_RADIUS2, ("[%s] RADIUS: %s: RAD_MICROSOFT_MS_MPPE_ENCRYPTION_TYPES: %d (%s)",
			auth->info.lnkname, __func__, auth->params.msoft.types, 
			AuthMPPETypesname(auth->params.msoft.types, buf, sizeof(buf))));
		}
		break;

	      default:
		Log(LG_RADIUS2, ("[%s] RADIUS: %s: Dropping MICROSOFT vendor specific attribute: %d ",
		  auth->info.lnkname, __func__, res));
		break;
	    }
	    break;

	  case RAD_VENDOR_MPD:

	    if (res == RAD_MPD_RULE) {
	      acl1 = acl = rad_cvt_string(data, len);
	      Log(LG_RADIUS2, ("[%s] RADIUS: %s: RAD_MPD_RULE: %s",
		auth->info.lnkname, __func__, acl));
	      acls = &(auth->params.acl_rule);
	    } else if (res == RAD_MPD_PIPE) {
	      acl1 = acl = rad_cvt_string(data, len);
	      Log(LG_RADIUS2, ("[%s] RADIUS: %s: RAD_MPD_PIPE: %s",
	        auth->info.lnkname, __func__, acl));
	      acls = &(auth->params.acl_pipe);
	    } else if (res == RAD_MPD_QUEUE) {
	      acl1 = acl = rad_cvt_string(data, len);
	      Log(LG_RADIUS2, ("[%s] RADIUS: %s: RAD_MPD_QUEUE: %s",
	        auth->info.lnkname, __func__, acl));
	      acls = &(auth->params.acl_queue);
	    } else if (res == RAD_MPD_TABLE) {
	      acl1 = acl = rad_cvt_string(data, len);
	      Log(LG_RADIUS2, ("[%s] RADIUS: %s: RAD_MPD_TABLE: %s",
	        auth->info.lnkname, __func__, acl));
	      acls = &(auth->params.acl_table);
	    } else if (res == RAD_MPD_TABLE_STATIC) {
	      acl1 = acl = rad_cvt_string(data, len);
	      Log(LG_RADIUS2, ("[%s] RADIUS: %s: RAD_MPD_TABLE_STATIC: %s",
	        auth->info.lnkname, __func__, acl));
	      acls = &(auth->params.acl_table);
	    } else if (res == RAD_MPD_FILTER) {
	      acl1 = acl = rad_cvt_string(data, len);
	      Log(LG_RADIUS2, ("[%s] RADIUS: %s: RAD_MPD_FILTER: %s",
	        auth->info.lnkname, __func__, acl));
	      acl2 = strsep(&acl1, "#");
	      i = atol(acl2);
	      if (i <= 0 || i > ACL_FILTERS) {
	        Log(LG_RADIUS, ("[%s] RADIUS: %s: wrong filter number: %i",
		  auth->info.lnkname, __func__, i));
	        free(acl);
	        break;
	      }
	      acls = &(auth->params.acl_filters[i - 1]);
	    } else if (res == RAD_MPD_LIMIT) {
	      acl1 = acl = rad_cvt_string(data, len);
	      Log(LG_RADIUS2, ("[%s] RADIUS: %s: RAD_MPD_LIMIT: %s",
	        auth->info.lnkname, __func__, acl));
	      acl2 = strsep(&acl1, "#");
	      if (strcasecmp(acl2, "in") == 0) {
	        i = 0;
	      } else if (strcasecmp(acl2, "out") == 0) {
	        i = 1;
	      } else {
	        Log(LG_ERR, ("[%s] RADIUS: %s: wrong limit direction: '%s'",
		  auth->info.lnkname, __func__, acl2));
	        free(acl);
	        break;
	      }
	      acls = &(auth->params.acl_limits[i]);
	    } else if (res == RAD_MPD_DROP_USER) {
	      auth->drop_user = rad_cvt_int(data);
	      Log(LG_RADIUS2, ("[%s] RADIUS: %s: RAD_MPD_DROP_USER: %d",
		auth->info.lnkname, __func__, auth->drop_user));
	      break;
	    } else {
	      Log(LG_RADIUS2, ("[%s] RADIUS: %s: Dropping MPD vendor specific attribute: %d",
		auth->info.lnkname, __func__, res));
	      break;
	    }

	    if (acl1 == NULL) {
	      Log(LG_ERR, ("[%s] RADIUS: %s: incorrect acl!",
		auth->info.lnkname, __func__));
	      break;
	    }
	    
	    acl3 = acl1;
	    strsep(&acl3, "=");
	    acl2 = acl1;
	    strsep(&acl2, "#");
	    i = atol(acl1);
	    if (i <= 0) {
	      Log(LG_ERR, ("[%s] RADIUS: %s: wrong acl number: %i",
		auth->info.lnkname, __func__, i));
	      free(acl);
	      break;
	    }
	    if ((acl3 == NULL) || (acl3[0] == 0)) {
	      Log(LG_ERR, ("[%s] RADIUS: %s: wrong acl", auth->info.lnkname, __func__));
	      free(acl);
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
	    if (acl2)
		strlcpy(acls1->name, acl2, sizeof(acls1->name));
	    strlcpy(acls1->rule, acl3, sizeof(acls1->rule));
	    while ((*acls != NULL) && ((*acls)->number < acls1->number))
	      acls = &((*acls)->next);

	    if (*acls == NULL) {
	      acls1->next = NULL;
	    } else if (((*acls)->number == acls1->number) &&
		(res != RAD_MPD_TABLE) &&
		(res != RAD_MPD_TABLE_STATIC)) {
	      Log(LG_ERR, ("[%s] RADIUS: %s: duplicate acl",
		auth->info.lnkname, __func__));
	      free(acl);
	      break;
	    } else {
	      acls1->next = *acls;
	    }
	    *acls = acls1;

	    free(acl);
	    break;

	  default:
	    Log(LG_RADIUS2, ("[%s] RADIUS: %s: Dropping vendor %d  attribute: %d ", 
	      auth->info.lnkname, __func__, vendor, res));
	    break;
	}
	break;

      default:
	Log(LG_RADIUS2, ("[%s] RADIUS: %s: Dropping attribute: %d ", 
	  auth->info.lnkname, __func__, res));
	break;
    }
  }

  /* sanity check, this happens when FreeRADIUS has no msoft-dictionary loaded */
  if (auth->proto == PROTO_CHAP && cp->recv_alg == CHAP_ALG_MSOFTv2
    && auth->mschapv2resp == NULL && auth->mschap_error == NULL) {
    Log(LG_RADIUS, ("[%s] RADIUS: %s: PANIC no MS-CHAPv2 response received",
      auth->info.lnkname, __func__));
    return RAD_NACK;
  }
  
  /* MPPE allowed or required, but no MPPE keys returned */
  /* print warning, because MPPE doesen't work */
  if (!got_mppe_keys && auth->params.msoft.policy != MPPE_POLICY_NONE) {
    Log(LG_RADIUS, ("[%s] RADIUS: %s: WARNING no MPPE-Keys received, MPPE will not work",
      auth->info.lnkname, __func__));
  }

  /* If no MPPE-Infos are returned by the RADIUS server, then allow all */
  /* MSoft IAS sends no Infos if all MPPE-Types are enabled and if encryption is optional */
  if (auth->params.msoft.policy == MPPE_POLICY_NONE &&
      auth->params.msoft.types == MPPE_TYPE_0BIT &&
      got_mppe_keys) {
    auth->params.msoft.policy = MPPE_POLICY_ALLOWED;
    auth->params.msoft.types = MPPE_TYPE_40BIT | MPPE_TYPE_128BIT | MPPE_TYPE_56BIT;
    Log(LG_RADIUS, ("[%s] RADIUS: %s: MPPE-Keys, but no MPPE-Infos received => allowing MPPE with all types",
      auth->info.lnkname, __func__));
  }
  
    /* If Framed-IP-Address is present and Framed-Netmask != 32 add route */
    if (auth->params.range_valid && auth->params.range.width == 32 &&
	    auth->params.netmask != 32) {
	struct in_addr tmpmask;
	widthtoin_addr(auth->params.netmask, &tmpmask);
	r = Malloc(MB_AUTH, sizeof(struct ifaceroute));
	r->dest.addr = auth->params.range.addr;
	r->dest.addr.u.ip4.s_addr &= tmpmask.s_addr;
	r->dest.width = auth->params.netmask;
	r->ok = 0;
	j = 0;
	SLIST_FOREACH(r1, &auth->params.routes, next) {
	  if (!u_rangecompare(&r->dest, &r1->dest)) {
	    Log(LG_RADIUS, ("[%s] RADIUS: %s: Duplicate route", auth->info.lnkname, __func__));
	    j = 1;
	  }
	};
	if (j == 0) {
	    SLIST_INSERT_HEAD(&auth->params.routes, r, next);
	} else {
	    Freee(MB_AUTH, r);
	}
    }
  
    return RAD_ACK;
}


