/*
 * See ``COPYRIGHT.mpd''
 *
 * $Id$
 *
 */

#include "radius.h"
#include "pptp.h"
#include "pppoe.h"
#include "chap.h"
#include "ngfunc.h"

#include <sys/types.h>

#include <radlib.h>
#include <radlib_vs.h>
#include <md5.h>

/* Global variables */

  static int RadiusSetCommand(int ac, char *av[], void *arg);
  static int RadiusAddServer (short request_type);
  static int RadiusInit(short request_type);
  static void RadiusClose(void);
  static const char * RadiusMPPEPolicyname(int policy);
  static const char * RadiusMPPETypesname(int types);

/* Set menu options */

  enum {
    SET_SERVER,
    SET_ME,
    SET_TIMEOUT,
    SET_RETRIES,
    SET_CONFIG,
    SET_UPDATE,
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
    { "timeout <seconds>",		"Set timeout in seconds",
	RadiusSetCommand, NULL, (void *) SET_TIMEOUT },
    { "retries <# retries>",		"set number of retries",
	RadiusSetCommand, NULL, (void *) SET_RETRIES },
    { "config <path to radius.conf>",	"set path to config file for libradius",
	RadiusSetCommand, NULL, (void *) SET_CONFIG },
    { "acct-update <seconds>",		"set update interval",
	RadiusSetCommand, NULL, (void *) SET_UPDATE },
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

/* Set menu options */
static int
RadiusSetCommand(int ac, char *av[], void *arg) 
{
  static char function[] = "RadiusSetCommand";
  RadConf const conf = &bund->radiusconf;
  RadServe_Conf server;
  RadServe_Conf t_server;
  int val, count;

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
	    lnk->name, function, RADIUS_MAX_SERVERS));
	  return (-1);
	}

	server = Malloc(MB_RADIUS, sizeof(*server));
	server->auth_port = 1812;
	server->acct_port = 1813;
	server->next = NULL;

	if (strlen(av[0]) > 255) {
	  Log(LG_ERR, ("Hostname too long!. > 255 char."));
	  return(-1);
	}

	if (strlen(av[1]) > 127) {
	  Log(LG_ERR, ("Shared Secret too long! > 127 char."));
	  return(-1);
	}

	if (ac > 2 && atoi(av[2]) < 65535 && atoi(av[2]) > 1) {
	  server->auth_port = atoi (av[2]);

	} else if ( ac > 2 ) {
	  Log(LG_ERR, ("Auth Port number too high > 65535"));
	  return(-1);
	}

	if (ac > 3 && atoi(av[3]) < 65535 && atoi(av[3]) > 1) {
	  server->acct_port = atoi (av[3]);
	} else if ( ac > 3 ) {
	  Log(LG_ERR, ("Acct Port number too high > 65535"));
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
	val = inet_aton(*av, &(conf->radius_me));
	  if (val == 0)
	    Log(LG_ERR, ("Bad NAS address."));
	break;

      case SET_TIMEOUT:
	val = atoi(*av);
	  if (val <= 0)
	    Log(LG_ERR, ("Timeout must be positive."));
	  else
	    conf->radius_timeout = val;
	break;

      case SET_UPDATE:
	val = atoi(*av);
	  if (val <= 0)
	    Log(LG_ERR, ("Update interval must be positive."));
	   else
	     conf->acct_update = val;
	break;

      case SET_RETRIES:
	val = atoi(*av);
	if (val <= 0)
	  Log(LG_ERR, ("Retries must be positive."));
	else
	  conf->radius_retries = val;
	break;

      case SET_CONFIG:
	if (strlen(av[0]) > PATH_MAX)
	  Log(LG_ERR, (" PATH_MAX exceeded for config file."));
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

int
RadiusInit(short request_type)
{
  struct radius *rad = &lnk->radius;

  RadiusClose();
  
  if (request_type == RAD_ACCESS_REQUEST) {
  
    rad->radh = rad_open();
    if (rad->radh == NULL) {
      Log(LG_RADIUS, ("[%s] RADIUS: rad_open failed", lnk->name));
      return (RAD_NACK);
    }

  /* RAD_ACCOUNTING_REQUEST */
  } else {
  
    rad->radh = rad_acct_open();
    if (rad->radh == NULL) {
      Log(LG_RADIUS, ("[%s] RADIUS: rad_acct_open failed", lnk->name));
      return (RAD_NACK);
    }

  }
  
  if (strlen(bund->radiusconf.file)) {
    Log(LG_RADIUS, ("[%s] RADIUS: using %s", lnk->name, bund->radiusconf.file));
    if (rad_config(rad->radh, bund->radiusconf.file) != 0) {
      Log(LG_RADIUS, ("[%s] RADIUS: rad_config: %s", lnk->name, rad_strerror(rad->radh)));
      RadiusClose();      
      return (RAD_NACK);
    }
  }

  if (RadiusAddServer(request_type) == RAD_NACK) {
    RadiusClose();    
    return (RAD_NACK);
  }
  
  return RAD_ACK;

}

void
RadiusClose(void) 
{
  struct radius *rad = &lnk->radius;

  if (rad->radh != NULL) rad_close(rad->radh);  
  rad->radh = NULL;
}

static int GetLinkID(void) {
    int port, i;
    
    port =- 1;    
    for (i = 0; i < gNumLinks; i++) {
      if (gLinks[i] && gLinks[i]==lnk) {
	port = i;
      }
    }
    return port;
};

void
RadiusDown(void) 
{
  struct radius		*rad = &lnk->radius;

  Log(LG_RADIUS, ("[%s] RADIUS: Down Event", lnk->name));
  if (rad->pers.state != NULL)
    Freee(MB_RADIUS, rad->pers.state);

  memset(&rad->pers, 0, sizeof(struct radius_persistent));
  RadiusDestroy();
}

void
RadiusDestroy(void) 
{
  struct radius 	*rad = &lnk->radius;
  struct radius_acl	*acls, *acls1;

  RadiusClose();
  free(rad->msdomain);
  rad->msdomain = NULL;
  free(rad->mschap_error);
  rad->mschap_error = NULL;
  free(rad->mschapv2resp);
  rad->mschapv2resp = NULL;
  free(rad->reply_message);
  rad->reply_message = NULL;
  Freee(MB_RADIUS, rad->eapmsg);
  rad->eapmsg = NULL;

  acls = rad->acl_rule;
  while (acls != NULL) {
    acls1 = acls->next;
    Freee(MB_RADIUS, acls);
    acls = acls1;
  };
  acls = rad->acl_pipe;
  while (acls != NULL) {
    acls1 = acls->next;
    Freee(MB_RADIUS, acls);
    acls = acls1;
  };
  acls = rad->acl_queue;
  while (acls != NULL) {
    acls1 = acls->next;
    Freee(MB_RADIUS, acls);
    acls = acls1;
  };
  memset(rad, 0, sizeof(struct radius) - sizeof(struct radius_persistent));
}

int RadiusStart(short request_type)
{
  static char		function[] = "RadiusStart";
  struct radius		*rad = &lnk->radius;
  char			host[MAXHOSTNAMELEN];
  struct in_addr	*peer_ip;
  char			*peeripname;
  u_char		*peer_mac;
  char			peermacname[18];

  if (RadiusInit(request_type) == RAD_NACK) 
    return RAD_NACK;

  if (gethostname(host, sizeof (host)) == -1) {
    Log(LG_RADIUS, ("[%s] RADIUS: %s: gethostname() failed", lnk->name, function));
    return (RAD_NACK);
  }

  if (rad_create_request(rad->radh, request_type) == -1) {
    Log(LG_RADIUS, ("[%s] RADIUS: rad_create_request: %s", lnk->name, rad_strerror(rad->radh)));
    return (RAD_NACK);
  }

  if (rad_put_string(rad->radh, RAD_NAS_IDENTIFIER, host) == -1)  {
    Log(LG_RADIUS, ("[%s] RADIUS: %s: rad_put_string(host) failed %s", lnk->name,
      function, rad_strerror(rad->radh)));
    RadiusClose();    
    return (RAD_NACK);
  }
  
  if (bund->radiusconf.radius_me.s_addr != 0) {
    if (rad_put_addr(rad->radh, RAD_NAS_IP_ADDRESS, bund->radiusconf.radius_me) == -1)  {
      Log(LG_RADIUS, ("[%s] RADIUS: %s: rad_put_addr(RAD_NAS_IP_ADDRESS) failed %s", lnk->name,
	function, rad_strerror(rad->radh)));
      RadiusClose();
      return (RAD_NACK);
    }
  }

  /* Insert the Message Authenticator RFC 3579
   * This is just a dummy attribute, libradius calculates the HMAC-MD5
   * implicitely, if this attribute was added.
   */
  if (Enabled(&bund->radiusconf.options, RADIUS_CONF_MESSAGE_AUTHENTIC)
      && request_type != RAD_ACCOUNTING_REQUEST)
    if (rad_put_int(rad->radh, RAD_MESSAGE_AUTHENTIC, 0) == -1) {
      Log(LG_RADIUS, ("[%s] RADIUS: %s: rad_put_int(RAD_MESSAGE_AUTHENTIC) failed %s", lnk->name,
        function, rad_strerror(rad->radh)));
      RadiusClose();
      return (RAD_NACK);
    }

  if (rad_put_int(rad->radh, RAD_NAS_PORT, GetLinkID()) == -1)  {
    Log(LG_RADIUS, ("[%s] RADIUS: %s: rad_put_int(RAD_NAS_PORT) failed %s", lnk->name,
      function, rad_strerror(rad->radh)));
    RadiusClose();
    return (RAD_NACK);
  }

  if (rad_put_int(rad->radh, RAD_NAS_PORT_TYPE, RAD_VIRTUAL) == -1) {
    Log(LG_RADIUS, ("[%s] RADIUS: %s: rad_put_int(RAD_NAS_PORT_TYPE) failed %s", lnk->name,
      function, rad_strerror(rad->radh)));
    RadiusClose();
    return (RAD_NACK);
  }

  if (rad_put_int(rad->radh, RAD_SERVICE_TYPE, RAD_FRAMED) == -1) {
    Log(LG_RADIUS, ("[%s] RADIUS: %s: rad_put_int(RAD_SERVICE_TYPE) failed %s", lnk->name,
      function, rad_strerror(rad->radh)));
    RadiusClose();
    return (RAD_NACK);
  }
  
  if (rad_put_int(rad->radh, RAD_FRAMED_PROTOCOL, RAD_PPP) == -1) {
    Log(LG_RADIUS, ("[%s] RADIUS: %s: rad_put_int(RAD_FRAMED_PROTOCOL) failed %s", lnk->name,
      function, rad_strerror(rad->radh)));
    RadiusClose();
    return (RAD_NACK);
  }

  if (rad->pers.state != NULL) {
      Log(LG_RADIUS, ("[%s] RADIUS: putting RAD_STATE", lnk->name));

    if (rad_put_attr(rad->radh, RAD_STATE, rad->pers.state, rad->pers.state_len) == -1) {
      Log(LG_RADIUS, ("[%s] RADIUS: %s: rad_put_int(RAD_STATE) failed %s", lnk->name,
        function, rad_strerror(rad->radh)));
      RadiusClose();
      return (RAD_NACK);
    }
  }


  peer_ip = PptpGetPeerIp();
  if (peer_ip != NULL && peer_ip->s_addr != 0) {
    peeripname = inet_ntoa(*peer_ip);
    if (peeripname != NULL) {
      if (rad_put_string(rad->radh, RAD_CALLING_STATION_ID, peeripname) == -1) {
	Log(LG_RADIUS, ("[%s] RADIUS: %s: rad_put_string(RAD_CALLING_STATION_ID) failed %s", lnk->name,
	  function, rad_strerror(rad->radh)));
	RadiusClose();
	return (RAD_NACK);
      }  
    } 
  }

  peer_mac = PppoeGetPeerAddr();
  if ((peer_mac != NULL) && 
      ((peer_mac[0] != 0) || (peer_mac[1] != 0) || (peer_mac[2] != 0) || 
       (peer_mac[3] !=0 ) || (peer_mac[4] != 0) || (peer_mac[5] != 0))
    ) {
    snprintf(peermacname, sizeof(peermacname), "%02x%02x%02x%02x%02x%02x",
      peer_mac[0], peer_mac[1], peer_mac[2], peer_mac[3], peer_mac[4], peer_mac[5]);
    if (rad_put_string(rad->radh, RAD_CALLING_STATION_ID, peermacname) == -1) {
      Log(LG_RADIUS, ("[%s] RADIUS: %s: rad_put_string(RAD_CALLING_STATION_ID) failed %s", lnk->name,
	function, rad_strerror(rad->radh)));
      RadiusClose();
      return (RAD_NACK);
    }
  }
  
  return RAD_ACK;
}

int
RadiusPutAuth(const char *name, const char *password, int passlen,
        const char *challenge, int challenge_size, u_char chapid, int auth_type)
{
  static char		function[] = "RadiusPutAuth";
  struct radius		*rad = &lnk->radius;
  struct rad_chapvalue		rad_chapval;
  struct rad_mschapvalue	rad_mschapval;
  struct rad_mschapv2value	rad_mschapv2val;
  struct mschapvalue		*mschapval;
  struct mschapv2value		*mschapv2val;  

  if (name == NULL || password == NULL) {
    Log(LG_RADIUS, ("[%s] RADIUS: %s: name or password NULL", lnk->name, function));
    return (RAD_NACK);
  }

  /* Remember authname */
  strncpy(rad->authname, name, AUTH_MAX_AUTHNAME);

  if (rad_put_string(rad->radh, RAD_USER_NAME, name) == -1) {
    Log(LG_RADIUS, ("[%s] RADIUS: %s: rad_put_string(username) failed %s", lnk->name,
      function, rad_strerror(rad->radh)));
    RadiusClose();
    return (RAD_NACK);
  }

  /* Remember Auth-Type */
  rad->auth_type = auth_type;
  switch (auth_type) {

    case CHAP_ALG_MSOFT:
      Log(LG_RADIUS, ("[%s] RADIUS: %s: RADIUS_CHAP (MSOFTv1) peer name: %s", lnk->name, function, name));
       if (passlen != 49) {
        Log(LG_RADIUS, ("[%s] RADIUS: %s: RADIUS_CHAP (MSOFTv1) unrecognised key length %d/%d",
	  lnk->name, function, passlen, 49));
	RadiusClose();        
        return RAD_NACK;
      }

      if (rad_put_vendor_attr(rad->radh, RAD_VENDOR_MICROSOFT, RAD_MICROSOFT_MS_CHAP_CHALLENGE,
	  challenge, challenge_size) == -1)  {
        Log(LG_RADIUS, ("[%s] RADIUS: %s: rad_put_vendor_attr(RAD_MICROSOFT_MS_CHAP_CHALLENGE) failed %s",
	  lnk->name, function, rad_strerror(rad->radh)));
	RadiusClose();          
        return (RAD_NACK);
      }

      mschapval = (struct mschapvalue *)password;
      rad_mschapval.ident = chapid;
      rad_mschapval.flags = 0x01;
      memcpy(rad_mschapval.lm_response, mschapval->lmHash, 24);
      memcpy(rad_mschapval.nt_response, mschapval->ntHash, 24);

      if (rad_put_vendor_attr(rad->radh, RAD_VENDOR_MICROSOFT, RAD_MICROSOFT_MS_CHAP_RESPONSE,
	&rad_mschapval, sizeof rad_mschapval) == -1)  {
        Log(LG_RADIUS, ("[%s] RADIUS: %s: rad_put_vendor_attr(RAD_MICROSOFT_MS_CHAP_RESPONSE) failed %s",
	  lnk->name, function, rad_strerror(rad->radh)));
	RadiusClose();
        return (RAD_NACK);
      }
      break;

    case CHAP_ALG_MSOFTv2:
      
      Log(LG_RADIUS, ("[%s] RADIUS: %s: RADIUS_CHAP (MSOFTv2) peer name: %s",
	lnk->name, function, name));
      if (rad_put_vendor_attr(rad->radh, RAD_VENDOR_MICROSOFT,
	  RAD_MICROSOFT_MS_CHAP_CHALLENGE, challenge, challenge_size) == -1)  {
        Log(LG_RADIUS, ("[%s] RADIUS: %s: rad_put_vendor_attr(RAD_MICROSOFT_MS_CHAP_CHALLENGE) failed %s",
	  lnk->name, function, rad_strerror(rad->radh)));
	RadiusClose();
        return (RAD_NACK);
      }

      if (passlen != sizeof(*mschapv2val)) {
        Log(LG_RADIUS, ("[%s] RADIUS: %s: RADIUS_CHAP (MSOFTv2) unrecognised key length %d/%d", lnk->name,
	  function, passlen, sizeof(*mschapv2val)));
	RadiusClose();        
        return RAD_NACK;
      }
      
      mschapv2val = (struct mschapv2value *)password;
      rad_mschapv2val.ident = chapid;
      rad_mschapv2val.flags = mschapv2val->flags;
      memcpy(rad_mschapv2val.response,		mschapv2val->ntHash,	sizeof rad_mschapv2val.response);
      memset(rad_mschapv2val.reserved,		'\0', 			sizeof rad_mschapv2val.reserved);
      memcpy(rad_mschapv2val.pchallenge,	mschapv2val->peerChal,	sizeof rad_mschapv2val.pchallenge);

      if (rad_put_vendor_attr(rad->radh, RAD_VENDOR_MICROSOFT, RAD_MICROSOFT_MS_CHAP2_RESPONSE,
	  &rad_mschapv2val, sizeof rad_mschapv2val) == -1)  {
        Log(LG_RADIUS, ("[%s] RADIUS: %s: rad_put_vendor_attr(RAD_MICROSOFT_MS_CHAP2_RESPONSE) failed %s",
	  lnk->name, function, rad_strerror(rad->radh)));
	RadiusClose();        
        return (RAD_NACK);
      }
      
      break;

    case CHAP_ALG_MD5:
      /* RADIUS requires the CHAP Ident in the first byte of the CHAP-Password */
      rad_chapval.ident = chapid;
      memcpy(rad_chapval.response, password, passlen);
      Log(LG_RADIUS, ("[%s] RADIUS: %s: RADIUS_CHAP (MD5) peer name: %s", lnk->name, function, name));
      if (rad_put_attr(rad->radh, RAD_CHAP_PASSWORD, &rad_chapval, passlen + 1) == -1 ||
        rad_put_attr(rad->radh, RAD_CHAP_CHALLENGE, challenge, challenge_size) == -1) {
        Log(LG_RADIUS, ("[%s] RADIUS: %s: rad_put_string(password) failed %s", lnk->name,
          function, rad_strerror(rad->radh)));
	RadiusClose();
        return (RAD_NACK);
      }
      break;

    case RADIUS_PAP:
        Log(LG_RADIUS, ("[%s] RADIUS: %s: RADIUS_PAP DEBUG: peer name: %s",  lnk->name, function, name));
        if (rad_put_string(rad->radh, RAD_USER_PASSWORD, password) == -1) {
          Log(LG_RADIUS, ("[%s] RADIUS: %s: rad_put_string(password) failed %s", lnk->name,
            function, rad_strerror(rad->radh)));
	  RadiusClose();
          return (RAD_NACK);
        }
      break;

    default:
      Log(LG_RADIUS, ("[%s] RADIUS: %s: RADIUS auth type unkown", lnk->name, function));
      RadiusClose();
      return (RAD_NACK);
      break;
  }
  
  return RAD_ACK;

}

int RadiusSendRequest(void)
{
  static char		function[] = "RadiusSendRequest";
  struct radius		*rad = &lnk->radius;
  struct timeval	timelimit;
  struct timeval	tv;
  int 			fd, n;

  n = rad_init_send_request(rad->radh, &fd, &tv);
  if (n != 0) {
    Log(LG_RADIUS, ("[%s] RADIUS: %s: rad_init_send_request failed: %d %s",
      lnk->name, function, n, rad_strerror(rad->radh)));
     return RAD_NACK;
  }

  gettimeofday(&timelimit, NULL);
  timeradd(&tv, &timelimit, &timelimit);

  for ( ; ; ) {
    fd_set readfds;

    FD_ZERO(&readfds);
    FD_SET(fd, &readfds);

    n = select(fd + 1, &readfds, NULL, NULL, &tv);

    if (n == -1) {
      Log(LG_RADIUS, ("[%s] RADIUS: %s: select failed: %s", lnk->name, function, strerror(errno)));
      return RAD_NACK;
    }

    if (!FD_ISSET(fd, &readfds)) {
      /* Compute a new timeout */
      gettimeofday(&tv, NULL);
      timersub(&timelimit, &tv, &tv);
      if (tv.tv_sec > 0 || (tv.tv_sec == 0 && tv.tv_usec > 0))
	/* Continue the select */
	continue;
    }

    n = rad_continue_send_request(rad->radh, n, &fd, &tv);
    if (n != 0)
      break;

    gettimeofday(&timelimit, NULL);
    timeradd(&tv, &timelimit, &timelimit);
  }

  rad->response_type = n;
  switch (n) {

    case RAD_ACCESS_ACCEPT:
      Log(LG_RADIUS, ("[%s] RADIUS: %s: RAD_ACCESS_ACCEPT for user %s", lnk->name,
        function, rad->authname));
      rad->authenticated = 1;
      break;

    case RAD_ACCESS_CHALLENGE:
      Log(LG_RADIUS, ("[%s] RADIUS: %s: RAD_ACCESS_CHALLENGE for user %s", lnk->name,
        function, rad->authname));
      return RAD_ACK;

    case RAD_ACCESS_REJECT:
      Log(LG_RADIUS, ("[%s] RADIUS: %s: RAD_ACCESS_REJECT for user %s", lnk->name,
        function, rad->authname));
      rad->authenticated = 0;
      break;

    case RAD_ACCOUNTING_RESPONSE:
      Log(LG_RADIUS, ("[%s] RADIUS: %s: RAD_ACCOUNTING_RESPONSE for user %s", lnk->name,
        function, rad->authname));
      return RAD_ACK;

    case -1:
      Log(LG_RADIUS, ("[%s] RADIUS: %s: rad_send_request failed %s", lnk->name,
        function, rad_strerror(rad->radh)));
      RadiusClose();
      return(RAD_NACK);
      break;
      
    default:
      Log(LG_RADIUS, ("[%s] RADIUS: %s: rad_send_request: unexpected return value %s", lnk->name, 
        function, rad_strerror(rad->radh)));
      RadiusClose();      
      return(RAD_NACK);
    }
    
    return RAD_ACK;

}

int
RadiusPAPAuthenticate(const char *name, const char *password)
{
  struct radius	*rad = &lnk->radius;

  RadiusDestroy();
  if (RadiusStart(RAD_ACCESS_REQUEST) == RAD_NACK)
    return RAD_NACK;

  if (RadiusPutAuth(name, password, 0, NULL, NULL, 0, RADIUS_PAP) == RAD_NACK)
    return RAD_NACK;

  if (RadiusSendRequest() == RAD_NACK) 
    return RAD_NACK;

  if (RadiusGetParams(FALSE) == RAD_NACK)
    return RAD_NACK;

  if (rad->authenticated) {
    return RAD_ACK;
  } else {
    return RAD_NACK;
  }

}

int
RadiusCHAPAuthenticate(const char *name, const char *password, int passlen,
        const char *challenge, int challenge_size, u_char chapid, int chap_type) 
{
  struct radius	*rad = &lnk->radius;

  RadiusDestroy();    
  if (RadiusStart(RAD_ACCESS_REQUEST) == RAD_NACK) 
    return RAD_NACK;

  if (RadiusPutAuth(name, password, passlen, challenge, challenge_size, chapid, chap_type) == RAD_NACK) 
    return RAD_NACK;
  
  if (RadiusSendRequest() == RAD_NACK) 
    return RAD_NACK;

  if (RadiusGetParams(FALSE) == RAD_NACK)
    return RAD_NACK;
  
  if (rad->authenticated) {
    return RAD_ACK;
  } else {
    return RAD_NACK;
  }
  
}

int
RadiusEAPProxy(const char *identity, const char *pkt, int len)
{
  static char function[] = "RadiusEAPProxy";
  struct radius	*rad = &lnk->radius;
  int		pos = 0, mlen = RAD_MAX_ATTR_LEN;

  RadiusDestroy();
  if (RadiusStart(RAD_ACCESS_REQUEST) == RAD_NACK)
    return RAD_NACK;

  /* Remember authname */
  strncpy(rad->authname, identity, AUTH_MAX_AUTHNAME);

  if (rad_put_string(rad->radh, RAD_USER_NAME, identity) == -1) {
    Log(LG_RADIUS, ("[%s] RADIUS-EAP: %s: rad_put_string(identity) failed %s", lnk->name,
      function, rad_strerror(rad->radh)));
    RadiusClose();
    return (RAD_NACK);
  }

  for (pos = 0; pos <= len; pos += RAD_MAX_ATTR_LEN) {
    char	chunk[RAD_MAX_ATTR_LEN];

    if (pos + RAD_MAX_ATTR_LEN > len)
      mlen = len - pos;

    memcpy(chunk, &pkt[pos], mlen);
    if (rad_put_attr(rad->radh, RAD_EAP_MESSAGE, chunk, mlen) == -1) {
      Log(LG_RADIUS, ("[%s] RADIUS-EAP: %s: rad_put_attr(RAD_EAP_MESSAGE) failed %s",
	lnk->name, function, rad_strerror(rad->radh)));
      RadiusClose();
      return (RAD_NACK);
    }
#ifdef DEBUG
    Log(LG_RADIUS, ("[%s] RADIUS-EAP: chunk:%d len:%d",
      lnk->name, pos / RAD_MAX_ATTR_LEN, mlen));
#endif
  }

  rad->auth_type = RADIUS_EAP;

  if (RadiusSendRequest() == RAD_NACK)
    return RAD_NACK;

  switch (rad->response_type) {

    case RAD_ACCESS_ACCEPT:
      return RadiusGetParams(FALSE);
      break;

    case RAD_ACCESS_CHALLENGE:
      break;

    case RAD_ACCESS_REJECT:
      RadiusGetParams(FALSE);
      return RAD_NACK;
  }
  return RadiusGetParams(TRUE);
}

int
RadiusGetParams(int eap_proxy)
{
  char		function[] = "RadiusGetParams";
  struct radius	*rad = &lnk->radius;
  MppcInfo	const mppc = &bund->ccp.mppc;
  int		res, i, j, tmpkey_len;
  size_t	len;
  const void	*data;
  u_int32_t	vendor;
  char		*route, *acl1, *acl2;
  u_char	*tmpkey;
  short		got_mppe_keys = FALSE;
  struct radius_acl	**acls, *acls1;
  struct ifaceroute	r;
  struct in_range	range;

  while ((res = rad_get_attr(rad->radh, &data, &len)) > 0) {

    switch (res) {

      case RAD_STATE:
	Log(LG_RADIUS, ("[%s] RADIUS: %s: RAD_STATE", lnk->name, function));
	rad->pers.state_len = len;
	if (rad->pers.state != NULL)
	  Freee(MB_RADIUS, rad->pers.state);
	rad->pers.state = Malloc(MB_RADIUS, len);
	memcpy(rad->pers.state, data, len);
	continue;

	/* libradius already checks the message-authenticator, so simply ignore it */
      case RAD_MESSAGE_AUTHENTIC:
	Log(LG_RADIUS, ("[%s] RADIUS: %s: RAD_MESSAGE_AUTHENTIC", lnk->name, function));
	continue;

      case RAD_EAP_MESSAGE:
	if (rad->eapmsg != NULL) {
	  char *tbuf;
#ifdef DEBUG
	  Log(LG_RADIUS, ("[%s] RADIUS: %s: RAD_EAP_MESSAGE (continued) Len:%d",
	    lnk->name, function, rad->eapmsg_len + len));
#endif
	  tbuf = Malloc(MB_RADIUS, rad->eapmsg_len + len);
	  memcpy(tbuf, rad->eapmsg, rad->eapmsg_len);
	  memcpy(&tbuf[rad->eapmsg_len], data, len);
	  rad->eapmsg_len += len;
	  Freee(MB_RADIUS, rad->eapmsg);
	  rad->eapmsg = tbuf;
	} else {
	  Log(LG_RADIUS, ("[%s] RADIUS: %s: RAD_EAP_MESSAGE", lnk->name, function));
	  rad->eapmsg = Malloc(MB_RADIUS, len);
	  memcpy(rad->eapmsg, data, len);
	  rad->eapmsg_len = len;
	}
	continue;
    }

    if (!eap_proxy)
      switch (res) {

      case RAD_FRAMED_IP_ADDRESS:
        rad->ip = rad_cvt_addr(data);
        Log(LG_RADIUS, ("[%s] RADIUS: %s: RAD_FRAMED_IP_ADDRESS: %s ",
          lnk->name, function, inet_ntoa(rad->ip)));
        break;

      case RAD_FRAMED_IP_NETMASK:
        rad->mask = rad_cvt_addr(data);
        Log(LG_RADIUS, ("[%s] RADIUS: %s: RAD_FRAMED_IP_NETMASK: %s ",
          lnk->name, function, inet_ntoa(rad->mask)));
        break;

      case RAD_FRAMED_ROUTE:
	route = rad_cvt_string(data, len);
	Log(LG_RADIUS, ("[%s] RADIUS: %s: RAD_FRAMED_ROUTE: %s ",
	  lnk->name, function, route));
	if (!ParseAddr(route, &range)) {
	  Log(LG_ERR, ("route: bad route \"%s\"", route));
	  free(route);
	  break;
	}
	free(route);
	r.netmask.s_addr = range.width ? htonl(~0 << (32 - range.width)) : 0;
	r.dest.s_addr = (range.ipaddr.s_addr & r.netmask.s_addr);
	j = 0;
	for (i = 0;i < rad->n_routes; i++) {
	  if ((r.dest.s_addr == rad->routes[i].dest.s_addr)
	      && (r.netmask.s_addr == rad->routes[i].netmask.s_addr))
	    j = 1;
	};
	if (j == 0)
	  rad->routes[rad->n_routes++] = r;
	break;

      case RAD_SESSION_TIMEOUT:
        rad->session_timeout = rad_cvt_int(data);
        Log(LG_RADIUS, ("[%s] RADIUS: %s: RAD_SESSION_TIMEOUT: %lu ",
          lnk->name, function, rad->session_timeout));
        break;

      case RAD_IDLE_TIMEOUT:
        rad->idle_timeout = rad_cvt_int(data);
        Log(LG_RADIUS, ("[%s] RADIUS: %s: RAD_IDLE_TIMEOUT: %lu ",
          lnk->name, function, rad->idle_timeout));
        break;

     case RAD_ACCT_INTERIM_INTERVAL:
	rad->interim_interval = rad_cvt_int(data);
        Log(LG_RADIUS, ("[%s] RADIUS: %s: RAD_ACCT_INTERIM_INTERVAL: %lu ",
          lnk->name, function, rad->interim_interval));
	break;

      case RAD_FRAMED_MTU:
	rad->mtu = rad_cvt_int(data);
	if (rad->mtu < IFACE_MIN_MTU || rad->mtu > IFACE_MAX_MTU) {
	  Log(LG_RADIUS, ("[%s] RADIUS: %s: RAD_FRAMED_MTU: invalid MTU: %lu ",
	    lnk->name, function, rad->mtu));
	  rad->mtu = 0;
	  break;
	}
	Log(LG_RADIUS, ("[%s] RADIUS: %s: RAD_FRAMED_MTU: %lu ",
	  lnk->name, function, rad->mtu));
        break;

      case RAD_FRAMED_COMPRESSION:
	rad->vj = rad_cvt_int(data) == 1 ? 1 : 0;
	Log(LG_RADIUS, ("[%s] RADIUS: %s: RAD_FRAMED_COMPRESSION: %d ",
	  lnk->name, function, rad->vj));
        break;

      case RAD_FRAMED_PROTOCOL:
	rad->protocol = rad_cvt_int(data);
	Log(LG_RADIUS, ("[%s] RADIUS: %s: RAD_FRAMED_PROTOCOL: %lu ",
	  lnk->name, function, rad->protocol));
        break;

      case RAD_SERVICE_TYPE:
	rad->service_type = rad_cvt_int(data);
	Log(LG_RADIUS, ("[%s] RADIUS: %s: RAD_FRAMED_PROTOCOL: %lu ",
	  lnk->name, function, rad->service_type));
        break;

      case RAD_CLASS:
	rad->class = rad_cvt_int(data);
	Log(LG_RADIUS, ("[%s] RADIUS: %s: RAD_CLASS: %lu ",
	  lnk->name, function, rad->class));
        break;

      case RAD_REPLY_MESSAGE:
	free(rad->reply_message);
	rad->reply_message = rad_cvt_string(data, len);
	Log(LG_RADIUS, ("[%s] RADIUS: %s: RAD_REPLY_MESSAGE: %s ",
	  lnk->name, function, rad->reply_message));
        break;

      case RAD_VENDOR_SPECIFIC:
	if ((res = rad_get_vendor_attr(&vendor, &data, &len)) == -1) {
	  Log(LG_RADIUS, ("[%s] RADIUS: %s: rad_get_vendor_attr failed: %s ",
	    lnk->name, function, rad_strerror(rad->radh)));
	  return RAD_NACK;
	}

	switch (vendor) {

	  case RAD_VENDOR_MICROSOFT:
	    switch (res) {

	      case RAD_MICROSOFT_MS_CHAP_ERROR:
		/* there is a nullbyte on the first pos, don't know why */
		if (((const char *)data)[0] == '\0') {
		  ((const char *)data)++;
		  len--;
		}
		free(rad->mschap_error);
		rad->mschap_error = rad_cvt_string(data, len);

		Log(LG_RADIUS, ("[%s] RADIUS: %s: MS-CHAP-Error: %s",
		  lnk->name, function, rad->mschap_error));
		break;

	      /* this was taken from userland ppp */
	      case RAD_MICROSOFT_MS_CHAP2_SUCCESS:
		free(rad->mschapv2resp);
		if (len == 0)
		  rad->mschapv2resp = NULL;
		else {
		  if (len < 3 || ((const char *)data)[1] != '=') {
		    /*
		     * Only point at the String field if we don't think the
		     * peer has misformatted the response.
		     */
		    ((const char *)data)++;
		    len--;
		  } else
		    Log(LG_RADIUS, ("[%s] RADIUS: %s: Warning: The MS-CHAP2-Success attribute is mis-formatted. Compensating",
		      lnk->name, function));
		    if ((rad->mschapv2resp = rad_cvt_string((const char *)data, len)) == NULL) {
		    Log(LG_RADIUS, ("[%s] RADIUS: %s: rad_cvt_string failed: %s",
		      lnk->name, function, rad_strerror(rad->radh)));
		    return RAD_NACK;
		  }
		  Log(LG_RADIUS, ("[%s] RADIUS: %s: RAD_MICROSOFT_MS_CHAP2_SUCCESS: %s",
		    lnk->name, function, rad->mschapv2resp));
		}
		break;

	      case RAD_MICROSOFT_MS_CHAP_DOMAIN:
		free(rad->msdomain);
		rad->msdomain = rad_cvt_string(data, len);
		Log(LG_RADIUS, ("[%s] RADIUS: %s: RAD_MICROSOFT_MS_CHAP_DOMAIN: %s",
		  lnk->name, function, rad->msdomain));
		break;

              /* MPPE Keys MS-CHAPv2 and EAP-TLS */
	      case RAD_MICROSOFT_MS_MPPE_RECV_KEY:
		got_mppe_keys = TRUE;
		Log(LG_RADIUS, ("[%s] RADIUS: %s: RAD_MICROSOFT_MS_MPPE_RECV_KEY",
		  lnk->name, function));
		tmpkey = rad_demangle_mppe_key(rad->radh, data, len, &tmpkey_len);
		if (!tmpkey) {
		  Log(LG_RADIUS, ("[%s] RADIUS: %s: rad_demangle_mppe_key failed: %s",
		    lnk->name, function, rad_strerror(rad->radh)));
		  return RAD_NACK;
		}

		memcpy(mppc->recv_key0, tmpkey, MPPE_KEY_LEN);
		free(tmpkey);
		break;

	      case RAD_MICROSOFT_MS_MPPE_SEND_KEY:
		got_mppe_keys = TRUE;
		Log(LG_RADIUS, ("[%s] RADIUS: %s: RAD_MICROSOFT_MS_MPPE_SEND_KEY",
		  lnk->name, function));
		tmpkey = rad_demangle_mppe_key(rad->radh, data, len, &tmpkey_len);
		if (!tmpkey) {
		  Log(LG_RADIUS, ("[%s] RADIUS: %s: rad_demangle_mppe_key failed: %s",
		    lnk->name, function, rad_strerror(rad->radh)));
		  return RAD_NACK;
		}

		memcpy(mppc->xmit_key0, tmpkey, MPPE_KEY_LEN);
		free(tmpkey);
		break;

              /* MPPE Keys MS-CHAPv1 */
	      case RAD_MICROSOFT_MS_CHAP_MPPE_KEYS:
		got_mppe_keys = TRUE;
		Log(LG_RADIUS, ("[%s] RADIUS: %s: RAD_MICROSOFT_MS_CHAP_MPPE_KEYS",
		  lnk->name, function));

		if (len != 32) {
		  Log(LG_RADIUS, ("[%s] RADIUS: %s: Server returned garbage %d of expected %d Bytes",
		    lnk->name, function, len, 32));
		  return RAD_NACK;
		}

		tmpkey = rad_demangle(rad->radh, data, len);
		if (tmpkey == NULL) {
		  Log(LG_RADIUS, ("[%s] RADIUS: %s: rad_demangle failed: %s",
		    lnk->name, function, rad_strerror(rad->radh)));
		  return RAD_NACK;
		}
		memcpy(rad->mppe.lm_key, tmpkey, len);
		free(tmpkey);
		break;

	      case RAD_MICROSOFT_MS_MPPE_ENCRYPTION_POLICY:
		rad->mppe.policy = rad_cvt_int(data);
		Log(LG_RADIUS, ("[%s] RADIUS: %s: RAD_MICROSOFT_MS_MPPE_ENCRYPTION_POLICY: %d (%s)",
		  lnk->name, function, rad->mppe.policy, RadiusMPPEPolicyname(rad->mppe.policy)));
		break;

	      case RAD_MICROSOFT_MS_MPPE_ENCRYPTION_TYPES:
		rad->mppe.types = rad_cvt_int(data);
		Log(LG_RADIUS, ("[%s] RADIUS: %s: RAD_MICROSOFT_MS_MPPE_ENCRYPTION_TYPES: %d (%s)",
		  lnk->name, function, rad->mppe.types, RadiusMPPETypesname(rad->mppe.types)));
		break;

	      default:
		Log(LG_RADIUS, ("[%s] RADIUS: %s: Dropping MICROSOFT vendor specific attribute: %d ",
		  lnk->name, function, res));
		break;
	    }
	    break;

	  case RAD_VENDOR_MPD:

	    if (res == RAD_MPD_RULE) {
	      acl2 = rad_cvt_string(data, len);
	      Log(LG_RADIUS, ("[%s] RADIUS: %s: RAD_MPD_RULE: %s",
		lnk->name, function, acl2));
	      acls = &(rad->acl_rule);
	    } else if (res == RAD_MPD_PIPE) {
	      acl2 = rad_cvt_string(data, len);
	      Log(LG_RADIUS, ("[%s] RADIUS: %s: RAD_MPD_PIPE: %s",
	        lnk->name, function, acl2));
	      acls = &(rad->acl_pipe);
	    } else if (res == RAD_MPD_QUEUE) {
	      acl2 = rad_cvt_string(data, len);
	      Log(LG_RADIUS, ("[%s] RADIUS: %s: RAD_MPD_QUEUE: %s",
	        lnk->name, function, acl2));
	      acls = &(rad->acl_queue);
	    } else {
	      Log(LG_RADIUS, ("[%s] RADIUS: %s: Dropping MPD vendor specific attribute: %d ",
		lnk->name, function, res));
	      break;
	    }

	    acl1 = strsep(&acl2, "=");
	    i = atol(acl1);
	    if (i <= 0) {
	      Log(LG_RADIUS, ("[%s] RADIUS: %s: wrong acl number: %i",
		lnk->name, function, i));
	      free(acl1);
	      break;
	    }
	    if ((acl2 == NULL) && (acl2[0] == 0)) {
	      Log(LG_RADIUS, ("[%s] RADIUS: %s: wrong acl", lnk->name, function));
	      free(acl1);
	      break;
	    }
	    acls1 = Malloc(MB_RADIUS, sizeof(struct radius_acl));
	    acls1->number = i;
	    strncpy(acls1->rule, acl2, ACL_LEN);
	    while ((*acls != NULL) && ((*acls)->number < i))
	      acls = &((*acls)->next);

	    if (*acls == NULL) {
	      acls1->next = NULL;
	    } else if ((*acls)->number == i) {
	      Log(LG_RADIUS, ("[%s] RADIUS: %s: duplicate acl",
		lnk->name, function));
	      free(acl1);
	      break;
	    } else {
	      acls1->next = *acls;
	    }
	    *acls = acls1;

	    free(acl1);
	    break;

    	  default:
    	    Log(LG_RADIUS, ("[%s] RADIUS: %s: Dropping vendor %d  attribute: %d ", lnk->name, function, vendor, res));
    	    break;
	}
	break;

      default:
	Log(LG_RADIUS, ("[%s] RADIUS: %s: Dropping attribute: %d ", lnk->name, function, res));
	break;
    }
  }

  /* sanity check, this happens when FreeRADIUS has no msoft-dictionary loaded */
  if (rad->auth_type == CHAP_ALG_MSOFTv2 && rad->mschapv2resp == NULL) {
    Log(LG_RADIUS, ("[%s] RADIUS: %s: PANIC no MS-CHAPv2 response received",
      lnk->name, function));
    return RAD_NACK;
  }
  
  /* MPPE allowed or required, but no MPPE keys returned */
  /* print warning, because MPPE doesen't work */
  if (!got_mppe_keys && rad->mppe.policy != MPPE_POLICY_NONE) {
    Log(LG_RADIUS, ("[%s] RADIUS: %s: WARNING no MPPE-Keys received, MPPE will not work",
      lnk->name, function));
  }

  /* If no MPPE-Infos are returned by the RADIUS server, then allow all */
  /* MSoft IAS sends no Infos if all MPPE-Types are enabled and if encryption is optional */
  if (rad->mppe.policy == MPPE_POLICY_NONE &&
      rad->mppe.types == MPPE_TYPE_0BIT &&
      got_mppe_keys) {
    rad->mppe.policy = MPPE_POLICY_ALLOWED;
    rad->mppe.types = MPPE_TYPE_40BIT | MPPE_TYPE_128BIT | MPPE_TYPE_56BIT;
    Log(LG_RADIUS, ("[%s] RADIUS: %s: MPPE-Keys, but no MPPE-Infos received => allowing MPPE with all types",
      lnk->name, function));
  }

  return RAD_ACK;
}

void
RadiusAcctUpdate(void *a)
{
  char  function[]	= "RadiusAcctUpdate";

  Log(LG_RADIUS, ("[%s] RADIUS: %s: Sending Accounting Update",
      lnk->name, function));

  TimerStop(&lnk->radius.radUpdate);
  RadiusAccount(RAD_UPDATE);
  TimerStart(&lnk->radius.radUpdate);
}


int 
RadiusAccount(short acct_type) 
{
  char  function[]	= "RadiusAccount";
  struct radius		*rad = &lnk->radius;
  int			authentic;

  /* if Radius-Auth wasn't used, then copy in authname */
  if (!strlen(rad->authname))
    strncpy(rad->authname, bund->peer_authname, AUTH_MAX_AUTHNAME);  
  
  Log(LG_RADIUS, ("[%s] RADIUS: %s for: %s", lnk->name, function, rad->authname));

  if (lnk->radius.authenticated) {
    authentic = RAD_AUTH_RADIUS;
  } else {
    authentic = RAD_AUTH_LOCAL;
  }

  if (RadiusStart(RAD_ACCOUNTING_REQUEST) == RAD_NACK)
    return RAD_NACK;

  /* Grab some accounting data and initialize structure */
  if (acct_type == RAD_START) {

    /* Generate a session ID */
    snprintf(lnk->radius.session_id, RAD_ACCT_MAX_SESSIONID, "%ld-%s",
      time(NULL) % 10000000, lnk->name);
      
    /* The first accounting request generates the multi Session ID */
    /* wich is the same for all links */
    if (strlen(rad->multi_session_id) == 0) {
      snprintf(rad->multi_session_id, RAD_ACCT_MAX_SESSIONID, "%ld-%s",
	time(NULL) % 10000000, bund->name);
    }

  }

  if (rad_put_string(rad->radh, RAD_USER_NAME, lnk->peer_authname) != 0 ||
      rad_put_addr(rad->radh, RAD_FRAMED_IP_ADDRESS, bund->ipcp.peer_addr)) { /*!= 0 ||
      rad_put_addr(rad->radh, RAD_FRAMED_IP_NETMASK, ac->mask) != 0) {*/
    Log(LG_RADIUS, ("[%s] RADIUS: %s: put (USER_NAME, FRAMED_IP_ADDRESS): %s", 
      lnk->name, function, rad_strerror(rad->radh)));
    RadiusClose();
    return RAD_NACK;
  }

  if (rad_put_int(rad->radh, RAD_ACCT_STATUS_TYPE, acct_type) != 0 ||
      rad_put_string(rad->radh, RAD_ACCT_SESSION_ID, lnk->radius.session_id) != 0 ||
      rad_put_string(rad->radh, RAD_ACCT_MULTI_SESSION_ID, rad->multi_session_id) != 0) {
    Log(LG_RADIUS, ("[%s] RADIUS: %s: put (STATUS_TYPE, SESSION_ID, MULTI_SESSION_ID): %s", 
      lnk->name, function, rad_strerror(rad->radh)));
    RadiusClose();
    return RAD_NACK;
  }

  if (rad_put_int(rad->radh, RAD_ACCT_LINK_COUNT, bund->n_links) != 0) {
    Log(LG_RADIUS, ("[%s] RADIUS: %s: rad_put_int(RAD_ACCT_LINK_COUNT) failed: %s", 
      lnk->name, function, rad_strerror(rad->radh)));
    RadiusClose();
    return RAD_NACK;
  }

  if (rad_put_int(rad->radh, RAD_ACCT_AUTHENTIC, authentic) != 0) {
    Log(LG_RADIUS, ("[%s] RADIUS: %s: rad_put_int(RAD_ACCT_AUTHENTIC) failed: %s",
      lnk->name, function, rad_strerror(rad->radh)));
    RadiusClose();    
    return RAD_NACK;
  }

  if (acct_type == RAD_STOP || acct_type == RAD_UPDATE) {

    if (acct_type == RAD_STOP) {
      int	termCause = RAD_TERM_PORT_ERROR;

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

      if (rad_put_int(rad->radh, RAD_ACCT_TERMINATE_CAUSE, termCause) != 0) {
	Log(LG_RADIUS, ("[%s] RADIUS: %s: rad_put_int(RAD_ACCT_TERMINATE_CAUSE) failed: %s",
	  lnk->name, function, rad_strerror(rad->radh)));
	RadiusClose();
	return RAD_NACK;
      }
    }

    if (rad_put_int(rad->radh, RAD_ACCT_SESSION_TIME, time(NULL) - lnk->bm.last_open) != 0) {
	Log(LG_RADIUS, ("[%s] RADIUS: %s: rad_put_int(RAD_ACCT_SESSION_TIME) failed: %s",
	  lnk->name, function, rad_strerror(rad->radh)));
	RadiusClose();
	return RAD_NACK;
    }

    LinkUpdateStats();
    if (rad_put_int(rad->radh, RAD_ACCT_INPUT_OCTETS, lnk->stats.recvOctets % MAX_U_INT32) != 0 ||
	rad_put_int(rad->radh, RAD_ACCT_INPUT_PACKETS, lnk->stats.recvFrames) != 0 ||
    	rad_put_int(rad->radh, RAD_ACCT_OUTPUT_OCTETS, lnk->stats.xmitOctets % MAX_U_INT32) != 0 ||
     	rad_put_int(rad->radh, RAD_ACCT_OUTPUT_PACKETS, lnk->stats.xmitFrames) != 0 ||
     	rad_put_int(rad->radh, RAD_ACCT_INPUT_GIGAWORDS, lnk->stats.recvOctets / MAX_U_INT32) != 0 ||
     	rad_put_int(rad->radh, RAD_ACCT_OUTPUT_GIGAWORDS, lnk->stats.xmitOctets / MAX_U_INT32) != 0) {
      Log(LG_RADIUS, ("[%s] RADIUS: %s: put stats: %s", lnk->name, function,
        rad_strerror(rad->radh)));
      RadiusClose();
      return RAD_NACK;
    }
  }

  Log(LG_RADIUS, ("[%s] RADIUS: %s: Sending accounting data (Type: %d)",
    lnk->name, function, acct_type));
  if (RadiusSendRequest() == RAD_NACK)
    return RAD_NACK;

  return RAD_ACK;

}

int
RadiusAddServer (short request_type)
{
  char		function[] = "RadiusAddServer";
  int		i;
  RadConf	const c = &bund->radiusconf;
  RadServe_Conf	s;
  struct radius	*rad = &lnk->radius;

  if (c->server == NULL)
    return (RAD_ACK);

  s = c->server;
  i = 1;
  while (s) {

    Log(LG_RADIUS, ("[%s] RADIUS: %s Adding %s", lnk->name, function, s->hostname));
    if (request_type == RAD_ACCESS_REQUEST) {
      if (rad_add_server (rad->radh, s->hostname,
	s->auth_port,
	s->sharedsecret,
	c->radius_timeout,
	c->radius_retries) == -1) {
	  Log(LG_RADIUS, ("[%s] RADIUS: %s error: %s", lnk->name, function, rad_strerror(rad->radh)));
	  return (RAD_NACK);
      }
    } else {
      if (rad_add_server (rad->radh, s->hostname,
	s->acct_port,
	s->sharedsecret,
	c->radius_timeout,
	c->radius_retries) == -1) {
	  Log(LG_RADIUS, ("[%s] RADIUS: %s error: %s", lnk->name, function, rad_strerror(rad->radh)));
	  return (RAD_NACK);
      }
    }

    s = s->next;
  }

  return (RAD_ACK);
}

void
RadiusSetAuth(AuthData auth) 
{
  char  function[] = "RadiusSetAuth";
  strncpy(auth->authname, lnk->radius.authname, AUTH_MAX_AUTHNAME);

  if (Enabled(&bund->ipcp.conf.options, IPCP_CONF_RADIUSIP)) {

    Log(LG_RADIUS, ("[%s] RADIUS: %s: Trying to use IP-address from radius-server",
      lnk->name, function));

    if (strcmp(inet_ntoa(lnk->radius.ip), "255.255.255.255") == 0) {
      /* the peer can choose an address */
      Log(LG_RADIUS, ("[%s] RADIUS: %s: server says that the peer can choose an address",
        lnk->name, function));
      auth->range.ipaddr.s_addr = 0;
      auth->range.width = 0;
      auth->range_valid = 1;

    } else if (strcmp(inet_ntoa(lnk->radius.ip), "255.255.255.254") == 0) {

      /* we should choose the ip */
      Log(LG_RADIUS, ("[%s] RADIUS: %s: server says that we should choose an address",
        lnk->name, function));
      auth->range_valid = 0;

    } else {

      /* or use IP from Radius-server */
      Log(LG_RADIUS, ("[%s] RADIUS: %s: using this IP: %s",
        lnk->name, function, inet_ntoa(lnk->radius.ip)));
      memcpy(&auth->range.ipaddr, &lnk->radius.ip, sizeof(struct in_addr));
      auth->range_valid = 1;
      auth->range.width = 32;
    }
  }
}

int
RadStat(int ac, char *av[], void *arg)
{
  int		i;
  RadConf	const conf = &bund->radiusconf;
  RadServe_Conf	server;
  struct radius	*rad = &lnk->radius;

  printf("\tTimeout      : %d\n", conf->radius_timeout);
  printf("\tRetries      : %d\n", conf->radius_retries);
  printf("\tConfig-file  : %s\n", conf->file);
  printf("\tMe (NAS-IP)  : %s\n", inet_ntoa(conf->radius_me));
  printf("\tAcct-Interval: %d\n", conf->acct_update);
  
  if (conf->server != NULL) {

    server = conf->server;
    i = 1;

    while (server) {
      printf("\t---------------  Radius Server %d ---------------\n", i);
      printf("\thostname   : %s\n", server->hostname);
      printf("\tsecret     : *********\n");
      printf("\tauth port  : %d\n", server->auth_port);
      printf("\tacct port  : %d\n", server->acct_port);
      i++;
      server = server->next;
    }

  }

  printf("RADIUS options\n");
  OptStat(&bund->radiusconf.options, gConfList);

  printf("\t---------------  Radius Data ---------------\n");
  printf("\tAuthenticated   : %s\n", rad->authenticated ? "yes" : "no");
  printf("\tAuthname        : %s\n", rad->authname);
  printf("\tReply-message   : %s\n", rad->reply_message == NULL ? "" : rad->reply_message);
  printf("\tIP              : %s\n", inet_ntoa(rad->ip));
  printf("\tMASK            : %s\n", inet_ntoa(rad->mask));
  printf("\tMTU             : %lu\n", rad->mtu);
  printf("\tSession-timeout : %lu\n", rad->session_timeout);
  printf("\tIdle-timeout    : %lu\n", rad->idle_timeout);
  printf("\tVJ              : %d\n", rad->vj);
  printf("\tClass           : %lu\n", rad->class);
  printf("\tProtocol        : %lu\n", rad->protocol);
  printf("\tService-type    : %lu\n", rad->service_type);  
  printf("\tFilter-Id       : %s\n", rad->filterid == NULL ? "" : rad->filterid);    
  printf("\tAcct-SID        : %s\n", lnk->radius.session_id);
  printf("\tAcct-MSID       : %s\n", rad->multi_session_id);

  printf("\t---------------  Radius MSoft related Data ---------------\n");  
  printf("\tMPPE Types         : %s\n", RadiusMPPETypesname(rad->mppe.types));
  printf("\tMPPE Policy        : %s\n", RadiusMPPEPolicyname(rad->mppe.policy));
  printf("\tMS-Domain          : %s\n", rad->msdomain == NULL ? "" : rad->msdomain);      
  printf("\tMS-CHAP-Error      : %s\n", rad->mschap_error == NULL ? "" : rad->mschap_error);
  printf("\tMS-CHAPv2-Response : %s\n", rad->mschapv2resp == NULL ? "" : rad->mschapv2resp);

  return (0);
}

static const char *
RadiusMPPEPolicyname(int policy) 
{
  switch(policy) {
    case MPPE_POLICY_ALLOWED:
      return "Allowed";
    case MPPE_POLICY_REQUIRED:
      return "Required";
    case MPPE_POLICY_NONE:
      return "Not available";
    default:
      return "Unknown Policy";
  }

}

static const char *
RadiusMPPETypesname(int types) {
  static char res[30];

  memset(res, 0, sizeof res);
  if (types == 0) {
    sprintf(res, "no encryption required");
    return res;
  }

  if (types & MPPE_TYPE_40BIT) sprintf (res, "40 ");
  if (types & MPPE_TYPE_56BIT) sprintf (&res[strlen(res)], "56 ");
  if (types & MPPE_TYPE_128BIT) sprintf (&res[strlen(res)], "128 ");

  if (strlen(res) == 0) {
    sprintf (res, "unknown types");
  } else {
    sprintf (&res[strlen(res)], "bit");
  }

  return res;

}

