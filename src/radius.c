/*
 * radius.c
 *
 * Written by Michael Bretterklieber <mbretter@jawa.at>
 * Written by Brendan Bank <brendan@gnarst.net>
 */

#include "radius.h"
#include "pptp.h"
#include "chap.h"
#include "ngfunc.h"

#include <sys/types.h>

#include <radlib.h>
#include <radlib_vs.h>
#include <md5.h>

/* Global variables */

  static int RadiusSetCommand(int ac, char *av[], void *arg);
  static int RadiusAddServer (void);
  static int RadiusInit(short request_type);
  static void RadiusClose(void);
  static const char * RadiusMPPEPolicyname(int policy);
  static const char * RadiusMPPETypesname(int types);
  /* compatibility functions until libradius has these builtin */
  static int rad_demangle(struct rad_handle *, const void *, size_t, u_char *);
  static int rad_demangle_mppe_key(struct rad_handle *, const void *, size_t, u_char *, size_t *);


/* Set menu options */

  enum {
    SET_SERVER,
    SET_TIMEOUT,
    SET_RETRIES,
    SET_CONFIG
  };

/*
 * GLOBAL VARIABLES
 */
 
  const struct cmdtab RadiusSetCmds[] = { 
    { "server <name> <secret> [auth port] [acct port]", "Set radius server parameters" ,
        RadiusSetCommand, NULL, (void *) SET_SERVER },
    { "timeout <seconds>",                 "Set timeout in seconds",
        RadiusSetCommand, NULL, (void *) SET_TIMEOUT },
    { "retries <# retries>",                "set number of retries",
        RadiusSetCommand, NULL, (void *) SET_RETRIES },
    { "config <path to radius.conf>",    "set path to config file for libradius",
        RadiusSetCommand, NULL, (void *) SET_CONFIG },
    { NULL },
  };
  
/* Set menu options */
static int
RadiusSetCommand(int ac, char *av[], void *arg) 
{
  static char function[] = "RadiusSetCommand";
  RadConf const conf = &bund->radius.conf;
  RadServe_Conf server;
  RadServe_Conf t_server;
  int val, count;

  /* Log(LG_RADIUS, ("[%s] %s: started",  lnk->name, function)); */

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

      case SET_TIMEOUT:
        val = atoi(*av);
          if (val <= 0)
            Log(LG_ERR, ("Timeout must be positive."));
          else
            conf->radius_timeout = val;
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

      default:
        assert(0);
    }

    return 0;
}

int
RadiusInit(short request_type) 
{
  struct radius *rad = &bund->radius;

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
  
  if (strlen(bund->radius.conf.file)) {
    Log(LG_RADIUS, ("[%s] RADIUS: using %s", lnk->name, bund->radius.conf.file));
    if (rad_config(rad->radh, bund->radius.conf.file) != 0) {
      Log(LG_RADIUS, ("[%s] RADIUS: rad_config: %s", lnk->name, rad_strerror(rad->radh)));
      RadiusClose();      
      return (RAD_NACK);
    }
  }

  if (RadiusAddServer() == RAD_NACK) {
    RadiusClose();    
    return (RAD_NACK);
  }
  
  return RAD_ACK;

}

void
RadiusClose(void) 
{
  struct radius *rad = &bund->radius;

  if (rad->radh != NULL) rad_close(rad->radh);  
  rad->radh = NULL;
}

void
RadiusDown(void) 
{
  Log(LG_RADIUS, ("[%s] RADIUS: Down Event", lnk->name));
  RadiusDestroy();
}

void
RadiusDestroy(void) 
{
  struct radius 	*rad = &bund->radius;

  RadiusClose();
  free(rad->msdomain);
  rad->msdomain = NULL;
  free(rad->mschap_error);
  rad->mschap_error = NULL;
  free(rad->mschapv2resp);
  rad->mschapv2resp = NULL;
  free(rad->reply_message);
  rad->reply_message = NULL;  
  memset(rad, 0, sizeof(struct radius) - sizeof(struct radiusconf));
}

int RadiusStart(short request_type)
{
  static char		function[] = "RadiusStart";
  struct radius		*rad = &bund->radius;
  char			host[MAXHOSTNAMELEN];
  struct in_addr	peer_ip;
  char			*peeripname;

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

  peer_ip = PptpGetPeerIp();
  peeripname = inet_ntoa(peer_ip);

  if (peeripname != NULL) {
    if (rad_put_string(rad->radh, RAD_CALLING_STATION_ID, inet_ntoa(peer_ip)) == -1) {
      Log(LG_RADIUS, ("[%s] RADIUS: %s: rad_put_int(RAD_SERVICE_TYPE) failed %s", lnk->name,
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
  struct radius		*rad = &bund->radius;
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

  switch (auth_type) {

    case CHAP_ALG_MSOFT:
      Log(LG_RADIUS, ("[%s] RADIUS: %s: RADIUS_CHAP (MSOFTv1) peer name: %s", lnk->name, function, name));
       if (passlen != 49) {
        Log(LG_RADIUS, ("[%s] RADIUS: %s: RADIUS_CHAP (MSOFTv1) unrecognised key length %d/%d", lnk->name, function, passlen, 49));
	RadiusClose();        
        return RAD_NACK;
      }

      if (rad_put_vendor_attr(rad->radh, RAD_VENDOR_MICROSOFT, RAD_MICROSOFT_MS_CHAP_CHALLENGE, challenge, challenge_size) == -1)  {
        Log(LG_RADIUS, ("[%s] RADIUS: %s: rad_put_vendor_attr(RAD_MICROSOFT_MS_CHAP_CHALLENGE) failed %s", lnk->name,
          function, rad_strerror(rad->radh)));
	RadiusClose();          
        return (RAD_NACK);
      }

      mschapval = (struct mschapvalue *)password;
      rad_mschapval.ident = chapid;
      rad_mschapval.flags = 0x01;
      memcpy(rad_mschapval.lm_response, mschapval->lmHash, 24);
      memcpy(rad_mschapval.nt_response, mschapval->ntHash, 24);

      if (rad_put_vendor_attr(rad->radh, RAD_VENDOR_MICROSOFT, RAD_MICROSOFT_MS_CHAP_RESPONSE, &rad_mschapval, sizeof rad_mschapval) == -1)  {
        Log(LG_RADIUS, ("[%s] RADIUS: %s: rad_put_vendor_attr(RAD_MICROSOFT_MS_CHAP_RESPONSE) failed %s", lnk->name,
          function, rad_strerror(rad->radh)));
	RadiusClose();
        return (RAD_NACK);
      }
      break;

    case CHAP_ALG_MSOFTv2:
      
      Log(LG_RADIUS, ("[%s] RADIUS: %s: RADIUS_CHAP (MSOFTv2) peer name: %s", lnk->name, function, name));
      if (rad_put_vendor_attr(rad->radh, RAD_VENDOR_MICROSOFT, RAD_MICROSOFT_MS_CHAP_CHALLENGE, challenge, challenge_size) == -1)  {
        Log(LG_RADIUS, ("[%s] RADIUS: %s: rad_put_vendor_attr(RAD_MICROSOFT_MS_CHAP_CHALLENGE) failed %s", lnk->name,
          function, rad_strerror(rad->radh)));
	RadiusClose();
        return (RAD_NACK);
      }

      if (passlen != sizeof(*mschapv2val)) {
        Log(LG_RADIUS, ("[%s] RADIUS: %s: RADIUS_CHAP (MSOFTv2) unrecognised key length %d/%d", lnk->name, function, passlen, sizeof(*mschapv2val)));
	RadiusClose();        
        return RAD_NACK;
      }
      
      mschapv2val = (struct mschapv2value *)password;
      rad_mschapv2val.ident = chapid;
      rad_mschapv2val.flags = mschapv2val->flags;
      memcpy(rad_mschapv2val.response,		mschapv2val->ntHash,	sizeof rad_mschapv2val.response);
      memset(rad_mschapv2val.reserved,		'\0', 			sizeof rad_mschapv2val.reserved);
      memcpy(rad_mschapv2val.pchallenge,	mschapv2val->peerChal,	sizeof rad_mschapv2val.pchallenge);

      if (rad_put_vendor_attr(rad->radh, RAD_VENDOR_MICROSOFT, RAD_MICROSOFT_MS_CHAP2_RESPONSE, &rad_mschapv2val, sizeof rad_mschapv2val) == -1)  {
        Log(LG_RADIUS, ("[%s] RADIUS: %s: rad_put_vendor_attr(RAD_MICROSOFT_MS_CHAP2_RESPONSE) failed %s", lnk->name,
          function, rad_strerror(rad->radh)));
	RadiusClose();        
        return (RAD_NACK);
      }
      
      break;

    case CHAP_ALG_MD5:

      /* Radius wants the CHAP Ident in the first byte of the CHAP-Password */
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

int
RadiusPutChangePassword(const char *mschapvalue, int mschapvaluelen, u_char chapid, int chap_type) 
{
  static char			function[] = "RadiusPutChangePassword";
  struct radius			*rad = &bund->radius;
  struct mschapv2value_cpw	*mschapv2val_cpw;
  struct rad_mschapv2value_cpw	rad_mschapv2val_cpw;
  struct rad_mschap_new_nt_pw	new_nt_pw;
  int				chunk;

  switch (chap_type) {

    case CHAP_ALG_MSOFT:
      Log(LG_RADIUS, ("[%s] RADIUS: %s: Password changing using MS-CHAPv1 not implemented", lnk->name, function));
      return (RAD_NACK);
      break;
    
    case CHAP_ALG_MSOFTv2:
    
      mschapv2val_cpw = (struct mschapv2value_cpw *)mschapvalue;
      if (mschapvaluelen != sizeof(*mschapv2val_cpw)) {
        Log(LG_RADIUS, ("[%s] RADIUS: %s: RADIUS_CHAP (MSOFTv2) unrecognised key length %d/%d", lnk->name, function, 
          mschapvaluelen, sizeof(*mschapv2val_cpw)));
        return RAD_NACK;
      }
      
      rad_mschapv2val_cpw.code = 7;
      rad_mschapv2val_cpw.ident = chapid;
      memcpy(rad_mschapv2val_cpw.encryptedHash,	mschapv2val_cpw->encryptedHash,	sizeof rad_mschapv2val_cpw.encryptedHash);
      memcpy(rad_mschapv2val_cpw.pchallenge,	mschapv2val_cpw->peerChal,	sizeof rad_mschapv2val_cpw.pchallenge);        
      memset(rad_mschapv2val_cpw.reserved,	'\0', 				sizeof rad_mschapv2val_cpw.reserved);
      memcpy(rad_mschapv2val_cpw.nt_response,	mschapv2val_cpw->ntResponse,	sizeof rad_mschapv2val_cpw.nt_response);
      memcpy(rad_mschapv2val_cpw.flags,		mschapv2val_cpw->flags,		sizeof rad_mschapv2val_cpw.flags);

      if (rad_put_vendor_attr(rad->radh, RAD_VENDOR_MICROSOFT, RAD_MICROSOFT_MS_CHAP2_PW, &rad_mschapv2val_cpw, sizeof rad_mschapv2val_cpw) == -1)  {
        Log(LG_RADIUS, ("[%s] RADIUS: %s: rad_put_vendor_attr(RAD_MICROSOFT_MS_CHAP2_PW) failed %s", lnk->name,
          function, rad_strerror(rad->radh)));
	RadiusClose();        
        return (RAD_NACK);
      }

      new_nt_pw.ident = chapid;
        
      for (chunk = 0; chunk < 4; chunk++) {
        new_nt_pw.chunk = chunk;
        printf("Chunk:%d\n",chunk);
        memcpy(new_nt_pw.data, &mschapv2val_cpw->encryptedPass[(sizeof new_nt_pw.data) * chunk], sizeof new_nt_pw.data);
      
        if (rad_put_vendor_attr(rad->radh, RAD_VENDOR_MICROSOFT, RAD_MICROSOFT_MS_CHAP_NT_ENC_PW, &new_nt_pw, sizeof new_nt_pw) == -1)  {
          Log(LG_RADIUS, ("[%s] RADIUS: %s: rad_put_vendor_attr(RAD_MICROSOFT_MS_CHAP_NT_ENC_PW) failed %s", lnk->name,
            function, rad_strerror(rad->radh)));
	  RadiusClose();
          return (RAD_NACK);
        }
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
  struct radius		*rad = &bund->radius;
  
  switch (rad_send_request(rad->radh)) {

    case RAD_ACCESS_ACCEPT:
      Log(LG_RADIUS, ("[%s] RADIUS: %s: RAD_ACCESS_ACCEPT for user %s", lnk->name, 
        function, rad->authname));
      rad->valid = 1;
      break;

    case RAD_ACCESS_REJECT:
      Log(LG_RADIUS, ("[%s] RADIUS: %s: RAD_ACCESS_REJECT for user %s", lnk->name, 
        function, rad->authname));
      rad->valid = 0;
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
  struct radius	*rad = &bund->radius;
  
  RadiusDestroy();
  if (RadiusStart(RAD_ACCESS_REQUEST) == RAD_NACK) 
    return RAD_NACK;
  
  if (RadiusPutAuth(name, password, 0, NULL, NULL, 0, RADIUS_PAP) == RAD_NACK) 
    return RAD_NACK;
  
  if (RadiusSendRequest() == RAD_NACK) 
    return RAD_NACK;
    
  if (RadiusGetParams() == RAD_NACK) 
    return RAD_NACK;
  
  if (rad->valid) {
    return RAD_ACK;
  } else {
    return RAD_NACK;
  }

}

int
RadiusCHAPAuthenticate(const char *name, const char *password, int passlen,
        const char *challenge, int challenge_size, u_char chapid, int chap_type) 
{
  struct radius	*rad = &bund->radius;

  RadiusDestroy();    
  if (RadiusStart(RAD_ACCESS_REQUEST) == RAD_NACK) 
    return RAD_NACK;

  if (RadiusPutAuth(name, password, passlen, challenge, challenge_size, chapid, chap_type) == RAD_NACK) 
    return RAD_NACK;
  
  if (RadiusSendRequest() == RAD_NACK) 
    return RAD_NACK;

  if (RadiusGetParams() == RAD_NACK) 
    return RAD_NACK;
  
  if (rad->valid) {
    return RAD_ACK;
  } else {
    return RAD_NACK;
  }
  
}

int
RadiusMSCHAPChangePassword(const char *mschapvalue, int mschapvaluelen, const char *challenge, 
	int challenge_size, u_char chapid, int chap_type) 
{
  static char			function[] = "RadiusMSCHAPChangePassword";
  struct radius			*rad = &bund->radius;
  struct mschapv2value_cpw	*mschapv2val_cpw;
  struct mschapv2value		*mschapv2val;
  
  if (chap_type != CHAP_ALG_MSOFTv2) {
    Log(LG_RADIUS, ("[%s] RADIUS: %s: must use MS-CHAPv2 for changing passwords", lnk->name, function));
    return RAD_NACK;
  }

  if (RadiusStart(RAD_ACCESS_REQUEST) == RAD_NACK) 
    return RAD_NACK;
  
  mschapv2val_cpw = (struct mschapv2value_cpw *)mschapvalue;
  mschapv2val = (struct mschapv2value *)mschapv2val_cpw->encryptedHash;

  if (RadiusPutChangePassword(mschapvalue, mschapvaluelen, chapid, chap_type) == RAD_NACK) 
    return RAD_NACK;

  if (RadiusPutAuth(rad->authname, (const char *)mschapv2val, sizeof *mschapv2val, challenge, challenge_size, chapid, chap_type) 
    == RAD_NACK) 
      return RAD_NACK;

  if (RadiusSendRequest() == RAD_NACK) 
    return RAD_NACK;
    
  if (RadiusGetParams() == RAD_NACK) 
    return RAD_NACK;
  
  if (rad->valid) {
    return RAD_ACK;
  } else {
    return RAD_NACK;
  }
  
}

int
RadiusGetParams() 
{
  char  function[] = "RadiusGetParams";
  struct radius *rad = &bund->radius;
  int res;
  size_t len;
  const void *data;
  u_int32_t vendor;

  while ((res = rad_get_attr(rad->radh, &data, &len)) > 0) {

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
                rad->valid = 0;
                return RAD_NACK;
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

              /* MPPE Keys MS-CHAPv2 */
              case RAD_MICROSOFT_MS_MPPE_RECV_KEY:
                Log(LG_RADIUS, ("[%s] RADIUS: %s: RAD_MICROSOFT_MS_MPPE_RECV_KEY",
                  lnk->name, function));
		rad_demangle_mppe_key(rad->radh, data, len, rad->mppe.recvkey, &rad->mppe.recvkeylen);
                break;

              case RAD_MICROSOFT_MS_MPPE_SEND_KEY:
                Log(LG_RADIUS, ("[%s] RADIUS: %s: RAD_MICROSOFT_MS_MPPE_SEND_KEY",
                  lnk->name, function));
		rad_demangle_mppe_key(rad->radh, data, len, rad->mppe.sendkey, &rad->mppe.sendkeylen);                
                break;

              /* MPPE Keys MS-CHAPv1 */
              case RAD_MICROSOFT_MS_CHAP_MPPE_KEYS:
                Log(LG_RADIUS, ("[%s] RADIUS: %s: RAD_MICROSOFT_MS_CHAP_MPPE_KEYS",
                  lnk->name, function));

                if (len != 32) {
                  Log(LG_RADIUS, ("[%s] RADIUS: %s: Server returned garbage %d of expected %d Bytes",
                    lnk->name, function, len, 32));
                  return RAD_NACK;
                }
                
                if (rad_demangle(rad->radh, data, len, rad->mppe.lm_key) == -1) {
                  Log(LG_RADIUS, ("[%s] RADIUS: %s: rad_demangle failed: %s",
                    lnk->name, function, rad_strerror(rad->radh)));
		  return RAD_NACK;
                }
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
        }
        break;

      default:
        Log(LG_RADIUS, ("[%s] RADIUS: %s: Dropping attribute: %d ", lnk->name, function, res));
        break;
    }
  }

  return RAD_ACK;
}

int 
RadiusAccount(short acct_type) 
{
  char  function[]	= "RadiusAccount";
  struct radius		*rad = &bund->radius;
  IfaceState 		const iface = &bund->iface;
  int			authentic;

  /* if Radius-Auth wasn't used, then copy in authname */
  if (!strlen(rad->authname))
    strncpy(rad->authname, bund->peer_authname, AUTH_MAX_AUTHNAME);  
  
  Log(LG_RADIUS, ("[%s] RADIUS: %s for: %s", lnk->name, function, rad->authname));

  if (rad->valid) {
    authentic = RAD_AUTH_RADIUS;
  } else {
    authentic = RAD_AUTH_LOCAL;
  }
 
  if (RadiusStart(RAD_ACCOUNTING_REQUEST) == RAD_NACK) 
    return RAD_NACK;
  
  /* Grab some accounting data and initialize structure */
  if (acct_type == RAD_START) {
 
    /* Generate a session ID */
    snprintf(rad->session_id, sizeof rad->session_id, "%s:%ld-%s:%s",
	rad->authname, (long)getpid(), bund->name, lnk->name);
    snprintf(rad->multi_session_id, sizeof rad->multi_session_id, "%s:%ld-%s",
	rad->authname, (long)getpid(), bund->name);

    rad->acct_start = time(NULL);
  };

  if (rad_put_string(rad->radh, RAD_USER_NAME, rad->authname) != 0 ||
      rad_put_addr(rad->radh, RAD_FRAMED_IP_ADDRESS, iface->self_addr)) { /*!= 0 ||
      rad_put_addr(rad->radh, RAD_FRAMED_IP_NETMASK, ac->mask) != 0) {*/
    Log(LG_RADIUS, ("[%s] RADIUS: %s: put (USER_NAME, FRAMED_IP_ADDRESS): %s", 
      lnk->name, function, rad_strerror(rad->radh)));
    RadiusClose();
    return RAD_NACK;
  }

  if (rad_put_int(rad->radh, RAD_ACCT_STATUS_TYPE, acct_type) != 0 ||
      rad_put_string(rad->radh, RAD_ACCT_SESSION_ID, rad->session_id) != 0 ||
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
    Log(LG_RADIUS, ("[%s] RADIUS: %s: rad_put_int(RAD_ACCT_AUTHENTIC) failed: %s", lnk->name, function, 
      rad_strerror(rad->radh)));
    RadiusClose();    
    return RAD_NACK;
  }

  if (acct_type == RAD_STOP) {
    struct ng_ppp_link_stat	stats;
    int				termCause = RAD_TERM_USER_REQUEST;
    
    if (lnk->downReason != NULL) {
      if (!strcmp(lnk->downReason, STR_QUIT))		termCause = RAD_TERM_ADMIN_RESET;
      if (!strcmp(lnk->downReason, STR_PEER_DISC))	termCause = RAD_TERM_USER_REQUEST;
      if (!strcmp(lnk->downReason, STR_IDLE_TIMEOUT)) 	termCause = RAD_TERM_IDLE_TIMEOUT;
    }

    if (rad_put_int(rad->radh, RAD_ACCT_TERMINATE_CAUSE, termCause) != 0) {
      Log(LG_RADIUS, ("[%s] RADIUS: %s: rad_put_int(RAD_ACCT_TERMINATE_CAUSE) failed: %s", lnk->name, function, 
        rad_strerror(rad->radh)));
      RadiusClose();        
      return RAD_NACK;
    }

    if (NgFuncGetStats(lnk->bundleIndex, 0, &stats) >= 0) {

      if (rad_put_int(rad->radh, RAD_ACCT_INPUT_OCTETS, stats.recvOctets) != 0 ||
	rad_put_int(rad->radh, RAD_ACCT_INPUT_PACKETS, stats.recvFrames) != 0 ||
	rad_put_int(rad->radh, RAD_ACCT_OUTPUT_OCTETS, stats.xmitOctets) != 0 ||
	rad_put_int(rad->radh, RAD_ACCT_OUTPUT_PACKETS, stats.xmitFrames) != 0 ||
	rad_put_int(rad->radh, RAD_ACCT_SESSION_TIME, time(NULL) - rad->acct_start) != 0) {
	Log(LG_RADIUS, ("[%s] RADIUS: %s: put stats: %s", lnk->name, function, rad_strerror(rad->radh)));
	RadiusClose();        
	return RAD_NACK;
       }
       
       rad->acct_start = 0;
       
    }
  }
  
  Log(LG_RADIUS, ("[%s] RADIUS: %s: Sending accounting data (Type: %d)", lnk->name, function, acct_type));
  if (RadiusSendRequest() == RAD_NACK) 
    return RAD_NACK;

  return RAD_ACK;

}

int
RadiusAddServer (void) 
{
  RadConf       const c = &bund->radius.conf;
  RadServe_Conf s;
  char  function[] = "RadiusAddServer";
  int i;
  struct radius *rad = &bund->radius;

  if (c->server == NULL)
    return (RAD_ACK);

  s = c->server;
  i = 1;
  while (s) {

    Log(LG_RADIUS, ("[%s] RADIUS: %s Adding %s", lnk->name, function, s->hostname));
    if (rad_add_server (rad->radh, s->hostname,
        s->auth_port,
        s->sharedsecret,
        c->radius_timeout,
        c->radius_retries) == -1) {
      Log(LG_RADIUS, ("[%s] RADIUS: %s error: %s", lnk->name, function, rad_strerror(rad->radh)));
      return (RAD_NACK);
    }

    s = s->next;
  }

  return (RAD_ACK);
}

void
RadiusSetAuth(AuthData auth) 
{
  char  function[] = "RadiusSetAuth";
  strncpy(auth->authname, bund->radius.authname, AUTH_MAX_AUTHNAME);

  if (Enabled(&bund->ipcp.conf.options, IPCP_CONF_RADIUSIP)) {

    Log(LG_RADIUS, ("[%s] RADIUS: %s: Trying to use IP-address from radius-server",
      lnk->name, function));

    if (strcmp(inet_ntoa(bund->radius.ip), "255.255.255.255") == 0) {
      /* the peer can choose an address */
      Log(LG_RADIUS, ("[%s] RADIUS: %s: server says that the peer can choose an address",
        lnk->name, function));
      auth->range.ipaddr.s_addr = 0;
      auth->range.width = 0;
      auth->range_valid = 1;

    } else if (strcmp(inet_ntoa(bund->radius.ip), "255.255.255.254") == 0) {

      /* we should choose the ip */
      Log(LG_RADIUS, ("[%s] RADIUS: %s: server says that we should choose an address",
        lnk->name, function));
      auth->range_valid = 0;

    } else {

      /* or use IP from Radius-server */
      Log(LG_RADIUS, ("[%s] RADIUS: %s: using this IP: %s",
        lnk->name, function, inet_ntoa(bund->radius.ip)));
      memcpy(&auth->range.ipaddr, &bund->radius.ip, sizeof(struct in_addr));
      auth->range_valid = 1;
      auth->range.width = 32;
    }
  }
}

int
RadStat(int ac, char *av[], void *arg) 
{
  RadConf       const conf = &bund->radius.conf;
  RadServe_Conf server;
  struct radius	*rad = &bund->radius;  
  int i;

  printf("\tTimeout     : %d\n", conf->radius_timeout);
  printf("\tRetries     : %d\n", conf->radius_retries);
  printf("\tConfig-file : %s\n", conf->file);
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

  printf("\t---------------  Radius Data ---------------\n");
  printf("\tAuthenticated   : %s\n", rad->valid ? "yes" : "no");
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
  printf("\tAcct-SID        : %s\n", rad->session_id);
  printf("\tAcct-MSID       : %s\n", rad->multi_session_id);
  printf("\tAcct-Started    : %ld\n", rad->acct_start);
  
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

/* compatibility functions until libradius has these builtin */
static int
rad_demangle(struct rad_handle *h, const void *mangled, size_t mlen, u_char *demangled) 
{
  char  function[] = "rad_demangle";
  char R[AUTH_LEN];
  const char *S;
  int i, Ppos;
  MD5_CTX Context;
  u_char b[16], *C;

  if ((mlen % 16 != 0) || (mlen > 128)) {
    Log(LG_RADIUS, ("[%s] RADIUS: %s: Cannot interpret mangled data of length %ld",
      lnk->name, function, (u_long)mlen));
    return -1;
  }

  C = (u_char *)mangled;

  /* We need the shared secret as Salt */
  S = rad_server_secret(h);

  /* We need the request authenticator */
  if (rad_request_authenticator(h, R, sizeof R) != AUTH_LEN) {
    Log(LG_RADIUS, ("[%s] RADIUS: %s: Cannot obtain the RADIUS request authenticator",
      lnk->name, function));
    return -1;
  }

  MD5Init(&Context);
  MD5Update(&Context, S, strlen(S));
  MD5Update(&Context, R, AUTH_LEN);
  MD5Final(b, &Context);
  Ppos = 0;
  while (mlen) {

    mlen -= 16;
    for (i = 0; i < 16; i++)
      demangled[Ppos++] = C[i] ^ b[i];

    if (mlen) {
      MD5Init(&Context);
      MD5Update(&Context, S, strlen(S));
      MD5Update(&Context, C, 16);
      MD5Final(b, &Context);
    }

    C += 16;
  }

  return 0;
}

static int
rad_demangle_mppe_key(struct rad_handle *h, const void *mangled, size_t mlen, u_char *demangled, size_t *len)
{
  char  function[] = "rad_demangle_mppe_key";
  char R[AUTH_LEN];    /* variable names as per rfc2548 */
  const char *S;
  u_char b[16];
  const u_char *A, *C;
  MD5_CTX Context;
  int Slen, i, Clen, Ppos;
  u_char *P;

  if (mlen % 16 != SALT_LEN) {
    Log(LG_RADIUS, ("[%s] RADIUS: %s: Cannot interpret mangled data of length %ld",
      lnk->name, function, (u_long)mlen));
    return -1;
  }

  /* We need the RADIUS Request-Authenticator */
  if (rad_request_authenticator(h, R, sizeof R) != AUTH_LEN) {
    Log(LG_RADIUS, ("[%s] RADIUS: %s: Cannot obtain the RADIUS request authenticator",
      lnk->name, function));
    return -1;
  }

  A = (const u_char *)mangled;      /* Salt comes first */
  C = (const u_char *)mangled + SALT_LEN;  /* Then the ciphertext */
  Clen = mlen - SALT_LEN;
  S = rad_server_secret(h);    /* We need the RADIUS secret */
  Slen = strlen(S);
  P = alloca(Clen);        /* We derive our plaintext */

  MD5Init(&Context);
  MD5Update(&Context, S, Slen);
  MD5Update(&Context, R, AUTH_LEN);
  MD5Update(&Context, A, SALT_LEN);
  MD5Final(b, &Context);
  Ppos = 0;

  while (Clen) {
    Clen -= 16;

    for (i = 0; i < 16; i++)
      P[Ppos++] = C[i] ^ b[i];

    if (Clen) {
      MD5Init(&Context);
      MD5Update(&Context, S, Slen);
      MD5Update(&Context, C, 16);
      MD5Final(b, &Context);
    }
                
    C += 16;
  }

  /*
   * The resulting plain text consists of a one-byte length, the text and
   * maybe some padding.
   */
  *len = *P;
  if (*len > mlen - 1) {
    Log(LG_RADIUS, ("[%s] RADIUS: %s: Mangled data seems to be garbage %d %d",
      lnk->name, function, *len, mlen-1));
    return -1;
  }

  if (*len > MPPE_KEY_LEN) {
    Log(LG_RADIUS, ("[%s] RADIUS: %s: Key to long (%d) for me max. %d",
      lnk->name, function, *len, MPPE_KEY_LEN));
    return -1;
  }

  memcpy(demangled, P + 1, *len);
  return 0;
}
