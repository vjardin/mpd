/*
 * radius.c
 *
 * Written by Michael Bretterklieber <mbretter@inode.at>
 * Written by Brendan Bank <brendan@gnarst.net>
 */

#include "radius.h"
#include "pptp.h"
#include "chap.h"
#include <radlib.h>
#include <radlib_vs.h>
#include <md5.h>

/* Global variables */

  static int RadiusSetCommand(int ac, char *av[], void *arg);
  static int RadiusAddServer (void);
  static void RadiusInit(void);
  static void RadiusMPPEExtractKey(const void *mangled, size_t mlen, u_char *buf, size_t *len);
  static int RadiusDecryptPassword(const void *mangled, size_t clen, u_char *P);
  static const char * RadiusMPPEPolicyname(int policy);
  static const char * RadiusMPPETypesname(int types);

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
        server->auth_port = 1645;
        server->acct_port = 1646;
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

void RadiusInit(void) {
  struct radius *rad = &bund->radius;

  if (rad->radh != NULL) rad_close(rad->radh);
  memset(rad, 0, sizeof(struct radius) - sizeof(struct radiusconf));
}

extern int
RadiusAuthenticate(const char *name, const char *password, int passlen,
        const char *challenge, int challenge_size, u_char chapid, int auth_type)
{
  static char function[] = "RadiusAuthenticate";
  struct radius *rad = &bund->radius;
  char     host[MAXHOSTNAMELEN];
  struct in_addr          peer_ip;
  char  *peeripname;
  int res;
  struct chap_response chapres;
  struct mschap_response mschapres;
  struct mschapv2_response mschap2res;
  struct mschapv2value *mschapv2;
  struct mschapvalue *mschapv;

  RadiusInit();

  if (gethostname(host, sizeof (host)) == -1) {
    Log(LG_RADIUS, ("[%s] RADIUS: %s: gethostname() failed", lnk->name, function));
    return (RAD_NACK);
  }

  if (name == NULL || password == NULL) {
    Log(LG_RADIUS, ("[%s] RADIUS: %s: name or password NULL", lnk->name, function));
    return (RAD_NACK);
  }

  rad->radh = rad_open();
  if (rad->radh == NULL) {
    Log(LG_RADIUS, ("[%s] RADIUS: rad_open failed", lnk->name));
    return (RAD_NACK);
  }

  if (strlen(bund->radius.conf.file)) {
    Log(LG_RADIUS, ("[%s] RADIUS: using %s", lnk->name, bund->radius.conf.file));
    if (rad_config(rad->radh, bund->radius.conf.file) != 0) {
      Log(LG_RADIUS, ("[%s] RADIUS: rad_config: %s", lnk->name, rad_strerror(rad->radh)));
      rad_close(rad->radh);
      return (RAD_NACK);
    }
  }

  if (RadiusAddServer() == RAD_NACK) {
    rad_close(rad->radh);
    return (RAD_NACK);
  }

  if (rad_create_request(rad->radh, RAD_ACCESS_REQUEST) == -1) {
    Log(LG_RADIUS, ("[%s] RADIUS: rad_create_request: %s", lnk->name, rad_strerror(rad->radh)));
    return (RAD_NACK);
  }

  if (rad_put_string(rad->radh, RAD_USER_NAME, name) == -1) {
    Log(LG_RADIUS, ("[%s] RADIUS: %s: rad_put_string(username) failed %s", lnk->name,
      function, rad_strerror(rad->radh)));
    rad_close(rad->radh);
    return (RAD_NACK);
  }

  switch (auth_type) {

    case CHAP_ALG_MSOFT:
      Log(LG_RADIUS, ("[%s] RADIUS: %s: RADIUS_CHAP (MSOFTv1) peer name: %s", lnk->name, function, name));
       if (passlen != 49) {
        Log(LG_RADIUS, ("[%s] RADIUS: %s: RADIUS_CHAP (MSOFTv1) unrecognised key length %d/%d", lnk->name, function, passlen, 49));
        rad_close(rad->radh);
        return RAD_NACK;
      }

      if (rad_put_vendor_attr(rad->radh, RAD_VENDOR_MICROSOFT, RAD_MICROSOFT_MS_CHAP_CHALLENGE, challenge, challenge_size) == -1)  {
        Log(LG_RADIUS, ("[%s] RADIUS: %s: rad_put_vendor_attr(RAD_MICROSOFT_MS_CHAP_CHALLENGE) failed %s", lnk->name,
          function, rad_strerror(rad->radh)));
        rad_close(rad->radh);
        return (RAD_NACK);
      }

      mschapv = (struct mschapvalue *)password;
      mschapres.ident = chapid;
      mschapres.flags = 0x01;
      memcpy(mschapres.lm_response, mschapv->lmHash, 24);
      memcpy(mschapres.nt_response, mschapv->ntHash, 24);

      if (rad_put_vendor_attr(rad->radh, RAD_VENDOR_MICROSOFT, RAD_MICROSOFT_MS_CHAP_RESPONSE, &mschapres, sizeof mschapres) == -1)  {
        Log(LG_RADIUS, ("[%s] RADIUS: %s: rad_put_vendor_attr(RAD_MICROSOFT_MS_CHAP_RESPONSE) failed %s", lnk->name,
          function, rad_strerror(rad->radh)));
        rad_close(rad->radh);
        return (RAD_NACK);
      }
      break;

    case CHAP_ALG_MSOFTv2:
      Log(LG_RADIUS, ("[%s] RADIUS: %s: RADIUS_CHAP (MSOFTv2) peer name: %s", lnk->name, function, name));
      if (passlen != sizeof(*mschapv2)) {
        Log(LG_RADIUS, ("[%s] RADIUS: %s: RADIUS_CHAP (MSOFTv2) unrecognised key length %d/%d", lnk->name, function, passlen, sizeof(*mschapv2)));
        rad_close(rad->radh);
        return RAD_NACK;
      }

      if (rad_put_vendor_attr(rad->radh, RAD_VENDOR_MICROSOFT, RAD_MICROSOFT_MS_CHAP_CHALLENGE, challenge, challenge_size) == -1)  {
        Log(LG_RADIUS, ("[%s] RADIUS: %s: rad_put_vendor_attr(RAD_MICROSOFT_MS_CHAP_CHALLENGE) failed %s", lnk->name,
          function, rad_strerror(rad->radh)));
        rad_close(rad->radh);
        return (RAD_NACK);
      }

      mschapv2 = (struct mschapv2value *)password;
      mschap2res.ident = chapid;
      mschap2res.flags = mschapv2->flags;
      memcpy(mschap2res.response, mschapv2->ntHash, sizeof mschap2res.response);
      memset(mschap2res.reserved, '\0', sizeof mschap2res.reserved);
      memcpy(mschap2res.pchallenge, mschapv2->peerChal, sizeof mschap2res.pchallenge);

      if (rad_put_vendor_attr(rad->radh, RAD_VENDOR_MICROSOFT, RAD_MICROSOFT_MS_CHAP2_RESPONSE, &mschap2res, sizeof mschap2res) == -1)  {
        Log(LG_RADIUS, ("[%s] RADIUS: %s: rad_put_vendor_attr(RAD_MICROSOFT_MS_CHAP2_RESPONSE) failed %s", lnk->name,
          function, rad_strerror(rad->radh)));
        rad_close(rad->radh);
        return (RAD_NACK);
      }
      break;

    case CHAP_ALG_MD5:

      /* Radius wants the CHAP Ident in the first byte of the CHAP-Password */
      chapres.ident = chapid;
      memcpy(chapres.response, password, passlen);
      Log(LG_RADIUS, ("[%s] RADIUS: %s: RADIUS_CHAP (MD5) peer name: %s", lnk->name, function, name));
      if (rad_put_attr(rad->radh, RAD_CHAP_PASSWORD, &chapres, passlen + 1) == -1 ||
        rad_put_attr(rad->radh, RAD_CHAP_CHALLENGE, challenge, challenge_size) == -1) {
        Log(LG_RADIUS, ("[%s] RADIUS: %s: rad_put_string(password) failed %s", lnk->name,
          function, rad_strerror(rad->radh)));
        rad_close(rad->radh);
        return (RAD_NACK);
      }
      break;

    case RADIUS_PAP:
        Log(LG_RADIUS, ("[%s] RADIUS: %s: RADIUS_PAP DEBUG: peer name: %s",  lnk->name, function, name));
        if (rad_put_string(rad->radh, RAD_USER_PASSWORD, password) == -1) {
          Log(LG_RADIUS, ("[%s] RADIUS: %s: rad_put_string(password) failed %s", lnk->name,
            function, rad_strerror(rad->radh)));
          rad_close(rad->radh);
          return (RAD_NACK);
        }
      break;

    default:
      Log(LG_RADIUS, ("[%s] RADIUS: %s: RADIUS auth type unkown", lnk->name, function));
      rad_close(rad->radh);
      return (RAD_NACK);
      break;
  }

  if (rad_put_string(rad->radh, RAD_NAS_IDENTIFIER, host) == -1)  {
    Log(LG_RADIUS, ("[%s] RADIUS: %s: rad_put_string(host) failed %s", lnk->name,
      function, rad_strerror(rad->radh)));
    rad_close(rad->radh);
    return (RAD_NACK);
  }
  if (rad_put_int(rad->radh, RAD_SERVICE_TYPE, RAD_FRAMED) == -1) {
    Log(LG_RADIUS, ("[%s] RADIUS: %s: rad_put_int(RAD_SERVICE_TYPE) failed %s", lnk->name,
      function, rad_strerror(rad->radh)));
    rad_close(rad->radh);
    return (RAD_NACK);
  }
  if (rad_put_int(rad->radh, RAD_FRAMED_PROTOCOL, RAD_PPP) == -1) {
    Log(LG_RADIUS, ("[%s] RADIUS: %s: rad_put_int(RAD_FRAMED_PROTOCOL) failed %s", lnk->name,
      function, rad_strerror(rad->radh)));
    rad_close(rad->radh);
    return (RAD_NACK);
  }

  peer_ip = PptpGetPeerIp();
  peeripname = inet_ntoa(peer_ip);

  if (peeripname != NULL) {
    if (rad_put_string(rad->radh, RAD_CALLING_STATION_ID, inet_ntoa(peer_ip)) == -1) {
      Log(LG_RADIUS, ("[%s] RADIUS: %s: rad_put_int(RAD_SERVICE_TYPE) failed %s", lnk->name,
      function, rad_strerror(rad->radh)));
      rad_close(rad->radh);
      return (RAD_NACK);
    }
  }

  switch (rad_send_request(rad->radh)) {

    case RAD_ACCESS_ACCEPT:
      rad->valid = 1;
      Log(LG_RADIUS, ("[%s] RADIUS: %s: RAD_ACCESS_ACCEPT for user %s", lnk->name, function, name));
      break;

    case RAD_ACCESS_REJECT:
      Log(LG_RADIUS, ("[%s] RADIUS: %s: RAD_ACCESS_REJECT for user %s", lnk->name, function, name));
      rad_close(rad->radh);
      return(RAD_NACK);
      break;

    case -1:
      Log(LG_RADIUS, ("[%s] RADIUS: %s: rad_send_request failed %s", lnk->name,
      function, rad_strerror(rad->radh)));
      return(RAD_NACK);
      break;
    default:
      Log(LG_RADIUS, ("[%s] RADIUS: %s: rad_send_request: unexpected "
      "return value %s", lnk->name, function, rad_strerror(rad->radh)));
      rad_close(rad->radh);
      return(RAD_NACK);
    }

    // Remember authname
    strncpy(rad->authname, name, AUTH_MAX_AUTHNAME);
    res = RadiusGetParams();
    if (res == RAD_NACK) rad->valid = 0;
    rad_close(rad->radh);
    return(res);
}

int
RadiusPAPAuthenticate(const char *name, const char *password) {
  return (RadiusAuthenticate(name, password, 0, NULL, NULL, 0, RADIUS_PAP));
}

int
RadiusCHAPAuthenticate(const char *name, const char *password, int passlen,
        const char *challenge, int challenge_size, u_char chapid, int chap_type) {
  return (RadiusAuthenticate(name, password, passlen, challenge, challenge_size, chapid, chap_type));
}


int
RadiusGetParams() {
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
        rad->sessiontime = rad_cvt_int(data);
        Log(LG_RADIUS, ("[%s] RADIUS: %s: RAD_SESSION_TIMEOUT: %lu ",
          lnk->name, function, rad->sessiontime));
        break;

      case RAD_FRAMED_MTU:
        rad->mtu = rad_cvt_int(data);
        Log(LG_RADIUS, ("[%s] RADIUS: %s: RAD_FRAMED_MTU: %lu ",
          lnk->name, function, rad->mtu));
        break;

      case RAD_FRAMED_COMPRESSION:
        rad->vj = rad_cvt_int(data) == 1 ? 1 : 0;
        Log(LG_RADIUS, ("[%s] RADIUS: %s: RAD_FRAMED_COMPRESSION: %d ",
          lnk->name, function, rad->vj));
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

              // MPPE Keys MS-CHAPv2
              case RAD_MICROSOFT_MS_MPPE_RECV_KEY:
                Log(LG_RADIUS, ("[%s] RADIUS: %s: RAD_MICROSOFT_MS_MPPE_RECV_KEY",
                  lnk->name, function));
                RadiusMPPEExtractKey(data, len, rad->mppe.recvkey, &rad->mppe.recvkeylen);
                break;

              case RAD_MICROSOFT_MS_MPPE_SEND_KEY:
                Log(LG_RADIUS, ("[%s] RADIUS: %s: RAD_MICROSOFT_MS_MPPE_SEND_KEY",
                  lnk->name, function));
                RadiusMPPEExtractKey(data, len, rad->mppe.sendkey, &rad->mppe.sendkeylen);
                break;

              // MPPE Keys MS-CHAPv1
              case RAD_MICROSOFT_MS_CHAP_MPPE_KEYS:
                Log(LG_RADIUS, ("[%s] RADIUS: %s: RAD_MICROSOFT_MS_CHAP_MPPE_KEYS",
                  lnk->name, function));

                if (len != 32) {
                  Log(LG_RADIUS, ("[%s] RADIUS: %s: Server returned garbage %d of expected %d Bytes",
                    lnk->name, function, len, 32));
                  return RAD_NACK;
                }

                if (RadiusDecryptPassword(data, len, rad->mppe.lm_key) == RAD_NACK) {
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
RadiusAddServer (void) {
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
RadiusSetAuth(AuthData auth) {
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
RadStat(int ac, char *av[], void *arg) {
  RadConf       const conf = &bund->radius.conf;
  RadServe_Conf server;
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
  printf("\tAuthname        : %s\n", bund->radius.authname);
  printf("\tIP              : %s\n", inet_ntoa(bund->radius.ip));
  printf("\tMASK            : %s\n", inet_ntoa(bund->radius.mask));
  printf("\tMTU             : %lu\n", bund->radius.mtu);
  printf("\tSessiontimeout  : %lu\n", bund->radius.sessiontime);
  printf("\tVJ              : %d\n", bund->radius.vj);
  printf("\tMPPE Types      : %s\n", RadiusMPPETypesname(bund->radius.mppe.types));
  printf("\tMPPE Policy     : %s\n", RadiusMPPEPolicyname(bund->radius.mppe.policy));

  return (0);
}

/* This algorithm was been taken from userland-ppp */
/* For exact description see RFC2548 */
static void
RadiusMPPEExtractKey(const void *mangled, size_t mlen, u_char *buf, size_t *len)
{
  char  function[] = "RadiusExtractMPPEKey";
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
    buf = NULL;
    *len = 0;
    return;
  }

  /* We need the RADIUS Request-Authenticator */
  if (rad_request_authenticator(bund->radius.radh, R, sizeof R) != AUTH_LEN) {
    Log(LG_RADIUS, ("[%s] RADIUS: %s: Cannot obtain the RADIUS request authenticator",
      lnk->name, function));
    buf = NULL;
    *len = 0;
    return;
  }

  A = (const u_char *)mangled;      /* Salt comes first */
  C = (const u_char *)mangled + SALT_LEN;  /* Then the ciphertext */
  Clen = mlen - SALT_LEN;
  S = rad_server_secret(bund->radius.radh);    /* We need the RADIUS secret */
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
    Log(LG_RADIUS, ("[%s] RADIUS %s: Mangled data seems to be garbage %d %d",
      lnk->name, function, *len, mlen-1));
    buf = NULL;
    *len = 0;
    return;
  }

  if (*len > MPPE_KEY_LEN) {
    Log(LG_RADIUS, ("[%s] RADIUS %s: Key to long (%d) for me max. %d",
      lnk->name, function, *len, MPPE_KEY_LEN));
    buf = NULL;
    *len = 0;
    return;
  }

  memcpy(buf, P + 1, *len);
}

static const char *
RadiusMPPEPolicyname(int policy) {
  switch(policy) {
    case MPPE_POLICY_ALLOWED:
      return "Allowed";
    case MPPE_POLICY_REQUIRED:
      return "Required";
    default:
      return "Unknown Policy";
  }

}

static const char *
RadiusMPPETypesname(int types) {
  static char res[30];

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

/* Decrypting Radius Password */
/* For exact description see RFC2865 */
static int
RadiusDecryptPassword(const void *mangled, size_t clen, u_char *P) {
  char  function[] = "RadiusDecryptPassword";
  char R[AUTH_LEN];
  const char *S;
  int i, Ppos;
  MD5_CTX Context;
  u_char b[16], *C;

  C = (u_char *)mangled;

  /* We need the shared secret as Salt */
  S = rad_server_secret(bund->radius.radh);

  /* We need the request authenticator */
  if (rad_request_authenticator(bund->radius.radh, R, sizeof R) != AUTH_LEN) {
    Log(LG_RADIUS, ("[%s] RADIUS: %s: Cannot obtain the RADIUS request authenticator",
      lnk->name, function));
    return RAD_NACK;
  }

  MD5Init(&Context);
  MD5Update(&Context, S, strlen(S));
  MD5Update(&Context, R, AUTH_LEN);
  MD5Final(b, &Context);
  Ppos = 0;
  while (clen) {

    clen -= 16;
    for (i = 0; i < 16; i++)
      P[Ppos++] = C[i] ^ b[i];

    if (clen) {
      MD5Init(&Context);
      MD5Update(&Context, S, strlen(S));
      MD5Update(&Context, C, 16);
      MD5Final(b, &Context);
    }

    C += 16;
  }

  return RAD_ACK;
}
