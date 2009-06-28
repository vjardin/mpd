
/*
 * radsrv.c
 *
 * Written by Alexander Motin <mav@FreeBSD.org>
 */

#include "ppp.h"
#include "radsrv.h"
#include "util.h"

#ifdef RAD_COA_REQUEST

/*
 * DEFINITIONS
 */

  /* Set menu options */
  enum {
    SET_OPEN,
    SET_CLOSE,
    SET_SELF,
    SET_PEER,
    SET_DISABLE,
    SET_ENABLE
  };


/*
 * INTERNAL FUNCTIONS
 */

  static int	RadsrvSetCommand(Context ctx, int ac, char *av[], void *arg);

/*
 * GLOBAL VARIABLES
 */

  const struct cmdtab RadsrvSetCmds[] = {
    { "open",			"Open the radsrv" ,
  	RadsrvSetCommand, NULL, 2, (void *) SET_OPEN },
    { "close",			"Close the radsrv" ,
  	RadsrvSetCommand, NULL, 2, (void *) SET_CLOSE },
    { "self {ip} [{port}]",	"Set radsrv ip and port" ,
  	RadsrvSetCommand, NULL, 2, (void *) SET_SELF },
    { "peer {ip} {secret}",	"Set peer ip and secret" ,
  	RadsrvSetCommand, NULL, 2, (void *) SET_PEER },
    { "enable [opt ...]",	"Enable radsrv option" ,
  	RadsrvSetCommand, NULL, 2, (void *) SET_ENABLE },
    { "disable [opt ...]",	"Disable radsrv option" ,
  	RadsrvSetCommand, NULL, 2, (void *) SET_DISABLE },
    { NULL },
  };


/*
 * INTERNAL VARIABLES
 */

  static const struct confinfo	gConfList[] = {
    { 0,	RADSRV_DISCONNECT,	"disconnect"	},
    { 0,	RADSRV_COA,	"coa"	},
    { 0,	0,		NULL	},
  };

/*
 * RadsrvInit()
 */

int
RadsrvInit(Radsrv w)
{
    /* setup radsrv-defaults */
    memset(&gRadsrv, 0, sizeof(gRadsrv));

    Enable(&w->options, RADSRV_DISCONNECT);
    Enable(&w->options, RADSRV_COA);

    ParseAddr(DEFAULT_RADSRV_IP, &w->addr, ALLOW_IPV4);
    w->port = DEFAULT_RADSRV_PORT;

    return (0);
}

static void
RadsrvEvent(int type, void *cookie)
{
    Radsrv w = (Radsrv)cookie;
    const void	*data;
    size_t	len;
    int res, result;

    result = rad_receive_request(w->handle);
    if (result < 0) {
	Log(LG_ERR, ("radsrv: request receive error: %d", result));
	return;
    }
    switch (result) {
	case RAD_DISCONNECT_REQUEST:
	    if (!Enabled(&w->options, RADSRV_DISCONNECT)) {
		Log(LG_ERR, ("radsrv: DISCONNECT request, support disabled"));
		rad_create_response(w->handle, RAD_DISCONNECT_NAK);
		rad_put_int(w->handle, RAD_ERROR_CAUSE, 501);
		rad_send_response(w->handle);
		return;
	    }
	    Log(LG_ERR, ("radsrv: DISCONNECT request"));
	    break;
	case RAD_COA_REQUEST:
	    if (!Enabled(&w->options, RADSRV_COA)) {
		Log(LG_ERR, ("radsrv: CoA request, support disabled"));
		rad_create_response(w->handle, RAD_COA_NAK);
		rad_put_int(w->handle, RAD_ERROR_CAUSE, 501);
		rad_send_response(w->handle);
		return;
	    }
	    Log(LG_ERR, ("radsrv: CoA request, not yet supported"));
	    rad_create_response(w->handle, RAD_COA_NAK);
	    rad_put_int(w->handle, RAD_ERROR_CAUSE, 406);
	    rad_send_response(w->handle);
	    return;
	default:
	    Log(LG_ERR, ("radsrv: unsupported request: %d", result));
	    return;
    }
    while ((res = rad_get_attr(w->handle, &data, &len)) > 0) {
	switch (res) {
	    case RAD_USER_NAME:
		break;
	}
    }

    rad_create_response(w->handle, RAD_DISCONNECT_NAK);
    rad_send_response(w->handle);
}

/*
 * RadsrvOpen()
 */

int
RadsrvOpen(Radsrv w)
{
    char		addrstr[INET6_ADDRSTRLEN];
    struct sockaddr_in sin;
    struct radiusclient_conf *s;

    if (w->handle) {
	Log(LG_ERR, ("radsrv: radsrv already running"));
	return (-1);
    }

    if ((w->fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1) {
	Log(LG_ERR, ("%s: Cannot create socket: %s", __FUNCTION__, strerror(errno)));
	return (-1);
    }
    memset(&sin, 0, sizeof sin);
    sin.sin_len = sizeof sin;
    sin.sin_family = AF_INET;
    sin.sin_addr = w->addr.u.ip4;
    sin.sin_port = htons(w->port);
    if (bind(w->fd, (const struct sockaddr *)&sin,
	    sizeof sin) == -1) {
	Log(LG_ERR, ("%s: bind: %s", __FUNCTION__, strerror(errno)));
	close(w->fd);
	w->fd = -1;
	return (-1);
    }

    if (!(w->handle = rad_server_open(w->fd))) {
	Log(LG_ERR, ("%s: rad_server_open error", __FUNCTION__));
	close(w->fd);
	w->fd = -1;
	return(-1);
    }

    EventRegister(&w->event, EVENT_READ, w->fd,
	EVENT_RECURRING, RadsrvEvent, w);

    s = w->clients;
    while (s) {
	Log(LG_RADIUS2, ("radsrv: Adding client %s", s->hostname));
	if (rad_add_server (w->handle, s->hostname,
		0, s->sharedsecret, 0, 0) == -1) {
		Log(LG_RADIUS, ("radsrv: Adding client error: %s",
		    rad_strerror(w->handle)));
	}
	s = s->next;
    }

    Log(LG_ERR, ("radsrv: listening on %s %d", 
	u_addrtoa(&w->addr,addrstr,sizeof(addrstr)), w->port));
    return (0);
}

/*
 * RadsrvClose()
 */

int
RadsrvClose(Radsrv w)
{

    if (!w->handle) {
	Log(LG_ERR, ("radsrv: radsrv is not running"));
	return (-1);
    }
    EventUnRegister(&w->event);
    rad_close(w->handle);
    w->handle = NULL;

    Log(LG_ERR, ("radsrv: stop listening"));
    return (0);
}

/*
 * RadsrvStat()
 */

int
RadsrvStat(Context ctx, int ac, char *av[], void *arg)
{
  Radsrv		w = &gRadsrv;
  char		addrstr[64];

  Printf("Radsrv configuration:\r\n");
  Printf("\tState         : %s\r\n", w->handle ? "OPENED" : "CLOSED");
  Printf("\tIP-Address    : %s\r\n", u_addrtoa(&w->addr,addrstr,sizeof(addrstr)));
  Printf("\tPort          : %d\r\n", w->port);

  Printf("Radsrv options:\r\n");
  OptStat(ctx, &w->options, gConfList);

  return 0;
}

/*
 * RadsrvSetCommand()
 */

static int
RadsrvSetCommand(Context ctx, int ac, char *av[], void *arg) 
{
    Radsrv	 w = &gRadsrv;
    int		port, count;
    struct radiusclient_conf *peer, *t_peer;

  switch ((intptr_t)arg) {

    case SET_OPEN:
      RadsrvOpen(w);
      break;

    case SET_CLOSE:
      RadsrvClose(w);
      break;

    case SET_ENABLE:
	EnableCommand(ac, av, &w->options, gConfList);
      break;

    case SET_DISABLE:
	DisableCommand(ac, av, &w->options, gConfList);
      break;

    case SET_SELF:
      if (ac < 1 || ac > 2)
	return(-1);

      if (!ParseAddr(av[0],&w->addr, ALLOW_IPV4)) 
	Error("Bogus IP address given %s", av[0]);

      if (ac == 2) {
        port =  strtol(av[1], NULL, 10);
        if (port < 1 || port > 65535)
	    Error("Bogus port given %s", av[1]);
        w->port=port;
      }
      break;

    case SET_PEER:
	if (ac != 2)
	  return(-1);

	count = 0;
	for ( t_peer = w->clients ; t_peer ;
	  t_peer = t_peer->next) {
	  count++;
	}
	if (count > RADSRV_MAX_SERVERS) {
	  Error("cannot configure more than %d peers",
	    RADSRV_MAX_SERVERS);
	}

	peer = Malloc(MB_RADIUS, sizeof(*peer));

	if (strlen(av[0]) > 255) {
	    Freee(peer);
	    Error("Hostname too long. > 255 char.");
	}

	if (strlen(av[1]) > 127) {
	    Freee(peer);
	    Error("Shared Secret too long. > 127 char.");
	}

	peer->hostname = Mstrdup(MB_RADIUS, av[0]);
	peer->sharedsecret = Mstrdup(MB_RADIUS, av[1]);
	peer->next = w->clients;
	w->clients = peer;
	break;

    default:
      return(-1);

  }

  return 0;
}

#endif
