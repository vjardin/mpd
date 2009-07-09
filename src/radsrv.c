
/*
 * radsrv.c
 *
 * Written by Alexander Motin <mav@FreeBSD.org>
 */

#include "ppp.h"
#include "radsrv.h"
#include "util.h"
#include <radlib.h>
#include <radlib_vs.h>

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
    Radsrv	w = (Radsrv)cookie;
    const void	*data;
    size_t	len;
    int		res, result, found, err, anysesid, l;
    Bund	B;
    Link  	L;
    char        *tmpval;
    char	*username = NULL, *called = NULL, *calling = NULL, *sesid = NULL;
    char	*msesid = NULL;
    int		nasport = -1, serv_type = 0, i;
    struct in_addr ip = { -1 };
    char	buf[64];
    u_int32_t	vendor;
    u_char	*state = NULL;
    int		state_len = 0;
    int		authentic = 0;
#if defined(USE_NG_BPF) && defined(USE_IPFW)
    struct acl	**acls, *acls1;
    char	*acl, *acl1, *acl2, *acl3;
#endif
#ifdef USE_IPFW
    struct acl		*acl_rule = NULL;	/* ipfw rules */
    struct acl		*acl_pipe = NULL;	/* ipfw pipes */
    struct acl		*acl_queue = NULL;	/* ipfw queues */
    struct acl		*acl_table = NULL;	/* ipfw tables */
#endif
#ifdef USE_NG_BPF
    struct acl		*acl_filters[ACL_FILTERS]; /* mpd's internal bpf filters */
    struct acl		*acl_limits[ACL_DIRS];	/* traffic limits based on mpd's filters */

    char 		std_acct[ACL_DIRS][ACL_NAME_LEN]; /* Names of ACL rerurned in standard accounting */
#endif
    bzero(acl_filters, sizeof(acl_filters));
    bzero(acl_limits, sizeof(acl_limits));
    bzero(std_acct, sizeof(std_acct));

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
	    Log(LG_ERR, ("radsrv: CoA request"));
	    break;
	default:
	    Log(LG_ERR, ("radsrv: unsupported request: %d", result));
	    return;
    }
    anysesid = 0;
    while ((res = rad_get_attr(w->handle, &data, &len)) > 0) {
	switch (res) {
	    case RAD_USER_NAME:
		anysesid = 1;
		username = rad_cvt_string(data, len);
		Log(LG_RADIUS2, ("radsrv: Got RAD_USER_NAME: %s",
		    username));
		break;
	    case RAD_SERVICE_TYPE:
		serv_type = rad_cvt_int(data);
		Log(LG_RADIUS2, ("radsrv: Got RAD_SERVICE_TYPE: %d",
		    serv_type));
		break;
    	    case RAD_STATE:
		tmpval = Bin2Hex(data, len);
		Log(LG_RADIUS2, ("radsrv: Get RAD_STATE: 0x%s", tmpval));
		Freee(tmpval);
		state_len = len;
		if (state != NULL)
		    Freee(state);
		state = Mdup(MB_AUTH, data, len);
		break;
	    case RAD_CALLED_STATION_ID:
		anysesid = 1;
		called = rad_cvt_string(data, len);
		Log(LG_RADIUS2, ("radsrv: Got RAD_CALLED_STATION_ID: %s ",
		    called));
		break;
	    case RAD_CALLING_STATION_ID:
		anysesid = 1;
		called = rad_cvt_string(data, len);
		Log(LG_RADIUS2, ("radsrv: Got RAD_CALLING_STATION_ID: %s ",
		    calling));
		break;
	    case RAD_ACCT_SESSION_ID:
		anysesid = 1;
		sesid = rad_cvt_string(data, len);
		Log(LG_RADIUS2, ("radsrv: Got RAD_ACCT_SESSION_ID: %s ",
		    sesid));
		break;
	    case RAD_ACCT_MULTI_SESSION_ID:
		anysesid = 1;
		sesid = rad_cvt_string(data, len);
		Log(LG_RADIUS2, ("radsrv: Got RAD_ACCT_MULTI_SESSION_ID: %s ",
		    msesid));
		break;
	    case RAD_FRAMED_IP_ADDRESS:
		anysesid = 1;
		ip = rad_cvt_addr(data);
		Log(LG_RADIUS2, ("radsrv: Got RAD_FRAMED_IP_ADDRESS: %s ",
		    inet_ntoa(ip)));
		break;
	    case RAD_NAS_PORT:
		anysesid = 1;
		nasport = rad_cvt_int(data);
		Log(LG_RADIUS2, ("radsrv: Got RAD_NAS_PORT: %d ",
		    nasport));
		break;
	    case RAD_MESSAGE_AUTHENTIC:
		Log(LG_RADIUS2, ("radsrv: Got RAD_MESSAGE_AUTHENTIC"));
		authentic = 1;
		break;
	    case RAD_VENDOR_SPECIFIC:
		if ((res = rad_get_vendor_attr(&vendor, &data, &len)) == -1) {
		    Log(LG_RADIUS, ("radsrv: Get vendor attr failed: %s ",
			rad_strerror(w->handle)));
		    break;
		}
		switch (vendor) {
		    case RAD_VENDOR_MPD:
#ifdef USE_IPFW
		        if (res == RAD_MPD_RULE) {
    			  acl1 = acl = rad_cvt_string(data, len);
		    	  Log(LG_RADIUS2, ("radsrv: Get RAD_MPD_RULE: %s",
			    acl));
		    	  acls = &acl_rule;
			} else if (res == RAD_MPD_PIPE) {
			  acl1 = acl = rad_cvt_string(data, len);
		          Log(LG_RADIUS2, ("radsrv: Get RAD_MPD_PIPE: %s",
			    acl));
		          acls = &acl_pipe;
		        } else if (res == RAD_MPD_QUEUE) {
			  acl1 = acl = rad_cvt_string(data, len);
			  Log(LG_RADIUS2, ("radsrv: Get RAD_MPD_QUEUE: %s",
			    acl));
			  acls = &acl_queue;
			} else if (res == RAD_MPD_TABLE) {
			  acl1 = acl = rad_cvt_string(data, len);
			  Log(LG_RADIUS2, ("radsrv: Get RAD_MPD_TABLE: %s",
			    acl));
			  acls = &acl_table;
			} else if (res == RAD_MPD_TABLE_STATIC) {
			  acl1 = acl = rad_cvt_string(data, len);
			  Log(LG_RADIUS2, ("radsrv: Get RAD_MPD_TABLE_STATIC: %s",
			    acl));
			  acls = &acl_table;
			} else
#endif /* USE_IPFW */
#ifdef USE_NG_BPF
			if (res == RAD_MPD_FILTER) {
			  acl1 = acl = rad_cvt_string(data, len);
			  Log(LG_RADIUS2, ("radsrv: Get RAD_MPD_FILTER: %s",
		            acl));
		          acl2 = strsep(&acl1, "#");
		          i = atol(acl2);
		          if (i <= 0 || i > ACL_FILTERS) {
		            Log(LG_RADIUS, ("radsrv: Wrong filter number: %i", i));
		            free(acl);
	    		    break;
			  }
			  acls = &(acl_filters[i - 1]);
			} else if (res == RAD_MPD_LIMIT) {
			  acl1 = acl = rad_cvt_string(data, len);
		          Log(LG_RADIUS2, ("radsrv: Get RAD_MPD_LIMIT: %s",
			    acl));
		          acl2 = strsep(&acl1, "#");
		          if (strcasecmp(acl2, "in") == 0) {
		            i = 0;
		          } else if (strcasecmp(acl2, "out") == 0) {
		            i = 1;
		          } else {
		            Log(LG_ERR, ("radsrv: Wrong limit direction: '%s'",
		    		acl2));
		            free(acl);
			    break;
		          }
		          acls = &(acl_limits[i]);
		        } else if (res == RAD_MPD_INPUT_ACCT) {
			  tmpval = rad_cvt_string(data, len);
	    		  Log(LG_RADIUS2, ("radsrv: Get RAD_MPD_INPUT_ACCT: %s",
	    		    tmpval));
			  strlcpy(std_acct[0], tmpval, sizeof(std_acct[0]));
			  free(tmpval);
			  break;
			} else if (res == RAD_MPD_OUTPUT_ACCT) {
			  tmpval = rad_cvt_string(data, len);
	    		  Log(LG_RADIUS2, ("radsrv: Get RAD_MPD_OUTPUT_ACCT: %s",
	    		    tmpval));
			  strlcpy(std_acct[1], tmpval, sizeof(std_acct[1]));
			  free(tmpval);
			  break;
			} else
#endif /* USE_NG_BPF */
			{
			  Log(LG_RADIUS2, ("radsrv: Dropping MPD vendor specific attribute: %d",
			    res));
	    		  break;
			}
#if defined(USE_NG_BPF) || defined(USE_IPFW)
		    if (acl1 == NULL) {
		      Log(LG_ERR, ("radsrv: Incorrect acl!"));
		      break;
		    }
	    
		    acl3 = acl1;
		    strsep(&acl3, "=");
		    acl2 = acl1;
		    strsep(&acl2, "#");
		    i = atol(acl1);
		    if (i <= 0) {
		      Log(LG_ERR, ("radsrv: Wrong acl number: %i", i));
		      free(acl);
		      break;
		    }
		    if ((acl3 == NULL) || (acl3[0] == 0)) {
		      Log(LG_ERR, ("radsrv: Wrong acl"));
		      free(acl);
		      break;
		    }
		    acls1 = Malloc(MB_AUTH, sizeof(struct acl) + strlen(acl3));
		    if (res != RAD_MPD_TABLE_STATIC) {
			    acls1->number = i;
			    acls1->real_number = 0;
		    } else {
			    acls1->number = 0;
			    acls1->real_number = i;
		    }
		    if (acl2)
	    		strlcpy(acls1->name, acl2, sizeof(acls1->name));
		    strcpy(acls1->rule, acl3);
		    while ((*acls != NULL) && ((*acls)->number < acls1->number))
		      acls = &((*acls)->next);

		    if (*acls == NULL) {
		      acls1->next = NULL;
		    } else if (((*acls)->number == acls1->number) &&
			(res != RAD_MPD_TABLE) &&
			(res != RAD_MPD_TABLE_STATIC)) {
		      Log(LG_ERR, ("radsrv: Duplicate acl"));
		      free(acl);
		      break;
		    } else {
		      acls1->next = *acls;
		    }
		    *acls = acls1;

		    free(acl);
		    break;
#endif /* USE_NG_BPF or USE_IPFW */

		  default:
		    Log(LG_RADIUS2, ("radsrv: Dropping vendor %d attribute: %d ", 
		      vendor, res));
		    break;
		}
		break;
	    default:
		Log(LG_RADIUS2, ("radsrv: Unknown attribute: %d ", 
		    res));
		break;
	}
    }
    if (anysesid == 0 || serv_type != 0) {
	if (result == RAD_DISCONNECT_REQUEST)
	    rad_create_response(w->handle, RAD_DISCONNECT_NAK);
	else
	    rad_create_response(w->handle, RAD_COA_NAK);
	if (state != NULL)
	    rad_put_attr(w->handle, RAD_STATE, state, state_len);
	if (anysesid == 0) {
	    Log(LG_ERR, ("radsrv: request without session identification"));
	    rad_put_int(w->handle, RAD_ERROR_CAUSE, 402);
	} else {
	    Log(LG_ERR, ("radsrv: Service-Type attribute not supported"));
	    rad_put_int(w->handle, RAD_ERROR_CAUSE, 405);
	}
	if (authentic)
	    rad_put_message_authentic(w->handle);
	rad_send_response(w->handle);
	return;
    }
    found = 0;
    err = 503;
    for (l = 0; l < gNumLinks; l++) {
	if ((L = gLinks[l]) != NULL) {
	    B = L->bund;
	    if (nasport != -1 && nasport != l)
		continue;
	    if (sesid && strcmp(sesid, L->session_id))
		continue;
	    if (msesid && strcmp(msesid, L->msession_id))
		continue;
	    if (username && strcmp(username, L->lcp.auth.params.authname))
		continue;
	    if (called && !PhysGetCalledNum(L, buf, sizeof(buf)) &&
		    strcmp(called, buf))
		continue;
	    if (calling && !PhysGetCallingNum(L, buf, sizeof(buf)) &&
		    strcmp(calling, buf))
		continue;
	    if (ip.s_addr != -1 && B &&
		    ip.s_addr != B->iface.peer_addr.u.ip4.s_addr)
		continue;
		
	    Log(LG_RADIUS2, ("radsrv: Matched link: %s",
		L->name));
	    if (L->tmpl) {
		Log(LG_ERR, ("radsrv: Impossible to affect template"));
		err = 504;
		continue;
	    }
	    found++;
	    
	    if (result == RAD_DISCONNECT_REQUEST) {
		RecordLinkUpDownReason(NULL, L, 0, STR_MANUALLY, NULL);
		LinkClose(L);
	    } else { /* CoA */
		if (B && B->iface.up && !B->iface.dod) {
		    if (B->iface.ip_up)
			IfaceIpIfaceDown(B);
		    if (B->iface.ipv6_up)
			IfaceIpv6IfaceDown(B);
		    IfaceDown(B);
		}
#ifdef USE_IPFW
	        ACLDestroy(L->lcp.auth.params.acl_rule);
	        ACLDestroy(L->lcp.auth.params.acl_pipe);
	        ACLDestroy(L->lcp.auth.params.acl_queue);
	        ACLDestroy(L->lcp.auth.params.acl_table);
	        L->lcp.auth.params.acl_rule = NULL;
	        L->lcp.auth.params.acl_pipe = NULL;
	        L->lcp.auth.params.acl_queue = NULL;
	        L->lcp.auth.params.acl_table = NULL;
	        ACLCopy(acl_rule, &L->lcp.auth.params.acl_rule);
	        ACLCopy(acl_pipe, &L->lcp.auth.params.acl_pipe);
	        ACLCopy(acl_queue, &L->lcp.auth.params.acl_queue);
	        ACLCopy(acl_table, &L->lcp.auth.params.acl_table);
#endif /* USE_IPFW */
#ifdef USE_NG_BPF
	        for (i = 0; i < ACL_FILTERS; i++) {
	    	    ACLDestroy(L->lcp.auth.params.acl_filters[i]);
	    	    L->lcp.auth.params.acl_filters[i] = NULL;
	    	    ACLCopy(acl_filters[i], &L->lcp.auth.params.acl_filters[i]);
		}
	        for (i = 0; i < ACL_DIRS; i++) {
	    	    ACLDestroy(L->lcp.auth.params.acl_limits[i]);
	    	    L->lcp.auth.params.acl_limits[i] = NULL;
	    	    ACLCopy(acl_limits[i], &L->lcp.auth.params.acl_limits[i]);
		}
#endif
		strcpy(L->lcp.auth.params.std_acct[0], std_acct[0]);
		strcpy(L->lcp.auth.params.std_acct[1], std_acct[1]);
		if (B && B->iface.up && !B->iface.dod) {
		    authparamsDestroy(&B->params);
		    authparamsCopy(&L->lcp.auth.params,&B->params);
		    if (B->iface.ip_up)
			IfaceIpIfaceUp(B, 1);
		    if (B->iface.ipv6_up)
			IfaceIpv6IfaceUp(B, 1);
		    IfaceUp(B, 1);
		}
	    }
	}
    }
    if (result == RAD_DISCONNECT_REQUEST) {
	if (found) {
	    rad_create_response(w->handle, RAD_DISCONNECT_ACK);
	} else {
	    rad_create_response(w->handle, RAD_DISCONNECT_NAK);
	    rad_put_int(w->handle, RAD_ERROR_CAUSE, err);
	}
    } else {
	if (found) {
	    rad_create_response(w->handle, RAD_COA_ACK);
	} else {
	    rad_create_response(w->handle, RAD_COA_NAK);
	    rad_put_int(w->handle, RAD_ERROR_CAUSE, err);
	}
    }
    if (state != NULL)
        rad_put_attr(w->handle, RAD_STATE, state, state_len);
    if (authentic)
	rad_put_message_authentic(w->handle);
    rad_send_response(w->handle);

    if (username)
	free(username);
    if (called)
	free(called);
    if (calling)
	free(calling);
    if (sesid)
	free(sesid);
    if (msesid)
	free(msesid);
#ifdef USE_IPFW
    ACLDestroy(acl_rule);
    ACLDestroy(acl_pipe);
    ACLDestroy(acl_queue);
    ACLDestroy(acl_table);
#endif /* USE_IPFW */
#ifdef USE_NG_BPF
    for (i = 0; i < ACL_FILTERS; i++)
	ACLDestroy(acl_filters[i]);
    for (i = 0; i < ACL_DIRS; i++)
	ACLDestroy(acl_limits[i]);
#endif /* USE_NG_BPF */
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
