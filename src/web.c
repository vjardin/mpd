
/*
 * web.c
 *
 * Written by Alexander Motin <mav@alkar.net>
 */

#include "ppp.h"
#include "web.h"
#include "util.h"


/*
 * DEFINITIONS
 */

  /* Set menu options */
  enum {
    SET_OPEN,
    SET_CLOSE,
    SET_USER,
    SET_PORT,
    SET_IP,
    SET_DISABLE,
    SET_ENABLE,
  };


/*
 * INTERNAL FUNCTIONS
 */

  static int	WebSetCommand(Context ctx, int ac, char *av[], void *arg);

  static int	WebServletRun(struct http_servlet *servlet,
                         struct http_request *req, struct http_response *resp);
  static void	WebServletDestroy(struct http_servlet *servlet);
  static const char*	WebAuth(void *arg,
                      struct http_request *req, const char *username,
		      const char *password);

  static int            WebUserHashEqual(struct ghash *g, const void *item1,
                              const void *item2);
  static u_int32_t      WebUserHash(struct ghash *g, const void *item);
				     

/*
 * GLOBAL VARIABLES
 */

  const struct cmdtab WebSetCmds[] = {
    { "open",		"Open the web" ,
  	WebSetCommand, NULL, (void *) SET_OPEN },
    { "close",		"Close the web" ,
  	WebSetCommand, NULL, (void *) SET_CLOSE },
    { "user <name> <password>", "Add a web user" ,
      	WebSetCommand, NULL, (void *) SET_USER },
    { "port <port>",		"Set port" ,
  	WebSetCommand, NULL, (void *) SET_PORT },
    { "ip <ip>",		"Set IP address" ,
  	WebSetCommand, NULL, (void *) SET_IP },
    { "enable [opt ...]",	"Enable web option" ,
  	WebSetCommand, NULL, (void *) SET_ENABLE },
    { "disable [opt ...]",	"Disable web option" ,
  	WebSetCommand, NULL, (void *) SET_DISABLE },
    { NULL },
  };


/*
 * INTERNAL VARIABLES
 */

  static const struct confinfo	gConfList[] = {
    { 0,	WEB_AUTH,	"auth"	},
    { 0,	0,		NULL	},
  };

  static struct pevent_ctx *gWebCtx = NULL;
    
/*
 * WebInit()
 */

int
WebInit(Web w)
{
  /* setup web-defaults */
  memset(&gWeb, 0, sizeof(gWeb));

  Enable(&w->options, WEB_AUTH);  
  
  ParseAddr(DEFAULT_WEB_IP, &w->addr, ALLOW_IPV4|ALLOW_IPV6);
  w->port = DEFAULT_WEB_PORT;

  w->users = ghash_create(w, 0, 0, MB_WEB, WebUserHash, WebUserHashEqual, NULL, NULL);

  return 0;
}

/*
 * WebOpen()
 */

int
WebOpen(Web w)
{
  char		addrstr[INET6_ADDRSTRLEN];

  if (w->srv) {
    Log(LG_ERR, ("web: web already running"));
    return -1;
  }

  gWebCtx = pevent_ctx_create(MB_WEB, NULL);
  if (!gWebCtx) {
    Log(LG_ERR, ("%s: error pevent_ctx_create: %d", __FUNCTION__, errno));
    return(-1);
  }
  
  if (!(w->srv = http_server_start(gWebCtx, w->addr.u.ip4,
           w->port, NULL, "mpd web server", NULL))) {
    Log(LG_ERR, ("%s: error http_server_start: %d", __FUNCTION__, errno));
    return(-1);
  }

  if (Enabled(&w->options, WEB_AUTH)) {
    if (!(w->srvlet_auth = http_servlet_basicauth_create(WebAuth, w, NULL))) {
	Log(LG_ERR, ("%s: error http_servlet_basicauth_create: %d", __FUNCTION__, errno));
	return(-1);
    }

    if (http_server_register_servlet(w->srv, w->srvlet_auth, NULL, ".*", 5) < 0) {
	Log(LG_ERR, ("%s: error http_server_register_servlet: %d", __FUNCTION__, errno));
        return(-1);
    }
  }
  
  w->srvlet.arg=NULL;
  w->srvlet.hook=NULL;
  w->srvlet.run=WebServletRun;
  w->srvlet.destroy=WebServletDestroy;
	   
  if (http_server_register_servlet(w->srv, &w->srvlet, NULL, ".*", 10) < 0) {
    Log(LG_ERR, ("%s: error http_server_register_servlet: %d", __FUNCTION__, errno));
    return(-1);
  }
  
  Log(LG_ERR, ("web: listening on %s %d", 
	u_addrtoa(&w->addr,addrstr,sizeof(addrstr)), w->port));
  return 0;
}

/*
 * WebClose()
 */

int
WebClose(Web w)
{
  if (!w->srv) {
    Log(LG_ERR, ("web: web is not running"));
    return -1;
  }

  http_server_stop(&w->srv);
  if (gWebCtx) pevent_ctx_destroy(&gWebCtx);
  
  return 0;
}

/*
 * WebStat()
 */

int
WebStat(Context ctx, int ac, char *av[], void *arg)
{
  Web		w = &gWeb;
  WebUser	u;
  struct ghash_walk     walk;
  char		addrstr[64];

  Printf("Web configuration:\r\n");
  Printf("\tState         : %s\r\n", w->srv ? "OPENED" : "CLOSED");
  Printf("\tIP-Address    : %s\r\n", u_addrtoa(&w->addr,addrstr,sizeof(addrstr)));
  Printf("\tPort          : %d\r\n", w->port);

  Printf("Web options:\r\n");
  OptStat(&w->options, gConfList);

  Printf("Web configured users:\r\n");
  ghash_walk_init(w->users, &walk);
  while ((u = ghash_walk_next(w->users, &walk)) !=  NULL)
    Printf("\tUsername: %s\r\n", u->username);

  return 0;
}

/*
 * ConsoleSessionWriteV()
 */

static void 
WebConsoleSessionWriteV(ConsoleSession cs, const char *fmt, va_list vl)
{
  vfprintf((FILE *)(cs->cookie), fmt, vl);
}

/*
 * WebConsoleSessionWrite()
 */

static void 
WebConsoleSessionWrite(ConsoleSession cs, const char *fmt, ...)
{
  va_list vl;

  va_start(vl, fmt);
  WebConsoleSessionWriteV(cs, fmt, vl);
  va_end(vl);
}

static void
WebShowCSS(FILE *f)
{
  fprintf(f, "body {font : Arial, Helvetica, sans-serif; background-color: #EEEEEE; }\n");
  fprintf(f, "table {background-color: #FFFFFF; }\n");
  fprintf(f, "th {background-color: #00B000; }\n");
  fprintf(f, "td {background-color: #EEEEEE; }\n");
  fprintf(f, "td.r {background-color: #EECCCC; }\n");
  fprintf(f, "td.y {background-color: #EEEEBB; }\n");
  fprintf(f, "td.g {background-color: #BBEEBB; }\n");
  fprintf(f, "pre {background-color: #FFFFFF; }\n");
  fprintf(f, "a, a:visited, a:link { color: blue; }\n");
}

static void
WebShowSummary(FILE *f)
{
  int		b,l;
  Bund		B;
  Link  	L;
  Rep		R;
  PhysInfo	P;
  char		buf[64],buf2[64];

  fprintf(f, "<H2>Current status summary</H2>\n");
  fprintf(f, "<table>\n");
  fprintf(f, "<TR><TH colspan=2>Iface</TH><TH>IPCP</TH><TH>IPV6CP</TH><TH>CCP</TH><TH>ECP</TH><TH>Bund</TH>"
	     "<TH>Link</TH><TH>LCP</TH><TH>User</TH><TH colspan=2>Device</TH><TH>Peer</TH><TH colspan=3></TH><TH></TH></TR>");
  for (b = 0; b<gNumBundles; b++) {
    B=gBundles[b];
    if (B) {
	int shown = 0;
	for (l = 0; l < B->n_links; l++) {
	    L=B->links[l];
	    if (L) {
		fprintf(f, "<TR>\n");
#define FSM_COLOR(s) (((s)==ST_OPENED)?"g":(((s)==ST_INITIAL)?"r":"y"))
#define PHYS_COLOR(s) (((s)==PHYS_STATE_UP)?"g":(((s)==PHYS_STATE_DOWN)?"r":"y"))
		if (!shown) {
		    fprintf(f, "<TD rowspan=\"%d\" class=\"%s\"><A href=\"/cmd?%s&amp;show&amp;iface\">%s</a></TD>\n", 
			B->n_links, (B->iface.up?"g":"r"), L->name, B->iface.ifname);
		    fprintf(f, "<TD rowspan=\"%d\" class=\"%s\"><A href=\"/cmd?%s&amp;show&amp;iface\">%s</a></TD>\n", 
			B->n_links, (B->iface.up?"g":"r"), L->name, (B->iface.up?"Up":"Down"));
		    fprintf(f, "<TD rowspan=\"%d\" class=\"%s\"><A href=\"/cmd?%s&amp;show&amp;ipcp\">%s</a></TD>\n", 
			B->n_links, FSM_COLOR(B->ipcp.fsm.state), L->name,FsmStateName(B->ipcp.fsm.state));
		    fprintf(f, "<TD rowspan=\"%d\" class=\"%s\"><A href=\"/cmd?%s&amp;show&amp;ipv6cp\">%s</a></TD>\n", 
			B->n_links, FSM_COLOR(B->ipv6cp.fsm.state), L->name,FsmStateName(B->ipv6cp.fsm.state));
		    fprintf(f, "<TD rowspan=\"%d\" class=\"%s\"><A href=\"/cmd?%s&amp;show&amp;ccp\">%s</a></TD>\n", 
			B->n_links, FSM_COLOR(B->ccp.fsm.state), L->name,FsmStateName(B->ccp.fsm.state));
		    fprintf(f, "<TD rowspan=\"%d\" class=\"%s\"><A href=\"/cmd?%s&amp;show&amp;ecp\">%s</a></TD>\n", 
			B->n_links, FSM_COLOR(B->ecp.fsm.state), L->name,FsmStateName(B->ecp.fsm.state));
		    fprintf(f, "<TD rowspan=\"%d\"><A href=\"/cmd?%s&amp;show&amp;bund\">%s</a></TD>\n", 
			B->n_links, L->name, B->name);
		}
		fprintf(f, "<TD><A href=\"/cmd?%s&amp;show&amp;link\">%s</a></TD>\n", 
		    L->name, L->name);
		fprintf(f, "<TD class=\"%s\"><A href=\"/cmd?%s&amp;show&amp;lcp\">%s</a></TD>\n", 
		    FSM_COLOR(L->lcp.fsm.state), L->name, FsmStateName(L->lcp.fsm.state));
		fprintf(f, "<TD><A href=\"/cmd?%s&amp;show&amp;auth\">%s</a></TD>\n", 
		    L->name, L->lcp.auth.params.authname);
		fprintf(f, "<TD class=\"%s\"><A href=\"/cmd?%s&amp;show&amp;phys\">%s</a></TD>\n", 
		    PHYS_COLOR(L->phys->state), L->name, L->phys->type?L->phys->type->name:"");
		fprintf(f, "<TD class=\"%s\"><A href=\"/cmd?%s&amp;show&amp;phys\">%s</a></TD>\n", 
		    PHYS_COLOR(L->phys->state), L->name, gPhysStateNames[L->phys->state]);
		if (L->phys->state != PHYS_STATE_DOWN) {
		    PhysGetPeerAddr(L->phys, buf, sizeof(buf));
		    fprintf(f, "<TD>%s</TD>\n", buf);
		    PhysGetCallingNum(L->phys, buf, sizeof(buf));
		    PhysGetCalledNum(L->phys, buf2, sizeof(buf2));
		    if (PhysGetOriginate(L->phys) == LINK_ORIGINATE_REMOTE) {
			    fprintf(f, "<TD>%s</TD><TD><=</TD><TD>%s</TD>\n", 
				buf2, buf);
		    } else {
			    fprintf(f, "<TD>%s</TD><TD>=></TD><TD>%s</TD>\n", 
				buf, buf2);
		    }
		} else {
			fprintf(f, "<TD></TD>\n");
			fprintf(f, "<TD colspan=3></TD>\n");
		}
		fprintf(f, "<TD><A href=\"/cmd?%s&amp;open\">[Open]</a><A href=\"/cmd?%s&amp;close\">[Close]</a></TD>\n", 
		    L->name, L->name);
		fprintf(f, "</TR>\n");
		
		shown = 1;
	    }
	}
    }
  }
  for (b = 0; b<gNumReps; b++) {
    R=gReps[b];
    if (R) {
	int shown = 0;
	for (l = 0; l < 2; l++) {
	    P=R->physes[l];
	    if (P) {
		fprintf(f, "<TR>\n");
#define FSM_COLOR(s) (((s)==ST_OPENED)?"g":(((s)==ST_INITIAL)?"r":"y"))
#define PHYS_COLOR(s) (((s)==PHYS_STATE_UP)?"g":(((s)==PHYS_STATE_DOWN)?"r":"y"))
		if (!shown) {
		    fprintf(f, "<TD rowspan=2 colspan=6>Repeater</TD>\n");
		    fprintf(f, "<TD rowspan=2 class=\"%s\"><A href=\"/cmd?%s&amp;show&amp;repeater\">%s</a></TD>\n", 
			(R->p_up?"g":"r"), P->name, R->name);
		}
		fprintf(f, "<TD colspan=3></TD>\n");
		fprintf(f, "<TD class=\"%s\"><A href=\"/cmd?%s&amp;show&amp;phys\">%s</a></TD>\n", 
		    PHYS_COLOR(P->state), P->name, P->type?P->type->name:"");
		fprintf(f, "<TD class=\"%s\"><A href=\"/cmd?%s&amp;show&amp;phys\">%s</a></TD>\n", 
		    PHYS_COLOR(P->state), P->name, gPhysStateNames[P->state]);
		if (P->state != PHYS_STATE_DOWN) {
		    PhysGetPeerAddr(P, buf, sizeof(buf));
		    fprintf(f, "<TD>%s</TD>\n", buf);
		    PhysGetCallingNum(P, buf, sizeof(buf));
		    PhysGetCalledNum(P, buf2, sizeof(buf2));
		    if (PhysGetOriginate(P) == LINK_ORIGINATE_REMOTE) {
			    fprintf(f, "<TD>%s</TD><TD><=</TD><TD>%s</TD>\n", 
				buf2, buf);
		    } else {
			    fprintf(f, "<TD>%s</TD><TD>=></TD><TD>%s</TD>\n", 
				buf, buf2);
		    }
		} else {
			fprintf(f, "<TD></TD>\n");
			fprintf(f, "<TD colspan=3></TD>\n");
		}
		fprintf(f, "<TD></TD>\n");
		fprintf(f, "</TR>\n");
		
		shown = 1;
	    }
	}
    }
  }
  fprintf(f, "</TABLE>\n");
}

static void
WebRunCmdCleanup(void *cookie) {
    gConsoleSession = NULL;;
}

static void 
WebRunCmd(FILE *f, const char *querry)
{
  Console		c = &gConsole;
  struct console_session css;
  ConsoleSession	cs = &css;
  char			buf[1024];
  char			buf1[1024];
  char			*tmp;
  int			argc;
  char			*argv[MAX_CONSOLE_ARGS];
  char			*av[MAX_CONSOLE_ARGS];
  int			k;
  
  memset(cs, 0, sizeof(*cs));

  cs->cookie = f;
  cs->console = c;
  cs->close = NULL;
  cs->write = WebConsoleSessionWrite;
  cs->writev = WebConsoleSessionWriteV;
  cs->prompt = NULL;

  strlcpy(buf,querry,sizeof(buf));
  tmp = buf;
  
  for (argc = 0; (argv[argc] = strsep(&tmp, "&")) != NULL;)
      if (argv[argc][0] != '\0')
         if (++argc >= MAX_CONSOLE_ARGS)
            break;

  if (argc > 0) {
    fprintf(f, "<H2>Command '");
    for (k = 1; k < argc; k++) {
	fprintf(f, "%s ",argv[k]);
    }
    fprintf(f, "' for phys '%s'</H2>\n", argv[0]);

    if ((!strcmp(argv[1], "show")) ||
	(!strcmp(argv[1], "open")) ||
	(!strcmp(argv[1], "close"))) {

	fprintf(f, "<P><A href=\"/\"><< Back</A></P>\n");
    
	fprintf(f, "<PRE>\n");

	pthread_cleanup_push(WebRunCmdCleanup, NULL);
	gConsoleSession = cs;

	strcpy(buf1, "phys");
        av[0] = buf1;
        av[1] = argv[0];
        DoCommand(&cs->context, 2, av, NULL, 0);
  
        for (k = 1; k < argc; k++) {
    	    av[k-1] = argv[k];
        }
        DoCommand(&cs->context, argc-1, av, NULL, 0);

	gConsoleSession = NULL;;
	pthread_cleanup_pop(0);

	fprintf(f, "</PRE>\n");
    } else {
	fprintf(f, "<P>Command denied!</P>\n");
    }
  } else {
    fprintf(f, "<P>No command cpecified!</P>\n");
  }
  fprintf(f, "<P><A href=\"/\"><< Back</A></P>\n");
}

static void
WebServletRunCleanup(void *cookie) {
    GIANT_MUTEX_UNLOCK();
}

static int	
WebServletRun(struct http_servlet *servlet,
                         struct http_request *req, struct http_response *resp)
{
    FILE *f;
    const char *path;
    const char *querry;

    if (!(f = http_response_get_output(resp, 0))) {
	return 0;
    }
    if (!(path = http_request_get_path(req)))
	return 0;
    if (!(querry = http_request_get_query_string(req)))
	return 0;

    if (!strcmp(path,"/mpd.css")) {
	http_response_set_header(resp, 0, "Content-Type", "text/css");
	WebShowCSS(f);
    } else {
	http_response_set_header(resp, 0, "Content-Type", "text/html");
	http_response_set_header(resp, 1, "Pragma", "no-cache");
	http_response_set_header(resp, 1, "Cache-Control", "no-cache, must-revalidate");
	
	pthread_cleanup_push(WebServletRunCleanup, NULL);
	GIANT_MUTEX_LOCK();
	fprintf(f, "<!DOCTYPE HTML "
	    "PUBLIC \"-//W3C//DTD HTML 4.01//EN\" "
	    "\"http://www.w3.org/TR/html4/strict.dtd\">\n");
	fprintf(f, "<HTML>\n");
	fprintf(f, "<HEAD><TITLE>Multi-link PPP Daemon for FreeBSD (mpd)</TITLE>\n");
	fprintf(f, "<LINK rel='stylesheet' href='/mpd.css' type='text/css'>\n");
	fprintf(f, "</HEAD>\n<BODY>\n");
	fprintf(f, "<H1>Multi-link PPP Daemon for FreeBSD</H1>\n");
    
	if (!strcmp(path,"/"))
	    WebShowSummary(f);
	else if (!strcmp(path,"/cmd"))
	    WebRunCmd(f, querry);
	    
	GIANT_MUTEX_UNLOCK();
	pthread_cleanup_pop(0);
	
	fprintf(f, "</BODY>\n</HTML>\n");
    }
    return 1;
};

static void	
WebServletDestroy(struct http_servlet *servlet)
{
};

static const char*	
WebAuth(void *arg, struct http_request *req, const char *username,
		      const char *password) 
{
    Web	w = (Web)arg;
    
    WebUser u;

    u = ghash_get(w->users, &username);

    if ((u == NULL) || strcmp(u->password, password)) 
      return "Access Denied";

    return NULL;    
}

/*
 * WebUserHash
 *
 * Fowler/Noll/Vo- hash
 * see http://www.isthe.com/chongo/tech/comp/fnv/index.html
 *
 * By:
 *  chongo <Landon Curt Noll> /\oo/\
 *  http://www.isthe.com/chongo/
 */

static u_int32_t
WebUserHash(struct ghash *g, const void *item)
{
  WebUser u = (WebUser) item;
  u_char *s = (u_char *) u->username;
  u_int32_t hash = 0x811c9dc5;

  while (*s) {
    hash += (hash<<1) + (hash<<4) + (hash<<7) + (hash<<8) + (hash<<24);
    /* xor the bottom with the current octet */
    hash ^= (u_int32_t)*s++;
  }

  return hash;
}

/*
 * WebUserHashEqual
 */

static int
WebUserHashEqual(struct ghash *g, const void *item1, const void *item2)
{
  WebUser u1 = (WebUser) item1;
  WebUser u2 = (WebUser) item2;

  if (u1 && u2)
    return (strcmp(u1->username, u2->username) == 0);
  else
    return 0;
}


/*
 * WebSetCommand()
 */

static int
WebSetCommand(Context ctx, int ac, char *av[], void *arg) 
{
  Web	 		w = &gWeb;
  WebUser		u;
  int			port;

  switch ((intptr_t)arg) {

    case SET_OPEN:
      WebOpen(w);
      break;

    case SET_CLOSE:
      WebClose(w);
      break;

    case SET_ENABLE:
	EnableCommand(ac, av, &w->options, gConfList);
      break;

    case SET_DISABLE:
	DisableCommand(ac, av, &w->options, gConfList);
      break;

    case SET_USER:
      if (ac != 2) 
	return(-1);

      u = Malloc(MB_WEB, sizeof(*u));
      u->username = typed_mem_strdup(MB_WEB, av[0]);
      u->password = typed_mem_strdup(MB_WEB, av[1]);
      ghash_put(w->users, u);
      break;

    case SET_PORT:
      if (ac != 1)
	return(-1);

      port =  strtol(av[0], NULL, 10);
      if (port < 1 && port > 65535) {
	Log(LG_ERR, ("web: Bogus port given %s", av[0]));
	return(-1);
      }
      w->port=port;
      break;

    case SET_IP:
      if (ac != 1)
	return(-1);

      if (!ParseAddr(av[0],&w->addr, ALLOW_IPV4)) 
      {
	Log(LG_ERR, ("web: Bogus IP address given %s", av[0]));
	return(-1);
      }
      break;

    default:
      return(-1);

  }

  return 0;
}
