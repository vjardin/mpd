
/*
 * auth.c
 *
 * Written by Archie Cobbs <archie@freebsd.org>
 * Copyright (c) 1995-1999 Whistle Communications, Inc. All rights reserved.
 * See ``COPYRIGHT.whistle''
 */

#include "ppp.h"
#include "auth.h"
#include "pap.h"
#include "chap.h"
#include "lcp.h"
#include "log.h"
#include "ngfunc.h"
#include "msoft.h"
#include "util.h"

#include <libutil.h>
#include <security/pam_appl.h>	

/*
 * DEFINITIONS
 */
    
  #define OPIE_ALG_MD5	5
  
/*
 * INTERNAL FUNCTIONS
 */

  static void		AuthTimeout(void *arg);
  static int		AuthGetExternalPassword(char * extcmd, char *authname,
			    char *password, size_t passlen);
  static void		AuthAsync(void *arg);
  static void		AuthAsyncFinish(void *arg, int was_canceled);
  static int		AuthPreChecks(AuthData auth);
  static void		AuthAccountTimeout(void *arg);
  static void		AuthAccount(void *arg);
  static void		AuthAccountFinish(void *arg, int was_canceled);
  static void		AuthInternal(AuthData auth);
  static void		AuthExternal(AuthData auth);
  static void		AuthExternalAcct(AuthData auth);
  static void		AuthSystem(AuthData auth);
  static void		AuthSystemAcct(AuthData auth);
  static void		AuthPAM(AuthData auth);
  static void		AuthPAMAcct(AuthData auth);
  static int		pam_conv(int n, const struct pam_message **msg,
			    struct pam_response **resp, void *data);
  static void		AuthOpie(AuthData auth);
  static const char	*AuthCode(int proto, u_char code, char *buf, size_t len);
  static int		AuthSetCommand(Context ctx, int ac, char *av[], void *arg);

  /* Set menu options */
  enum {
    SET_ACCEPT,
    SET_DENY,
    SET_ENABLE,
    SET_DISABLE,
    SET_YES,
    SET_NO,
    SET_AUTHNAME,
    SET_PASSWORD,
    SET_EXTAUTH_SCRIPT,
    SET_EXTACCT_SCRIPT,
    SET_MAX_LOGINS,
    SET_ACCT_UPDATE,
    SET_ACCT_UPDATE_LIMIT_IN,
    SET_ACCT_UPDATE_LIMIT_OUT,
    SET_TIMEOUT,
  };

/*
 * GLOBAL VARIABLES
 */

  const struct cmdtab AuthSetCmds[] = {
    { "max-logins {num}",		"Max concurrent logins",
	AuthSetCommand, NULL, 2, (void *) SET_MAX_LOGINS },
    { "authname {name}",		"Authentication name",
	AuthSetCommand, NULL, 2, (void *) SET_AUTHNAME },
    { "password {pass}",		"Authentication password",
	AuthSetCommand, NULL, 2, (void *) SET_PASSWORD },
    { "extauth-script {script}",	"Authentication script",
	AuthSetCommand, NULL, 2, (void *) SET_EXTAUTH_SCRIPT },
    { "extacct-script {script}",	"Accounting script",
	AuthSetCommand, NULL, 2, (void *) SET_EXTACCT_SCRIPT },
    { "acct-update {seconds}",		"set update interval",
	AuthSetCommand, NULL, 2, (void *) SET_ACCT_UPDATE },
    { "update-limit-in {bytes}",	"set update suppresion limit",
	AuthSetCommand, NULL, 2, (void *) SET_ACCT_UPDATE_LIMIT_IN },
    { "update-limit-out {bytes}",	"set update suppresion limit",
	AuthSetCommand, NULL, 2, (void *) SET_ACCT_UPDATE_LIMIT_OUT },
    { "timeout {seconds}",		"set auth timeout",
	AuthSetCommand, NULL, 2, (void *) SET_TIMEOUT },
    { "accept [opt ...]",		"Accept option",
	AuthSetCommand, NULL, 2, (void *) SET_ACCEPT },
    { "deny [opt ...]",			"Deny option",
	AuthSetCommand, NULL, 2, (void *) SET_DENY },
    { "enable [opt ...]",		"Enable option",
	AuthSetCommand, NULL, 2, (void *) SET_ENABLE },
    { "disable [opt ...]",		"Disable option",
	AuthSetCommand, NULL, 2, (void *) SET_DISABLE },
    { "yes [opt ...]",			"Enable and accept option",
	AuthSetCommand, NULL, 2, (void *) SET_YES },
    { "no [opt ...]",			"Disable and deny option",
	AuthSetCommand, NULL, 2, (void *) SET_NO },
    { NULL },
  };

  const u_char	gMsoftZeros[32];
  int		gMaxLogins = 0;	/* max number of concurrent logins per user */

/*
 * INTERNAL VARIABLES
 */

  static struct confinfo	gConfList[] = {
    { 0,	AUTH_CONF_RADIUS_AUTH,	"radius-auth"	},
    { 0,	AUTH_CONF_RADIUS_ACCT,	"radius-acct"	},
    { 0,	AUTH_CONF_INTERNAL,	"internal"	},
    { 0,	AUTH_CONF_EXT_AUTH,	"ext-auth"	},
    { 0,	AUTH_CONF_EXT_ACCT,	"ext-acct"	},
    { 0,	AUTH_CONF_SYSTEM_AUTH,	"system-auth"	},
    { 0,	AUTH_CONF_SYSTEM_ACCT,	"system-acct"	},
    { 0,	AUTH_CONF_PAM_AUTH,	"pam-auth"	},
    { 0,	AUTH_CONF_PAM_ACCT,	"pam-acct"	},
    { 0,	AUTH_CONF_OPIE,		"opie"		},
    { 0,	0,			NULL		},
  };

void	authparamsInit(struct authparams *ap) {
    memset(ap,0,sizeof(struct authparams));
    SLIST_INIT(&ap->routes);
};

void	authparamsDestroy(struct authparams *ap) {
    struct acl		*acls, *acls1;
    IfaceRoute		r;
    int i;
  
    if (ap->eapmsg) {
	Freee(ap->eapmsg);
    }
    if (ap->state) {
	Freee(ap->state);
    }
    if (ap->class) {
	Freee(ap->class);
    }

    acls = ap->acl_rule;
    while (acls != NULL) {
	acls1 = acls->next;
	Freee(acls);
	acls = acls1;
    };
    acls = ap->acl_pipe;
    while (acls != NULL) {
	acls1 = acls->next;
	Freee(acls);
	acls = acls1;
    };
    acls = ap->acl_queue;
    while (acls != NULL) {
	acls1 = acls->next;
	Freee(acls);
	acls = acls1;
    };
    acls = ap->acl_table;
    while (acls != NULL) {
	acls1 = acls->next;
	Freee(acls);
	acls = acls1;
    };

    for (i = 0; i < ACL_FILTERS; i++) {
	acls = ap->acl_filters[i];
	while (acls != NULL) {
	    acls1 = acls->next;
	    Freee(acls);
	    acls = acls1;
	};
    };

    for (i = 0; i < ACL_DIRS; i++) {
	acls = ap->acl_limits[i];
	while (acls != NULL) {
	    acls1 = acls->next;
	    Freee(acls);
	    acls = acls1;
	};
    };

    while ((r = SLIST_FIRST(&ap->routes)) != NULL) {
	SLIST_REMOVE_HEAD(&ap->routes, next);
	Freee(r);
    }

    if (ap->msdomain) {
	Freee(ap->msdomain);
    }
    
    memset(ap,0,sizeof(struct authparams));
};

void	authparamsCopy(struct authparams *src, struct authparams *dst) {
    struct acl		*acls;
    struct acl		**pacl;
    IfaceRoute		r, r1;
    int			i;

    memcpy(dst,src,sizeof(struct authparams));
  
    if (src->eapmsg)
	dst->eapmsg = Mdup(MB_AUTH, src->eapmsg, src->eapmsg_len);
    if (src->state)
	dst->state = Mdup(MB_AUTH, src->state, src->state_len);
    if (src->class)
	dst->class = Mdup(MB_AUTH, src->class, src->class_len);

    acls = src->acl_rule;
    pacl = &dst->acl_rule;
    while (acls != NULL) {
	*pacl = Mdup(MB_AUTH, acls, sizeof(struct acl));
	acls = acls->next;
	pacl = &((*pacl)->next);
    };
    *pacl = NULL;
    acls = src->acl_pipe;
    pacl = &dst->acl_pipe;
    while (acls != NULL) {
	*pacl = Mdup(MB_AUTH, acls, sizeof(struct acl));
	acls = acls->next;
	pacl = &((*pacl)->next);
    };
    *pacl = NULL;
    acls = src->acl_queue;
    pacl = &dst->acl_queue;
    while (acls != NULL) {
	*pacl = Mdup(MB_AUTH, acls, sizeof(struct acl));
	acls = acls->next;
	pacl = &((*pacl)->next);
    };
    *pacl = NULL;
    acls = src->acl_table;
    pacl = &dst->acl_table;
    while (acls != NULL) {
	*pacl = Mdup(MB_AUTH, acls, sizeof(struct acl));
	acls = acls->next;
	pacl = &((*pacl)->next);
    };
    *pacl = NULL;

    for (i = 0; i < ACL_FILTERS; i++) {
	acls = src->acl_filters[i];
	pacl = &dst->acl_filters[i];
	while (acls != NULL) {
	    *pacl = Mdup(MB_AUTH, acls, sizeof(struct acl));
	    acls = acls->next;
	    pacl = &((*pacl)->next);
	};
	*pacl = NULL;
    };

    for (i = 0; i < ACL_DIRS; i++) {
	acls = src->acl_limits[i];
	pacl = &dst->acl_limits[i];
	while (acls != NULL) {
	    *pacl = Mdup(MB_AUTH, acls, sizeof(struct acl));
	    acls = acls->next;
	    pacl = &((*pacl)->next);
	};
	*pacl = NULL;
    };

    SLIST_INIT(&dst->routes);
    SLIST_FOREACH(r, &src->routes, next) {
	r1 = Mdup(MB_AUTH, r, sizeof(*r1));
	SLIST_INSERT_HEAD(&dst->routes, r1, next);
    }

    if (src->msdomain)
	dst->msdomain = Mdup(MB_AUTH, src->msdomain, strlen(src->msdomain)+1);
};

void	authparamsMove(struct authparams *src, struct authparams *dst)
{
    memcpy(dst,src,sizeof(struct authparams));
    memset(src,0,sizeof(struct authparams));
}

/*
 * AuthInit()
 */

void
AuthInit(Link l)
{
    AuthConf	const ac = &l->lcp.auth.conf;
  
    ac->timeout = 40;
    Enable(&ac->options, AUTH_CONF_INTERNAL);

    EapInit(l);
    RadiusInit(l);
}

/*
 * AuthShutdown()
 */

void
AuthShutdown(Link l)
{
    Auth	a = &l->lcp.auth;
  
    if (a->thread)
	paction_cancel(&a->thread);
    if (a->acct_thread)
	paction_cancel(&a->acct_thread);
}

/*
 * AuthStart()
 *
 * Initialize authorization info for a link
 */

void
AuthStart(Link l)
{
    Auth	a = &l->lcp.auth;

    /* generate a uniq session id */
    snprintf(l->session_id, AUTH_MAX_SESSIONID, "%d-%s",
	(int)(time(NULL) % 10000000), l->name);

    authparamsInit(&a->params);

    /* What auth protocols were negotiated by LCP? */
    a->self_to_peer = l->lcp.peer_auth;
    a->peer_to_self = l->lcp.want_auth;

    /* remember peer's IP address */
    PhysGetPeerAddr(l, a->params.peeraddr, sizeof(a->params.peeraddr));
  
    /* remember peer's TCP or UDP port */
    PhysGetPeerPort(l, a->params.peerport, sizeof(a->params.peerport));
  
    /* remember peer's MAC address */
    PhysGetPeerMacAddr(l, a->params.peermacaddr, sizeof(a->params.peermacaddr));
  
    /* remember peer's iface */
    PhysGetPeerIface(l, a->params.peeriface, sizeof(a->params.peeriface));
  
    /* remember calling number */
    PhysGetCallingNum(l, a->params.callingnum, sizeof(a->params.callingnum));
  
    /* remember called number */
    PhysGetCalledNum(l, a->params.callednum, sizeof(a->params.callednum));
    
  Log(LG_AUTH, ("[%s] %s: auth: peer wants %s, I want %s",
    Pref(&l->lcp.fsm), Fsm(&l->lcp.fsm),
    a->self_to_peer ? ProtoName(a->self_to_peer) : "nothing",
    a->peer_to_self ? ProtoName(a->peer_to_self) : "nothing"));

  /* Is there anything to do? */
  if (!a->self_to_peer && !a->peer_to_self) {
    LcpAuthResult(l, TRUE);
    return;
  }

  /* Start global auth timer */
  TimerInit(&a->timer, "AuthTimer",
    l->lcp.auth.conf.timeout * SECONDS, AuthTimeout, l);
  TimerStart(&a->timer);

  /* Start my auth to him */
  switch (a->self_to_peer) {
    case 0:
      break;
    case PROTO_PAP:
      PapStart(l, AUTH_SELF_TO_PEER);
      break;
    case PROTO_CHAP:
      ChapStart(l, AUTH_SELF_TO_PEER);
      break;
    case PROTO_EAP:
      EapStart(l, AUTH_SELF_TO_PEER);
      break;
    default:
      assert(0);
  }

  /* Start his auth to me */
  switch (a->peer_to_self) {
    case 0:
      break;
    case PROTO_PAP:
      PapStart(l, AUTH_PEER_TO_SELF);
      break;
    case PROTO_CHAP:
      ChapStart(l, AUTH_PEER_TO_SELF);
      break;
    case PROTO_EAP:
      EapStart(l, AUTH_PEER_TO_SELF);
      break;
    default:
      assert(0);
  }
}

/*
 * AuthInput()
 *
 * Deal with PAP/CHAP/EAP packet
 */

void
AuthInput(Link l, int proto, Mbuf bp)
{
  AuthData		auth;
  Auth			const a = &l->lcp.auth;
  int			len;
  struct fsmheader	fsmh;
  u_char		*pkt;

  /* Sanity check */
  if (l->lcp.phase != PHASE_AUTHENTICATE && l->lcp.phase != PHASE_NETWORK) {
    Log(LG_AUTH, ("[%s] AUTH: rec'd stray packet", l->name));
    PFREE(bp);
    return;
  }
  
  if (a->thread) {
    Log(LG_AUTH, ("[%s] AUTH: Thread already running, dropping this packet", 
      l->name));
    PFREE(bp);
    return;
  }

  /* Make packet a single mbuf */
  len = plength(bp = mbunify(bp));

  /* Sanity check length */
  if (len < sizeof(fsmh)) {
    Log(LG_AUTH, ("[%s] AUTH: rec'd runt packet: %d bytes",
      l->name, len));
    PFREE(bp);
    return;
  }

  auth = AuthDataNew(l);
  auth->proto = proto;

  bp = mbread(bp, (u_char *) &fsmh, sizeof(fsmh), NULL);
  len -= sizeof(fsmh);
  if (len > ntohs(fsmh.length))
    len = ntohs(fsmh.length);

  if (bp == NULL && proto != PROTO_EAP && proto != PROTO_CHAP)
  {
    char	failMesg[64];
    u_char	code = 0;

    Log(LG_AUTH, (" Bad packet"));
    auth->why_fail = AUTH_FAIL_INVALID_PACKET;
    AuthFailMsg(auth, 0, failMesg, sizeof(failMesg));
    if (proto == PROTO_PAP)
      code = PAP_NAK;
    else
      assert(0);
    AuthOutput(l, proto, code, fsmh.id, (u_char *)failMesg, strlen(failMesg), 1, 0);
    AuthFinish(l, AUTH_PEER_TO_SELF, FALSE);
    AuthDataDestroy(auth);
    return;
  }

  pkt = MBDATA(bp);

  auth->id = fsmh.id;
  auth->code = fsmh.code;
  /* Status defaults to undefined */
  auth->status = AUTH_STATUS_UNDEF;
  
  switch (proto) {
    case PROTO_PAP:
      PapInput(l, auth, pkt, len);
      break;
    case PROTO_CHAP:
      ChapInput(l, auth, pkt, len);
      break;
    case PROTO_EAP:
      EapInput(l, auth, pkt, len);
      break;
    default:
      assert(0);
  }
  
  PFREE(bp);
}

/*
 * AuthOutput()
 *
 */

void
AuthOutput(Link l, int proto, u_int code, u_int id, const u_char *ptr,
	int len, int add_len, u_char eap_type)
{
  struct fsmheader	lh;
  Mbuf			bp;
  int			plen;
  char			buf[32];

  add_len = !!add_len;
  /* Setup header */
  if (proto == PROTO_EAP)
    plen = sizeof(lh) + len + add_len + 1;
  else
    plen = sizeof(lh) + len + add_len;
  lh.code = code;
  lh.id = id;
  lh.length = htons(plen);

  /* Build packet */
  bp = mballoc(MB_AUTH, plen);
  memcpy(MBDATAU(bp), &lh, sizeof(lh));
  if (proto == PROTO_EAP)
    memcpy(MBDATAU(bp) + sizeof(lh), &eap_type, 1);

  if (add_len)
    *(MBDATAU(bp) + sizeof(lh)) = (u_char)len;

  if (proto == PROTO_EAP) {
    memcpy(MBDATAU(bp) + sizeof(lh) + add_len + 1, ptr, len);
    Log(LG_AUTH, ("[%s] %s: sending %s Type %s len:%d", l->name,
      ProtoName(proto), AuthCode(proto, code, buf, sizeof(buf)), EapType(eap_type), len));
  } else {
    memcpy(MBDATAU(bp) + sizeof(lh) + add_len, ptr, len);
    Log(LG_AUTH, ("[%s] %s: sending %s len:%d", l->name,
      ProtoName(proto), AuthCode(proto, code, buf, sizeof(buf)), len));
  }

  /* Send it out */

  NgFuncWritePppFrameLink(l, proto, bp);
}

/*
 * AuthFinish()
 *
 * Authorization is finished, so continue one way or the other
 */

void
AuthFinish(Link l, int which, int ok)
{
    Auth	const a = &l->lcp.auth;

    if (which == AUTH_SELF_TO_PEER)
        a->self_to_peer = 0;
    else
        a->peer_to_self = 0;
    /* Did auth fail (in either direction)? */
    if (!ok) {
	AuthStop(l);
	LcpAuthResult(l, FALSE);
	return;
    }
    /* Did auth succeed (in both directions)? */
    if (!a->peer_to_self && !a->self_to_peer) {
	AuthStop(l);
	LcpAuthResult(l, TRUE);
	return;
    }
}

/*
 * AuthCleanup()
 *
 * Cleanup auth structure, invoked on link-down
 */

void
AuthCleanup(Link l)
{
    Auth	a = &l->lcp.auth;

    Log(LG_AUTH, ("[%s] AUTH: Cleanup", l->name));

    authparamsDestroy(&a->params);

    l->session_id[0] = 0;
}

/* 
 * AuthDataNew()
 *
 * Create a new auth-data object
 */

AuthData
AuthDataNew(Link l) 
{
    AuthData	auth;
    Auth	a = &l->lcp.auth;  

    auth = Malloc(MB_AUTH, sizeof(*auth));
    auth->conf = l->lcp.auth.conf;

    strlcpy(auth->info.lnkname, l->name, sizeof(auth->info.lnkname));
    strlcpy(auth->info.msession_id, l->msession_id, sizeof(auth->info.msession_id));
    strlcpy(auth->info.session_id, l->session_id, sizeof(auth->info.session_id));
    strlcpy(auth->info.peer_ident, l->lcp.peer_ident, sizeof(l->lcp.peer_ident));

    if (l->bund) {
	strlcpy(auth->info.ifname, l->bund->iface.ifname, sizeof(auth->info.ifname));
	strlcpy(auth->info.bundname, l->bund->name, sizeof(auth->info.bundname));
        auth->info.n_links = l->bund->n_links;
	auth->info.peer_addr = l->bund->ipcp.peer_addr;
    }

    /* Copy current link statistics */
    memcpy(&auth->info.stats, &l->stats, sizeof(auth->info.stats));
    
    /* If it is present copy services statistics */
    if (l->bund) {
	IfaceGetStats(l->bund, &auth->info.ss);
	IfaceAddStats(&auth->info.ss, &l->bund->iface.prevstats);
    }

    if (l->downReasonValid)
	auth->info.downReason = Mdup(MB_LINK, l->downReason, strlen(l->downReason) + 1);

    auth->info.last_open = l->last_open;
    auth->info.phys_type = l->type;
    auth->info.linkID = l->id;

    authparamsCopy(&a->params,&auth->params);

    return auth;
}

/*
 * AuthDataDestroy()
 *
 * Destroy authdata
 */

void
AuthDataDestroy(AuthData auth)
{
    authparamsDestroy(&auth->params);
    Freee(auth->info.downReason);
    Freee(auth->reply_message);
    Freee(auth->mschap_error);
    Freee(auth->mschapv2resp);
    IfaceFreeStats(&auth->info.ss);
    Freee(auth);
}

/*
 * AuthStop()
 *
 * Stop the authorization process
 */

void
AuthStop(Link l)
{
  Auth	a = &l->lcp.auth;

  TimerStop(&a->timer);
  PapStop(&a->pap);
  ChapStop(&a->chap);
  EapStop(&a->eap);
  paction_cancel(&a->thread);
}

/*
 * AuthStat()
 *
 * Show auth stats
 */
 
int
AuthStat(Context ctx, int ac, char *av[], void *arg)
{
    Auth	const au = &ctx->lnk->lcp.auth;
    AuthConf	const conf = &au->conf;
    char	buf[64];
    struct acl	*a;
    IfaceRoute	r;
    int		k;

    Printf("Configuration:\r\n");
    Printf("\tMy authname     : %s\r\n", conf->authname);
    Printf("\tMax-Logins      : %d\r\n", gMaxLogins);
    Printf("\tAcct Update     : %d\r\n", conf->acct_update);
    Printf("\t   Limit In     : %d\r\n", conf->acct_update_lim_recv);
    Printf("\t   Limit Out    : %d\r\n", conf->acct_update_lim_xmit);
    Printf("\tAuth timeout    : %d\r\n", conf->timeout);
    Printf("\tExtAuth script  : %s\r\n", conf->extauth_script);
    Printf("\tExtAcct script  : %s\r\n", conf->extacct_script);
  
    Printf("Auth options\r\n");
    OptStat(ctx, &conf->options, gConfList);

    Printf("Auth Data\r\n");
    Printf("\tPeer authname   : %s\r\n", au->params.authname);
    Printf("\tIP range        : %s\r\n", (au->params.range_valid)?
	u_rangetoa(&au->params.range,buf,sizeof(buf)):"");
    Printf("\tIP pool         : %s\r\n", au->params.ippool);
    Printf("\tMTU             : %u\r\n", au->params.mtu);
    Printf("\tSession-Timeout : %u\r\n", au->params.session_timeout);
    Printf("\tIdle-Timeout    : %u\r\n", au->params.idle_timeout);
    Printf("\tAcct-Update     : %u\r\n", au->params.acct_update);
    Printf("\tRoutes          :\r\n");
    SLIST_FOREACH(r, &au->params.routes, next) {
        Printf("\t\t%s\r\n", u_rangetoa(&r->dest,buf,sizeof(buf)));
    }
    Printf("\tIPFW rules      :\r\n");
    a = au->params.acl_rule;
    while (a) {
        Printf("\t\t%d\t: '%s'\r\n", a->number, a->rule);
        a = a->next;
    }
    Printf("\tIPFW pipes      :\r\n");
    a = au->params.acl_pipe;
    while (a) {
        Printf("\t\t%d\t: '%s'\r\n", a->number, a->rule);
        a = a->next;
    }
    Printf("\tIPFW queues     :\r\n");
    a = au->params.acl_queue;
    while (a) {
        Printf("\t\t%d\t: '%s'\r\n", a->number, a->rule);
        a = a->next;
    }
    Printf("\tIPFW tables     :\r\n");
    a = au->params.acl_table;
    while (a) {
        if (a->number != 0)
    	    Printf("\t\t%d\t: '%s'\r\n", a->number, a->rule);
        else
    	    Printf("\t\t#%d\t: '%s'\r\n", a->real_number, a->rule);
        a = a->next;
    }
    Printf("\tTraffic filters :\r\n");
    for (k = 0; k < ACL_FILTERS; k++) {
        a = au->params.acl_filters[k];
        while (a) {
    	    Printf("\t%d#%d\t: '%s'\r\n", (k + 1), a->number, a->rule);
    	    a = a->next;
	}
    }
    Printf("\tTraffic limits  :\r\n");
    for (k = 0; k < 2; k++) {
        a = au->params.acl_limits[k];
	while (a) {
	    Printf("\t\t%s#%d%s%s\t: '%s'\r\n", (k?"out":"in"), a->number,
		((a->name[0])?"#":""), a->name, a->rule);
	    a = a->next;
	}
    }
    Printf("\tMS-Domain       : %s\r\n", au->params.msdomain);  
    Printf("\tMPPE Types      : %s\r\n", AuthMPPEPolicyname(au->params.msoft.policy));
    Printf("\tMPPE Policy     : %s\r\n", AuthMPPETypesname(au->params.msoft.types, buf, sizeof(buf)));
    Printf("\tMPPE Keys       : %s\r\n", au->params.msoft.has_keys ? "yes" : "no");

    return (0);
}


/*
 * AuthAccount()
 *
 * Accounting stuff, 
 */
 
void
AuthAccountStart(Link l, int type)
{
  Auth		const a = &l->lcp.auth;
  AuthData	auth;
  u_long	updateInterval = 0;
      
  /* maybe an outstanding thread is running */
  if (a->acct_thread) {
    if (type == AUTH_ACCT_START || type == AUTH_ACCT_STOP) {
	paction_cancel(&a->acct_thread);
    } else {
	Log(LG_AUTH, ("[%s] AUTH: Accounting thread is already running", 
    	    l->name));
	return;
    }
  }

  LinkUpdateStats(l);
  if (type == AUTH_ACCT_STOP) {
    Log(LG_AUTH, ("[%s] AUTH: Accounting data for user %s: %lu seconds, %llu octets in, %llu octets out",
      l->name, a->params.authname,
      (unsigned long) (time(NULL) - l->last_open),
      (unsigned long long)l->stats.recvOctets,
      (unsigned long long)l->stats.xmitOctets));
  }

  if (type == AUTH_ACCT_START) {
  
    if (a->params.acct_update > 0)
      updateInterval = a->params.acct_update;
    else if (l->lcp.auth.conf.acct_update > 0)
      updateInterval = l->lcp.auth.conf.acct_update;

    if (updateInterval > 0) {
	/* Save initial statistics. */
	memcpy(&a->prev_stats, &l->stats, 
	  sizeof(a->prev_stats));

	/* Start accounting update timer. */
	TimerInit(&a->acct_timer, "AuthAccountTimer",
	  updateInterval * SECONDS, AuthAccountTimeout, l);
	TimerStartRecurring(&a->acct_timer);
    }
  }
  
  if (type == AUTH_ACCT_UPDATE) {
    /*
     * Suppress sending of accounting update, if byte threshold
     * is configured, and delta since last update doesn't exceed it.
     */
    if (a->conf.acct_update_lim_recv > 0 ||
      a->conf.acct_update_lim_xmit > 0) {
	if ((l->stats.recvOctets - a->prev_stats.recvOctets <
    	   a->conf.acct_update_lim_recv) &&
    	  (l->stats.xmitOctets - a->prev_stats.xmitOctets <
    	   a->conf.acct_update_lim_xmit)) {
    	    Log(LG_AUTH, ("[%s] AUTH: Shouldn't send Interim-Update",
    	      l->name));
    	    return;
        } else {
	    /* Save current statistics. */
	    memcpy(&a->prev_stats, &l->stats, 
	      sizeof(a->prev_stats));
        }
    }
  }
    
  if (type == AUTH_ACCT_STOP) {
    /* Stop accounting update timer if running. */
    TimerStop(&a->acct_timer);
  }
    
  auth = AuthDataNew(l);
  auth->acct_type = type;

  if (paction_start(&a->acct_thread, &gGiantMutex, AuthAccount, 
    AuthAccountFinish, auth) == -1) {
    Log(LG_ERR, ("[%s] AUTH: Couldn't start Accounting-Thread %d", 
      l->name, errno));
    AuthDataDestroy(auth);
  }

}

/*
 * AuthAccountTimeout()
 *
 * Timer function for accounting updates
 */
 
static void
AuthAccountTimeout(void *arg)
{
    Link	l = (Link)arg;
  
    Log(LG_AUTH, ("[%s] AUTH: Sending Accounting Update",
	l->name));

    AuthAccountStart(l, AUTH_ACCT_UPDATE);
}

/*
 * AuthAccount()
 *
 * Asynchr. accounting handler, called from a paction.
 * NOTE: Thread safety is needed here
 */
 
static void
AuthAccount(void *arg)
{
    AuthData	const auth = (AuthData)arg;
  
    Log(LG_AUTH, ("[%s] AUTH: Accounting-Thread started", auth->info.lnkname));
  
    if (Enabled(&auth->conf.options, AUTH_CONF_RADIUS_ACCT))
	RadiusAccount(auth);

    if (Enabled(&auth->conf.options, AUTH_CONF_PAM_ACCT))
	AuthPAMAcct(auth);

    if (Enabled(&auth->conf.options, AUTH_CONF_SYSTEM_ACCT))
	AuthSystemAcct(auth);

    if (Enabled(&auth->conf.options, AUTH_CONF_EXT_ACCT))
	AuthExternalAcct(auth);
}

/*
 * AuthAccountFinish
 * 
 * Return point for the accounting thread()
 */
 
static void
AuthAccountFinish(void *arg, int was_canceled)
{
    AuthData		auth = (AuthData)arg;
    Link 		l;

    if (was_canceled) {
	Log(LG_AUTH, ("[%s] AUTH: Accounting-Thread was canceled", 
    	    auth->info.lnkname));
    } else {
	Log(LG_AUTH, ("[%s] AUTH: Accounting-Thread finished normally", 
	    auth->info.lnkname));
    }
    
    /* Cleanup */
    RadiusClose(auth);

    if (was_canceled) {
	AuthDataDestroy(auth);
	return;
    }  
    
    l = gLinks[auth->info.linkID];
    if (l == NULL) {
	AuthDataDestroy(auth);
	return;
    }    

    if (auth->drop_user && auth->acct_type != AUTH_ACCT_STOP) {
	Log(LG_AUTH, ("[%s] AUTH: Link close requested at the accounting reply", 
	    l->name));
	RecordLinkUpDownReason(NULL, l, 0, STR_MANUALLY, NULL);
	LinkClose(l);
    }
    AuthDataDestroy(auth);
    LinkShutdownCheck(l, l->lcp.fsm.state);
}

/*
 * AuthGetData()
 *
 * NOTE: Thread safety is needed here
 */

int
AuthGetData(char *authname, char *password, size_t passlen, 
    struct u_range *range, u_char *range_valid)
{
  FILE		*fp;
  int		ac;
  char		*av[20];
  char		*line;

  /* Check authname, must be non-empty */
  if (authname == NULL || authname[0] == 0) {
    return(-1);
  }

  /* Search secrets file */
  if ((fp = OpenConfFile(SECRET_FILE, NULL)) == NULL)
    return(-1);
  while ((line = ReadFullLine(fp, NULL, NULL, 0)) != NULL) {
    memset(av, 0, sizeof(av));
    ac = ParseLine(line, av, sizeof(av) / sizeof(*av), 1);
    Freee(line);
    if (ac >= 2
	&& (strcmp(av[0], authname) == 0
	 || (av[1][0] == '!' && strcmp(av[0], "*") == 0))) {
      if (av[1][0] == '!') {		/* external auth program */
	if (AuthGetExternalPassword((av[1]+1), 
	    authname, password, passlen) == -1) {
	  FreeArgs(ac, av);
	  fclose(fp);
	  return(-1);
	}
      } else {
	strlcpy(password, av[1], passlen);
      }
      if (range != NULL && range_valid != NULL) {
        u_rangeclear(range);
        if (ac >= 3)
	    *range_valid = ParseRange(av[2], range, ALLOW_IPV4);
	else
	    *range_valid = FALSE;
      }
      FreeArgs(ac, av);
      fclose(fp);
      return(0);
    }
    FreeArgs(ac, av);
  }
  fclose(fp);

  return(-1);		/* Invalid */
}

/*
 * AuthAsyncStart()
 *
 * Starts the Auth-Thread
 */

void 
AuthAsyncStart(Link l, AuthData auth)
{
    Auth	const a = &l->lcp.auth;
    char	*rept;
    
    /* Check link action */
    rept = LinkMatchAction(l, 2, auth->params.authname);
    if (rept) {
	/* Action told we must forward this connection */
	if (RepCreate(l, rept)) {
	    Log(LG_ERR, ("[%s] Repeater to \"%s\" creation error", l->name, rept));
	    PhysClose(l);
	    return;
	}
	/* Create repeater */
	RepIncoming(l);
	/* Reconnect link netgraph hook to repeater */
	LinkNgToRep(l);
	/* Kill the LCP */
	LcpDown(l);
	LcpClose(l);
	return;
    }
  
  /* perform pre authentication checks (single-login, etc.) */
  if (AuthPreChecks(auth) < 0) {
    Log(LG_AUTH, ("[%s] AUTH: AuthPreCheck failed for \"%s\"", 
      l->name, auth->params.authname));
    auth->finish(l, auth);
    return;
  }

  if (paction_start(&a->thread, &gGiantMutex, AuthAsync, 
    AuthAsyncFinish, auth) == -1) {
    Log(LG_ERR, ("[%s] AUTH: Couldn't start Auth-Thread %d", 
      l->name, errno));
    auth->status = AUTH_STATUS_FAIL;
    auth->why_fail = AUTH_FAIL_NOT_EXPECTED;
    auth->finish(l, auth);
  }
}

/*
 * AuthAsync()
 *
 * Asynchr. auth handler, called from a paction.
 * NOTE: Thread safety is needed here
 */
 
static void
AuthAsync(void *arg)
{
  AuthData	const auth = (AuthData)arg;

  Log(LG_AUTH, ("[%s] AUTH: Auth-Thread started", auth->info.lnkname));

  if (Enabled(&auth->conf.options, AUTH_CONF_EXT_AUTH)) {
    auth->params.authentic = AUTH_CONF_EXT_AUTH;
    Log(LG_AUTH, ("[%s] AUTH: Trying EXTERNAL", auth->info.lnkname));
    AuthExternal(auth);
    Log(LG_AUTH, ("[%s] AUTH: EXTERNAL returned %s", auth->info.lnkname, AuthStatusText(auth->status)));
    if (auth->status == AUTH_STATUS_SUCCESS 
      || auth->status == AUTH_STATUS_UNDEF)
	return;
  }

  if (auth->proto == PROTO_EAP && auth->eap_radius) {
    auth->params.authentic = AUTH_CONF_RADIUS_AUTH;
    RadiusEapProxy(auth);
    return;
  } else if (Enabled(&auth->conf.options, AUTH_CONF_RADIUS_AUTH)) {
    auth->params.authentic = AUTH_CONF_RADIUS_AUTH;
    Log(LG_AUTH, ("[%s] AUTH: Trying RADIUS", auth->info.lnkname));
    RadiusAuthenticate(auth);
    Log(LG_AUTH, ("[%s] AUTH: RADIUS returned %s", 
      auth->info.lnkname, AuthStatusText(auth->status)));
    if (auth->status == AUTH_STATUS_SUCCESS)
      return;
  }
  
  if (Enabled(&auth->conf.options, AUTH_CONF_PAM_AUTH)) {
    auth->params.authentic = AUTH_CONF_PAM_AUTH;
    Log(LG_AUTH, ("[%s] AUTH: Trying PAM", auth->info.lnkname));
    AuthPAM(auth);
    Log(LG_AUTH, ("[%s] AUTH: PAM returned %s", 
      auth->info.lnkname, AuthStatusText(auth->status)));
    if (auth->status == AUTH_STATUS_SUCCESS 
      || auth->status == AUTH_STATUS_UNDEF)
        return;
  }

  if (Enabled(&auth->conf.options, AUTH_CONF_SYSTEM_AUTH)) {
    auth->params.authentic = AUTH_CONF_SYSTEM_AUTH;
    Log(LG_AUTH, ("[%s] AUTH: Trying SYSTEM", auth->info.lnkname));
    AuthSystem(auth);
    Log(LG_AUTH, ("[%s] AUTH: SYSTEM returned %s", 
      auth->info.lnkname, AuthStatusText(auth->status)));
    if (auth->status == AUTH_STATUS_SUCCESS 
      || auth->status == AUTH_STATUS_UNDEF)
        return;
  }
  
  if (Enabled(&auth->conf.options, AUTH_CONF_OPIE)) {
    auth->params.authentic = AUTH_CONF_OPIE;
    Log(LG_AUTH, ("[%s] AUTH: Trying OPIE", auth->info.lnkname));
    AuthOpie(auth);
    Log(LG_AUTH, ("[%s] AUTH: OPIE returned %s", 
      auth->info.lnkname, AuthStatusText(auth->status)));
    if (auth->status == AUTH_STATUS_SUCCESS 
      || auth->status == AUTH_STATUS_UNDEF)
        return;
  }    
  
  if (Enabled(&auth->conf.options, AUTH_CONF_INTERNAL)) {
    auth->params.authentic = AUTH_CONF_INTERNAL;
    Log(LG_AUTH, ("[%s] AUTH: Trying INTERNAL", auth->info.lnkname));
    AuthInternal(auth);
    Log(LG_AUTH, ("[%s] AUTH: INTERNAL returned %s", 
      auth->info.lnkname, AuthStatusText(auth->status)));
    if (auth->status == AUTH_STATUS_SUCCESS 
      || auth->status == AUTH_STATUS_UNDEF)
         return;
  } 

  Log(LG_AUTH, ("[%s] AUTH: ran out of backends", auth->info.lnkname));
  auth->status = AUTH_STATUS_FAIL;
  auth->why_fail = AUTH_FAIL_INVALID_LOGIN;
}

/*
 * AuthAsyncFinish()
 * 
 * Return point for the auth thread
 */
 
static void
AuthAsyncFinish(void *arg, int was_canceled)
{
    AuthData	auth = (AuthData)arg;
    Link	l;

    if (was_canceled)
	Log(LG_AUTH, ("[%s] AUTH: Auth-Thread was canceled", auth->info.lnkname));

    /* cleanup */
    RadiusClose(auth);
  
    if (was_canceled) {
	AuthDataDestroy(auth);
	return;
    }  
  
    l = gLinks[auth->info.linkID];
    if (l == NULL) {
	AuthDataDestroy(auth);
	return;
    }    

    Log(LG_AUTH, ("[%s] AUTH: Auth-Thread finished normally", l->name));

    /* Replace modified data */
    authparamsDestroy(&l->lcp.auth.params);
    authparamsMove(&auth->params,&l->lcp.auth.params);
  
    auth->finish(l, auth);
}

/*
 * AuthInternal()
 * 
 * Authenticate against mpd.secrets
 */
 
static void
AuthInternal(AuthData auth)
{
    if (AuthGetData(auth->params.authname, auth->params.password, 
	    sizeof(auth->params.password), &auth->params.range, 
	    &auth->params.range_valid) < 0) {
	Log(LG_AUTH, ("AUTH: User \"%s\" not found in secret file", 
	    auth->params.authname));
	auth->status = AUTH_STATUS_FAIL;
	auth->why_fail = AUTH_FAIL_INVALID_LOGIN;
	return;
    }
    auth->status = AUTH_STATUS_UNDEF;
}

/*
 * AuthSystem()
 * 
 * Authenticate against Systems password database
 */
 
static void
AuthSystem(AuthData auth)
{
  PapParams	pp = &auth->params.pap;
  struct passwd	*pw;
  struct passwd pwc;
  u_char	*bin;
  int 		err;
  
  /* protect getpwnam and errno 
   * NOTE: getpwnam_r doesen't exists on FreeBSD < 5.1 */
  GIANT_MUTEX_LOCK();
  errno = 0;
  pw = getpwnam(auth->params.authname);
  if (!pw) {
    err=errno;
    GIANT_MUTEX_UNLOCK(); /* We must release lock before Log() */
    if (err)
      Log(LG_ERR, ("AUTH: Error retrieving passwd %s", strerror(errno)));
    else
      Log(LG_AUTH, ("AUTH: User \"%s\" not found in the systems database", auth->params.authname));
    auth->status = AUTH_STATUS_FAIL;
    auth->why_fail = AUTH_FAIL_INVALID_LOGIN;
    return;
  }
  memcpy(&pwc,pw,sizeof(struct passwd)); /* we must make copy before release lock */
  GIANT_MUTEX_UNLOCK();
  
  Log(LG_AUTH, ("AUTH: Found user %s Uid:%d Gid:%d Fmt:%*.*s", pwc.pw_name, 
    pwc.pw_uid, pwc.pw_gid, 3, 3, pwc.pw_passwd));

  if (auth->proto == PROTO_PAP) {
    /* protect non-ts crypt() */
    GIANT_MUTEX_LOCK();
    if (strcmp(crypt(pp->peer_pass, pwc.pw_passwd), pwc.pw_passwd) == 0) {
      auth->status = AUTH_STATUS_SUCCESS;
    } else {
      auth->status = AUTH_STATUS_FAIL;
      auth->why_fail = AUTH_FAIL_INVALID_LOGIN;
    }
    GIANT_MUTEX_UNLOCK();
    return;
  } else if (auth->proto == PROTO_CHAP 
      && (auth->params.chap.recv_alg == CHAP_ALG_MSOFT 
        || auth->params.chap.recv_alg == CHAP_ALG_MSOFTv2)) {

    if (!strstr(pwc.pw_passwd, "$3$$")) {
      Log(LG_AUTH, (" Password has the wrong format, nth ($3$) is needed"));
      auth->status = AUTH_STATUS_FAIL;
      auth->why_fail = AUTH_FAIL_INVALID_LOGIN;
      return;
    }

    bin = Hex2Bin(&pwc.pw_passwd[4]);
    memcpy(auth->params.msoft.nt_hash, bin, sizeof(auth->params.msoft.nt_hash));
    Freee(bin);
    NTPasswordHashHash(auth->params.msoft.nt_hash, auth->params.msoft.nt_hash_hash);
    auth->params.msoft.has_nt_hash = TRUE;
    auth->status = AUTH_STATUS_UNDEF;
    return;

  } else {
    Log(LG_ERR, (" Using systems password database only possible for PAP and MS-CHAP"));
    auth->status = AUTH_STATUS_FAIL;
    auth->why_fail = AUTH_FAIL_NOT_EXPECTED;
    return;
  }

}

/*
 * AuthSystemAcct()
 * 
 * Account with system
 */

static void
AuthSystemAcct(AuthData auth)
{
	struct utmp	ut;

	memset(&ut, 0, sizeof(ut));
	strlcpy(ut.ut_line, auth->info.lnkname, sizeof(ut.ut_line));

	if (auth->acct_type == AUTH_ACCT_START) {
    	    time_t	t;

    	    strlcpy(ut.ut_host, auth->params.peeraddr, sizeof(ut.ut_host));
    	    strlcpy(ut.ut_name, auth->params.authname, sizeof(ut.ut_name));
    	    time(&t);
    	    ut.ut_time = t;
    	    login(&ut);
    	    Log(LG_AUTH, ("[%s] AUTH: wtmp %s %s %s login", auth->info.lnkname, ut.ut_line, 
    		ut.ut_name, ut.ut_host));
	} else if (auth->acct_type == AUTH_ACCT_STOP) {
    	    Log(LG_AUTH, ("[%s] AUTH: wtmp %s logout", auth->info.lnkname, ut.ut_line));
    	    logout(ut.ut_line);
    	    logwtmp(ut.ut_line, "", "");
	}
}

/*
 * AuthPAM()
 * 
 * Authenticate with PAM system
 */

static int
pam_conv(int n, const struct pam_message **msg, struct pam_response **resp,
  void *data)
{
    AuthData 	auth = (AuthData)data;
    int		i;

    for (i = 0; i < n; i++) {
	Log(LG_AUTH, ("[%s] AUTH: PAM: %s",
    	    auth->info.lnkname, msg[i]->msg));
    }

    /* We support only requests for password */
    if (n != 1 || msg[0]->msg_style != PAM_PROMPT_ECHO_OFF)
	return (PAM_CONV_ERR);

    if ((*resp = malloc(sizeof(struct pam_response))) == NULL)
	return (PAM_CONV_ERR);
    (*resp)[0].resp = strdup(auth->params.pap.peer_pass);
    (*resp)[0].resp_retcode = 0;

    return ((*resp)[0].resp != NULL ? PAM_SUCCESS : PAM_CONV_ERR);
}
 
static void
AuthPAM(AuthData auth)
{
    struct pam_conv pamc = {
        &pam_conv,
	auth
    };
    pam_handle_t *pamh;
    int status;

    if (auth->proto != PROTO_PAP) {
	Log(LG_ERR, ("[%s] Using PAM only possible for PAP", auth->info.lnkname));
	auth->status = AUTH_STATUS_FAIL;
	auth->why_fail = AUTH_FAIL_NOT_EXPECTED;
	return;
    }
    
    if (pam_start("mpd", auth->params.authname, &pamc, &pamh) != PAM_SUCCESS) {
	Log(LG_ERR, ("[%s] PAM error", auth->info.lnkname));
	auth->status = AUTH_STATUS_FAIL;
	auth->why_fail = AUTH_FAIL_NOT_EXPECTED;
	return;
    }

    if (auth->params.peeraddr[0] &&
	pam_set_item(pamh, PAM_RHOST, auth->params.peeraddr) != PAM_SUCCESS) {
	Log(LG_ERR, ("[%s] PAM set PAM_RHOST error", auth->info.lnkname));
    }

    if (pam_set_item(pamh, PAM_TTY, auth->info.lnkname) != PAM_SUCCESS) {
	Log(LG_ERR, ("[%s] PAM set PAM_TTY error", auth->info.lnkname));
    }

    status = pam_authenticate(pamh, 0);

    if (status == PAM_SUCCESS) {
	status = pam_acct_mgmt(pamh, 0);
    }

    if (status == PAM_SUCCESS) {
	auth->status = AUTH_STATUS_SUCCESS;
    } else {
	Log(LG_AUTH, ("[%s] AUTH: PAM error: %s",
	    auth->info.lnkname, pam_strerror(pamh, status)));
	switch (status) {
	case PAM_AUTH_ERR:
	case PAM_USER_UNKNOWN:
    	    auth->status = AUTH_STATUS_FAIL;
    	    auth->why_fail = AUTH_FAIL_INVALID_LOGIN;
	    break;
	case PAM_ACCT_EXPIRED:
	case PAM_AUTHTOK_EXPIRED:
	case PAM_CRED_EXPIRED:
    	    auth->status = AUTH_STATUS_FAIL;
    	    auth->why_fail = AUTH_FAIL_ACCT_DISABLED;
	    break;
	default:
    	    auth->status = AUTH_STATUS_FAIL;
    	    auth->why_fail = AUTH_FAIL_NOT_EXPECTED;
	}
    }

    pam_end(pamh, status);
}

/*
 * AuthPAMAcct()
 * 
 * Account with system
 */

static void
AuthPAMAcct(AuthData auth)
{
    pam_handle_t *pamh;
    int status;
    struct pam_conv pamc = {
        &pam_conv,
	auth
    };
    
    if (auth->acct_type != AUTH_ACCT_START &&
      auth->acct_type != AUTH_ACCT_STOP) {
        return;
    }

    if (pam_start("mpd", auth->params.authname, &pamc, &pamh) != PAM_SUCCESS) {
	Log(LG_ERR, ("[%s] PAM error", auth->info.lnkname));
	return;
    }

    if (auth->params.peeraddr[0] &&
	pam_set_item(pamh, PAM_RHOST, auth->params.peeraddr) != PAM_SUCCESS) {
	Log(LG_ERR, ("[%s] PAM set PAM_RHOST error", auth->info.lnkname));
    }

    if (pam_set_item(pamh, PAM_TTY, auth->info.lnkname) != PAM_SUCCESS) {
	Log(LG_ERR, ("[%s] PAM set PAM_TTY error", auth->info.lnkname));
    }

    if (auth->acct_type == AUTH_ACCT_START) {
    	    Log(LG_AUTH, ("[%s] AUTH: PAM open session \"%s\"",
		auth->info.lnkname, auth->params.authname));
	    status = pam_open_session(pamh, 0);
    } else {
    	    Log(LG_AUTH, ("[%s] AUTH: PAM close session \"%s\"",
		auth->info.lnkname, auth->params.authname));
	    status = pam_close_session(pamh, 0);
    }
    if (status != PAM_SUCCESS) {
    	Log(LG_AUTH, ("[%s] AUTH: PAM session error",
	    auth->info.lnkname));
    }
    
    pam_end(pamh, status);
}

/*
 * AuthOpie()
 */

static void
AuthOpie(AuthData auth)
{
  PapParams	const pp = &auth->params.pap;
  struct	opie_otpkey key;
  char		opieprompt[OPIE_CHALLENGE_MAX + 1];
  int		ret, n;
  char		secret[OPIE_SECRET_MAX + 1];
  char		english[OPIE_RESPONSE_MAX + 1];

  ret = opiechallenge(&auth->opie.data, auth->params.authname, opieprompt);

  auth->status = AUTH_STATUS_UNDEF;
  
  switch (ret) {
    case 0:
      break;
  
    case 1:
      Log(LG_ERR, (" User \"%s\" not found in opiekeys", auth->params.authname));
      auth->status = AUTH_STATUS_FAIL;
      auth->why_fail = AUTH_FAIL_INVALID_LOGIN;
      return;

    case -1:
    case 2:
    default:
      Log(LG_ERR, (" System error"));
      auth->status = AUTH_STATUS_FAIL;
      auth->why_fail = AUTH_FAIL_NOT_EXPECTED;
      return;
  };

  Log(LG_AUTH, (" Opieprompt:%s", opieprompt));

  if (auth->proto == PROTO_PAP ) {
    if (!opieverify(&auth->opie.data, pp->peer_pass)) {
      auth->status = AUTH_STATUS_SUCCESS;
    } else {
      auth->why_fail = AUTH_FAIL_INVALID_LOGIN;
      auth->status = AUTH_STATUS_FAIL;
    }
    return;
  }

  if (AuthGetData(auth->params.authname, secret, sizeof(secret), NULL, NULL) < 0) {
    Log(LG_AUTH, (" Can't get credentials for \"%s\"", auth->params.authname));
    auth->status = AUTH_STATUS_FAIL;
    auth->why_fail = AUTH_FAIL_INVALID_LOGIN;    
    return;
  }
  
  opiekeycrunch(OPIE_ALG_MD5, &key, auth->opie.data.opie_seed, secret);
  n = auth->opie.data.opie_n - 1;
  while (n-- > 0)
    opiehash(&key, OPIE_ALG_MD5);

  opiebtoe(english, &key);
  strlcpy(auth->params.password, english, sizeof(auth->params.password));
}

/*
 * AuthPreChecks()
 */

static int
AuthPreChecks(AuthData auth)
{

  if (!strlen(auth->params.authname)) {
    Log(LG_AUTH, (" We don't accept empty usernames"));
    auth->status = AUTH_STATUS_FAIL;
    auth->why_fail = AUTH_FAIL_INVALID_LOGIN;
    return (-1);
  }
  /* check max. number of logins */
  if (gMaxLogins != 0) {
    int		ac;
    u_long	num = 0;
    for(ac = 0; ac < gNumBundles; ac++)
      if (gBundles[ac] && gBundles[ac]->open)
	if (!strcmp(gBundles[ac]->params.authname, auth->params.authname))
	  num++;

    if (num >= gMaxLogins) {
	Log(LG_AUTH, (" Name: \"%s\" max. number of logins exceeded",
	    auth->params.authname));
        auth->status = AUTH_STATUS_FAIL;
        auth->why_fail = AUTH_FAIL_INVALID_LOGIN;
        return (-1);
    }
  }
  return (0);
}

/*
 * AuthTimeout()
 *
 * Timer expired for the whole authorization process
 */

static void
AuthTimeout(void *arg)
{
    Link l = (Link)arg;

  Log(LG_AUTH, ("[%s] %s: authorization timer expired", Pref(&l->lcp.fsm), Fsm(&l->lcp.fsm)));
  AuthStop(l);
  LcpAuthResult(l, FALSE);
}

/* 
 * AuthFailMsg()
 */

const char *
AuthFailMsg(AuthData auth, int alg, char *buf, size_t len)
{
    const char	*mesg;

    if (auth->proto == PROTO_CHAP
        && (alg == CHAP_ALG_MSOFT || alg == CHAP_ALG_MSOFTv2)) {
	    int	mscode;

	    if (auth->mschap_error != NULL) {
    		    strlcpy(buf, auth->mschap_error, len);
		    return(buf);
	    }

	    switch (auth->why_fail) {
    	      case AUTH_FAIL_ACCT_DISABLED:
		mscode = MSCHAP_ERROR_ACCT_DISABLED;
		mesg = AUTH_MSG_ACCT_DISAB;
		break;
	      case AUTH_FAIL_NO_PERMISSION:
		mscode = MSCHAP_ERROR_NO_DIALIN_PERMISSION;
		mesg = AUTH_MSG_NOT_ALLOWED;
		break;
	      case AUTH_FAIL_RESTRICTED_HOURS:
		mscode = MSCHAP_ERROR_RESTRICTED_LOGON_HOURS;
		mesg = AUTH_MSG_RESTR_HOURS;
		break;
	      case AUTH_FAIL_INVALID_PACKET:
	      case AUTH_FAIL_INVALID_LOGIN:
	      case AUTH_FAIL_NOT_EXPECTED:
	      default:
		mscode = MSCHAP_ERROR_AUTHENTICATION_FAILURE;
		mesg = AUTH_MSG_INVALID;
		break;
	    }

    	    snprintf(buf, len, "E=%d R=0 M=%s", mscode, mesg);
    
    } else {

	    if (auth->reply_message != NULL) {
    		    strlcpy(buf, auth->reply_message, len);
		    return(buf);
	    }

	    switch (auth->why_fail) {
	      case AUTH_FAIL_ACCT_DISABLED:
		mesg = AUTH_MSG_ACCT_DISAB;
		break;
	      case AUTH_FAIL_NO_PERMISSION:
		mesg = AUTH_MSG_NOT_ALLOWED;
		break;
	      case AUTH_FAIL_RESTRICTED_HOURS:
		mesg = AUTH_MSG_RESTR_HOURS;
		break;
	      case AUTH_FAIL_NOT_EXPECTED:
		mesg = AUTH_MSG_NOT_EXPECTED;
		break;
	      case AUTH_FAIL_INVALID_PACKET:
		mesg = AUTH_MSG_BAD_PACKET;
		break;
	      case AUTH_FAIL_INVALID_LOGIN:
	      default:
		mesg = AUTH_MSG_INVALID;
		break;
	    }
	    strlcpy(buf, mesg, len);
    }
    return(buf);
}

/* 
 * AuthStatusText()
 */

const char *
AuthStatusText(int status)
{  
  switch (status) {
    case AUTH_STATUS_UNDEF:
      return "undefined";

    case AUTH_STATUS_SUCCESS:
      return "authenticated";

    case AUTH_STATUS_FAIL:
      return "failed";

    default:
      return "INCORRECT STATUS";
  }
}

/* 
 * AuthMPPEPolicyname()
 */

const char *
AuthMPPEPolicyname(int policy) 
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

/* 
 * AuthMPPETypesname()
 */

const char *
AuthMPPETypesname(int types, char *buf, size_t len) 
{
  if (types == 0) {
    sprintf(buf, "no encryption required");
    return (buf);
  }

  buf[0]=0;
  if (types & MPPE_TYPE_40BIT) sprintf (buf, "40 ");
  if (types & MPPE_TYPE_56BIT) sprintf (&buf[strlen(buf)], "56 ");
  if (types & MPPE_TYPE_128BIT) sprintf (&buf[strlen(buf)], "128 ");

  if (strlen(buf) == 0) {
    sprintf (buf, "unknown types");
  } else {
    sprintf (&buf[strlen(buf)], "bit");
  }

  return (buf);
}

/*
 * AuthGetExternalPassword()
 *
 * Run the named external program to fill in the password for the user
 * mentioned in the AuthData
 * -1 on error (can't fork, no data read, whatever)
 */
static int
AuthGetExternalPassword(char * extcmd, char *authname, char *password, size_t passlen)
{
  char cmd[AUTH_MAX_PASSWORD + 5 + AUTH_MAX_AUTHNAME];
  int ok = 0;
  FILE *fp;
  int len;

  snprintf(cmd, sizeof(cmd), "%s %s", extcmd, authname);
  Log(LG_AUTH, ("Invoking external auth program: '%s'", cmd));
  if ((fp = popen(cmd, "r")) == NULL) {
    Perror("Popen");
    return (-1);
  }
  if (fgets(password, passlen, fp) != NULL) {
    len = strlen(password);	/* trim trailing newline */
    if (len > 0 && password[len - 1] == '\n')
      password[len - 1] = '\0';
    ok = (password[0] != '\0');
  } else {
    if (ferror(fp))
      Perror("Error reading from external auth program");
  }
  if (!ok)
    Log(LG_AUTH, ("External auth program failed for user \"%s\"", 
      authname));
  pclose(fp);
  return (ok ? 0 : -1);
}

/*
 * AuthCode()
 */

static const char *
AuthCode(int proto, u_char code, char *buf, size_t len)
{
  switch (proto) {
    case PROTO_EAP:
      return EapCode(code, buf, len);

    case PROTO_CHAP:
      return ChapCode(code, buf, len);

    case PROTO_PAP:
      return PapCode(code, buf, len);

    default:
      snprintf(buf, len, "code %d", code);
      return(buf);
  }
}


/*
 * AuthSetCommand()
 */

static int
AuthSetCommand(Context ctx, int ac, char *av[], void *arg)
{
  AuthConf	const autc = &ctx->lnk->lcp.auth.conf;
  int		val;

  if (ac == 0)
    return(-1);

  switch ((intptr_t)arg) {

    case SET_AUTHNAME:
      snprintf(autc->authname, sizeof(autc->authname), "%s", *av);
      break;

    case SET_PASSWORD:
      snprintf(autc->password, sizeof(autc->password), "%s", *av);
      break;
      
    case SET_EXTAUTH_SCRIPT:
      snprintf(autc->extauth_script, sizeof(autc->extauth_script), "%s", *av);
      break;
      
    case SET_EXTACCT_SCRIPT:
      snprintf(autc->extacct_script, sizeof(autc->extacct_script), "%s", *av);
      break;
      
    case SET_MAX_LOGINS:
      gMaxLogins = atoi(*av);
      break;
      
    case SET_ACCT_UPDATE:
      val = atoi(*av);
      if (val < 0)
	Error("Update interval must be positive.");
      else
	autc->acct_update = val;
      break;

    case SET_ACCT_UPDATE_LIMIT_IN:
    case SET_ACCT_UPDATE_LIMIT_OUT:
      val = atoi(*av);
      if (val < 0)
	Error("Update suppression limit must be positive.");
      else {
	if ((intptr_t)arg == SET_ACCT_UPDATE_LIMIT_IN)
	  autc->acct_update_lim_recv = val;
	else
	  autc->acct_update_lim_xmit = val;
      }
      break;

    case SET_TIMEOUT:
      val = atoi(*av);
      if (val <= 20)
	Error("Authorization timeout must be greater then 20.");
      else
	autc->timeout = val;
      break;
      
    case SET_ACCEPT:
      AcceptCommand(ac, av, &autc->options, gConfList);
      break;

    case SET_DENY:
      DenyCommand(ac, av, &autc->options, gConfList);
      break;

    case SET_ENABLE:
      EnableCommand(ac, av, &autc->options, gConfList);
      break;

    case SET_DISABLE:
      DisableCommand(ac, av, &autc->options, gConfList);
      break;

    case SET_YES:
      YesCommand(ac, av, &autc->options, gConfList);
      break;

    case SET_NO:
      NoCommand(ac, av, &autc->options, gConfList);
      break;

    default:
      assert(0);
  }

  return(0);
}

/*
 * AuthExternal()
 * 
 * Authenticate via call external script extauth-script
 */
 
static void
AuthExternal(AuthData auth)
{
    char	line[256];
    FILE	*fp;
    char	*attr, *val;
    int		len;
 
    if (!auth->conf.extauth_script[0]) {
	    Log(LG_ERR, ("[%s] Ext-auth: Script not specified!", 
		auth->info.lnkname));
	    auth->status = AUTH_STATUS_FAIL;
	    return;
    }
    if (strchr(auth->params.authname, '\'') ||
	strchr(auth->params.authname, '\n')) {
	    Log(LG_ERR, ("[%s] Ext-auth: Denied character in USER_NAME!", 
		auth->info.lnkname));
	    auth->status = AUTH_STATUS_FAIL;
	    return;
    }
    snprintf(line, sizeof(line), "%s '%s'", 
	auth->conf.extauth_script, auth->params.authname);
    Log(LG_AUTH, ("[%s] Ext-auth: Invoking auth program: '%s'", 
	auth->info.lnkname, line));
    if ((fp = popen(line, "r+")) == NULL) {
	Perror("Popen");
	return;
    }

    /* SENDING REQUEST */
    fprintf(fp, "USER_NAME:%s\n", auth->params.authname);
    if (auth->proto == PROTO_PAP)
	fprintf(fp, "USER_PASSWORD:%s\n", auth->params.pap.peer_pass);

    fprintf(fp, "ACCT_SESSION_ID:%s\n", auth->info.session_id);
    fprintf(fp, "LINK:%s\n", auth->info.lnkname);
    fprintf(fp, "NAS_PORT:%d\n", auth->info.linkID);
    fprintf(fp, "NAS_PORT_TYPE:%s\n", auth->info.phys_type->name);
    fprintf(fp, "CALLING_STATION_ID:%s\n", auth->params.callingnum);
    fprintf(fp, "CALLED_STATION_ID:%s\n", auth->params.callednum);
    fprintf(fp, "PEER_ADDR:%s\n", auth->params.peeraddr);
    fprintf(fp, "PEER_PORT:%s\n", auth->params.peerport);
    fprintf(fp, "PEER_MAC_ADDR:%s\n", auth->params.peermacaddr);
    fprintf(fp, "PEER_IFACE:%s\n", auth->params.peeriface);
    fprintf(fp, "PEER_IDENT:%s\n", auth->info.peer_ident);
 

    /* REQUEST DONE */
    fprintf(fp, "\n");

    /* REPLY PROCESSING */
    while (fgets(line, sizeof(line), fp)) {
	/* trim trailing newline */
	len = strlen(line);
	if (len > 0 && line[len - 1] == '\n') {
    	    line[len - 1] = '\0';
	    len--;
	}

	/* Empty line is the end marker */
	if (len == 0)
	    break;

	/* split line on attr:value */
	val = line;
	attr = strsep(&val, ":");

	/* Log data w/o password */
	if (strcmp(attr, "USER_PASSWORD") != 0) {
	    Log(LG_AUTH, ("[%s] Ext-auth: attr:'%s', value:'%s'", 
		auth->info.lnkname, attr, val));
	} else {
	    Log(LG_AUTH, ("[%s] Ext-auth: attr:'%s', value:'XXX'", 
		auth->info.lnkname, attr));
	}
    
    if (strcmp(attr, "RESULT") == 0) {
	if (strcmp(val, "SUCCESS") == 0) {
	    auth->status = AUTH_STATUS_SUCCESS;
	} else if (strcmp(val, "UNDEF") == 0) {
	    auth->status = AUTH_STATUS_UNDEF;
	} else 
	    auth->status = AUTH_STATUS_FAIL;

    } else if (strcmp(attr, "USER_NAME") == 0) {
	strlcpy(auth->params.authname, val, sizeof(auth->params.authname));

    } else if (strcmp(attr, "USER_PASSWORD") == 0) {
	strlcpy(auth->params.password, val, sizeof(auth->params.password));

    } else if (strcmp(attr, "FRAMED_IP_ADDRESS") == 0) {
        auth->params.range_valid = 
    	    ParseRange(val, &auth->params.range, ALLOW_IPV4);

    } else if (strcmp(attr, "FRAMED_ROUTE") == 0) {
	struct u_range        range;

	if (!ParseRange(val, &range, ALLOW_IPV4)) {
	  Log(LG_AUTH, ("[%s] Ext-auth: FRAMED_ROUTE: Bad route \"%s\"", 
	    auth->info.lnkname, val));
	} else {
	    struct ifaceroute     *r, *r1;
	    int		j;

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
	        Freee(r);
	    }
	}

    } else if (strcmp(attr, "FRAMED_IPV6_ROUTE") == 0) {
	struct u_range        range;

	if (!ParseRange(val, &range, ALLOW_IPV6)) {
	  Log(LG_AUTH, ("[%s] Ext-auth: FRAMED_IPV6_ROUTE: Bad route \"%s\"", 
	    auth->info.lnkname, val));
	} else {
	    struct ifaceroute     *r, *r1;
	    int		j;

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
	        Freee(r);
	    }
	}

    } else if (strcmp(attr, "SESSION_TIMEOUT") == 0) {
	auth->params.session_timeout = atoi(val);

    } else if (strcmp(attr, "IDLE_TIMEOUT") == 0) {
	auth->params.idle_timeout = atoi(val);

    } else if (strcmp(attr, "ACCT_INTERIM_INTERVAL") == 0) {
	auth->params.acct_update = atoi(val);

    } else if (strcmp(attr, "FRAMED_MTU") == 0) {
	auth->params.mtu = atoi(val);

    } else if (strcmp(attr, "FRAMED_COMPRESSION") == 0) {
	if (atoi(val) == 1)
	    auth->params.vjc_enable = 1;

    } else if (strcmp(attr, "FRAMED_POOL") == 0) {
	strlcpy(auth->params.ippool, val, sizeof(auth->params.ippool));

    } else if (strcmp(attr, "REPLY_MESSAGE") == 0) {
	if (auth->reply_message)
		Freee(auth->reply_message);
	auth->reply_message = Mdup(MB_AUTH, val, strlen(val) + 1);

    } else if (strcmp(attr, "MS_CHAP_ERROR") == 0) {
	if (auth->mschap_error)
		Freee(auth->mschap_error);
	/* "E=%d R=0 M=%s" */
	auth->mschap_error = Mdup(MB_AUTH, val, strlen(val) + 1);

    } else if (strncmp(attr, "MPD_", 4) == 0) {
	struct acl	**acls, *acls1;
	char		*acl, *acl1, *acl2, *acl3;
	int		i;
	
	    if (strcmp(attr, "MPD_RULE") == 0) {
	      acl1 = acl = val;
	      acls = &(auth->params.acl_rule);
	    } else if (strcmp(attr, "MPD_PIPE") == 0) {
	      acl1 = acl = val;
	      acls = &(auth->params.acl_pipe);
	    } else if (strcmp(attr, "MPD_QUEUE") == 0) {
	      acl1 = acl = val;
	      acls = &(auth->params.acl_queue);
	    } else if (strcmp(attr, "MPD_TABLE") == 0) {
	      acl1 = acl = val;
	      acls = &(auth->params.acl_table);
	    } else if (strcmp(attr, "MPD_TABLE_STATIC") == 0) {
	      acl1 = acl = val;
	      acls = &(auth->params.acl_table);
	    } else if (strcmp(attr, "MPD_FILTER") == 0) {
	      acl1 = acl = val;
	      acl2 = strsep(&acl1, "#");
	      i = atol(acl2);
	      if (i <= 0 || i > ACL_FILTERS) {
	        Log(LG_ERR, ("[%s] Ext-auth: wrong filter number: %i",
		  auth->info.lnkname, i));
	        continue;
	      }
	      acls = &(auth->params.acl_filters[i - 1]);
	    } else if (strcmp(attr, "MPD_LIMIT") == 0) {
	      acl1 = acl = val;
	      acl2 = strsep(&acl1, "#");
	      if (strcasecmp(acl2, "in") == 0) {
	        i = 0;
	      } else if (strcasecmp(acl2, "out") == 0) {
	        i = 1;
	      } else {
	        Log(LG_ERR, ("[%s] Ext-auth: wrong limit direction: '%s'",
		  auth->info.lnkname, acl2));
	        continue;
	      }
	      acls = &(auth->params.acl_limits[i]);
	    } else {
	      Log(LG_ERR, ("[%s] Ext-auth: Dropping MPD vendor specific attribute: '%s'",
		auth->info.lnkname, attr));
	      continue;
	    }

	    if (acl1 == NULL) {
	      Log(LG_ERR, ("[%s] Ext-auth: incorrect acl!",
		auth->info.lnkname));
	      continue;
	    }
	    
	    acl3 = acl1;
	    strsep(&acl3, "=");
	    acl2 = acl1;
	    strsep(&acl2, "#");
	    i = atol(acl1);
	    if (i <= 0) {
	      Log(LG_ERR, ("[%s] Ext-auth: wrong acl number: %i",
		auth->info.lnkname, i));
	      continue;
	    }
	    if ((acl3 == NULL) || (acl3[0] == 0)) {
	      Log(LG_ERR, ("[%s] Ext-auth: wrong acl", auth->info.lnkname));
	      continue;
	    }
	    acls1 = Malloc(MB_AUTH, sizeof(struct acl));
	    if (strcmp(attr, "MPD_TABLE_STATIC") != 0) {
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
		(strcmp(attr, "MPD_TABLE") != 0) &&
		(strcmp(attr, "MPD_TABLE_STATIC") != 0)) {
	      Log(LG_ERR, ("[%s] Ext-auth: duplicate acl",
		auth->info.lnkname));
	      continue;
	    } else {
	      acls1->next = *acls;
	    }
	    *acls = acls1;

    } else {
	Log(LG_ERR, ("[%s] Ext-auth: Unknown attr:'%s'", 
	    auth->info.lnkname, attr));
    }
    }
 
    pclose(fp);
    return;
}

/*
 * AuthExternalAcct()
 * 
 * Accounting via call external script extacct-script
 */
 
static void
AuthExternalAcct(AuthData auth)
{
    char	line[256];
    FILE	*fp;
    char	*attr, *val;
    int		len;
 
    if (!auth->conf.extacct_script[0]) {
	    Log(LG_ERR, ("[%s] Ext-acct: Script not specified!", 
		auth->info.lnkname));
	    return;
    }
    if (strchr(auth->params.authname, '\'') ||
	strchr(auth->params.authname, '\n')) {
	    Log(LG_ERR, ("[%s] Ext-acct: Denied character in USER_NAME!", 
		auth->info.lnkname));
	    return;
    }
    snprintf(line, sizeof(line), "%s '%s'", 
	auth->conf.extacct_script, auth->params.authname);
    Log(LG_AUTH, ("[%s] Ext-acct: Invoking acct program: '%s'", 
	auth->info.lnkname, line));
    if ((fp = popen(line, "r+")) == NULL) {
	Perror("Popen");
	return;
    }

    /* SENDING REQUEST */
    fprintf(fp, "ACCT_STATUS_TYPE:%s\n", 
	(auth->acct_type == AUTH_ACCT_START)?
	    "START":((auth->acct_type == AUTH_ACCT_STOP)?
		"STOP":"UPDATE"));

    fprintf(fp, "ACCT_SESSION_ID:%s\n", auth->info.session_id);
    fprintf(fp, "ACCT_MULTI_SESSION_ID:%s\n", auth->info.msession_id);
    fprintf(fp, "USER_NAME:%s\n", auth->params.authname);
    fprintf(fp, "IFACE:%s\n", auth->info.ifname);
    fprintf(fp, "BUNDLE:%s\n", auth->info.bundname);
    fprintf(fp, "LINK:%s\n", auth->info.lnkname);
    fprintf(fp, "NAS_PORT:%d\n", auth->info.linkID);
    fprintf(fp, "NAS_PORT_TYPE:%s\n", auth->info.phys_type->name);
    fprintf(fp, "ACCT_LINK_COUNT:%d\n", auth->info.n_links);
    fprintf(fp, "CALLING_STATION_ID:%s\n", auth->params.callingnum);
    fprintf(fp, "CALLED_STATION_ID:%s\n", auth->params.callednum);
    fprintf(fp, "PEER_ADDR:%s\n", auth->params.peeraddr);
    fprintf(fp, "PEER_PORT:%s\n", auth->params.peerport);
    fprintf(fp, "PEER_MAC_ADDR:%s\n", auth->params.peermacaddr);
    fprintf(fp, "PEER_IFACE:%s\n", auth->params.peeriface);
    fprintf(fp, "PEER_IDENT:%s\n", auth->info.peer_ident);

    fprintf(fp, "FRAMED_IP_ADDRESS:%s\n",
	inet_ntoa(auth->info.peer_addr));

    if (auth->acct_type == AUTH_ACCT_STOP) {
	fprintf(fp, "ACCT_TERMINATE_CAUSE:%s\n", auth->info.downReason);
    }

    if (auth->acct_type != AUTH_ACCT_START) {
	struct svcstatrec *ssr;
	fprintf(fp, "ACCT_SESSION_TIME:%ld\n", 
	    (long int)(time(NULL) - auth->info.last_open));
	fprintf(fp, "ACCT_INPUT_OCTETS:%llu\n", 
	    (long long unsigned)auth->info.stats.recvOctets);
	fprintf(fp, "ACCT_INPUT_PACKETS:%llu\n", 
	    (long long unsigned)auth->info.stats.recvFrames);
	fprintf(fp, "ACCT_OUTPUT_OCTETS:%llu\n", 
	    (long long unsigned)auth->info.stats.xmitOctets);
	fprintf(fp, "ACCT_OUTPUT_PACKETS:%llu\n", 
	    (long long unsigned)auth->info.stats.xmitFrames);
	SLIST_FOREACH(ssr, &auth->info.ss.stat[0], next) {
	    fprintf(fp, "MPD_INPUT_OCTETS:%s:%llu\n",
		ssr->name, (long long unsigned)ssr->Octets);
	    fprintf(fp, "MPD_INPUT_PACKETS:%s:%llu\n",
		ssr->name, (long long unsigned)ssr->Packets);
	}
	SLIST_FOREACH(ssr, &auth->info.ss.stat[1], next) {
	    fprintf(fp, "MPD_OUTPUT_OCTETS:%s:%llu\n",
		ssr->name, (long long unsigned)ssr->Octets);
	    fprintf(fp, "MPD_OUTPUT_PACKETS:%s:%llu\n",
		ssr->name, (long long unsigned)ssr->Packets);
	}
    }

    /* REQUEST DONE */
    fprintf(fp, "\n");

    /* REPLY PROCESSING */
    while (fgets(line, sizeof(line), fp)) {
	/* trim trailing newline */
	len = strlen(line);
	if (len > 0 && line[len - 1] == '\n') {
    	    line[len - 1] = '\0';
	    len--;
	}

	/* Empty line is the end marker */
	if (len == 0)
	    break;

	/* split line on attr:value */
	val = line;
	attr = strsep(&val, ":");

	Log(LG_AUTH, ("[%s] Ext-acct: attr:'%s', value:'%s'", 
	    auth->info.lnkname, attr, val));
    
	if (strcmp(attr, "MPD_DROP_USER") == 0) {
	    auth->drop_user = atoi(val);

	} else {
	    Log(LG_ERR, ("[%s] Ext-acct: Unknown attr:'%s'", 
		auth->info.lnkname, attr));
	}
    }
 
    pclose(fp);
    return;
}
