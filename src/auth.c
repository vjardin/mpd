
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
#include "custom.h"
#include "log.h"
#include "ngfunc.h"
#include "msoft.h"
#include "util.h"

#include <libutil.h>

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
  static int		AuthPreChecks(AuthData auth, int complain);
  static void		AuthAccountTimeout(void *arg);
  static void		AuthAccount(void *arg);
  static void		AuthAccountFinish(void *arg, int was_canceled);
  static void		AuthInternal(AuthData auth);
  static void		AuthSystem(AuthData auth);
  static void		AuthOpie(AuthData auth);
  static const char	*AuthCode(int proto, u_char code);
  static int		AuthSetCommand(int ac, char *av[], void *arg);

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
    { "max-logins num",			"Max concurrent logins",
	AuthSetCommand, NULL, (void *) SET_MAX_LOGINS },
    { "authname name",			"Authentication name",
	AuthSetCommand, NULL, (void *) SET_AUTHNAME },
    { "password pass",			"Authentication password",
	AuthSetCommand, NULL, (void *) SET_PASSWORD },
    { "acct-update <seconds>",		"set update interval",
	AuthSetCommand, NULL, (void *) SET_ACCT_UPDATE },
    { "update-limit-in <bytes>",	"set update suppresion limit",
	AuthSetCommand, NULL, (void *) SET_ACCT_UPDATE_LIMIT_IN },
    { "update-limit-out <bytes>",	"set update suppresion limit",
	AuthSetCommand, NULL, (void *) SET_ACCT_UPDATE_LIMIT_OUT },
    { "timeout <seconds>",		"set auth timeout",
	AuthSetCommand, NULL, (void *) SET_TIMEOUT },
    { "accept [opt ...]",		"Accept option",
	AuthSetCommand, NULL, (void *) SET_ACCEPT },
    { "deny [opt ...]",			"Deny option",
	AuthSetCommand, NULL, (void *) SET_DENY },
    { "enable [opt ...]",		"Enable option",
	AuthSetCommand, NULL, (void *) SET_ENABLE },
    { "disable [opt ...]",		"Disable option",
	AuthSetCommand, NULL, (void *) SET_DISABLE },
    { "yes [opt ...]",			"Enable and accept option",
	AuthSetCommand, NULL, (void *) SET_YES },
    { "no [opt ...]",			"Disable and deny option",
	AuthSetCommand, NULL, (void *) SET_NO },
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
    { 0,	AUTH_CONF_SYSTEM,	"system"	},
    { 0,	AUTH_CONF_OPIE,		"opie"		},
    { 0,	AUTH_CONF_UTMP_WTMP,	"utmp-wtmp"	},
    { 0,	0,			NULL		},
  };

void	authparamsInit(struct authparams *ap) {
    memset(ap,0,sizeof(struct authparams));
};

void	authparamsDestroy(struct authparams *ap) {
    struct acl		*acls, *acls1;
    int i;
  
    if (ap->eapmsg) {
	Freee(MB_AUTH, ap->eapmsg);
    }
    if (ap->state) {
	Freee(MB_AUTH, ap->state);
    }

    acls = ap->acl_rule;
    while (acls != NULL) {
	acls1 = acls->next;
	Freee(MB_AUTH, acls);
	acls = acls1;
    };
    acls = ap->acl_pipe;
    while (acls != NULL) {
	acls1 = acls->next;
	Freee(MB_AUTH, acls);
	acls = acls1;
    };
    acls = ap->acl_queue;
    while (acls != NULL) {
	acls1 = acls->next;
	Freee(MB_AUTH, acls);
	acls = acls1;
    };
    acls = ap->acl_table;
    while (acls != NULL) {
	acls1 = acls->next;
	Freee(MB_AUTH, acls);
	acls = acls1;
    };

    for (i = 0; i < ACL_FILTERS; i++) {
	acls = ap->acl_filters[i];
	while (acls != NULL) {
	    acls1 = acls->next;
	    Freee(MB_AUTH, acls);
	    acls = acls1;
	};
    };

    for (i = 0; i < ACL_DIRS; i++) {
	acls = ap->acl_limits[i];
	while (acls != NULL) {
	    acls1 = acls->next;
	    Freee(MB_AUTH, acls);
	    acls = acls1;
	};
    };

    if (ap->msdomain) {
	Freee(MB_AUTH, ap->msdomain);
    }
    
    memset(ap,0,sizeof(struct authparams));
};

void	authparamsCopy(struct authparams *src, struct authparams *dst) {
    struct acl	*acls;
    struct acl	**pacl;
    int		i;

    memcpy(dst,src,sizeof(struct authparams));
  
    if (src->eapmsg) {
	dst->eapmsg = Malloc(MB_AUTH, src->eapmsg_len);
	memcpy(dst->eapmsg, src->eapmsg, src->eapmsg_len);
	dst->eapmsg_len = src->eapmsg_len;
    }
    if (src->state) {
	dst->state = Malloc(MB_AUTH, src->state_len);
	memcpy(dst->state, src->state, src->state_len);
	dst->state_len = src->state_len;
    }

    acls = src->acl_rule;
    pacl = &dst->acl_rule;
    while (acls != NULL) {
	*pacl = Malloc(MB_AUTH, sizeof(struct acl));
	memcpy(*pacl, acls, sizeof(struct acl));
	acls = acls->next;
	pacl = &((*pacl)->next);
    };
    acls = src->acl_pipe;
    pacl = &dst->acl_pipe;
    while (acls != NULL) {
	*pacl = Malloc(MB_AUTH, sizeof(struct acl));
	memcpy(*pacl, acls, sizeof(struct acl));
	acls = acls->next;
	pacl = &((*pacl)->next);
    };
    acls = src->acl_queue;
    pacl = &dst->acl_queue;
    while (acls != NULL) {
	*pacl = Malloc(MB_AUTH, sizeof(struct acl));
	memcpy(*pacl, acls, sizeof(struct acl));
	acls = acls->next;
	pacl = &((*pacl)->next);
    };
    acls = src->acl_table;
    pacl = &dst->acl_table;
    while (acls != NULL) {
	*pacl = Malloc(MB_AUTH, sizeof(struct acl));
	memcpy(*pacl, acls, sizeof(struct acl));
	acls = acls->next;
	pacl = &((*pacl)->next);
    };

    for (i = 0; i < ACL_FILTERS; i++) {
	acls = src->acl_filters[i];
	pacl = &dst->acl_filters[i];
	while (acls != NULL) {
	    *pacl = Malloc(MB_AUTH, sizeof(struct acl));
	    memcpy(*pacl, acls, sizeof(struct acl));
	    acls = acls->next;
	    pacl = &((*pacl)->next);
	};
    };

    for (i = 0; i < ACL_DIRS; i++) {
	acls = src->acl_limits[i];
	pacl = &dst->acl_limits[i];
	while (acls != NULL) {
	    *pacl = Malloc(MB_AUTH, sizeof(struct acl));
	    memcpy(*pacl, acls, sizeof(struct acl));
	    acls = acls->next;
	    pacl = &((*pacl)->next);
	};
    };

    if (src->msdomain) {
	dst->msdomain = Malloc(MB_AUTH, strlen(src->msdomain)+1);
	strcpy(dst->msdomain, src->msdomain);
    }
};


/*
 * AuthInit()
 */

void
AuthInit(void)
{
  AuthConf	const ac = &lnk->lcp.auth.conf;
  
  RadiusInit();

  Disable(&ac->options, AUTH_CONF_RADIUS_AUTH);
  Disable(&ac->options, AUTH_CONF_RADIUS_ACCT);
  
  Enable(&ac->options, AUTH_CONF_INTERNAL);

  /* default auth timeout */
  ac->timeout = 40;
}

/*
 * AuthStart()
 *
 * Initialize authorization info for a link
 */

void
AuthStart(void)
{
  Auth	a = &lnk->lcp.auth;

  /* What auth protocols were negotiated by LCP? */
  a->self_to_peer = lnk->lcp.peer_auth;
  a->peer_to_self = lnk->lcp.want_auth;

    /* remember peer's IP address */
    PhysGetPeerAddr(lnk->phys, a->params.peeraddr, sizeof(a->params.peeraddr));
  
    /* remember calling number */
    PhysGetCallingNum(lnk->phys, a->params.callingnum, sizeof(a->params.callingnum));
  
    /* remember called number */
    PhysGetCalledNum(lnk->phys, a->params.callednum, sizeof(a->params.callednum));
  
  Log(LG_AUTH, ("%s: auth: peer wants %s, I want %s",
    Pref(&lnk->lcp.fsm),
    a->self_to_peer ? ProtoName(a->self_to_peer) : "nothing",
    a->peer_to_self ? ProtoName(a->peer_to_self) : "nothing"));

  /* Is there anything to do? */
  if (!a->self_to_peer && !a->peer_to_self) {
    LcpAuthResult(TRUE);
    return;
  }

  /* Start global auth timer */
  TimerInit(&a->timer, "AuthTimer",
    lnk->lcp.auth.conf.timeout * SECONDS, AuthTimeout, lnk);
  TimerStart(&a->timer);

  /* Start my auth to him */
  switch (a->self_to_peer) {
    case 0:
      break;
    case PROTO_PAP:
      PapStart(lnk, AUTH_SELF_TO_PEER);
      break;
    case PROTO_CHAP:
      ChapStart(lnk, AUTH_SELF_TO_PEER);
      break;
    case PROTO_EAP:
      EapStart(lnk, AUTH_SELF_TO_PEER);
      break;
    default:
      assert(0);
  }

  /* Start his auth to me */
  switch (a->peer_to_self) {
    case 0:
      break;
    case PROTO_PAP:
      PapStart(lnk, AUTH_PEER_TO_SELF);
      break;
    case PROTO_CHAP:
      ChapStart(lnk, AUTH_PEER_TO_SELF);
      break;
    case PROTO_EAP:
      EapStart(lnk, AUTH_PEER_TO_SELF);
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
    Log(LG_ERR, ("[%s] AUTH: Thread already running, dropping this packet", 
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

  auth = AuthDataNew();
  auth->proto = proto;

  bp = mbread(bp, (u_char *) &fsmh, sizeof(fsmh), NULL);
  len -= sizeof(fsmh);
  if (len > ntohs(fsmh.length))
    len = ntohs(fsmh.length);

  if (bp == NULL && proto != PROTO_EAP && proto != PROTO_CHAP)
  {
    const char	*failMesg;
    u_char	code = 0;

    Log(LG_AUTH, (" Bad packet"));
    auth->why_fail = AUTH_FAIL_INVALID_PACKET;
    failMesg = AuthFailMsg(auth, 0);
    if (proto == PROTO_PAP)
      code = PAP_NAK;
    else if (proto == PROTO_CHAP)
      code = CHAP_FAILURE;
    else
      assert(0);
    AuthOutput(proto, code, fsmh.id, failMesg, strlen(failMesg), 1, 0);
    AuthFinish(AUTH_PEER_TO_SELF, FALSE);
    AuthDataDestroy(auth);
    return;
  }

  pkt = MBDATAU(bp);

  auth->id = fsmh.id;
  auth->code = fsmh.code;
  /* Status defaults to undefined */
  auth->status = AUTH_STATUS_UNDEF;
  
  switch (proto) {
    case PROTO_PAP:
      PapInput(auth, pkt, len);
      break;
    case PROTO_CHAP:
      ChapInput(auth, pkt, len);
      break;
    case PROTO_EAP:
      EapInput(auth, pkt, len);
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
AuthOutput(int proto, u_int code, u_int id, const u_char *ptr,
	int len, int add_len, u_char eap_type)
{
  struct fsmheader	lh;
  Mbuf			bp;
  int			plen;

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
  if (bp == NULL) {
    Log(LG_ERR, ("[%s] %s: mballoc() error", lnk->name, ProtoName(proto)));
    return;
  }

  memcpy(MBDATAU(bp), &lh, sizeof(lh));
  if (proto == PROTO_EAP)
    memcpy(MBDATAU(bp) + sizeof(lh), &eap_type, 1);

  if (add_len)
    *(MBDATAU(bp) + sizeof(lh)) = (u_char)len;

  if (proto == PROTO_EAP) {
    memcpy(MBDATAU(bp) + sizeof(lh) + add_len + 1, ptr, len);
    Log(LG_AUTH, ("[%s] %s: sending %s Type %s len:%d", lnk->name,
      ProtoName(proto), AuthCode(proto, code), EapType(eap_type), len));
  } else {
    memcpy(MBDATAU(bp) + sizeof(lh) + add_len, ptr, len);
    Log(LG_AUTH, ("[%s] %s: sending %s len:%d", lnk->name,
      ProtoName(proto), AuthCode(proto, code), len));
  }

  /* Send it out */

  NgFuncWritePppFrame(bund, lnk->bundleIndex, proto, bp);
}

/*
 * AuthFinish()
 *
 * Authorization is finished, so continue one way or the other
 */

void
AuthFinish(int which, int ok)
{
  Auth		const a = &lnk->lcp.auth;

  switch (which) {
    case AUTH_SELF_TO_PEER:
      a->self_to_peer = 0;
      break;

    case AUTH_PEER_TO_SELF:
      a->peer_to_self = 0;
      break;

    default:
      assert(0);
  }

  /* Did auth fail (in either direction)? */
  if (!ok) {
    AuthStop();
    LcpAuthResult(FALSE);
    return;
  }

  /* Did auth succeed (in both directions)? */
  if (!a->peer_to_self && !a->self_to_peer) {
    AuthStop();
    LcpAuthResult(TRUE);
    return;
  }
}

/*
 * AuthCleanup()
 *
 * Cleanup auth structure, invoked on link-down
 */

void
AuthCleanup(void)
{
  Auth			a = &lnk->lcp.auth;

  Log(LG_AUTH, ("[%s] AUTH: Cleanup", lnk->name));

  TimerStop(&a->acct_timer);
  
  authparamsDestroy(&a->params);
}

static int 
GetLinkID(Link lnk) {
    int port, i;
    
    port =- 1;    
    for (i = 0; i < gNumPhyses; i++) {
      if (gPhyses[i]->link == lnk) {
	port = i;
	break;
      }
    }
    return port;
};

/* 
 * AuthDataNew()
 *
 * Create a new auth-data object
 */

AuthData
AuthDataNew(void) 
{
  AuthData	auth;
  Auth		a = &lnk->lcp.auth;  

  auth = Malloc(MB_AUTH, sizeof(*auth));
  auth->conf = lnk->lcp.auth.conf;

  strlcpy(auth->info.lnkname, lnk->name, sizeof(auth->info.lnkname));
  strlcpy(auth->info.msession_id, lnk->msession_id, sizeof(auth->info.msession_id));
  strlcpy(auth->info.session_id, lnk->session_id, sizeof(auth->info.session_id));

  auth->info.n_links = bund->n_links;
  auth->info.peer_addr = bund->ipcp.peer_addr;

  /* Copy current link statistics */
  memcpy(&auth->info.stats, &lnk->stats, sizeof(auth->info.stats));

  if (lnk->downReasonValid) {
    auth->info.downReason = Malloc(MB_LINK, strlen(lnk->downReason) + 1);
    strcpy(auth->info.downReason, lnk->downReason);
  }

  auth->info.last_open = lnk->last_open;
  auth->info.phys_type = lnk->phys->type;
  auth->info.linkID = GetLinkID(lnk);

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
  Freee(MB_AUTH, auth->info.downReason);
  Freee(MB_AUTH, auth->reply_message);
  Freee(MB_AUTH, auth->mschap_error);
  Freee(MB_AUTH, auth->mschapv2resp);
  Freee(MB_AUTH, auth);
}

/*
 * AuthStop()
 *
 * Stop the authorization process
 */

void
AuthStop(void)
{
  Auth	a = &lnk->lcp.auth;

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
AuthStat(int ac, char *av[], void *arg)
{
  Auth		const a = &lnk->lcp.auth;
  AuthConf	const conf = &a->conf;

  Printf("Configuration:\r\n");
  Printf("\tMy authname     : %s\r\n", conf->authname);
  Printf("\tMax-Logins      : %d\r\n", gMaxLogins);
  Printf("\tAcct Update     : %d\r\n", conf->acct_update);
  Printf("\t   Limit In     : %d\r\n", conf->acct_update_lim_recv);
  Printf("\t   Limit Out    : %d\r\n", conf->acct_update_lim_xmit);
  Printf("\tAuth timeout    : %d\r\n", conf->timeout);
  
  Printf("Auth options\r\n");
  OptStat(&conf->options, gConfList);

  Printf("Auth Data\r\n");
  Printf("\tPeer authname   : %s\r\n", a->params.authname);
  Printf("\tMTU             : %ld\r\n", a->params.mtu);
  Printf("\tSession-Timeout : %ld\r\n", a->params.session_timeout);
  Printf("\tIdle-Timeout    : %ld\r\n", a->params.idle_timeout);
  Printf("\tAcct-Update     : %ld\r\n", a->params.acct_update);
  Printf("\tNum Routes      : %d\r\n", a->params.n_routes);
  Printf("\tACL Rules       : %s\r\n", a->params.acl_rule ? "yes" : "no");
  Printf("\tACL Pipes       : %s\r\n", a->params.acl_pipe ? "yes" : "no");
  Printf("\tACL Queues      : %s\r\n", a->params.acl_queue ? "yes" : "no");
  Printf("\tACL Tables      : %s\r\n", a->params.acl_table ? "yes" : "no");
  Printf("\tTraffic Limits  : %s\r\n", (a->params.acl_limits[0] || a->params.acl_limits[1]) ? "yes" : "no");
  Printf("\tMS-Domain       : %s\r\n", a->params.msdomain);  
  Printf("\tMPPE Types      : %s\r\n", AuthMPPEPolicyname(a->params.msoft.policy));
  Printf("\tMPPE Policy     : %s\r\n", AuthMPPETypesname(a->params.msoft.types));
  Printf("\tMPPE Keys       : %s\r\n", a->params.msoft.has_keys ? "yes" : "no");

  return (0);
}


/*
 * AuthAccount()
 *
 * Accounting stuff, 
 */
 
void
AuthAccountStart(int type)
{
  Auth		const a = &lnk->lcp.auth;
  AuthData	auth;
  u_long	updateInterval = 0;
      
  LinkUpdateStats(lnk);
  if (type == AUTH_ACCT_STOP) {
    Log(LG_AUTH, ("[%s] AUTH: Accounting data for user %s: %lu seconds, %llu octets in, %llu octets out",
      lnk->name, a->params.authname,
      (unsigned long) (time(NULL) - lnk->last_open),
      lnk->stats.recvOctets, lnk->stats.xmitOctets));
  }

  if (!Enabled(&lnk->lcp.auth.conf.options, AUTH_CONF_RADIUS_ACCT)
      && !Enabled(&lnk->lcp.auth.conf.options, AUTH_CONF_UTMP_WTMP))
    return;

  if (type == AUTH_ACCT_START || type == AUTH_ACCT_STOP) {
  
    /* maybe an outstanding thread is running */
    paction_cancel(&a->acct_thread);
    
  }

  if (type == AUTH_ACCT_START) {
    
    if (a->params.acct_update > 0)
      updateInterval = a->params.acct_update;
    else if (lnk->lcp.auth.conf.acct_update > 0)
      updateInterval = lnk->lcp.auth.conf.acct_update;

    if (updateInterval > 0) {
      TimerInit(&a->acct_timer, "AuthAccountTimer",
	updateInterval * SECONDS, AuthAccountTimeout, lnk);
      TimerStart(&a->acct_timer);
    }
  }
  
  auth = AuthDataNew();
  auth->acct_type = type;

  if (paction_start(&a->acct_thread, &gGiantMutex, AuthAccount, 
    AuthAccountFinish, auth) == -1) {
    Log(LG_ERR, ("[%s] AUTH: Couldn't start Accounting-Thread %d", 
      lnk->name, errno));
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
  Auth	const a = &l->lcp.auth;
  
  Log(LG_AUTH, ("[%s] AUTH: Sending Accounting Update",
    l->name));

  TimerStop(&a->acct_timer);
  AuthAccountStart(AUTH_ACCT_UPDATE);
  TimerStart(&a->acct_timer);
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

  if (Enabled(&auth->conf.options, AUTH_CONF_UTMP_WTMP)) {
    struct utmp	ut;

    memset(&ut, 0, sizeof(ut));
    strlcpy(ut.ut_line, auth->info.lnkname, sizeof(ut.ut_line));

    if (auth->acct_type == AUTH_ACCT_START) {

      strlcpy(ut.ut_host, auth->params.peeraddr, sizeof(ut.ut_host));
      strlcpy(ut.ut_name, auth->params.authname, sizeof(ut.ut_name));
      time(&ut.ut_time);
      login(&ut);
      Log(LG_AUTH, ("[%s] AUTH: wtmp %s %s %s login", auth->info.lnkname, ut.ut_line, 
        ut.ut_name, ut.ut_host));
    }
  
    if (auth->acct_type == AUTH_ACCT_STOP) {
      Log(LG_AUTH, ("[%s] AUTH: wtmp %s logout", auth->info.lnkname, ut.ut_line));
      logout(ut.ut_line);
      logwtmp(ut.ut_line, "", "");
    }
  }
}

/*
 * AuthAccountFinish
 * 
 * Return point for the accounting thread()
 */
 
static void
AuthAccountFinish(void *arg, int was_canceled)
{
  AuthData	auth = (AuthData)arg;
  char		*av[1];

  if (was_canceled)
    Log(LG_AUTH, ("[%s] AUTH: Accounting-Thread was canceled", 
      auth->info.lnkname));
    
  /* Cleanup */
  RadiusClose(auth);
  
  if (was_canceled) {
    AuthDataDestroy(auth);
    return;
  }  

  av[0] = auth->info.lnkname;
  /* Re-Activate lnk and bund */
  if (LinkCommand(1, av, NULL) == -1) {
    AuthDataDestroy(auth);
    return;
  }    

  Log(LG_AUTH, ("[%s] AUTH: Accounting-Thread finished normally", 
    auth->info.lnkname));

  if (auth->acct_type != AUTH_ACCT_STOP) {
    /* Copy back modified data. */
    authparamsCopy(&auth->params,&lnk->lcp.auth.params);
  }

  AuthDataDestroy(auth);
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
    Freee(MB_UTIL, line);
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
AuthAsyncStart(AuthData auth)
{
  Auth	const a = &lnk->lcp.auth;
  
  /* perform pre authentication checks (single-login, etc.) */
  if (AuthPreChecks(auth, 1) < 0) {
    Log(LG_AUTH, ("[%s] AUTH: AuthPreCheck failed for \"%s\"", 
      lnk->name, auth->params.authname));
    auth->finish(auth);
    return;
  }

  if (paction_start(&a->thread, &gGiantMutex, AuthAsync, 
    AuthAsyncFinish, auth) == -1) {
    Log(LG_ERR, ("[%s] AUTH: Couldn't start Auth-Thread %d", 
      lnk->name, errno));
    auth->status = AUTH_STATUS_FAIL;
    auth->why_fail = AUTH_FAIL_NOT_EXPECTED;
    auth->finish(auth);
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

  if (auth->proto == PROTO_EAP && auth->eap_radius) {
    RadiusEapProxy(auth);
    return;
  } else if (Enabled(&auth->conf.options, AUTH_CONF_RADIUS_AUTH)) {
    Log(LG_AUTH, ("[%s] AUTH: Trying RADIUS", auth->info.lnkname));
    RadiusAuthenticate(auth);
    Log(LG_AUTH, ("[%s] AUTH: RADIUS returned %s", 
      auth->info.lnkname, AuthStatusText(auth->status)));
    if (auth->status == AUTH_STATUS_SUCCESS)
      return;
  }

  if (Enabled(&auth->conf.options, AUTH_CONF_SYSTEM)) {
    Log(LG_AUTH, ("[%s] AUTH: Trying SYSTEM", auth->info.lnkname));
    AuthSystem(auth);
    Log(LG_AUTH, ("[%s] AUTH: SYSTEM returned %s", 
      auth->info.lnkname, AuthStatusText(auth->status)));
    if (auth->status == AUTH_STATUS_SUCCESS 
      || auth->status == AUTH_STATUS_UNDEF)
      return;
  }
  
  if (Enabled(&auth->conf.options, AUTH_CONF_OPIE)) {
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

  Log(LG_ERR, ("[%s] AUTH: ran out of backends", auth->info.lnkname));
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
  char		*av[1];

  if (was_canceled)
    Log(LG_AUTH, ("[%s] AUTH: Auth-Thread was canceled", auth->info.lnkname));

  /* cleanup */
  RadiusClose(auth);
  
  if (was_canceled) {
    AuthDataDestroy(auth);
    return;
  }  
  
  av[0] = auth->info.lnkname;
  /* Re-Activate lnk and bund */
  if (LinkCommand(1, av, NULL) == -1) {
    AuthDataDestroy(auth);
    return;
  }    

  Log(LG_AUTH, ("[%s] AUTH: Auth-Thread finished normally", lnk->name));

  /* copy back modified data */
  authparamsCopy(&auth->params,&lnk->lcp.auth.params);
  
  if (auth->mschapv2resp != NULL)
    strcpy(auth->ack_mesg, auth->mschapv2resp);
  
  auth->finish(auth);
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
      auth->params.authentic = AUTH_CONF_OPIE;      
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
    Freee(MB_UTIL, bin);
    NTPasswordHashHash(auth->params.msoft.nt_hash, auth->params.msoft.nt_hash_hash);
    auth->params.msoft.has_nt_hash = TRUE;
    auth->status = AUTH_STATUS_UNDEF;
    auth->params.authentic = AUTH_CONF_OPIE;
    return;

  } else {
    Log(LG_ERR, (" Using systems password database only possible for PAP and MS-CHAP"));
    auth->status = AUTH_STATUS_FAIL;
    auth->why_fail = AUTH_FAIL_NOT_EXPECTED;
    return;
  }

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
      auth->params.authentic = AUTH_CONF_OPIE;
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
  auth->params.authentic = AUTH_CONF_OPIE;
}

/*
 * AuthPreChecks()
 */

static int
AuthPreChecks(AuthData auth, int complain)
{

  if (!strlen(auth->params.authname)) {
    if (complain)
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
      if (gBundles[ac]->open)
	if (!strcmp(gBundles[ac]->params.authname, auth->params.authname))
	  num++;

    if (num >= gMaxLogins) {
      if (complain) {
	Log(LG_AUTH, (" Name: \"%s\" max. number of logins exceeded",
	  auth->params.authname));
      }
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

  Log(LG_AUTH, ("%s: authorization timer expired", Pref(&l->lcp.fsm)));
  AuthStop();
  LcpAuthResult(FALSE);
}

/* 
 * AuthFailMsg()
 */

const char *
AuthFailMsg(AuthData auth, int alg)
{
  static char	buf[64];
  const char	*mesg, *mesg2;

  if (auth->proto == PROTO_CHAP
      && (alg == CHAP_ALG_MSOFT || alg == CHAP_ALG_MSOFTv2)) {
    int	mscode;

    switch (auth->why_fail) {
      case AUTH_FAIL_ACCT_DISABLED:
	mscode = MSCHAP_ERROR_ACCT_DISABLED;
	mesg2 = AUTH_MSG_ACCT_DISAB;
	break;
      case AUTH_FAIL_NO_PERMISSION:
	mscode = MSCHAP_ERROR_NO_DIALIN_PERMISSION;
	mesg2 = AUTH_MSG_NOT_ALLOWED;
	break;
      case AUTH_FAIL_RESTRICTED_HOURS:
	mscode = MSCHAP_ERROR_RESTRICTED_LOGON_HOURS;
	mesg2 = AUTH_MSG_RESTR_HOURS;
	break;
      case AUTH_FAIL_INVALID_PACKET:
      case AUTH_FAIL_INVALID_LOGIN:
      case AUTH_FAIL_NOT_EXPECTED:
      default:
	mscode = MSCHAP_ERROR_AUTHENTICATION_FAILURE;
	mesg2 = AUTH_MSG_INVALID;
	break;
    }

    if (auth->mschap_error != NULL) {
      snprintf(buf, sizeof(buf), auth->mschap_error);
    } else {
      snprintf(buf, sizeof(buf), "E=%d R=0 M=%s", mscode, mesg2);
    }
    mesg = buf;
    
  } else {
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
  }
  return(mesg);
}

/* 
 * AuthStatusText()
 */

const char *
AuthStatusText(int status)
{  
  static char	buf[12];
  
  switch (status) {
    case AUTH_STATUS_UNDEF:
      return "undefined";

    case AUTH_STATUS_SUCCESS:
      return "authenticated";

    case AUTH_STATUS_FAIL:
      return "failed";

    default:
      snprintf(buf, sizeof(buf), "status %d", status);
      return(buf);
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
AuthMPPETypesname(int types) 
{
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
AuthCode(int proto, u_char code)
{
  static char	buf[12];

  switch (proto) {
    case PROTO_EAP:
      return EapCode(code);

    case PROTO_CHAP:
      return ChapCode(code);

    case PROTO_PAP:
      return PapCode(code);

    default:
      snprintf(buf, sizeof(buf), "code %d", code);
      return(buf);
  }
}


/*
 * AuthSetCommand()
 */

static int
AuthSetCommand(int ac, char *av[], void *arg)
{
  AuthConf	const autc = &lnk->lcp.auth.conf;
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
      
    case SET_MAX_LOGINS:
      gMaxLogins = atoi(*av);
      break;
      
    case SET_ACCT_UPDATE:
      val = atoi(*av);
      if (val < 0)
	Log(LG_ERR, ("Update interval must be positive."));
      else
	autc->acct_update = val;
      break;

    case SET_ACCT_UPDATE_LIMIT_IN:
    case SET_ACCT_UPDATE_LIMIT_OUT:
      val = atoi(*av);
      if (val < 0)
	Log(LG_ERR, ("Update suppression limit must be positive."));
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
	Log(LG_ERR, ("Authorization timeout must be greater then 20."));
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

