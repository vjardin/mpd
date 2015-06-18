
/*
 * nat.c
 *
 * Written by Alexander Motin <mav@FreeBSD.org>
 * Rewritten by Dmitry Luhtionov <dmitryluhtionov@gmail.com>
 */

#include "ppp.h"
#include "nat.h"
#include "iface.h"
#include "netgraph.h"
#ifdef NG_NAT_DESC_LENGTH
#include "ngfunc.h"
#endif
#include "util.h"

/*
 * DEFINITIONS
 */

/* Set menu options */

  enum {
    SET_ADDR,
    SET_TARGET,
    SET_ENABLE,
    SET_DISABLE,
    SET_REDIRECT_PORT,
    SET_REDIRECT_ADDR,
    SET_REDIRECT_PROTO,
    UNSET_REDIRECT_PORT,
    UNSET_REDIRECT_ADDR,
    UNSET_REDIRECT_PROTO
  };

static int	NatSetCommand(Context ctx, int ac, char *av[], void *arg);
  
/*
 * GLOBAL VARIABLES
 */

#ifdef NG_NAT_DESC_LENGTH
  const struct cmdtab NatUnSetCmds[] = {
    { "red-port {proto} {alias_addr} {alias_port} {local_addr} {local_port} [{remote_addr} {remote_port}]",	"Redirect port",
	NatSetCommand, AdmitBund, 2, (void *) UNSET_REDIRECT_PORT },
    { "red-addr {alias_addr} {local_addr}",	"Redirect address",
	NatSetCommand, AdmitBund, 2, (void *) UNSET_REDIRECT_ADDR },
    { "red-proto {proto} {alias-addr} {local_addr} [{remote-addr}]",	"Redirect protocol",
	NatSetCommand, AdmitBund, 2, (void *) UNSET_REDIRECT_PROTO },
	  { NULL },
  };
#endif

  const struct cmdtab NatSetCmds[] = {
    { "address {addr}",		"Set alias address",
	NatSetCommand, AdmitBund, 2, (void *) SET_ADDR },
    { "target {addr}",		"Set target address",
	NatSetCommand, AdmitBund, 2, (void *) SET_TARGET },
#ifdef NG_NAT_DESC_LENGTH
    { "red-port {proto} {alias_addr} {alias_port} {local_addr} {local_port} [{remote_addr} {remote_port}]",	"Redirect port",
	NatSetCommand, AdmitBund, 2, (void *) SET_REDIRECT_PORT },
    { "red-addr {alias_addr} {local_addr}",	"Redirect address",
	NatSetCommand, AdmitBund, 2, (void *) SET_REDIRECT_ADDR },
    { "red-proto {proto} {alias-addr} {local_addr} [{remote-addr}]",	"Redirect protocol",
	NatSetCommand, AdmitBund, 2, (void *) SET_REDIRECT_PROTO },
#endif
    { "enable [opt ...]",		"Enable option",
	NatSetCommand, AdmitBund, 2, (void *) SET_ENABLE },
    { "disable [opt ...]",		"Disable option",
	NatSetCommand, AdmitBund, 2, (void *) SET_DISABLE },
    { NULL },
  };

/*
 * INTERNAL VARIABLES
 */

  static const struct confinfo	gConfList[] = {
    { 0,	NAT_CONF_LOG,			"log"		},
    { 0,	NAT_CONF_INCOMING,		"incoming"	},
    { 0,	NAT_CONF_SAME_PORTS,		"same-ports"	},
    { 0,	NAT_CONF_UNREG_ONLY,		"unreg-only"	},
    { 0,	0,				NULL		},
  };

/*
 * NatInit()
 */

void
NatInit(Bund b)
{
  NatState	const nat = &b->iface.nat;

  /* Default configuration */
  u_addrclear(&nat->alias_addr);
  u_addrclear(&nat->target_addr);
  Disable(&nat->options, NAT_CONF_LOG);
  Enable(&nat->options, NAT_CONF_INCOMING);
  Enable(&nat->options, NAT_CONF_SAME_PORTS);
  Disable(&nat->options, NAT_CONF_UNREG_ONLY);
#ifdef NG_NAT_DESC_LENGTH
  bzero(nat->nrpt, sizeof(nat->nrpt));
  bzero(nat->nrpt_id, sizeof(nat->nrpt_id));
  bzero(nat->nrad, sizeof(nat->nrad));
  bzero(nat->nrad_id, sizeof(nat->nrad_id));
  bzero(nat->nrpr, sizeof(nat->nrpr));
  bzero(nat->nrpr_id, sizeof(nat->nrpr_id));
#endif
}


/*
 * NatSetCommand()
 */

static int
NatSetCommand(Context ctx, int ac, char *av[], void *arg)
{
  NatState	const nat = &ctx->bund->iface.nat;
  IfaceState	const iface = &ctx->bund->iface;
#ifdef NG_NAT_DESC_LENGTH
  char	path[NG_PATHSIZ];
  union {
    u_char buf[sizeof(struct ng_mesg) + sizeof(uint32_t)];
    struct ng_mesg reply;
  } u;
  uint32_t *const nat_id = (uint32_t *)(void *)u.reply.data;

  snprintf(path, sizeof(path), "mpd%d-%s-nat:", gPid, (char *)&ctx->bund->name);
#endif

  if (ac == 0)
    return(-1);
  switch ((intptr_t)arg) {
    case SET_TARGET:
#ifndef NG_NAT_LOG
	Error("Target address setting is unsupported by current kernel");
#endif
    /* FALL */
    case SET_ADDR:
      {
	struct u_addr	addr;

	/* Parse */
	if (ac != 1)
	  return(-1);
	if (!ParseAddr(av[0], &addr, ALLOW_IPV4))
	  Error("bad IP address \"%s\"", av[0]);

	/* OK */
	if ((intptr_t)arg == SET_ADDR) {
	    nat->alias_addr = addr;
	} else {
	    nat->target_addr = addr;
	}
      }
      break;

#ifdef NG_NAT_DESC_LENGTH
    case SET_REDIRECT_PORT:
    case UNSET_REDIRECT_PORT:
      {
	struct protoent	*proto;
	struct in_addr	l_addr, a_addr, r_addr;
	int lp, ap, rp = 0;
	uint32_t k;

	/* Parse */
	if (ac != 5 && ac != 7)
	  return(-1);
	if ((proto = getprotobyname(av[0])) == 0)
	  Error("bad PROTO name \"%s\"", av[0]);
	if (!inet_aton (av[1], &a_addr))
	  Error("bad alias IP address \"%s\"", av[1]);
	ap = atoi(av[2]);
	if (ap <= 0 || ap > 65535)
	  Error("Incorrect alias port number \"%s\"", av[2]);
	if (!inet_aton (av[3], &l_addr))
	  Error("bad local IP address \"%s\"", av[3]);
	lp = atoi(av[4]);
	if (lp <= 0 || lp > 65535)
	  Error("Incorrect local port number \"%s\"", av[4]);
	if (ac == 7) {
	  if (!inet_aton (av[5], &r_addr))
	    Error("bad remote IP address \"%s\"", av[5]);
	  rp = atoi(av[6]);
	  if (rp <= 0 || rp > 65535)
	    Error("Incorrect remote port number \"%s\"", av[6]);
	}
	/* OK */
	if ((intptr_t)arg == SET_REDIRECT_PORT) {
	  for (k=0;k<NM_PORT;k++) {
	    if (nat->nrpt_id[k] == 0) {
	      memcpy(&nat->nrpt[k].local_addr, &l_addr, sizeof(struct in_addr));
	      memcpy(&nat->nrpt[k].alias_addr, &a_addr, sizeof(struct in_addr));
	      nat->nrpt[k].local_port = lp;
	      nat->nrpt[k].alias_port = ap;
	      if (ac == 7) {
	        memcpy(&nat->nrpt[k].remote_addr, &r_addr, sizeof(struct in_addr));
	        nat->nrpt[k].remote_port = rp;
	      }
	      nat->nrpt[k].proto = (uint8_t)proto->p_proto;
	      snprintf(nat->nrpt[k].description, NG_NAT_DESC_LENGTH, "nat-port-%d", k);
	      nat->nrpt_id[k] = -1;
	      if (iface->up && iface->nat_up) {
	        if (NgFuncSendQuery(path, NGM_NAT_COOKIE, NGM_NAT_REDIRECT_PORT,
	          &nat->nrpt[k], sizeof(struct ng_nat_redirect_port),
	          &u.reply, sizeof(u), NULL) == 0)
	            nat->nrpt_id[k] = *nat_id;
	      }
	      break;
	    }
	  }
	  if (k == NM_PORT)
	    Error("max number of redirect-port \"%d\" reached", NM_PORT);
	} else {
	  struct ng_nat_redirect_port	tmp_rule;

	  bzero(&tmp_rule, sizeof(struct ng_nat_redirect_port));
	  memcpy(&tmp_rule.local_addr, &l_addr, sizeof(struct in_addr));
	  memcpy(&tmp_rule.alias_addr, &a_addr, sizeof(struct in_addr));
	  tmp_rule.local_port = lp;
	  tmp_rule.alias_port = ap;
	  if (ac == 7) {
	    memcpy(&tmp_rule.remote_addr, &r_addr, sizeof(struct in_addr));
	    tmp_rule.remote_port = rp;
	  }
	  tmp_rule.proto = (uint8_t)proto->p_proto;
	  /* hack to fill misaligned space */
	  snprintf(tmp_rule.description, NG_NAT_DESC_LENGTH, "nat-port-0");
	  for (k=0;k<NM_PORT;k++) {
	    if ((nat->nrpt_id[k] != 0) && (memcmp(&tmp_rule, &nat->nrpt[k],
	      sizeof(struct ng_nat_redirect_port)-NG_NAT_DESC_LENGTH) == 0)) {
	      if (iface->up && iface->nat_up) {
	        if (NgSendMsg(gLinksCsock, path, NGM_NAT_COOKIE,
	          NGM_NAT_REDIRECT_DELETE, &k, sizeof(k)) < 0) {
	          Perror("Can't delete nat rule");
	          break;
	        }
	      }
	      nat->nrpt_id[k] = 0;
	      bzero(&nat->nrpt[k], sizeof(struct ng_nat_redirect_port));
	      break;
	    }
	  }
	  if (k == NM_PORT)
	    Error("Rule not found");
	}
      }
      break;

    case SET_REDIRECT_ADDR:
    case UNSET_REDIRECT_ADDR:
      {
	struct in_addr	l_addr, a_addr;
	uint32_t k;

	/* Parse */
	if (ac != 2)
	  return(-1);
	if (!inet_aton (av[0], &a_addr))
	  Error("bad alias IP address \"%s\"", av[0]);
	if (!inet_aton (av[1], &l_addr))
	  Error("bad local IP address \"%s\"", av[1]);

	/* OK */
	if ((intptr_t)arg == SET_REDIRECT_ADDR) {
	  for (k=0;k<NM_ADDR;k++) {
	    if (nat->nrad_id[k] == 0) {
	      memcpy(&nat->nrad[k].local_addr, &l_addr, sizeof(struct in_addr));
	      memcpy(&nat->nrad[k].alias_addr, &a_addr, sizeof(struct in_addr));
	      snprintf(nat->nrad[k].description, NG_NAT_DESC_LENGTH, "nat-addr-%d", k);
	      nat->nrad_id[k] = -1;
	      if (iface->up && iface->nat_up) {
	        if (NgFuncSendQuery(path, NGM_NAT_COOKIE, NGM_NAT_REDIRECT_ADDR,
	          &nat->nrad[k], sizeof(struct ng_nat_redirect_addr),
	          &u.reply, sizeof(u), NULL) == 0)
	            nat->nrad_id[k] = *nat_id;
	      }
	      break;
	    }
	  }
	  if (k == NM_ADDR)
	    Error("max number of redirect-addr \"%d\" reached", NM_ADDR);
	} else {
	  struct ng_nat_redirect_addr	tmp_rule;

	  bzero(&tmp_rule, sizeof(struct ng_nat_redirect_addr));
	  memcpy(&tmp_rule.local_addr, &l_addr, sizeof(struct in_addr));
	  memcpy(&tmp_rule.alias_addr, &a_addr, sizeof(struct in_addr));
	  /* hack to fill misaligned space */
	  snprintf(tmp_rule.description, NG_NAT_DESC_LENGTH, "nat-addr-0");
	  for (k=0;k<NM_ADDR;k++) {
	    if ((nat->nrad_id[k] != 0) && (memcmp(&tmp_rule, &nat->nrad[k],
	      sizeof(struct ng_nat_redirect_addr)-NG_NAT_DESC_LENGTH) == 0)) {
	      if (iface->up && iface->nat_up) {
	        if (NgSendMsg(gLinksCsock, path, NGM_NAT_COOKIE,
	          NGM_NAT_REDIRECT_DELETE, &k, sizeof(k)) < 0) {
	          Perror("Can't delete nat rule");
	          break;
	        }
	      }
	      nat->nrad_id[k] = 0;
	      bzero(&nat->nrad[k], sizeof(struct ng_nat_redirect_addr));
	      break;
	    }
	  }
	  if (k == NM_ADDR)
	    Error("Rule not found");
	}
      }
      break;

    case SET_REDIRECT_PROTO:
    case UNSET_REDIRECT_PROTO:
      {
	struct protoent	*proto;
	struct in_addr	l_addr, a_addr, r_addr;
	uint32_t k;

	/* Parse */
	if (ac != 3 && ac != 4)
	  return(-1);
	if ((proto = getprotobyname(av[0])) == 0)
	  Error("bad PROTO name \"%s\"", av[0]);
	if (!inet_aton (av[1], &a_addr))
	  Error("bad alias IP address \"%s\"", av[1]);
	if (!inet_aton (av[2], &l_addr))
	  Error("bad local IP address \"%s\"", av[2]);
	if (ac == 4) {
	  if (!inet_aton (av[3], &r_addr))
	    Error("bad remote IP address \"%s\"", av[3]);
	}

	/* OK */
	if ((intptr_t)arg == SET_REDIRECT_PROTO) {
	  for (k=0;k<NM_PROTO;k++) {
	    if (nat->nrpr_id[k] == 0) {
	      memcpy(&nat->nrpr[k].local_addr, &l_addr, sizeof(struct in_addr));
	      memcpy(&nat->nrpr[k].alias_addr, &a_addr, sizeof(struct in_addr));
	      if (ac == 4)
	        memcpy(&nat->nrpr[k].remote_addr, &r_addr, sizeof(struct in_addr));
	      nat->nrpr[k].proto = (uint8_t)proto->p_proto;
	      snprintf(nat->nrpr[k].description, NG_NAT_DESC_LENGTH, "nat-proto-%d", k);
	      nat->nrpr_id[k] = -1;
	      if (iface->up && iface->nat_up) {
	        if (NgFuncSendQuery(path, NGM_NAT_COOKIE, NGM_NAT_REDIRECT_PROTO,
	          &nat->nrpr[k], sizeof(struct ng_nat_redirect_proto),
	          &u.reply, sizeof(u), NULL) == 0)
	            nat->nrpr_id[k] = *nat_id;
	      }
	      break;
	    }
	  }
	  if (k == NM_PROTO)
	    Error("max number of redirect-proto \"%d\" reached", NM_PROTO);
	} else {
	  struct ng_nat_redirect_proto	tmp_rule;

	  bzero(&tmp_rule, sizeof(struct ng_nat_redirect_proto));
	  memcpy(&tmp_rule.local_addr, &l_addr, sizeof(struct in_addr));
	  memcpy(&tmp_rule.alias_addr, &a_addr, sizeof(struct in_addr));
	  if (ac == 4) {
	    memcpy(&tmp_rule.remote_addr, &r_addr, sizeof(struct in_addr));
	  }
	  tmp_rule.proto = (uint8_t)proto->p_proto;
	  /* hack to fill misaligned space */
	  snprintf(tmp_rule.description, NG_NAT_DESC_LENGTH, "nat-proto-0");
	  for (k=0;k<NM_PROTO;k++) {
	    if ((nat->nrpr_id[k] != 0) && (memcmp(&tmp_rule, &nat->nrpr[k],
	      sizeof(struct ng_nat_redirect_proto)-NG_NAT_DESC_LENGTH) == 0)) {
	      if (iface->up && iface->nat_up) {
	        if (NgSendMsg(gLinksCsock, path, NGM_NAT_COOKIE,
	          NGM_NAT_REDIRECT_DELETE, &k, sizeof(k)) < 0) {
	          Perror("Can't delete nat rule");
	          break;
	        }
	      }
	      nat->nrpr_id[k] = 0;
	      bzero(&nat->nrpr[k], sizeof(struct ng_nat_redirect_proto));
	      break;
	    }
	  }
	  if (k == NM_PROTO)
	    Error("Rule not found");
	}
      }
      break;
#endif

    case SET_ENABLE:
      EnableCommand(ac, av, &nat->options, gConfList);
      break;

    case SET_DISABLE:
      DisableCommand(ac, av, &nat->options, gConfList);
      break;

    default:
      assert(0);
  }
  return(0);
}

/*
 * NatStat()
 */

int
NatStat(Context ctx, int ac, char *av[], void *arg)
{
    NatState	const nat = &ctx->bund->iface.nat;
#ifdef NG_NAT_LIBALIAS_INFO
    IfaceState	const iface = &ctx->bund->iface;
    union {
        u_char buf[sizeof(struct ng_mesg) + sizeof(struct ng_nat_libalias_info)];
        struct ng_mesg reply;
    } u;
    struct ng_nat_libalias_info *const li = \
        (struct ng_nat_libalias_info *)(void *)u.reply.data;
    char	path[NG_PATHSIZ];
#endif
    char	buf[48];
    int k;

    Printf("NAT configuration:\r\n");
    Printf("\tAlias addresses : %s\r\n", 
	u_addrtoa(&nat->alias_addr,buf,sizeof(buf)));
    Printf("\tTarget addresses: %s\r\n", 
	u_addrtoa(&nat->target_addr,buf,sizeof(buf)));
#ifdef NG_NAT_DESC_LENGTH
    Printf("Redirect ports:\r\n");
    for (k=0;k<NM_PORT;k++) {
      if (nat->nrpt_id[k] != 0) {
	struct protoent	*proto;
	char	li[16], ai[16], ri[16];
	inet_ntop(AF_INET, &nat->nrpt[k].local_addr, li, sizeof(li));
	inet_ntop(AF_INET, &nat->nrpt[k].alias_addr, ai, sizeof(ai));
	inet_ntop(AF_INET, &nat->nrpt[k].remote_addr, ri, sizeof(ri));
	proto = getprotobynumber(nat->nrpt[k].proto);
	Printf("\t%s %s:%d %s:%d %s:%d (%sactive)\r\n", proto->p_name,
	    ai, nat->nrpt[k].alias_port, li, nat->nrpt[k].local_port,
	    ri, nat->nrpt[k].remote_port, nat->nrpt_id[k]<0?"in":"");
      }
    }
    Printf("Redirect address:\r\n");
    for (k=0;k<NM_ADDR;k++) {
      if (nat->nrad_id[k] != 0) {
	char	li[16], ai[16];
	inet_ntop(AF_INET, &nat->nrad[k].local_addr, li, sizeof(li));
	inet_ntop(AF_INET, &nat->nrad[k].alias_addr, ai, sizeof(ai));
	Printf("\t%s %s (%sactive)\r\n", ai, li, nat->nrad_id[k]<0?"in":"");
      }
    }
    Printf("Redirect proto:\r\n");
    for (k=0;k<NM_PROTO;k++) {
      if (nat->nrpr_id[k] != 0) {
	struct protoent	*proto;
	char	li[16], ai[16], ri[16];
	proto = getprotobynumber(nat->nrpr[k].proto);
	inet_ntop(AF_INET, &nat->nrpr[k].local_addr, li, sizeof(li));
	inet_ntop(AF_INET, &nat->nrpr[k].alias_addr, ai, sizeof(ai));
	inet_ntop(AF_INET, &nat->nrpr[k].remote_addr, ri, sizeof(ri));
	Printf("\t%s %s %s %s (%sactive)\r\n", proto->p_name,
	    ai, li, ri, nat->nrpr_id[k]<0?"in":"");
      }
    }
#endif
    Printf("NAT options:\r\n");
    OptStat(ctx, &nat->options, gConfList);
#ifdef NG_NAT_LIBALIAS_INFO
    if (Enabled(&nat->options, NAT_CONF_LOG) && iface->up && iface->nat_up) {
        snprintf(path, sizeof(path), "mpd%d-%s-nat:", gPid, \
            (char *)&ctx->bund->name);
        bzero(li, sizeof(struct ng_nat_libalias_info));
        Printf("LibAlias statistic:\r\n");
        if (NgFuncSendQuery(path, NGM_NAT_COOKIE, NGM_NAT_LIBALIAS_INFO,
            NULL, 0, &u.reply, sizeof(u), NULL) < 0)
            Perror("Can't get LibAlis stats");
        Printf("\ticmpLinkCount  : %u\r\n", li->icmpLinkCount);
        Printf("\tudpLinkCount   : %u\r\n", li->udpLinkCount);
        Printf("\ttcpLinkCount   : %u\r\n", li->tcpLinkCount);
        Printf("\tsctpLinkCount  : %u\r\n", li->sctpLinkCount);
        Printf("\tpptpLinkCount  : %u\r\n", li->pptpLinkCount);
        Printf("\tprotoLinkCount : %u\r\n", li->protoLinkCount);
        Printf("\tfragmentIdLinkCount  : %u\r\n", li->fragmentIdLinkCount);
        Printf("\tfragmentPtrLinkCount : %u\r\n", li->fragmentPtrLinkCount);
        Printf("\tsockCount      : %u\r\n", li->sockCount);
    }
#endif
    return(0);
}
