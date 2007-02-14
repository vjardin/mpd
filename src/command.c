
/*
 * command.c
 *
 * Written by Toshiharu OHNO <tony-o@iij.ad.jp>
 * Copyright (c) 1993, Internet Initiative Japan, Inc. All rights reserved.
 * See ``COPYRIGHT.iij''
 * 
 * Rewritten by Archie Cobbs <archie@freebsd.org>
 * Copyright (c) 1995-1999 Whistle Communications, Inc. All rights reserved.
 * See ``COPYRIGHT.whistle''
 */

#include "ppp.h"
#include "console.h"
#include "web.h"
#include "command.h"
#include "ccp.h"
#include "iface.h"
#include "radius.h"
#include "bund.h"
#include "link.h"
#include "lcp.h"
#include "ipcp.h"
#include "ip.h"
#include "devices.h"
#include "netgraph.h"
#include "custom.h"
#include "ngfunc.h"
#include "util.h"

/*
 * DEFINITIONS
 */

  struct layer {
    const char	*name;
    void	(*opener)(void);
    void	(*closer)(void);
    const char	*desc;
  };
  typedef struct layer	*Layer;

  #define DEFAULT_OPEN_LAYER	"link"

  /* Set menu options */
  enum {
    SET_ENABLE,
    SET_DISABLE,
    SET_RULE,
    SET_QUEUE,
    SET_PIPE,
    SET_TABLE,
  };


/*
 * INTERNAL FUNCTIONS
 */

  /* Commands */
  static int	ShowVersion(int ac, char *av[], void *arg);
  static int	ShowLayers(int ac, char *av[], void *arg);
  static int	ShowTypes(int ac, char *av[], void *arg);
  static int	ShowSummary(int ac, char *av[], void *arg);
  static int	ShowEvents(int ac, char *av[], void *arg);
  static int	ShowGlobals(int ac, char *av[], void *arg);
  static int	OpenCommand(int ac, char *av[], void *arg);
  static int	CloseCommand(int ac, char *av[], void *arg);
  static int	LoadCommand(int ac, char *av[], void *arg);
  static int	ExitCommand(int ac, char *av[], void *arg);
  static int	QuitCommand(int ac, char *av[], void *arg);
  static int	NullCommand(int ac, char *av[], void *arg);
  static int	GlobalSetCommand(int ac, char *av[], void *arg);
  static int	SetDebugCommand(int ac, char *av[], void *arg);

  /* Other stuff */
  static int	DoCommandTab(CmdTab cmdlist, int ac, char *av[]);
  static Layer	GetLayer(const char *name);

/*
 * INTERNAL VARIABLES
 */

  static int	exitflag;

  const struct cmdtab GlobalSetCmds[] = {
    { "enable [opt ...]", 		"Enable option" ,
       	GlobalSetCommand, NULL, (void *) SET_ENABLE },
    { "disable [opt ...]", 		"Disable option" ,
       	GlobalSetCommand, NULL, (void *) SET_DISABLE },
    { "startrule num", 			"Initial ipfw rule number" ,
       	GlobalSetCommand, NULL, (void *) SET_RULE },
    { "startqueue num", 		"Initial ipfw queue number" ,
       	GlobalSetCommand, NULL, (void *) SET_QUEUE },
    { "startpipe num",			"Initial ipfw pipe number" ,
       	GlobalSetCommand, NULL, (void *) SET_PIPE },
    { "starttable num", 		"Initial ipfw table number" ,
       	GlobalSetCommand, NULL, (void *) SET_TABLE },
    { NULL },
  };

  static const struct confinfo	gGlobalConfList[] = {
    { 0,	GLOBAL_CONF_TCPWRAPPER,	"tcp-wrapper"	},
    { 0,	0,			NULL		},
  };

  static const struct cmdtab ShowCommands[] = {
    { "bundle [name]",			"Bundle status",
	BundStat, AdmitBund, NULL },
    { "ccp",				"CCP status",
	CcpStat, AdmitBund, NULL },
    { "ecp",				"ECP status",
	EcpStat, AdmitBund, NULL },
    { "eap",				"EAP status",
	EapStat, AdmitBund, NULL },
    { "events",				"Current events",
	ShowEvents, NULL, NULL },
    { "ipcp",				"IPCP status",
	IpcpStat, AdmitBund, NULL },
    { "ipv6cp",				"IPV6CP status",
	Ipv6cpStat, AdmitBund, NULL },
    { "iface",				"Interface status",
	IfaceStat, NULL, NULL },
    { "routes",				"IP routing table",
	IpShowRoutes, NULL, NULL },
    { "layers",				"Layers to open/close",
	ShowLayers, NULL, NULL },
    { "phys",				"Physical device status",
	PhysStat, AdmitBund, NULL },
    { "link",				"Link status",
	LinkStat, AdmitBund, NULL },
    { "auth",				"Auth status",
	AuthStat, AdmitBund, NULL },
    { "radius",				"RADIUS status",
	RadStat, AdmitBund, NULL },
    { "lcp",				"LCP status",
	LcpStat, AdmitBund, NULL },
    { "mem",				"Memory map",
	MemStat, NULL, NULL },
    { "mp",				"Multi-link status",
	MpStat, AdmitBund, NULL },
    { "console",			"Console status",
	ConsoleStat, NULL, NULL },
    { "web",				"Web status",
	WebStat, NULL, NULL },
    { "globals",			"Global settings",
	ShowGlobals, NULL, NULL },
    { "types",				"Supported device types",
	ShowTypes, NULL, NULL },
    { "version",			"Version string",
	ShowVersion, NULL, NULL },
    { "summary",			"Daemon status summary",
	ShowSummary, NULL, NULL },
    { NULL },
  };

  static const struct cmdtab SetCommands[] = {
    { "bundle ...",			"Bundle specific stuff",
	CMD_SUBMENU, AdmitBund, (void *) BundSetCmds },
    { "link ...",			"Link specific stuff",
	CMD_SUBMENU, AdmitBund, (void *) LinkSetCmds },
    { "iface ...",			"Interface specific stuff",
	CMD_SUBMENU, AdmitBund, (void *) IfaceSetCmds },
    { "ipcp ...",			"IPCP specific stuff",
	CMD_SUBMENU, AdmitBund, (void *) IpcpSetCmds },
    { "ipv6cp ...",			"IPV6CP specific stuff",
	CMD_SUBMENU, AdmitBund, (void *) Ipv6cpSetCmds },
    { "ccp ...",			"CCP specific stuff",
	CMD_SUBMENU, AdmitBund, (void *) CcpSetCmds },
    { "ecp ...",			"ECP specific stuff",
	CMD_SUBMENU, AdmitBund, (void *) EcpSetCmds },
    { "eap ...",			"EAP specific stuff",
	CMD_SUBMENU, AdmitBund, (void *) EapSetCmds },
    { "auth ...",			"Auth specific stuff",
	CMD_SUBMENU, AdmitBund, (void *) AuthSetCmds },
    { "radius ...",			"RADIUS specific stuff",
	CMD_SUBMENU, AdmitBund, (void *) RadiusSetCmds },
    { "console ...",			"Console specific stuff",
	CMD_SUBMENU, NULL, (void *) ConsoleSetCmds },
    { "web ...",			"Web specific stuff",
	CMD_SUBMENU, NULL, (void *) WebSetCmds },
    { "global ...",			"Global settings",
	CMD_SUBMENU, NULL, (void *) GlobalSetCmds },
#ifdef USE_NG_NETFLOW
    { "netflow ...", 			"NetFlow settings",
	CMD_SUBMENU, NULL, (void *) NetflowSetCmds },
#endif
    { "debug level",			"Set netgraph debug level",
	SetDebugCommand, NULL, NULL },
#define _WANT_DEVICE_CMDS
#include "devices.h"
    { NULL },
  };

  const struct cmdtab gCommands[] = {
    { "new [-nti ng#] bundle link ...",	"Create new bundle",
    	BundCreateCmd, NULL, NULL },
    { "bundle [name]",			"Choose/list bundles",
	BundCommand, AdmitBund, NULL },
    { "custom ...",			"Custom stuff",
	CMD_SUBMENU, NULL, (void *) CustomCmds },
    { "link name",			"Choose link",
	LinkCommand, AdmitBund, NULL },
    { "open [layer]",			"Open a layer",
	OpenCommand, AdmitBund, NULL },
    { "close [layer]",			"Close a layer",
	CloseCommand, AdmitBund, NULL },
    { "load label",			"Read from config file",
	LoadCommand, NULL, NULL },
    { "set ...",			"Set parameters",
	CMD_SUBMENU, NULL, (void *) SetCommands },
    { "show ...",			"Show status",
	CMD_SUBMENU, NULL, (void *) ShowCommands },
    { "exit",				"Exit console",
	ExitCommand, NULL, NULL },
    { "null",				"Do nothing",
	NullCommand, NULL, NULL },
    { "log [+/-opt ...]",		"Set/view log options",
	LogCommand, NULL, NULL },
    { "quit",				"Quit program",
	QuitCommand, NULL, NULL },
    { "help ...",			"Help on any command",
	HelpCommand, NULL, NULL },
    { NULL },
  };



/*
 * Layers
 */

  struct layer	gLayers[] = {
    { "iface",
      IfaceOpen,
      IfaceClose,
      "System interface"
    },
    { "ipcp",
      IpcpOpen,
      IpcpClose,
      "IPCP: IP control protocol"
    },
    { "ipv6cp",
      Ipv6cpOpen,
      Ipv6cpClose,
      "IPV6CP: IPv6 control protocol"
    },
    { "ccp",
      CcpOpen,
      CcpClose,
      "CCP: compression ctrl prot."
    },
    { "ecp",
      EcpOpen,
      EcpClose,
      "ECP: encryption ctrl prot."
    },
    { "bund",
      BundOpen,
      BundClose,
      "Multilink bundle"
    },
    { "link",
      LinkOpenCmd,
      LinkCloseCmd,
      "Link layer"
    },
    { "phys",
      PhysOpen,
      PhysClose,
      "Physical link layer"
    },
  };

  #define NUM_LAYERS	(sizeof(gLayers) / sizeof(*gLayers))

/*
 * DoCommand()
 *
 * Executes command. Returns TRUE if user wants to quit.
 */

int
DoCommand(int ac, char *av[], const char *file, int line)
{
  int	rtn;
  char	filebuf[100];
  
  exitflag = FALSE;
  rtn = DoCommandTab(gCommands, ac, av);

  /* Bad usage? */
  if (rtn < 0) {
    if (file) {
	snprintf(filebuf,sizeof(filebuf),"%s:%d: ", file, line);
	HelpCommand(ac, av, filebuf);
    } else {
	HelpCommand(ac, av, NULL);
    }
  }
  
  return(exitflag);
}

/*
 * DoCommandTab()
 *
 * Execute command from given command menu
 */

static int
DoCommandTab(CmdTab cmdlist, int ac, char *av[])
{
  CmdTab	cmd;
  int		rtn = 0;

  /* Huh? */
  if (ac <= 0)
    return(-1);

  /* Find command */
  if (FindCommand(cmdlist, av[0], &cmd))
    return(-1);

  /* Check command admissibility */
  if (cmd->admit && !(cmd->admit)(cmd))
    return(0);

  /* Find command and either execute or recurse into a submenu */
  if (cmd->func == CMD_SUBMENU)
    rtn = DoCommandTab((CmdTab) cmd->arg, ac - 1, av + 1);
  else if (cmd->func == CMD_UNIMPL)
    Log(LG_ERR, ("command '%s' is not implemented", av[0]));
  else
    rtn = (cmd->func)(ac - 1, av + 1, cmd->arg);

  return(rtn);
}

/*
 * FindCommand()
 */

int
FindCommand(CmdTab cmds, char *str, CmdTab *cmdp)
{
  int		nmatch;
  int		len = strlen(str);

  for (nmatch = 0; cmds->name; cmds++) {
    if (cmds->name && !strncmp(str, cmds->name, len)) {
      *cmdp = cmds;
      nmatch++;
    }
  }
  switch (nmatch) {
    case 0:
      return(-1);
    case 1:
      return(0);
    default:
      return(-2);
  }
}

/********** COMMANDS **********/


/*
 * GlobalSetCommand()
 */

static int
GlobalSetCommand(int ac, char *av[], void *arg) 
{
    int val;

  if (ac == 0)
    return(-1);

  switch ((intptr_t)arg) {
    case SET_ENABLE:
      EnableCommand(ac, av, &gGlobalConf.options, gGlobalConfList);
      break;

    case SET_DISABLE:
      DisableCommand(ac, av, &gGlobalConf.options, gGlobalConfList);
      break;

    case SET_RULE:
	if (rule_pool) 
	    Log(LG_ERR, ("Rule pool is not empty. Impossible to set initial number"));
	else {
	    val = atoi(*av);
	    if (val <= 0 || val>=65535)
		Log(LG_ERR, ("Incorrect rule number"));
	    else
		rule_pool_start = val;
	}
      break;

    case SET_QUEUE:
	if (queue_pool) 
	    Log(LG_ERR, ("Queue pool is not empty. Impossible to set initial number"));
	else {
	    val = atoi(*av);
	    if (val <= 0 || val>=65535)
		Log(LG_ERR, ("Incorrect queue number"));
	    else
		queue_pool_start = val;
	}
      break;

    case SET_PIPE:
	if (rule_pool) 
	    Log(LG_ERR, ("Pipe pool is not empty. Impossible to set initial number"));
	else {
	    val = atoi(*av);
	    if (val <= 0 || val>=65535)
		Log(LG_ERR, ("Incorrect rule number"));
	    else
		pipe_pool_start = val;
	}
      break;

    case SET_TABLE:
	if (rule_pool) 
	    Log(LG_ERR, ("Table pool is not empty. Impossible to set initial number"));
	else {
	    val = atoi(*av);
	    if (val <= 0 || val>127) /* table 0 is usually possible but we deny it */
		Log(LG_ERR, ("Incorrect rule number"));
	    else
		table_pool_start = val;
	}
      break;

    default:
      return(-1);
  }

  return 0;
}

/*
 * HelpCommand()
 */

int
HelpCommand(int ac, char *av[], void *arg)
{
  int		depth;
  CmdTab	menu, cmd;
  char		*mark, *mark_save;
  const char	*errfmt;
  char		buf[100];
  int		err;

  for (mark = buf, depth = *buf = 0, menu = gCommands;
      depth < ac;
      depth++, menu = (CmdTab) cmd->arg) {
    if ((err = FindCommand(menu, av[depth], &cmd))) {
      int k;

      for (*buf = k = 0; k <= depth; k++)
	snprintf(buf + strlen(buf), sizeof(buf) - strlen(buf), "%s%c",
	  av[k], k == depth ? '\0' : ' ');
      switch (err) {
        case -1:
          errfmt = "%sUnknown command: '%s'. Try \"help\".";
	  break;
        case -2:
	  errfmt = "%sAmbiguous command: '%s'";
	  break;
	default:
	  errfmt = "%sUnknown error: '%s'";
      }
      if (arg) {
        Log(LG_ERR, (errfmt, (char*)arg, buf));
      } else {
        Log(LG_ERR, (errfmt, "", buf));
      }
      return(0);
    }
    sprintf(mark, depth ? " %s" : "%s", cmd->name);
    mark_save = mark;
    if ((mark = strchr(mark + 1, ' ')) == NULL)
      mark = mark_save + strlen(mark_save);
    if (cmd->func != CMD_SUBMENU)
    {
      Printf("Usage: %s\r\n", buf);
      return(0);
    }
  }

  /* Show list of available commands in this submenu */
  *mark = 0;
  if (!*buf)
    Printf("Available commands:\r\n");
  else
    Printf("Commands available under \"%s\":\r\n", buf);
  for (cmd = menu; cmd->name; cmd++) {
    snprintf(buf, sizeof(buf), "%s", cmd->name);
    if ((mark = strchr(buf, ' ')))
      *mark = 0;
    Printf(" %-9s: %-20s%s", buf, cmd->desc,
      ((cmd - menu) & 1)? "\r\n" : "\t");
  }
  if ((cmd - menu) & 1)
    Printf("\r\n");
  return(0);
}

/*
 * SetDebugCommand()
 */

static int
SetDebugCommand(int ac, char *av[], void *arg)
{
  switch (ac) {
    case 1:
      NgSetDebug(atoi(av[0]));
      break;
    default:
      return(-1);
  }
  return(0);
}

/*
 * ShowVersion()
 */

static int
ShowVersion(int ac, char *av[], void *arg)
{
  Printf("MPD version: %s\r\n", gVersion);
  return(0);
}

/*
 * ShowEvents()
 */

static int
ShowEvents(int ac, char *av[], void *arg)
{
  EventDump("mpd events");
  return(0);
}

/*
 * ShowGlobals()
 */

static int
ShowGlobals(int ac, char *av[], void *arg)
{
  Printf("Global settings:\r\n");
  OptStat(&gGlobalConf.options, gGlobalConfList);
  return 0;
}


/*
 * ExitCommand()
 */

static int
ExitCommand(int ac, char *av[], void *arg)
{
  exitflag = TRUE;
  return(0);
}

/*
 * QuitCommand()
 */

static int
QuitCommand(int ac, char *av[], void *arg)
{
  SendSignal(SIGTERM);
  exitflag = TRUE;
  return(0);
}

/*
 * NullCommand()
 */

static int
NullCommand(int ac, char *av[], void *arg)
{
  return(0);
}

/*
 * LoadCommand()
 */

static int
LoadCommand(int ac, char *av[], void *arg)
{
  static int depth=0;
  
  if (ac != 1)
    return(-1);
  else {
    if (depth>20) {
      Log(LG_ERR, ("Depth limit was reached while loading '%s'!", *av));
      Log(LG_ERR, ("There is a configuration loop!"));
      return(-2);
    }
    depth++;
    ReadFile(gConfigFile, *av, DoCommand);
    depth--;
  }
  return(0);
}

/*
 * OpenCommand()
 */

static int
OpenCommand(int ac, char *av[], void *arg)
{
  Layer		layer;
  const char	*name;

  switch (ac) {
    case 0:
      name = DEFAULT_OPEN_LAYER;
      break;
    case 1:
      name = av[0];
      break;
    default:
      return(-1);
  }
  if ((layer = GetLayer(name)) != NULL)
    (*layer->opener)();
  return(0);
}

/*
 * CloseCommand()
 */

static int
CloseCommand(int ac, char *av[], void *arg)
{
  Layer		layer;
  const char	*name;

  switch (ac) {
    case 0:
      name = DEFAULT_OPEN_LAYER;
      break;
    case 1:
      name = av[0];
      break;
    default:
      return(-1);
  }
  if ((layer = GetLayer(name)) != NULL)
    (*layer->closer)();
  return(0);
}

/*
 * GetLayer()
 */

static Layer
GetLayer(const char *name)
{
  int	k, found;

  if (name == NULL)
    name = "iface";
  for (found = -1, k = 0; k < NUM_LAYERS; k++) {
    if (!strncasecmp(name, gLayers[k].name, strlen(name))) {
      if (found > 0) {
	Log(LG_ERR, ("%s: ambiguous", name));
	return(NULL);
      } else
	found = k;
    }
  }
  if (found < 0) {
    Log(LG_ERR, ("unknown layer \"%s\": try \"show layers\"", name));
    return(NULL);
  }
  return(&gLayers[found]);
}

/*
 * ShowLayers()
 */

static int
ShowLayers(int ac, char *av[], void *arg)
{
  int	k;

  Printf("\tName\t\tDescription\r\n"
	 "\t----\t\t-----------\r\n");
  for (k = 0; k < NUM_LAYERS; k++)
    Printf("\t%s\t\t%s\r\n", gLayers[k].name, gLayers[k].desc);
  return(0);
}

/*
 * ShowTypes()
 */

static int
ShowTypes(int ac, char *av[], void *arg)
{
  PhysType	pt;
  int		k;

  Printf("Supported device types:\r\n\t");
  for (k = 0; (pt = gPhysTypes[k]); k++)
    Printf(" %s", pt->name);
  Printf("\r\n");
  return(0);
}

/*
 * ShowSummary()
 */

static int
ShowSummary(int ac, char *av[], void *arg)
{
  int	b,l;
  Bund	B;
  Link  L;
  char	buf[64];

  Printf("Current daemon status summary\r\n");
  Printf("Iface\tBund\tLink\tDevice\tIface\tLCP\tDevice\tUser\t\tFrom\r\n");
  for (b = 0; b<gNumBundles; b++) {
    B=gBundles[b];
    if (B) {
	Printf("%s\t%s\t", B->iface.ifname, B->name);
	for (l = 0; l < B->n_links; l++) {
	    if (l != 0) {
		Printf("\t\t");
	    }
	    L=B->links[l];
	    if (L) {
		if (L->phys->type && L->phys->type->peeraddr)
		    L->phys->type->peeraddr(L->phys, buf, sizeof(buf));
		else 
		    buf[0] = 0;
		Printf("%s\t%s\t%s\t%s\t%s\t%8s\t%s", 
		    L->name,
		    (L->phys->type?L->phys->type->name:""),
		    (B->iface.up?"Up":"Down"),
		    FsmStateName(L->lcp.fsm.state),
		    gPhysStateNames[L->phys->state],
		    L->lcp.auth.params.authname,
		    buf
		    );
		Printf("\r\n");
	    }
	}
    }
  }
  return(0);
}

/*
 * AdmitBund()
 */

int
AdmitBund(CmdTab cmd)
{
  if (!bund) {
    Log(LG_ERR, ("no bundles defined"));
    return(FALSE);
  }
  return(TRUE);
}

/*
 * AdmitDev()
 */

int
AdmitDev(CmdTab cmd)
{
  if (!AdmitBund(cmd))
    return(FALSE);
  if (lnk->phys->type == NULL) {
    Log(LG_ERR, ("type of link \"%s\" is unspecified", lnk->name));
    return(FALSE);
  }
  if (strncmp(cmd->name, lnk->phys->type->name, strlen(lnk->phys->type->name))) {
    Log(LG_ERR, ("[%s] link type is %s, '%s' command isn't allowed here!",
      lnk->name, lnk->phys->type->name, cmd->name));
    return(FALSE);
  }
  return(TRUE);
}

