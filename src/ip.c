
/*
 * ip.c
 *
 * Written by Toshiharu OHNO <tony-o@iij.ad.jp>
 * Copyright (c) 1993, Internet Initiative Japan, Inc. All rights reserved.
 * See ``COPYRIGHT.iij''
 * 
 * Rewritten by Archie Cobbs <archie@whistle.com>
 * Copyright (c) 1995-1999 Whistle Communications, Inc. All rights reserved.
 * See ``COPYRIGHT.whistle''
 */

#include "ppp.h"
#include "ip.h"
#include "iface.h"
#include "ipcp.h"

/*
 * IpShowRoutes()
 *
 * Show routing tables
 */

int
IpShowRoutes(int ac, char *av[], void *arg)
{
  int	ch;
  FILE	*fp;

  if ((fp = popen(PATH_NETSTAT " -nr -f inet", "r")) == NULL)
  {
    Perror("popen");
    return(0);
  }
  while ((ch = getc(fp)) != EOF)
    putchar(ch);
  pclose(fp);
  return(0);
}

/*
 * IpAddrInRange()
 *
 * Is the IP address within the range?
 */

int
IpAddrInRange(struct in_range *range, struct in_addr ipaddr)
{
  long	mask;

  mask = range->width ? htonl(~0 << (32 - range->width)) : 0;
  return((ipaddr.s_addr & mask) == (range->ipaddr.s_addr & mask));
}


