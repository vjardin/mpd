
/*
 * util.h
 *
 * Written by Archie Cobbs <archie@freebsd.org>
 * Copyright (c) 1995-1999 Whistle Communications, Inc. All rights reserved.
 * See ``COPYRIGHT.whistle''
 */

#ifndef _UTIL_H_
#define _UTIL_H_

#include "ip.h"
#include "ipcp.h"

  /*-
   * The following macro is used to update an
   * internet checksum.  "acc" is a 32-bit
   * accumulation of all the changes to the
   * checksum (adding in old 16-bit words and
   * subtracting out new words), and "cksum"
   * is the checksum value to be updated.
   */
  #define ADJUST_CHECKSUM(acc, cksum) { \
    acc += cksum; \
    if (acc < 0) { \
      acc = -acc; \
      acc = (acc >> 16) + (acc & 0xffff); \
      acc += acc >> 16; \
      cksum = (u_short) ~acc; \
    } else { \
      acc = (acc >> 16) + (acc & 0xffff); \
      acc += acc >> 16; \
      cksum = (u_short) acc; \
    } \
  }

  #define MAX_U_INT32 0xffffffffU

  #define MAX_INTERFACES	2048

/*
 * FUNCTIONS
 */

  extern FILE		*OpenConfFile(const char *name);
  extern int		SeekToLabel(FILE *fp, const char *label, int *lineNum);

  extern char		*ReadFullLine(FILE *fp, int *lineNum);
  extern int		ReadFile(const char *filename, const char *target,
				int (*func)(int ac, char *av[]));
  extern int		ParseLine(char *line, char *vec[], int max_args);
  extern void		FreeArgs(int ac, char *av[]);

  extern int		ParseAddr(char *s, struct in_range *range);
  extern struct sockaddr_in * ParseAddrPort(int ac, char *av[]);

  extern int		TcpGetListenPort(struct in_addr ip, int *port, int block);
  extern int		TcpAcceptConnection(int sock, struct sockaddr_in *addr, int block);
  extern int		TcpMakeConnection(struct in_addr addr, int port);
  extern int		GetInetSocket(int type, struct in_addr locip,
			  int locport, int block, char *ebuf, int len);

  extern int		OpenSerialDevice(const char *path, int baudrate);
  extern int		ExclusiveOpenDevice(const char *path);
  extern void		ExclusiveCloseDevice(int fd, const char *path);

  extern int		WriteMbuf(Mbuf *mp, int fd, const char *label);
  extern int		PIDCheck(const char *lockfile, int killem);

  extern void		LengthenArray(void *arrayp, int esize,
				int *alenp, const char *type);

  extern int		ExecCmd(int log, const char *fmt, ...)
				__printflike(2, 3);
  extern void		ShowMesg(int log, const char *buf, int len);
  extern char		*Bin2Hex(const unsigned char *bin, int len);
  extern u_char		*Hex2Bin(char *hexstr);
  extern u_short	Crc16(u_short fcs, u_char *cp, int len);
  extern u_long		GenerateMagic(void);

  extern int		GetAnyIpAddress(struct in_addr *ipaddr, char *ifname);
  extern int		GetEther(struct in_addr *addr,
			    struct sockaddr_dl *hwaddr);

#endif

