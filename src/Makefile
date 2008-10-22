# $Id$
#
# Makefile for mpd, multi-link PPP daemon for FreeBSD
#
# Written by Archie Cobbs <archie@freebsd.org>
# Copyright (c) 1995-1999 Whistle Communications, Inc. All rights reserved.
# See ``COPYRIGHT.whistle''
#

PROG?=			mpd5
PREFIX?=		/usr/local
BINDIR?=		${PREFIX}/sbin
VERSION=		5.2
NOMAN=
NO_MAN=

# Default configuration directory

MPD_CONF_DIR?=		${PREFIX}/etc/mpd5

# Define supported physical layer types

PHYSTYPE_MODEM=		yes
PHYSTYPE_TCP=		yes
PHYSTYPE_UDP=		yes
PHYSTYPE_NG_SOCKET=	yes
PHYSTYPE_PPTP=		yes
PHYSTYPE_PPPOE=		yes
PHYSTYPE_L2TP=		yes

# Define supported encryption types

ENCRYPTION_DES=		yes

# Define system features wanted to use (if present)

USE_NG_BPF=		yes
USE_NG_CAR=		yes
USE_NG_DEFLATE=		yes
USE_NG_IPACCT=		yes
USE_NG_NAT=		yes
USE_NG_NETFLOW=		yes
USE_NG_PRED1=		yes
USE_NG_TCPMSS=		yes
USE_NG_VJC=		yes
USE_IPFW=		yes
USE_FETCH=		yes

# Set syslog logging facility. Change LOG_DAEMON to whatever you like.

SYSLOG_FACILITY=	LOG_DAEMON

# Compiler & linker flags

LDADD+=		-lmd 
DPADD+=		${LIBMD}
LDADD+=		-lwrap
DPADD+=		${LIBWRAP}
LDADD+=		-lcrypt
DPADD+=		${LIBCRYPT}
LDADD+=		-lopie -lmd
DPADD+=		${LIBOPIE} ${LIBMD}
LDADD+=		-lutil
DPADD+=		${LIBUTIL}
LDADD+=		-lnetgraph
DPADD+=		${LIBNETGRAPH}
LDADD+=		-L/usr/lib -lradius
DPADD+=		${LIBRADIUS}
LDADD+=		-lpam
DPADD+=		${LIBPAM}

LDADD+=		-L${PREFIX}/lib
LDADD+=		-lpdel
LDADD+=		-lexpat

MPD_VERSION!=	echo -n "${VERSION} (`id -un`@`uname -n` `LC_TIME=C date +'%R %v'`)"

COPTS+=		-DPATH_CONF_DIR=\"${MPD_CONF_DIR}\"
COPTS+=		-DSYSLOG_FACILITY=${SYSLOG_FACILITY}
COPTS+=		-DMPD_VERSION='"${MPD_VERSION}"'
COPTS+=		-g
COPTS+=		-Wall \
		-Wcast-align \
		-Wchar-subscripts \
		-Wformat \
		-Winline \
		-Wmissing-declarations \
		-Wmissing-prototypes \
		-Wnested-externs \
		-Wpointer-arith \
		-Wwrite-strings \
		-pthread \
		-I${PREFIX}/include

.if defined ( MPD_VENDOR )
COPTS+=		'-DMPD_VENDOR="${MPD_VENDOR}"'
.endif

# Standard sources

STDSRCS=        assert.c auth.c bund.c rep.c ccp.c chap.c \
		console.c command.c ecp.c event.c fsm.c iface.c input.c \
		ip.c ipcp.c ipv6cp.c lcp.c link.c log.c main.c mbuf.c mp.c \
		msg.c ngfunc.c pap.c phys.c proto.c radius.c timer.c \
		util.c vars.c eap.c ccp_mppc.c msoft.c web.c ippool.c \
		ccp_pred1.c ccp_deflate.c

# Add sources and flags for the various physical layer types

.if defined ( PHYSTYPE_MODEM )
SRCS+=		modem.c chat.c
COPTS+=		-DPHYSTYPE_MODEM
.endif
.if defined ( PHYSTYPE_UDP )
SRCS+=		udp.c
COPTS+=		-DPHYSTYPE_UDP
.endif
.if defined ( PHYSTYPE_TCP )
SRCS+=		tcp.c
COPTS+=		-DPHYSTYPE_TCP
.endif
.if defined ( PHYSTYPE_NG_SOCKET )
SRCS+=		ng.c
COPTS+=		-DPHYSTYPE_NG_SOCKET
.endif
.if defined ( PHYSTYPE_PPTP )
SRCS+=		pptp.c pptp_ctrl.c
COPTS+=		-DPHYSTYPE_PPTP
.endif
.if defined ( PHYSTYPE_PPPOE )
SRCS+=		pppoe.c
COPTS+=		-DPHYSTYPE_PPPOE
.endif
.if defined ( PHYSTYPE_L2TP )
SRCS+=		l2tp.c l2tp_avp.c l2tp_ctrl.c
COPTS+=		-DPHYSTYPE_L2TP
.endif

# Encryption

.if defined ( ENCRYPTION_DES )
SRCS+=		ecp_dese.c
SRCS+=		ecp_dese_bis.c
COPTS+=		-DENCRYPTION_DES
NEED_DES=	yes
.endif

# Features

.if defined ( USE_NG_BPF )
COPTS+=		-DUSE_NG_BPF
LDADD+=		-lpcap
DPADD+=		${LIBPCAP}
.endif
.if defined ( USE_NG_CAR )
COPTS+=         -DUSE_NG_CAR
.endif
.if defined ( USE_NG_DEFLATE )
COPTS+=         -DUSE_NG_DEFLATE
.endif
.if defined ( USE_NG_IPACCT )
COPTS+=         -DUSE_NG_IPACCT
.endif
.if defined ( USE_NG_NAT )
SRCS+=		nat.c
COPTS+=         -DUSE_NG_NAT
.endif
.if defined ( USE_NG_NETFLOW )
COPTS+=         -DUSE_NG_NETFLOW
.endif
.if defined ( USE_NG_PRED1 )
COPTS+=         -DUSE_NG_PRED1
.endif
.if defined ( USE_NG_TCPMSS )
COPTS+=         -DUSE_NG_TCPMSS
.endif
.if defined ( USE_NG_VJC )
COPTS+=         -DUSE_NG_VJC
.endif
.if defined ( USE_IPFW )
COPTS+=         -DUSE_IPFW
.endif
.if defined ( USE_FETCH )
COPTS+=         -DUSE_IPFW
LDADD+=		-lfetch
DPADD+=		${LIBFETCH}
.endif

# Add in required support files and libraries

.if defined ( NEED_DES )
LDADD+=		-lcrypto
DPADD+=		${LIBCRYPTO}
.endif

# Now add standard sources

SRCS+=		${STDSRCS}

.include <bsd.prog.mk>
