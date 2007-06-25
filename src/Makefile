# $Id$
#
# Makefile for mpd, multi-link PPP daemon for FreeBSD
#
# Written by Archie Cobbs <archie@freebsd.org>
# Copyright (c) 1995-1999 Whistle Communications, Inc. All rights reserved.
# See ``COPYRIGHT.whistle''
#

PROG?=			mpd4
PREFIX?=		/usr/local
BINDIR?=		${PREFIX}/sbin
VERSION=		4.2
NOMAN=
NO_MAN=

# Default configuration directory

MPD_CONF_DIR?=		${PREFIX}/etc/mpd4

# Define supported physical layer types

PHYSTYPE_MODEM=		yes
PHYSTYPE_TCP=		yes
PHYSTYPE_UDP=		yes
PHYSTYPE_NG_SOCKET=	yes
PHYSTYPE_PPTP=		yes
PHYSTYPE_PPPOE=		yes
PHYSTYPE_L2TP=		yes

# Define supported compression types
# Notes:
#  The MPPC compressions require proprietary
#  code from Stac Electronics (now known as Hi/Fn).

COMPRESSION_PRED1=	yes
COMPRESSION_DEFLATE=	yes

# Define supported encryption types

ENCRYPTION_DES=		yes

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
LDADD+=		-lpcap
DPADD+=		${LIBPCAP}

LDADD+=		-L${PREFIX}/lib -lpdel -lssl -lexpat

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
		console.c command.c ecp.c fsm.c iface.c input.c \
		ip.c ipcp.c ipv6cp.c lcp.c link.c log.c main.c mbuf.c mp.c \
		msg.c nat.c ngfunc.c pap.c phys.c proto.c radius.c timer.c \
		util.c vars.c custom.c eap.c ccp_mppc.c msoft.c web.c

# Mpd is event based, using this handy little event library..

STDSRCS+=	event.c

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

# Compression

.if defined ( COMPRESSION_PRED1 )
SRCS+=		ccp_pred1.c
COPTS+=		-DCOMPRESSION_PRED1
.endif
.if defined ( COMPRESSION_DEFLATE )
SRCS+=		ccp_deflate.c
COPTS+=		-DCOMPRESSION_DEFLATE
.endif

# Encryption

.if defined ( ENCRYPTION_DES )
SRCS+=		ecp_dese.c
SRCS+=		ecp_dese_bis.c
COPTS+=		-DENCRYPTION_DES
NEED_DES=	yes
.endif

# Add in required support files and libraries

.if defined ( NEED_DES )
LDADD+=		-lcrypto
DPADD+=		${LIBCRYPTO}
.endif

# Now add standard sources

SRCS+=		${STDSRCS}

.include <bsd.prog.mk>
