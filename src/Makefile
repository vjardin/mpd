# $Id$
#
# Makefile for mpd, multi-link PPP daemon for FreeBSD
#
# Written by Archie Cobbs <archie@freebsd.org>
# Copyright (c) 1995-1999 Whistle Communications, Inc. All rights reserved.
# See ``COPYRIGHT.whistle''
#

PROG?=			mpd
PREFIX?=		/usr/local
BINDIR?=		${PREFIX}/sbin
VERSION=		3.10
NOMAN=

# Default configuration directory

MPD_CONF_DIR?=		${PREFIX}/etc/mpd

# Define supported physical layer types

PHYSTYPE_MODEM=		yes
#PHYSTYPE_TCP=		yes
PHYSTYPE_UDP=		yes
PHYSTYPE_NG_SOCKET=	yes
PHYSTYPE_PPTP=		yes
PHYSTYPE_PPPOE=		yes

# Define supported compression types
# Notes:
#  These are either incomplete or untested. Volunteers are
#  welcome. The STAC and MPPC compressions require proprietary
#  code from Stac Electronics (now known as Hi/Fn).

#COMPRESSION_PRED1=	yes
#COMPRESSION_STAC=	yes
#COMPRESSION_DEFLATE=	yes
#COMPRESSION_MPPC=	yes

# Define supported encryption types

ENCRYPTION_MPPE=	yes
ENCRYPTION_DES=		yes

# Define whether to support Microsoft CHAP. This requires libdes.
# This is included automatically if you are using MPPE encryption.

MICROSOFT_CHAP=		yes

# Set syslog logging facility. Change LOG_DAEMON to whatever you like.

SYSLOG_FACILITY=	LOG_DAEMON

# Compiler & linker flags

LDADD+=		-lmd
DPADD+=		${LIBMD}
LDADD+=		-lnetgraph
DPADD+=		${LIBNETGRAPH}

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
		-Wstrict-prototypes \
		-Wwrite-strings

# Standard sources

STDSRCS=        assert.c auth.c bund.c ccp.c chap.c \
		console.c command.c ecp.c fsm.c iface.c input.c \
		ip.c ipcp.c lcp.c link.c log.c main.c mbuf.c mp.c \
		msg.c ngfunc.c pap.c phys.c proto.c timer.c util.c \
		vars.c custom.c

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
.if defined ( PPTP_VENDOR_NAME )
COPTS+=		'-DPPTP_VENDOR_NAME="${PPTP_VENDOR_NAME}"'
.else
COPTS+=		'-DPPTP_VENDOR_NAME="FreeBSD mpd-${VERSION}"'
.endif
.endif
.if defined ( PHYSTYPE_PPPOE )
SRCS+=		pppoe.c
COPTS+=		-DPHYSTYPE_PPPOE
.endif

# Compression

.if defined ( COMPRESSION_MPPC )
NEED_MPPC=	yes
.endif
.if defined ( COMPRESSION_PRED1 )
SRCS+=		ccp_pred1.c
COPTS+=		-DCOMPRESSION_PRED1
.endif
.if defined ( COMPRESSION_STAC )
SRCS+=		ccp_stac.c lzsc.c
COPTS+=		-DCOMPRESSION_STAC
.endif
.if defined ( COMPRESSION_DEFLATE )
SRCS+=		ccp_deflate.c
COPTS+=		-DCOMPRESSION_DEFLATE
LDADD+=		-lz
DPADD+=		${LIBZ}
.endif

# Encryption

.if defined ( ENCRYPTION_DES )
SRCS+=		ecp_des.c
COPTS+=		-DENCRYPTION_DES
NEED_DES=	yes
.endif
.if defined ( ENCRYPTION_MPPE )
SRCS+=		sha-1.c
COPTS+=		-DENCRYPTION_MPPE
NEED_MPPC=	yes
NEED_MSOFT=	yes
# Microsoft CHAP is required for MPPE encryption to work
MICROSOFT_CHAP=	yes
.endif

# Microsoft CHAP

.if defined ( MICROSOFT_CHAP )
COPTS+=		-DMICROSOFT_CHAP
NEED_DES=	yes
NEED_MSOFT=	yes
.endif

# Add in required support files and libraries

.if defined ( NEED_MPPC )
SRCS+=		ccp_mppc.c
COPTS+=		-DCOMPRESSION_MPPC
.endif
.if defined ( NEED_MSOFT )
SRCS+=		msoft.c
.endif
.if defined ( NEED_DES )
LDADD+=		-ldes
DPADD+=		${LIBDES}
.endif

# Now add standard sources

SRCS+=		${STDSRCS}

.include <bsd.prog.mk>
