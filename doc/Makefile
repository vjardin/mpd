# $Id$

.NOTPARALLEL:

all:		mpd.8

DOC=		mpd
FORMATS=	html ps

SRCS+=		mpd.sgml version.sgml
SRCS+=		overview.sgml layers.sgml manorg.sgml changes.sgml
SRCS+=		getting.sgml building.sgml installing.sgml
SRCS+=		invoke.sgml configfmt.sgml cli.sgml
SRCS+=		gencmd.sgml global.sgml console.sgml bundle.sgml interface.sgml links.sgml
SRCS+=		ipcp.sgml compression.sgml encryption.sgml
SRCS+=		modem.sgml netgraph.sgml tcp.sgml udp.sgml pptp.sgml pppoe.sgml
SRCS+=		chat.sgml
SRCS+=		trouble.sgml
SRCS+=		refs.sgml
SRCS+=		int-auth.sgml
SRCS+=		todo.sgml

CLEANFILES+=	version.sgml mpd.8 mpd.ps

.SUFFIXES:	.in

.in:
	VERSION=`grep ^VERSION= ../src/Makefile | awk '{ print $$2 }'`; \
	DATE=`date +'%B %e, %Y`; \
	sed \
	  -e "s/@DATE@/$$DATE/g" \
	  -e "s/@VERSION@/$$VERSION/g" \
	  < ${.ALLSRC} > ${.TARGET}

.include "bsd.sgml.mk"
