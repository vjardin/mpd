# $Id$

.NOTPARALLEL:

all:		mpd.8

DOC=		mpd
FORMATS=	html ps

SRCS+=		mpd.sgml version.sgml overview.sgml layers.sgml manorg.sgml
SRCS+=		changes.sgml getting.sgml building.sgml installing.sgml
SRCS+=		invoke.sgml configfmt.sgml cli.sgml
SRCS+=		gencmd.sgml global.sgml console.sgml web.sgml bundle.sgml
SRCS+=		repeater.sgml interface.sgml links.sgml ipcp.sgml 
SRCS+=		compression.sgml encryption.sgml modem.sgml nat.sgml
SRCS+=		netgraph.sgml tcp.sgml udp.sgml pptp.sgml l2tp.sgml pppoe.sgml
SRCS+=		chat.sgml trouble.sgml refs.sgml int-auth.sgml int-extauth.sgml
SRCS+=		int-radius.sgml todo.sgml netflow.sgml

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
