# $Id$

VERSION!=	cat src/Makefile | grep ^VERSION | awk '{ print $$2 }'

DISTNAME=	mpd-${VERSION}
TARBALL=	${DISTNAME}.tar.gz
PORTBALL=	port.tgz

all:		${TARBALL} ${PORTBALL} testport

${TARBALL}:	._export-done
	cd mpd && ${MAKE} .${TARBALL}
	cp mpd/${TARBALL} ./${TARBALL}

.${TARBALL}:	.dist-done
	rm -f ${TARBALL}
	tar cvf - ${DISTNAME} | gzip --best > ${TARBALL}

${PORTBALL}:	._export-done
	cd mpd && ${MAKE} .${PORTBALL}
	cp mpd/${PORTBALL} ./${PORTBALL}

.${PORTBALL}:	.dist-done
	cd port && ${MAKE} port

._export-done:
	@if [ -z ${TAG} ]; then						\
		echo ERROR: Please specify TAG=HEAD? in environment;	\
		false;							\
	fi
	git archive --format=tar.gz --prefix=mpd/ ${TAG} >mpd-${TAG}.tgz
	tar xvzf mpd-${TAG}.tgz
	touch ${.TARGET}

.dist-done:	.doc-done
	rm -rf ${DISTNAME} ${.TARGET}
	mkdir ${DISTNAME} ${DISTNAME}/src ${DISTNAME}/doc ${DISTNAME}/conf
	cp dist/Makefile ${DISTNAME}
	cp dist/Makefile.conf ${DISTNAME}/conf/Makefile
	cp dist/Makefile.doc ${DISTNAME}/doc/Makefile
	cp -r src/COPYRIGHT* src/Makefile src/[a-z]* ${DISTNAME}/src
	sed 's/@VERSION@/${VERSION}/g' < src/Makefile > ${DISTNAME}/src/Makefile
	cp doc/mpd*.html doc/mpd.ps ${DISTNAME}/doc
	cp doc/mpd.8 ${DISTNAME}/doc/mpd5.8.in
	cp conf/[a-z]* ${DISTNAME}/conf
	sed 's/@VERSION@/${VERSION}/g' < dist/README > ${DISTNAME}/README
	touch ${.TARGET}

.doc-done:
	rm -f ${.TARGET}
	cd doc && ${MAKE}
	touch ${.TARGET}

regen:		clean ${TARBALL}

testport:	${TARBALL} ${PORTBALL}
	sudo cp ${TARBALL} /usr/ports/distfiles/mpd5/
	mkdir -p ._${PORTBALL}
	cd ._${PORTBALL} && tar xvzf ../${PORTBALL} && make

clean cleandir:
	rm -rf mpd
	rm -f ._export-done
	cd doc && ${MAKE} clean
	rm -f .doc-done
	rm -rf ${DISTNAME} ${TARBALL} ${PORTBALL}
	rm -rf ._${PORTBALL}
	rm -f .dist-done
	cd src && ${MAKE} cleandir
	cd port && ${MAKE} cleandir

distclean:	clean
	rm -f ${TARBALL}

vers:
	@echo The version is: ${VERSION}

