
VERSION!=	cat ../src/Makefile | grep ^VERSION | awk '{ print $$2 }'

PDIR=		port.temp

MAKEFILE=	${PDIR}/Makefile
PLIST=		${PDIR}/pkg-plist
DESCR=		${PDIR}/pkg-descr
COMMENT=	${PDIR}/pkg-comment
MD5=		${PDIR}/distinfo
MTREE=		${PDIR}/files/mpd.mtree

port:
		rm -rf ${PDIR}
		mkdir -p ${PDIR}
		mkdir -p ${PDIR}/files
		cat PLIST.head > ${PLIST}
		( cd ../mpd-${VERSION}/doc && ls *.html | sort ) \
		  | awk '{ printf "share/doc/mpd/%s\n", $$1 }' >> ${PLIST}
		cat PLIST.tail >> ${PLIST}
		cp DESCR ${DESCR}
		cp COMMENT ${COMMENT}
		cp mpd.mtree ${MTREE}
		( cd .. && md5 mpd-${VERSION}.tar.gz ) > ${MD5}
		sed 's/@VERSION@/${VERSION}/g' < Makefile.in > ${MAKEFILE}
		( cd ${PDIR} && tar cvf - * | gzip --best ) > ../port.tgz
		rm -rf ${PDIR}

clean cleandir:
		rm -f ../port.tgz

