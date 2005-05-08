
VERSION!=	cat ../src/Makefile | grep ^VERSION | awk '{ print $$2 }'

PDIR=		port.temp

MAKEFILE=	${PDIR}/Makefile
PLIST=		${PDIR}/pkg-plist
DESCR=		${PDIR}/pkg-descr
MD5=		${PDIR}/distinfo
MTREE=		${PDIR}/files/mpd4.mtree
RCSCRIPT=	${PDIR}/files/mpd4.sh

port:
		rm -rf ${PDIR}
		mkdir -p ${PDIR}
		mkdir -p ${PDIR}/files
		cat PLIST.head > ${PLIST}
		( cd ../mpd4-${VERSION}/doc && ls *.html | sort ) \
		  | awk '{ printf "share/doc/mpd4/%s\n", $$1 }' >> ${PLIST}
		cat PLIST.tail >> ${PLIST}
		cp DESCR ${DESCR}
		cp mpd4.mtree ${MTREE}
		cp mpd4.sh ${RCSCRIPT}
		( cd .. && md5 mpd4-${VERSION}.tar.gz ) \
		  | sed 's,mpd4-,mpd4/mpd4-,g' > ${MD5}
		sed 's/@VERSION@/${VERSION}/g' < Makefile.in > ${MAKEFILE}
		( cd ${PDIR} && tar cvf - * | gzip --best ) > ../port.tgz
		rm -rf ${PDIR}

clean cleandir:
		rm -f ../port.tgz

