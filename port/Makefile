
VERSION!=	cat ../src/Makefile | grep ^VERSION | awk '{ print $$2 }'
HTMLNUM!=	( cd ../mpd4-${VERSION}/doc && ls *[0-9]*.html | 	\
		sed -e 's/mpd//' -e 's/\.html//' | sort -n | 		\
		paste -d ' ' - - - - - - - - - - - - |			\
		sed -e 's/^/          /' -e '$$!s/$$/ \\/')

PDIR=		port.temp

MAKEFILE=	${PDIR}/Makefile
DESCR=		${PDIR}/pkg-descr
MD5=		${PDIR}/distinfo
MTREE=		${PDIR}/files/mpd4.mtree
RCSCRIPT=	${PDIR}/files/mpd4.sh

port:
		rm -rf ${PDIR}
		mkdir -p ${PDIR}
		mkdir -p ${PDIR}/files
		cp DESCR ${DESCR}
		cp mpd4.mtree ${MTREE}
		cp mpd4.sh ${RCSCRIPT}
		( cd .. && md5 mpd4-${VERSION}.tar.gz ) \
		  | sed 's,mpd4-,mpd4/mpd4-,g' > ${MD5}
		sed -e 's/@VERSION@/${VERSION}/g -e 's/@HTMLNUM@/${HTMLNUM}/g ' \
		  < Makefile.in > ${MAKEFILE}
		( cd ${PDIR} && tar cvf - * | gzip --best ) > ../port.tgz
		rm -rf ${PDIR}

clean cleandir:
		rm -f ../port.tgz

