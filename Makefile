LOCALBASE?= /usr/local/

SCRIPT=	filter-mimedefang.pl
MAN8=	filter-mimedefang.8
BINDIR=	${LOCALBASE}/libexec/smtpd/
MANDIR=	${LOCALBASE}/man/man

build:
	pod2man --section=8 filter-mimedefang.pl >filter-mimedefang.8

install:
	${INSTALL} -d ${DESTDIR}${BINDIR}
	${INSTALL} -m 0555 ${SCRIPT} ${DESTDIR}${BINDIR}
	${INSTALL} -m 0644 ${MAN8} ${DESTDIR}${MANDIR}8/

.include <bsd.prog.mk>
