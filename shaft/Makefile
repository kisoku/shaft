#	$OpenBSD: Makefile,v 1.11 2008/04/18 12:32:11 djm Exp $

.PATH:		${.CURDIR}/.. ${.CURDIR}/../../../usr.bin/ssh

PROG=	shaft
BINOWN=	root

BINMODE?=555

BINDIR=	/usr/sbin
MAN=	shaft.1

SRCS=	shaft.c shaft-client.c shaft-common.c

.include <bsd.prog.mk>

LDADD+=	-lutil
