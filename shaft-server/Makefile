#	$OpenBSD: Makefile,v 1.11 2008/04/18 12:32:11 djm Exp $

.PATH:		${.CURDIR}/.. ${CURDIR}/../../ssh

PROG=	shaft-server
BINOWN=	root

BINMODE?=555

BINDIR=	/usr/libexec
MAN=	shaft-server.8

SRCS=	shaft-server.c shaft-common.c

.include <bsd.prog.mk>

LDADD+=	-lutil
