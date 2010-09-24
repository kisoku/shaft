#	$OpenBSD: Makefile.inc,v 1.36 2010/02/20 20:28:11 markus Exp $

CFLAGS+=	-I${.CURDIR}/.. -I${.CURDIR}/../../../usr.bin/ssh

CDIAGFLAGS=	-Wall
#CDIAGFLAGS+=	-Werror
CDIAGFLAGS+=	-Wpointer-arith
CDIAGFLAGS+=	-Wuninitialized
CDIAGFLAGS+=	-Wstrict-prototypes
CDIAGFLAGS+=	-Wmissing-prototypes
CDIAGFLAGS+=	-Wunused
CDIAGFLAGS+=	-Wsign-compare
CDIAGFLAGS+=	-Wbounded
CDIAGFLAGS+=	-Wshadow

CFLAGS+=	${CDIAGFLAGS}

DEBUG=-g

#CFLAGS+=	-DJPAKE

#CFLAGS+=	-DENABLE_PKCS11
#.include <bsd.own.mk>
#.ifndef NOPIC
#CFLAGS+=	-DHAVE_DLOPEN
#.endif

.include <bsd.obj.mk>

.if exists(${.CURDIR}/../../../usr.bin/ssh/lib/${__objdir})
LDADD+=         -L${.CURDIR}/../../../usr.bin/ssh/lib/${__objdir} -lssh
DPADD+=         ${.CURDIR}/../../../usr.bin/ssh/lib/${__objdir}/libssh.a
.else
LDADD+=         -L${.CURDIR}/../../../usr.bin/ssh/lib -lssh
DPADD+=         ${.CURDIR}/../../../usr.bin/ssh/lib/libssh.a
.endif
