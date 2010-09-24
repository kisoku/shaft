/* $OpenBSD$ */

/*
 * Copyright (c) 2010 Mathieu Sauve-Frankel <msf@openbsd.org>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/* Maximum packet that we are willing to send/accept */
#define SHAFT_MAX_MSG_LENGTH	(256 * 1024)

extern pid_t ipsecpid;

struct shaft_flow {
	char *local;
	char *dst;
	char *peer;
};

struct shaft_sa {
	u_int status;
	char *src;
	char *dst;
	char *akey1;
	char *akey2;
	char *ekey1;
	char *ekey2;
	char *spi1;
	char *spi2;
};


void decode_sa(Buffer *, struct shaft_sa *);
void encode_sa(Buffer *, struct shaft_sa *);
void discover_params(char *, char *, struct shaft_flow *);
char *create_key(int);
struct shaft_sa *create_sa(char *, char *);
char *create_rules(struct shaft_flow *, struct shaft_sa *);
void exec_ipsecctl(int, char *);
void test_rules(char *);
void add_rules(char *);
void delete_rules(char *);
