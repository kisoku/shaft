
/* $OpenBSD$ */

/*
 * Copyright (c) 2010 Damien Miller <djm@openbsd.org>
 * Copyright (c) 2010 Mathieu Sauve-Frankel <msf@openbsd.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip_ipsp.h>
#include <arpa/inet.h>

#include <ctype.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <limits.h>
#include <netdb.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>
#include <netdb.h>

#include "xmalloc.h"
#include "buffer.h"
#include "log.h"
#include "misc.h"
#include "shaft.h"
#include "shaft-common.h"

/* PID of ipsecctl process */
pid_t ipsecpid = -1;
int   responder = 0;

void
decode_sa(Buffer *b, struct shaft_sa *sa)
{	
	sa->status = buffer_get_int(b);
	sa->src = buffer_get_cstring(b, NULL);
	sa->dst = buffer_get_cstring(b, NULL);
	sa->akey1 = buffer_get_cstring(b, NULL);
	sa->akey2 = buffer_get_cstring(b, NULL);
	sa->ekey1 = buffer_get_cstring(b, NULL);
	sa->ekey2 = buffer_get_cstring(b, NULL);
	sa->spi1 = buffer_get_cstring(b, NULL);
	sa->spi2 = buffer_get_cstring(b, NULL);
}

void
encode_sa(Buffer *b, struct shaft_sa *sa)
{
	buffer_put_int(b, sa->status);
	buffer_put_cstring(b, sa->src);
	buffer_put_cstring(b, sa->dst);
	buffer_put_cstring(b, sa->akey1);
	buffer_put_cstring(b, sa->akey2);
	buffer_put_cstring(b, sa->ekey1);
	buffer_put_cstring(b, sa->ekey2);
	buffer_put_cstring(b, sa->spi1);
	buffer_put_cstring(b, sa->spi2);
}

void
discover_params(char *host, char *port, struct shaft_flow *flow)
{
	int sock = -1, ret;
	struct sockaddr_storage addr;
	socklen_t addrlen;
	struct addrinfo hints, *ai;
	char local[NI_MAXHOST];
	char peer[NI_MAXHOST];

	/* Get IP address of client. */
	addrlen = sizeof(addr);
	memset(&addr, 0, sizeof(addr));

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;

	ret = getaddrinfo(host, port, &hints, &ai);
	if (ret)
		fatal("getaddrinfo: %s", gai_strerror(ret));

	sock = socket(ai->ai_family, SOCK_STREAM, 0);
	if (sock < 0) {
		fatal("socket: %.100s", strerror(errno));
	}

	if (connect(sock, ai->ai_addr, ai->ai_addrlen) < 0)
		fatal("connect: %s", gai_strerror(ret));

	if (getsockname(sock, (struct sockaddr *)&addr, &addrlen)
			< 0)
		fatal("getsockname");

	/* Get the remote IP */
	if ((ret = getnameinfo(ai->ai_addr, ai->ai_addrlen, peer,
	    sizeof(peer), NULL, 0, NI_NUMERICHOST)) != 0) {
		fatal("get_socket_address: getnameinfo %d failed: %s", NI_NUMERICHOST,
		    gai_strerror(ret));
	}

	/* Get the local IP */
	if ((ret = getnameinfo((struct sockaddr *)&addr, addrlen, local,
	    sizeof(local), NULL, 0, NI_NUMERICHOST)) != 0) {
		fatal("get_socket_address: getnameinfo %d failed: %s", NI_NUMERICHOST,
		    gai_strerror(ret));
	}

	write(sock, "SSH-2.0-Probe-Shaft\r\n", 21);
	close(sock);

	flow->local = xstrdup(local);
	flow->peer = xstrdup(peer);
}

char *
create_key(int bits)
{
	int i, j;
	char *hexkey; 
	u_char *key;
	key = xmalloc(bits / 8);
	hexkey = xmalloc((bits / 4) + 1);
	arc4random_buf(key, bits / 8);
	
	for (i = j = 0; i < (bits / 8); i++) {
		snprintf(hexkey + j, 3, "%02x", key[i]);
		j += 2;
	}

	hexkey[j] = '\0';

	bzero(key, bits / 8); 
	free(key); 

	return(hexkey);
}

void
create_tmpfile(FILE **fp, char **path)
{
	int fd;

	*path = xstrdup(_PATH_SHAFT_RULES);

	debug2("Creating tmpfile");
	if ((fd = mkstemp(*path)) == -1 || (*fp = fdopen(fd, "w+")) == NULL) {
		if (fd != -1) {
			unlink(*path);
		        close(fd);
		}
		fatal("Couldn't create shaft_rules: %s", *path);
	}
}

struct shaft_sa *
create_sa(char *src, char *dst)
{
	struct shaft_sa *sa;
	sa = xmalloc(sizeof(*sa));
	sa->status = SHAFT_SA_INACTIVE;
	sa->src = src;
	sa->dst = dst;
	sa->spi1 = create_key(32);
	sa->spi2 = create_key(32);
	sa->akey1 = create_key(256);
	sa->akey2 = create_key(256);
	sa->ekey1 = create_key(160);
	sa->ekey2 = create_key(160);

	return(sa);
}

char *
create_rules(struct shaft_flow *flow, struct shaft_sa *sa)
{
	FILE *out; 
	char *rule_path;

	create_tmpfile(&out, &rule_path);
	fprintf(out, "flow esp from %s to %s peer %s\n", 
	    flow->local, flow->dst, flow->peer);
	if (strcmp(flow->dst, flow->peer) == 0) {
		if (responder == 0) {
			fprintf(out, "flow esp proto tcp from %s to %s port ssh peer %s type bypass\n",
				flow->local, flow->dst, flow->peer);
		} else {
			fprintf(out, "flow esp proto tcp from %s port ssh to %s peer %s type bypass\n",
				flow->local, flow->dst, flow->peer);
		}
			
	}
	fprintf(out, "esp transport from %s to %s spi 0x%s:0x%s \\\n", 
	    sa->src, sa->dst, sa->spi1, sa->spi2);
	fprintf(out, "\tauth hmac-sha2-256 enc aesctr \\\n");
	fprintf(out, "\tauthkey \"%s:%s\" \\\n", sa->akey1, sa->akey2);
	fprintf(out, "\tenckey \"%s:%s\"\n", sa->ekey1, sa->ekey2);
	fclose(out);

	return(rule_path);
}

void
exec_ipsecctl(int action, char *rules_path)
{
	int s;
	char *ipsecctl_program = _PATH_IPSECCTL;

	arglist args;
	memset(&args, '\0', sizeof(args));
	args.list = NULL;

	addargs(&args, ipsecctl_program);
	switch(action) {
		case IPSECCTL_ADD:
			break;
		case IPSECCTL_TEST:
			addargs(&args, "-n");
			break;
		case IPSECCTL_DELETE:
			addargs(&args, "-d");
			break;
	}
	addargs(&args, "-f");
	addargs(&args, "%s", rules_path);

	if ((ipsecpid = fork()) == -1) 
		fatal("fork: %s", strerror(errno));
	else if (ipsecpid == 0) {
		signal(SIGINT, SIG_IGN);
		signal(SIGTERM, SIG_DFL);
		execvp(ipsecctl_program, args.list);
		fprintf(stderr, "exec: %s: %s\n", *args.list, strerror(errno));
		_exit(1);
	}

	waitpid(ipsecpid, &s, 0);
	if (s != 0)
		fatal("exec: ipsecctl exited abnormally");
}

void
test_rules(char *rules_path)
{
	exec_ipsecctl(IPSECCTL_TEST, rules_path);
}

void
add_rules(char *rules_path)
{
	exec_ipsecctl(IPSECCTL_ADD, rules_path);
}

void
delete_rules(char *rules_path)
{
	exec_ipsecctl(IPSECCTL_DELETE, rules_path);
}

/*
static void
insert_rules(char *path, **args)
{
	pid_t ipsecpid; 

	if ((ipsecpid = fork()) == -1) {
		fatal("fork: %s", strerror(errno));
	else if (ipsecpid == 0) {

		signal(SIGINT, SIG_IGN);
		signal(SIGTERM, SIG_DFL);
		execvp(path, args);
	}
}
*/
