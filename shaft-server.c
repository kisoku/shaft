/* $OpenBSD$ */

/*
 * Copyright (c) 2010 Mathieu Sauve-Frankel <msf@openbsd.org>
 * Copyright (c) 2000-2004 Markus Friedl.  All rights reserved.
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
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/param.h>
#include <sys/wait.h>

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <pwd.h>
#include <time.h>
#include <unistd.h>
#include <stdarg.h>
#include <signal.h>

#include "xmalloc.h"
#include "buffer.h"
#include "log.h"
#include "misc.h"
#include "uidswap.h"

#include "shaft.h"
#include "shaft-common.h"

/* helper */
#define get_int64()			buffer_get_int64(&iqueue);
#define get_int()			buffer_get_int(&iqueue);
#define get_string(lenp)		buffer_get_string(&iqueue, lenp);
#define get_cstring(lenp)		buffer_get_cstring(&iqueue, lenp);

extern int responder;

/* Our verbosity */
LogLevel log_level = SYSLOG_LEVEL_ERROR;

/* Our client */
struct passwd *pw = NULL;

/* connection state */
struct shaft_flow flow;
struct shaft_sa sa;
char   *rules;

/* input and output queue */
Buffer iqueue;
Buffer oqueue;

/* Version of client */
int version;

/* send replies */

static void
killchild(int signo)
{
	if (ipsecpid > 1) {
		kill(ipsecpid, SIGTERM);
		waitpid(ipsecpid, NULL, 0);
	}

	_exit(1);
}

static void
send_msg(Buffer *m)
{
	int mlen = buffer_len(m);

	debug2("placing message of len: %u on oqueue", mlen);
	buffer_put_int(&oqueue, mlen);
	buffer_append(&oqueue, buffer_ptr(m), mlen);
	buffer_consume(m, mlen);
}

static const char *
status_to_message(u_int32_t status)
{
	const char *status_messages[] = {
		"Success",			/* SHAFT_OK */
		"End of file",			/* SHAFT_EOF */
		"No such file",			/* SHAFT_NO_SUCH_FILE */
		"Permission denied",		/* SHAFT_PERMISSION_DENIED */
		"Failure",			/* SHAFT_FAILURE */
		"Bad message",			/* SHAFT_BAD_MESSAGE */
		"No connection",		/* SHAFT_NO_CONNECTION */
		"Connection lost",		/* SHAFT_CONNECTION_LOST */
		"Operation unsupported",	/* SHAFT_OP_UNSUPPORTED */
		"Unknown error"			/* Others */
	};
	return (status_messages[MIN(status,SHAFT_MAX)]);
}

static void
send_status(u_int32_t id, u_int32_t status)
{
	Buffer msg;

	debug3("request %u: sent status %u", id, status);
	if (log_level > SYSLOG_LEVEL_VERBOSE ||
	    (status != SHAFT_OK && status != SHAFT_EOF))
		logit("sent status %s", status_to_message(status));
	buffer_init(&msg);
	buffer_put_char(&msg, SHAFT_STATUS);
	buffer_put_int(&msg, id);
	buffer_put_int(&msg, status);
	if (version >= 3) {
		buffer_put_cstring(&msg, status_to_message(status));
		buffer_put_cstring(&msg, "");
	}
	send_msg(&msg);
	buffer_free(&msg);
}

static void
process_init(void)
{
	Buffer msg;

	version = get_int();
	verbose("received client version %d", version);
	flow.dst = get_cstring(NULL);
	verbose("received dst address %s", flow.dst);
	buffer_init(&msg);
	buffer_put_char(&msg, SHAFT_VERSION);
	buffer_put_int(&msg, 1);
	buffer_put_cstring(&msg, flow.local);
	send_msg(&msg);
	buffer_free(&msg);
}

static void
process_req_sa(void)
{
	Buffer	msg;
	u_int32_t id;
	struct shaft_sa *s;
	
	id = get_int();

	s = create_sa(flow.local, flow.dst);
	rules = create_rules(&flow, s);
	debug2("rules: %s", rules);
	
	test_rules(rules);
	buffer_init(&msg);
	buffer_put_char(&msg, SHAFT_REPLY_SA);
	
	encode_sa(&msg, s);
	send_msg(&msg);

	buffer_free(&msg);

	sa.status = s->status;
	sa.src = s->src;
	sa.dst = s->dst;
	sa.spi1 = s->spi1;
	sa.spi2 = s->spi2;
	sa.akey1 = s->akey1;
	sa.akey2 = s->akey2;
	sa.ekey1 = s->ekey1;
	sa.ekey2 = s->ekey2;
}

static void
process_add_sa(void)
{
	u_int32_t id;

	id = get_int();
	add_rules(rules);

	send_status(id, SHAFT_OK);
}

static void
process(void)
{
	u_int msg_len;
	u_int buf_len;
	u_int consumed;
	u_int type;
	u_char *cp;

	buf_len = buffer_len(&iqueue);
	if (buf_len < 5)
		return;		/* Incomplete message. */
	cp = buffer_ptr(&iqueue);
	msg_len = get_u32(cp);
	if (msg_len > SHAFT_MAX_MSG_LENGTH) {
		error("bad message from %s local user %s",
		    flow.peer, pw->pw_name);
		shaft_server_cleanup_exit(11);
	}
	if (buf_len < msg_len + 4)
		return;
	buffer_consume(&iqueue, 4);
	buf_len -= 4;
	/* XXX */ buffer_dump(&iqueue);
	type = buffer_get_char(&iqueue);
	switch (type) {
		case SHAFT_INIT:
			process_init();
			break;
		case SHAFT_REQUEST_SA:
			process_req_sa();
			break;
		case SHAFT_ADD_SA:
			process_add_sa();
			break;
	default:
		error("Unknown message %d", type);
		break;
	}
	/* discard the remaining bytes from the current packet */
	if (buf_len < buffer_len(&iqueue)) {
		error("iqueue grew unexpectedly");
		shaft_server_cleanup_exit(255);
	}
	consumed = buf_len - buffer_len(&iqueue);
	if (msg_len < consumed) {
		error("msg_len %d < consumed %d", msg_len, consumed);
		shaft_server_cleanup_exit(255);
	}
	if (msg_len > consumed)
		buffer_consume(&iqueue, msg_len - consumed);
}

/* Cleanup handler that logs active handles upon normal exit */
void
shaft_server_cleanup_exit(int i)
{
	if (pw != NULL && flow.peer != NULL) {
		logit("session closed for local user %s from [%s]",
		    pw->pw_name, flow.peer);
	}
	_exit(i);
}

static void
usage(void)
{
	extern char *__progname;
	fprintf(stderr, "usage: %s [-f log_facility] [-l log_level]\n", __progname);
	exit(1);
}

int
main (int argc, char **argv)
{
	fd_set *rset, *wset;
	int in, out, max, ch, skipargs = 0, log_stderr = 0;
	ssize_t len, olen, set_size;
	SyslogFacility log_facility = SYSLOG_FACILITY_AUTH;
	char *cp, buf[4*4096];
	struct passwd *user_pw;

	extern char *optarg;
	extern char *__progname;

	responder = 1;

	/* Ensure that fds 0, 1 and 2 are open or directed to /dev/null */
	sanitise_stdfd();

	log_init(__progname, log_level, log_facility, log_stderr);

	if ((user_pw = getpwuid(getuid())) == NULL) {
		fprintf(stderr, "No user found for uid %lu\n",
		    (u_long)getuid());
		return 1;
	}

	while (!skipargs && (ch = getopt(argc, argv, "f:l:h")) != -1) {
		switch (ch) {
		case 'l':
			log_level = log_level_number(optarg);
			if (log_level == SYSLOG_LEVEL_NOT_SET)
				error("Invalid log level \"%s\"", optarg);
			break;
		case 'f':
			log_facility = log_facility_number(optarg);
			if (log_facility == SYSLOG_FACILITY_NOT_SET)
				error("Invalid log facility \"%s\"", optarg);
			break;
		case 'h':
		default:
			usage();
		}
	}

	log_init(__progname, log_level, log_facility, log_stderr);

	char **fp = NULL, *conn_str = NULL;
	int field = 0;

	if ((conn_str = getenv("SSH_CONNECTION")) != NULL) {
		while ((cp = strsep(&conn_str, " ")) != NULL) {
			if (*cp == '\0')
				continue;
			fp = xrealloc(fp, (field + 1), sizeof(*fp));
			fp[field++] = cp;
		}
		if (field < 4)
			fatal("corrupt SSH_CONNECTION");
		flow.peer = xstrdup(fp[0]);
		flow.local = xstrdup(fp[2]);
	} else {
		fatal("SSH_CONNECTION is unset");
	}

	pw = pwcopy(user_pw);

	logit("session opened for local user %s from [%s]",
	    pw->pw_name, flow.peer);

	in = STDIN_FILENO;
	out = STDOUT_FILENO;

	max = 0;
	if (in > max)
		max = in;
	if (out > max)
		max = out;

	buffer_init(&iqueue);
	buffer_init(&oqueue);

	set_size = howmany(max + 1, NFDBITS) * sizeof(fd_mask);
	rset = (fd_set *)xmalloc(set_size);
	wset = (fd_set *)xmalloc(set_size);

	for (;;) {
		memset(rset, 0, set_size);
		memset(wset, 0, set_size);

		/*
		 * Ensure that we can read a full buffer and handle
		 * the worst-case length packet it can generate,
		 * otherwise apply backpressure by stopping reads.
		 */
		if (buffer_check_alloc(&iqueue, sizeof(buf)) &&
		    buffer_check_alloc(&oqueue, SHAFT_MAX_MSG_LENGTH))
			FD_SET(in, rset);

		olen = buffer_len(&oqueue);
		if (olen > 0)
			FD_SET(out, wset);

		if (select(max+1, rset, wset, NULL, NULL) < 0) {
			if (errno == EINTR)
				continue;
			error("select: %s", strerror(errno));
			shaft_server_cleanup_exit(2);
		}

		/* copy stdin to iqueue */
		if (FD_ISSET(in, rset)) {
			len = read(in, buf, sizeof buf);
			if (len == 0) {
				debug("read eof");
				shaft_server_cleanup_exit(0);
			} else if (len < 0) {
				error("read: %s", strerror(errno));
				shaft_server_cleanup_exit(1);
			} else {
				buffer_append(&iqueue, buf, len);
			}
		}
		/* send oqueue to stdout */
		if (FD_ISSET(out, wset)) {
			len = write(out, buffer_ptr(&oqueue), olen);
			if (len < 0) {
				error("write: %s", strerror(errno));
				shaft_server_cleanup_exit(1);
			} else {
				buffer_consume(&oqueue, len);
			}
		}

		/*
		 * Process requests from client if we can fit the results
		 * into the output buffer, otherwise stop processing input
		 * and let the output queue drain.
		 */
		if (buffer_check_alloc(&oqueue, SHAFT_MAX_MSG_LENGTH))
			process();
	}

	signal(SIGTERM, killchild);
	signal(SIGINT, killchild);
	signal(SIGHUP, killchild);
}
