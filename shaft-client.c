/* $OpenBSD: shaft-client.c,v 1.92 2010/07/19 03:16:33 djm Exp $ */
/*
 * Copyright (c) 2001-2004 Damien Miller <djm@openbsd.org>
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

/* XXX: memleaks */
/* XXX: signed vs unsigned */
/* XXX: remove all logging, only return status codes */
/* XXX: copy between two remote sites */

#include <sys/types.h>
#include <sys/queue.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/param.h>
#include <sys/statvfs.h>
#include <sys/uio.h>

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "xmalloc.h"
#include "buffer.h"
#include "log.h"
#include "atomicio.h"
#include "progressmeter.h"
#include "misc.h"

#include "shaft.h"
#include "shaft-common.h"
#include "shaft-client.h"

/* Minimum amount of data to read at a time */
#define MIN_READ_SIZE	512

/* Maximum depth to descend in directory trees */
#define MAX_DIR_DEPTH 64

struct shaft_conn {
	int fd_in;
	int fd_out;
	u_int num_requests;
	u_int version;
	u_int msg_id;
};

static void
send_msg(int fd, Buffer *m)
{
	u_char mlen[4];
	struct iovec iov[2];

	if (buffer_len(m) > SHAFT_MAX_MSG_LENGTH)
		fatal("Outbound message too long %u", buffer_len(m));

	/* Send length first */
	put_u32(mlen, buffer_len(m));
	iov[0].iov_base = mlen;
	iov[0].iov_len = sizeof(mlen);
	iov[1].iov_base = buffer_ptr(m);
	iov[1].iov_len = buffer_len(m);

	if (atomiciov(writev, fd, iov, 2) != buffer_len(m) + sizeof(mlen))
		fatal("Couldn't send packet: %s", strerror(errno));

	buffer_clear(m);
}

static void
get_msg(int fd, Buffer *m)
{
	u_int msg_len;

	/* XXX */ buffer_dump(m);
	buffer_append_space(m, 4);
	if (atomicio(read, fd, buffer_ptr(m), 4) != 4) {
		if (errno == EPIPE)
			fatal("Connection closed");
		else
			fatal("Couldn't read packet: %s", strerror(errno));
	}

	msg_len = buffer_get_int(m);
	if (msg_len > SHAFT_MAX_MSG_LENGTH)
		fatal("Received message too long %u", msg_len);

	buffer_append_space(m, msg_len);
	if (atomicio(read, fd, buffer_ptr(m), msg_len) != msg_len) {
		if (errno == EPIPE)
			fatal("Connection closed");
		else
			fatal("Read packet: %s", strerror(errno));
	}
}

static u_int
get_status(int fd, u_int expected_id)
{
	Buffer msg;
	u_int type, id, status;

	buffer_init(&msg);
	get_msg(fd, &msg);
	type = buffer_get_char(&msg);
	id = buffer_get_int(&msg);

	if (id != expected_id)
		fatal("ID mismatch (%u != %u)", id, expected_id);
	if (type != SHAFT_STATUS)
		fatal("Expected SHAFT_STATUS(%u) packet, got %u",
		    SHAFT_STATUS, type);

	status = buffer_get_int(&msg);
	buffer_free(&msg);

	debug3("SHAFT_STATUS %u", status);

	return(status);
}

struct shaft_conn *
do_init(int fd_in, int fd_out, struct shaft_flow *flow)
{
	u_int type, version;
	Buffer msg;
	struct shaft_conn *ret;

	buffer_init(&msg);
	buffer_put_char(&msg, SHAFT_INIT);
	buffer_put_int(&msg, SHAFT_VERSION);
	buffer_put_cstring(&msg, flow->local);
	send_msg(fd_out, &msg);

	buffer_clear(&msg);

	get_msg(fd_in, &msg);

	/* Expecting a VERSION reply */
	if ((type = buffer_get_char(&msg)) != SHAFT_VERSION) {
		error("Invalid packet back from SHAFT_INIT (type %u)",
		    version);
		buffer_free(&msg);
		return(NULL);
	}
	version = buffer_get_int(&msg);
	flow->dst = buffer_get_cstring(&msg, NULL);
	if (flow->dst == NULL) {
		error("Invalid packet back from SHAFT_INIT remote addr is null");
		buffer_free(&msg);
		return(NULL);
	}

	debug2("Remote version: %u", version);
	debug2("Remote Address: %s", flow->dst);

	buffer_free(&msg);

	ret = xmalloc(sizeof(*ret));
	ret->fd_in = fd_in;
	ret->fd_out = fd_out;
	ret->version = version;
	ret->msg_id = 1;

	return(ret);
}

void
do_req_sa(struct shaft_conn *conn, struct shaft_sa *sa)
{
	u_int id, type;
	Buffer msg;

	id = conn->msg_id++;

        buffer_init(&msg);
	buffer_put_char(&msg, SHAFT_REQUEST_SA);
	buffer_put_int(&msg, id);

	/* XXX */ buffer_dump(&msg);
	send_msg(conn->fd_out, &msg);
	buffer_clear(&msg);

	get_msg(conn->fd_in, &msg);

	if ((type = buffer_get_char(&msg)) != SHAFT_REPLY_SA) {
		error("Invalid packet back from SHAFT_REQUEST_SA");
		buffer_free(&msg);
	}

	decode_sa(&msg, sa);

	if (sa == NULL)
		error("Invalide packet back from SHAFT_REPLY_SA");

	buffer_free(&msg);
}

void
do_add_sa(struct shaft_conn *conn, char * rules_path)
{
	u_int status, id, type;
	Buffer msg;

	id = conn->msg_id++;

        buffer_init(&msg);
	buffer_put_char(&msg, SHAFT_ADD_SA);
	buffer_put_int(&msg, id);

	/* XXX */ buffer_dump(&msg);
	send_msg(conn->fd_out, &msg);

	add_rules(rules_path);

	buffer_clear(&msg);
	status = get_status(conn->fd_in, id);

	if (status != SHAFT_OK)
		fatal("Couldn't add SA");
}
