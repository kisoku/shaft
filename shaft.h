/* $OpenBSD$ */

/*
 * Copyright (c) 2010 Mathieu Sauve-Frankel <msf@openbsd.org>
 * Copyright (c) 2001 Markus Friedl.  All rights reserved.
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

#define _PATH_SHAFT_SERVER		"/usr/libexec/shaft-server"
#define _PATH_SHAFT_RULES 		"/tmp/shaft_rules.XXXXXXX"
#define _PATH_IPSECCTL			"/sbin/ipsecctl"

#define SHAFT_DEFAULT_PORT		"ssh"

#define SHAFT_VERSION			1

#define SHAFT_INIT			1
#define SHAFT_REQUEST_SA		2
#define SHAFT_REPLY_SA			3
#define SHAFT_ADD_SA			4
#define SHAFT_DELETE_SA			5

#define IPSECCTL_TEST			1
#define IPSECCTL_ADD			2
#define IPSECCTL_DELETE			3

#define SHAFT_SA_INACTIVE		1
#define SHAFT_SA_ACTIVE			2

/* status messages */
#define SHAFT_OK			0
#define SHAFT_EOF			1
#define SHAFT_NO_SUCH_FILE		2
#define SHAFT_PERMISSION_DENIED		3
#define SHAFT_FAILURE			4
#define SHAFT_BAD_MESSAGE		5
#define SHAFT_NO_CONNECTION		6
#define SHAFT_CONNECTION_LOST		7
#define SHAFT_OP_UNSUPPORTED		8
#define SHAFT_MAX			8
#define SHAFT_STATUS			101

void	shaft_server_cleanup_exit(int) __attribute__((noreturn));
