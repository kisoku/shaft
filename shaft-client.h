/* $OpenBSD$ */

/*
 * Copyright (c) 2010 Mathieu Sauve-Frankel <msf@openbsd.org>
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

/*
 * Initialise a shaft connection. Returns NULL on error or
 * a pointer to a initialized sftp_conn struct on success.
 */

struct shaft_conn;
struct shaft_flow;
struct shaft_sa;

struct shaft_conn *do_init(int, int, struct shaft_flow *);
void do_req_sa(struct shaft_conn *, struct shaft_sa *);
void do_add_sa(struct shaft_conn *, char *);
