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

#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/param.h>
#include <sys/statvfs.h>
#include <net/pfkeyv2.h>
#include <net/route.h>
#include <netinet/in.h>
#include <netinet/ip_ipsp.h>
#include <arpa/inet.h>

#include <ctype.h>
#include <errno.h>
#include <glob.h>
#include <histedit.h>
#include <paths.h>
#include <libgen.h>
#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <util.h>
#include <stdarg.h>

#include "xmalloc.h"
#include "log.h"
#include "pathnames.h"
#include "misc.h"

#include "shaft.h"
#include "buffer.h"
#include "shaft-client.h"
#include "shaft-common.h"

/* PID of ssh transport process */
static pid_t sshpid = -1;

/* ARGSUSED */
static void
killchild(int signo)
{
	if (sshpid > 1) {
		kill(sshpid, SIGTERM);
		waitpid(sshpid, NULL, 0);
	}

	if (ipsecpid > 1) {
		kill(ipsecpid, SIGTERM);
		waitpid(ipsecpid, NULL, 0);
	}

	_exit(1);
}

static void
connect_to_server(char *path, char **args, int *in, int *out)
{
	int c_in, c_out;

	int inout[2];

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, inout) == -1)
		fatal("socketpair: %s", strerror(errno));
	*in = *out = inout[0];
	c_in = c_out = inout[1];

	if ((sshpid = fork()) == -1)
		fatal("fork: %s", strerror(errno));
	else if (sshpid == 0) {
		if ((dup2(c_in, STDIN_FILENO) == -1) ||
		    (dup2(c_out, STDOUT_FILENO) == -1)) {
			fprintf(stderr, "dup2: %s\n", strerror(errno));
			_exit(1);
		}
		close(*in);
		close(*out);
		close(c_in);
		close(c_out);

		/*
		 * The underlying ssh is in the same process group, so we must
		 * ignore SIGINT if we want to gracefully abort commands,
		 * otherwise the signal will make it to the ssh process and
		 * kill it too.  Contrawise, since sftp sends SIGTERMs to the
		 * underlying ssh, it must *not* ignore that signal.
		 */
		signal(SIGINT, SIG_IGN);
		signal(SIGTERM, SIG_DFL);
		execvp(path, args);
		fprintf(stderr, "exec: %s: %s\n", path, strerror(errno));
		_exit(1);
	}

	signal(SIGTERM, killchild);
	signal(SIGINT, killchild);
	signal(SIGHUP, killchild);
	close(c_in);
	close(c_out);
}

static void
usage(void)
{
	extern char *__progname;

	fprintf(stderr,
	    "usage: %s [-1246Cpqrv] [-c cipher]\n"
	    "          [-D shaft_server_path] [-i identity_file]\n"
	    "          [-o ssh_option] [-P port]"
	    "[-S program]\n"
	    "          [-s subsystem | shaft_server] host\n",
	    __progname);
	exit(1);
}

int
main(int argc, char **argv)
{
	int in, out, ch, err;
	char *host = NULL, *userhost;
	char *port = SHAFT_DEFAULT_PORT;
	int debug_level = 0, sshver = 2;
	char *shaft_server = NULL;
	char *ssh_program = _PATH_SSH_PROGRAM, *shaft_direct = NULL;
	LogLevel ll = SYSLOG_LEVEL_INFO;
	arglist args;
	extern int optind;
	extern char *optarg;
	struct shaft_conn *conn;
	struct shaft_flow flow;
	struct shaft_sa	  sa;
	char *rules_path;

	/* Ensure that fds 0, 1 and 2 are open or directed to /dev/null */
	sanitise_stdfd();

	bzero(&flow, sizeof(flow));
	bzero(&sa, sizeof(sa));

	memset(&args, '\0', sizeof(args));
	args.list = NULL;
	addargs(&args, "%s", ssh_program);
	addargs(&args, "-oForwardX11 no");
	addargs(&args, "-oForwardAgent no");
	addargs(&args, "-oPermitLocalCommand no");
	addargs(&args, "-oClearAllForwardings yes");
	/* disallow the parsing of user or system configuration */
	addargs(&args, "-F/dev/null");

	ll = SYSLOG_LEVEL_INFO;

	while ((ch = getopt(argc, argv,
	    "1246hqvCc:i:o:s:S:F:P:D:")) != -1) {
		switch (ch) {
		/* Passed through to ssh(1) */
		case '4':
		case '6':
		case 'C':
			addargs(&args, "-%c", ch);
			break;
		/* Passed through to ssh(1) with argument */
		case 'c':
		case 'i':
		case 'o':
			addargs(&args, "-%c", ch);
			addargs(&args, "%s", optarg);
			break;
		case 'q':
			addargs(&args, "-%c", ch);
			break;
		case 'P':
			port = optarg;
			addargs(&args, "-oPort %s", optarg);
			break;
		case 'D':
			shaft_direct = optarg;
			break;
		case 'v':
			if (debug_level < 3) {
				addargs(&args, "-v");
				ll = SYSLOG_LEVEL_DEBUG1 + debug_level;
			}
			debug_level++;
			break;
		case '1':
			sshver = 1;
			if (shaft_server == NULL)
				shaft_server = _PATH_SHAFT_SERVER;
			break;
		case '2':
			sshver = 2;
			break;
		case 's':
			shaft_server = optarg;
			break;
		case 'S':
			ssh_program = optarg;
			replacearg(&args, 0, "%s", ssh_program);
			break;
		case 'h':
		default:
			usage();
		}
	}

	log_init(argv[0], ll, SYSLOG_FACILITY_USER, 1);
	if (shaft_direct == NULL) {
		if (optind == argc || argc > (optind + 1))
			usage();

		userhost = xstrdup(argv[optind]);

		if ((host = strrchr(userhost, '@')) == NULL)
			host = userhost;
		else {
			*host++ = '\0';
			if (!userhost[0]) {
				fprintf(stderr, "Missing username\n");
				usage();
			}
			addargs(&args, "-l");
			addargs(&args, "%s", userhost);
		}

		host = cleanhostname(host);

		if (!*host) {
			fprintf(stderr, "Missing hostname\n");
			usage();
		}

		discover_params(host, port, &flow);

		addargs(&args, "-oProtocol %d", sshver);

		/* no subsystem if the server-spec contains a '/' */
		if (shaft_server == NULL || strchr(shaft_server, '/') == NULL)
			addargs(&args, "-s");

		addargs(&args, "--");
		addargs(&args, "%s", host);
		addargs(&args, "%s", (shaft_server != NULL ?
		    shaft_server : "shaft"));

		connect_to_server(ssh_program, args.list, &in, &out);
	} else {
		args.list = NULL;
		addargs(&args, "shaft-server");

		connect_to_server(shaft_direct, args.list, &in, &out);
	}
	freeargs(&args);

	conn = do_init(in, out, &flow);
	if (conn == NULL)
		fatal("Couldn't initialise connection to server");

        do_req_sa(conn, &sa);
	rules_path = create_rules(&flow, &sa);
	debug2("rules: %s", rules_path);
	test_rules(rules_path);
	do_add_sa(conn, rules_path);

	close(in);
	close(out);

	while (waitpid(sshpid, NULL, 0) == -1)
		if (errno != EINTR)
			fatal("Couldn't wait for ssh process: %s",
			    strerror(errno));

	exit(err == 0 ? 0 : 1);
}
