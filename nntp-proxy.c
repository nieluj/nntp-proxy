/*
 * This file is part of the nntp proxy project
 * Copyright (C) 2012 Julien Perrot
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 * See the file "COPYING" for the exact licensing terms.
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>
#include <crypt.h>
#include <sys/time.h>
#include <time.h>
#include <libconfig.h>

#include <event2/dns.h>
#include <event2/bufferevent_ssl.h>
#include <event2/bufferevent.h>
#include <event2/buffer.h>
#include <event2/listener.h>
#include <event2/util.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/engine.h>

struct user_info {
    char *username;
    char *password;
    int max_conns;
};

/** Configuration part **/

/* Username needed to establish the connection to the NNTP server */
#define SERVER_USER "FIXME"
/* Password associated to username */
#define SERVER_PASS "FIXME"
/* Maximum number of connections allowed by the NNTP */
#define MAX_CONNS 20

/* Login / passwords for the client side of the proxy, the password is generated with  'mkpasswd -m sha-512' */
/* The last field is the number of allowed connections for this user */
struct user_info users[] = {
    { "foo", "$6$aBUzpyBd$TNZv2jzHtARuoUPQmVjxRSHBZPKniMuZIUzAAd8Ob1c5pzcExsTDfA9zCF.sN8pmZL0Cb48FW/7iEtang7wBg/", 1 },
    { NULL, NULL, 0 }
};

/** end of configuration **/

#define NNTP_SERVICE_READY 200
#define NNTP_AUTH_ACCEPTED 281
#define NNTP_MORE_AUTH     381
#define NNTP_AUTH_REQUIRED 480
#define NNTP_AUTH_REJECTED 482
#define NNTP_NO_PERM       502

#define NNTP_BANNER "NNTP Proxy service ready."

#define ERROR_LEVEL   0
#define WARNING_LEVEL 1
#define NOTICE_LEVEL  2
#define INFO_LEVEL    3
#define DEBUG_LEVEL   4

#define PRINT_MSG(level, fmt, ...) print_msg(ERROR_LEVEL, "[%s:%d] " fmt, __PRETTY_FUNCTION__, __LINE__, ## __VA_ARGS__)

#define ERROR(fmt, ...)   PRINT_MSG(ERROR_LEVEL, fmt, ## __VA_ARGS__)
#define WARNING(fmt, ...) PRINT_MSG(WARNING_LEVEL, fmt, ## __VA_ARGS__)
#define NOTICE(fmt, ...)  PRINT_MSG(NOTICE_LEVEL, fmt, ## __VA_ARGS__)
#define INFO(fmt, ...)    PRINT_MSG(INFO_LEVEL, fmt, ## __VA_ARGS__)
#define DEBUG(fmt, ...)   PRINT_MSG(DEBUG_LEVEL, fmt, ## __VA_ARGS__)

#define MAX_CMD_ARGS 32

#define PARTNER_BEV(bev, conn) (bev == conn->server_bev) ? conn->client_bev : conn->server_bev
#define IS_SERVER(bev, conn) bev == conn->server_bev

enum conn_status {
    CLIENT_CONNECTING,
    CLIENT_CONNECTED,
    CLIENT_AUTHENTICATED,
    SERVER_CONNECTING,
    SERVER_CONNECTED,
    SERVER_AUTHENTICATED,
    CLIENT_CLOSING,
    CLIENT_CLOSED,
    SERVER_CLOSING,
    SERVER_CLOSED
};

struct conn_desc {
    /* connection from the proxy to the server */
    struct bufferevent *server_bev;
    /* connection from the client to the proxy */
    struct bufferevent *client_bev;
    int status;
    /* username from the client */
    char *client_username;
    /* number of the connection */
    int n;

    struct timeval last_cmd;
    size_t bytes;   
};

static struct conn_desc *connections;

static int verbose_level = ERROR_LEVEL;

static struct event_base *base;
static struct evdns_base *dns_base;

static struct sockaddr_storage listen_on_addr;
static const char *server_hostname;
static int server_port;

/* proxy server-side */
static SSL_CTX *ssl_server_ctx = NULL;
/* proxy client-side */
static SSL_CTX *ssl_client_ctx = NULL;

static int use_padlock_engine = 0;

#define MAX_OUTPUT (256*1024)

/* forward declarations */
static void common_readcb(struct bufferevent *bev, void *arg);
static void server_auth_readcb(struct bufferevent *bev, void *arg);
static void client_auth_readcb(struct bufferevent *bev, void *arg);

static void drained_writecb(struct bufferevent *bev, void *arg);
static void close_on_finished_writecb(struct bufferevent *bev, void *arg);
static void eventcb(struct bufferevent *bev, short what, void *arg);

static char str_inet[INET_ADDRSTRLEN];
static char str_inet6[INET6_ADDRSTRLEN];

static void print_msg(int level, const char *fmt, ...)
{
    char outstr[200];
    time_t t;
    struct tm *tmp;
    va_list ap;

    if (verbose_level < level)
	return;

    t = time(NULL);
    tmp = localtime(&t);
    strftime(outstr, sizeof(outstr), "%d/%m/%y %T", tmp);

    fprintf(stderr, "%s ", outstr);

    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
}

static struct conn_desc * get_next_conn(void)
{
    struct conn_desc *ret;
    int i;

    ret = connections;
    for (i = 0; i < MAX_CONNS; i++) {
	if (!ret->server_bev && !ret->client_bev) {
	    ret->n = i;
	    ret->bytes = 0;
	    INFO("Connection %d is available\n", ret->n);
	    return ret;
	} else {
	    DEBUG("conn %d not available, ret->server_bev = %p, ret->clien_bev = %p\n", i,
		    ret->server_bev, ret->client_bev);
	}
	ret++;
    }
    WARNING("No more connections available\n");
    return NULL;
}

static int allow_connection(const char *username)
{
    struct conn_desc *conn;
    struct user_info *user;
    int i, n = 0;

    user = users;
    while (user->username != NULL) {
	if (!strcmp(user->username, username)) {
	    break;
	}
	user++;
    }

    if (user->username == NULL) {
	WARNING("user info not found for username %s\n", username);
	return -1;
    }

    conn = connections;
    for (i = 0; i < MAX_CONNS; i++) {
	if (conn->client_username &&
		!strcmp(conn->client_username, username)) {
	    DEBUG("connection %d is used by user %s\n", conn->n, username);
	    n++;
	}
	conn++;
    }

    DEBUG("found %d existing connections for user %s\n", n, username);

    if (n < user->max_conns)
	return 0;
    else
	return -1;
}

static char * parse_nntp_response(char *str, int *code)
{
    char *tok;

    tok = strtok(str, " \t");
    if (!tok) {
	WARNING("invalid response\n");
	return NULL;
    }
    *code = atoi(tok);
    if (*code == 0) {
	WARNING("invalid code in response\n");
	return NULL;
    }

    tok = strtok(NULL, "");
    return tok;
}

static void parse_nntp_cmd(char *str, char **args, int *n)
{
    char *tok;

    tok = strtok(str, " ");
    if (!tok) {
	WARNING("invalid cmd\n");
	*n = 0;
	return;
    }
    *n = 0;

    while (tok != NULL && *n < MAX_CMD_ARGS) {
	args[*n] = tok;
	*n += 1;
	tok = strtok(NULL, " ");
    }
}

static char *ip_str_from_sa(const struct sockaddr *sa)
{
    char *ret;

    switch(sa->sa_family) {
	case AF_INET:
	    inet_ntop(AF_INET, &(((struct sockaddr_in *)sa)->sin_addr),
		    str_inet, INET_ADDRSTRLEN);
	    ret = str_inet;
	    break;
	case AF_INET6:
	    inet_ntop(AF_INET6,  &(((struct sockaddr_in6 *)sa)->sin6_addr),
		    str_inet6, INET6_ADDRSTRLEN);
	    ret = str_inet6;
	    break;
	default:
	    ret =NULL;
    }
    return ret;
}

static void syntax(const char *binpath)
{
    fprintf(stderr, "Syntax:\n");
    fprintf(stderr, "\t%s <keypath> <certpath> <listen-on-addr> <connect-to-addr>\n", binpath);
    fprintf(stderr, "Example:\n");
    fprintf(stderr, "\t%s key.pem cert.pem 0.0.0.0:563 ssl-eu.astraweb.com:443\n", binpath);

    exit(EXIT_FAILURE);
}

static SSL_CTX * ssl_server_init(const char *keypath, const char *certpath)
{
    SSL_CTX *ctx;
    ENGINE *e;

    ENGINE_load_builtin_engines();
    ENGINE_register_all_complete();

    e = ENGINE_by_id("padlock");
    if (e) {
	fprintf(stderr, "[*] Using padlock engine for default ciphers\n");
	ENGINE_set_default_ciphers(ENGINE_by_id("padlock"));
	use_padlock_engine = 1;
    } else {
	fprintf(stderr, "[*] Padlock engine not available\n");
	use_padlock_engine = 0;
    }

    SSL_load_error_strings();
    SSL_library_init();

    if (!RAND_poll())
	return NULL;

    ctx = SSL_CTX_new(SSLv23_server_method());

    if (!SSL_CTX_use_certificate_chain_file(ctx, certpath) ||
	    !SSL_CTX_use_PrivateKey_file(ctx, keypath, SSL_FILETYPE_PEM)) {
	fprintf(stderr, "Could not read %s or %s file\n", keypath, certpath);
	fprintf(stderr, "To generate a key and self-signed certificate, run:\n");
	fprintf(stderr, "\topenssl genrsa -out key.pem 2048\n");
	fprintf(stderr, "\topenssl req -new -key key.pem -out cert.req\n");
	fprintf(stderr, "\topenssl x509 -req -days 365 -in cert.req -signkey key.pem -out cert.pem\n");
	return NULL;
    }

    SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2);
    if (use_padlock_engine == 1) {
	if (SSL_CTX_set_cipher_list(ctx, "AES+SHA") != 1) {
	    fprintf(stderr, "Error setting client cipher list\n");
	    return NULL;
	}
    }
    return ctx;
}

static SSL_CTX * ssl_client_init(void)
{
    SSL_CTX *ctx = SSL_CTX_new(SSLv23_client_method());

    SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2);
    if (use_padlock_engine == 1) {
	if (SSL_CTX_set_cipher_list(ctx, "AES+SHA") != 1) {
	    fprintf(stderr, "Error setting client cipher list\n");
	    return NULL;
	}
    }
    return ctx;
}

static void close_client(struct conn_desc *conn)
{
    //SSL *ssl;

    DEBUG("closing client connection %d\n", conn->n);

    assert(conn->client_bev);
    assert(conn->status != CLIENT_CLOSED);

    // FIXME
    //ssl = bufferevent_openssl_get_ssl(conn->client_bev);
    //SSL_set_shutdown(ssl, SSL_RECEIVED_SHUTDOWN);
    //SSL_shutdown(ssl);

    bufferevent_free(conn->client_bev);
    conn->client_bev = NULL;
    conn->status = CLIENT_CLOSED;

    if (conn->client_username) {
	free(conn->client_username);
	conn->client_username = NULL;
    }
}

static void close_server(struct conn_desc *conn)
{
    //SSL *ssl;

    DEBUG("closing server connection %d\n", conn->n);

    assert(conn->server_bev);
    assert(conn->status != SERVER_CLOSED);

    //FIXME
    //ssl = bufferevent_openssl_get_ssl(conn->server_bev);
    //SSL_set_shutdown(ssl, SSL_RECEIVED_SHUTDOWN);
    //SSL_shutdown(ssl);

    bufferevent_free(conn->server_bev);
    conn->server_bev = NULL;
    conn->status = SERVER_CLOSED;

    if (conn->client_username) {
	free(conn->client_username);
	conn->client_username = NULL;
    }
}

static void close_connection(struct conn_desc *conn)
{
    close_client(conn);
    close_server(conn);
}

static void close_bev(struct bufferevent *bev, struct conn_desc *conn)
{
    if (IS_SERVER(bev, conn))
	close_server(conn);
    else
	close_client(conn);
}

static void drained_writecb(struct bufferevent *bev, void *arg)
{
    struct conn_desc *conn = arg;
    struct bufferevent *partner = PARTNER_BEV(bev, conn);

    assert(conn->status == SERVER_AUTHENTICATED);

    //DEBUG("write buffer is drained\n");
    /* We were choking the other side until we drained our outbuf a bit.
     * Now it seems drained. */
    bufferevent_setcb(bev, common_readcb, NULL, eventcb, conn);
    bufferevent_setwatermark(bev, EV_WRITE, 0, 0);
    if (partner) {
	//DEBUG("enabling read events on partner\n");
	bufferevent_enable(partner, EV_READ);
    }
}

static void close_on_finished_writecb(struct bufferevent *bev, void *arg)
{
    struct conn_desc *conn = arg;
    struct evbuffer *b = bufferevent_get_output(bev);

    if (evbuffer_get_length(b) == 0)
	close_bev(bev, conn);
}

static int timeval_subtract (result, x, y)
    struct timeval *result, *x, *y;
{
    /* Perform the carry for the later subtraction by updating y. */
    if (x->tv_usec < y->tv_usec) {
	int nsec = (y->tv_usec - x->tv_usec) / 1000000 + 1;
	y->tv_usec -= 1000000 * nsec;
	y->tv_sec += nsec;
    }
    if (x->tv_usec - y->tv_usec > 1000000) {
	int nsec = (x->tv_usec - y->tv_usec) / 1000000;
	y->tv_usec += 1000000 * nsec;
	y->tv_sec -= nsec;
    }

    /* Compute the time remaining to wait.
       tv_usec is certainly positive. */
    result->tv_sec = x->tv_sec - y->tv_sec;
    result->tv_usec = x->tv_usec - y->tv_usec;

    /* Return 1 if result is negative. */
    return x->tv_sec < y->tv_sec;
}

static void common_readcb(struct bufferevent *bev, void *arg)
{
    struct conn_desc *conn = arg;
    struct bufferevent *partner;
    struct evbuffer *src, *dst;
    size_t len;
    char *cmd;

    /* the two parts of the connection must be authenticated */
    assert(conn->status == SERVER_AUTHENTICATED);

    src = bufferevent_get_input(bev);
    len = evbuffer_get_length(src);

    partner = PARTNER_BEV(bev, conn);
    dst = bufferevent_get_output(partner);

    if (conn->client_bev == bev) {
	//DEBUG("client -> proxy: got %d bytes to read\n", len);
	if (conn->bytes != 0) {
	    struct timeval now;
	    struct timeval tdiff;
	    float sec_diff;
	    gettimeofday(&now, NULL);
	    timeval_subtract(&tdiff, &now, &conn->last_cmd);
	    sec_diff = tdiff.tv_sec + (tdiff.tv_usec / 1000000.0);
	    DEBUG("[%d] command finished, %d bytes transferred in %.2f seconds (%.2f kb/s)\n", conn->n, conn->bytes,
		    sec_diff, (conn->bytes * 1.0 / 1024 ) / sec_diff);
	}
	cmd = evbuffer_readln(src, NULL, EVBUFFER_EOL_CRLF);
	DEBUG("[%d] command from client: %s\n", conn->n, cmd);
	evbuffer_add_printf(dst, "%s\r\n", cmd);
	free(cmd);
	conn->bytes = 0;
	gettimeofday(&conn->last_cmd, NULL);
    } else {
	conn->bytes += len;
	evbuffer_add_buffer(dst, src);
    }

    len = evbuffer_get_length(dst);
    if (len >= MAX_OUTPUT) {
	/* We're giving the other side data faster than it can
	 * pass it on.  Stop reading here until we have drained the
	 * other side to MAX_OUTPUT/2 bytes. */
	//WARNING("[%d] Client not fast enough (%d bytes in write buffer of %p), disabling read callbacks\n",
	//	conn->n, len, partner);

	bufferevent_setcb(partner, common_readcb, drained_writecb, eventcb, conn);
	bufferevent_setwatermark(partner, EV_WRITE, MAX_OUTPUT/2, MAX_OUTPUT);
	bufferevent_disable(bev, EV_READ);
    }
}

static int authenticate(const char *username, const char *password)
{
    struct user_info *user;
    char *ret;

    user = users;
    while (user->username != NULL) {
	if (!strcmp(user->username, username)) {
	    ret = crypt(password, user->password);
	    if (!strcmp(ret, user->password)) {
		return 0;
	    }
	}
	user++;
    }
    return -1;
}

static int connect_to_server(struct conn_desc *conn)
{
    SSL *ssl;

    conn->status = SERVER_CONNECTING;
    ssl = SSL_new(ssl_client_ctx);
    assert(ssl);

    conn->server_bev = bufferevent_openssl_socket_new(base, -1, ssl,
	    BUFFEREVENT_SSL_CONNECTING,
	    BEV_OPT_CLOSE_ON_FREE|BEV_OPT_DEFER_CALLBACKS);
    if (!conn->server_bev) {
	perror("bufferevent_openssl_socket_new");
	return -1;
    }

    INFO("Connecting to %s port %d\n", server_hostname, server_port);

    if (bufferevent_socket_connect_hostname(conn->server_bev,
		dns_base, AF_UNSPEC, server_hostname, server_port)) {
	perror("bufferevent_socket_connect_hostname");
	return -1;
    }
    bufferevent_setcb(conn->server_bev, server_auth_readcb, NULL, eventcb, conn);
    bufferevent_enable(conn->server_bev, EV_READ|EV_WRITE);
    bufferevent_disable(conn->client_bev, EV_READ);

    return 0;
}

/* handles read event from client during the authentication process */
static void client_auth_readcb(struct bufferevent *bev, void *arg)
{
    struct conn_desc *conn = arg;
    struct evbuffer *src, *dst;
    size_t len;
    char *cmd;
    char *cmd_args[MAX_CMD_ARGS];
    int nargs;

    assert(conn->client_bev == bev);
    assert(conn->status == CLIENT_CONNECTED);

    src = bufferevent_get_input(bev);
    dst = bufferevent_get_output(bev);

    len = evbuffer_get_length(src);

    DEBUG("client -> proxy: got %d bytes to read\n", len);

    cmd = evbuffer_readln(src, NULL, EVBUFFER_EOL_CRLF);
    assert(cmd);
    DEBUG("cmd = %s\n", cmd);

    if (!strcasestr(cmd, "AUTHINFO")) {
	DEBUG("sending 480 Authentication required for command\n");
	evbuffer_add_printf(dst, "%d Authentication required for command\r\n",
		NNTP_AUTH_REQUIRED);
	goto exit;
    }

    parse_nntp_cmd(cmd, cmd_args, &nargs);
    if (nargs < 2) {
	WARNING("invalid command\n");
	goto exit;
    }

    DEBUG("cmd_args = %s %s\n", cmd_args[1], cmd_args[2]);

    if (!strcasecmp("USER", cmd_args[1])) {
	char *username = cmd_args[2];
	if (allow_connection(username) == -1) {
	    WARNING("Too many connections for username %s\n", username);
	    evbuffer_add_printf(dst, "%d Too many connections\r\n",
		    NNTP_NO_PERM);
	    close_client(conn);
	    goto exit;
	}

	conn->client_username = strdup(username);
	DEBUG("username = %s\n", username);
	evbuffer_add_printf(dst, "%d PASS required\r\n", NNTP_MORE_AUTH);
    } else if (!strcasecmp("PASS", cmd_args[1])) {
	if (!conn->client_username) {
	    evbuffer_add_printf(dst, "%d Authentication required for command\r\n",
		    NNTP_AUTH_REQUIRED);
	    goto exit;
	}

	if (authenticate(conn->client_username, cmd_args[2]) == -1) {
	    WARNING("Authentication failed for username %s\n", conn->client_username);
	    evbuffer_add_printf(dst, "%d Wrong username or password\r\n",
		    NNTP_AUTH_REJECTED);
	    goto exit;
	}

	DEBUG("client is authenticated\n");
	conn->status = CLIENT_AUTHENTICATED;

	evbuffer_add_printf(dst, "%d OK\r\n", NNTP_AUTH_ACCEPTED);
	if (connect_to_server(conn) == -1) {
	    ERROR("cannot connect to server, closing connection ...\n");
	    close_connection(conn);
	}
    } else {
	WARNING("invalid AUTHINFO command\n");
	evbuffer_add_printf(dst, "%d Authentication required for command\r\n",
		NNTP_AUTH_REQUIRED);
    }
exit:
    free(cmd);
}

/* handles read event from server during the authentication process */
static void server_auth_readcb(struct bufferevent *bev, void *arg)
{
    struct conn_desc *conn = arg;
    struct evbuffer *src, *dst;
    size_t len;
    char *resp, *msg;
    int code;


    assert(conn->server_bev == bev);
    assert(conn->status == SERVER_CONNECTED);

    src = bufferevent_get_input(bev);
    dst = bufferevent_get_output(bev);

    len = evbuffer_get_length(src);

    DEBUG("server -> proxy: got %d bytes to read\n", len);

    resp = evbuffer_readln(src, NULL, EVBUFFER_EOL_CRLF);
    assert(resp);

    msg = parse_nntp_response(resp, &code);
    if (!msg) {
	WARNING("invalid response\n");
	return;
    }
    DEBUG("code = %d, msg = %s\n", code, msg);

    if (code == NNTP_AUTH_REQUIRED) {
	evbuffer_add_printf(dst, "AUTHINFO USER %s\r\n", SERVER_USER);
    } else if (code == NNTP_MORE_AUTH) {
	evbuffer_add_printf(dst, "AUTHINFO PASS %s\r\n", SERVER_PASS);
    } else if (code == NNTP_AUTH_ACCEPTED) {
	DEBUG("got authentication from server\n");
	conn->status = SERVER_AUTHENTICATED;

	bufferevent_setcb(conn->server_bev, common_readcb, NULL, eventcb, conn);
	bufferevent_setcb(conn->client_bev, common_readcb, NULL, eventcb, conn);
	bufferevent_enable(conn->client_bev, EV_READ);
    } else if (code == NNTP_SERVICE_READY) {
	/* Banner from server */
	evbuffer_add_printf(dst, "AUTHINFO USER %s\r\n", SERVER_USER);
    }

    free(resp);
}

static void print_openssl_err(struct bufferevent *bev)
{
    unsigned long err;
    while ((err = (bufferevent_get_openssl_error(bev)))) {
	const char *msg = (const char*)
	    ERR_reason_error_string(err);
	const char *lib = (const char*)
	    ERR_lib_error_string(err);
	const char *func = (const char*)
	    ERR_func_error_string(err);
	fprintf(stderr,
		"%s in %s %s\n", msg, lib, func);
    }
}

static void eventcb(struct bufferevent *bev, short what, void *ctx)
{
    struct conn_desc *conn = ctx;
    struct bufferevent *partner;
    struct evbuffer *dst;
    int err;

    if (IS_SERVER(bev, conn)) {
	DEBUG("event received for server connection\n");
    } else {
	DEBUG("event received for client connection\n");
    }

    partner = PARTNER_BEV(bev, conn);

    if (what & BEV_EVENT_READING)
	DEBUG("BEV_EVENT_READING\n");
    if (what & BEV_EVENT_WRITING)
	DEBUG("BEV_EVENT_WRITING\n");
    if (what & BEV_EVENT_ERROR)
	DEBUG("BEV_EVENT_ERROR\n");
    if (what & BEV_EVENT_TIMEOUT)
	DEBUG("BEV_EVENT_TIMEOUT\n");
    if (what & BEV_EVENT_EOF)
	DEBUG("BEV_EVENT_EOF\n");
    if (what & BEV_EVENT_CONNECTED)
	DEBUG("BEV_EVENT_CONNECTED\n");

    /* TODO : clean this */
    if (what & (BEV_EVENT_EOF|BEV_EVENT_ERROR)) {
	if (what & BEV_EVENT_ERROR) {
	    print_openssl_err(bev);

	    ERROR("Error: %s\n", evutil_socket_error_to_string(EVUTIL_SOCKET_ERROR()));

	    err = bufferevent_socket_get_dns_error(bev);
	    if (err)
		ERROR("DNS error: %s\n", evutil_gai_strerror(err));
	}

	if (partner) {
	    size_t len;
	    /* Flush all pending data */
	    len = evbuffer_get_length(bufferevent_get_input(bev));
	    if (len) {
		DEBUG("Flushing pending data: %d\n", len);
		common_readcb(bev, ctx);
	    }

	    len = evbuffer_get_length(bufferevent_get_output(partner));
	    if (len) {
		/* We still have to flush data from the other
		 * side, but when that's done, close the other
		 * side. */
		bufferevent_setcb(partner, NULL, close_on_finished_writecb,
			eventcb, conn);
		bufferevent_disable(partner, EV_READ);
	    } else {
		/* We have nothing left to say to the other
		 * side; close it. */
		close_bev(partner, conn);
	    }
	}

	close_bev(bev, conn);
    } else if (what & BEV_EVENT_CONNECTED) {
	if (bev == conn->client_bev) {
	    DEBUG("client connected, sending banner to client\n");
	    conn->status = CLIENT_CONNECTED;
	    dst = bufferevent_get_output(bev);
	    evbuffer_add_printf(dst, "%d %s\r\n", NNTP_SERVICE_READY, NNTP_BANNER);
	    //bufferevent_setcb(bev, client_auth_readcb, NULL, eventcb, conn);
	    //bufferevent_enable(bev, EV_READ);
	} else {
	    DEBUG("connected to server, waiting for banner\n");
	    conn->status = SERVER_CONNECTED;
	}
    }
}

static void ssl_accept_cb(struct evconnlistener *listener, evutil_socket_t sock,
	struct sockaddr *sa, int sa_len, void *arg)
{
    SSL *ssl;
    struct conn_desc *conn;

    INFO("new connection from %s\n", ip_str_from_sa(sa));

    conn = get_next_conn();
    if (!conn) {
	ERROR("no more available connections\n");
	goto err;
    }

    conn->status = CLIENT_CONNECTING;
    assert(conn->client_username == NULL);

    ssl = SSL_new(ssl_server_ctx);
    if (!ssl) {
	fprintf(stderr, "Error creating SSL server side\n");
	goto err;
    }

    conn->client_bev = bufferevent_openssl_socket_new(base, sock, ssl, 
	    BUFFEREVENT_SSL_ACCEPTING,
	    BEV_OPT_CLOSE_ON_FREE|BEV_OPT_DEFER_CALLBACKS);
    if (!conn->client_bev) {
	perror("bufferevent_openssl_socket_new");
	goto err;
    }
    conn->server_bev = NULL;

    bufferevent_setcb(conn->client_bev, client_auth_readcb, NULL, eventcb, conn);
    bufferevent_enable(conn->client_bev, EV_READ|EV_WRITE);

    return;
err:
    if (conn && conn->client_bev) {
	bufferevent_free(conn->client_bev);
	conn->client_bev = NULL;
    }
    evutil_closesocket(sock);
}

int main(int argc, char **argv)
{
    char *tmp;
    int socklen;
    struct evconnlistener *listener = NULL;

    if (argc != 5)
	syntax(argv[0]);

    verbose_level = DEBUG_LEVEL;

    INFO("Starting proxy ...\n"); 

    ssl_server_ctx = ssl_server_init(argv[1], argv[2]);
    if (!ssl_server_ctx) {
	fprintf(stderr, "SSL server init failed\n");
	exit(EXIT_FAILURE);
    }

    DEBUG("SSL server context initialized: %p\n", ssl_server_ctx);

    ssl_client_ctx = ssl_client_init();
    if (!ssl_client_ctx) {
	fprintf(stderr, "SSL client init failed\n");
	exit(EXIT_FAILURE);
    }

    DEBUG("SSL client context initialized: %p\n", ssl_client_ctx);

    memset(&listen_on_addr, 0, sizeof(listen_on_addr));
    socklen = sizeof(listen_on_addr);

    if (evutil_parse_sockaddr_port(argv[3],
		(struct sockaddr *) &listen_on_addr, &socklen) < 0) {
	syntax(argv[0]);
    }

    tmp = strtok(argv[4], ":");
    if (!tmp) {
	syntax(argv[0]);
	exit(EXIT_FAILURE);
    }
    server_hostname = tmp;
    tmp = strtok(NULL, ":");
    if (!tmp) {
	syntax(argv[0]);
	exit(EXIT_FAILURE);
    }
    server_port = atoi(tmp);

    connections = calloc(MAX_CONNS, sizeof(struct conn_desc));
    if (!connections) {
	perror("calloc");
	exit(EXIT_FAILURE);
    }

    base = event_base_new();
    if (!base) {
	perror("event_base_new()");
	exit(EXIT_FAILURE);
    }
    dns_base = evdns_base_new(base, 1);
    if (!dns_base) {
	perror("evdns_base_new()");
	exit(EXIT_FAILURE);
    }

    listener = evconnlistener_new_bind(base, ssl_accept_cb, NULL,
	    LEV_OPT_CLOSE_ON_FREE|LEV_OPT_REUSEABLE,
	    -1, (struct sockaddr *) &listen_on_addr, sizeof(listen_on_addr));

    if (!listener) {
	perror("evconnlistener_new_bind");
	exit(EXIT_FAILURE);
    }

    DEBUG("Listener initialized (%p), starting dispatching events\n", listener);

    event_base_dispatch(base);

    INFO("Closing proxy ...\n");

    evconnlistener_free(listener);
    event_base_free(base);
    evdns_base_free(dns_base, 1);

    exit(EXIT_SUCCESS);
}
