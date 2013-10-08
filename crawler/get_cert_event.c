
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <event.h>
#include <event2/bufferevent_ssl.h>

#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <ulimit.h>
#include <openssl/ssl.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <pthread.h>

#include <openssl/crypto.h>

#include <openssl/ssl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <string.h>
#include <fcntl.h>

pthread_mutex_t * ssl_locks;
int ssl_num_locks;

/* Implements a thread-ID function as requied by openssl */
static unsigned long
get_thread_id_cb(void)
{
    return (unsigned long)pthread_self();
}

static void
thread_lock_cb(int mode, int which, const char * f, int l)
{
    if (which < ssl_num_locks) {
        if (mode & CRYPTO_LOCK) {
            pthread_mutex_lock(&(ssl_locks[which]));
        } else {
            pthread_mutex_unlock(&(ssl_locks[which]));
        }
    }
}

int
init_ssl_locking(void)
{
    int i;

    ssl_num_locks = CRYPTO_num_locks();
    ssl_locks = malloc(ssl_num_locks * sizeof(pthread_mutex_t));
    if (ssl_locks == NULL)
        return -1;

    for (i = 0; i < ssl_num_locks; i++) {
        pthread_mutex_init(&(ssl_locks[i]), NULL);
    }

    CRYPTO_set_id_callback(get_thread_id_cb);
    CRYPTO_set_locking_callback(thread_lock_cb);

    return 0;
}

struct config {
	uint16_t port;
	int connect_timeout;	// how long to wait for connecting (seconds)
	int current_running;
	int max_concurrent;
	struct event_base *base;
	struct bufferevent *stdin_bev;
	int stdin_closed;

	struct stats_st {
		uint64_t hosts_tried;
		uint64_t certs_gathered;
	} stats;
};


struct state {
	struct config *conf;
	uint32_t ip;
	char *ip_str;
	SSL *ssl;
	SSL_CTX *ctx;
	enum {CONNECTING, TLS, DONE} state;
};
int verify(int v, X509_STORE_CTX *c)
{
	(void) v;
	(void) c;
	return 1;
}
struct event *status_timer;
char cafile[4096];
void stdin_readcb(struct bufferevent *bev, void *ptr);
void print_status(evutil_socket_t fd, short events, void *arg)
{
	struct config *conf = arg;
	printf("STATUS: (%d/%d) used %llu connection attempts %llu certs gathered\n",
			conf->current_running, conf->max_concurrent,
			conf->stats.hosts_tried,
			conf->stats.certs_gathered);
	struct timeval status_timeout = {5, 0};
	evtimer_add(status_timer, &status_timeout);
}
void decrement_cur_running(struct state *st)
{
	struct config *conf = st->conf;
	free(st->ip_str);
	SSL_CTX_free(st->ctx);
	free(st);
	conf->current_running--;

	if (evbuffer_get_length(bufferevent_get_input(conf->stdin_bev)) > 0) {
		stdin_readcb(conf->stdin_bev, conf);
	}
	if (conf->stdin_closed && conf->current_running == 0) {
		print_status(0, 0, conf);
		exit(0);
	}
}
void sslconnect_cb(struct bufferevent *bev, short events, void *arg)
{
	struct state *st = arg;
	struct timeval timeout = {st->conf->connect_timeout, 0};
	if (events & BEV_EVENT_CONNECTED) {
		SSL *ssl = st->ssl;
		X509 *cert = SSL_get_peer_certificate(ssl);
		FILE *fp = fopen(st->ip_str,"w");
		PEM_write_X509(fp, cert);
		st->conf->stats.certs_gathered++;
		fclose(fp);
	} else {
	}
	bufferevent_free(bev);
	decrement_cur_running(st);
}
void grab_cert(struct state *st)
{
	struct timeval timeout = {st->conf->connect_timeout, 0};
	struct sockaddr_in addr;
	struct bufferevent *bev;

	addr.sin_family = AF_INET;
	addr.sin_port = htons(st->conf->port);
	addr.sin_addr.s_addr = st->ip;
	st->state = CONNECTING;


	SSL_CTX *ctx;
	if (!(ctx = SSL_CTX_new(SSLv23_client_method()))){
		fprintf(stderr, "Error setting up SSL context");
	}

	if (SSL_CTX_load_verify_locations(ctx, cafile, NULL) != 1) {
		fprintf(stderr, "Error loading trusted certs from %s\n", cafile);
	}
	SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, verify);
	SSL_CTX_set_timeout (ctx, 1);
	SSL *ssl = SSL_new(ctx);
	st->ssl = ssl;
	st->ctx = ctx;

	bev = bufferevent_openssl_socket_new(st->conf->base, -1,
			ssl, BUFFEREVENT_SSL_CONNECTING,
			BEV_OPT_CLOSE_ON_FREE);

	bufferevent_set_timeouts(bev, &timeout, &timeout);
	bufferevent_setcb(bev, NULL, NULL, sslconnect_cb, st);

	st->conf->stats.hosts_tried++;
	if (bufferevent_socket_connect(bev,
				(struct socaddr *)&addr,
				sizeof(addr)) < 0) {
		bufferevent_free(bev);
		decrement_cur_running(st);
	}

}

void stdin_readcb(struct bufferevent *bev, void *ptr)
{
	struct evbuffer *input = bufferevent_get_input(bev);
	struct config *conf = ptr;
	struct state *st;
	while (conf->current_running < conf->max_concurrent && evbuffer_get_length(input) > 0) {
		char *ip_str;
		size_t line_length;
		ip_str = evbuffer_readln(input, &line_length, EVBUFFER_EOL_LF);
		if (!ip_str) {
			break;
		}
		conf->current_running++;
		st = malloc(sizeof(*st));
		st->ip_str = malloc(strlen(ip_str)+1);
		strncpy(st->ip_str, ip_str, strlen(ip_str)+1);
		st->conf = conf;
		st->ip = inet_addr(ip_str);
		grab_cert(st);
	}

}

void stdin_eventcb(struct bufferevent *bev, short events, void *ptr)
{
	struct config *conf = ptr;
	if (events & BEV_EVENT_EOF) {
		conf->stdin_closed = 1;
		if (conf->current_running == 0) {
			print_status(0, 0, conf);
			exit(0);
		}
	}
}

int main(int argc, char *argv[])
{
	struct event_base *base;
	struct timeval status_timeout = {5, 0};
	int c;
	struct option long_options[] = {
		{"concurrent", required_argument, 0, 'c'},
		{"port", required_argument, 0, 'p'},
		{"conn-timeout", required_argument, 0, 't'},
		{"ca", required_argument, 0, 'f'},
		{0, 0, 0, 0} };

	struct config conf;
	int ret;
	FILE *fp;
	SSL_load_error_strings();
	SSL_library_init();
	init_ssl_locking();

	ret = ulimit(4, 1000000);	// Allow us to open 1 million fds (instead of 1024)
	if (ret < 0) {
		perror("ulimit");
		exit(1);
	}

	base = event_base_new();
	conf.base = base;

	// buffer stdin as an event
	conf.stdin_bev = bufferevent_socket_new(base, 0, BEV_OPT_DEFER_CALLBACKS);
	bufferevent_setcb(conf.stdin_bev, stdin_readcb, NULL, stdin_eventcb, &conf);
	bufferevent_enable(conf.stdin_bev, EV_READ);

	// Status timer
	status_timer = evtimer_new(base, print_status, &conf);
	evtimer_add(status_timer, &status_timeout);

	// Defaults
	conf.max_concurrent = 1;
	conf.current_running = 0;
	memset(&conf.stats, 0, sizeof(conf.stats));
	conf.connect_timeout = 4;
	conf.stdin_closed = 0;

	// Parse command line args
	while (1) {
		int option_index = 0;
		c = getopt_long(argc, argv, "c:p:t:f:",
				long_options, &option_index);

		if (c < 0) {
			break;
		}

		switch (c) {
		case 'c':
			conf.max_concurrent = atoi(optarg);
			break;
		case 'p':
			conf.port = atoi(optarg);
			break;
		case 't':
			conf.connect_timeout = atoi(optarg);
			break;
		case 'f':
			strncpy(cafile, optarg, sizeof(cafile));
			break;
		case '?':
			printf("Usage:\n");
			printf("\t%s [-c max_concurrency] [-t connect_timeout] "
				   "[-f cafile] -p port\n", argv[0]);
			exit(1);
		default:
			break;
		}
	}
	event_base_dispatch(base);

	return 0;
}
