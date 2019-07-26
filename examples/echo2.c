#ifndef _XOPEN_SOURCE
#define _XOPEN_SOURCE 700 /* required for glibc to use getaddrinfo, etc. */
#endif
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <stdio.h>
#include <stdarg.h>
#include <sys/types.h>
#include <string.h>
#include <stdlib.h>
#include "../quic.h"
#ifdef _WINDOWS
#include <ws2tcpip.h>
typedef HANDLE pthread_t;
#else
#include <pthread.h>
#include <netdb.h>
#include <sys/select.h>
#include <unistd.h>
#include <sys/socket.h>
#endif
static void PANIC(const char* format, ...)
{
    va_list argv;
    va_start(argv, format);
    vfprintf(stderr, format, argv);
    va_end(argv);
    exit(-1);
}
static int _isServer = 0;
quiconn_t _conns[256];
static int is_server(void) { return _isServer; }
static int resolve_address(struct sockaddr *sa, socklen_t *salen, const char *host,
    const char *port, int family, int type, int proto)
{
    struct addrinfo hints, *res;
    int err;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = family;
    hints.ai_socktype = type;
    hints.ai_protocol = proto;
    hints.ai_flags = AI_ADDRCONFIG | AI_NUMERICSERV | AI_PASSIVE;
    if ((err = getaddrinfo(host, port, &hints, &res)) != 0 || res == NULL) {
        fprintf(stderr, "failed to resolve address:%s:%s:%s\n", host, port,
            err != 0 ? gai_strerror(err) : "getaddrinfo returned NULL");
        return -1;
    }

    memcpy(sa, res->ai_addr, res->ai_addrlen);
    *salen = res->ai_addrlen;

    freeaddrinfo(res);
    return 0;
}

static void usage(const char *progname)
{
    printf("Usage: %s [options] [host]\n"
        "Options:\n"
        "  -C <cid-key>             CID encryption key (server-only). Randomly generated\n"
        "                           if omitted.\n"
        "  -c <file>                specifies the certificate chain file (PEM format)\n"
        "  -k <file>                specifies the private key file (PEM format)\n"
        "  -s session-file          file to load / store the session ticket\n"
        "  -p <number>              specifies the port number (default: 4433)\n"
        "  -E event-log-file        file to log events\n"
        "  -e log-file              file to log traffic secrets\n"
        "  -h                       prints this help\n"
        "\n"
        "When both `-c` and `-k` is specified, runs as a server.  Otherwise, runs as a\n"
        "client connecting to host:port.  If omitted, host defaults to 127.0.0.1.\n",
        progname);
    exit(0);
}

static void process_msg(const struct sockaddr_storage* addr, char* buf, size_t len)
{
    size_t off;
    quicstm_t strmId[1024];
    quicbuf_t data[1024];
    int packet_len,i;

    /* split UDP datagram into multiple QUIC packets */
    for (off = 0; off < len; off += packet_len) {
        quicpkt_t decoded;
        data[0].base = buf + off;
        data[0].len  = len - off;
        packet_len = quic_decode(&decoded, data);
        if (packet_len <= 0)
            return;
        /* find the corresponding connection (TODO handle version negotiation, rebinding, retry, etc.) */
        for (i = 0; _conns[i] != 0; ++i)
            if (quic_is_target(_conns[i], &decoded, addr))
                break;
        if (_conns[i] != 0) /* let the current connection handle ingress packets */
            quic_receive(_conns[i], &decoded);
        else if (is_server()) /* assume that the packet is a new connection */
            _conns[i] = quic_accept(addr, &decoded);
        else
            continue;

        quiconn_t conndId = _conns[i];
        int ret = quic_fetch (conndId, strmId, data);
        for (i=0;i<ret;++i) {
            if (is_server()) {
                printf("[%d:%llu]:%-.*s", conndId, strmId[i], (int)data[i].len, data[i].base);
                quic_write(conndId, strmId[i], &data[i]);
            }
            else {
                /* client: print to stdout */
                fwrite(data[i].base, 1, data[i].len, stdout);
                fflush(stdout);
            }
            quic_shift(conndId, strmId[i], data[i].len);
        }
    }
}
static socklen_t socklen(const struct sockaddr_storage* addr)
{
    switch (addr->ss_family) {
    case AF_INET:
        return sizeof(struct sockaddr_in);
    case AF_INET6:
        return sizeof(struct sockaddr_in6);
    default:
        return 0;
    }
}
static int send_one(int fd, void *buf, int num, struct sockaddr_storage *sa)
{
    int ret;
    while ((ret = (int)sendto(fd, buf, num, 0, (struct sockaddr*)sa, socklen(sa))) == -1 && errno == EINTR)
        ;
    return ret;
}

/* read stdin, send the input to the active stream 0 */
static void* forward_stdin(void* p)
{
    char buf[4096];

    while (_conns[0]) {
        char* ret = fgets(buf, sizeof(buf), stdin);
        if (ret) { /* write data to send buffer */
            quicbuf_t cbuf = { buf, strlen(ret) };
            quic_write(_conns[0], 0, &cbuf);
        }
    }
    return NULL;
}

static void run_loop(int fd)
{
    size_t i;
    while (1) {
        /* wait for sockets to become readable, or some event in the QUIC stack to fire */
        fd_set readfds;
        struct timeval tv;
        do {
            int64_t delta = quic_timeout(_conns, 256);
            tv.tv_sec = delta / 1000;
            tv.tv_usec = (delta % 1000) * 1000;

            FD_ZERO(&readfds);
            FD_SET(fd, &readfds);
        } while (select(fd + 1, &readfds, NULL, NULL, &tv) == -1 && errno == EINTR);

        /* read the QUIC fd */
        if (FD_ISSET(fd, &readfds)) {
            char buf[1500];
            struct sockaddr_storage sa;
            socklen_t salen = sizeof(sa);
            int ret = recvfrom(fd, buf, sizeof(buf), 0, (struct sockaddr*)&sa, &salen);
            if (ret > 0) process_msg(&sa, buf, ret);
        }
        /* send QUIC packets, if any */
        for (i = 0; _conns[i] != 0; ++i) {
            quicbuf_t vbuf[256];
            struct sockaddr_storage addr;
            int ret = quic_encode(_conns[i], vbuf, &addr);
            if (ret < 0) {
                if (!is_server()) return;
                printf("[%d] closed\n", _conns[i]);
                memmove(_conns + i, _conns + i + 1, sizeof(_conns) - sizeof(_conns[0]) * (i + 1));
                --i;
            }
            else if (ret > 0) {
                for (int j=0;j<ret;++j)
                    send_one(fd, vbuf[j].base, vbuf[j].len, &addr);
            }
        }
    }
}
/* resolve command line options and arguments */
static void parse(int argc, char **argv, char** host, char** port, quicarg_t *quic_arg)
{
    int ch;
    *host = "127.0.0.1", *port = "4433";
    memset(quic_arg, 0, sizeof(*quic_arg));
    while ((ch = getopt(argc, argv, "C:c:k:p:E:e:t:hs")) != -1) {
        switch (ch) {
        case 'C': quic_arg->cid_key = optarg; break;
        case 'c': quic_arg->cert_pem_file = optarg; break; /* load certificate chain */
        case 'k': quic_arg->key_pem_file = optarg; break; /* load private key */
        case 't': quic_arg->ticket_file = optarg; break;
        case 'p': *port = optarg; break; /* port */
        case 's': _isServer = 1; break;
        case 'h': usage(argv[0]); break; /* help */
        case 'e':
            quic_arg->secret_log = fopen(optarg, "w+"); 
            break;
        case 'E':
            quic_arg->event_log = fopen(optarg, "w+"); 
            quic_arg->event_mask = UINT64_MAX;
            break;
        default: exit(1);
        }
    }
    argc -= optind;
    argv += optind;
    if (argc != 0) *host = *argv++;
}
int main(int argc, char **argv)
{
    char *host;
    struct sockaddr_storage sa;
    socklen_t salen;
#ifdef _WINDOWS
    WSADATA wsd;
    WSAStartup(MAKEWORD(2, 2), &wsd);
#endif
    {
        char *port;
        quicarg_t quic_arg;
        parse(argc, argv,  &host, &port, &quic_arg);
        if (resolve_address((struct sockaddr *)&sa, &salen, host, port, AF_INET, SOCK_DGRAM, 0) != 0)
            exit(1);
        if (quic_init(&quic_arg) < 0)
            PANIC("quic_init:%d\n", errno);
    }

    int fd;
    pthread_t thread;
    /* open socket, on the specified port (as a server), or on any port (as a client) */
    if ((fd = socket(sa.ss_family, SOCK_DGRAM, IPPROTO_UDP)) == -1) 
        PANIC("socket(2):%s\n",strerror(errno));

    if (is_server()) {
        int reuseaddr = 1;
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (char*)&reuseaddr, sizeof(reuseaddr));
        if (bind(fd, (struct sockaddr *)&sa, salen) != 0)
            PANIC("bind(2):%s\n", strerror(errno));
    }
    else {
        /* initiate a connection, and open a stream */
        _conns[0] = quic_connect(&sa, host);
        if (!_conns[0])
            PANIC("quicly_connect:%d\n", errno);

        if (quic_open(_conns[0], 0) != 0)
            PANIC("first stream must 0\n");
#ifdef _WINDOWS
        thread = (pthread_t)_beginthreadex (NULL, 0, forward_stdin, NULL, 0 , NULL);
#else
        pthread_create (&thread, NULL, forward_stdin, NULL);
#endif
    }
    run_loop(fd);
    if (!is_server()) {
        _conns[0] = 0;
        printf("Press Enter to exit!\n");
#if defined _WIN32
        WaitForSingleObject(thread, INFINITE);
#else
        pthread_join(thread, NULL);
#endif
    }
    return 0;
}
