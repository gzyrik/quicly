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
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>
#include <sys/select.h>
#include <unistd.h>
#include <sys/socket.h>
#define closesocket(s) close(s)
#ifndef INADDR_LOOPBACK
#define INADDR_LOOPBACK  0x7f000001
#endif
#endif
static void PANIC(const char* format, ...)
{
    va_list argv;
    va_start(argv, format);
    vfprintf(stderr, format, argv);
    va_end(argv);
    exit(-1);
}
static int _port = 4433;
static int _isServer = 0;
static int _logLevel = 0;
quiconn_t _conns[256];
static int is_server(void) { return _isServer; }
static int is_server_addr(const struct sockaddr_storage* addr) {
    struct sockaddr_in*v4 = (struct sockaddr_in*)addr;
    struct sockaddr_in6*v6 = (struct sockaddr_in6*)addr;
    switch (addr->ss_family) {
    case AF_INET:
        return (ntohl(v4->sin_addr.s_addr) >> 24) != 127 || ntohs(v4->sin_port) == _port;
    case AF_INET6:
        return memcmp(&v6->sin6_addr, &in6addr_loopback, sizeof(in6addr_loopback)) != 0 || ntohs(v6->sin6_port) == _port;
    }
    return 0;
}
static void usage(const char *progname)
{
    printf("Usage: %s [options] [host]\n"
        "Options:\n"
        "  -R                       require Retry (server only)\n"
        "  -C <cid-key>             CID encryption key (server-only). Randomly generated\n"
        "                           if omitted.\n"
        "  -c certificate-file\n"
        "  -k key-file              specifies the credentials to be used for running the\n"
        "                           server. If omitted, the command runs as a client.\n"
        "  -V                       verify peer using the default certificates\n"
        "  -s session-file          file to load / store the session ticket\n"
        "  -p <number>              specifies the port number (default: 4433)\n"
        "  -E event-log-file        file to log events\n"
        "  -e log-file              file to log traffic secrets\n"
        "  -L <number>              log level\n"
        "  -6                       using IPV6\n"
        "  -h                       prints this help\n"
        "\n"
        "When both `-c` and `-k` is specified, runs as a server.  Otherwise, runs as a\n"
        "client connecting to host:port.  If omitted, host defaults to 127.0.0.1.\n",
        progname);
    exit(0);
}
static socklen_t socklen(const void* p)
{
    const struct sockaddr* addr = (const struct sockaddr*)p;
    switch (addr->sa_family) {
    case AF_INET:
        return sizeof(struct sockaddr_in);
    case AF_INET6:
        return sizeof(struct sockaddr_in6);
    default:
        return 0;
    }
}
static int send_one(int fd, void *buf, int num,  const void*sa)
{
    int ret;
    if (num <= 0) return 0;
    while ((ret = (int)sendto(fd, (const char *)buf, num,
        0, (const struct sockaddr*)sa, socklen(sa))) == -1 && errno == EINTR)
        ;
    return ret;
}
static int addr_str(struct sockaddr* addr, char buf[], size_t buflen)
{
    int port = 0;
    void* in_addr;
    if (addr->sa_family == AF_INET) {
        struct sockaddr_in* ipv4 = (struct sockaddr_in*)addr;
        in_addr = &ipv4->sin_addr;
        port = ntohs(ipv4->sin_port);
    }
    else if (addr->sa_family == AF_INET6) {
        struct sockaddr_in6* ipv6 = (struct sockaddr_in6*)addr;
        in_addr = &ipv6->sin6_addr;
        port = ntohs(ipv6->sin6_port);
    }
    else
        PANIC("invalid ss_family\n");

    inet_ntop(addr->sa_family, in_addr, buf, buflen);
    return port;
}
static void process_msg(int fd, struct sockaddr* addr, char* buf, size_t len)
{
    size_t off;
    quiconn_t conndId;
    quicstm_t strmId[1024];
    quicbuf_t data[1024];
    int packet_len,i, ret;

    if (_logLevel > 8) {
        char buf[128];
        int port = addr_str(addr, buf, sizeof(buf));
        printf("<%s:%d %d bytes\n", buf, port, (int)len);
    }
    /* split UDP datagram into multiple QUIC packets */
    for (off = 0; off < len; off += packet_len) {
        quicpkt_t decoded;
        data[0].base = buf + off;
        data[0].len  = len - off;
        packet_len = quic_decode(&decoded, &data[0], addr);
        if (packet_len <= 0){
            send_one(fd, data[0].base, data[0].len, addr);
            return;
        }
        /* find the corresponding connection (TODO handle version negotiation, rebinding, retry, etc.) */
        for (i = 0; _conns[i] != 0; ++i) {
            if (quic_is_target(_conns[i], &decoded, addr))
                break;
        }
        if (_conns[i] != 0) {/* let the current connection handle ingress packets */
            quic_received(_conns[i], &decoded);
        }
        else if (is_server()) {/* assume that the packet is a new connection */
            _conns[i] = quic_accept(addr, &decoded, &data[0]);
            if (!_conns[i]) {
                send_one(fd, data[0].base, data[0].len, addr);
                continue;
            }
        }
        else {
            printf("** WARN: unknown pkt\n");
            continue;
        }
        conndId = _conns[i];
        if (_logLevel > 8) printf("[%d]< %d bytes\n", conndId, (int)packet_len);
        ret = quic_ingress_fetch (conndId, strmId, data);
        for (i=0;i<ret;++i) {
            if (is_server()) {
                printf("[%d]%llu:%-.*s", conndId, strmId[i], (int)data[i].len, data[i].base);
                quic_egress_write(conndId, strmId[i], &data[i]);
                quic_egress_shutdown(conndId, strmId[i]);
            }
            else {
                /* client: print to stdout */
                fwrite(data[i].base, 1, data[i].len, stdout);
                fflush(stdout);
                if (quic_ingress_states(conndId, strmId[i])&QUIC_INGRESS_FINAL)
                    quic_close(conndId, 0);
            }
            quic_ingress_shift(conndId, strmId[i], data[i].len);
        }
    }
}
/* read stdin, send the input to the active stream 0 */
static void* forward_stdin(void* p)
{
    int fd;
    char buf[4096];
    struct sockaddr* addr = (struct sockaddr*)p;
    int port = addr_str(addr, buf, sizeof(buf));
    printf("local addr is %s:%d\n", buf, port);

    if ((fd = socket(addr->sa_family, SOCK_DGRAM, IPPROTO_UDP)) == -1)
        PANIC("socket(2):%s\n", strerror(errno));
    while (_conns[0]) {
        char* ret = fgets(buf, sizeof(buf), stdin);
        /* write data to send buffer */
        if (ret) send_one(fd, buf, strlen(ret), p);
    }
    closesocket(fd);
    return NULL;
}

static void run_loop(int fd)
{
    int ret;
    size_t i;
    while (1) {
        /* wait for sockets to become readable, or some event in the QUIC stack to fire */
        fd_set readfds;
        struct timeval tv;
        do {
            int64_t delta = quic_timeout_ms(_conns, 256);
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
            if ((ret = recvfrom(fd, buf, sizeof(buf), 0, (struct sockaddr*)&sa, &salen)) > 0) {
                if (is_server() || is_server_addr(&sa))
                    process_msg(fd, (struct sockaddr*)&sa, buf, ret);
                else {/* read from stdin */
                    quicbuf_t cbuf = {buf, ret};
                    quic_egress_write(_conns[0], 0, &cbuf);
                }
            }
        }
        /* send QUIC packets, if any */
        for (i = 0; _conns[i] != 0; ++i) {
            quicbuf_t vbuf[256];
            struct sockaddr_storage addr;
            if ((ret = quic_encode(_conns[i], vbuf, &addr)) < 0) {
                printf("[%d] closed\n", _conns[i]);
                if (!is_server()) return;
                memmove(_conns + i, _conns + i + 1, sizeof(_conns) - sizeof(_conns[0]) * (i + 1));
                --i;
            }
            else if (ret > 0) {
                if (_logLevel > 8) {
                    char buf[128];
                    int port = addr_str((struct sockaddr*)&addr, buf, sizeof(buf));
                    printf("[%d]>%s:%d %d pkts\n", _conns[i], buf, port, ret);
                }
                for (int j=0;j<ret;++j)
                    send_one(fd, vbuf[j].base, vbuf[j].len, &addr);
            }
        }
    }
}
static FILE* open_log_file(const char* file)
{
    if (!strcmp(file, "stderr"))
        return stderr;
    else if (!strcmp(file, "stdout"))
        return stdout;
    return fopen(file, "w+");
}
/* resolve command line options and arguments */
static const char* parse(int argc, char **argv, struct sockaddr_storage* sa, quicarg_t *quic_arg)
{
    int ch;
    memset(quic_arg, 0, sizeof(*quic_arg));
    sa->ss_family = AF_INET;
    while ((ch = getopt(argc, argv, "C:c:k:p:E:e:L:t:hVR6")) != -1) {
        switch (ch) {
        case 'C':
            quic_arg->cid_key = optarg;
            break;
        case 'c': /* load certificate chain */
            quic_arg->cert_file = optarg;
            break; 
        case 'k': /* load private key */
            quic_arg->key_file = optarg;
            break; 
        case 't':
            quic_arg->ticket_file = optarg;
            break;
        case 'V':
            quic_arg->verify_cert = 1;
            break;
        case 'R':
            quic_arg->enforce_retry = 1;
            break;
        case 'p': /* port */
            _port = atoi(optarg);
            break; 
        case '6':
            sa->ss_family = AF_INET6;
            break;
        case 'h':/* help */
            usage(argv[0]); break;
        case 'e':
            quic_arg->secret_log = open_log_file(optarg);
            break;
        case 'E':
            quic_arg->event_log = open_log_file(optarg); 
            quic_arg->event_mask = UINT64_MAX;
            break;
        case 'L':
            _logLevel = atoi(optarg);
            break;
        default: exit(1);
        }
    }
    _isServer = (quic_arg->cert_file && quic_arg->key_file);
    if (sa->ss_family == AF_INET) {
        struct sockaddr_in* ipv4 = (struct sockaddr_in*)sa;
        ipv4->sin_port = htons (_port);
        if (_isServer)
            ipv4->sin_addr.s_addr = htonl (INADDR_ANY);
        else if (argc > optind)
            inet_pton(sa->ss_family, argv[optind], &ipv4->sin_addr);
        else 
            ipv4->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    }
    else if (sa->ss_family == AF_INET6) {
        struct sockaddr_in6* ipv6 = (struct sockaddr_in6*)sa;
        ipv6->sin6_port = htons (_port);
        if (_isServer)
            ipv6->sin6_addr = in6addr_any;
        else if (argc > optind)
            inet_pton(sa->ss_family, argv[optind], &ipv6->sin6_addr);
        else
            ipv6->sin6_addr = in6addr_loopback;
    }
    return argc > optind ? argv[optind] : "localhost";
}
int main(int argc, char **argv)
{
    int fd;
    const char* host;
    pthread_t thread;
    struct sockaddr_storage sa={0};
#ifdef _WINDOWS
    WSADATA wsd;
    WSAStartup(MAKEWORD(2, 2), &wsd);
#endif
    {
        quicarg_t quic_arg;
        host = parse(argc, argv, &sa, &quic_arg);
        if (quic_init(&quic_arg) < 0)
            PANIC("quic_init:%d\n", errno);
    }

    /* open socket, on the specified port (as a server), or on any port (as a client) */
    if ((fd = socket(sa.ss_family, SOCK_DGRAM, IPPROTO_UDP)) == -1) 
        PANIC("socket(2):%s\n",strerror(errno));
    else {
        int reuseaddr = 1;
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (char*)&reuseaddr, sizeof(reuseaddr));
    }

    if (is_server()) {
        if (bind(fd, (struct sockaddr*)&sa, socklen(&sa)) != 0)
            PANIC("server bind:%s\n", strerror(errno));
    }
    else {
        socklen_t salen = 0;
        /* initiate a connection, and open a stream */
        _conns[0] = quic_connect((struct sockaddr*)&sa, host);
        if (!_conns[0])
            PANIC("quicly_connect:%d\n", errno);

        if (quic_open_stream(_conns[0], 0) != 0)
            PANIC("first stream must 0\n");

        if (sa.ss_family == AF_INET) {
            struct sockaddr_in* ipv4 = (struct sockaddr_in*)&sa;
            ipv4->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
            ipv4->sin_port = 0;
            salen = sizeof(*ipv4);
        }
        else if (sa.ss_family == AF_INET6) {
            struct sockaddr_in6* ipv6 = (struct sockaddr_in6*)&sa;
            ipv6->sin6_addr = in6addr_loopback;
            ipv6->sin6_port = 0;
            salen = sizeof(*ipv6);
        }
        else 
            PANIC("invalid ss_family\n");
        if (bind(fd, (struct sockaddr *)&sa, salen) != 0)
            PANIC("client bind:%s\n", strerror(errno));

        salen = sizeof(sa);
        if (getsockname(fd, (struct sockaddr *)&sa, &salen) != 0)
            PANIC("getsockname:%s\n", strerror(errno));

#ifdef _WINDOWS
        thread = (pthread_t)_beginthreadex (NULL, 0, forward_stdin, &sa, 0 , NULL);
#else
        pthread_create (&thread, NULL, forward_stdin, &sa);
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
    closesocket(fd);
    return 0;
}
