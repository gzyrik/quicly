#include "quic.h"
#include <stdarg.h>
#include <errno.h>
#include <fcntl.h>
#ifdef _WIN32
#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "Bcrypt.lib")
#if PICOTLS_USE_OPENSSL 
#pragma comment(lib, "libcrypto.lib")
#endif
#include <ws2tcpip.h>
#else
#include <unistd.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/stat.h>
#endif
#if PICOTLS_USE_OPENSSL 
#include <openssl/pem.h>
#include "picotls/openssl.h"
#else
#include "picotls/minicrypto.h"
#endif
#include "quicly.h"
#include "quicly/defaults.h"
#include "quicly/streambuf.h"
#include "khash.h"
#define STREAM_VBUF(stream)  ((quicbuf_t*)((uint8_t*)stream->data + sizeof(quicly_streambuf_t)))
static int on_stop_sending(quicly_stream_t *stream, int err)
{
    fprintf(stderr, "received STOP_SENDING: %d \n", QUICLY_ERROR_GET_ERROR_CODE(err));
    quicly_close(stream->conn, QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(0), "");
    return 0;
}

static int on_receive_reset(quicly_stream_t *stream, int err)
{
    fprintf(stderr, "received RESET_STREAM: %d\n", QUICLY_ERROR_GET_ERROR_CODE(err));
    quicly_close(stream->conn, QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(0), "");
    return 0;
}
static int on_receive(quicly_stream_t *stream, size_t off, const void *src, size_t len)
{
    int ret;
    ptls_iovec_t input;
    quicbuf_t* vbuf;
    /* read input to receive buffer */
    if ((ret = quicly_streambuf_ingress_receive(stream, off, src, len)) != 0)
        return ret;
    /* obtain contiguous bytes from the receive buffer */
    input = quicly_streambuf_ingress_get(stream);
    vbuf = STREAM_VBUF(stream);
    vbuf->base = (char*)input.base;
    vbuf->len = input.len;
    return 0;
}
static int on_stream_open(quicly_stream_open_t *self, quicly_stream_t *stream)
{
    static const quicly_stream_callbacks_t stream_callbacks = {
        quicly_streambuf_destroy, quicly_streambuf_egress_shift, quicly_streambuf_egress_emit, on_stop_sending, on_receive,
        on_receive_reset};
    int ret;

    if ((ret = quicly_streambuf_create(stream, sizeof(quicly_streambuf_t)+sizeof(quicbuf_t))) != 0)
        return ret;
    memset(STREAM_VBUF(stream), 0, sizeof(quicbuf_t));
    stream->callbacks = &stream_callbacks;
    return 0;
}
static void on_closed_by_peer(quicly_closed_by_peer_t *self, quicly_conn_t *conn, int err,
    uint64_t frame_type, const char *reason, size_t reason_len)
{
    if (QUICLY_ERROR_IS_QUIC_TRANSPORT(err)) {
        if (err >= QUICLY_TRANSPORT_ERROR_TLS_ALERT_BASE)  
            fprintf(stderr, "tls close:code=0x%" PRIx16 ";frame=%" PRIu64 ";reason=%.*s\n",
                (uint16_t)PTLS_ERROR_TO_ALERT(err), frame_type, (int)reason_len, reason);
        else
            fprintf(stderr, "transport close:code=0x%" PRIx16 ";frame=%" PRIu64 ";reason=%.*s\n",
                QUICLY_ERROR_GET_ERROR_CODE(err), frame_type, (int)reason_len, reason);
    } else if (QUICLY_ERROR_IS_QUIC_APPLICATION(err)) {
        fprintf(stderr, "application close:code=0x%" PRIx16 ";reason=%.*s\n",
            QUICLY_ERROR_GET_ERROR_CODE(err), (int)reason_len, reason);
    } else if (err == QUICLY_ERROR_RECEIVED_STATELESS_RESET) {
        fprintf(stderr, "stateless reset\n");
    } else {
        fprintf(stderr, "unexpected close:code=%d\n", err);
    }
}
static ptls_handshake_properties_t _hs_properties;
static quicly_transport_parameters_t _resumed_transport_params;
struct st_util_save_ticket_t {
    ptls_save_ticket_t super;
    char* ticket_file;
};
static int save_ticket_cb(ptls_save_ticket_t *_self, ptls_t *tls, ptls_iovec_t src)
{
    struct st_util_save_ticket_t *self = (void *)_self;
    quicly_conn_t *conn = *ptls_get_data_ptr(tls);
    ptls_buffer_t buf;
    FILE *fp = NULL;
    int ret;

    if (self->ticket_file == NULL)
        return 0;

    ptls_buffer_init(&buf, "", 0);

    /* build data (session ticket and transport parameters) */
    ptls_buffer_push_block(&buf, 2, { ptls_buffer_pushv(&buf, src.base, src.len); });
    ptls_buffer_push_block(&buf, 2, {
        if ((ret = quicly_encode_transport_parameter_list(&buf, 1, quicly_get_peer_transport_parameters(conn), NULL, NULL)) != 0)
            goto Exit;
    });

    /* write file */
    if ((fp = fopen(self->ticket_file, "wb")) == NULL) {
        fprintf(stderr, "failed to open file:%s:%s\n", self->ticket_file, strerror(errno));
        ret = PTLS_ERROR_LIBRARY;
        goto Exit;
    }
    fwrite(buf.base, 1, buf.off, fp);

    ret = 0;
Exit:
    if (fp != NULL)
        fclose(fp);
    ptls_buffer_dispose(&buf);
    return 0;
}
static void load_ticket(const char* ticket_file)
{
    static uint8_t buf[65536];
    size_t len;
    int ret;
    {
        FILE *fp;
        if ((fp = fopen(ticket_file, "rb")) == NULL)
            return;
        len = fread(buf, 1, sizeof(buf), fp);
        if (len == 0 || !feof(fp)) {
            fprintf(stderr, "failed to load ticket from file:%s\n", ticket_file);
            exit(1);
        }
        fclose(fp);
    }

    {
        const uint8_t *src = buf, *end = buf + len;
        ptls_iovec_t ticket;
        ptls_decode_open_block(src, end, 2, {
            ticket = ptls_iovec_init(src, end - src);
            src = end;
        });
        ptls_decode_block(src, end, 2, {
            if ((ret = quicly_decode_transport_parameter_list(&_resumed_transport_params, NULL, NULL, 1, src, end)) != 0)
                goto Exit;
            src = end;
        });
        _hs_properties.client.session_ticket = ticket;
    }
Exit:;
}

struct st_util_log_event_t {
    ptls_log_event_t super;
    FILE *fp;
};
static void log_event_cb(ptls_log_event_t *_self, ptls_t *tls, const char *type, const char *fmt, ...)
{
    struct st_util_log_event_t *self = (void *)_self;
    char randomhex[PTLS_HELLO_RANDOM_SIZE * 2 + 1];
    va_list args;

    ptls_hexdump(randomhex, ptls_get_client_random(tls).base, PTLS_HELLO_RANDOM_SIZE);
    fprintf(self->fp, "%s %s ", type, randomhex);

    va_start(args, fmt);
    vfprintf(self->fp, fmt, args);
    va_end(args);

    fprintf(self->fp, "\n");
    fflush(self->fp);
}
static quicly_context_t _ctx;
static quicly_cid_plaintext_t _next_cid;
static int _enforce_retry;
#define QUIC_MAX_CONN 1024
static quicly_conn_t *_conns[QUIC_MAX_CONN];
int quic_init(quicarg_t* arg)
{
    int ret;
    static ptls_context_t tlsctx = {
#if PICOTLS_USE_OPENSSL
        .random_bytes = ptls_openssl_random_bytes,
        .key_exchanges = ptls_openssl_key_exchanges,
        .cipher_suites = ptls_openssl_cipher_suites,
#else
        .random_bytes = ptls_minicrypto_random_bytes,
        .key_exchanges = ptls_minicrypto_key_exchanges,
        .cipher_suites = ptls_minicrypto_cipher_suites,
#endif
        .get_time = &ptls_get_time,
        .log_event = NULL
    };
    static quicly_stream_open_t stream_open = { on_stream_open };
    static quicly_closed_by_peer_t closed_by_peer = { &on_closed_by_peer };
    /* setup quic context */
    _ctx = quicly_spec_context;
    _ctx.tls = &tlsctx;
    quicly_amend_ptls_context(_ctx.tls);
    _ctx.stream_open = &stream_open;
    _ctx.closed_by_peer = &closed_by_peer;
    if (!arg) return 0;

    _enforce_retry = (arg->enforce_retry != 0);
    if (arg->event_log) {
        setvbuf(arg->event_log, NULL, _IONBF, 0);
        _ctx.event_log.cb = quicly_new_default_event_logger(arg->event_log);
        _ctx.event_log.mask = arg->event_mask;
    }
    if (arg->secret_log) {
        static struct st_util_log_event_t ls;
        ls.fp = arg->secret_log;
        ls.super.cb = log_event_cb;
        _ctx.tls->log_event = &ls.super;
    }
    if (arg->cert_file && arg->cert_file[0]) {
        if ((ret = ptls_load_certificates(_ctx.tls, arg->cert_file)) != 0) {
            fprintf(stderr, "failed to load certificates from file %s:%d\n", arg->cert_file, ret);
            return -1;
        }
    }
    if (arg->key_file && arg->key_file[0]) {
#if PICOTLS_USE_OPENSSL
        BIO* bio = BIO_new(BIO_s_file());
        if (bio == NULL || BIO_read_filename(bio, arg->key_file) <= 0) {
            fprintf(stderr, "failed to open file `%s': %s\n", arg->key_file, strerror(errno));
            return -1;
        }
        EVP_PKEY *pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
        BIO_free(bio);
        if (pkey == NULL) {
            fprintf(stderr, "failed to parse file `%s': %s\n", arg->key_file, strerror(errno));
            return -1;
        }
        static ptls_openssl_sign_certificate_t sign_certificate;
        ptls_openssl_init_sign_certificate(&sign_certificate, pkey);
        EVP_PKEY_free(pkey);
        _ctx.tls->sign_certificate = &sign_certificate.super;
#else
        if ((ret = ptls_minicrypto_load_private_key(_ctx.tls, arg->key_pem_file)) != 0) {
            fprintf(stderr, "failed to open file `%s': %s\n", arg->key_pem_file, strerror(errno));
            return -1;
        }
#endif
    }
#if PICOTLS_USE_OPENSSL
    if (arg->verify_cert) {
        static ptls_openssl_verify_certificate_t vc;
        ptls_openssl_init_verify_certificate(&vc, NULL);
        if (arg->cert_file && arg->cert_file[0]) {
            X509_LOOKUP *lookup = X509_STORE_add_lookup(vc.cert_store, X509_LOOKUP_file());
            if (lookup) X509_LOOKUP_load_file(lookup, arg->cert_file, X509_FILETYPE_PEM);
        }
        _ctx.tls->verify_certificate = &vc.super;
    }
    if (!arg->cid_key && _ctx.tls->certificates.count != 0 && _ctx.tls->sign_certificate != NULL) {
        static char random_key[17];
        _ctx.tls->random_bytes(random_key, sizeof(random_key) - 1);
        arg->cid_key = random_key;
    }
    if (arg->cid_key && arg->cid_key[0]) {
        _ctx.cid_encryptor = quicly_new_default_cid_encryptor(
            &ptls_openssl_bfecb, &ptls_openssl_sha256,
            ptls_iovec_init(arg->cid_key, strlen(arg->cid_key)));
    }
#endif
    if (arg->ticket_file && arg->ticket_file[0]) {
        static struct st_util_save_ticket_t st;
        st.super.cb = save_ticket_cb;
        st.ticket_file = strdup(arg->ticket_file);
        _ctx.tls->save_ticket = &st.super;
        load_ticket(arg->ticket_file);
    }
    return 0;
}
#define MAX_DATADRAM 256
static quiconn_t add_conn(quicly_conn_t *conn)
{
    int i;
    struct _st_quicly_conn_public_t *p = (struct _st_quicly_conn_public_t*)conn;
    for (i=1; i<QUIC_MAX_CONN; ++i) {
        if (!_conns[i]) {
            p->data = calloc(MAX_DATADRAM, sizeof(quicly_datagram_t*));
            _conns[i] = conn;
            return i;
        }
    }
    quicly_free(conn);
    return 0;
}
static quicly_stream_t* get_strm(quiconn_t connId, quicstm_t strmId)
{
    if (connId < QUIC_MAX_CONN && _conns[connId])
        return quicly_get_stream(_conns[connId], strmId);
    return NULL;
}
int64_t quic_timeout_ms (quiconn_t connId[], size_t num_id)
{
    size_t i;
    int64_t first_timeout = INT64_MAX, now = _ctx.now->cb(_ctx.now);
    for (i=0; i<num_id && connId[i] && connId[i] < QUIC_MAX_CONN; ++i) {
        int64_t conn_timeout = quicly_get_first_timeout(_conns[connId[i]]) - now;
        if (conn_timeout <= 0) return 0;
        else if (conn_timeout <= first_timeout)
            first_timeout = conn_timeout;
    }
    if (first_timeout > _ctx.transport_params.idle_timeout)
        first_timeout = _ctx.transport_params.idle_timeout;
    return first_timeout;
}
static socklen_t socklen(const struct sockaddr* addr)
{
    switch(addr->sa_family) {
    case AF_INET:
        return sizeof(struct sockaddr_in);
    case AF_INET6:
        return sizeof(struct sockaddr_in6);
    default:
        return 0;
    }
}
int quic_is_target(quiconn_t connId, const quicpkt_t *pkt, const struct sockaddr* addr)
{
    return quicly_is_destination(_conns[connId], 
        (struct sockaddr*)addr, socklen(addr), (quicly_decoded_packet_t*)pkt);
}
quiconn_t quic_connect (const struct sockaddr* addr, const char *server_name)
{
    quicly_conn_t *conn = NULL;
    if (quicly_connect(&conn, &_ctx, server_name,
            (struct sockaddr*)addr, socklen(addr), &_next_cid, &_hs_properties, &_resumed_transport_params) != 0) 
        return 0;
    ++_next_cid.master_id;
    return add_conn(conn);
}
static void send_reply(quicbuf_t *rep, quicly_datagram_t* rp)
{
    static quicly_datagram_t* _reply = NULL;
    if (_reply) _ctx.packet_allocator->free_packet(_ctx.packet_allocator, _reply); 
    rep->base = (char*)rp->data.base;
    rep->len  = rp->data.len;
    _reply = rp;
}
quiconn_t quic_accept (const struct sockaddr* addr, const quicpkt_t *pkt, quicbuf_t *rep)
{
    quicly_conn_t *conn = NULL;
    quicly_decoded_packet_t* packet = (quicly_decoded_packet_t*)pkt;
    rep->len = 0;
    if (QUICLY_PACKET_IS_LONG_HEADER(packet->octets.base[0])) {
        /* long header packet; potentially a new connection */
        if (_enforce_retry && packet->token.len == 0 && packet->cid.dest.encrypted.len >= 8) {
            /* unbound connection; send a retry token unless the client has supplied the correct one, but not too many
            */
            uint8_t new_server_cid[8];
            memcpy(new_server_cid, packet->cid.dest.encrypted.base, sizeof(new_server_cid));
            new_server_cid[0] ^= 0xff;
            send_reply(rep, quicly_send_retry(
                    &_ctx, (struct sockaddr*)&addr, socklen(addr),
                    packet->cid.src, ptls_iovec_init(new_server_cid, sizeof(new_server_cid)),
                    packet->cid.dest.encrypted, packet->cid.dest.encrypted /* FIXME SMAC(odcid || sockaddr) */));
        } else {
            /* new connection */
            if (quicly_accept(&conn, &_ctx,(struct sockaddr*)addr, socklen(addr), packet, 
                    _enforce_retry ? packet->token /* a production server should validate the token */
                    : ptls_iovec_init(NULL, 0),
                    &_next_cid, NULL) != 0)
                return 0;
            ++_next_cid.master_id;
            return add_conn(conn);
        }
    } else {
        /* short header packet; potentially a dead connection. No need to check the length of the incoming packet,
         * because loop is prevented by authenticating the CID (by checking node_id and thread_id). If the peer is also
         * sending a reset, then the next CID is highly likely to contain a non-authenticating CID, ... */
        if (packet->cid.dest.plaintext.node_id == 0 && packet->cid.dest.plaintext.thread_id == 0)
            send_reply(rep, quicly_send_stateless_reset(&_ctx,
                (struct sockaddr*)&addr, socklen(addr), packet->cid.dest.encrypted.base));
    }
    return 0;
}
void quic_close (quiconn_t connId, int err)
{
    if (_conns[connId])
        quicly_close(_conns[connId], err, NULL);
}
int quic_decode (quicpkt_t *pkt, quicbuf_t *buf, const struct sockaddr* addr)
{
    quicly_decoded_packet_t* packet = (quicly_decoded_packet_t*)pkt;
    size_t ret = quicly_decode_packet(&_ctx, packet, (uint8_t*)buf->base, buf->len);
    buf->len = 0;
    if (ret == SIZE_MAX) 
        return -1;
    else if (QUICLY_PACKET_IS_LONG_HEADER(packet->octets.base[0])) {
        if (packet->version != QUICLY_PROTOCOL_VERSION) {
            send_reply(buf, quicly_send_version_negotiation(&_ctx, (struct sockaddr*)&addr, socklen(addr),
                packet->cid.src, packet->cid.dest.encrypted));
            return -1;
        }
        /* there is no way to send response to these v1 packets */
        if (packet->cid.dest.encrypted.len > QUICLY_MAX_CID_LEN_V1 || packet->cid.src.len > QUICLY_MAX_CID_LEN_V1)
            return -1;
    }
    return (int)ret;
}

int quic_received(quiconn_t connId, const quicpkt_t *pkt)
{
    QUICLY_BUILD_ASSERT(sizeof(quicpkt_t) >= sizeof(quicly_decoded_packet_t));
    return quicly_receive(_conns[connId], (quicly_decoded_packet_t*)pkt);
}

quicstm_t quic_open_stream (quiconn_t connId, int unidirectional)
{
    quicly_stream_t *stream = NULL;
    quicly_open_stream(_conns[connId], &stream, unidirectional);
    return stream ? stream->stream_id : -1;
}
int quic_request_stop (quiconn_t connId, quicstm_t strmId, int err)
{
    quicly_stream_t* stream = get_strm(connId, strmId); 
    if (!stream) return -1;
    if (!quicly_stream_has_receive_side(quicly_is_client(stream->conn), stream->stream_id))
        return -1;
    quicly_request_stop(stream, QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(err));
    return 0;
}
int quic_egress_write (quiconn_t connId, quicstm_t strmId, const quicbuf_t *buf)
{
    quicly_stream_t* stream = get_strm(connId, strmId); 
    if (!stream) return -1;
    if (!quicly_sendstate_is_open(&stream->sendstate)) return -1;
    return quicly_streambuf_egress_write(stream, buf->base, buf->len);
}
#ifdef _WINDOWS
static int pread(unsigned int fd, char *buf, size_t count, int offset)
{ 
    if (_lseek(fd, offset, SEEK_SET) != offset)
        return -1;
    return read(fd, buf, count);
}
#endif
static int flatten_file_vec(quicly_sendbuf_vec_t *vec, void *dst, size_t off, size_t len)
{
    int fd = (int)vec->cbdata;
    ssize_t rret;

    /* FIXME handle partial read */
    while ((rret = pread(fd, dst, len, off)) == -1 && errno == EINTR)
        ;

    return rret == len ? 0 : QUICLY_TRANSPORT_ERROR_INTERNAL; /* should return application-level error */
}

static void discard_file_vec(quicly_sendbuf_vec_t *vec)
{
    int fd = (int)vec->cbdata;
    close(fd);
}

int quic_egress_sendf(quiconn_t connId, quicstm_t strmId, const char *filename)
{
    static const quicly_streambuf_sendvec_callbacks_t send_file_callbacks = {flatten_file_vec, discard_file_vec};
    int fd;
    size_t len;

    if ((fd = open(filename, O_RDONLY)) == -1)
        return 0;
#ifdef _WINDOWS
    len = _filelengthi64(fd);
#else
    struct stat st;
    if (fstat(fd, &st) != 0) {
        close(fd);
        return 0;
    }
    len = (size_t)st.st_size;
#endif
    quicly_stream_t* stream = get_strm(connId, strmId);
    quicly_sendbuf_vec_t vec = {&send_file_callbacks, len, (void *)(intptr_t)fd};
    return quicly_streambuf_egress_write_vec(stream, &vec);
}
int quic_egress_states (quiconn_t connId, quicstm_t strmId, const uint64_t *max_stream_data)
{
    int state = 0;
    quicly_stream_t* stream = get_strm(connId, strmId);
    if (!stream) return 0;
    if (quicly_sendstate_transfer_complete(&stream->sendstate))
        state |= QUIC_EGRESS_FINAL;
    else if (quicly_sendstate_is_open(&stream->sendstate))
        state |= QUIC_EGRESS_OPEN;
    if (!quicly_sendstate_can_send(&stream->sendstate, max_stream_data))
        state |= QUIC_EGRESS_BLOCK;
    return 0;
}
int quic_egress_shutdown(quiconn_t connId, quicstm_t strmId)
{
    quicly_stream_t* stream = get_strm(connId, strmId); 
    if (!stream) return -1;
    if (!quicly_sendstate_is_open(&stream->sendstate)) return -1;

    return quicly_streambuf_egress_shutdown(stream);
}

struct myfetch {
    quicstm_t *strm;
    quicbuf_t *vbuf;
};
static void fetch_vbuf(quicly_stream_t* stream, size_t* p, void* f)
{
    struct myfetch* mf = (struct myfetch*)f;
    quicbuf_t* v = STREAM_VBUF(stream);
    if (stream->stream_id >=0 && v->len > 0) {
        size_t i = (*p)++;
        if (i >= 1024) abort();
        mf->strm[i] = stream->stream_id;
        mf->vbuf[i] = *v;
    }
}
int quic_ingress_fetch (quiconn_t connId, quicstm_t strmId[1024], quicbuf_t vbuf[1024])
{
    struct myfetch mf = { strmId , vbuf };
    quicly_conn_t *conn = _conns[connId];
    return (int)quicly_foreach_stream(conn, &mf, fetch_vbuf);
}
int quic_ingress_shift (quiconn_t connId, quicstm_t strmId, size_t off)
{
    quicbuf_t* vbuf;
    quicly_stream_t* stream = get_strm(connId, strmId);
    if (!stream) return -1;
    vbuf = STREAM_VBUF(stream);
    if (vbuf->len == 0) return 0;
    if (off > vbuf->len) off = vbuf->len;
    /* remove used bytes from receive buffer */
    quicly_streambuf_ingress_shift(stream, off);
    return vbuf->len -= off;
}
int quic_ingress_states (quiconn_t connId, quicstm_t strmId)
{
    int state = 0;
    quicly_stream_t* stream = get_strm(connId, strmId);
    if (!stream) return 0;
    if (quicly_recvstate_transfer_complete(&stream->recvstate))
        state |= QUIC_INGRESS_FINAL;
    return 0;
}
int quic_encode (quiconn_t connId, quicbuf_t vbuf[256], struct sockaddr_storage* addr)
{
    struct sockaddr* sa;
    socklen_t salen;
    quicly_conn_t *conn = _conns[connId];
    size_t i, num_pkt = MAX_DATADRAM;
    struct _st_quicly_conn_public_t *p = (struct _st_quicly_conn_public_t*)conn;
    quicly_datagram_t** pkt = (quicly_datagram_t**)p->data;
    for (i=0;i < num_pkt && pkt[i];++i) {
        _ctx.packet_allocator->free_packet(
            _ctx.packet_allocator, pkt[i]);
        pkt[i] = NULL;
    }
    int ret = quicly_send(conn, pkt, &num_pkt);
    if (ret == QUICLY_ERROR_FREE_CONNECTION){
        free(p->data);
        quicly_free(conn);
        _conns[connId] = NULL;
        return -1;
    }
    for (i=0;i<num_pkt; ++i) {
        vbuf[i].base = (char*)pkt[i]->data.base;
        vbuf[i].len  = pkt[i]->data.len;
    }
    quicly_get_peername(conn, &sa, &salen);
    memcpy(addr, sa, salen);
    return num_pkt;
}
