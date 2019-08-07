#ifndef __QUIC_H__
#define __QUIC_H__
#pragma once
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
struct sockaddr;
struct sockaddr_storage;
typedef uint64_t quicstm_t;
typedef uint16_t quiconn_t;
typedef struct{ char _[128]; } quicpkt_t;
typedef struct{ char* base; size_t len;} quicbuf_t;
/**
 * - event_mask,event_log
 *   file to log events
 * - secret_log
 *   file to log traffic secrets
 *
 * - cert_file
 *   specifies the certificate chain file (PEM format)
 * - key_file
 *   specifies the private key file (PEM format)
 * - cid_key
 *   CID encryption key(server-only). Randomly generated if omitted.
 * - enforce_retry
 *   require Retry (server only)
 *
 * - verify_cert
 *   verify peer using 'cert_file' or the default certificates: 
 *   internal openssl used getenv('SSL_CERT_DIR' or 'SSL_CERT_FILE')
 * - ticket_file
 *   file to load / store the session ticket
 */
typedef struct {
    uint64_t event_mask;
    FILE* event_log;
    FILE* secret_log;

    const char* cert_file;
    const char* key_file;
    const char* cid_key;
    int enforce_retry;

    int verify_cert;
    const char* ticket_file;
} quicarg_t;

int         quic_init       (quicarg_t* arg);

quiconn_t   quic_connect    (const struct sockaddr* addr, const char *server_name);
quiconn_t   quic_accept     (const struct sockaddr* addr, const quicpkt_t *pkt, quicbuf_t *rep);
void        quic_close      (quiconn_t connId, int err);
int64_t     quic_timeout    (quiconn_t connId[], size_t num_id);

int         quic_encode     (quiconn_t connId, quicbuf_t buf[256], struct sockaddr_storage* addr);
int         quic_decode     (quicpkt_t *pkt, quicbuf_t *buf, const struct sockaddr* addr);
int         quic_is_target  (quiconn_t connId, const quicpkt_t *pkt, const struct sockaddr* addr);
int         quic_receive    (quiconn_t connId, const quicpkt_t *pkt);

quicstm_t   quic_open       (quiconn_t connId, int unidirectional);
int         quic_write      (quiconn_t connId, quicstm_t strmId, const quicbuf_t* buf);
int         quic_send_file  (quiconn_t connId, quicstm_t strmId, const char *filename);
int         quic_fetch      (quiconn_t connId, quicstm_t strmId[1024], quicbuf_t buf[1024]);
int         quic_shift      (quiconn_t connId, quicstm_t strmId, size_t offset);
int         quic_reset      (quiconn_t connId, quicstm_t strmId, int err);
#endif
