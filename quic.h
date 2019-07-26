#ifndef __QUIC_H__
#define __QUIC_H__
#pragma once
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
struct sockaddr_storage;
typedef uint64_t quicstm_t;
typedef uint16_t quiconn_t;
typedef struct{ char _[128]; } quicpkt_t;
typedef struct{ char* base; size_t len;} quicbuf_t;
typedef struct {
    const char* cert_pem_file;
    const char* key_pem_file;
    const char* ticket_file;
    const char* cid_key;
    uint64_t event_mask;
    FILE* event_log;
    FILE* secret_log;
} quicarg_t;

int         quic_init       (quicarg_t* arg);
int64_t     quic_timeout    (quiconn_t connId[], size_t num_id);

quiconn_t   quic_connect    (const struct sockaddr_storage* addr, const char *server_name);
quiconn_t   quic_accept     (const struct sockaddr_storage* addr, quicpkt_t *pkt);
void        quic_close      (quiconn_t connId, int err);

int         quic_encode     (quiconn_t connId, quicbuf_t buf[256], struct sockaddr_storage* addr);
int         quic_decode     (quicpkt_t *pkt, const quicbuf_t *buf);
int         quic_is_target  (quiconn_t connId, const quicpkt_t *pkt, const struct sockaddr_storage* addr);
int         quic_receive    (quiconn_t connId, quicpkt_t *pkt);

quicstm_t   quic_open       (quiconn_t connId, int unidirectional);
int         quic_write      (quiconn_t connId, quicstm_t strmId, const quicbuf_t* buf);
int         quic_send_file  (quiconn_t connId, quicstm_t strmId, const char *filename);
int         quic_fetch      (quiconn_t connId, quicstm_t strmId[1024], quicbuf_t buf[1024]);
int         quic_shift      (quiconn_t connId, quicstm_t strmId, size_t offset);
int         quic_reset      (quiconn_t connId, quicstm_t strmId, int err);
#endif
