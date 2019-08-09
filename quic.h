#ifndef __QUIC_H__
#define __QUIC_H__
#pragma once
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#ifdef __cplusplus
extern "C" {
#endif
struct sockaddr;
struct sockaddr_storage;
typedef uint64_t quicstm_t;
typedef uint16_t quiconn_t;
typedef struct{ char _[128]; } quicpkt_t;
typedef struct{ char* base; size_t len;} quicbuf_t;
//发送缓冲已完成清空
#define QUIC_EGRESS_FINAL   2
//处于正常发送状态(没有调用 reset/shutdown)
#define QUIC_EGRESS_OPEN    4
//处于拥塞状态
#define QUIC_EGRESS_BLOCK   8
//接收缓冲已完成清空
#define QUIC_INGRESS_FINAL  1

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

/** 请求连接
 * @param[in] addr 服务端地址
 * @param[in] server_name 服务器名称,用于证书校验
 * @return 出错返回0
 */
quiconn_t   quic_connect    (const struct sockaddr* addr, const char *server_name);
/** 接受并建立连接
 * @param[in] addr 客户端地址
 * @param[in] pkt  客户端的请求包,由quic_decode
 * @param[out]rep  出错或拒绝时的应答包
 * @return 出错或拒绝返回0, 需将rep 回复给客户端
 */
quiconn_t   quic_accept     (const struct sockaddr* addr, const quicpkt_t *pkt, quicbuf_t *rep);
/** 关闭连接 */
void        quic_close      (quiconn_t connId, int err);
/** 连接集合的最小超时毫秒值 */
int64_t     quic_timeout_ms (quiconn_t connId[], size_t num_conn);

/** 将QUIC协议数据打包,用于 UDP 发送
 * @param[in] connId 连接 ID
 * @param[out] buf   UDP数据
 * @param[out] addr  目标地址
 */
int         quic_encode     (quiconn_t connId, quicbuf_t buf[256], struct sockaddr_storage* addr);
/** 将 UDP 数据解码与 QUIC 包
 * @param[out] pkt 解码出来的 QUIC 包
 * @param[in,out] buf 原始的 UDP 数据包
 * @param[in] addr 来源地址
 */
int         quic_decode     (quicpkt_t *pkt, quicbuf_t *buf, const struct sockaddr* addr);
/** 判断connId是否是该QUIC包的目标 */
int         quic_is_target  (quiconn_t connId, const quicpkt_t *pkt, const struct sockaddr* addr);
/** 将该 QUIC 包放入 connId 中 */
int         quic_receive    (quiconn_t connId, const quicpkt_t *pkt);

/** 打开流 */
quicstm_t   quic_open_stream    (quiconn_t connId, int unidirectional);
/** 停止流 */
int         quic_request_stop   (quiconn_t connId, quicstm_t strmId, int err);

/**  往流的发送队列中写入数据块 */
int         quic_egress_write   (quiconn_t connId, quicstm_t strmId, const quicbuf_t* buf);
/**  往流的发送队列中写入文件 */
int         quic_egress_sendf   (quiconn_t connId, quicstm_t strmId, const char *filename);
/** 关闭流的发送队列 */
int         quic_egress_shutdown(quiconn_t connId, quicstm_t strmId);
/** 查询流的发送状态 */
int         quic_egress_states  (quiconn_t connId, quicstm_t strmId, const uint64_t *max_stream_data);

/** 获取所有流的接收队列 */
int         quic_ingress_fetch  (quiconn_t connId, quicstm_t strmId[1024], quicbuf_t buf[1024]);
/** 前进流的接收队列 */
int         quic_ingress_shift  (quiconn_t connId, quicstm_t strmId, size_t offset);
/** 查询流的接收状态*/
int         quic_ingress_states (quiconn_t connId, quicstm_t strmId);
#ifdef __cplusplus
}
#endif
#endif
