
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_EVENT_CONNECT_H_INCLUDED_
#define _NGX_EVENT_CONNECT_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>


#define NGX_PEER_KEEPALIVE           1
#define NGX_PEER_NEXT                2
#define NGX_PEER_FAILED              4


typedef struct ngx_peer_connection_s  ngx_peer_connection_t;

/* 当使用长连接与上游服务器通信时，可通过该方法由连接池中获取一个新连接 */
typedef ngx_int_t (*ngx_event_get_peer_pt)(ngx_peer_connection_t *pc,
    void *data);
/* 当使用长连接与上游服务器通信时，通过该方法将使用完毕的连接释放给连接池 */
typedef void (*ngx_event_free_peer_pt)(ngx_peer_connection_t *pc, void *data,
    ngx_uint_t state);
typedef void (*ngx_event_notify_peer_pt)(ngx_peer_connection_t *pc,
    void *data, ngx_uint_t type);
typedef ngx_int_t (*ngx_event_set_peer_session_pt)(ngx_peer_connection_t *pc,
    void *data);
typedef void (*ngx_event_save_peer_session_pt)(ngx_peer_connection_t *pc,
    void *data);


struct ngx_peer_connection_s {
    /* 一个主动连接实际上也需要 ngx_connection_t 结构体中的大部分成员，并且出于重用的考虑而定义了 connection 成员 */
    ngx_connection_t                *connection;

    /* 上游服务器的 sockaddr 地址 */
    struct sockaddr                 *sockaddr;
    socklen_t                        socklen;
    /* 上游服务器的名称 */
    ngx_str_t                       *name;

    /* 表示在连接一个上游服务器时，当前连接出现异常失败后可以重试的次数，也就是允许的最多失败次数 */
    ngx_uint_t                       tries;
    ngx_msec_t                       start_time;

    /* 获取连接的方法，如果使用长连接构成的连接池，那么必须要实现 get 方法 */
    ngx_event_get_peer_pt            get;
    /* 与 get 方法对应的释放连接的方法 */
    ngx_event_free_peer_pt           free;
    ngx_event_notify_peer_pt         notify;
    /* 该 data 指针仅用于和上面的 get、free、notify 方法配合传递参数 */
    void                            *data;

#if (NGX_SSL || NGX_COMPAT)
    ngx_event_set_peer_session_pt    set_session;
    ngx_event_save_peer_session_pt   save_session;
#endif

    /* 本机地址信息 */
    ngx_addr_t                      *local;

    int                              type;
    /* 套接字接收缓冲区大小 */
    int                              rcvbuf;

    /* 记录日志的 ngx_log_t 对象 */
    ngx_log_t                       *log;

    /* 标志位，为 1 时表示上面的 connection 连接已经缓存 */
    unsigned                         cached:1;
    unsigned                         transparent:1;
    unsigned                         so_keepalive:1;

    /* 与 ngx_connection_t 里的 log_error 意义是相同的，区别在于这里的 log_error 只有两位，只能表达 4 种错误，
     * NGX_ERROR_IGNORE_EINVAL 错误无法表达 */
                                     /* ngx_connection_log_error_e */
    unsigned                         log_error:2;

    NGX_COMPAT_BEGIN(2)
    NGX_COMPAT_END
};


ngx_int_t ngx_event_connect_peer(ngx_peer_connection_t *pc);
ngx_int_t ngx_event_get_peer(ngx_peer_connection_t *pc, void *data);


#endif /* _NGX_EVENT_CONNECT_H_INCLUDED_ */
