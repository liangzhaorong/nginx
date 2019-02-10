
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_HTTP_UPSTREAM_H_INCLUDED_
#define _NGX_HTTP_UPSTREAM_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_event_connect.h>
#include <ngx_event_pipe.h>
#include <ngx_http.h>


#define NGX_HTTP_UPSTREAM_FT_ERROR           0x00000002
#define NGX_HTTP_UPSTREAM_FT_TIMEOUT         0x00000004
#define NGX_HTTP_UPSTREAM_FT_INVALID_HEADER  0x00000008
#define NGX_HTTP_UPSTREAM_FT_HTTP_500        0x00000010
#define NGX_HTTP_UPSTREAM_FT_HTTP_502        0x00000020
#define NGX_HTTP_UPSTREAM_FT_HTTP_503        0x00000040
#define NGX_HTTP_UPSTREAM_FT_HTTP_504        0x00000080
#define NGX_HTTP_UPSTREAM_FT_HTTP_403        0x00000100
#define NGX_HTTP_UPSTREAM_FT_HTTP_404        0x00000200
#define NGX_HTTP_UPSTREAM_FT_HTTP_429        0x00000400
#define NGX_HTTP_UPSTREAM_FT_UPDATING        0x00000800
#define NGX_HTTP_UPSTREAM_FT_BUSY_LOCK       0x00001000
#define NGX_HTTP_UPSTREAM_FT_MAX_WAITING     0x00002000
#define NGX_HTTP_UPSTREAM_FT_NON_IDEMPOTENT  0x00004000
#define NGX_HTTP_UPSTREAM_FT_NOLIVE          0x40000000
#define NGX_HTTP_UPSTREAM_FT_OFF             0x80000000

#define NGX_HTTP_UPSTREAM_FT_STATUS          (NGX_HTTP_UPSTREAM_FT_HTTP_500  \
                                             |NGX_HTTP_UPSTREAM_FT_HTTP_502  \
                                             |NGX_HTTP_UPSTREAM_FT_HTTP_503  \
                                             |NGX_HTTP_UPSTREAM_FT_HTTP_504  \
                                             |NGX_HTTP_UPSTREAM_FT_HTTP_403  \
                                             |NGX_HTTP_UPSTREAM_FT_HTTP_404  \
                                             |NGX_HTTP_UPSTREAM_FT_HTTP_429)

#define NGX_HTTP_UPSTREAM_INVALID_HEADER     40


#define NGX_HTTP_UPSTREAM_IGN_XA_REDIRECT    0x00000002
#define NGX_HTTP_UPSTREAM_IGN_XA_EXPIRES     0x00000004
#define NGX_HTTP_UPSTREAM_IGN_EXPIRES        0x00000008
#define NGX_HTTP_UPSTREAM_IGN_CACHE_CONTROL  0x00000010
#define NGX_HTTP_UPSTREAM_IGN_SET_COOKIE     0x00000020
#define NGX_HTTP_UPSTREAM_IGN_XA_LIMIT_RATE  0x00000040
#define NGX_HTTP_UPSTREAM_IGN_XA_BUFFERING   0x00000080
#define NGX_HTTP_UPSTREAM_IGN_XA_CHARSET     0x00000100
#define NGX_HTTP_UPSTREAM_IGN_VARY           0x00000200


typedef struct {
    ngx_uint_t                       status;
    ngx_msec_t                       response_time;
    ngx_msec_t                       connect_time;
    ngx_msec_t                       header_time;
    ngx_msec_t                       queue_time;
    off_t                            response_length;
    off_t                            bytes_received;

    ngx_str_t                       *peer;
} ngx_http_upstream_state_t;


typedef struct {
    ngx_hash_t                       headers_in_hash;
    ngx_array_t                      upstreams;
                                             /* ngx_http_upstream_srv_conf_t */
} ngx_http_upstream_main_conf_t;

typedef struct ngx_http_upstream_srv_conf_s  ngx_http_upstream_srv_conf_t;

typedef ngx_int_t (*ngx_http_upstream_init_pt)(ngx_conf_t *cf,
    ngx_http_upstream_srv_conf_t *us);
typedef ngx_int_t (*ngx_http_upstream_init_peer_pt)(ngx_http_request_t *r,
    ngx_http_upstream_srv_conf_t *us);


typedef struct {
    ngx_http_upstream_init_pt        init_upstream;
    ngx_http_upstream_init_peer_pt   init;
    void                            *data;
} ngx_http_upstream_peer_t;


typedef struct {
    ngx_str_t                        name;
    ngx_addr_t                      *addrs;
    ngx_uint_t                       naddrs;
    ngx_uint_t                       weight;
    ngx_uint_t                       max_conns;
    ngx_uint_t                       max_fails;
    time_t                           fail_timeout;
    ngx_msec_t                       slow_start;
    ngx_uint_t                       down;

    unsigned                         backup:1;

    NGX_COMPAT_BEGIN(6)
    NGX_COMPAT_END
} ngx_http_upstream_server_t;


#define NGX_HTTP_UPSTREAM_CREATE        0x0001
#define NGX_HTTP_UPSTREAM_WEIGHT        0x0002
#define NGX_HTTP_UPSTREAM_MAX_FAILS     0x0004
#define NGX_HTTP_UPSTREAM_FAIL_TIMEOUT  0x0008
#define NGX_HTTP_UPSTREAM_DOWN          0x0010
#define NGX_HTTP_UPSTREAM_BACKUP        0x0020
#define NGX_HTTP_UPSTREAM_MAX_CONNS     0x0100


struct ngx_http_upstream_srv_conf_s {
    ngx_http_upstream_peer_t         peer;
    void                           **srv_conf;

    ngx_array_t                     *servers;  /* ngx_http_upstream_server_t */

    ngx_uint_t                       flags;
    ngx_str_t                        host;
    u_char                          *file_name;
    ngx_uint_t                       line;
    in_port_t                        port;
    ngx_uint_t                       no_port;  /* unsigned no_port:1 */

#if (NGX_HTTP_UPSTREAM_ZONE)
    ngx_shm_zone_t                  *shm_zone;
#endif
};


typedef struct {
    ngx_addr_t                      *addr;
    ngx_http_complex_value_t        *value;
#if (NGX_HAVE_TRANSPARENT_PROXY)
    ngx_uint_t                       transparent; /* unsigned  transparent:1; */
#endif
} ngx_http_upstream_local_t;


typedef struct {
    /* 当在 ngx_http_upstream_t 结构体中没有实现 resolved 成员时，upstream 这个
     * 结构体才会生效，它会定义上游服务器的配置 */
    ngx_http_upstream_srv_conf_t    *upstream;

    /* proxy_connect_timeout 指令
     * 建立 TCP 连接的超时时间，实际上就是写事件添加到定时器中时设置的超时时间 */
    ngx_msec_t                       connect_timeout;
    /* proxy_send_timeout 指令
     * 发送请求的超时时间。通常就是写事件添加到定时器中设置的超时时间 */
    ngx_msec_t                       send_timeout;
    /* proxy_read_timeout 指令
     * 接收响应的超时时间。通常就是读事件添加到定时器中设置的超时时间 */
    ngx_msec_t                       read_timeout;
    /* proxy_next_upstream_timeout 指令
     * 向下一个服务器发出请求之前经过的时间 */
    ngx_msec_t                       next_upstream_timeout;

    /* proxy_send_lowat 指令
     * TCP 的 SO_SNOLOWAT 选项，表示发送缓冲区的下限 */
    size_t                           send_lowat;
    /* proxy_buffer_size 指令
     * 定义了接收响应头部的缓冲区分配的内存大小（ngx_http_upstream_t 中的 buffer 缓冲区），
     * 当不转发响应给下游或者 buffering 标志位为 0 的情况下转发响应时，它同样表示接收包体的
     * 缓冲区大小 */
    size_t                           buffer_size;
    /* proxy_limit_rate 指令 */
    size_t                           limit_rate;

    /* 仅当 buffering 标志位为 1，并且向下游转发响应时生效。它会设置到 
     * ngx_event_pipe_t 结构体的 busy_size 成员中 */
    size_t                           busy_buffers_size;
    /* 在 buffering 标志位为 1 时，如果上游速度快于下游速度，将有可能把来自上游的响应
     * 存储到临时文件中，而 max_temp_file_size 指定了临时文件的最大长度。实际上，它将限制
     * ngx_event_pipe_t 结构体中 temp_file */
    size_t                           max_temp_file_size;
    /* 表示将缓冲区中的响应写入临时文件时一次写入字符流的最大长度 */
    size_t                           temp_file_write_size;

    /* proxy_busy_buffers_size 指令 */
    size_t                           busy_buffers_size_conf;
    /* proxy_max_temp_file_size 指令 */
    size_t                           max_temp_file_size_conf;
    size_t                           temp_file_write_size_conf;

    /* proxy_buffers 指令
     * 以缓存响应的方式转发上游服务器的包体时所使用的内存大小 */
    ngx_bufs_t                       bufs;

    /* 针对 ngx_http_upstream_t 结构体中保存解析完的包头的 headers_in 成员，ignore_headers
     * 可以按照二进制位使得 upstream 在转发包头时跳过对某些头部的处理。目前有如下设置:
     * #define NGX_HTTP_UPSTREAM_IGN_XA_REDIRECT    0x00000002
     * #define NGX_HTTP_UPSTREAM_IGN_XA_EXPIRES     0x00000004
     * #define NGX_HTTP_UPSTREAM_IGN_EXPIRES        0x00000008
     * #define NGX_HTTP_UPSTREAM_IGN_CACHE_CONTROL  0x00000010
     * #define NGX_HTTP_UPSTREAM_IGN_SET_COOKIE     0x00000020
     * #define NGX_HTTP_UPSTREAM_IGN_XA_LIMIT_RATE  0x00000040
     * #define NGX_HTTP_UPSTREAM_IGN_XA_BUFFERING   0x00000080
     * #define NGX_HTTP_UPSTREAM_IGN_XA_CHARSET     0x00000100
     * #define NGX_HTTP_UPSTREAM_IGN_VARY           0x00000200 */
    ngx_uint_t                       ignore_headers;
    /* proxy_next_upstream 指令
     * 以二进制位来表示一些错误码，如果处理上游响应时发现这些错误码，那么在没有
     * 将响应转发给下游客户端时，将会选择下一个上游服务器来重发请求 */
    ngx_uint_t                       next_upstream;
    /* 在 buffering 标志位为 1 的情况下转发响应时，将有可能把响应存放到临时文件中。
     * 在 ngx_http_upstream_t 中的 store 标志位为 1 时，store_access 表示所创建
     * 的目录、文件的权限 */
    ngx_uint_t                       store_access;
    /* proxy_next_upstream_tries 指令 */
    ngx_uint_t                       next_upstream_tries;
    /* proxy_buffering 指令
     * 决定转发响应方式的标志位，buffering 为 1 时表示打开缓存，这时认为上游的网速
     * 快于下游的网速，会尽量地在内存或者磁盘中缓存来自上游的响应；如果 buffering
     * 为 0，仅会开辟一块固定大小的内存块作为缓存来转发响应 */
    ngx_flag_t                       buffering;
    /* proxy_request_buffering 指令 */
    ngx_flag_t                       request_buffering;
    /* proxy_pass_request_headers 指令 */
    ngx_flag_t                       pass_request_headers;
    /* proxy_pass_request_body 指令 */
    ngx_flag_t                       pass_request_body;

    /* proxy_ignore_client_abort 指令
     * 标志位，为 1 时表示与上游服务器交互时将不检查 Nginx 与下游客户端间的连接是否
     * 断开。也就是说，即使下游客户端主动关闭了连接，也不会中断与上游服务器间的交互 */
    ngx_flag_t                       ignore_client_abort;
    /* proxy_intercept_errors 指令
     * 当解析上游响应的包头时，如果解析后设置到 headers_in 结构体中的 status_n 错误码
     * 大于 400，则会试图把它与 error_page 中指定的错误码相匹配，如果匹配上，则发送
     * error_page 中指定的响应，否则继续返回上游服务器的错误码 */
    ngx_flag_t                       intercept_errors;
    /* buffering 标志位为 1 的情况下转发响应时才有意义。这时，如果 cycli_temp_file 为 1，
     * 则会复用临时文件中已经使用过的空间。不建议将cycli_temp_file 设为 1 */
    ngx_flag_t                       cyclic_temp_file;
    /* proxy_force_ranges 指令 */
    ngx_flag_t                       force_ranges;

    /* proxy_temp_path 指令
     * 在 buffering 标志位为 1 的情况下转发响应时，存放临时文件的路径 */
    ngx_path_t                      *temp_path;

    /* 不转发的头部。实际上是通过 ngx_http_upstream_hide_headers_hash 方法，根据
     * hide_headers 和 pass_headers 动态数组构造出的需要隐藏的 HTTP 头部散列表 */
    ngx_hash_t                       hide_headers_hash;
    /* proxy_hide_header 指令
     * 当转发上游响应头部(ngx_http_upstream_t 中 headers_in 结构体中的头部)给下游客户端时，
     * 如果不希望某些头部转发给下游，就设置到 hide_headers 动态数组中 */
    ngx_array_t                     *hide_headers;
    /* proxy_pass_header 指令
     * 当转发上游响应头部(ngx_http_upstream_t 中 headers_in 结构体中的头部)给下游客户端时，
     * upstream 机制默认不会转发如 "Date"、"Server" 之类的头部，如果确实希望直接转发它们到
     * 下游，就设置到 pass_headers 动态数组中 */
    ngx_array_t                     *pass_headers;

    /* proxy_bind 指令.
     * 连接上游服务器时使用的本机地址 */
    ngx_http_upstream_local_t       *local;
    /* proxy_socket_keepalive 指令 */
    ngx_flag_t                       socket_keepalive;

#if (NGX_HTTP_CACHE)
    /* proxy_cache 指令定义的共享内存区域 */
    ngx_shm_zone_t                  *cache_zone;
    ngx_http_complex_value_t        *cache_value;

    /* proxy_cache_min_uses 指令，默认请求 1 次将会被缓存 */
    ngx_uint_t                       cache_min_uses;
    /* proxy_cache_use_stale 指令 */
    ngx_uint_t                       cache_use_stale;
    /* proxy_cache_methods 指令，指定缓存特定的方法，默认缓存"GET"和"HEAD" */
    ngx_uint_t                       cache_methods;

    /* proxy_cache_max_range_offset 指令 */
    off_t                            cache_max_range_offset;

    /* proxy_cache_lock 指令 */
    ngx_flag_t                       cache_lock;
    /* proxy_cache_lock_timeout 指令 */
    ngx_msec_t                       cache_lock_timeout;
    /* proxy_cache_lock_age 指令 */
    ngx_msec_t                       cache_lock_age;

    /* proxy_cache_revalidate 指令 */
    ngx_flag_t                       cache_revalidate;
    /* proxy_cache_convert_head 指令 */
    ngx_flag_t                       cache_convert_head;
    /* proxy_cache_background_update 指令 */
    ngx_flag_t                       cache_background_update;

    ngx_array_t                     *cache_valid;
    /* proxy_cache_bypass 指令 */
    ngx_array_t                     *cache_bypass;
    /* proxy_cache_purge 指令 */
    ngx_array_t                     *cache_purge;
    ngx_array_t                     *no_cache;
#endif

    /* 当 ngx_http_upstream_t 中的 store 标志位为 1 时，如果需要将上游的响应存放到文件中，
     * store_lengths 将表示存放路径的长度，而 store_values 表示存放路径 */
    ngx_array_t                     *store_lengths;
    ngx_array_t                     *store_values;

#if (NGX_HTTP_CACHE)
    /* proxy_cache 指令 */
    signed                           cache:2;
#endif
    /* store 标志位的意义与 ngx_http_upstream_t 中的 store 相同 */
    signed                           store:2;
    /* 上面的 intercept_errors 标志位定义了 400 以上的错误码将会与 error_page 比较后
     * 再行处理，实际上这个规则是可以有一个例外情况的，如果将 intercept_404 标志位
     * 设为 1，当上游响应 404 时会直接转发这个错误码给下游，而不会去与 error_page
     * 进行比较 */
    unsigned                         intercept_404:1;
    /* 当该标志位为 1 时，将会根据 ngx_http_upstream_t 中 headers_in 结构体里的 X-Accel-Buffering
     * 头部(它的值会是 yes 和 no)来改变 buffering 标志位，当其值为 yes 时，buffering 标志位为 1。
     * 因此，change_buffering 为 1 时将有可能根据上游服务器返回的响应头部，动态地决定是以上游网速
     * 优先还是以下游网速优先 */
    unsigned                         change_buffering:1;
    unsigned                         pass_trailers:1;
    unsigned                         preserve_output:1;

#if (NGX_HTTP_SSL || NGX_COMPAT)
    ngx_ssl_t                       *ssl;
    ngx_flag_t                       ssl_session_reuse;

    /* proxy_ssl_name 指令 */
    ngx_http_complex_value_t        *ssl_name;
    /* proxy_ssl_server_name 指令 */
    ngx_flag_t                       ssl_server_name;
    /* proxy_ssl_verify 指令 */
    ngx_flag_t                       ssl_verify;
#endif

    /* 使用 upstream 的模块名称，仅用于记录日志 */
    ngx_str_t                        module;

    NGX_COMPAT_BEGIN(2)
    NGX_COMPAT_END
} ngx_http_upstream_conf_t;


typedef struct {
    ngx_str_t                        name;
    ngx_http_header_handler_pt       handler;
    ngx_uint_t                       offset;
    ngx_http_header_handler_pt       copy_handler;
    ngx_uint_t                       conf;
    ngx_uint_t                       redirect;  /* unsigned   redirect:1; */
} ngx_http_upstream_header_t;


typedef struct {
    ngx_list_t                       headers;
    ngx_list_t                       trailers;

    ngx_uint_t                       status_n;
    ngx_str_t                        status_line;

    ngx_table_elt_t                 *status;
    ngx_table_elt_t                 *date;
    ngx_table_elt_t                 *server;
    ngx_table_elt_t                 *connection;

    ngx_table_elt_t                 *expires;
    ngx_table_elt_t                 *etag;
    ngx_table_elt_t                 *x_accel_expires;
    ngx_table_elt_t                 *x_accel_redirect;
    ngx_table_elt_t                 *x_accel_limit_rate;

    ngx_table_elt_t                 *content_type;
    ngx_table_elt_t                 *content_length;

    ngx_table_elt_t                 *last_modified;
    ngx_table_elt_t                 *location;
    ngx_table_elt_t                 *accept_ranges;
    ngx_table_elt_t                 *www_authenticate;
    ngx_table_elt_t                 *transfer_encoding;
    ngx_table_elt_t                 *vary;

#if (NGX_HTTP_GZIP)
    ngx_table_elt_t                 *content_encoding;
#endif

    ngx_array_t                      cache_control;
    ngx_array_t                      cookies;

    off_t                            content_length_n;
    time_t                           last_modified_time;

    unsigned                         connection_close:1;
    unsigned                         chunked:1;
} ngx_http_upstream_headers_in_t;


typedef struct {
    ngx_str_t                        host;
    in_port_t                        port;
    ngx_uint_t                       no_port; /* unsigned no_port:1 */

    ngx_uint_t                       naddrs;
    ngx_resolver_addr_t             *addrs;

    struct sockaddr                 *sockaddr;
    socklen_t                        socklen;
    ngx_str_t                        name;

    ngx_resolver_ctx_t              *ctx;
} ngx_http_upstream_resolved_t;


typedef void (*ngx_http_upstream_handler_pt)(ngx_http_request_t *r,
    ngx_http_upstream_t *u);


struct ngx_http_upstream_s {
    /* 处理读事件的回调方法，每一个阶段都有不同的 read_event_handler.
     * 注意 ngx_http_upstream_t 和 ngx_http_request_t 都有该成员, 分别在 ngx_http_request_handler 和 
     * ngx_http_upstream_handler 中执行.
     */
    ngx_http_upstream_handler_pt     read_event_handler;
    /* 处理写事件的回调方法，每一个阶段都有不同的 write_event_handler */
    ngx_http_upstream_handler_pt     write_event_handler;

    /* 表示主动向上游服务器发起的连接 */
    ngx_peer_connection_t            peer;

    /* 当向下游客户端转发响应时（ngx_http_request_t 结构体中的 subrequest_in_memory 标志位为 0），
     * 如果打开了缓存且认为上游网速更快（conf 配置中的 buffering 标志位为 1），这时会使用 pipe
     * 成员来转发响应。在使用这种方式转发响应时，必须由 HTTP 模块在使用 upstream 机制前构造 pipe
     * 结构体，否则会出现严重的 coredump 错误 */
    ngx_event_pipe_t                *pipe;

    /* 以链表的形式把 ngx_buf_t 缓冲区链接起来，它表示所有需要发送到上游服务器的请求内容。
     * 所以，HTTP 模块实现的 create_request 回调方法就在于构造 request_bufs 链表 */
    ngx_chain_t                     *request_bufs;

    /* 定义了向下游发送响应的方式 */
    ngx_output_chain_ctx_t           output;
    ngx_chain_writer_ctx_t           writer;

    /* 使用 upstream 机制时的各种配置 */
    ngx_http_upstream_conf_t        *conf;
    ngx_http_upstream_srv_conf_t    *upstream;
#if (NGX_HTTP_CACHE)
    ngx_array_t                     *caches;
#endif

    /* HTTP 模块在实现 process_header 方法时，如果希望 upstream 直接转发响应，就需要把解析出的
     * 响应头部适配为 HTTP 的响应头部，同时需要把包头中的信息设置到 headers_in 结构体中，这样
     * 就会在xxx中把 headers_in 中设置的头部添加到要发送到下游客户端的响应头部 headers_out 中 */
    ngx_http_upstream_headers_in_t   headers_in;

    /* 用于解析主机域名 */
    ngx_http_upstream_resolved_t    *resolved;

    ngx_buf_t                        from_client;

    ngx_buf_t                        buffer;
    /* 来自上游服务器的响应包体的长度 */
    off_t                            length;

    /* out_bufs 在两种场景下有不同的意义：1. 当不需要转发包体，且使用默认的 input_filter 方法
     * （也就是 ngx_http_upstream_non_buffered_filter 方法）处理包体时，out_bufs 将会指向响应
     * 包体，事实上，out_bufs 链表中会产生多个 ngx_buf_t 缓冲区，每个缓冲区都指向 buffer 缓存
     * 中的一部分，而这里的一部分就是每次调用 recv 方法接收到的一段 TCP 流。
     * 2. 当需要转发响应包体到下游时（buffering 标志位为0，即以下游网速优先），这个链表指向上
     * 一次向下游转发响应到现在这段时间内接收自上游的缓存响应 */
    ngx_chain_t                     *out_bufs;
    /* 当需要转发响应包体到下游时（buffering 标志位为0，即以下游网速优先），它表示上一次向下游
     * 转发响应时没有发送完的内容 */
    ngx_chain_t                     *busy_bufs;
    /* 这个链表将用于回收 out_bufs 中已经发送给下游的 ngx_buf_t 结构体，这同样应用在 buffering
     * 标志位为 0（即以下游网速优先的场景）*/
    ngx_chain_t                     *free_bufs;

    /* 处理包体前的初始化方法，其中 data 参数用于传递用户数据结构，它实际就是
     * 下面的    input_filter_ctx 指针 */
    ngx_int_t                      (*input_filter_init)(void *data);
    /* 处理包体的方法。data 即为 input_filter_ctx 指针，bytes 则表示本次接收到的包体长度。
     * 返回 NGX_ERROR 时表示处理包体错误，请求需要结束，否则都将继续 upstream 流程 */
    ngx_int_t                      (*input_filter)(void *data, ssize_t bytes);
    /* 用于传递 HTTP 模块自定义的数据结构，在上面两个方法被回调时作为参数传递过去 */
    void                            *input_filter_ctx;

#if (NGX_HTTP_CACHE)
    ngx_int_t                      (*create_key)(ngx_http_request_t *r);
#endif
    /* 用于构造发往上游服务器的请求 */
    ngx_int_t                      (*create_request)(ngx_http_request_t *r);
    /* 与上游服务器的通信失败后，如果按照重试规则还需要再次向上游服务器发起连接，则会
     * 调用 reinit_request 方法 */
    ngx_int_t                      (*reinit_request)(ngx_http_request_t *r);
    /* 解析上游服务器返回响应的包头，返回 NGX_AGAIN 表示包头还没有接收完整，返回
     * NGX_HTTP_UPSTREAM_INVALID_HEADER 表示包头不合法，返回 NGX_ERROR 表示出现错误，
     * 返回 NGX_OK 表示解析到完整的包头 */
    ngx_int_t                      (*process_header)(ngx_http_request_t *r);
    void                           (*abort_request)(ngx_http_request_t *r);
    /* 请求结束时调用 */
    void                           (*finalize_request)(ngx_http_request_t *r,
                                         ngx_int_t rc);
    /* 在上游返回的响应出现 Location 或者 Refresh 头部表示重定向时，会通过 
     * ngx_http_upstream_process_headers 方法调用到可由 HTTP 模块实现的
     * rewrite_redirect 方法 */
    ngx_int_t                      (*rewrite_redirect)(ngx_http_request_t *r,
                                         ngx_table_elt_t *h, size_t prefix);
    ngx_int_t                      (*rewrite_cookie)(ngx_http_request_t *r,
                                         ngx_table_elt_t *h);

    ngx_msec_t                       timeout;

    /* 用于表示上游响应的错误码、包体长度等信息 */
    ngx_http_upstream_state_t       *state;

    /* 不使用文件缓存时没有意义 */
    ngx_str_t                        method;
    /* schema 和 uri 仅在记录日志时会用到，除此之外没有意义 */
    ngx_str_t                        schema;
    ngx_str_t                        uri;

#if (NGX_HTTP_SSL || NGX_COMPAT)
    ngx_str_t                        ssl_name;
#endif

    /* 目前仅用于表示是否需要清理资源，相当于一个标志位，实际不会调用到它所指向的方法 */
    ngx_http_cleanup_pt             *cleanup;

    /* 是否指定文件缓存路径的标志位 */
    unsigned                         store:1;
    /* 是否启用文件缓存 */
    unsigned                         cacheable:1;
    unsigned                         accel:1;
    /* 是否基于 SSL 协议访问上游服务器 */
    unsigned                         ssl:1;
#if (NGX_HTTP_CACHE)
    unsigned                         cache_status:3;
#endif

    /* 向下游转发上游的响应包体时，是否开启更大的内存及临时磁盘文件用于缓存来不及发送到
     * 下游的响应包体 */
    unsigned                         buffering:1;
    unsigned                         keepalive:1;
    unsigned                         upgrade:1;

    /* request_sent 表示是否已经向上游服务器发送了请求，当 request_sent 为 1 时，表示 upstream
     * 机制已经向上游服务器发送了全部或者部分的请求。事实上，这个标志位更多的是为了使用 
     * ngx_output_chain 方法发送请求，因为该方法发送请求时会自动把未发送完的 request_bufs 链表
     * 记录下来，为了防止反复发送重复请求，必须有 request_sent 标志位记录是否调用过
     * ngx_output_chain 方法 */
    unsigned                         request_sent:1;
    unsigned                         request_body_sent:1;
    unsigned                         request_body_blocked:1;
    /* 将上游服务器的响应划分为包头和包尾，如果把响应直接转发给客户端，header_sent 标志位表示
     * 包头是否发送，header_sent 为 1 时表示已经把包头转发给客户端了。如果不转发响应到客户端，
     * 则 header_sent 没有意义 */
    unsigned                         header_sent:1;
};


typedef struct {
    ngx_uint_t                      status;
    ngx_uint_t                      mask;
} ngx_http_upstream_next_t;


typedef struct {
    ngx_str_t   key;
    ngx_str_t   value;
    ngx_uint_t  skip_empty;
} ngx_http_upstream_param_t;


ngx_int_t ngx_http_upstream_create(ngx_http_request_t *r);
void ngx_http_upstream_init(ngx_http_request_t *r);
ngx_http_upstream_srv_conf_t *ngx_http_upstream_add(ngx_conf_t *cf,
    ngx_url_t *u, ngx_uint_t flags);
char *ngx_http_upstream_bind_set_slot(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
char *ngx_http_upstream_param_set_slot(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
ngx_int_t ngx_http_upstream_hide_headers_hash(ngx_conf_t *cf,
    ngx_http_upstream_conf_t *conf, ngx_http_upstream_conf_t *prev,
    ngx_str_t *default_hide_headers, ngx_hash_init_t *hash);


#define ngx_http_conf_upstream_srv_conf(uscf, module)                         \
    uscf->srv_conf[module.ctx_index]


extern ngx_module_t        ngx_http_upstream_module;
extern ngx_conf_bitmask_t  ngx_http_upstream_cache_method_mask[];
extern ngx_conf_bitmask_t  ngx_http_upstream_ignore_headers_masks[];


#endif /* _NGX_HTTP_UPSTREAM_H_INCLUDED_ */
