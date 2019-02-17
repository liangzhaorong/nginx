
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_EVENT_PIPE_H_INCLUDED_
#define _NGX_EVENT_PIPE_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>


typedef struct ngx_event_pipe_s  ngx_event_pipe_t;

/* 处理接收自上游的包体的回调方法原型 */
typedef ngx_int_t (*ngx_event_pipe_input_filter_pt)(ngx_event_pipe_t *p,
                                                    ngx_buf_t *buf);
/* 向下游发送响应的回调方法原型 */
typedef ngx_int_t (*ngx_event_pipe_output_filter_pt)(void *data,
                                                     ngx_chain_t *chain);


/* 注：该结构体仅用于转发响应 */
struct ngx_event_pipe_s {
    /* Nginx 与上游服务器间的连接 */
    ngx_connection_t  *upstream;
    /* Nginx 与下游客户端间的连接 */
    ngx_connection_t  *downstream;

    /* 直接接收自上游服务器的缓冲区链表，注意，这个链表中的顺序是逆序的，也就是说，
     * 链表前端的 ngx_buf_t 缓冲区指向的是后接收到的响应，而后端的 ngx_buf_t 缓冲区
     * 指向的是先接收到的响应。因此，raw_bufs 链表仅在接收响应时使用 */
    ngx_chain_t       *free_raw_bufs;
    /* 表示接收到的上游响应缓冲区。通常，in 链表是在 input_filter 方法中设置的，可参考
     * ngx_event_pipe_copy_input_filter 方法，它会将接收到的缓冲区设置到 in 链表中 */
    ngx_chain_t       *in;
    /* 指向刚刚接收到的一个缓冲区 */
    ngx_chain_t      **last_in;

    ngx_chain_t       *writing;

    /* 保存着将要发送给客户端的缓冲区链表。在写入临时文件成功时，会把 in 链表中写入
     * 文件的缓冲区添加到 out 链表中 */
    ngx_chain_t       *out;
    /* 等待释放的缓冲区 */
    ngx_chain_t       *free;
    /* 表示上次调用 ngx_http_output_filter 方法发送响应时没有发送完的缓冲区链表。
     * 这个链表中的缓冲区已经保存到请求的 out 链表中，busy 仅用于记录还有多大的
     * 响应正等待发送 */
    ngx_chain_t       *busy;

    /*
     * the input filter i.e. that moves HTTP/1.1 chunks
     * from the raw bufs to an incoming chain
     */

    /* 处理接收到的来自上游服务器的缓冲区。一般使用 upstream 机制默认提供的
     * ngx_event_pipe_copy_input_filter 方法作为 input_filter */
    ngx_event_pipe_input_filter_pt    input_filter;
    /* 用于 input_filter 方法的成员，一般将它设置为 ngx_http_request_t 结构体的地址 */
    void                             *input_ctx;

    /* 表示向下游发送响应的方法，默认使用 ngx_http_upstream_output_filter 作为 output_filter */
    ngx_event_pipe_output_filter_pt   output_filter;
    /* 指向 ngx_http_request_t 结构体 */
    void                             *output_ctx;

#if (NGX_THREADS || NGX_COMPAT)
    ngx_int_t                       (*thread_handler)(ngx_thread_task_t *task,
                                                      ngx_file_t *file);
    void                             *thread_ctx;
    ngx_thread_task_t                *thread_task;
#endif

    /* 标志位，为 1 时表示当前已经读取到上游的响应 */
    unsigned           read:1;
    /* 标志位，为 1 时表示启用文件缓存 */
    unsigned           cacheable:1;
    /* 标志位，为 1 时表示接收上游响应时一次只能接收一个 ngx_buf_t 缓冲区 */
    unsigned           single_buf:1;
    /* 标志位，为 1 时表示一旦不再接收上游响应包体，将尽可能地立刻释放缓冲区。所谓尽可能是指，
     * 一旦这个缓冲区没有被引用，如没有用于写入临时文件或用于向下游客户端释放，就把缓冲区指向
     * 的内存释放给 pool 内存池 */
    unsigned           free_bufs:1;
    /* 提供给 HTTP 模块在 input_filter 方法中使用的标志位，表示 Nginx 与上游间的交互已经结束。
     * 如果 HTTP 模块在解析包体时，认为从业务上需要结束与上游间的连接，那么可以把 upstream_done
     * 标志位置为 1 */
    unsigned           upstream_done:1;
    /* Nginx 与上游服务器之间的连接出现错误时，upstream_error 标志位为 1，一般当接收上游响应
     * 超时，或者调用 recv 接收出现错误时，就会把该标志位置为 1 */
    unsigned           upstream_error:1;
    /* 表示 Nginx 与上游的连接状态。当 Nginx 与上游的连接已经关闭时，upstream_eof 标志位为 1 */
    unsigned           upstream_eof:1;
    /* 表示暂时阻塞住读取上游响应的流程，期待通过向下游发送响应来清理出空闲的缓冲区，再用空出的
     * 缓冲区接收响应。也就是说，blocked 标志位为 1 时会在 ngx_event_pipe 方法的循环中先调用
     * ngx_event_pipe_write_to_downstream 方法发送响应，然后再次调用 ngx_event_pipe_read_upstream
     * 方法读取上游的响应 */
    unsigned           upstream_blocked:1;
    /* 标志位，为 1 表示 Nginx 与下游客户端间的交互已经结束 */
    unsigned           downstream_done:1;
    /* 标志位，为 1 时表示 Nginx 与下游客户端的连接出现错误。一般时向下游发送响应超时，或者使用
     * ngx_http_output_filter 方法发送响应却返回 NGX_ERROR 时，将该标志位置为 1 */
    unsigned           downstream_error:1;
    /* 标志位，为 1 时会试图复用临时文件中曾经使用过的空间。不推荐设置为 1 */
    unsigned           cyclic_temp_file:1;
    unsigned           aio:1;

    /* 表示已经分配的缓冲区数目，allocated 受到 bufs.num 的限制 */
    ngx_int_t          allocated;
    /* bufs 记录了接收上游响应的内存缓冲区大小，其中 bufs.size 表示每个内存缓冲区的大小，
     * 而 bufs.num 表示最多可以有 num 个接收缓冲区 */
    ngx_bufs_t         bufs;
    /* 用于设置、比较缓冲区链表中 ngx_buf_t 结构体的 tag 标志位 */
    ngx_buf_tag_t      tag;

    /* 设置 busy 缓冲区中待发送的响应长度触发值，当达到 busy_size 长度时，必须等待
     * busy 缓冲区发送了足够的内容，才能继续发送 out 和 in 缓冲区中的内容 */
    ssize_t            busy_size;

    /* 已经接收到上游响应包体长度 */
    off_t              read_length;
    off_t              length;

    /* 与 ngx_http_upstream_conf_t 配置结构体中的 max_temp_file_size 含义相同，同时它们的
     * 值也是相等的，表示临时文件的最大长度 */
    off_t              max_temp_file_size;
    /* 与 ngx_http_upstream_conf_t 配置结构体中的 temp_file_write_size 含义相同，同时它们的
     * 值也是相等的，表示一次写入临时文件时的最大长度 */
    ssize_t            temp_file_write_size;

    /* 读取上游响应的超时时间 */
    ngx_msec_t         read_timeout;
    /* 向下游发送响应的超时时间 */
    ngx_msec_t         send_timeout;
    /* 向下游发送响应时，TCP 连接中设置的 send_lowat "水位" */
    ssize_t            send_lowat;

    /* 用于分配内存缓冲区的连接池对象 */
    ngx_pool_t        *pool;
    /* 用于记录日志的 ngx_log_t 对象 */
    ngx_log_t         *log;

    /* 表示在接收上游服务器响应头部阶段，已经读取到的响应包体 */
    ngx_chain_t       *preread_bufs;
    /* 表示在接收上游服务器响应头部阶段，已经读取到的响应包体长度 */
    size_t             preread_size;
    ngx_buf_t         *buf_to_file;

    size_t             limit_rate;
    time_t             start_sec;

    /* 存放上游响应的临时文件，最大长度由 max_temp_file_size 成员限制 */
    ngx_temp_file_t   *temp_file;

    /* STUB */ int     num;
};


ngx_int_t ngx_event_pipe(ngx_event_pipe_t *p, ngx_int_t do_write);
ngx_int_t ngx_event_pipe_copy_input_filter(ngx_event_pipe_t *p, ngx_buf_t *buf);
ngx_int_t ngx_event_pipe_add_free_buf(ngx_event_pipe_t *p, ngx_buf_t *b);


#endif /* _NGX_EVENT_PIPE_H_INCLUDED_ */
