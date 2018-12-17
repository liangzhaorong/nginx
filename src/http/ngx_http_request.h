
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_HTTP_REQUEST_H_INCLUDED_
#define _NGX_HTTP_REQUEST_H_INCLUDED_


#define NGX_HTTP_MAX_URI_CHANGES           10
#define NGX_HTTP_MAX_SUBREQUESTS           50

/* must be 2^n */
#define NGX_HTTP_LC_HEADER_LEN             32


#define NGX_HTTP_DISCARD_BUFFER_SIZE       4096
#define NGX_HTTP_LINGERING_BUFFER_SIZE     4096


#define NGX_HTTP_VERSION_9                 9
#define NGX_HTTP_VERSION_10                1000
#define NGX_HTTP_VERSION_11                1001
#define NGX_HTTP_VERSION_20                2000

#define NGX_HTTP_UNKNOWN                   0x0001
#define NGX_HTTP_GET                       0x0002
#define NGX_HTTP_HEAD                      0x0004
#define NGX_HTTP_POST                      0x0008
#define NGX_HTTP_PUT                       0x0010
#define NGX_HTTP_DELETE                    0x0020
#define NGX_HTTP_MKCOL                     0x0040
#define NGX_HTTP_COPY                      0x0080
#define NGX_HTTP_MOVE                      0x0100
#define NGX_HTTP_OPTIONS                   0x0200
#define NGX_HTTP_PROPFIND                  0x0400
#define NGX_HTTP_PROPPATCH                 0x0800
#define NGX_HTTP_LOCK                      0x1000
#define NGX_HTTP_UNLOCK                    0x2000
#define NGX_HTTP_PATCH                     0x4000
#define NGX_HTTP_TRACE                     0x8000

#define NGX_HTTP_CONNECTION_CLOSE          1
#define NGX_HTTP_CONNECTION_KEEP_ALIVE     2


#define NGX_NONE                           1


#define NGX_HTTP_PARSE_HEADER_DONE         1

#define NGX_HTTP_CLIENT_ERROR              10
#define NGX_HTTP_PARSE_INVALID_METHOD      10
#define NGX_HTTP_PARSE_INVALID_REQUEST     11
#define NGX_HTTP_PARSE_INVALID_VERSION     12
#define NGX_HTTP_PARSE_INVALID_09_METHOD   13

#define NGX_HTTP_PARSE_INVALID_HEADER      14


/* unused                                  1 */
#define NGX_HTTP_SUBREQUEST_IN_MEMORY      2
#define NGX_HTTP_SUBREQUEST_WAITED         4
#define NGX_HTTP_SUBREQUEST_CLONE          8
#define NGX_HTTP_SUBREQUEST_BACKGROUND     16

#define NGX_HTTP_LOG_UNSAFE                1


#define NGX_HTTP_CONTINUE                  100
#define NGX_HTTP_SWITCHING_PROTOCOLS       101
#define NGX_HTTP_PROCESSING                102

#define NGX_HTTP_OK                        200
#define NGX_HTTP_CREATED                   201
#define NGX_HTTP_ACCEPTED                  202
#define NGX_HTTP_NO_CONTENT                204
#define NGX_HTTP_PARTIAL_CONTENT           206

#define NGX_HTTP_SPECIAL_RESPONSE          300
#define NGX_HTTP_MOVED_PERMANENTLY         301
#define NGX_HTTP_MOVED_TEMPORARILY         302
#define NGX_HTTP_SEE_OTHER                 303
#define NGX_HTTP_NOT_MODIFIED              304
#define NGX_HTTP_TEMPORARY_REDIRECT        307
#define NGX_HTTP_PERMANENT_REDIRECT        308

#define NGX_HTTP_BAD_REQUEST               400
#define NGX_HTTP_UNAUTHORIZED              401
#define NGX_HTTP_FORBIDDEN                 403
#define NGX_HTTP_NOT_FOUND                 404
#define NGX_HTTP_NOT_ALLOWED               405
#define NGX_HTTP_REQUEST_TIME_OUT          408
#define NGX_HTTP_CONFLICT                  409
#define NGX_HTTP_LENGTH_REQUIRED           411
#define NGX_HTTP_PRECONDITION_FAILED       412
#define NGX_HTTP_REQUEST_ENTITY_TOO_LARGE  413
#define NGX_HTTP_REQUEST_URI_TOO_LARGE     414
#define NGX_HTTP_UNSUPPORTED_MEDIA_TYPE    415
#define NGX_HTTP_RANGE_NOT_SATISFIABLE     416
#define NGX_HTTP_MISDIRECTED_REQUEST       421
#define NGX_HTTP_TOO_MANY_REQUESTS         429


/* Our own HTTP codes */

/* The special code to close connection without any response */
#define NGX_HTTP_CLOSE                     444

#define NGX_HTTP_NGINX_CODES               494

#define NGX_HTTP_REQUEST_HEADER_TOO_LARGE  494

#define NGX_HTTPS_CERT_ERROR               495
#define NGX_HTTPS_NO_CERT                  496

/*
 * We use the special code for the plain HTTP requests that are sent to
 * HTTPS port to distinguish it from 4XX in an error page redirection
 */
#define NGX_HTTP_TO_HTTPS                  497

/* 498 is the canceled code for the requests with invalid host name */

/*
 * HTTP does not define the code for the case when a client closed
 * the connection while we are processing its request so we introduce
 * own code to log such situation when a client has closed the connection
 * before we even try to send the HTTP header to it
 */
#define NGX_HTTP_CLIENT_CLOSED_REQUEST     499


#define NGX_HTTP_INTERNAL_SERVER_ERROR     500
#define NGX_HTTP_NOT_IMPLEMENTED           501
#define NGX_HTTP_BAD_GATEWAY               502
#define NGX_HTTP_SERVICE_UNAVAILABLE       503
#define NGX_HTTP_GATEWAY_TIME_OUT          504
#define NGX_HTTP_VERSION_NOT_SUPPORTED     505
#define NGX_HTTP_INSUFFICIENT_STORAGE      507


#define NGX_HTTP_LOWLEVEL_BUFFERED         0xf0
#define NGX_HTTP_WRITE_BUFFERED            0x10
#define NGX_HTTP_GZIP_BUFFERED             0x20
#define NGX_HTTP_SSI_BUFFERED              0x01
#define NGX_HTTP_SUB_BUFFERED              0x02
#define NGX_HTTP_COPY_BUFFERED             0x04


typedef enum {
    NGX_HTTP_INITING_REQUEST_STATE = 0,
    NGX_HTTP_READING_REQUEST_STATE,
    NGX_HTTP_PROCESS_REQUEST_STATE,

    NGX_HTTP_CONNECT_UPSTREAM_STATE,
    NGX_HTTP_WRITING_UPSTREAM_STATE,
    NGX_HTTP_READING_UPSTREAM_STATE,

    NGX_HTTP_WRITING_REQUEST_STATE,
    NGX_HTTP_LINGERING_CLOSE_STATE,
    NGX_HTTP_KEEPALIVE_STATE
} ngx_http_state_e;


typedef struct {
    ngx_str_t                         name;
    ngx_uint_t                        offset;
    ngx_http_header_handler_pt        handler;
} ngx_http_header_t;


typedef struct {
    ngx_str_t                         name;
    ngx_uint_t                        offset;
} ngx_http_header_out_t;


typedef struct {
    ngx_list_t                        headers;

    ngx_table_elt_t                  *host;
    ngx_table_elt_t                  *connection;
    ngx_table_elt_t                  *if_modified_since;
    ngx_table_elt_t                  *if_unmodified_since;
    ngx_table_elt_t                  *if_match;
    ngx_table_elt_t                  *if_none_match;
    ngx_table_elt_t                  *user_agent;
    ngx_table_elt_t                  *referer;
    ngx_table_elt_t                  *content_length;
    ngx_table_elt_t                  *content_range;
    ngx_table_elt_t                  *content_type;

    ngx_table_elt_t                  *range;
    ngx_table_elt_t                  *if_range;

    ngx_table_elt_t                  *transfer_encoding;
    ngx_table_elt_t                  *te;
    ngx_table_elt_t                  *expect;
    ngx_table_elt_t                  *upgrade;

#if (NGX_HTTP_GZIP || NGX_HTTP_HEADERS)
    ngx_table_elt_t                  *accept_encoding;
    ngx_table_elt_t                  *via;
#endif

    ngx_table_elt_t                  *authorization;

    ngx_table_elt_t                  *keep_alive;

#if (NGX_HTTP_X_FORWARDED_FOR)
    ngx_array_t                       x_forwarded_for;
#endif

#if (NGX_HTTP_REALIP)
    ngx_table_elt_t                  *x_real_ip;
#endif

#if (NGX_HTTP_HEADERS)
    ngx_table_elt_t                  *accept;
    ngx_table_elt_t                  *accept_language;
#endif

#if (NGX_HTTP_DAV)
    ngx_table_elt_t                  *depth;
    ngx_table_elt_t                  *destination;
    ngx_table_elt_t                  *overwrite;
    ngx_table_elt_t                  *date;
#endif

    ngx_str_t                         user;
    ngx_str_t                         passwd;

    ngx_array_t                       cookies;

    ngx_str_t                         server;
    off_t                             content_length_n;
    time_t                            keep_alive_n;

    unsigned                          connection_type:2;
    unsigned                          chunked:1;
    unsigned                          msie:1;
    unsigned                          msie6:1;
    unsigned                          opera:1;
    unsigned                          gecko:1;
    unsigned                          chrome:1;
    unsigned                          safari:1;
    unsigned                          konqueror:1;
} ngx_http_headers_in_t;


typedef struct {
    ngx_list_t                        headers;
    ngx_list_t                        trailers;

    ngx_uint_t                        status;
    ngx_str_t                         status_line;

    ngx_table_elt_t                  *server;
    ngx_table_elt_t                  *date;
    ngx_table_elt_t                  *content_length;
    ngx_table_elt_t                  *content_encoding;
    ngx_table_elt_t                  *location;
    ngx_table_elt_t                  *refresh;
    ngx_table_elt_t                  *last_modified;
    ngx_table_elt_t                  *content_range;
    ngx_table_elt_t                  *accept_ranges;
    ngx_table_elt_t                  *www_authenticate;
    ngx_table_elt_t                  *expires;
    ngx_table_elt_t                  *etag;

    ngx_str_t                        *override_charset;

    size_t                            content_type_len;
    ngx_str_t                         content_type;
    ngx_str_t                         charset;
    u_char                           *content_type_lowcase;
    ngx_uint_t                        content_type_hash;

    ngx_array_t                       cache_control;
    ngx_array_t                       link;

    off_t                             content_length_n;
    off_t                             content_offset;
    time_t                            date_time;
    time_t                            last_modified_time;
} ngx_http_headers_out_t;


typedef void (*ngx_http_client_body_handler_pt)(ngx_http_request_t *r);

typedef struct {
    /* 存放 HTTP 包体的临时文件 */
    ngx_temp_file_t                  *temp_file;
    /* 接收 HTTP 包体的缓冲区链表。当包体需要全部存放在内存中时，如果一块
     * ngx_buf_t 缓冲区无法存放完，这时就需要使用 ngx_chain_t 链表来存放 */
    ngx_chain_t                      *bufs;
    /* 直接接收 HTTP 包体的缓存 */
    ngx_buf_t                        *buf;
    /* 根据 content-length 头部和已接收到的包体长度，计算出的还需要接收的包体长度 */
    off_t                             rest;
    off_t                             received;
    ngx_chain_t                      *free;
    ngx_chain_t                      *busy;
    ngx_http_chunked_t               *chunked;
    /* HTTP 包体接收完毕后的回调方法 */
    ngx_http_client_body_handler_pt   post_handler;
} ngx_http_request_body_t;


typedef struct ngx_http_addr_conf_s  ngx_http_addr_conf_t;

typedef struct {
    ngx_http_addr_conf_t             *addr_conf;
    ngx_http_conf_ctx_t              *conf_ctx;

#if (NGX_HTTP_SSL || NGX_COMPAT)
    ngx_str_t                        *ssl_servername;
#if (NGX_PCRE)
    ngx_http_regex_t                 *ssl_servername_regex;
#endif
#endif

    ngx_chain_t                      *busy;
    ngx_int_t                         nbusy;

    ngx_chain_t                      *free;

    unsigned                          ssl:1;
    unsigned                          proxy_protocol:1;
} ngx_http_connection_t;


typedef void (*ngx_http_cleanup_pt)(void *data);

typedef struct ngx_http_cleanup_s  ngx_http_cleanup_t;

struct ngx_http_cleanup_s {
    /* 由 HTTP 模块提供的清理资源的回调方法 */
    ngx_http_cleanup_pt               handler;
    /* 希望给上面的 handler 传递的参数 */
    void                             *data;
    /* 一个请求可能有多个 ngx_http_cleanup_t 清理方法，这些清理方法间就是通过
     * next 指针连接成单链表 */
    ngx_http_cleanup_t               *next;
};


typedef ngx_int_t (*ngx_http_post_subrequest_pt)(ngx_http_request_t *r,
    void *data, ngx_int_t rc);

typedef struct {
    ngx_http_post_subrequest_pt       handler;
    void                             *data;
} ngx_http_post_subrequest_t;


typedef struct ngx_http_postponed_request_s  ngx_http_postponed_request_t;

struct ngx_http_postponed_request_s {
    ngx_http_request_t               *request;
    ngx_chain_t                      *out;
    ngx_http_postponed_request_t     *next;
};


typedef struct ngx_http_posted_request_s  ngx_http_posted_request_t;

struct ngx_http_posted_request_s {
    /* 指向当前待处理子请求的 ngx_http_request_t 结构体 */
    ngx_http_request_t               *request;
    /* 指向下一个子请求，如果没有，则为 NULL 空指针 */
    ngx_http_posted_request_t        *next;
};


/* 由 HTTP 模块实现的 handler 处理方法 */
typedef ngx_int_t (*ngx_http_handler_pt)(ngx_http_request_t *r);
typedef void (*ngx_http_event_handler_pt)(ngx_http_request_t *r);


struct ngx_http_request_s {
    uint32_t                          signature;         /* "HTTP" */

    /* 这个请求对应的客户端连接 */
    ngx_connection_t                 *connection;

    /* 指向存放所有 HTTP 模块的上下文结构体的指针数组 */
    void                            **ctx;
    /* 指向请求对应的存放 main 级别配置结构体的指针数组 */
    void                            **main_conf;
    /* 指向请求对应的存放 srv 级别配置结构体的指针数组 */
    void                            **srv_conf;
    /* 指向请求对应的存放 loc 级别配置结构体的指针数组 */
    void                            **loc_conf;

    /* 在接收完 HTTP 头部，第一次在业务上处理 HTTP 请求时，HTTP 框架提供的处理方法是 ngx_http_process_request。
     * 但如果该方法无法一次处理完该请求的全部业务，在归还控制权到 epoll 事件模块后，该请求再次被回调时，将通过
     * ngx_http_request_handler 方法来处理，而这个方法中对于可读事件的处理就是调用 read_event_handler 处理请求。
     * 也就是说，HTTP 模块希望在底层处理请求的读事件时，重新实现 read_event_handler 方法 */
    ngx_http_event_handler_pt         read_event_handler;
    /* 与 read_event_handler 回调方法类似，如果 ngx_http_request_handler 方法判断当前事件是写事件，则调用
     * write_event_handler 处理请求 */
    ngx_http_event_handler_pt         write_event_handler;

#if (NGX_HTTP_CACHE)
    ngx_http_cache_t                 *cache;
#endif

    ngx_http_upstream_t              *upstream;
    ngx_array_t                      *upstream_states;
                                         /* of ngx_http_upstream_state_t */

    /* 表示这个请求的内存池，在 ngx_http_free_request 方法中销毁。它与 ngx_connection_t 中的内存池意义不同，当
     * 请求释放时，TCP 连接可能并没有关闭，这时请求的内存池会销毁，但 ngx_connection_t 中的内存池并不会被销毁 */
    ngx_pool_t                       *pool;
    /* 用于接收 HTTP 请求内容的缓冲区，主要用于接收 HTTP 头部 */
    ngx_buf_t                        *header_in;

    /* ngx_http_process_request_headers 方法在接收、解析完 HTTP 请求的头部后，会把解析完的每一个 HTTP 头部加入
     * 到 headers_in 的 headers 链表中，同时会构造 headers_in 中的其他成员 */
    ngx_http_headers_in_t             headers_in;
    /* HTTP 模块会把想要发送的 HTTP 响应信息放到 headers_out 中，期望 HTTP 框架将 headers_out 中的成员序列化
     * 为 HTTP 响应包发送给用户 */
    ngx_http_headers_out_t            headers_out;

    /* 接收 HTTP 请求中包体的数据结构 */
    ngx_http_request_body_t          *request_body;

    /* 延迟关闭连接的时间 */
    time_t                            lingering_time;
    /* 当前请求初始化时的时间。start_sec 是格林威治时间(1970-1-1 0:0:0)但当前时间的秒数。如果这个请求是子请求，
     * 则该时间是子请求的生成时间；如果这个请求是用户发来的请求，则是在建立起 TCP 连接后，第一次接收到可读事件时的时间 */
    time_t                            start_sec;
    ngx_msec_t                        start_msec;

    ngx_uint_t                        method;
    ngx_uint_t                        http_version;

    ngx_str_t                         request_line;
    ngx_str_t                         uri;
    ngx_str_t                         args;
    ngx_str_t                         exten;
    ngx_str_t                         unparsed_uri;

    ngx_str_t                         method_name;
    ngx_str_t                         http_protocol;
    ngx_str_t                         schema;

    /* 表示需要发送给客户端的 HTTP 响应。out 中保存着由 headers_out 中序列化后的表示 HTTP 头部的 TCP 流。在调用
     * ngx_http_output_filter 方法后，out 中还会保存待发送的 HTTP 包体，它是实现异步发送 HTTP 响应的关键 */
    ngx_chain_t                      *out;
    /* 当前请求既可能是用户发来的请求，也可能是派生出的子请求，而 main 则标识一系列相关的派生子请求的原始请求，我们
     * 一般可通过 main 和当前请求的地址是否相等来判断当前请求是否为用户发来的原始请求 */
    ngx_http_request_t               *main;
    /* 当前请求的父请求。注意，父请求未必是原始请求 */
    ngx_http_request_t               *parent;
    ngx_http_postponed_request_t     *postponed;
    ngx_http_post_subrequest_t       *post_subrequest;
    /* 所有的子请求都是通过 posted_requests 这个单链表来链接起来的，执行 post 子请求时调用的 
     * ngx_http_run_posted_requests 方法就是通过遍历该单链表来执行子请求的 */
    ngx_http_posted_request_t        *posted_requests;

    /* 全局的 ngx_http_phase_engine_t 结构体中定义了一个 ngx_http_phase_handler_t 回调方法组成的数组，而 phase_handler
     * 成员则与该数组配合使用，表示请求下次应当执行以 phase_handler 作为序号指定的数组中的回调方法。HTTP 框架正是以这种
     * 方法把各个 HTTP 模块集成起来处理请求的 */
    ngx_int_t                         phase_handler;
    /* 表示 NGX_HTTP_CONTENT_PHASE 阶段提供给 HTTP 模块处理请求的一种方式，content_handler 指向 HTTP 模块实现的请求处理方法
     * 有些 HTTP 模块可能仅希望在这个处理请求内容的阶段，仅仅针对某种请求唯一生效，而不是对所有的请求生效。如，仅当请求
     * 的 URI 匹配了配置文件中的某个 location 块时，再根据 location 块下的配置选择一个 HTTP 模块执行它的 handler 处理方法，
     * 并以此替代 NGX_HTTP_CONTENT_PHASE 阶段的其他 handler 方法（这些 handler 方法对于该请求将得不到执行）*/
    ngx_http_handler_pt               content_handler;
    /* 在 NGX_HTTP_ACCESS_PHASE 阶段需要判断请求是否具有访问权限时，通过 access_code 来传递 HTTP 模块的 handler 回调方法
     * 的返回值，如果 access_code 为 0，则表示请求具备访问权限，反之则说明请求不具备访问权限 */
    ngx_uint_t                        access_code;

    /*
     * 变量值如果可以被缓存，则它一定只能缓存在每一个 HTTP 请求内，对于 Nginx
     * 这样的 web 服务器，不可能为不同的 HTTP 请求缓存同一个值。
     * variables 数组存储所有序列化了的变量值，数组下标即为索引号.
     */
    ngx_http_variable_value_t        *variables;

#if (NGX_PCRE)
    ngx_uint_t                        ncaptures;
    int                              *captures;
    u_char                           *captures_data;
#endif

    size_t                            limit_rate;
    size_t                            limit_rate_after;

    /* used to learn the Apache compatible response length without a header */
    size_t                            header_size;

    /* HTTP 请求的全部长度，包括 HTTP 包体 */
    off_t                             request_length;

    ngx_uint_t                        err_status;

    ngx_http_connection_t            *http_connection;
    ngx_http_v2_stream_t             *stream;

    ngx_http_log_handler_pt           log_handler;

    /* 在这个请求中如果打开了某些资源，并需要在请求结束时释放，那么都需要在把定义的释放资源方法添加
     * 到 cleanup 成员中 */
    ngx_http_cleanup_t               *cleanup;

    /* 表示当前请求的引用计数。如，在使用 subrequest 功能时，依附在这个请求上的子请求数目会返回到 count 上，
     * 每增加一个子请求，count 数就加 1。其中任何一个子请求派生出新的子请求时，对应的原始请求(main 指针指向的请求)
     * 的 count 值都要加 1。又如，当我们接收 HTTP 包体时，由于这也是一个异步调用，所以 count 上也需要加 1，这样在
     * 结束请求时，就不会在 count 引用计数未清零时销毁请求 */
    unsigned                          count:16;
    unsigned                          subrequests:8;
    /* 阻塞标志位，目前仅由 aio 使用 */
    unsigned                          blocked:8;

    /* 标志位，为 1 时表示当前请求正在使用异步文件 IO */
    unsigned                          aio:1;

    unsigned                          http_state:4;

    /* URI with "/." and on Win32 with "//" */
    unsigned                          complex_uri:1;

    /* URI with "%" */
    unsigned                          quoted_uri:1;

    /* URI with "+" */
    unsigned                          plus_in_uri:1;

    /* URI with " " */
    unsigned                          space_in_uri:1;

    unsigned                          invalid_header:1;

    unsigned                          add_uri_to_alias:1;
    unsigned                          valid_location:1;
    unsigned                          valid_unparsed_uri:1;
    /* 标志位，为 1 时表示 URL 发生过 rewrite 重写 */
    unsigned                          uri_changed:1;
    /* 表示使用 rewrite 重写 URL 的次数。因为目前最多可以更改 10 次，所以 uri_changes 初始化为 11，
     * 而每重写 URL 一次就把 uri_changes 减 1，一旦 uri_changes 等于 0，则向用户返回失败 */
    unsigned                          uri_changes:4;

    unsigned                          request_body_in_single_buf:1;
    unsigned                          request_body_in_file_only:1;
    unsigned                          request_body_in_persistent_file:1;
    unsigned                          request_body_in_clean_file:1;
    unsigned                          request_body_file_group_access:1;
    unsigned                          request_body_file_log_level:3;
    unsigned                          request_body_no_buffering:1;

    unsigned                          subrequest_in_memory:1;
    unsigned                          waited:1;

#if (NGX_HTTP_CACHE)
    unsigned                          cached:1;
#endif

#if (NGX_HTTP_GZIP)
    unsigned                          gzip_tested:1;
    unsigned                          gzip_ok:1;
    unsigned                          gzip_vary:1;
#endif

    unsigned                          proxy:1;
    unsigned                          bypass_cache:1;
    unsigned                          no_cache:1;

    /*
     * instead of using the request context data in
     * ngx_http_limit_conn_module and ngx_http_limit_req_module
     * we use the single bits in the request structure
     */
    unsigned                          limit_conn_set:1;
    unsigned                          limit_req_set:1;

#if 0
    unsigned                          cacheable:1;
#endif

    unsigned                          pipeline:1;
    unsigned                          chunked:1;
    unsigned                          header_only:1;
    unsigned                          expect_trailers:1;
    /* 标志位，为 1 时表示当前请求是 keepalive 请求 */
    unsigned                          keepalive:1;
    /* 延迟关闭标志位，为 1 时表示需要延迟关闭。如，在接收完 HTTP 头部时如果发现还有包体存在，该标志位
     * 会设为 1，而放弃接收包体时则会设为 0 */
    unsigned                          lingering_close:1;
    /* 标志位，为 1 时表示正在丢弃 HTTP 请求中的包体 */
    unsigned                          discard_body:1;
    unsigned                          reading_body:1;
    /* 标志位，为 1 时表示请求的当前状态是在做内部跳转 */
    unsigned                          internal:1;
    unsigned                          error_page:1;
    unsigned                          filter_finalize:1;
    unsigned                          post_action:1;
    unsigned                          request_complete:1;
    unsigned                          request_output:1;
    /* 标志位，为 1 时表示发送给客户端的 HTTP 响应头部已经发送。在调用 ngx_http_send_header 方法
     * 后，若已经成功地启动响应头部发送流程，该标志位就会置为 1，用来防止反复地发送头部 */
    unsigned                          header_sent:1;
    unsigned                          expect_tested:1;
    unsigned                          root_tested:1;
    unsigned                          done:1;
    unsigned                          logged:1;

    /* 表示缓冲中是否有待发送内容的标志位 */
    unsigned                          buffered:4;

    unsigned                          main_filter_need_in_memory:1;
    unsigned                          filter_need_in_memory:1;
    unsigned                          filter_need_temporary:1;
    unsigned                          preserve_body:1;
    unsigned                          allow_ranges:1;
    unsigned                          subrequest_ranges:1;
    unsigned                          single_range:1;
    unsigned                          disable_not_modified:1;
    unsigned                          stat_reading:1;
    unsigned                          stat_writing:1;
    unsigned                          stat_processing:1;

    unsigned                          background:1;
    unsigned                          health_check:1;

    /* used to parse HTTP headers */

    /* 状态机解析 HTTP 时使用 state 来表示当前的解析状态 */
    ngx_uint_t                        state;

    ngx_uint_t                        header_hash;
    ngx_uint_t                        lowcase_index;
    u_char                            lowcase_header[NGX_HTTP_LC_HEADER_LEN];

    u_char                           *header_name_start;
    u_char                           *header_name_end;
    u_char                           *header_start;
    u_char                           *header_end;

    /*
     * a memory that can be reused after parsing a request line
     * via ngx_http_ephemeral_t
     */

    u_char                           *uri_start;
    u_char                           *uri_end;
    u_char                           *uri_ext;
    u_char                           *args_start;
    u_char                           *request_start;
    u_char                           *request_end;
    u_char                           *method_end;
    u_char                           *schema_start;
    u_char                           *schema_end;
    u_char                           *host_start;
    u_char                           *host_end;
    u_char                           *port_start;
    u_char                           *port_end;

    unsigned                          http_minor:16;
    unsigned                          http_major:16;
};


typedef struct {
    ngx_http_posted_request_t         terminal_posted_request;
} ngx_http_ephemeral_t;


#define ngx_http_ephemeral(r)  (void *) (&r->uri_start)


extern ngx_http_header_t       ngx_http_headers_in[];
extern ngx_http_header_out_t   ngx_http_headers_out[];


#define ngx_http_set_log_request(log, r)                                      \
    ((ngx_http_log_ctx_t *) log->data)->current_request = r


#endif /* _NGX_HTTP_REQUEST_H_INCLUDED_ */
