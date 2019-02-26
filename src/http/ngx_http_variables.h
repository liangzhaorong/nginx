
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_HTTP_VARIABLES_H_INCLUDED_
#define _NGX_HTTP_VARIABLES_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


/* 描述变量的值 */
typedef ngx_variable_value_t  ngx_http_variable_value_t;

#define ngx_http_variable(v)     { sizeof(v) - 1, 1, 0, 0, 0, (u_char *) v }

typedef struct ngx_http_variable_s  ngx_http_variable_t;

typedef void (*ngx_http_set_variable_pt) (ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
typedef ngx_int_t (*ngx_http_get_variable_pt) (ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);

/*
 * 表示对应的变量值可以改变，也就是对一个请求内的同一个变量可以反复地修改其变量值。
 * 反过来说，如果没有这个标志位，一旦对一个赋过值的变量重新赋值就会报错。对于内部
 * 变量，再深入看看可以知道，没有这个标志位的变量，是不允许一次以上定义同一变量名
 * 的，因为多次设置变量的解析方法与修改变量值是等价的，我们常在 Nginx 启动时发现
 * 错误 "the duplicate ...variable"，就是这个原因。对于由 set 指令等设置的外部变量，
 * 它们一定允许反复修改同一变量的值，所以必须加上该标志位.
 */
#define NGX_HTTP_VAR_CHANGEABLE   1
/*
 * 不要缓存这个变量的值，每次使用变量时都需要重新解析。为什么不允许缓存呢？因为有些
 * 请求的变量会在执行中伴随着 URL 跳转等动作反复改变，如 $uri 这个变量，如果读取到了
 * 上一次缓存的值是无法确定其是否正确的.
 */
#define NGX_HTTP_VAR_NOCACHEABLE  2
/*
 * 将变量索引，加速访问。为什么又要缓存一些变量的值呢？因为有些变量在一次请求的执行中
 * 是永远不变的，例如 $request_uri 这个变量，它表示最初接收自客户端的请求 URI，自然不会
 * 变化，那么缓存之后的反复使用速度就会更快.
 */
#define NGX_HTTP_VAR_INDEXED      4
/*
 * 不要把这个变量 hash 到散列表中。为什么会想着使一个变量不做散列优化呢？这是因为散列表
 * 也是需要消耗内存的，如果某个模块设计了一个可选变量提供给其他模块使用，并且要求如果有
 * 其他模块使用该变量就必须索引化再使用（即不能调用 ngx_http_get_variable 方法来获取变量
 * 值），这样，这个变量就不用浪费散列表的存储空间了.
 */
#define NGX_HTTP_VAR_NOHASH       8
#define NGX_HTTP_VAR_WEAK         16
#define NGX_HTTP_VAR_PREFIX       32


/*
 * 该结构体负责指定一个变量名字符串，以及如何去解析出相应的变量值。所有的变量名定义
 * ngx_http_variable_t 都会保存在全局唯一的 ngx_http_core_main_conf_t 对象中，解析
 * 变量时也是围绕着它进行.
 */
struct ngx_http_variable_s {
    /* 字符串变量名，如 $remote_addr, 当然不包含 '$' 符号 */
    ngx_str_t                     name;   /* must be first to build the hash */
    /*
     * 如果需要变量最初赋值时就进行变量值的设置，那么可以实现 set_handler 方法。
     * 如果我们定义的内部变量允许在 nginx.conf 中以 set 方式又重新设置其值，那么
     * 可以实现该方法（参考 args 参数，它就是一个内部变量，同时也允许 set 方法在
     * nginx.conf 里重新设置其值）.
     */
    ngx_http_set_variable_pt      set_handler;
    /*
     * 每次获取一个变量的值时，会先调用 get_handler 方法，所以 Nginx 的官方模块
     * 变量的解析大都在此方法中完成.
     */
    ngx_http_get_variable_pt      get_handler;
    /* 这个整数是作为参数传递给 get_handler、set_handler 回调方法使用 */
    uintptr_t                     data;
    /* 变量的特性，见上面的 NGX_HTTP_VAR_* */
    ngx_uint_t                    flags;
    /* 变量值在请求中的缓存数组中的索引 */
    ngx_uint_t                    index;
};

#define ngx_http_null_variable  { ngx_null_string, NULL, NULL, 0, 0, 0 }


ngx_http_variable_t *ngx_http_add_variable(ngx_conf_t *cf, ngx_str_t *name,
    ngx_uint_t flags);
ngx_int_t ngx_http_get_variable_index(ngx_conf_t *cf, ngx_str_t *name);
ngx_http_variable_value_t *ngx_http_get_indexed_variable(ngx_http_request_t *r,
    ngx_uint_t index);
ngx_http_variable_value_t *ngx_http_get_flushed_variable(ngx_http_request_t *r,
    ngx_uint_t index);

ngx_http_variable_value_t *ngx_http_get_variable(ngx_http_request_t *r,
    ngx_str_t *name, ngx_uint_t key);

ngx_int_t ngx_http_variable_unknown_header(ngx_http_variable_value_t *v,
    ngx_str_t *var, ngx_list_part_t *part, size_t prefix);


#if (NGX_PCRE)

typedef struct {
    ngx_uint_t                    capture;
    ngx_int_t                     index;
} ngx_http_regex_variable_t;


typedef struct {
    ngx_regex_t                  *regex;
    ngx_uint_t                    ncaptures;
    ngx_http_regex_variable_t    *variables;
    ngx_uint_t                    nvariables;
    ngx_str_t                     name;
} ngx_http_regex_t;


typedef struct {
    ngx_http_regex_t             *regex;
    void                         *value;
} ngx_http_map_regex_t;


ngx_http_regex_t *ngx_http_regex_compile(ngx_conf_t *cf,
    ngx_regex_compile_t *rc);
ngx_int_t ngx_http_regex_exec(ngx_http_request_t *r, ngx_http_regex_t *re,
    ngx_str_t *s);

#endif


typedef struct {
    ngx_hash_combined_t           hash;
#if (NGX_PCRE)
    ngx_http_map_regex_t         *regex;
    ngx_uint_t                    nregex;
#endif
} ngx_http_map_t;


void *ngx_http_map_find(ngx_http_request_t *r, ngx_http_map_t *map,
    ngx_str_t *match);


ngx_int_t ngx_http_variables_add_core_vars(ngx_conf_t *cf);
ngx_int_t ngx_http_variables_init_vars(ngx_conf_t *cf);


extern ngx_http_variable_value_t  ngx_http_variable_null_value;
extern ngx_http_variable_value_t  ngx_http_variable_true_value;


#endif /* _NGX_HTTP_VARIABLES_H_INCLUDED_ */
