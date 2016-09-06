/*
* @Author: detailyang
* @Date:   2016-09-05 11:10:38
* @Last Modified by:   detailyang
* @Last Modified time: 2016-09-06 23:45:25
*/


#ifndef DDEBUG
#define DDEBUG 1
#endif
#include "ddebug.h"

#include <ngx_core.h>
#include <ngx_http.h>
#include <nginx.h>

#define NGX_AUTH_FILE_BUFFER_SIZE 4096

typedef struct { 
    ngx_open_file_t *file;
} ngx_http_auth_file_loc_conf_t;

static char *
ngx_http_auth_file(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static ngx_int_t
ngx_http_auth_file_post_conf(ngx_conf_t *cf);
static void *
ngx_http_auth_file_create_loc_conf(ngx_conf_t *cf);
static ngx_int_t
ngx_http_auth_file_handler(ngx_http_request_t *r);
static void
ngx_http_auth_file_flush(ngx_open_file_t *file, ngx_log_t *log);
static char *
ngx_http_auth_file_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);
static ngx_int_t
ngx_http_auth_file_read(ngx_http_request_t *r);

static ngx_command_t  ngx_http_auth_file_module_commands[] = {

    { ngx_string("auth_file"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
      ngx_http_auth_file,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL},
      ngx_null_command
};


static ngx_http_module_t  ngx_http_auth_file_module_ctx = {
    NULL,                                   /* preconfiguration */
    ngx_http_auth_file_post_conf,           /* postconfiguration */

    NULL,                                   /* create main configuration */
    NULL,                                   /* init main configuration */

    NULL,                                   /* create server configuration */
    NULL,                                   /* merge server configuration */

    ngx_http_auth_file_create_loc_conf,     /* create location configuration */
    ngx_http_auth_file_merge_loc_conf       /* merge location configuration */
};


ngx_module_t ngx_http_auth_file_module = {
    NGX_MODULE_V1,
    &ngx_http_auth_file_module_ctx,        /* module context */
    ngx_http_auth_file_module_commands,    /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


static char *
ngx_http_auth_file(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_http_auth_file_loc_conf_t *aflcf = conf;    
    
    ngx_str_t                  *value;
    
    
    value = cf->args->elts;
    aflcf->file = ngx_conf_open_file(cf->cycle, &value[1]);
    if (aflcf->file == NULL) {
        return NGX_CONF_ERROR;
    }
    dd("file %*s", (int)aflcf->file->name.len, aflcf->file->name.data);
    // workaround to hook when reopen file
    aflcf->file->flush = ngx_http_auth_file_flush;
     
    return NGX_CONF_OK;
}

static void *
ngx_http_auth_file_create_loc_conf(ngx_conf_t *cf) {
    ngx_http_auth_file_loc_conf_t    *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_auth_file_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    /*
     * set by ngx_pcalloc():
     * conf->file = NULL
     */

    return conf;
}

static char *
ngx_http_auth_file_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_auth_file_loc_conf_t    *prev = parent;
    ngx_http_auth_file_loc_conf_t    *conf = child;

    if (conf->file == NULL) {
        conf->file = prev->file;
    }

    return NGX_CONF_OK;
}

static ngx_int_t
ngx_http_auth_file_post_conf(ngx_conf_t *cf) {
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
    h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }
    *h = ngx_http_auth_file_handler;
    
    return NGX_OK;
}

static ngx_int_t
ngx_http_auth_file_read(ngx_http_request_t *r) {
        u_char                          *p, *last, *end;
    size_t                           len;
    ngx_fd_t             fd;
    u_char                           buf[NGX_AUTH_FILE_BUFFER_SIZE];
    ssize_t                          n;
    ngx_http_auth_file_loc_conf_t   *aflcf;
    ngx_array_t *passwords;
    ngx_str_t *pwd;
    
    aflcf = ngx_http_get_module_loc_conf(r, ngx_http_auth_file_module);
    dd("file %u", (int)ngx_http_auth_file_module.ctx_index);
    
    passwords = ngx_array_create(r->pool, 4, sizeof(ngx_str_t));
    if (passwords == NULL) {
        return NGX_ERROR;
    }
    
    fd = ngx_open_file(aflcf->file->name.data, NGX_FILE_RDONLY, NGX_FILE_OPEN, 0);
    if (fd == NGX_INVALID_FILE) {
        ngx_log_error(NGX_LOG_EMERG, r->connection->log, ngx_errno,
                           ngx_open_file_n " \"%V\" failed", &aflcf->file->name);
        return NGX_ERROR;
    }
     
    len = 0;
    last = buf;
    // blocking IO
    do {
        n = ngx_read_fd(fd, last, NGX_AUTH_FILE_BUFFER_SIZE - len);
        if (n == -1) {
            dd(ngx_read_fd_n " \"%*s\" failed", (int)aflcf->file->name.len, aflcf->file->name.data);
            goto cleanup;
        }

        end = last + n;

        if (len && n == 0) {
            *end++ = LF;
        }

        p = buf;

        for ( ;; ) {
            last = ngx_strlchr(last, end, LF);

            if (last == NULL) {
                goto cleanup;
            }

            len = last++ - p;

            if (len && p[len - 1] == CR) {
                len--;
            }

            if (len) {
                pwd = ngx_array_push(passwords);
                if (pwd == NULL) {
                    passwords = NULL;
                    goto cleanup;
                }

                pwd->len = len;
                pwd->data = ngx_pnalloc(r->pool, len);

                if (pwd->data == NULL) {
                    passwords->nelts--;
                    passwords = NULL;
                    goto cleanup;
                }

                ngx_memcpy(pwd->data, p, len);
            }

            p = last;
        }

        len = end - p;

        if (len == NGX_AUTH_FILE_BUFFER_SIZE) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                               "too long line in \"%V\"", &aflcf->file->name);
            goto cleanup;
        }

        ngx_memmove(buf, p, len);
        last = buf + len;

    } while (n != 0); 
    
cleanup:

    if (ngx_close_file(fd) == NGX_FILE_ERROR) {
        ngx_conf_log_error(NGX_LOG_ALERT, r->connection->log, ngx_errno,
                           ngx_close_file_n " \"%V\" failed", &aflcf->file->name);
    }

    ngx_memzero(buf, NGX_AUTH_FILE_BUFFER_SIZE);
    
    return NGX_OK;
}

static ngx_int_t
ngx_http_auth_file_handler(ngx_http_request_t *r) {
    ngx_http_auth_file_loc_conf_t   *aflcf;
    
    aflcf = ngx_http_get_module_loc_conf(r, ngx_http_auth_file_module);
    ngx_http_auth_file_read(r);
    
    return NGX_OK;
}

static void
ngx_http_auth_file_flush(ngx_open_file_t *file, ngx_log_t *log) {
    dd("reopen the file %*s", (int)file->name.len, file->name.data);
}