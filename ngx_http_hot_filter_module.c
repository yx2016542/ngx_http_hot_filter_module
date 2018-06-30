
/*
 * Copyright (C) 2017-2018 jiajie8301@163.com  Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#define NGX_HTTP_HOT_MODE_OFF 0
#define NGX_HTTP_HOT_MODE_ON  1

typedef struct {
    ngx_int_t       mode;

    ngx_str_t       header;
    ngx_str_t       header_lc;
    ngx_uint_t      header_hash;
} ngx_http_hot_loc_conf_t;

typedef struct {
	ngx_str_t hot_value;
}ngx_http_hot_value_ctx_t;

static ngx_str_t ngx_http_hot_value = ngx_string("hot_value");

static ngx_int_t ngx_http_hot_header_filter(ngx_http_request_t *r);
static char * ngx_http_hot_set_mode(ngx_conf_t *cf, ngx_command_t *cmd, 
    void *conf);
static char * ngx_http_hot_set_header(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static void * ngx_http_hot_create_loc_conf(ngx_conf_t *cf);
static char * ngx_http_hot_merge_loc_conf(ngx_conf_t *cf, void *parent, 
    void *child);
static ngx_int_t ngx_http_hot_filter_init(ngx_conf_t *cf);
static ngx_int_t ngx_http_hot_value_add_variables(ngx_conf_t *cf);
static ngx_int_t ngx_http_hot_value_handler_variable(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data);

static ngx_command_t ngx_http_hot_filter_commands[] = {

    { ngx_string("hot"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_hot_set_mode,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_hot_loc_conf_t, mode),
      NULL },

    { ngx_string("hot_header"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_hot_set_header,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_hot_loc_conf_t, header),
      NULL },

#if 0
    { ngx_string("hot_prefix"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_hot_loc_conf_t, prefix),
      NULL },
#endif
      
    ngx_null_command
};


static ngx_http_module_t ngx_http_hot_filter_module_ctx = {
    ngx_http_hot_value_add_variables,   /* preconfiguration */
    ngx_http_hot_filter_init,         /* postconfiguration */

    NULL,                               /* create main configuration */
    NULL,                               /* init main configuration */

    NULL,                               /* create server configuration */
    NULL,                               /* merge server configuration */

    ngx_http_hot_create_loc_conf,     /* create location configuration */
    ngx_http_hot_merge_loc_conf       /* merge location configuration */
};


ngx_module_t ngx_http_hot_filter_module = {
    NGX_MODULE_V1,
    &ngx_http_hot_filter_module_ctx,  /* module context */
    ngx_http_hot_filter_commands,     /* module directives */
    NGX_HTTP_MODULE,                    /* module type */
    NULL,                               /* init master */
    NULL,                               /* init module */
    NULL,                               /* init process */  
    NULL,                               /* init thread */
    NULL,                               /* exit thread */
    NULL,                               /* exit process */
    NULL,                               /* exit master */
    NGX_MODULE_V1_PADDING
};

static ngx_http_output_header_filter_pt ngx_http_next_header_filter;


/* TODO
 */


static ngx_int_t
ngx_http_hot_header_filter(ngx_http_request_t *r)
{
    ngx_int_t                   found;
    ngx_uint_t                  i;
    u_char                      *value;
    size_t                      value_len;
    ngx_time_t                  *tp;
    ngx_list_part_t             *part;
    ngx_table_elt_t             *headers;
    ngx_table_elt_t             *h;
    ngx_http_hot_loc_conf_t   *slcf;
    ngx_http_hot_value_ctx_t    *ctx;	

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http hot filter");

    slcf = ngx_http_get_module_loc_conf(r, ngx_http_hot_filter_module);

    if (r != r->main || slcf->mode == NGX_HTTP_HOT_MODE_OFF){
        return ngx_http_next_header_filter(r);
    }

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http hot filter header \"%V\" in mode %d", 
                   &slcf->header, slcf->mode);

    ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_hot_value_ctx_t));
    if(ctx == NULL){
	ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "mem alloc value ctx is error");

	return NGX_ERROR;
    }

    ngx_http_set_ctx(r, ctx, ngx_http_hot_filter_module);
    ngx_str_null(&ctx->hot_value);

    found = 0;
    part = &r->headers_out.headers.part;
    headers = part->elts;

    for (i = 0; /* void */; i++) {

        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }

            part = part->next;
            headers = part->elts;
            i = 0;
        }

        if (headers[i].hash != slcf->header_hash 
            || headers[i].key.len != slcf->header.len
            || headers[i].lowcase_key == NULL) 
        {
            continue;
        }

        if (ngx_strncmp(headers[i].lowcase_key, slcf->header_lc.data, 
                        slcf->header_lc.len) != 0) 
        {
            continue;
        }

        found = 1;
	
	ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0, "get hot filter found:%d, value:%V, hot_value:%s, value_len:%d", found, &headers[i].value, headers[i].value.data, headers[i].value.len);
	
	ctx->hot_value.data = ngx_pcalloc(r->pool, (headers[i].value.len + 1));	
        if(ctx->hot_value.data == NULL){
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "pcalloc hot value mem is error");
		return NGX_ERROR;
	}

	ngx_sprintf(ctx->hot_value.data, "%s", headers[i].value.data);
	ctx->hot_value.len = headers[i].value.len;

	ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0, "*******get hot_value:%V", &ctx->hot_value);

        break;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http hot filter found: %d", found);

    return ngx_http_next_header_filter(r);
}


static char *
ngx_http_hot_set_mode(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_hot_loc_conf_t *slcf = conf;

    ngx_str_t                   *value;

    value = cf->args->elts;

    if (ngx_strcmp(value[1].data, "off") == 0) {
        slcf->mode = NGX_HTTP_HOT_MODE_OFF;
    } else if (ngx_strcmp(value[1].data, "on") == 0) {
        slcf->mode = NGX_HTTP_HOT_MODE_ON;
    } else {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid parameter \"%V\" for directive \"hot\"",
                           &value[1]);
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


static char *
ngx_http_hot_set_header(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    char *rv;
    ngx_http_hot_loc_conf_t *slcf = conf;

    if ((rv = ngx_conf_set_str_slot(cf, cmd, conf)) != NGX_CONF_OK) {
        return rv;
    }

    slcf->header_lc.len = slcf->header.len;
    slcf->header_lc.data = ngx_pcalloc(cf->pool, slcf->header_lc.len + 1);
    if (slcf->header_lc.data == NULL) {
        return "alloc for header_lc error";
    }

    slcf->header_hash = ngx_hash_strlow(slcf->header_lc.data, slcf->header.data,
                                        slcf->header.len);

    return NGX_CONF_OK;
}


static void *
ngx_http_hot_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_hot_loc_conf_t *slcf;

    slcf = ngx_pcalloc(cf->pool, sizeof(ngx_http_hot_loc_conf_t));
    if (slcf == NULL) {
        return NULL;
    }

    slcf->mode = NGX_CONF_UNSET;
    slcf->header_hash = NGX_CONF_UNSET_UINT;

    return slcf;    
}


static char *
ngx_http_hot_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_hot_loc_conf_t *prev = parent;
    ngx_http_hot_loc_conf_t *conf = child;

    ngx_conf_merge_value(conf->mode, prev->mode, NGX_HTTP_HOT_MODE_OFF);

    ngx_conf_merge_str_value(conf->header, prev->header, "Proxy-Hot");

    ngx_conf_merge_str_value(conf->header_lc, prev->header_lc, "proxy-hot");

    ngx_conf_merge_uint_value(conf->header_hash, prev->header_hash,
                              ngx_hash_key_lc((u_char *) "Proxy-Hot", 
                                               sizeof("Proxy-Hot") - 1));

    //ngx_conf_merge_str_value(conf->prefix, prev->prefix, "p");

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_hot_filter_init(ngx_conf_t *cf)
{
    ngx_http_next_header_filter = ngx_http_top_header_filter;
    ngx_http_top_header_filter = ngx_http_hot_header_filter;

    return NGX_OK;
}

static ngx_int_t 
ngx_http_hot_value_add_variables(ngx_conf_t *cf)
{
	ngx_http_variable_t *var;
	
	//var = ngx_http_add_variable(cf, &ngx_http_hot_value, NGX_HTTP_VAR_NOHASH|NGX_HTTP_VAR_NOCACHEABLE);
	var = ngx_http_add_variable(cf, &ngx_http_hot_value, NGX_HTTP_VAR_NOCACHEABLE);
	if(var == NULL){
		return NGX_ERROR;
	}

	var->get_handler = ngx_http_hot_value_handler_variable;

	return NGX_OK;
}

static ngx_int_t 
ngx_http_hot_value_handler_variable(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data)
{
	ngx_http_hot_value_ctx_t *ctx;
	
	ctx = ngx_http_get_module_ctx(r, ngx_http_hot_filter_module);
	if (ctx == NULL){
		v->not_found = 1;
		return NGX_OK;
	} 	

	v->valid = 1;
	v->not_found = 0;
	u_char *buff = ngx_pcalloc(r->pool, 64);
	if(buff == NULL){
		return NGX_ERROR;
	}
	
	
	v->len = ctx->hot_value.len;
	
	ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "get hot_value.len =%d", ctx->hot_value.len);	

	if (v->len > 0){
		ngx_sprintf(buff, "%s", ctx->hot_value.data);
	}
	else{
		ngx_memset(buff, 0, 64);
	}

	v->data = buff;

	return NGX_OK;
}

