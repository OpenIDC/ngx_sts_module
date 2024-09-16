/***************************************************************************
 *
 * Copyright (C) 2018-2024 - ZmartZone Holding BV
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * @Author: Hans Zandbelt - hans.zandbelt@openidc.com
 *
 **************************************************************************/

#include <nginx.h>
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_http_config.h>

#include <oauth2/cfg.h>
#include <oauth2/mem.h>
#include <oauth2/version.h>

#include "oauth2/nginx.h"
#include "oauth2/sts.h"

typedef struct ngx_sts_config {
	oauth2_sts_cfg_t *cfg;
	ngx_http_complex_value_t source_token;
	ngx_str_t target_token;
	oauth2_log_t *log;
} ngx_sts_config;

static ngx_int_t ngx_sts_target_token_request_variable(
    ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data)
{
	ngx_sts_config *cfg = (ngx_sts_config *)data;

	ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
		       "sts request variable");

	v->len = cfg->target_token.len;
	v->data = cfg->target_token.data;

	if (v->len) {
		v->valid = 1;
		v->no_cacheable = 0;
		v->not_found = 0;
	} else {
		v->not_found = 1;
	}

	return NGX_OK;
}

static char *ngx_sts_set_variables(ngx_conf_t *cf, ngx_command_t *cmd,
				   void *conf)
{
	char *rv = NGX_CONF_ERROR;
	// ngx_http_core_loc_conf_t *clcf = NULL;
	ngx_sts_config *cfg = (ngx_sts_config *)conf;
	ngx_http_compile_complex_value_t ccv;
	ngx_str_t *value = NULL;
	ngx_http_variable_t *v;

	//	clcf = ngx_http_conf_get_module_loc_conf(cf,
	// ngx_http_core_module); 	if ((clcf == NULL) || (cfg == NULL)) {
	// rv = "internal error: ngx_http_core_loc_conf_t or "
	//"ngx_sts_config is null..."; 		goto end;
	//	}
	//	clcf->handler = ngx_sts_handler;

	value = cf->args->elts;
	ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));
	ccv.cf = cf;
	ccv.value = &value[1];
	ccv.complex_value = &cfg->source_token;

	if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
		rv = "ngx_http_compile_complex_value failed";
		goto end;
	}

	if (value[2].data[0] != '$') {
		ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
				   "invalid variable name \"%V\"", &value[2]);
		goto end;
	}

	value[2].len--;
	value[2].data++;

	v = ngx_http_add_variable(cf, &value[2], 0);
	if (v == NULL) {
		rv = "ngx_http_add_variable failed";
		goto end;
	}

	v->get_handler = ngx_sts_target_token_request_variable;
	v->data = (uintptr_t)cfg;

	rv = NGX_CONF_OK;

end:

	return rv;
}

OAUTH2_NGINX_CFG_FUNC_ARGS1(sts, ngx_sts_config, passphrase,
			    oauth2_crypto_passphrase_set, NULL)
OAUTH2_NGINX_CFG_FUNC_ARGS2(sts, ngx_sts_config, cache, oauth2_cfg_set_cache,
			    NULL)
OAUTH2_NGINX_CFG_FUNC_ARGS4(sts, ngx_sts_config, exchange, sts_cfg_set_exchange,
			    cfg->cfg)

static ngx_command_t ngx_sts_commands[] = {
    OAUTH2_NGINX_CMD(1, sts, STSCryptoPassphrase, passphrase),
    OAUTH2_NGINX_CMD(12, sts, STSCache, cache),
    OAUTH2_NGINX_CMD(3 | NGX_CONF_TAKE5, sts, STSExchange, exchange),
    OAUTH2_NGINX_CMD(2, sts, "STSVariables", variables), ngx_null_command};

static void ngx_sts_cleanup(void *data)
{
	ngx_sts_config *conf = (ngx_sts_config *)data;
	oauth2_sts_cfg_free(NULL, conf->cfg);
}

static void *ngx_sts_create_loc_conf(ngx_conf_t *cf)
{
	ngx_sts_config *conf = NULL;
	ngx_pool_cleanup_t *cln = NULL;

	char path[255];

	conf = ngx_pcalloc(cf->pool, sizeof(ngx_sts_config));
	conf->log = NULL;

	// TODO: path?
	sprintf(path, "%p", conf);

	//	oauth2_log_sink_t *log_sink_nginx =
	// oauth2_mem_alloc(sizeof(oauth2_log_sink_t));
	// log_sink_nginx->callback = oauth2_log_nginx;
	//	//	// TODO: get the log level from NGINX...
	//	log_sink_nginx->level = LMO_LOG_TRACE1;
	//	log_sink_nginx->ctx = cf->log;
	//	oauth2_log_t *log = oauth2_log_init(log_sink_nginx->level,
	// log_sink_nginx);
	oauth2_log_t *log = oauth2_log_init(OAUTH2_LOG_TRACE1, NULL);

	conf->cfg = oauth2_sts_cfg_create(log, path);

	cln = ngx_pool_cleanup_add(cf->pool, 0);
	if (cln == NULL)
		goto end;

	cln->handler = ngx_sts_cleanup;
	cln->data = conf;

	// ngx_memzero(&conf->source_token, sizeof(ngx_http_complex_value_t));
	// ngx_memzero(&conf->target_token, sizeof(ngx_http_complex_value_t));

	// fprintf(stderr, " ## ngx_sts_create_loc_conf: %p (log=%p)\n", conf,
	//	cf->log);

	// ngx_log_error_core(NGX_LOG_NOTICE, cf->log, 0, "# %s: %s",
	// "ngx_sts_create_loc_conf: %p", conf);

end:

	return conf;
}

static char *ngx_sts_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
	ngx_sts_config *prev = parent;
	ngx_sts_config *conf = child;

	oauth2_sts_cfg_merge(NULL, conf->cfg, prev->cfg, conf->cfg);

	// TODO: merge conf->source_token and conf->target_token?
	// ngx_memzero(&conf->source_token, sizeof(ngx_http_complex_value_t));
	// ngx_memzero(&conf->target_token, sizeof(ngx_http_complex_value_t));

	// ngx_log_error_core(NGX_LOG_NOTICE, cf->log, 0, "# %s: %s",
	// "ngx_sts_merge_loc_conf: %p->%p", prev, conf);

	// fprintf(stderr, " ## ngx_sts_merge_loc_conf: %p->%p (log=%p)\n",
	// prev, 	conf, cf->log);

	return NGX_CONF_OK;
}

static ngx_int_t ngx_sts_post_config(ngx_conf_t *cf);

// clang-format off
static ngx_http_module_t ngx_sts_module_ctx = {
		NULL,						/* preconfiguration              */
		ngx_sts_post_config,		/* postconfiguration             */

		NULL,						/* create main configuration     */
		NULL,						/* init main configuration       */

		NULL,						/* create server configuration   */
		NULL,						/* merge server configuration    */

		ngx_sts_create_loc_conf,	/* create location configuration */
		ngx_sts_merge_loc_conf		/* merge location configuration  */
};

ngx_module_t ngx_sts_module = {
		NGX_MODULE_V1,
		&ngx_sts_module_ctx,	/* module context    */
		ngx_sts_commands,		/* module directives */
		NGX_HTTP_MODULE,		/* module type       */
		NULL,					/* init master       */
		NULL,					/* init module       */
		NULL,					/* init process      */
		NULL,					/* init thread       */
		NULL,					/* exit thread       */
		NULL,					/* exit process      */
		NULL,					/* exit master       */
		NGX_MODULE_V1_PADDING
};
// clang-format on

static ngx_int_t ngx_sts_handler(ngx_http_request_t *r);

static ngx_int_t ngx_sts_post_config(ngx_conf_t *cf)
{
	ngx_int_t rv = NGX_ERROR;
	ngx_http_handler_pt *h = NULL;
	ngx_http_core_main_conf_t *cmcf = NULL;

	cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

	h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
	if (h == NULL)
		goto end;

	*h = ngx_sts_handler;

	rv = NGX_OK;

end:

	return rv;
}

static ngx_int_t ngx_sts_handler(ngx_http_request_t *r)
{
	ngx_int_t rv = NGX_DECLINED;
	bool rc = false;
	oauth2_nginx_request_context_t *ctx = NULL;
	ngx_sts_config *cfg = NULL;
	ngx_str_t ngx_source_token;
	char *source_token = NULL, *target_token = NULL;
	oauth2_http_status_code_t status_code = 0;

	if (r != r->main)
		goto end;

	cfg = (ngx_sts_config *)ngx_http_get_module_loc_conf(r, ngx_sts_module);
	if (cfg == NULL) {
		oauth2_warn(ctx->log,
			    "ngx_http_get_module_loc_conf returned NULL");
		goto end;
	}

	ctx = oauth2_nginx_request_context_init(r);
	if (ctx == NULL) {
		oauth2_warn(ctx->log,
			    "oauth2_nginx_request_context_init returned NULL");
		goto end;
	}

	if (sts_cfg_get_type(cfg->cfg) == STS_TYPE_DISABLED) {
		oauth2_debug(ctx->log, "disabled");
		goto end;
	}

	if (ngx_http_complex_value(r, &cfg->source_token, &ngx_source_token) !=
	    NGX_OK) {
		oauth2_warn(
		    ctx->log,
		    "ngx_http_complex_value failed to obtain source_token");
		goto end;
	}

	if (ngx_source_token.len == 0) {
		oauth2_warn(ctx->log,
			    "ngx_http_complex_value ngx_source_token.len=0");
		goto end;
	}

	source_token = oauth2_strndup((const char *)ngx_source_token.data,
				      ngx_source_token.len);

	oauth2_debug(ctx->log, "enter: source_token=%s, initial_request=%d",
		     source_token, (r != r->main));

	rc = sts_handler(ctx->log, cfg->cfg, source_token, NULL, &target_token,
			 &status_code);

	oauth2_debug(ctx->log, "target_token=%s (rc=%d)",
		     target_token ? target_token : "(null)", rc);

	if (rc == false) {
		if ((status_code >= 400) && (status_code < 500)) {
			r->headers_out.status = (status_code < 500)
						    ? NGX_HTTP_UNAUTHORIZED
						    : (ngx_uint_t)status_code;
			rv = NGX_ERROR;
		} else {
			rv = status_code;
		}
		goto end;
	}

	if (target_token == NULL)
		goto end;

	cfg->target_token.len = strlen(target_token);
	cfg->target_token.data = ngx_palloc(r->pool, cfg->target_token.len);
	ngx_memcpy(cfg->target_token.data, (unsigned char *)target_token,
		   cfg->target_token.len);

	// TODO: set response, right?
	rv = NGX_OK;

end:

	if (source_token)
		oauth2_mem_free(source_token);
	if (target_token)
		oauth2_mem_free(target_token);

	// hereafter we destroy the log object...
	oauth2_debug(ctx->log, "leave: %d", rv);

	if (ctx)
		oauth2_nginx_request_context_free(ctx);

	return rv;
}
