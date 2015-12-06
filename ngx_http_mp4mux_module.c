
/*
 * Copyright (C) Igor Sysoev
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <nginx.h>

#if (NGX_FREEBSD)
#include <sys/endian.h>
#endif

//#include <endia.h>
#include "ngx_http_mp4mux_list.h"

//#include <valgrind/memcheck.h>

#define MAX_FILE 10
#define MAX_ATOM_SIZE 16*1024*1024
#define SENDFILE_MAX_CHUNK 128*1024

#define MP4MUX_BUFFERED 0x80

#if __BYTE_ORDER == __LITTLE_ENDIAN
#define ATOM(n1,n2,n3,n4) (((uint32_t)n4<<24)|((uint32_t)n3<<16)|((uint32_t)n2<<8)|(uint32_t)n1)
#else
#define ATOM(n1,n2,n3,n4) (((uint32_t)n1<<24)|((uint32_t)n2<<16)|((uint32_t)n3<<8)|(uint32_t)n4)
#endif

#ifndef __packed
#define __packed __attribute__((packed))
#endif

/*static void *__pcalloc(size_t n)
{
	void *ptr = malloc(n);
	memset(ptr, 0, n);
	return ptr;
}

#define ngx_pcalloc(p,n) __pcalloc(n)
#define ngx_palloc(p,n) malloc(n)*/

typedef struct {
	uint32_t size;
	uint32_t type;
	u_char data[0];
} __packed mp4_atom_hdr_t;

typedef struct {
	mp4_atom_hdr_t hdr;
	uint32_t major;
	uint32_t minor;
	uint32_t brands[0];
} __packed mp4_atom_ftyp_t;

typedef struct {
	mp4_atom_hdr_t hdr;
	uint32_t version:8;
	uint32_t flags:24;
	uint32_t ctime;
	uint32_t mtime;
	uint32_t timescale;
	uint32_t duration;
	uint32_t pref_rate;
	uint16_t pref_vol;
	uint8_t reserved[10];
	uint8_t matrix[36];
	uint32_t preview_time;
	uint32_t preview_duration;
	uint32_t poster_time;
	uint32_t selection_time;
	uint32_t selection_duration;
	uint32_t current_time;
	uint32_t next_track_id;
} __packed mp4_atom_mvhd_t;

typedef struct {
	mp4_atom_hdr_t hdr;
	uint32_t version:8;
	uint32_t flags:24;
	uint32_t ctime;
	uint32_t mtime;
	uint32_t timescale;
	uint32_t duration;
	uint16_t lang;
	uint16_t q;
} __packed mp4_atom_mdhd_t;

typedef struct {
	mp4_atom_hdr_t hdr;
	uint32_t version:8;
	uint32_t flags:24;
	uint32_t sample_size;
	uint32_t sample_cnt;
	uint32_t tbl[0];
} __packed mp4_atom_stsz_t;

typedef struct {
	mp4_atom_hdr_t hdr;
	uint32_t version:8;
	uint32_t flags:24;
	uint32_t entries;
	uint32_t tbl[0];
} __packed mp4_atom_stss_t;


typedef struct {
	mp4_atom_hdr_t hdr;
	uint32_t version:8;
	uint32_t flags:24;
	uint32_t entries;
	struct {
		uint32_t count;
		uint32_t duration;
	} tbl[0];
} __packed mp4_atom_stts_t;

typedef struct {
	mp4_atom_hdr_t hdr;
	uint32_t version:8;
	uint32_t flags:24;
	uint32_t entries;
	struct {
		uint32_t count;
		uint32_t offset;
	} tbl[0];
} __packed mp4_atom_ctts_t;

typedef struct {
	mp4_atom_hdr_t hdr;
	uint32_t version:8;
	uint32_t flags:24;
	uint32_t sample_cnt;
	struct {
		uint32_t first_chunk;
		uint32_t sample_cnt;
		uint32_t desc_id;
	} tbl[0];
} __packed mp4_atom_stsc_t;

typedef struct {
	mp4_atom_hdr_t hdr;
	uint32_t version:8;
	uint32_t flags:24;
	uint32_t chunk_cnt;
	union {
		uint32_t tbl[0];
		uint64_t tbl64[0];
	} u;
} __packed mp4_atom_stco_t;

typedef struct {
	mp4_atom_hdr_t hdr;
	uint32_t version:8;
	uint32_t flags:24;
	uint32_t ctime;
	uint32_t mtime;
	uint32_t track_id;
	uint32_t reserved;
	uint32_t duration;
} __packed mp4_atom_tkhd_t;

struct mp4_atom_s;
struct mp4_atom_s {
	struct mp4mux_list_head entry;
	struct mp4_atom_s *parent;
	struct mp4mux_list_head atoms;
	mp4_atom_hdr_t *hdr;
	u_char data[0];
};

typedef struct mp4_atom_s mp4_atom_t;

typedef struct {
	struct mp4mux_list_head atoms;
	struct mp4mux_list_head atoms_tail;

	ngx_pool_t *pool;
	ngx_log_t *log;
	ngx_file_t file;
	
	ngx_str_t url;
	ngx_str_t fname;
	void *cproxy_ctx;

	mp4_atom_t *moov;
	mp4_atom_t *trak;
	mp4_atom_mvhd_t *mvhd;
	mp4_atom_stsz_t *stsz;
	mp4_atom_stsc_t *stsc;
	mp4_atom_t *stbl;

	off_t file_size;
	time_t file_mtime;
	off_t mdat_pos;
	off_t mdat_size;
	ngx_uint_t mdat_recv;
	
	//off_t chunk_pos;
	ngx_uint_t *chunk_size;
	ngx_uint_t chunk_cnt;

	u_char buf[16];
	ngx_int_t buf_pos;
	ngx_int_t hdr_offset;
	ngx_int_t ext_hdr:1;

	ngx_int_t remote:1;
	ngx_int_t wait:1;
} mp4_file_t;

typedef struct {
	ngx_http_request_t *req;
	void (*write_handler)(ngx_event_t *);
	ngx_chain_t *free;
	ngx_chain_t *busy;
	mp4_file_t mp4f;
	mp4_file_t *mp4_src[MAX_FILE];
	ngx_int_t cur_trak;
	ngx_int_t trak_cnt;
	ngx_uint_t chunk_num;
	ngx_int_t wait_remote;
	ngx_int_t start;
	ngx_int_t move_meta;
	ngx_pool_t *temp_pool;
	ngx_int_t done:1;
} ngx_http_mp4mux_ctx_t;

typedef struct {
    size_t       chunk_size;
    ngx_int_t   move_meta;
} ngx_http_mp4mux_conf_t;

/*typedef struct {
	char *type;
	ngx_int_t *(*handler)(mp4_file_t *file, mp4_atom_t *atom);
} mp4_atom_handler_t;

static mp4_atom_handler_t mp4_atom_handlers[] = {
	{ "mvhd", mp4_atom_handle_mvhd },
	{ "
}*/

static uint32_t mp4_atom_containers[] = {
	ATOM('m', 'o', 'o', 'v'), 
	ATOM('t', 'r', 'a', 'k'), 
	ATOM('m', 'd', 'i', 'a'),
	ATOM('m', 'i', 'n', 'f'),
	ATOM('s', 't', 'b', 'l')
};

#if (NGX_HTTP_CPROXY)
#define CPROXY_OPT_FULL_CHUNK   0x01
#define CPROXY_OPT_OFFSET       0x02
#define CPROXY_OPT_SENDFILE     0x04
#define CPROXY_OPT_SYNC         0x09
#define CPROXY_OPT_NO_FG        0x10
typedef ngx_int_t (*ngx_http_cproxy_output_pt)(ngx_http_request_t *req, ngx_chain_t *out, u_char *last, void *arg);
ngx_int_t ngx_http_cproxy_request(ngx_http_request_t *r, ngx_str_t *location, ngx_str_t *save_file, off_t file_size, off_t offset, ngx_int_t opts, ngx_http_cproxy_output_pt output_filter, void *arg, void **ctx);
void ngx_http_cproxy_handler(ngx_http_request_t *r, void *ctx);
#endif

static char *ngx_http_mp4mux(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static void *ngx_http_mp4mux_create_conf(ngx_conf_t *cf);
static char *ngx_http_mp4mux_merge_conf(ngx_conf_t *cf, void *parent, void *child);

//static ngx_int_t ngx_http_mp4mux_filter_init(ngx_conf_t *cf);
//static ngx_int_t ngx_http_mp4mux_body_filter(ngx_http_request_t *r, ngx_chain_t *in);

static ngx_int_t mp4_parse(ngx_http_mp4mux_ctx_t *ctx, mp4_file_t *f);
static ngx_int_t mp4_clone(mp4_file_t *src, mp4_file_t *dst);
static mp4_atom_t *mp4_clone_atom(mp4_atom_t *src, mp4_atom_t *parent, mp4_file_t *dst);
static off_t mp4_build_atoms(mp4_file_t *mp4f);
static off_t mp4_build_atoms_tail(mp4_file_t *mp4f);
static mp4_atom_stco_t *mp4_alloc_chunks(mp4_file_t *mp4f, mp4_atom_t *trak, mp4_file_t *mp4_src, int co64, double avg_chunk_size, ngx_pool_t *pool);
static ngx_int_t mp4_add_mdat(mp4_file_t *mp4f, off_t size, ngx_int_t co64);
static ngx_int_t mp4_tkhd_update(mp4_atom_t *trak, ngx_uint_t id, uint64_t start, uint32_t old_timescale, uint32_t new_timescale);
static ngx_chain_t *mp4_build_chain(ngx_http_mp4mux_ctx_t *ctx, struct mp4mux_list_head *list);
static void mp4_split(mp4_file_t *mp4f);
static ngx_int_t mp4_adjust_pos(mp4_file_t *mp4f, mp4_atom_t *trak, uint64_t start);
static int mp4mux_write(ngx_http_mp4mux_ctx_t *ctx);
static void ngx_http_mp4mux_write_handler(ngx_event_t *ev);
#if (NGX_HTTP_CPROXY)
static ngx_int_t mp4mux_cproxy_handler_header(ngx_http_request_t *req, ngx_chain_t *out, u_char *last, void *arg);
static ngx_int_t mp4mux_cproxy_handler_mdat(ngx_http_request_t *req, ngx_chain_t *out, u_char *last, void *arg);
#endif
static ngx_int_t mp4mux_send_response(ngx_http_mp4mux_ctx_t *ctx);
static void mp4mux_cleanup(void *data);

static ngx_command_t  ngx_http_mp4mux_commands[] = {

    { ngx_string("mp4mux"),
      NGX_HTTP_LOC_CONF|NGX_CONF_NOARGS,
      ngx_http_mp4mux,
      0,
      0,
      NULL },

    { ngx_string("mp4mux_chunk_size"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_mp4mux_conf_t, chunk_size),
      NULL },

    { ngx_string("mp4mux_move_meta"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_mp4mux_conf_t, move_meta),
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_mp4mux_module_ctx = {
    NULL,                          /* preconfiguration */
    NULL,                          /* postconfiguration */

    NULL,                          /* create main configuration */
    NULL,                          /* init main configuration */

    NULL,                          /* create server configuration */
    NULL,                          /* merge server configuration */

    ngx_http_mp4mux_create_conf,      /* create location configuration */
    ngx_http_mp4mux_merge_conf        /* merge location configuration */
};


ngx_module_t  ngx_http_mp4mux_module = {
    NGX_MODULE_V1,
    &ngx_http_mp4mux_module_ctx,      /* module context */
    ngx_http_mp4mux_commands,         /* module directives */
    NGX_HTTP_MODULE,               /* module type */
    NULL,                          /* init master */
    NULL,                          /* init module */
    NULL,                          /* init process */
    NULL,                          /* init thread */
    NULL,                          /* exit thread */
    NULL,                          /* exit process */
    NULL,                          /* exit master */
    NGX_MODULE_V1_PADDING
};

static ngx_int_t
ngx_http_mp4mux_handler(ngx_http_request_t *r)
{
    u_char                    *last;
    size_t                     root;
    ngx_int_t                  rc, n;
    ngx_uint_t                 i;
    ngx_str_t                  path, value;
		ngx_http_mp4mux_ctx_t *ctx;
		u_char argname[10];
		ngx_str_t fname;
		ngx_http_mp4mux_conf_t   *conf;
		ngx_http_cleanup_t *cln;
    ngx_log_t *log = r->connection->log;
		ngx_connection_t *c = r->connection;

    log = r->connection->log;
		ngx_log_debug0(NGX_LOG_DEBUG_HTTP, log, 0,
			"http_mp4mux_handler");

    if (!(r->method & (NGX_HTTP_GET|NGX_HTTP_HEAD))) {
        return NGX_HTTP_NOT_ALLOWED;
    }

		if (!r->args.len) {
        return NGX_DECLINED;
		}

    rc = ngx_http_discard_request_body(r);

    if (rc != NGX_OK) {
        return rc;
    }

    conf = ngx_http_get_module_loc_conf(r, ngx_http_mp4mux_module);

    last = ngx_http_map_uri_to_path(r, &path, &root, 0);
    if (last == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    path.len = last - path.data;

    ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_mp4mux_ctx_t));

		if (ctx == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

		ctx->req = r;

    ngx_http_set_ctx(r, ctx, ngx_http_mp4mux_module);

		ctx->temp_pool = ngx_create_pool(16384, log);
		if (!ctx->temp_pool)
			return NGX_HTTP_INTERNAL_SERVER_ERROR;

		cln = ngx_http_cleanup_add(r, 0);
		if (!cln)
			return NGX_HTTP_INTERNAL_SERVER_ERROR;

		cln->handler = mp4mux_cleanup;
		cln->data = ctx;


		for (i = 0, n = 0; i < r->args.len && i < MAX_FILE; i++) {
			ngx_memzero(argname, 10);
			ngx_sprintf(argname, "file%i", i);
      if (ngx_http_arg(r, (u_char *) argname, ngx_strlen(argname), &value) == NGX_OK) {

				ngx_log_debug1(NGX_LOG_DEBUG_HTTP, log, 0,
					"mp4mux: arg \"%V\"", &value);

				ctx->mp4_src[n] = ngx_pcalloc(r->pool, sizeof(mp4_file_t));
				if (!ctx->mp4_src[n])
					return NGX_HTTP_INTERNAL_SERVER_ERROR;

				ctx->mp4_src[n]->log = log;
				ctx->mp4_src[n]->pool = ctx->temp_pool;

				if (ngx_memcmp(value.data, "http://", 7) == 0) {
#if (NGX_HTTP_CPROXY)
					ctx->mp4_src[n]->url = value;
					ctx->mp4_src[n]->remote = 1;
					ngx_memzero(argname, 10);
					ngx_sprintf(argname, "store%i", i);
					if (ngx_http_arg(r, (u_char *) argname, ngx_strlen(argname), &value) != NGX_OK) {
						ngx_log_error(NGX_LOG_ERR, log, 0,
													"mp4mux: \"%V\": remote file without local store is not supported", &ctx->mp4_src[n]->url);
						return NGX_DECLINED;
					}

					ctx->mp4_src[n]->fname.len = path.len + value.len;
					ctx->mp4_src[n]->fname.data = ngx_pnalloc(r->pool, ctx->mp4_src[n]->fname.len + 1);
					ngx_memcpy(ctx->mp4_src[n]->fname.data, path.data, path.len);
					ngx_memcpy(ctx->mp4_src[n]->fname.data + path.len, value.data, value.len);
					ctx->mp4_src[n]->fname.data[ctx->mp4_src[n]->fname.len] = 0;

					ngx_log_debug2(NGX_LOG_DEBUG_HTTP, log, 0,
										 "mp4mux: url=\"%V\" fname=\"%V\"", &ctx->mp4_src[n]->url, &ctx->mp4_src[n]->fname);

					rc = ngx_http_cproxy_request(r, &ctx->mp4_src[n]->url, &ctx->mp4_src[n]->fname, -1, 0, CPROXY_OPT_SYNC | CPROXY_OPT_NO_FG, mp4mux_cproxy_handler_header, ctx->mp4_src[n], &ctx->mp4_src[n]->cproxy_ctx);
					ngx_log_debug1(NGX_LOG_DEBUG_HTTP, log, 0,
										 "mp4mux: rc=%i", rc);

					if (rc == NGX_OK) {
						ctx->wait_remote++;
						n++;
						ngx_log_debug1(NGX_LOG_DEBUG_HTTP, log, 0,
										 "mp4mux: wait_remote=%i", ctx->wait_remote);
						continue;
					}

					if (rc != NGX_DECLINED)
						return rc;
					
					ctx->mp4_src[n]->remote = 0;
#else
					return NGX_DECLINED;
#endif
				} else {
					fname.len = path.len + value.len;
					fname.data = ngx_pnalloc(r->pool, fname.len + 1);
					ngx_memcpy(fname.data, path.data, path.len);
					ngx_memcpy(fname.data + path.len, value.data, value.len);
					fname.data[fname.len] = 0;

					ctx->mp4_src[n]->fname = fname;
				}

				n++;
			}
		}

    if (r->args.len && ngx_http_arg(r, (u_char *) "start", 5, &value) == NGX_OK)
			ctx->start = (int) (strtod((char *) value.data, NULL) * 1000);
		else
			ctx->start = 0;

		ngx_log_debug1(NGX_LOG_DEBUG_HTTP, log, 0,
		   "start=%L", ctx->start);

		if (r->args.len && ngx_http_arg(r, (u_char *)"move_meta", 9, &value) == NGX_OK)
			ctx->move_meta = atoi((char *)value.data);
		else
			ctx->move_meta = conf->move_meta;

		r->connection->buffered |= MP4MUX_BUFFERED;
		//r->main->count++;
		r->allow_ranges = ctx->wait_remote == 0;

		if (ctx->wait_remote) {
			if (c->read->timer_set)
					ngx_del_timer(c->read);

			if (ngx_event_flags & NGX_USE_CLEAR_EVENT) {

					if (!c->write->active) {
							if (ngx_add_event(c->write, NGX_WRITE_EVENT, NGX_CLEAR_EVENT)
									== NGX_ERROR)
							{
									//ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
									//r->main->count--;
									return NGX_ERROR;
							}
					}
			}
			return NGX_OK;
		} else
			return mp4mux_send_response(ctx);
}

static void mp4mux_cleanup(void *data)
{
	ngx_http_mp4mux_ctx_t *ctx = data;
	
	if (ctx->temp_pool) {
		ngx_destroy_pool(ctx->temp_pool);
		ctx->temp_pool = NULL;
	}
}

static ngx_int_t mp4mux_open_file(ngx_http_mp4mux_ctx_t *ctx, mp4_file_t *f)
{
	ngx_open_file_info_t       of;
	ngx_http_core_loc_conf_t  *clcf;
	ngx_uint_t level;
	ngx_int_t rc;

	clcf = ngx_http_get_module_loc_conf(ctx->req, ngx_http_core_module);

	ngx_memzero(&of, sizeof(of));
	of.read_ahead = clcf->read_ahead;
	of.directio = clcf->directio;
	of.valid = clcf->open_file_cache_valid;
	of.min_uses = clcf->open_file_cache_min_uses;
	of.errors = clcf->open_file_cache_errors;
	of.events = clcf->open_file_cache_events;

	ngx_log_debug1(NGX_LOG_DEBUG_HTTP, ctx->req->connection->log, 0,
						 "mp4mux: open file: \"%V\"", &f->fname);
	if (ngx_open_cached_file(clcf->open_file_cache, &f->fname, &of, ctx->req->pool)
			!= NGX_OK)
	{
			switch (of.err) {

			case 0:
					return NGX_HTTP_INTERNAL_SERVER_ERROR;

			case NGX_ENOENT:
			case NGX_ENOTDIR:
			case NGX_ENAMETOOLONG:

					level = NGX_LOG_ERR;
					rc = NGX_HTTP_NOT_FOUND;
					break;

			case NGX_EACCES:

					level = NGX_LOG_ERR;
					rc = NGX_HTTP_FORBIDDEN;
					break;

			default:

					level = NGX_LOG_CRIT;
					rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
					break;
			}

			if (rc != NGX_HTTP_NOT_FOUND || clcf->log_not_found) {
					ngx_log_error(level, ctx->req->connection->log, of.err,
												"%s \"%V\" failed", of.failed, &f->fname);
			}

			return rc;
	}

	if (!of.is_file) {

			if (ngx_close_file(of.fd) == NGX_FILE_ERROR) {
					ngx_log_error(NGX_LOG_ALERT, ctx->req->connection->log, ngx_errno,
												ngx_close_file_n " \"%V\" failed", &f->fname);
			}

			return NGX_DECLINED;
	}

	f->file_size = of.size;
	f->file_mtime = of.mtime;
	f->file.fd = of.fd;
	f->file.name = f->fname;
	f->file.log = ctx->req->connection->log;
	f->file.directio = of.is_directio;

	return mp4_parse(ctx, f);
}


static ngx_int_t mp4mux_send_response(ngx_http_mp4mux_ctx_t *ctx)
{
		off_t total_mdat = 0;
		off_t offset;
		mp4_atom_t *trak[MAX_FILE];
		mp4_atom_stco_t *stco[MAX_FILE];
		ngx_chain_t   *out;
		ngx_int_t rc, i, n, co64;
    off_t len, len_tail;
    ngx_log_t *log = ctx->req->connection->log;
		ngx_http_request_t *r = ctx->req;
    ngx_uint_t chunk_num, sc;
		ngx_uint_t total_samples = 0, min_samples = INT_MAX;
		ngx_table_elt_t *etag;
		u_char *etag_val;
		double corr;
		
		for (n = 0; ctx->mp4_src[n]; n++) {
			rc = mp4mux_open_file(ctx, ctx->mp4_src[n]);
			if (rc != NGX_OK)
				goto out_err;


#if (NGX_HTTP_CPROXY)
			if (ctx->mp4_src[n]->remote) {
				rc = ngx_http_cproxy_request(r, &ctx->mp4_src[n]->url, &ctx->mp4_src[n]->fname, ctx->mp4_src[n]->file_size, ctx->mp4_src[n]->mdat_pos, CPROXY_OPT_OFFSET | CPROXY_OPT_SENDFILE | CPROXY_OPT_SYNC, mp4mux_cproxy_handler_mdat, ctx->mp4_src[n], &ctx->mp4_src[n]->cproxy_ctx);
				if (rc != NGX_OK)
					goto out_err;
			}
#endif
		}

		if (mp4_clone(ctx->mp4_src[0], &ctx->mp4f))
			goto out_err1;


		if (!ctx->move_meta)
			mp4_split(&ctx->mp4f);

		trak[0] = ctx->mp4f.trak;

		for (i = 0; i < n; i++) {
                        if (!ctx->mp4_src[i]->mvhd) {
				ngx_log_error(NGX_LOG_ERR, log, 0, "mp4mux: \"%V\" is invalid\n", &ctx->mp4_src[i]->fname);
                                goto out_err1;
			}
                }

		for (i = 1; i < n; i++) {
			if ((double)be32toh(ctx->mp4_src[i]->mvhd->duration) / be32toh(ctx->mp4_src[i]->mvhd->timescale) >
				(double)be32toh(ctx->mp4f.mvhd->duration) / be32toh(ctx->mp4f.mvhd->timescale)) {
				ctx->mp4f.mvhd->duration = ctx->mp4_src[i]->mvhd->duration;
				ctx->mp4f.mvhd->timescale = ctx->mp4_src[i]->mvhd->timescale;
			}
			trak[i] = mp4_clone_atom(ctx->mp4_src[i]->trak, ctx->mp4f.moov, &ctx->mp4f);
			if (!trak[i])
				goto out_err1;
		}

		if (ctx->start) {
			if (ctx->start * be32toh(ctx->mp4f.mvhd->timescale) / 1000 >= be32toh(ctx->mp4f.mvhd->duration))
				ctx->mp4f.mvhd->duration = 0;
			else
				ctx->mp4f.mvhd->duration = htobe32(be32toh(ctx->mp4f.mvhd->duration) - 
					ctx->start * be32toh(ctx->mp4f.mvhd->timescale) / 1000);
		}
		
		for (i = 0; i < n; i++) {
			if (mp4_tkhd_update(trak[i], i + 1, ctx->start, be32toh(ctx->mp4_src[i]->mvhd->timescale), be32toh(ctx->mp4f.mvhd->timescale)))
				goto out_err1;

			if (ctx->start && mp4_adjust_pos(ctx->mp4_src[i], trak[i], ctx->start))
				goto out_err1;

			total_mdat += ctx->mp4_src[i]->mdat_size;
		}

		ctx->mp4f.mvhd->next_track_id = htobe32(n + 1);

		co64 = total_mdat > 0xffffffffl;
		
		ngx_log_debug3(NGX_LOG_DEBUG_HTTP, log, 0,
		   "total_mdat: %O %i %i", total_mdat, co64, sizeof(total_mdat));
		
		for (i = 0; i < n; i++) {
			sc = be32toh(ctx->mp4_src[i]->stsz->sample_cnt);
			total_samples += sc;
			if (sc < min_samples)
				min_samples = sc;
		}

		corr = 1.0/((double)min_samples / total_samples * n);
		
		for (i = 0; i < n; i++) {
			stco[i] = mp4_alloc_chunks(&ctx->mp4f, trak[i], ctx->mp4_src[i], co64, corr * (double)be32toh(ctx->mp4_src[i]->stsz->sample_cnt) / total_samples * n, r->pool);
			if (!stco[i])
				goto out_err1;
		}

		len = mp4_build_atoms(&ctx->mp4f);
		if (len < 0)
			goto out_err1;

		len_tail = mp4_build_atoms_tail(&ctx->mp4f);
		if (len_tail < 0)
			goto out_err1;

		ngx_log_debug2(NGX_LOG_DEBUG_HTTP, log, 0,
				"len=%O tail=%O", len, len_tail);

		len += (co64 ? 16 : 8);
		offset = len; i = 0; chunk_num = 0;
		while (1) {
			for (; i < n; i++) {
				if (chunk_num < ctx->mp4_src[i]->chunk_cnt)
					break;
			}

			if (i == n) {
				chunk_num++;
				for (i = 0; i < n; i++) {
					if (chunk_num < ctx->mp4_src[i]->chunk_cnt)
						break;
				}

				if (i == n)
					break;
			}

			if (co64)
				stco[i]->u.tbl64[chunk_num] = htobe64(offset);
			else
				stco[i]->u.tbl[chunk_num] = htobe32(offset);

			offset += ctx->mp4_src[i]->chunk_size[chunk_num];

			i++;
		}
			
		if (mp4_add_mdat(&ctx->mp4f, offset - len, co64))
			goto out_err1;

		ctx->trak_cnt = n;

    r->root_tested = !r->error_page;

    log->action = "sending mp4mux to client";

    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = offset + len_tail;
    //r->headers_out.last_modified_time = ;
		ngx_str_set(&r->headers_out.content_type, "video/mp4");
		r->headers_out.content_type_len = r->headers_out.content_type.len;
		// Calculate ETag
		etag = ngx_list_push(&r->headers_out.headers);
		if (etag == NULL) goto out_err1;

		etag->hash = 1;
		ngx_str_set(&etag->key, "ETag");

		etag_val = ngx_pnalloc(r->pool, (NGX_OFF_T_LEN + NGX_TIME_T_LEN + 2)*n + 2);
		if (etag_val == NULL) {
			etag->hash = 0;
			goto out_err1;
		}
		etag->value.data = etag_val;

		*etag_val++ = '"';
		for (i = 0; i < n; i++) {
			if (i) *etag_val++ = '/';
			etag_val = ngx_sprintf(etag_val, "%xT-%xO",
				ctx->mp4_src[i]->file_mtime,
				ctx->mp4_src[i]->file_size);
		}
		*etag_val++ = '"';
		etag->value.len = etag_val - etag->value.data;
		r->headers_out.etag = etag;

		rc = ngx_http_send_header(r);
		if (rc == NGX_ERROR || rc > NGX_OK || r->header_only)
				goto out_err;

		//r->connection->read->handler = ngx_http_mp4mux_write_handler;
                ctx->write_handler = r->connection->write->handler;
		r->connection->write->handler = ngx_http_mp4mux_write_handler;

		out = mp4_build_chain(ctx, &ctx->mp4f.atoms);
		if (!out)
			goto out_err1;
					
		rc = ngx_http_output_filter(r, out);
	 
#if nginx_version > 1001000
		ngx_chain_update_chains(r->pool, &ctx->free, &ctx->busy, &out,
			(ngx_buf_tag_t) &ngx_http_mp4mux_module);
#else
		ngx_chain_update_chains(&ctx->free, &ctx->busy, &out,
			(ngx_buf_tag_t) &ngx_http_mp4mux_module);
#endif

		ngx_log_debug1(NGX_LOG_DEBUG_HTTP, log, 0,
			"http_mp4mux rc=%i", rc);
			
		if (rc != NGX_OK)
			return rc;

		return mp4mux_write(ctx);

out_err1:
	rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
out_err:
	r->connection->buffered &= ~MP4MUX_BUFFERED;
	//r->main->count--;
	//ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
	return rc;
}

static int mp4mux_write(ngx_http_mp4mux_ctx_t *ctx)
{
	ngx_buf_t    *b;
  ngx_chain_t   *out;
	ngx_int_t  j;
	ngx_int_t rc;
	ngx_http_request_t *r = ctx->req;
	ngx_connection_t *c = r->connection;

	ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
		"mp4mux: write: done %i", ctx->done ? 1 : 0);

	if (ctx->done)
		return NGX_DONE;

	while (1) {
		for (j = ctx->cur_trak; j < ctx->trak_cnt; j++) {
				ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
					"mp4mux: j=%i chunk_cnt=%i", j, ctx->mp4_src[j]->chunk_cnt);
			if (ctx->chunk_num >= ctx->mp4_src[j]->chunk_cnt)
				continue;
			break;
		}

		if (j == ctx->trak_cnt) {
			ctx->chunk_num++;
			for (j = 0; j < ctx->trak_cnt; j++) {
				ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
					"mp4mux: j=%i chunk_cnt=%i", j, ctx->mp4_src[j]->chunk_cnt);
				if (ctx->chunk_num >= ctx->mp4_src[j]->chunk_cnt)
					continue;
				break;
			}

			if (j == ctx->trak_cnt) {
				ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
					"mp4mux: last chain");

				break;
			}
		}

		ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
			"mp4mux: trak=%i chunk=%i size=%i", j, ctx->chunk_num, ctx->mp4_src[j]->chunk_size[ctx->chunk_num]);

		if (ctx->mp4_src[j]->chunk_size[ctx->chunk_num]) {

			if (ctx->mp4_src[j]->remote) {
				ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
					"http_mp4mux: remote: mdat_pos=%O mdat_recv=%O", ctx->mp4_src[j]->mdat_pos, ctx->mp4_src[j]->mdat_recv);
			}
		
			if (ctx->mp4_src[j]->remote && ctx->mp4_src[j]->chunk_size[ctx->chunk_num] < ctx->mp4_src[j]->mdat_recv) {
				ctx->cur_trak = j;
				ctx->mp4_src[j]->wait = 1;
				ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
					"http_mp4mux: wait remote %O %O");
				return NGX_OK;
			}

			out = ngx_chain_get_free_buf(r->pool, &ctx->free);
			if (!out)
				goto out_err;
			
			b = out->buf;
			//ngx_memzero(b, sizeof(*b));
			
			b->file = &ctx->mp4_src[j]->file;
			b->file_pos = ctx->mp4_src[j]->mdat_pos;
			b->file_last = ctx->mp4_src[j]->mdat_pos + ctx->mp4_src[j]->chunk_size[ctx->chunk_num];

			ctx->mp4_src[j]->mdat_pos += ctx->mp4_src[j]->chunk_size[ctx->chunk_num];
			ctx->mp4_src[j]->mdat_recv -= ctx->mp4_src[j]->chunk_size[ctx->chunk_num];

			b->in_file = 1;
			b->flush = 1;
			b->memory = 0;
			//b->last_buf = ctx->trak == ctx->tak_cnt - 1 && ctx->chunk_num == 
			b->tag = (ngx_buf_tag_t) &ngx_http_mp4mux_module; 

			rc = ngx_http_output_filter(r, out);

#if nginx_version > 1001000
			ngx_chain_update_chains(r->pool, &ctx->free, &ctx->busy, &out,
				(ngx_buf_tag_t) &ngx_http_mp4mux_module);
#else
			ngx_chain_update_chains(&ctx->free, &ctx->busy, &out,
				(ngx_buf_tag_t) &ngx_http_mp4mux_module);
#endif
		
			ctx->cur_trak = j + 1;
			
			/*if (rc == NGX_AGAIN && ctx->req->connection->write->ready)
				continue;*/
			if (rc == NGX_AGAIN) {
				if (ngx_event_flags & NGX_USE_CLEAR_EVENT) {

						if (!c->write->active) {
								if (ngx_add_event(c->write, NGX_WRITE_EVENT, NGX_CLEAR_EVENT)
										== NGX_ERROR) {
										goto out_err;
								}
						}
				}
			}

			if (rc != NGX_OK)
				return rc;
		} else
			ctx->cur_trak = j + 1;
	}

//exit:
	
	if (!mp4mux_list_empty(&ctx->mp4f.atoms_tail)) {
		out = mp4_build_chain(ctx, &ctx->mp4f.atoms_tail);
		if (!out)
			goto out_err;

		ngx_http_output_filter(r, out);
	}
	
	//ctx->req->main->count--;
	r->connection->buffered &= ~MP4MUX_BUFFERED;
	//r->buffered--;
	ctx->done = 1;

	ngx_log_debug2(NGX_LOG_DEBUG_HTTP, ctx->req->connection->log, 0,
		"mp4mux: done: count=%i buffered=%i", ctx->req->main->count, ctx->req->main->buffered);
	
  //for (out = ctx->req->out; out->next; out = out->next);
  //out->buf->last_buf = 1;

	return NGX_DONE;

out_err:
	return NGX_ERROR;
}

static char *
ngx_http_mp4mux(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_core_loc_conf_t  *clcf;

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_mp4mux_handler;

    return NGX_CONF_OK;
}

static ngx_int_t mp4_parse_atom(mp4_file_t *mp4f, mp4_atom_t *atom)
{
	ngx_uint_t i;
	mp4_atom_t *a;
	mp4_atom_hdr_t *hdr;
	off_t pos;
	uint32_t size, atom_size;
	char atom_name[5];

	atom_name[4] = 0;

	if (atom->hdr->type == ATOM('t', 'r', 'a', 'k'))
		mp4f->trak = atom;
	else if (atom->hdr->type == ATOM('s', 't', 's', 'z'))
		mp4f->stsz = (mp4_atom_stsz_t *)atom->hdr;
	else if (atom->hdr->type == ATOM('s', 't', 's', 'c'))
		mp4f->stsc = (mp4_atom_stsc_t *)atom->hdr;
	else if (atom->hdr->type == ATOM('m', 'v', 'h', 'd'))
		mp4f->mvhd = (mp4_atom_mvhd_t *)atom->hdr;
	/*else if (atom->hdr->type == ATOM('s', 't', 't', 's'))
		mp4f->stts = (mp4_atom_stts_t *)atom->hdr;*/

	for (i = 0; i < sizeof(mp4_atom_containers)/sizeof(mp4_atom_containers[0]); i++) {
		if (atom->hdr->type == mp4_atom_containers[i])
			goto found;
	}

	return 0;

found:
	atom_size = be32toh(atom->hdr->size) - sizeof(*hdr);
	for (pos = 0; pos < atom_size; pos += size) {
		hdr = (mp4_atom_hdr_t *)(atom->hdr->data + pos);
		size = be32toh(hdr->size);

		ngx_memcpy(atom_name, &hdr->type, 4);
		ngx_log_debug2(NGX_LOG_DEBUG_HTTP, mp4f->log, 0,
                   "begin atom: %s %i", atom_name, size);
		
		if (size < 8) {
			ngx_log_error(NGX_LOG_ERR, mp4f->log, 0,
										"mp4mux: \"%V\": atom is too small:%uL",
										&mp4f->fname, size);
			return -1;
		}

		if (hdr->type == ATOM('e', 'd', 't', 's'))
			continue;

		a = ngx_pcalloc(mp4f->pool, sizeof(*a));
		if (!a)
			return -1;

		ngx_memcpy(&a->hdr, hdr, sizeof(*hdr));

		MP4MUX_INIT_LIST_HEAD(&a->atoms);
		a->parent = atom;
		a->hdr = hdr;
		mp4mux_list_add_tail(&a->entry, &atom->atoms);

		if (mp4_parse_atom(mp4f, a))
			return -1;
		
		ngx_log_debug2(NGX_LOG_DEBUG_HTTP, mp4f->log, 0,
                   "end atom: %s %i", atom_name, size);
	}

	return 0;
}

static ngx_int_t mp4_parse(ngx_http_mp4mux_ctx_t *ctx, mp4_file_t *mp4f)
{
	mp4_atom_hdr_t hdr;
	mp4_atom_t *atom;
	off_t pos;
	uint32_t size;
	uint64_t size64;
	ngx_int_t n;
	char atom_name[5];

	atom_name[4] = 0;

	MP4MUX_INIT_LIST_HEAD(&mp4f->atoms);

	for (pos = 0; pos < mp4f->file_size; pos += size) {
		n = ngx_read_file(&mp4f->file, (u_char *)&hdr, sizeof(hdr), pos);

		if (n == NGX_ERROR)
			return NGX_HTTP_INTERNAL_SERVER_ERROR;
		
		size = be32toh(hdr.size);

		memcpy(atom_name, &hdr.type, 4);
		ngx_log_debug2(NGX_LOG_DEBUG_HTTP, mp4f->log, 0,
                   "begin atom: %s %i", atom_name, size);

		if (size == 1) {
			n = ngx_read_file(&mp4f->file, (u_char *)&size64, 8, pos + sizeof(hdr));
			if (n == NGX_ERROR)
				return NGX_HTTP_INTERNAL_SERVER_ERROR;
			size64 = be64toh(size64);
			ngx_log_debug1(NGX_LOG_DEBUG_HTTP, mp4f->log, 0, "size64 %L", size64);
		}

		if (size == 0) {
			size = mp4f->file_size - pos;
			hdr.size = htobe32(size);
		} else if (size != 1 && size < 8) {
			ngx_log_error(NGX_LOG_ERR, mp4f->log, 0,
										"mp4mux: \"%V\": atom is too small:%uL",
										&mp4f->fname, size);
			return NGX_DECLINED;
		}
		
		if (hdr.type == ATOM('m', 'd', 'a', 't')) {
			mp4f->mdat_pos = size == 1 ? (pos + sizeof(hdr) + 8) : (pos + sizeof(hdr));
			mp4f->mdat_size = size == 1 ? (size64 - sizeof(hdr) - 8) : (size - sizeof(hdr));
			if (size == 1)
				pos += size64 - 1;
		} else if (hdr.type != ATOM('f', 'r', 'e', 'e')) {
			if (size == 1 || size > MAX_ATOM_SIZE) {
				ngx_log_error(NGX_LOG_ERR, mp4f->log, 0,
											"mp4mux: \"%V\": mp4 atom is too large:%uL",
											&mp4f->fname, size);
				return NGX_DECLINED;
			}

			atom = ngx_pcalloc(mp4f->pool, sizeof(*atom) + size);
			if (!atom)
				return NGX_HTTP_INTERNAL_SERVER_ERROR;

			ngx_memcpy(atom->data, &hdr, sizeof(hdr));

			n = ngx_read_file(&mp4f->file, atom->data + sizeof(hdr), size - sizeof(hdr), pos + sizeof(hdr));
			if (n == NGX_ERROR)
				return NGX_HTTP_INTERNAL_SERVER_ERROR;
			
			atom->hdr = (mp4_atom_hdr_t *)atom->data;

			MP4MUX_INIT_LIST_HEAD(&atom->atoms);
			mp4mux_list_add_tail(&atom->entry, &mp4f->atoms);

			if (mp4_parse_atom(mp4f, atom))
				return NGX_DECLINED;
		}
		ngx_log_debug2(NGX_LOG_DEBUG_HTTP, mp4f->log, 0,
            "end atom: %s %i", atom_name, size);
	}
	
	mp4mux_list_for_each_entry(atom, &mp4f->atoms, entry) {
		memcpy(atom_name, &atom->hdr->type, 4);
		ngx_log_debug2(NGX_LOG_DEBUG_HTTP, mp4f->log, 0,
                 "atom: %s %i", atom_name, be32toh(atom->hdr->size));
	}

	return NGX_OK;
}

static ngx_int_t __copy_atoms(struct mp4mux_list_head *src_list, mp4_atom_t *parent, struct mp4mux_list_head *dst_list, mp4_file_t *dst)
{
	mp4_atom_t *atom, *a;
	char atom_name[5] = {0,0,0,0,0};

	mp4mux_list_for_each_entry(atom, src_list, entry) {
		if (atom->hdr->type == ATOM('s', 't', 'c', 'o'))
			continue;
		if (atom->hdr->type == ATOM('c', 'o', '6', '4'))
			continue;
		if (atom->hdr->type == ATOM('s', 't', 's', 'c'))
			continue;

		memcpy(atom_name, &atom->hdr->type, 4);
		ngx_log_debug1(NGX_LOG_DEBUG_HTTP, dst->log, 0,
		   "copy atom: %s ", atom_name);

		a = ngx_palloc(dst->pool, sizeof(*a));
		if (!a)
			return -1;
		a->hdr = atom->hdr;
		a->parent = parent;
		MP4MUX_INIT_LIST_HEAD(&a->atoms);
		mp4mux_list_add_tail(&a->entry, dst_list);
		
		if (a->hdr->type == ATOM('m', 'v', 'h', 'd'))
			dst->mvhd = (mp4_atom_mvhd_t *)a->hdr;
		else if (a->hdr->type == ATOM('m', 'o', 'o', 'v'))
			dst->moov = a;
		else if (a->hdr->type == ATOM('t', 'r', 'a', 'k'))
			dst->trak = a;
		/*else if (atom->hdr->type == ATOM('s', 't', 'b', 'l')) {
			if (!dst->stbl)
				dst->stbl = a;
		}*/
		
		if (!mp4mux_list_empty(&atom->atoms)) {
			if (__copy_atoms(&atom->atoms, a, &a->atoms, dst))
				return -1;
		}
	}

	return 0;
}

static ngx_int_t mp4_clone(mp4_file_t *src, mp4_file_t *dst)
{
	dst->log = src->log;
	dst->pool = src->pool;
	MP4MUX_INIT_LIST_HEAD(&dst->atoms);
	MP4MUX_INIT_LIST_HEAD(&dst->atoms_tail);
	return __copy_atoms(&src->atoms, NULL, &dst->atoms, dst);
}

static void mp4_split(mp4_file_t *mp4f)
{
	struct mp4mux_list_head *pos = mp4f->atoms.next->next;
	struct mp4mux_list_head *next;

	while (pos != &mp4f->atoms) {
		next = pos->next;
		mp4mux_list_move_tail(pos, &mp4f->atoms_tail);
		pos = next;
	}
}

static mp4_atom_t *mp4_clone_atom(mp4_atom_t *src, mp4_atom_t *parent, mp4_file_t *dst)
{
	mp4_atom_t *a;

	a = ngx_palloc(dst->pool, sizeof(*a));
	if (!a)
		return NULL;

	a->hdr = src->hdr;
	a->parent = parent;
	MP4MUX_INIT_LIST_HEAD(&a->atoms);
	mp4mux_list_add_tail(&a->entry, &parent->atoms);
	
	if (__copy_atoms(&src->atoms, a, &a->atoms, dst))
		return NULL;
	
	return a;
}

static off_t __build_atoms(struct mp4mux_list_head *list, mp4_file_t *mp4f)
{
	off_t len = 0, n;
	mp4_atom_t *a;
	char atom_name[5] = {0,0,0,0,0};

	mp4mux_list_for_each_entry(a, list, entry) {
		memcpy(atom_name, &a->hdr->type, 4);
		
		ngx_log_debug1(NGX_LOG_DEBUG_HTTP, mp4f->log, 0,
		   "build atom: %s", atom_name);

		if (mp4mux_list_empty(&a->atoms))
			len += be32toh(a->hdr->size);
		else {
			n = (off_t)sizeof(mp4_atom_hdr_t) + __build_atoms(&a->atoms, mp4f);
			a->hdr->size = htobe32(n);
			len += n;
		}
	}

	return len;
}

static off_t mp4_build_atoms(mp4_file_t *mp4f)
{
	return __build_atoms(&mp4f->atoms, mp4f);
}

static off_t mp4_build_atoms_tail(mp4_file_t *mp4f)
{
	return __build_atoms(&mp4f->atoms_tail, mp4f);
}

static mp4_atom_t *mp4_find_atom(struct mp4mux_list_head *list, uint32_t type)
{
	mp4_atom_t *a, *a1;

	mp4mux_list_for_each_entry(a, list, entry) {
		if (a->hdr->type == type)
			return a;

		a1 = mp4_find_atom(&a->atoms, type);
		if (a1)
			return a1;
	}

	return NULL;
}

static ngx_int_t mp4_tkhd_update(mp4_atom_t *trak, ngx_uint_t id, uint64_t start, uint32_t old_timescale, uint32_t new_timescale)
{
	mp4_atom_t *a;
	mp4_atom_tkhd_t *tkhd;

	uint64_t duration;

	a = mp4_find_atom(&trak->atoms, ATOM('t', 'k', 'h', 'd'));
	if (!a)
		return -1;

	tkhd = (mp4_atom_tkhd_t *)a->hdr;
	tkhd->track_id = htobe32(id);

	duration = (uint64_t)be32toh(tkhd->duration) * 1000 / old_timescale;

	if (start > duration)
		tkhd->duration = 0;
	else
		tkhd->duration = htobe32((duration - start) * new_timescale / 1000);
	
	return 0;
}

static ngx_int_t mp4_adjust_pos(mp4_file_t *mp4f, mp4_atom_t *trak, uint64_t start)
{
	mp4_atom_t *a, *stss_a, *ctts_a;
	mp4_atom_mdhd_t *mdhd;
	mp4_atom_stts_t *stts;
	mp4_atom_stsz_t *stsz;
	mp4_atom_stss_t *stss = NULL;
	mp4_atom_ctts_t *ctts = NULL;
	ngx_uint_t i, skip_samples = 0, skip_duration = 0, n, s, cnt;
	uint32_t samples, duration = 1;

	a = mp4_find_atom(&trak->atoms, ATOM('m', 'd', 'h', 'd'));
	if (!a)
		return -1;
	mdhd = (mp4_atom_mdhd_t *)a->hdr;

	a = mp4_find_atom(&trak->atoms, ATOM('s', 't', 't', 's'));
	if (!a)
		return -1;
	stts = (mp4_atom_stts_t *)a->hdr;

	a = mp4_find_atom(&trak->atoms, ATOM('s', 't', 's', 'z'));
	if (!a)
		return -1;
	stsz = (mp4_atom_stsz_t *)a->hdr;

	stss_a = mp4_find_atom(&trak->atoms, ATOM('s', 't', 's', 's'));
	if (stss_a)
		stss = (mp4_atom_stss_t *)stss_a->hdr;

	ctts_a = mp4_find_atom(&trak->atoms, ATOM('c', 't', 't', 's'));
	if (ctts_a)
		ctts = (mp4_atom_ctts_t *)ctts_a->hdr;
	
	start = start * be32toh(mdhd->timescale) / 1000;
	ngx_log_debug2(NGX_LOG_DEBUG_HTTP, mp4f->log, 0,
		"adjust_pos: start=%L duration=%i", start, be32toh(mdhd->duration));
	if (start >= be32toh(mdhd->duration)) {
		mdhd->duration = 0;
		stts->entries = 0;
		stts->hdr.size = htobe32(sizeof(*stts));
		mp4f->stsz->sample_cnt = 0;
		mp4f->stsz->hdr.size = htobe32(sizeof(*mp4f->stsz));
		if (stss_a) {
			stss->entries = 0;
			stss->hdr.size = htobe32(sizeof(*stss));
		}
		return 0;
	}

	n = be32toh(stts->entries);
	for (i = 0; i < n; i++) {
		samples = be32toh(stts->tbl[i].count);
		duration = be32toh(stts->tbl[i].duration);
		ngx_log_debug3(NGX_LOG_DEBUG_HTTP, mp4f->log, 0,
			"stts[%i]=%i %i", i, samples, duration);
		if (start < (uint64_t)samples * duration)
			break;
		skip_samples += samples;
		skip_duration += (uint64_t)samples * duration;
		start -= (uint64_t)samples * duration;
		stts->tbl[i].count = 0;
	}

	skip_samples += start / duration;
	skip_duration += (start / duration) * duration;
	stts->tbl[i].count = htobe32(be32toh(stts->tbl[i].count) - start / duration);
	
	ngx_log_debug2(NGX_LOG_DEBUG_HTTP, mp4f->log, 0,
		"adjust_pos: skip_samples=%i skip_duration=%i", skip_samples, skip_duration);

	mdhd->duration = htobe32(be32toh(mdhd->duration) - skip_duration);
	
	if (mp4f->stsz->sample_size) {
		mp4f->mdat_pos += be32toh(mp4f->stsz->sample_size) * skip_samples;
		mp4f->mdat_size -= be32toh(mp4f->stsz->sample_size) * skip_samples;
		mp4f->stsz->sample_cnt = htobe32(be32toh(mp4f->stsz->sample_cnt) - skip_samples);
	} else {
		for (i = 0; i < skip_samples; i++) {
			//ngx_log_debug2(NGX_LOG_DEBUG_HTTP, mp4f->log, 0,
			//	"stsz[%i]=%i", i, be32toh(stsz->tbl[i]));
			mp4f->mdat_pos += be32toh(stsz->tbl[i]);
			mp4f->mdat_size -= be32toh(stsz->tbl[i]);
		}
		//ngx_log_debug2(NGX_LOG_DEBUG_HTTP, mp4f->log, 0,
		//	"stsz[%i]=%i", i, be32toh(stsz->tbl[i]));
		//ngx_log_debug2(NGX_LOG_DEBUG_HTTP, mp4f->log, 0,
		//"stsz[%i]=%i", i+1, be32toh(stsz->tbl[i+1]));
		stsz->sample_cnt = htobe32(be32toh(stsz->sample_cnt) - skip_samples);
		stsz->hdr.size = htobe32(sizeof(*stsz) + be32toh(stsz->sample_cnt) * 4); 
		a->hdr = (mp4_atom_hdr_t *)((char *)(stsz->tbl + i) - sizeof(*stsz));
		memmove(a->hdr, stsz, sizeof(*stsz));
		mp4f->stsz = (mp4_atom_stsz_t *)a->hdr;
		//ngx_log_debug1(NGX_LOG_DEBUG_HTTP, mp4f->log, 0,
		//	"stsz[0]=%i", be32toh(mp4f->stsz->tbl[0]));
		//ngx_log_debug1(NGX_LOG_DEBUG_HTTP, mp4f->log, 0,
		//	"stsz[1]=%i", be32toh(mp4f->stsz->tbl[1]));
	}

	if (stss_a) {
		n = be32toh(stss->entries);
		for (i = 0; i < n; i++) {
			if (be32toh(stss->tbl[i]) > skip_samples)
				break;
		}
		stss->entries = htobe32(be32toh(stss->entries) - i);
		stss->hdr.size = htobe32(sizeof(*stss) + be32toh(stss->entries) * 4); 
		stss_a->hdr = (mp4_atom_hdr_t *)((char *)(stss->tbl + i) - sizeof(*stss));
		memmove(stss_a->hdr, stss, sizeof(*stss));
		stss = (mp4_atom_stss_t *)stss_a->hdr;
		n = be32toh(stss->entries);
		for (i = 0; i < n; i++) {
			stss->tbl[i] = htobe32(be32toh(stss->tbl[i]) - skip_samples);
		}
	}

	if (ctts_a) {
		s = skip_samples;
		n = be32toh(ctts->entries);
		for (i = 0; i < n && s; i++) {
			cnt = be32toh(ctts->tbl[i].count);
			if (cnt > s) {
				ctts->tbl[i].count = htobe32(cnt - s);
				break;
			}
			s -= cnt;
		}
		ctts->entries = htobe32(n - i);
		ctts->hdr.size = htobe32(sizeof(*ctts) + be32toh(ctts->entries) * 8); 
		ctts_a->hdr = (mp4_atom_hdr_t *)((char *)(ctts->tbl + i) - sizeof(*ctts));
		memmove(ctts_a->hdr, ctts, sizeof(*ctts));
	}


	return 0;
}

static mp4_atom_stco_t *mp4_alloc_chunks(mp4_file_t *mp4f, mp4_atom_t *trak, mp4_file_t *mp4_src, int co64, double avg_sample_cnt, ngx_pool_t *pool)
{
	mp4_atom_t *stbl, *a;
	mp4_atom_stsc_t *stsc;
	mp4_atom_stco_t *stco;
	uint32_t *ptr;
	ngx_uint_t stco_cnt = 0, stsc_cnt = 0;
	ngx_uint_t i, n;
	ngx_uint_t cnt, chunk, s_cnt;
	off_t pos, prev_pos;
	double sample;

	ngx_log_debug1(NGX_LOG_DEBUG_HTTP, mp4f->log, 0,
		"alloc chunks: sample_size=%f", avg_sample_cnt);
	
	stbl = mp4_find_atom(&trak->atoms, ATOM('s', 't', 'b', 'l'));
	if (!stbl)
		return NULL;
	
	ngx_log_debug2(NGX_LOG_DEBUG_HTTP, mp4f->log, 0,
		"stsz: sample_size=%i sample_count=%i", be32toh(mp4_src->stsz->sample_size), be32toh(mp4_src->stsz->sample_cnt));
	
	/*if (mp4_src->stsz->sample_size) {
		if (be32toh(mp4_src->stsz->sample_size) >= min_chunk_size) {
			stco_cnt = be32toh(mp4_src->stsz->sample_cnt);
			stsc_cnt = 1;
			stsc_n = 1;
		} else {
			stsc_n = ((min_chunk_size - 1) / be32toh(mp4_src->stsz->sample_size) + 1);
			stco_cnt = (be32toh(mp4_src->stsz->sample_cnt) - 1) / stsc_n + 1;
			if (stco_cnt * stsc_n == be32toh(mp4_src->stsz->sample_cnt))
				stsc_cnt = 1;
			else
				stsc_cnt = 2;
		}
	} else*/ {
		pos = 0; sample = avg_sample_cnt - 1; n = 0; s_cnt = be32toh(mp4_src->stsz->sample_cnt);
		for (i = 0, ptr = mp4_src->stsz->tbl; i < s_cnt; i++, ptr++) {
			if (mp4_src->stsz->sample_size)
				pos += be32toh(mp4_src->stsz->sample_size);
			else
				pos += be32toh(*ptr);

			if (i >= sample) {
				sample += avg_sample_cnt;
				stco_cnt++;
				stsc_cnt++;
				n = 0;
			}
		}

		if (n) {
			stco_cnt++;
			stsc_cnt++;
		}
	}

	if (mp4_src->mdat_pos + pos > mp4_src->file_size) {
		ngx_log_error(NGX_LOG_ERR, mp4f->log, 0, "mp4mux: \"%V\" is invalid (data is out of file)\n", &mp4_src->fname);
		return NULL;
	}

	
	ngx_log_debug2(NGX_LOG_DEBUG_HTTP, mp4f->log, 0,
		"stco_cnt=%i stsc_cnt=%i", stco_cnt, stsc_cnt);

	// build stsc atom
	// ================
	a = ngx_palloc(mp4f->pool, sizeof(*a) + sizeof(mp4_atom_stsc_t) + stsc_cnt * 12);
	if (!a)
		return NULL;

	a->hdr = (mp4_atom_hdr_t *)a->data;
	a->hdr->type = ATOM('s', 't', 's', 'c');
	a->parent = stbl;
	MP4MUX_INIT_LIST_HEAD(&a->atoms);
	mp4mux_list_add_tail(&a->entry, &stbl->atoms);

	stsc = (mp4_atom_stsc_t *)a->hdr;
	stsc->version = 0;
	stsc->flags = 0;

	/*if (mp4_src->stsz->sample_size) {
		stsc->tbl[0].first_chunk = htobe32(1);
		stsc->tbl[0].sample_cnt = htobe32(stsc_n);
		stsc->tbl[0].desc_id = mp4_src->stsc->tbl[0].desc_id;
		if (stsc_cnt == 2) {
			stsc->tbl[1].first_chunk = htobe32(stco_cnt);
			stsc->tbl[1].sample_cnt = htobe32(be32toh(mp4_src->stsz->sample_cnt) - stco_cnt * stsc_n);
			stsc->tbl[1].desc_id = mp4_src->stsc->tbl[0].desc_id;
		}
		stsc->sample_cnt = htobe32(stsc_cnt);
		a->hdr->size = htobe32(sizeof(mp4_atom_stsc_t) + stsc_cnt * 12);
	} else*/ {
		cnt = 0; n = 0; chunk = 1; pos = 0; sample = avg_sample_cnt - 1;
		s_cnt = be32toh(mp4_src->stsz->sample_cnt);
		for (i = 0; i < s_cnt; i++) {
			cnt++;
			//ngx_log_debug4(NGX_LOG_DEBUG_HTTP, mp4f->log, 0,
			//	"stsz[]: %i cnt=%i pos=%i chunk_pos=%i", be32toh(*ptr), cnt, pos, chunk_pos);
			if (i >= sample) {
				if (n == 0 || be32toh(stsc->tbl[n - 1].sample_cnt) != cnt) {
					stsc->tbl[n].first_chunk = htobe32(chunk);
					stsc->tbl[n].sample_cnt = htobe32(cnt);
					stsc->tbl[n].desc_id = mp4_src->stsc->tbl[0].desc_id;
					//ngx_log_debug4(NGX_LOG_DEBUG_HTTP, mp4f->log, 0,
					//	"stsc[%i]: first_chunk=%i sample_count=%i desc=%i", n, chunk, cnt, be32toh(mp4_src->stsc->tbl[0].desc_id));
					n++;
				}
				chunk++;
				cnt = 0;
				sample += avg_sample_cnt;
			}
		}

		if (cnt && (n == 0 || be32toh(stsc->tbl[n - 1].sample_cnt) != cnt)) {
			stsc->tbl[n].first_chunk = htobe32(chunk);
			stsc->tbl[n].sample_cnt = htobe32(cnt);
			stsc->tbl[n].desc_id = mp4_src->stsc->tbl[0].desc_id;
			//ngx_log_debug4(NGX_LOG_DEBUG_HTTP, mp4f->log, 0,
			//	"stsc[%i]: first_chunk=%i sample_count=%i desc=%i", n, chunk, cnt, be32toh(mp4_src->stsc->tbl[0].desc_id));
			n++;
		}
		stsc->sample_cnt = htobe32(n);
		a->hdr->size = htobe32(sizeof(*stsc) + n * 12);
	}
	ngx_log_debug1(NGX_LOG_DEBUG_HTTP, mp4f->log, 0,
			"stsc: sample_count=%i", be32toh(stsc->sample_cnt));
	//===================


	// build stco atom 
	// ==================
	a = ngx_palloc(mp4f->pool, sizeof(*a) + sizeof(mp4_atom_stco_t) + (stco_cnt + 2) * (co64 ? 8 : 4));
	if (!a)
		return NULL;
	
	a->hdr = (mp4_atom_hdr_t*)a->data;
	a->hdr->type = co64 ? ATOM('c', 'o', '6', '4') : ATOM('s', 't', 'c', 'o');
	a->hdr->size = htobe32(sizeof(mp4_atom_stco_t) + stco_cnt * ( co64 ? 8 : 4));
	a->parent = stbl;
	MP4MUX_INIT_LIST_HEAD(&a->atoms);
	mp4mux_list_add_tail(&a->entry, &stbl->atoms);

	stco = (mp4_atom_stco_t *)a->hdr;
	stco->version = 0;
	stco->flags = 0;
	stco->chunk_cnt = htobe32(stco_cnt);
	
	//mp4_src->chunk_pos = mp4_src->mdat_pos;
	mp4_src->chunk_cnt = stco_cnt;
	mp4_src->chunk_size = ngx_palloc(pool, (stco_cnt + 1) * sizeof(ngx_uint_t));
	//mp4_src->chunk_pos[i] = ctx->mp4_src[i]->mdat_pos;

	/*if (mp4_src->stsz->sample_size) {
		for (i = 1; i < stco_cnt; i++, ptr2++) {
			if (co64) {
				*(uint64_t *)ptr2 = stsc_n * be32toh(mp4_src->stsz->sample_size);
				ptr2++;
			} else
				*ptr2 = stsc_n * be32toh(mp4_src->stsz->sample_size);
		}
		pos = stsc_n * stco_cnt * be32toh(mp4_src->stsz->sample_size);
	} else*/ {
		prev_pos = 0; pos = 0; n = 0; sample = avg_sample_cnt - 1;
		for (i = 0, ptr = mp4_src->stsz->tbl; i < s_cnt; i++, ptr++) {
			if (mp4_src->stsz->sample_size)
				pos += be32toh(mp4_src->stsz->sample_size);
			else
				pos += be32toh(*ptr);
			
			if (i >= sample) {
				mp4_src->chunk_size[n] = pos - prev_pos;
			
				//ngx_log_debug3(NGX_LOG_DEBUG_HTTP, mp4f->log, 0,
				//	"stco[%i]: len=%i pos=%i", n, pos - prev_pos, pos);
				
				n++;
				prev_pos = pos;
				sample += avg_sample_cnt;
			}
		}
		ngx_log_debug4(NGX_LOG_DEBUG_HTTP, mp4f->log, 0,
				"stco[last]: len=%i pos=%i mdat_size=%i n=%i", pos - prev_pos, pos, mp4_src->mdat_size, n);
		mp4_src->chunk_size[n] = mp4_src->mdat_size - prev_pos;
	}

	return stco;
}

static ngx_int_t mp4_add_mdat(mp4_file_t *mp4f, off_t size, ngx_int_t co64)
{
	mp4_atom_t *a;
	
	/*a = ngx_pcalloc(mp4f->pool, sizeof(*a) + sizeof(mp4_atom_hdr_t));
	if (!a)
		return -1;
	
	MP4MUX_INIT_LIST_HEAD(&a->atoms);
	a->hdr = (mp4_atom_hdr_t *)a->data;
	a->hdr->type = ATOM('f', 'r', 'e', 'e');
	a->hdr->size = htobe32(sizeof(mp4_atom_hdr_t));
	mp4mux_list_add_tail(&a->entry, &mp4f->atoms);*/
	
	a = ngx_pcalloc(mp4f->pool, sizeof(*a) + sizeof(mp4_atom_hdr_t) + (co64 ? 8 : 0));
	if (!a)
		return -1;
	
	MP4MUX_INIT_LIST_HEAD(&a->atoms);
	a->hdr = (mp4_atom_hdr_t *)a->data;
	a->hdr->type = ATOM('m', 'd', 'a', 't');
	if (co64) {
		a->hdr->size = htobe32(1);
		*(uint64_t *)a->hdr->data = htobe64(sizeof(mp4_atom_hdr_t) + 8 + size);
	} else
		a->hdr->size = htobe32(sizeof(mp4_atom_hdr_t) + size);
	
	mp4mux_list_add_tail(&a->entry, &mp4f->atoms);

	return 0;
}

static ngx_int_t __build_chain(ngx_http_mp4mux_ctx_t *ctx, struct mp4mux_list_head *list, ngx_chain_t **out, ngx_chain_t **last)
{
	mp4_atom_t *a;
  ngx_chain_t *tl;
	ngx_buf_t *b;
	char atom_name[5] = {0,0,0,0,0};

	mp4mux_list_for_each_entry(a, list, entry) {
		tl = ngx_chain_get_free_buf(ctx->req->pool, &ctx->free);
		if (!tl) {
			return -1;
		}
	
		b = tl->buf;
		b->in_file = 0;
		b->memory = 1;
		b->flush = 0;
		b->start = (u_char *)a->hdr;
		b->pos = b->start;
		if (mp4mux_list_empty(&a->atoms) && a->hdr->type != ATOM('m', 'd', 'a', 't'))
			b->end = (u_char *)a->hdr + be32toh(a->hdr->size);
		else
			b->end = (u_char *)a->hdr + sizeof(mp4_atom_hdr_t) + ((be32toh(a->hdr->size) == 1 ? 8 : 0));
		b->last = b->end;
		
		memcpy(atom_name, &a->hdr->type, 4);
		ngx_log_debug2(NGX_LOG_DEBUG_HTTP, ctx->mp4f.log, 0,
			"build_header: %s %i", atom_name, ngx_buf_size(b));

		b->tag = (ngx_buf_tag_t) &ngx_http_mp4mux_module;
		
		
		if (*out)
			(*last)->next = tl;
		else
			*out = tl;
		*last = tl;
		
		if (!mp4mux_list_empty(&a->atoms)) {
			if (__build_chain(ctx, &a->atoms, out, last))
				return -1;
		}
	}
	
	return 0;
}

static ngx_chain_t *mp4_build_chain(ngx_http_mp4mux_ctx_t *ctx, struct mp4mux_list_head *list)
{
  ngx_chain_t *out = NULL, *last = NULL;

	if (__build_chain(ctx, list, &out, &last))
		return NULL;
	
	last->buf->flush = 1;

	return out;
}

static void ngx_http_mp4mux_write_handler(ngx_event_t *ev)
{
	ngx_connection_t     *c;
	ngx_http_request_t   *r;
	//x_http_log_ctx_t   *lctx;
	ngx_http_mp4mux_ctx_t   *ctx;
	ngx_int_t rc;

	c = ev->data;
	r = c->data;

	c = r->connection;

	//tx = c->log->data;
	//tx->current_request = r;

	ctx = ngx_http_get_module_ctx(r, ngx_http_mp4mux_module);

	ngx_log_debug2(NGX_LOG_DEBUG_HTTP, c->log, 0,
								 "http m4mux request: \"%V?%V\"", &r->uri, &r->args);

        ctx->write_handler(ev);

	if (c->destroyed || r->done)
	    return;

        //if (c->write->ready && !c->busy_sendfile) {
	if (!r->out) {
		if (ctx->temp_pool) {
			ngx_destroy_pool(ctx->temp_pool);
			ctx->temp_pool = NULL;
		}

            rc = mp4mux_write(ctx);
						/*if (rc == NGX_DONE && ctx->req->buffered == 0 && ctx->req->out == NULL)
							ngx_http_finalize_request(ctx->req, NGX_DONE);
						else*/ if (rc == NGX_ERROR)
							ngx_http_finalize_request(ctx->req, NGX_ERROR);
				}
        
        return;

	if (ev->write) {
		r->write_event_handler(r);
		
		if (c->destroyed)
		    return;
		
		/*for (i = 0; ctx->mp4_src[i]; i++) {
			if (ctx->mp4_src[i]->cproxy_ctx)
				ngx_http_cproxy_handler(r, ctx->mp4_src[i]->cproxy_ctx);
		}*/
                
                //if (c->write->ready && !c->busy_sendfile)
		
		        mp4mux_write(ctx);
	} else 
		r->read_event_handler(r);

	ngx_http_run_posted_requests(c);
}

#if (NGX_HTTP_CPROXY)
static ngx_int_t mp4mux_cproxy_handler_header(ngx_http_request_t *r, ngx_chain_t *out, u_char *last, void *arg)
{
	ngx_http_mp4mux_ctx_t *ctx;
	mp4_file_t *f = arg;
	mp4_atom_hdr_t *hdr;
	ngx_int_t n;
	ngx_int_t hdr_size = sizeof(hdr) + (f->ext_hdr ? 8 : 0);
	uint32_t size;
	uint64_t size64;
	ngx_int_t rc;
	char atom_name[5];
	
	atom_name[4] = 0;

	ctx = ngx_http_get_module_ctx(r, ngx_http_mp4mux_module);

	ngx_log_debug2(NGX_LOG_DEBUG_HTTP, ctx->req->connection->log, 0,
		"mp4mux: header: %p %i", out, out ? ngx_buf_size(out->buf) : 0);

	if (!out)
		goto done;

	while (1) {
		ngx_log_debug3(NGX_LOG_DEBUG_HTTP, ctx->req->connection->log, 0,
			"mp4mux: header: %i %i %i", ngx_buf_size(out->buf), f->hdr_offset, f->buf_pos);

		if (ngx_buf_size(out->buf) < f->hdr_offset) {
			f->hdr_offset -= ngx_buf_size(out->buf);
			goto out;
		}

		if (ngx_buf_size(out->buf) < f->hdr_offset + hdr_size) {
			n = f->hdr_offset > 0 ? f->hdr_offset : 0;

			ngx_memcpy(f->buf + f->buf_pos, out->buf->pos + n, ngx_buf_size(out->buf) - n);
			f->buf_pos += ngx_buf_size(out->buf) - n;
			f->hdr_offset -= ngx_buf_size(out->buf);
			goto out;
		}

		if (f->hdr_offset < 0) {
			ngx_memcpy(f->buf + f->buf_pos, out->buf->pos, hdr_size - f->buf_pos);
			hdr = (mp4_atom_hdr_t *)f->buf;
		} else
			hdr = (mp4_atom_hdr_t *)out->buf->pos + f->hdr_offset;
		
		size = be32toh(hdr->size);

		ngx_memcpy(atom_name, &hdr->type, 4);
		ngx_log_debug2(NGX_LOG_DEBUG_HTTP, ctx->req->connection->log, 0,
			"mp4mux: header: atom %s %i", atom_name, size);

		if (size == 1 && (int)ngx_buf_size(out->buf) < (int)(f->hdr_offset + sizeof(*hdr) + 8)) {
			f->ext_hdr = 1;
			n = f->hdr_offset > 0 ? f->hdr_offset : 0;
			ngx_memcpy(f->buf + f->buf_pos, out->buf->pos + n, ngx_buf_size(out->buf) - n);
			f->buf_pos += ngx_buf_size(out->buf) - n;
			f->hdr_offset -= ngx_buf_size(out->buf);
			goto out;
		}

		f->buf_pos = 0;
		f->ext_hdr = 0;

		if (size == 1)
			size64 = *(uint64_t *)(hdr + 1);
		else
			size64 = size;
		
		if (hdr->type == ATOM('m', 'd', 'a', 't')) {
			if (size == 0)
				goto done;

			f->hdr_offset = 0;

			rc = ngx_http_cproxy_request(r, &f->url, &f->fname, -1, f->mdat_pos + size64, CPROXY_OPT_SYNC | CPROXY_OPT_OFFSET | CPROXY_OPT_NO_FG, mp4mux_cproxy_handler_header, f, &f->cproxy_ctx);
		
			if (rc == NGX_DECLINED)
				goto done;

			if (rc == NGX_ERROR)
				ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
		
			out->buf->pos = out->buf->last;
			return NGX_DONE;
		} else {
			f->mdat_pos += size64;
			if (out->buf->pos + size64 >= out->buf->last) {
				f->hdr_offset = out->buf->pos + size64 - out->buf->last;
				goto out;
			}
			f->hdr_offset = 0;
			out->buf->pos += size64;		
		}
	}

out:
	out->buf->pos = out->buf->last;
	return NGX_OK;

done:
	ngx_log_debug2(NGX_LOG_DEBUG_HTTP, ctx->req->connection->log, 0,
		"mp4mux: done: \"%V\" %i", &f->fname, ctx->wait_remote);

	if (--ctx->wait_remote == 0) {
		rc = mp4mux_send_response(ctx);

		if (rc != NGX_OK)
			ngx_http_finalize_request(r, rc);
	}
	return NGX_DONE;
}

static ngx_int_t mp4mux_cproxy_handler_mdat(ngx_http_request_t *r, ngx_chain_t *out, u_char *last, void *arg)
{
	ngx_http_mp4mux_ctx_t *ctx;
	mp4_file_t *f = arg;	

	ctx = ngx_http_get_module_ctx(r, ngx_http_mp4mux_module);

	ngx_log_debug2(NGX_LOG_DEBUG_HTTP, ctx->req->connection->log, 0,
		"mp4mux: mdat: %p %O", out, f->mdat_recv);

	if (!out)
		return NGX_OK;
	
	f->mdat_recv += last ? (out->buf->last - last) : ngx_buf_size(out->buf);
	
	ngx_log_debug2(NGX_LOG_DEBUG_HTTP, ctx->req->connection->log, 0,
		"mp4mux: mdat: %O %O", f->mdat_recv, last ? (out->buf->last - last) : ngx_buf_size(out->buf));

	if (f->wait) {
		f->wait = 0;
		mp4mux_write(ctx);
	}

	out->buf->pos = out->buf->last;

	return NGX_OK;
}
#endif

static void *
ngx_http_mp4mux_create_conf(ngx_conf_t *cf)
{
    ngx_http_mp4mux_conf_t  *conf;

    conf = ngx_palloc(cf->pool, sizeof(ngx_http_mp4mux_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->chunk_size = NGX_CONF_UNSET_SIZE;
    conf->move_meta = NGX_CONF_UNSET;

    return conf;
}


static char *
ngx_http_mp4mux_merge_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_mp4mux_conf_t *prev = parent;
    ngx_http_mp4mux_conf_t *conf = child;

    ngx_conf_merge_size_value(conf->chunk_size, prev->chunk_size, 16 * 1024);
    ngx_conf_merge_value(conf->move_meta, prev->move_meta, 1);

    return NGX_CONF_OK;
}
