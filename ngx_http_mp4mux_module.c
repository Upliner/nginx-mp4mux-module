
/*
 * Copyright (C) Igor Sysoev
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_string.h>
#include <ngx_files.h>
#include <nginx.h>

#if (NGX_FREEBSD)
#include <sys/endian.h>
#endif

#include "ngx_http_mp4mux_list.h"
#include "hls.h"

#define MAX_FILE 10
#define MAX_ATOM_SIZE 16*1024*1024

#if __BYTE_ORDER == __LITTLE_ENDIAN
#define ATOM(n1,n2,n3,n4) (((uint32_t)n4<<24)|((uint32_t)n3<<16)|((uint32_t)n2<<8)|(uint32_t)n1)
#else
#define ATOM(n1,n2,n3,n4) (((uint32_t)n1<<24)|((uint32_t)n2<<16)|((uint32_t)n3<<8)|(uint32_t)n4)
#endif

#ifndef __packed
#define __packed __attribute__((packed))
#endif

#define FMT_MP4 0x00
#define FMT_HLS_INDEX 0x10
#define FMT_HLS_SEGMENT 0x11

#define TS_TYP1_START 0x41
#define TS_TYP1_CONTINUE 0x01

#define TS_TYP2_PAYLD 0x10
#define TS_TYP2_ADAPT_PAYLD 0x30

#define HLS_AUDIO_PACKET_LEN 2930

#define PES_VIDEO 0xe0
#define PES_AUDIO 0xc0

#define SECTOR_SIZE 4096  // you can set it to 512 if you don't use 4Kn drives

typedef u_char bool_t;

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
	u_char version;
	u_char prof_ind;
	u_char prof_comp;
	u_char level;
	u_char sf_len;
	u_char data[0];
} __packed mp4_atom_avcC_t;

typedef struct {
	mp4_atom_hdr_t hdr;
	uint32_t version:8;
	uint32_t flags:24;
	uint32_t entries;
	u_char reserved[16];
	uint16_t width;
	uint16_t height;
	uint32_t hres;
	uint32_t vres;
	uint32_t data_size;
	uint16_t fpsamp;
	u_char	codec_name[32];
	uint16_t bpcs;
	uint16_t ct_id;
	mp4_atom_avcC_t avcC;
} __packed mp4_atom_avc1_t;

typedef struct {
	mp4_atom_hdr_t hdr;
	uint32_t version:8;
	uint32_t flags:24;
	uint32_t entries;
	u_char reserved[20];
	mp4_atom_hdr_t esds;
} __packed mp4_atom_mp4a_t;

typedef struct {
	mp4_atom_hdr_t hdr;
	uint32_t version:8;
	uint32_t flags:24;
	uint32_t entries;
	union {
		mp4_atom_hdr_t hdr;
		mp4_atom_avc1_t avc1;
		mp4_atom_mp4a_t mp4a;
	} entry;
} __packed mp4_atom_stsd_t;

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

typedef struct {
	mp4mux_list_t entry;
	u_char *data, *data_end;
	size_t offs, offs_end;
	size_t size;
	bool_t persist;
	bool_t eof;
	bool_t aio_done;
} mp4_buf_t;

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
	uint32_t entry_count;
	uint32_t entry_no;
	uint32_t samp_left;
	uint32_t value;
} mp4_stbl_ptr_t;

typedef struct {
	uint32_t entry_count;
	uint32_t chunk_count;
	uint32_t entry_no;
	uint32_t chunk_no;
	uint32_t next;
	uint32_t samp_left;
	uint32_t samp_cnt;
} mp4_stsc_ptr_t;

typedef struct {
	u_char *cdata;        // raw codec-specific data (PPS and SPS for H.264)
	ngx_int_t cdata_len;
	uint32_t adts_hdr;    // First 4 bytes of ADTS frame header
	u_char pes_id;        // PES stream id
	u_char pes_typ;       // video or audio
	u_char sf_len;        // Length of mp4 subframe size field

	mp4_atom_stts_t *stts;
	mp4_atom_ctts_t *ctts;
	mp4_atom_stss_t *stss;
	mp4_stbl_ptr_t stts_ptr;
	mp4_stbl_ptr_t ctts_ptr;
	mp4_stsc_ptr_t stsc_ptr;
	mp4_atom_stco_t *co;
	bool_t co64;

	uint32_t frame_no;
	uint32_t sample_no;
	uint32_t timescale;
	uint32_t dts;
	uint32_t sample_max;
	off_t frame_offs;

	u_char cocnt;       // MPEG-TS continuity counter
	bool_t eof;
	off_t packet_count;

	uint32_t stss_ptr;
	uint32_t next_keyframe;
} mp4_hls_ctx_t;

typedef struct {
	struct mp4mux_list_head atoms;
	struct mp4mux_list_head atoms_tail;

	ngx_http_request_t *req;
	ngx_pool_t *pool;
	ngx_log_t *log;
	ngx_file_t file;

	ngx_str_t url;
	ngx_str_t fname;

	mp4_atom_t *moov;
	mp4_atom_t *trak;
	mp4_atom_mvhd_t *mvhd;
	mp4_atom_stsz_t *stsz;
	mp4_atom_stsc_t *stsc;
	mp4_atom_t *stbl;

	size_t file_size;
	time_t file_mtime;
	size_t mdat_pos;
	size_t mdat_size;
	ngx_uint_t mdat_recv;

	ngx_uint_t *chunk_size;
	ngx_uint_t chunk_cnt;

	// Read buffers
	mp4mux_list_t rdbufs;
	mp4mux_list_t free_rdbufs;
	mp4_buf_t *rdbuf_cur;
	size_t rdbuf_size;
	size_t offs, offs_restart, offs_buf;
	ngx_int_t rd_offs;
	#if (NGX_HAVE_FILE_AIO)
	bool_t aio;
	// Data for async reading of large atoms (like moov)
	mp4_atom_t *aio_atom;
	mp4_buf_t *aio_buf;
	#endif

	mp4_hls_ctx_t *hls_ctx;
} mp4_file_t;

typedef struct ngx_http_mp4mux_ctx_s {
	ngx_http_request_t *req;
	ngx_event_handler_pt write_handler;
	#if (NGX_HAVE_FILE_AIO)
	ngx_int_t (*aio_handler)(struct ngx_http_mp4mux_ctx_s *);
	#endif
	ngx_chain_t *free;
	ngx_chain_t *busy;
	ngx_chain_t *chain, *chain_last;
	mp4_file_t mp4f;
	mp4_file_t *mp4_src[MAX_FILE];
	ngx_int_t fmt;
	ngx_int_t hls_seg;
	ngx_int_t hls_bufsize;
	ngx_int_t cur_trak;
	ngx_int_t trak_cnt;
	ngx_uint_t chunk_num;
	ngx_int_t start;
	ngx_int_t move_meta;
	ngx_int_t segment_ms;
	ngx_int_t done:1;
	bool_t strict_cl;
} ngx_http_mp4mux_ctx_t;

typedef struct {
	size_t    rdbuf_size;
	size_t    wrbuf_size;
	ngx_int_t move_meta;
	ngx_int_t segment_ms;
} ngx_http_mp4mux_conf_t;

static uint32_t mp4_atom_containers[] = {
	ATOM('m', 'o', 'o', 'v'),
	ATOM('t', 'r', 'a', 'k'),
	ATOM('m', 'd', 'i', 'a'),
	ATOM('m', 'i', 'n', 'f'),
	ATOM('s', 't', 'b', 'l')
};

static const u_char m3u8_header[] =
	"#EXTM3U\n"
	"#EXT-X-ALLOW-CACHE:YES\n"
	"#EXT-X-PLAYLIST-TYPE:VOD\n"
	"#EXT-X-VERSION:3\n"
	"#EXT-X-MEDIA-SEQUENCE:1\n"
	"#EXT-X-TARGETDURATION:";

static const char m3u8_entry[] = "#EXTINF:%i.%03i,\nhttp://%V%V&fmt=hls/seg-%i.ts\n";

static const u_char m3u8_footer[] = "#EXT-X-ENDLIST\n";

static char *ngx_http_mp4mux(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static void *ngx_http_mp4mux_create_conf(ngx_conf_t *cf);
static char *ngx_http_mp4mux_merge_conf(ngx_conf_t *cf, void *parent, void *child);

static ngx_int_t mp4mux_do_read(mp4_file_t *f, mp4_buf_t *buf);
static ngx_int_t mp4mux_seek(mp4_file_t *f, size_t offs);
static ngx_int_t mp4mux_read(mp4_file_t *f, u_char *data, size_t size, bool_t noreturn);
static ngx_int_t mp4mux_read_direct(mp4_file_t *f, u_char **data, size_t size); // Read large data block without intermediary buffers
static void mp4mux_free_rdbuf(mp4_file_t *f, mp4_buf_t *buf);

static ngx_int_t mp4_parse(mp4_file_t *f);
static ngx_int_t mp4_clone(mp4_file_t *src, mp4_file_t *dst);
static mp4_atom_t *mp4_clone_atom(mp4_atom_t *src, mp4_atom_t *parent, mp4_file_t *dst);
static mp4_atom_t *mp4_find_atom(struct mp4mux_list_head *list, uint32_t type);
static off_t mp4_build_atoms(mp4_file_t *mp4f);
static off_t mp4_build_atoms_tail(mp4_file_t *mp4f);
static mp4_atom_stco_t *mp4_alloc_chunks(mp4_file_t *mp4f, mp4_atom_t *trak, mp4_file_t *mp4_src, int co64, double avg_chunk_size, ngx_pool_t *pool);
static ngx_int_t mp4_add_mdat(mp4_file_t *mp4f, off_t size, ngx_int_t co64);
static ngx_int_t mp4_tkhd_update(mp4_atom_t *trak, ngx_uint_t id, uint64_t start, uint32_t old_timescale, uint32_t new_timescale);
static ngx_chain_t *mp4_build_chain(ngx_http_mp4mux_ctx_t *ctx, struct mp4mux_list_head *list);
static void mp4_split(mp4_file_t *mp4f);
static ngx_int_t mp4_adjust_pos(mp4_file_t *mp4f, mp4_atom_t *trak, uint64_t start);
static ngx_int_t mp4mux_write(ngx_http_mp4mux_ctx_t *ctx);
static ngx_int_t mp4mux_hls_write(ngx_http_mp4mux_ctx_t *ctx);
static void ngx_http_mp4mux_write_handler(ngx_event_t *ev);
static ngx_int_t mp4mux_send_response(ngx_http_mp4mux_ctx_t *ctx);
static ngx_int_t mp4mux_hls_send_index(ngx_http_mp4mux_ctx_t *ctx);
static ngx_int_t mp4mux_hls_send_segment(ngx_http_mp4mux_ctx_t *ctx);

static ngx_command_t  ngx_http_mp4mux_commands[] = {

	{ ngx_string("mp4mux"),
	  NGX_HTTP_LOC_CONF|NGX_CONF_NOARGS,
	  ngx_http_mp4mux,
	  0,
	  0,
	  NULL },

	{ ngx_string("mp4mux_rdbuf_size"),
	  NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
	  ngx_conf_set_size_slot,
	  NGX_HTTP_LOC_CONF_OFFSET,
	  offsetof(ngx_http_mp4mux_conf_t, rdbuf_size),
	  NULL },

	{ ngx_string("mp4mux_wrbuf_size"),
	  NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
	  ngx_conf_set_size_slot,
	  NGX_HTTP_LOC_CONF_OFFSET,
	  offsetof(ngx_http_mp4mux_conf_t, wrbuf_size),
	  NULL },

	{ ngx_string("mp4mux_move_meta"),
	  NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
	  ngx_conf_set_flag_slot,
	  NGX_HTTP_LOC_CONF_OFFSET,
	  offsetof(ngx_http_mp4mux_conf_t, move_meta),
	  NULL },

	{ ngx_string("mp4mux_segment_duration"),
	  NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
	  ngx_conf_set_msec_slot,
	  NGX_HTTP_LOC_CONF_OFFSET,
	  offsetof(ngx_http_mp4mux_conf_t, segment_ms),
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

	ngx_http_mp4mux_create_conf,   /* create location configuration */
	ngx_http_mp4mux_merge_conf     /* merge location configuration */
};


ngx_module_t  ngx_http_mp4mux_module = {
	NGX_MODULE_V1,
	&ngx_http_mp4mux_module_ctx,   /* module context */
	ngx_http_mp4mux_commands,      /* module directives */
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

u_char* parseint(u_char *str, u_char *end, ngx_int_t *result)
{
	*result = 0;
	while (str < end && *str >= '0' && *str <= '9')
		*result = *result * 10 + *str++ - '0';
	return str;
}

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
	ngx_log_t *log = r->connection->log;

	ngx_log_debug0(NGX_LOG_DEBUG_HTTP, log, 0,
		"http_mp4mux_handler");

	if (!(r->method & (NGX_HTTP_GET|NGX_HTTP_HEAD)))
		return NGX_HTTP_NOT_ALLOWED;

	if (!r->args.len)
		return NGX_HTTP_NOT_FOUND;

	rc = ngx_http_discard_request_body(r);

	if (rc != NGX_OK)
		return rc;

	conf = ngx_http_get_module_loc_conf(r, ngx_http_mp4mux_module);

	last = ngx_http_map_uri_to_path(r, &path, &root, 0);
	if (last == NULL)
		return NGX_HTTP_INTERNAL_SERVER_ERROR;

	path.len = last - path.data;

	ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_mp4mux_ctx_t));

	if (ctx == NULL)
		return NGX_HTTP_INTERNAL_SERVER_ERROR;

	ctx->req = r;

	ngx_http_set_ctx(r, ctx, ngx_http_mp4mux_module);

	for (i = 0, n = 0; i < r->args.len && i < MAX_FILE; i++) {
		ngx_memzero(argname, 10);
		ngx_sprintf(argname, "file%i", i);
		if (ngx_http_arg(r, (u_char *) argname, ngx_strlen(argname), &value) == NGX_OK) {

			ngx_log_debug1(NGX_LOG_DEBUG_HTTP, log, 0,
				"mp4mux: arg \"%V\"", &value);

			ctx->mp4_src[n] = ngx_pcalloc(r->pool, sizeof(mp4_file_t));
			if (!ctx->mp4_src[n])
				return NGX_HTTP_INTERNAL_SERVER_ERROR;

			ctx->mp4_src[n]->req = r;
			ctx->mp4_src[n]->log = log;
			ctx->mp4_src[n]->pool = r->pool;

			fname.len = path.len + value.len;
			fname.data = ngx_pnalloc(r->pool, fname.len + 1);
			ngx_memcpy(fname.data, path.data, path.len);
			ngx_memcpy(fname.data + path.len, value.data, value.len);
			fname.data[fname.len] = 0;

			ctx->mp4_src[n]->fname = fname;

			n++;
		}
	}

	if (ngx_http_arg(r, (u_char *) "start", 5, &value) == NGX_OK)
		ctx->start = (int) (strtod((char *) value.data, NULL) * 1000);
	else
		ctx->start = 0;

	ngx_log_debug1(NGX_LOG_DEBUG_HTTP, log, 0,
		"start=%L", ctx->start);

	if (ngx_http_arg(r, (u_char *)"move_meta", 9, &value) == NGX_OK)
		ctx->move_meta = atoi((char *)value.data);
	else
		ctx->move_meta = conf->move_meta;

	ctx->segment_ms = conf->segment_ms;

	if (ngx_http_arg(r, (u_char *)"fmt", 3, &value) == NGX_OK) {
		if (value.len == 3 && ngx_memcmp(value.data, "mp4", 3) == 0)
			ctx->fmt = FMT_MP4;
		else if (value.len == 14 && ngx_memcmp(value.data, "hls/index.m3u8", 14) == 0)
			ctx->fmt = FMT_HLS_INDEX;
		else if (value.len >= 8 && ngx_memcmp(value.data, "hls/seg-", 8) == 0) {
			last = value.data + value.len - 3;
			if (ngx_memcmp(last, ".ts", 3)) {
				ngx_log_error(NGX_LOG_ERR, log, 0,
					"mp4mux: only .ts segments are supported for HLS, queried \"%V\"", &value);
				return NGX_HTTP_NOT_FOUND;
			}
			if (parseint(value.data + 8, last, &ctx->hls_seg) != last) {
				ngx_log_error(NGX_LOG_ERR, log, 0,
					"mp4mux: error parsing segment number in \"%V\"", &value);
				return NGX_HTTP_NOT_FOUND;
			}
			if (ctx->hls_seg == 0) {
				ngx_log_error(NGX_LOG_ERR, log, 0,
					"mp4mux: invalid HLS segment number in \"%V\"", &value);
				return NGX_HTTP_NOT_FOUND;
			}
			ctx->fmt = FMT_HLS_SEGMENT;
			ctx->hls_bufsize = conf->wrbuf_size/MPEGTS_PACKET_SIZE;
			if (ctx->hls_bufsize < 5) ctx->hls_bufsize = 5;
			ctx->hls_bufsize *= MPEGTS_PACKET_SIZE;
		} else {
			ngx_log_error(NGX_LOG_ERR, log, 0,
				"mp4mux: invalid fmt argument \"%V\"", &value);
			return NGX_HTTP_NOT_FOUND;
		}
	} else
		ctx->fmt = FMT_MP4;

	if (ctx->fmt != FMT_MP4 && ctx->start) {
			ngx_log_error(NGX_LOG_ERR, log, 0,
				"mp4mux: \"start\" parameter is invalid for HLS");
			return NGX_HTTP_NOT_FOUND;
	}

	r->allow_ranges = 1;
	ctx->trak_cnt = n;
	ctx->cur_trak = 0;
	ctx->write_handler = r->connection->write->handler;

	#if (NGX_HAVE_FILE_AIO)
	ctx->aio_handler = mp4mux_send_response;
	#endif
	return mp4mux_send_response(ctx);
}
#if (NGX_HAVE_FILE_AIO)
static void ngx_http_mp4mux_read_handler(ngx_event_t *ev) {
	ngx_event_aio_t *aio;
	mp4_file_t *f;
	ngx_http_request_t *req;
	mp4_buf_t *buf;
	ngx_http_mp4mux_ctx_t *ctx;
	ngx_int_t rc;

	aio = ev->data;
	f = aio->data;
	ngx_log_debug2(NGX_LOG_DEBUG_HTTP, f->log, 0, "started aio read handler, file: %p, fd = %i", f, f->file.fd);
	req = f->req;
	buf = f->aio_buf;
	if (buf == NULL) {
		ngx_log_error(NGX_LOG_ERR, f->log, 0, "aio buffer is null!");
		ngx_http_finalize_request(req, NGX_HTTP_INTERNAL_SERVER_ERROR);
		return;
	}

	req->blocked--;
	ngx_log_debug1(NGX_LOG_DEBUG_HTTP, f->log, 0, "blocked = %i", req->blocked);
	rc = ngx_file_aio_read(&f->file, NULL, 0, 0, f->pool);
	if (rc < 0)
	{
		ngx_log_error(NGX_LOG_ERR, f->log, 0, "async read failed, rc = %i", rc);
		ngx_http_finalize_request(req, NGX_HTTP_INTERNAL_SERVER_ERROR);
		return;
	}
	if (rc != (ngx_int_t)(buf->offs_end - buf->offs - f->rd_offs)) {
		ngx_log_error(NGX_LOG_ERR, f->log, 0,
			"async: wrong byte count read %i, expected %i", rc, buf->offs_end - buf->offs - f->rd_offs);
		ngx_http_finalize_request(req, NGX_HTTP_INTERNAL_SERVER_ERROR);
		return;
	}
	buf->aio_done = 1;
	f->rd_offs = 0;
	f->aio_buf = NULL;
	do { // Read next bufs if any
		buf = mp4mux_list_entry(buf->entry.next, mp4_buf_t, entry);
		ngx_log_debug2(NGX_LOG_DEBUG_HTTP, f->log, 0, "next buf = %p, rdbufs=%p", buf, &f->rdbufs);
		if (&buf->entry == &f->rdbufs || buf->aio_done) break;
		rc = mp4mux_do_read(f, buf);
		if (rc == NGX_AGAIN) return;
		if (rc != NGX_OK) {
			ngx_log_error(NGX_LOG_ERR, f->log, 0,
				"ngx_http_mp4mux_read_handler: error while reading next buf");
			ngx_http_finalize_request(req, NGX_HTTP_INTERNAL_SERVER_ERROR);
			return;
		}
	} while (1);

	if (req->blocked) return;
	ctx = ngx_http_get_module_ctx(req, ngx_http_mp4mux_module);
	if (ctx->done) return;

	if (f->offs != f->offs_restart) {
		ngx_log_debug0(NGX_LOG_DEBUG_HTTP, f->log, 0,
			"restarting at offs " + f->offs_restart);
		mp4mux_seek(f, f->offs_restart);
	}

	ngx_log_debug0(NGX_LOG_DEBUG_HTTP, f->log, 0,
		"calling context handler");
	rc = ctx->aio_handler(ctx);
	if (rc != NGX_AGAIN)
		ngx_http_finalize_request(req, rc);
}
#endif
static ngx_int_t mp4mux_checkeof(mp4_file_t *f, mp4_buf_t *buf)
{
	ngx_int_t newsz;
	if (buf->offs_end >= f->file_size) {
		buf->eof = 1;
		buf->offs_end = f->file_size;
		newsz = buf->offs_end - buf->offs;
	} else
		newsz = buf->size;
	buf->data_end = buf->data + newsz;
	return newsz;
}
static ngx_int_t mp4mux_do_read(mp4_file_t *f, mp4_buf_t *buf)
{
	ngx_int_t rc, newsz;
	if (buf == NULL) {
		ngx_log_error(NGX_LOG_ERR, f->log, 0,
			"mp4mux_do_read: buf is null");
		return NGX_ERROR;
	}

	newsz = mp4mux_checkeof(f, buf);

	#if (NGX_HAVE_FILE_AIO)
	if (f->aio) {
		if (f->aio_buf != NULL) {
			ngx_log_debug0(NGX_LOG_DEBUG_HTTP, f->log, 0,
				"mp4mux_do_read: avoiding second aio post");
			return NGX_AGAIN;
		}
		rc = ngx_file_aio_read(&f->file, buf->data + f->rd_offs,
			buf->size - f->rd_offs, buf->offs + f->rd_offs, f->pool);
		if (rc == NGX_AGAIN) {
			f->file.aio->data = f;
			f->file.aio->handler = ngx_http_mp4mux_read_handler;
			f->aio_buf = buf;
			f->req->blocked++;
		}
	} else
	#endif
		rc = ngx_read_file(&f->file, buf->data + f->rd_offs,
			buf->size - f->rd_offs, buf->offs + f->rd_offs);

	buf->aio_done = 0;
	if (rc < 0)
		return rc;
	if (rc != newsz - f->rd_offs)
		return NGX_ERROR;
	buf->aio_done = 1;
	f->rd_offs = 0;
	return NGX_OK;
}
static void mp4mux_free_rdbuf(mp4_file_t *f, mp4_buf_t *buf)
{
	if (buf->persist || !buf->aio_done) {
		ngx_log_debug3(NGX_LOG_DEBUG_HTTP, f->log, 0,
			"preserving buf %p: persist = %i, aio_done = %i", buf, buf->persist, buf->aio_done);
		return;
	}
	ngx_log_debug1(NGX_LOG_DEBUG_HTTP, f->log, 0,
		"freeing buf %p", buf);
	mp4mux_list_del(&buf->entry);
	if (buf->size == f->rdbuf_size) {
		mp4mux_list_add(&buf->entry, &f->free_rdbufs);
	} else {
		ngx_pfree(f->pool, buf->data);
		ngx_pfree(f->pool, buf);
	}
}
static mp4_buf_t *mp4mux_alloc_rdbuf(mp4_file_t *f, size_t size)
{
	mp4_buf_t *buf = ngx_pcalloc(f->pool, sizeof(mp4_buf_t));
	if (buf == NULL)
		return NULL;
	if (f->file.directio)
		buf->data = ngx_pmemalign(f->pool, size, SECTOR_SIZE);
	else
		buf->data = ngx_palloc(f->pool, size);
	buf->size = size;
	if (buf->data == NULL)
		return NULL;
	return buf;
}
static mp4_buf_t *mp4mux_get_rdbuf_sz(mp4_file_t *f, size_t size, size_t offs)
{
	ngx_int_t rc;
	mp4_buf_t *buf;
	ngx_log_debug2(NGX_LOG_ERR, f->log, 0,
		"mp4mux_get_rdbuf_sz() size %i, offs %i", size, offs);
	if (offs >= f->file_size) {
		ngx_log_error(NGX_LOG_ERR, f->log, 0,
			"mp4mux_get_rdbuf_sz(): tried to go beyond the end of file, offs = %i", offs);
		return NULL;
	}
	buf = mp4mux_alloc_rdbuf(f, size);
	buf->offs = offs;
	buf->offs_end = offs + size;
	rc = mp4mux_do_read(f, buf);
	if (rc != NGX_OK && rc != NGX_AGAIN)
		return NULL;
	return buf;
}
static mp4_buf_t *mp4mux_get_rdbuf(mp4_file_t *f, size_t offs)
{
	mp4_buf_t *buf;
	ngx_int_t rc;
	while (!mp4mux_list_empty(&f->free_rdbufs)) {
		buf = mp4mux_list_entry(f->free_rdbufs.next, mp4_buf_t, entry);
		mp4mux_list_del(&buf->entry);
		if (buf->size != f->rdbuf_size) {
			ngx_pfree(f->pool, buf->data);
			ngx_pfree(f->pool, buf);
		} else {
			if (offs >= f->file_size) {
				ngx_log_error(NGX_LOG_ERR, f->log, 0,
					"mp4mux_get_rdbuf(): tried to go beyond the end of file!");
				return NULL;
			}
			buf->offs = offs;
			buf->offs_end = offs + buf->size;
			rc = mp4mux_do_read(f, buf);
			if (rc < 0 && rc != NGX_AGAIN)
				return NULL;
			return buf;
		}
	}
	return mp4mux_get_rdbuf_sz(f, f->rdbuf_size, offs);
}
static mp4_buf_t *mp4mux_preread(mp4_file_t *f)
{
	mp4mux_list_t *entry;
	mp4_buf_t *buf;
	size_t offs;

	if (mp4mux_list_empty(&f->rdbufs)) {
		offs = 0;
		entry = &f->rdbufs;
	} else {
		buf = f->rdbuf_cur;
		do {
			ngx_log_debug7(NGX_LOG_DEBUG_HTTP, f->log, 0,
				"preread buf %p: offs = %i offs_end = %i aio_done = %i persist = %i data = %p rdbufs = %p",
				buf, buf->offs, buf->offs_end, buf->aio_done, buf->persist, buf->data, &f->rdbufs);
			offs = buf->offs_end;
			buf = mp4mux_list_entry(buf->entry.next, mp4_buf_t, entry);
		} while (&buf->entry != &f->rdbufs && buf->offs <= offs);
		entry = &buf->entry;
		if (entry == &f->rdbufs && mp4mux_list_entry(entry->prev, mp4_buf_t, entry)->eof)
			return NULL; // Reached EOF
	}
	buf = mp4mux_get_rdbuf(f, offs);

	ngx_log_debug3(NGX_LOG_DEBUG_HTTP, f->log, 0,
		"mp4mux_preread() = %p, offs = %i, entry = %p", buf, offs, entry);

	if (buf == NULL)
		return NULL;

	mp4mux_list_add_tail(&buf->entry, entry);
	if (f->rdbuf_cur == NULL)
		f->rdbuf_cur = buf;

	return buf;
}

static ngx_int_t mp4mux_open_file( mp4_file_t *f)
{
	ngx_open_file_info_t       of;
	ngx_http_core_loc_conf_t  *clcf;
	ngx_uint_t level;
	ngx_int_t rc;

	if (f->file_size) // File was opened, but not parsed yet
		return mp4_parse(f);

	clcf = ngx_http_get_module_loc_conf(f->req, ngx_http_core_module);

	ngx_memzero(&of, sizeof(of));
	of.read_ahead = clcf->read_ahead;
	of.directio = clcf->directio;
	of.valid = clcf->open_file_cache_valid;
	of.min_uses = clcf->open_file_cache_min_uses;
	of.errors = clcf->open_file_cache_errors;
	of.events = clcf->open_file_cache_events;

	ngx_log_debug1(NGX_LOG_DEBUG_HTTP, f->log, 0,
		"mp4mux: open file: \"%V\"", &f->fname);
	if (ngx_open_cached_file(clcf->open_file_cache, &f->fname, &of, f->pool)
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
			ngx_log_error(level, f->log, of.err,
				"%s \"%V\" failed", of.failed, &f->fname);
		}

		return rc;
	}

	if (!of.is_file) {

		if (ngx_close_file(of.fd) == NGX_FILE_ERROR) {
			ngx_log_error(NGX_LOG_ALERT, f->log, ngx_errno,
				ngx_close_file_n " \"%V\" failed", &f->fname);
		}

		return NGX_DECLINED;
	}

	#if (NGX_HAVE_FILE_AIO)
	if (clcf->aio) f->aio = 1;
	#endif

	// Use one-sector buffers while parsing atoms to minimize data copying
	// during relocation of moov atom
	f->rdbuf_size = SECTOR_SIZE;

	f->file_size = of.size;
	f->file_mtime = of.mtime;
	f->file.fd = of.fd;
	f->file.name = f->fname;
	f->file.log = f->log;
	f->file.directio = of.is_directio;

	if (f->file_size < 10) {
		ngx_log_error(NGX_LOG_ERR, f->log, of.err,
			"mp4mux: file \"%V\" is too small: %i", &f->fname, f->file_size);
		return NGX_HTTP_NOT_FOUND;
	}

	MP4MUX_INIT_LIST_HEAD(&f->atoms);
	MP4MUX_INIT_LIST_HEAD(&f->rdbufs);
	MP4MUX_INIT_LIST_HEAD(&f->free_rdbufs);

	if (mp4mux_seek(f, 0) != NGX_OK)
		return NGX_HTTP_INTERNAL_SERVER_ERROR;

	return mp4_parse(f);
}
static ngx_int_t mp4mux_seek(mp4_file_t *f, size_t offs) {
	mp4mux_list_t *entry;
	mp4_buf_t *buf;
	size_t newoffs = offs / SECTOR_SIZE * SECTOR_SIZE;

	f->offs = offs;
	f->offs_restart = offs;

	ngx_log_debug2(NGX_LOG_DEBUG_HTTP, f->log, 0,
			"mp4mux_seek(%p, %i)", f, offs);

	f->offs_buf = offs - newoffs;
	if (f->offs == f->file_size) {
		f->rdbuf_cur = NULL;
		return NGX_OK;
	}
	buf = mp4mux_list_entry(f->rdbufs.prev, mp4_buf_t, entry);
	if (mp4mux_list_empty(&f->rdbufs) || offs >= buf->offs_end) {
		// Initial buf or tail
		buf = mp4mux_get_rdbuf(f, newoffs);
		if (buf == NULL)
			return NGX_ERROR;
		mp4mux_list_add_tail(&buf->entry, &f->rdbufs);
		f->rdbuf_cur = buf;
		return NGX_OK;
	}
	buf = mp4mux_list_entry(f->rdbufs.next, mp4_buf_t, entry);
	ngx_log_debug1(NGX_LOG_DEBUG_HTTP, f->log, 0,
			"first buf offs: %i", buf->offs);
	if (offs > buf->offs) {
		// middle
		if (f->rdbuf_cur != NULL && offs >= f->rdbuf_cur->offs)
			buf = f->rdbuf_cur;
		ngx_log_debug1(NGX_LOG_DEBUG_HTTP, f->log, 0,
				"middle, offs_end = %i", buf->offs_end);
		while (offs >= buf->offs_end) {
			buf = mp4mux_list_entry(buf->entry.next, mp4_buf_t, entry);
			if (&buf->entry == &f->rdbufs) {
				ngx_log_error(NGX_LOG_ERR, f->log, 0,
					"mp4mux_seek(): invalid buffers list");
				return NGX_ERROR;
			}
		}
	}
	if (offs < buf->offs) {
		ngx_log_debug(NGX_LOG_DEBUG_HTTP, f->log, 0,
				"before first", buf->offs);
		entry = &buf->entry;
		if (buf->offs - newoffs < f->rdbuf_size)
			buf = mp4mux_get_rdbuf_sz(f, newoffs, buf->offs - newoffs);
		else
			buf = mp4mux_get_rdbuf(f, newoffs);
		mp4mux_list_add_tail(&buf->entry, entry);
	} else {
		f->offs_buf = offs - buf->offs;
	}
	if (buf != f->rdbuf_cur) {
		if (f->rdbuf_cur != NULL && buf->offs_end != f->rdbuf_cur->offs)
			mp4mux_free_rdbuf(f, f->rdbuf_cur);
		f->rdbuf_cur = buf;
	}
	return NGX_OK;
}
static mp4_buf_t *mp4mux_nextrdbuf(mp4_file_t *f) {
	mp4_buf_t *buf;
	if (f->rdbuf_cur->eof)
		return NULL;
	buf = mp4mux_list_entry(f->rdbuf_cur->entry.next, mp4_buf_t, entry);
	if (&buf->entry != &f->rdbufs && buf->offs <= f->rdbuf_cur->offs_end)
		return buf;
	return mp4mux_preread(f);
}
static ngx_int_t mp4mux_read(mp4_file_t *f, u_char *data, size_t size, bool_t noreturn) {
	size_t newsiz = size;
	u_char *start;
	u_char *end;
	mp4_buf_t *oldbuf;

	if (size == 0)
		return NGX_OK;
	if (f->rdbuf_cur == NULL) {
		ngx_log_error(NGX_LOG_ERR, f->log, 0,
			"mp4mux_read(): bad seek position");
		return NGX_ERROR;
	}
	if (!f->rdbuf_cur->aio_done)
		return NGX_AGAIN;
	start = f->rdbuf_cur->data + f->offs_buf;
	end = start + size;
	if (end > f->rdbuf_cur->data_end)
		newsiz = f->rdbuf_cur->data_end - start;
	memcpy(data, start, newsiz);
	f->offs += newsiz;
	if (noreturn)
		f->offs_restart = f->offs;
	if (end < f->rdbuf_cur->data_end) {
		f->offs_buf += newsiz;
		return NGX_OK;
	}
	// next buf
	if (f->rdbuf_cur->eof) {
		if (size == newsiz)
			return NGX_OK;
		else {
			ngx_log_error(NGX_LOG_ERR, f->log, 0,
				"mp4mux_read(): tried to read beyond EOF");
			return NGX_ERROR;
		}
	}
	oldbuf = f->rdbuf_cur;
	f->rdbuf_cur = mp4mux_nextrdbuf(f);
	if (f->rdbuf_cur == NULL)
		return NGX_ERROR;
	f->offs_buf = 0;
	if (noreturn) {
		mp4mux_free_rdbuf(f, oldbuf);
	}
	return mp4mux_read(f, data + newsiz, size - newsiz, noreturn);
}
#if (NGX_HAVE_FILE_AIO)
static ngx_int_t mp4mux_readahead(mp4_file_t *f, ngx_int_t size) {
	bool_t have_incomplete;

	ngx_log_debug2(NGX_LOG_DEBUG_HTTP, f->log, 0,
			"mp4mux_readahead(): %p %i ", f, size);

	mp4_buf_t *buf = f->rdbuf_cur;
	size_t offs;
	size -= buf->size-f->offs_buf;
	have_incomplete = !buf->aio_done;
	if (!buf->aio_done) {
		ngx_log_debug1(NGX_LOG_DEBUG_HTTP, f->log, 0,
			"buf %p doesn't have aio_done!", buf);
	}
	ngx_log_debug3(NGX_LOG_DEBUG_HTTP, f->log, 0, "buf %p, prev: %p, next:%p", buf, buf->entry.prev, buf->entry.next);
	while (size > 0) {
		offs = buf->offs_end;
		buf = mp4mux_list_entry(buf->entry.next, mp4_buf_t, entry);
		ngx_log_debug3(NGX_LOG_DEBUG_HTTP, f->log, 0, "buf %p, prev: %p, next:%p", buf, buf->entry.prev, buf->entry.next);
		if (&buf->entry == &f->rdbufs || buf->offs > offs) {
			buf = mp4mux_preread(f);
			if (buf == NULL) {
				ngx_log_error(NGX_LOG_ERR, f->log, 0,
					"Preread failed!");
				return NGX_ERROR;
			}
		}
		have_incomplete |= !buf->aio_done;
		size -= buf->size;
	}
	return have_incomplete ? NGX_AGAIN : NGX_OK;
}
#endif
static ngx_int_t mp4mux_read_direct(mp4_file_t *f, u_char **data, size_t size) {
	u_char *p;
	mp4_buf_t *b, *buf;
	ngx_int_t rc;

	ngx_log_debug3(NGX_LOG_DEBUG_HTTP, f->log, 0,
			"mp4mux_read_direct(): %p %p %i", f, data, size);

	buf = mp4mux_alloc_rdbuf(f, (f->offs_buf + size + SECTOR_SIZE - 1)/SECTOR_SIZE*SECTOR_SIZE);
	if (buf == NULL)
		return NGX_ERROR;
	buf->persist = 1;
	buf->offs = f->rdbuf_cur->offs;
	buf->offs_end = f->rdbuf_cur->offs + buf->size;
	*data = buf->data + f->offs_buf;
	f->rd_offs = 0;
	p = buf->data;
	for (b = f->rdbuf_cur; &b->entry != &f->rdbufs; f->rdbuf_cur = b) {
		ngx_memcpy(p, b->data, b->size);
		ngx_log_debug3(NGX_LOG_DEBUG_HTTP, f->log, 0,
				"memcpy %p %p %i", p, b->data, b->size);
		p += b->size;
		f->rd_offs += b->size;
		ngx_log_debug1(NGX_LOG_DEBUG_HTTP, f->log, 0,
				"rd_offs = %i", f->rd_offs);
		b = mp4mux_list_entry(f->rdbuf_cur->entry.next, mp4_buf_t, entry);
		mp4mux_free_rdbuf(f, f->rdbuf_cur);
		if (f->rdbuf_cur->offs_end != b->offs) break;
	}
	mp4mux_list_add_tail(&buf->entry, &b->entry);
	rc = mp4mux_do_read(f, buf);
	if (mp4mux_seek(f, f->offs + size) != NGX_OK)
		return NGX_ERROR;
	if (rc != NGX_OK)
		return rc;
	return rc >= 0 ? NGX_OK : rc;
}
static ngx_int_t mp4mux_handle_write_rc(ngx_http_request_t *r, ngx_int_t rc) {
    ngx_http_core_loc_conf_t  *clcf;
    ngx_event_t *ev;
	if (rc == NGX_AGAIN) {
		ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
			"mp4mux: ngx_http_output_filter() returned NGX_AGAIN, setting handler", rc);
		r->blocked++;
		ev = r->connection->write;
		ev->handler = ngx_http_mp4mux_write_handler;
		if (!ev->active) {
			clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
			if (ngx_handle_write_event(ev, clcf->send_lowat) != NGX_OK) {
				ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
				"mp4mux_handle_write_rc(): failed to set event handler");
				return NGX_ERROR;
			}
		}
	} else {
		ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
			"mp4mux: ngx_http_output_filter() failed, rc = %i", rc);
	}
	return NGX_OK;
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

	n = ctx->trak_cnt;
	i = ((ngx_http_mp4mux_conf_t*)ngx_http_get_module_loc_conf(r, ngx_http_mp4mux_module))->
		rdbuf_size / SECTOR_SIZE * SECTOR_SIZE;
	if (i < 32768) i = 32768;

	for (; ctx->cur_trak < n; ctx->cur_trak++) {
		rc = mp4mux_open_file(ctx->mp4_src[ctx->cur_trak]);
		if (rc != NGX_OK)
			return rc;

		if (!ctx->mp4_src[ctx->cur_trak]->mvhd) {
			ngx_log_error(NGX_LOG_ERR, log, 0, "mp4mux: \"%V\" is invalid\n", &ctx->mp4_src[n]->fname);
			return NGX_HTTP_INTERNAL_SERVER_ERROR;
		}

		ctx->mp4_src[ctx->cur_trak]->rdbuf_size = i;
	}
	ctx->cur_trak = 0;

	// Calculate ETag
	etag = ngx_list_push(&r->headers_out.headers);
	if (etag == NULL)
		return NGX_HTTP_INTERNAL_SERVER_ERROR;

	etag->hash = 1;
	ngx_str_set(&etag->key, "ETag");

	etag_val = ngx_pnalloc(r->pool, (NGX_OFF_T_LEN + NGX_TIME_T_LEN + 2)*n + 2);
	if (etag_val == NULL) {
		etag->hash = 0;
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
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

	if (ctx->fmt == FMT_HLS_INDEX) {
		return mp4mux_hls_send_index(ctx);
	} else if (ctx->fmt == FMT_HLS_SEGMENT) {
		return mp4mux_hls_send_segment(ctx);
	}

	if (mp4_clone(ctx->mp4_src[0], &ctx->mp4f))
		return NGX_HTTP_INTERNAL_SERVER_ERROR;

	if (!ctx->move_meta)
		mp4_split(&ctx->mp4f);

	trak[0] = ctx->mp4f.trak;

	for (i = 1; i < n; i++) {
		if ((double)be32toh(ctx->mp4_src[i]->mvhd->duration) / be32toh(ctx->mp4_src[i]->mvhd->timescale) >
			(double)be32toh(ctx->mp4f.mvhd->duration) / be32toh(ctx->mp4f.mvhd->timescale)) {
			ctx->mp4f.mvhd->duration = ctx->mp4_src[i]->mvhd->duration;
			ctx->mp4f.mvhd->timescale = ctx->mp4_src[i]->mvhd->timescale;
		}
		trak[i] = mp4_clone_atom(ctx->mp4_src[i]->trak, ctx->mp4f.moov, &ctx->mp4f);
		if (!trak[i])
			return NGX_HTTP_INTERNAL_SERVER_ERROR;
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
			return NGX_HTTP_INTERNAL_SERVER_ERROR;

		if (ctx->start && mp4_adjust_pos(ctx->mp4_src[i], trak[i], ctx->start))
			return NGX_HTTP_INTERNAL_SERVER_ERROR;

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
			return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}

	len = mp4_build_atoms(&ctx->mp4f);
	if (len < 0)
		return NGX_HTTP_INTERNAL_SERVER_ERROR;

	len_tail = mp4_build_atoms_tail(&ctx->mp4f);
	if (len_tail < 0)
		return NGX_HTTP_INTERNAL_SERVER_ERROR;

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
		return NGX_HTTP_INTERNAL_SERVER_ERROR;

	r->root_tested = !r->error_page;

	log->action = "sending mp4mux to client";

	r->headers_out.status = NGX_HTTP_OK;
	r->headers_out.content_length_n = offset + len_tail;
	//r->headers_out.last_modified_time = ;
	ngx_str_set(&r->headers_out.content_type, "video/mp4");
	r->headers_out.content_type_len = r->headers_out.content_type.len;

	rc = ngx_http_send_header(r);
	if (rc == NGX_ERROR || rc > NGX_OK || r->header_only)
		return rc;

	out = mp4_build_chain(ctx, &ctx->mp4f.atoms);
	if (!out)
		return NGX_HTTP_INTERNAL_SERVER_ERROR;

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

	if (rc != NGX_OK) {
		if (mp4mux_handle_write_rc(r, rc) != NGX_OK)
			return NGX_ERROR;
		return rc;
	}

	return mp4mux_write(ctx);
}

static ngx_int_t mp4mux_hls_send_index(ngx_http_mp4mux_ctx_t *ctx)
{
	ngx_http_core_srv_conf_t *cscf;
	ngx_http_request_t *r = ctx->req;
	ngx_table_elt_t *content_disp;
	ngx_int_t rc, i, n, len, rem;
	ngx_int_t longest_track = 0;
	ngx_str_t host = ngx_null_string, uri;
	u_char *match, *match_end;
	ngx_buf_t *buf;
	ngx_chain_t out;

	// Get host name
	if (r->headers_in.host == NULL) {
		cscf = ngx_http_get_module_srv_conf(r, ngx_http_core_module);
		if (cscf != NULL)
			host = cscf->server_name;
	} else
		host = r->headers_in.host->value;

	if (host.data == NULL) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
			"mp4mux: unable to detect host name for index.m3u8. Using localhost by default");
		ngx_str_set(&host, "localhost");
	}

	// Get URI
	uri.data = ngx_palloc(r->pool, r->unparsed_uri.len);
	if (!uri.data)
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	uri.len = r->unparsed_uri.len;
	ngx_memcpy(uri.data, r->unparsed_uri.data, uri.len);

	// Cut out fmt parameter from URI
	match = ngx_strnstr(uri.data, "fmt=hls/index.m3u8", uri.len);
	match_end = match + sizeof("fmt=hls/index.m3u8") - 1;
	if (match > uri.data) {
		if (match[-1] == '&') {
			match--;
		} else if (match_end < (uri.data + uri.len) && *match_end == '&')
			match_end++;
		ngx_memcpy(match, match_end, uri.data + uri.len - match_end);
		uri.len -= match_end - match;
	}

	// Find longest mp4 file
	for (i = 0; ctx->mp4_src[i]; i++) {
		len = be32toh(ctx->mp4_src[i]->mvhd->duration) * 1000 / be32toh(ctx->mp4_src[i]->mvhd->timescale);
		if (len > longest_track)
			longest_track = len;
	}

	// Allocate buffer
	n = longest_track / ctx->segment_ms;

	len = sizeof(m3u8_header) + sizeof(m3u8_footer) + NGX_INT_T_LEN + (uri.len + sizeof(m3u8_entry) + NGX_INT_T_LEN * 2) * (n+1);
	buf = ngx_create_temp_buf(r->pool, len);
	if (!buf) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
			"mp4mux: failed to allocate m3u8 buffer for %i entries, %i bytes.", n+1, len);
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}
	buf->last_buf = 1;

	// Write m3u8 body
	len = ctx->segment_ms / 1000;
	rem = ctx->segment_ms % 1000;

	ngx_memcpy(buf->pos, m3u8_header, sizeof(m3u8_header) - 1);
	buf->last = ngx_sprintf(buf->pos + sizeof(m3u8_header) - 1, "%i\n", len);

	for (i = 1; i <= n; i++)
		buf->last = ngx_sprintf(buf->last, m3u8_entry, len, rem, &host, &uri, i);

	len = longest_track % ctx->segment_ms;
	if (len) {
		rem = len % 1000;
		len /= 1000;
		buf->last = ngx_sprintf(buf->last, m3u8_entry, len, rem, &host, &uri, i);
	}
	ngx_memcpy(buf->last, m3u8_footer, sizeof(m3u8_footer) - 1);
	buf->last += sizeof(m3u8_footer) - 1;

	// Output headers and data
	r->headers_out.content_length_n = buf->last - buf->pos;

	r->headers_out.status = NGX_HTTP_OK;
	ngx_str_set(&r->headers_out.content_type, "application/vnd.apple.mpegurl");
	r->headers_out.content_type_len = r->headers_out.content_type.len;
	content_disp = ngx_list_push(&r->headers_out.headers);
	if (content_disp == NULL)
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	ngx_str_set(&content_disp->key, "Content-Disposition");
	ngx_str_set(&content_disp->value, "inline; filename=\"index.m3u8\"");
	content_disp->hash = r->header_hash;

	rc = ngx_http_send_header(r);
	if (rc == NGX_ERROR || rc > NGX_OK || r->header_only)
		return rc;

	out.buf = buf;
	out.next = NULL;
	rc = ngx_http_output_filter(r, &out);
	if (rc != NGX_OK)
		return rc;
	return NGX_OK;
}

static ngx_int_t mp4_stbl_ptr_init(mp4_stbl_ptr_t *ptr, mp4_atom_hdr_t *atom, ngx_log_t *log) {
	uint32_t *data = (uint32_t*)&atom->data;

	ptr->entry_count = be32toh(data[1]);
	if (be32toh(atom->size) != ptr->entry_count * 8 + 16) {
		ngx_log_error(NGX_LOG_ERR, log, 0,
			"mp4_stbl_ptr_init: atom size doesn't match entry count");
		return NGX_ERROR;
	}
	ptr->entry_no = 0;
	if (!ptr->entry_count) {
		ngx_log_error(NGX_LOG_ERR, log, 0,
			"mp4_stbl_ptr_init: atom is empty");
		return NGX_ERROR;
	}

	data += 2;
	ptr->samp_left = be32toh(data[0]);
	ptr->value = be32toh(data[1]);
	return NGX_OK;
}

static ngx_int_t mp4_stbl_ptr_advance_entry(mp4_stbl_ptr_t *ptr, mp4_atom_hdr_t *atom) {
	uint32_t *data;
	if (++ptr->entry_no >= ptr->entry_count) {
		ptr->samp_left = 1;
		return NGX_ERROR;
	}
	data = ((uint32_t*)atom->data) + 2 + ptr->entry_no * 2;
	ptr->samp_left = be32toh(data[0]);
	ptr->value = be32toh(data[1]);
	return NGX_OK;
}
static ngx_int_t mp4_stbl_ptr_advance(mp4_stbl_ptr_t *ptr, mp4_atom_hdr_t *atom) {
	if (--ptr->samp_left)
		return NGX_OK;
	return mp4_stbl_ptr_advance_entry(ptr, atom);
}
static ngx_int_t mp4_stbl_ptr_advance_n(mp4_stbl_ptr_t *ptr, mp4_atom_hdr_t *atom, uint32_t n) {
	while (n >= ptr->samp_left) {
		n -= ptr->samp_left;
		if (mp4_stbl_ptr_advance_entry(ptr, atom) != NGX_OK)
			return NGX_ERROR;
	}
	ptr->samp_left -= n;
	return NGX_OK;
}
static ngx_int_t mp4_stsc_ptr_init(mp4_stsc_ptr_t *ptr, mp4_atom_stsc_t *atom, uint32_t chunk_count, ngx_log_t *log)
{
	ptr->entry_count = be32toh(atom->sample_cnt);
	if (be32toh(atom->hdr.size) != ptr->entry_count * 12 + sizeof(mp4_atom_stsc_t)) {
		ngx_log_error(NGX_LOG_ERR, log, 0,
			"mp4_stsc_ptr_init: stsc atom size doesn't match entry count");
		return NGX_ERROR;
	}
	if (ptr->entry_count == 0) {
		ngx_log_error(NGX_LOG_ERR, log, 0,
			"mp4_stsc_ptr_init: stsc table is empty!");
		return NGX_ERROR;
	}
	ptr->chunk_count = chunk_count;
	ptr->chunk_no = be32toh(atom->tbl[0].first_chunk);
	ptr->samp_cnt = be32toh(atom->tbl[0].sample_cnt);
	ptr->samp_left = be32toh(atom->tbl[0].sample_cnt);
	ptr->entry_no = 1;
	if (ptr->entry_count == 1)
		ptr->next = chunk_count;
	else
		ptr->next = be32toh(atom->tbl[1].first_chunk);
	return NGX_OK;
}

static ngx_int_t mp4_stsc_ptr_advance_entry(mp4_stsc_ptr_t *ptr, mp4_atom_stsc_t *atom) {
	if (++ptr->chunk_no >= ptr->next) {
		ptr->samp_cnt = be32toh(atom->tbl[ptr->entry_no++].sample_cnt);
		if (ptr->entry_no > ptr->entry_count) {
			ptr->samp_left = 1;
			return NGX_ERROR;
		} else if (ptr->entry_no == ptr->entry_count)
			ptr->next = ptr->chunk_count;
		else
			ptr->next = be32toh(atom->tbl[ptr->entry_no].first_chunk);
	}
	ptr->samp_left = ptr->samp_cnt;
	return NGX_OK;
}
static ngx_int_t mp4_stsc_ptr_advance(mp4_stsc_ptr_t *ptr, mp4_atom_stsc_t *atom) {
	if (--ptr->samp_left)
		return NGX_OK;
	return mp4_stsc_ptr_advance_entry(ptr, atom);
}

static ngx_int_t mp4_stsc_ptr_advance_n(mp4_stsc_ptr_t *ptr, mp4_atom_stsc_t *atom, uint32_t n) {
	while (n > ptr->samp_left) {
		n -= ptr->samp_left;
		if (mp4_stsc_ptr_advance_entry(ptr, atom) != NGX_OK)
			return NGX_ERROR;
	}
	ptr->samp_left -= n;
	return NGX_OK;
}

static ngx_int_t mp4_stbl_init_atom(mp4_atom_hdr_t **atom, uint32_t atom_type, mp4_file_t *mp4, ngx_log_t *log) {
	ngx_str_t atom_str;
	mp4_atom_t *a;
	a = mp4_find_atom(&mp4->stbl->atoms, atom_type);
	if (a == NULL) {
		atom_str.len = 4;
		atom_str.data = (u_char*)&atom_type;
		ngx_log_error(NGX_LOG_ERR, log, 0,
			"mp4mux: no %V atom found in %V", &atom_str, &mp4->fname);
		return NGX_ERROR;
	}
	*atom = a->hdr;
	return NGX_OK;
}

static ngx_int_t mp4_stbl_init_atom_wptr(mp4_atom_hdr_t **atom, mp4_stbl_ptr_t *ptr, uint32_t atom_type,
		mp4_file_t *mp4, ngx_log_t *log) {
	ngx_str_t atom_str;
	if (mp4_stbl_init_atom(atom, atom_type, mp4, log) != NGX_OK)
		return NGX_ERROR;
	if (mp4_stbl_ptr_init(ptr, *atom, log) != NGX_OK) {
		atom_str.len = 4;
		atom_str.data = (u_char*)&atom_type;
		ngx_log_error(NGX_LOG_ERR, log, 0,
			"mp4mux: invalid %V atom in %V", &atom_str, &mp4->fname);
	}
	return NGX_OK;
}

static ngx_int_t mp4mux_hls_parse_stsd_video(ngx_http_mp4mux_ctx_t *ctx, mp4_hls_ctx_t *hls_ctx, mp4_atom_stsd_t *stsd) {
	mp4_atom_avc1_t *avc1;
	mp4_atom_avcC_t *avcC;
	ngx_int_t i, j;
	u_char *in, *in_end, *out;
	u_char cnt;
	uint16_t in_len;
	int out_len;
	if (be32toh(stsd->entries) != 1) {
		ngx_log_error(NGX_LOG_ERR, ctx->req->connection->log, 0,
			"mp4mux: number of entries in stsd must be 1");
		return NGX_ERROR;
	}
	in_end = (u_char*)stsd + be32toh(stsd->hdr.size);
	if (stsd->entry.hdr.type != ATOM('a','v','c','1')
		&& stsd->entry.hdr.type != ATOM('h','2','6','4')
		&& stsd->entry.hdr.type != ATOM('H','2','6','4')) {
		ngx_log_error(NGX_LOG_ERR, ctx->req->connection->log, 0,
			"mp4mux: only avc1 format is supported now");
		return NGX_ERROR;
	}
	avc1 = &stsd->entry.avc1;
	if (be32toh(avc1->entries) != 1) {
		ngx_log_error(NGX_LOG_ERR, ctx->req->connection->log, 0,
			"mp4mux: number of entries in avc1 must be 1");
		return NGX_ERROR;
	}
	if (avc1->avcC.hdr.type != ATOM('a','v','c','C')) {
		ngx_log_error(NGX_LOG_ERR, ctx->req->connection->log, 0,
			"mp4mux: avcC atom is not found in avc1");
		return NGX_ERROR;
	}
	avcC = &avc1->avcC;

	hls_ctx->sf_len = (avcC->sf_len & 0x03) + 1;

	// Parse SPS and PPS from avcC data
	ngx_log_debug0(NGX_LOG_DEBUG_HTTP, ctx->req->connection->log, 0,
		"mp4mux_hls: found avcC, parsing SPS and PPS");
	// calculate length
	in = (u_char*)avcC + be32toh(avcC->hdr.size);
	if (in > in_end) {
		ngx_log_error(NGX_LOG_ERR, ctx->req->connection->log, 0,
			"mp4mux: avcC atom goes out of stsd bounds, len: %i" + be32toh(avcC->hdr.size));
		return NGX_ERROR;
	}
	in_end = in;
	in = avcC->data;
	out_len = 0;
	for (i = 0; i < 2; i++) {
		if (in >= in_end) goto err;
		cnt = *in++ & 0x1f;
		for (j = 0; j < cnt; j++) {
			if (in >= in_end - 1) goto err;
			in_len = be16toh(*((uint16_t*)in));
			out_len += 4 + in_len;
			in += 2 + in_len;
		}
	}
	if (in > in_end) goto err;
	// convert and copy data
	out = ngx_palloc(ctx->req->pool, out_len);
	in = avcC->data;
	hls_ctx->cdata = out;
	for (i = 0; i < 2; i++) {
		cnt = *in++ & 0x1f;
		for (j = 0; j < cnt; j++) {
			in_len = be16toh(*((uint16_t*)in));
			in += 2;
			out4b(out, 0x00, 0x00, 0x00, 0x01);
			ngx_memcpy(out, in, in_len);
			out += in_len;
			in += in_len;
		}
	}
	hls_ctx->cdata_len = out - hls_ctx->cdata;
	return NGX_OK;
err:
	ngx_log_error(NGX_LOG_ERR, ctx->req->connection->log, 0,
		"mp4mux: error parsing avcC atom: out of bounds");
	return NGX_ERROR;
}

static ngx_int_t mp4mux_hls_parse_stsd_audio(ngx_log_t *log, mp4_hls_ctx_t *hls_ctx, mp4_atom_stsd_t *stsd) {
	mp4_atom_mp4a_t *mp4a;
	mp4_atom_hdr_t *esds;
	u_char profile, rate_idx, chanconf;

	if (be32toh(stsd->entries) != 1) {
		ngx_log_error(NGX_LOG_ERR, log, 0,
			"mp4mux: number of entries in stsd must be 1");
		return NGX_ERROR;
	}
	if (stsd->entry.hdr.type != ATOM('m','p','4','a')) {
		ngx_log_error(NGX_LOG_ERR, log, 0,
			"mp4mux: only mp4a format is supported for audio");
		return NGX_ERROR;
	}
	mp4a = &stsd->entry.mp4a;
	if (be32toh(mp4a->entries) != 1) {
		ngx_log_error(NGX_LOG_ERR, log, 0,
			"mp4mux: number of entries in mp4a must be 1");
		return NGX_ERROR;
	}
	esds = &mp4a->esds;
	if (esds->type != ATOM('e','s','d','s')) {
		ngx_log_error(NGX_LOG_ERR, log, 0,
			"mp4mux: esds atom is not found in mp4a");
		return NGX_ERROR;
	}
	if (*((uint32_t*)(esds->data + 0x1e)) != ATOM(0x05, 0x80, 0x80, 0x80)) {
		ngx_log_error(NGX_LOG_ERR, log, 0,
			"mp4mux: decoder-specific info is not found in esds atom");
		return NGX_ERROR;
	}
	profile = esds->data[0x23] >> 3;
	if (profile > 4 || profile == 0) {
		ngx_log_error(NGX_LOG_ERR, log, 0,
			"mp4mux: only AAC audio is supported, requested format id %i", profile);
		return NGX_ERROR;
	}
	profile--;
	rate_idx = ((esds->data[0x23] & 7) << 1) | (esds->data[0x24] >> 7);
	chanconf = (esds->data[0x24] >> 3) & 0x0f;
	if (chanconf > 7) {
		ngx_log_error(NGX_LOG_ERR, log, 0,
			"mp4mux: invalid channel configuration %i", chanconf);
		return NGX_ERROR;
	}
	hls_ctx->adts_hdr = htobe32(0xfff10000 | profile << 14 | rate_idx << 10 | chanconf << 6);
	return NGX_OK;
}

static void hls_calcdts(mp4_hls_ctx_t *hls_ctx) {
	hls_ctx->dts = ((int64_t)hls_ctx->sample_no * HLS_TIMESCALE + hls_ctx->timescale/2) / hls_ctx->timescale;
}
// Advances stts, frame_no and sample_no but not ctts, stsc and dts
static ngx_int_t hls_nextframe_base(mp4_file_t *mp4) {
	if (mp4->hls_ctx->eof) {
		ngx_log_error(NGX_LOG_ERR, mp4->log, 0,
			"mp4mux_hls_nextframebase: called on EOF track");
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}
	mp4->hls_ctx->sample_no += mp4->hls_ctx->stts_ptr.value;
	if (mp4->hls_ctx->sample_no >= mp4->hls_ctx->sample_max
			|| ++mp4->hls_ctx->frame_no >= be32toh(mp4->stsz->sample_cnt)) {
		mp4->hls_ctx->eof = 1;
		return NGX_OK;
	}
	if ((mp4_stbl_ptr_advance(&mp4->hls_ctx->stts_ptr, &mp4->hls_ctx->stts->hdr)) != NGX_OK) {
		ngx_log_error(NGX_LOG_ERR, mp4->log, 0,
			"mp4mux_hls_nextframebase: stts pointer is out of range, entry %i", mp4->hls_ctx->stts_ptr.entry_no);
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}
	return NGX_OK;
}
static bool_t hls_is_keyframe(mp4_file_t *mp4) {
	mp4_hls_ctx_t *hls_ctx = mp4->hls_ctx;
	if (hls_ctx->stss && hls_ctx->frame_no >= hls_ctx->next_keyframe) {
	    if (hls_ctx->frame_no > hls_ctx->next_keyframe)
			ngx_log_error(NGX_LOG_WARN, mp4->log, 0,
				"hls_is_keyframe: skipped keyframe %i, fixed in %i", hls_ctx->next_keyframe, hls_ctx->frame_no);
		hls_ctx->stss_ptr++;
		if (hls_ctx->stss_ptr == be32toh(hls_ctx->stss->entries))
			hls_ctx->next_keyframe = NGX_MAX_UINT32_VALUE;
		else
			hls_ctx->next_keyframe = be32toh(hls_ctx->stss->tbl[hls_ctx->stss_ptr]) - 1;
		return 1;
	}
	return 0;
}
static ngx_int_t hls_count_packets(ngx_http_mp4mux_ctx_t *ctx, mp4_file_t *mp4)
{
	uint32_t frame_no, sample_no, stss_ptr, len, dts;
	mp4_hls_ctx_t *hls_ctx = mp4->hls_ctx;
	mp4_stbl_ptr_t stts_save;
	ngx_int_t i;
	// Save pointer values before simulation
	frame_no = hls_ctx->frame_no;
	sample_no = hls_ctx->sample_no;
	stts_save = hls_ctx->stts_ptr;
	switch (hls_ctx->pes_typ) {
	case PES_VIDEO:
		len = be32toh(hls_ctx->stss->entries);
		for (stss_ptr = 0; stss_ptr < len; stss_ptr++) {
			hls_ctx->next_keyframe = be32toh(hls_ctx->stss->tbl[stss_ptr])-1;
			if (hls_ctx->next_keyframe >= hls_ctx->frame_no)
				break;
		}
		if (stss_ptr >= len)
			hls_ctx->next_keyframe = NGX_MAX_UINT32_VALUE;
		hls_ctx->stss_ptr = stss_ptr;
		if (ctx->strict_cl) {
			ngx_log_error(NGX_LOG_ERR, mp4->log, 0,
				"mp4mux: strict packet counting is not implemented yet");
			return NGX_HTTP_INTERNAL_SERVER_ERROR;
		}
		// Use unconverted mp4 frame length to determine packet count
		do {
			len = be32toh(mp4->stsz->tbl[hls_ctx->frame_no]);
			len += 8; // Adaptation
			len += 14; // Minimal PES header
			if (hls_ctx->ctts) len += 5; // additional timestamp
			len += 7; // frame header
			if (hls_is_keyframe(mp4))
				len += hls_ctx->cdata_len;
			hls_ctx->packet_count += (len + MPEGTS_PACKET_USABLE_SIZE - 1) / MPEGTS_PACKET_USABLE_SIZE;
			if (hls_nextframe_base(mp4) != NGX_OK)
				return NGX_HTTP_NOT_FOUND;
		} while (!hls_ctx->eof);
		hls_ctx->stss_ptr = stss_ptr;
		hls_ctx->next_keyframe = be32toh(hls_ctx->stss->tbl[stss_ptr])-1;
		break;
	case PES_AUDIO:
		do {
			len = 8; // Initial PES length
			i = be32toh(mp4->stsz->tbl[hls_ctx->frame_no]) + SIZEOF_ADTS_HEADER;
			hls_calcdts(hls_ctx);
			dts = hls_ctx->dts;
			do {
				len += i;
				if (hls_nextframe_base(mp4) != NGX_OK)
					return NGX_HTTP_NOT_FOUND;
				hls_calcdts(mp4->hls_ctx);
				i = be32toh(mp4->stsz->tbl[hls_ctx->frame_no]) + SIZEOF_ADTS_HEADER;
			} while (!hls_ctx->eof && hls_ctx->dts-dts < HLS_MAX_DELAY && len + i <= HLS_AUDIO_PACKET_LEN);
			hls_ctx->packet_count += (len + 8 + 6 + MPEGTS_PACKET_USABLE_SIZE - 1) / MPEGTS_PACKET_USABLE_SIZE;
		} while (!hls_ctx->eof);
		break;
	default:
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}
	// Restore pointer values
	hls_ctx->frame_no = frame_no;
	hls_ctx->sample_no = sample_no;
	hls_ctx->stts_ptr = stts_save;
	hls_ctx->eof = 0;
	hls_calcdts(mp4->hls_ctx);
	return NGX_OK;
}
static ngx_int_t mp4mux_hls_send_segment(ngx_http_mp4mux_ctx_t *ctx)
{
	ngx_http_request_t *r = ctx->req;
	ngx_table_elt_t *content_disp;
	mp4_hls_ctx_t *hls_ctx;
	mp4_atom_t *atom;
	mp4_atom_hdr_t *atom_hdr;
	ngx_str_t str;
	ngx_int_t rc, i, n;
	off_t sample_start;
	uint32_t crc;
	ngx_buf_t *b;
	u_char *p;
	u_char vid = PES_VIDEO, aid = PES_AUDIO;

	r->headers_out.status = NGX_HTTP_OK;
	ngx_str_set(&r->headers_out.content_type, "video/MP2T");
	r->headers_out.content_type_len = r->headers_out.content_type.len;
	content_disp = ngx_list_push(&r->headers_out.headers);
	if (content_disp == NULL)
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	ngx_str_set(&content_disp->key, "Content-Disposition");
	content_disp->value.data = ngx_palloc(r->pool, sizeof("inline; filename=\"seg-.ts\"") + NGX_INT_T_LEN);
	if (content_disp->value.data == NULL)
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	content_disp->value.len = ngx_sprintf(content_disp->value.data,
		"inline; filename=\"seg-%i.ts\"", ctx->hls_seg) - content_disp->value.data;
	content_disp->hash = r->header_hash;
	r->headers_out.content_length_n = MPEGTS_PACKET_SIZE * 2;

	if ((b = ngx_create_temp_buf(r->pool, ctx->hls_bufsize)) == NULL)
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	b->tag = (ngx_buf_tag_t) &ngx_http_mp4mux_module;
	if ((ctx->chain = ngx_alloc_chain_link(r->pool)) == NULL)
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	ctx->chain->buf = b;
	ctx->chain->next = NULL;
	ctx->chain_last = ctx->chain;

	// output PAT
	memcpy(b->last, pat_packet, sizeof(pat_packet));
	memset(b->last + sizeof(pat_packet), 0xff, MPEGTS_PACKET_SIZE - sizeof(pat_packet));
	b->last[3] += (ctx->hls_seg - 1) & 0x0f;
	b->last += MPEGTS_PACKET_SIZE;
	// output PMT
	p = b->last;
	memcpy(b->last, pmt_header_template, sizeof(pmt_header_template));
	b->last[3] += (ctx->hls_seg - 1) & 0x0f;
	b->last += sizeof(pmt_header_template);
	for (n = 0; n < ctx->trak_cnt; n++) {
		ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
			"mp4mux_hls: init %V", &ctx->mp4_src[n]->fname);
		// Detect track type and parse codec data
		if ((atom = mp4_find_atom(&ctx->mp4_src[n]->trak->atoms, ATOM('h','d','l','r'))) == NULL) {
			ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
				"mp4mux: no hdlr atom found in %V", &ctx->mp4_src[n]->fname);
			return NGX_HTTP_NOT_FOUND;
		}
		if ((ctx->mp4_src[n]->stbl = mp4_find_atom(&ctx->mp4_src[n]->trak->atoms, ATOM('s','t','b','l'))) == NULL) {
			ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
				"mp4mux: no stbl atom found in %V", &ctx->mp4_src[n]->fname);
			return NGX_HTTP_NOT_FOUND;
		}
		if (mp4_stbl_init_atom(&atom_hdr, ATOM('s','t','s','d'), ctx->mp4_src[n], r->connection->log) != NGX_OK)
			return NGX_HTTP_NOT_FOUND;
		hls_ctx = ngx_pcalloc(r->pool, sizeof(mp4_hls_ctx_t));
		ctx->mp4_src[n]->hls_ctx = hls_ctx;
		switch (*((uint32_t*)(atom->hdr->data + 8)))
		{
		case ATOM('v','i','d','e'):
			ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
				"mp4mux_hls: found video");
			hls_ctx->pes_id = vid++;
			hls_ctx->pes_typ = PES_VIDEO;
			if (mp4mux_hls_parse_stsd_video(ctx, hls_ctx, (mp4_atom_stsd_t *)atom_hdr) != NGX_OK)
				return NGX_HTTP_NOT_FOUND;
			if (hls_ctx->sf_len < 3)
				ctx->strict_cl = 1;
			memcpy(b->last, pmt_entry_template_avc, sizeof(pmt_entry_template_avc));
			b->last[2] = n;
			b->last += sizeof(pmt_entry_template_avc);
			if (mp4_stbl_init_atom((mp4_atom_hdr_t**)&hls_ctx->stss, ATOM('s','t','s','s'), ctx->mp4_src[n], r->connection->log) != NGX_OK)
				return NGX_HTTP_NOT_FOUND;
			atom = mp4_find_atom(&ctx->mp4_src[n]->stbl->atoms, ATOM('c','t','t','s'));
			if (atom != NULL) {
				hls_ctx->ctts = (mp4_atom_ctts_t*)atom->hdr;
				if (mp4_stbl_ptr_init(&hls_ctx->ctts_ptr, &hls_ctx->ctts->hdr, r->connection->log) != NGX_OK) {
					ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
						"mp4mux: invalid ctts atom in %V", &ctx->mp4_src[n]->fname);
					return NGX_HTTP_NOT_FOUND;
				}
			}
			break;
		case ATOM('s','o','u','n'):
			ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
				"mp4mux_hls: found audio");
			hls_ctx->pes_id = aid++;
			hls_ctx->pes_typ = PES_AUDIO;
			if (mp4mux_hls_parse_stsd_audio(r->connection->log, hls_ctx, (mp4_atom_stsd_t *)atom_hdr) != NGX_OK)
				return NGX_HTTP_NOT_FOUND;
			memcpy(b->last, pmt_entry_template_aac, sizeof(pmt_entry_template_aac));
			b->last[2] = n;
			b->last += sizeof(pmt_entry_template_aac);
			break;
		default:
			str.len = 4;
			str.data = atom_hdr->data + 8;
			ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
				"mp4mux: invalid media handler %V", &str);
			return NGX_HTTP_NOT_FOUND;
		}
		// Init stbl pointers
		atom = mp4_find_atom(&ctx->mp4_src[n]->stbl->atoms, ATOM('s','t','c','o'));
		if (atom == NULL) {
			atom = mp4_find_atom(&ctx->mp4_src[n]->stbl->atoms, ATOM('c','o','6','4'));
			if (atom == NULL) {
				ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
					"mp4mux: no stco/co64 atom found in %V", &ctx->mp4_src[n]->fname);
				return NGX_HTTP_NOT_FOUND;
			}
			hls_ctx->co64 = 1;
		}
		hls_ctx->co = (mp4_atom_stco_t*)atom->hdr;

		if (mp4_stbl_init_atom_wptr((mp4_atom_hdr_t**)&hls_ctx->stts, &hls_ctx->stts_ptr, ATOM('s','t','t','s'),
				ctx->mp4_src[n], r->connection->log) != NGX_OK)
			return NGX_HTTP_NOT_FOUND;

		if (mp4_stsc_ptr_init(&hls_ctx->stsc_ptr, ctx->mp4_src[n]->stsc, be32toh(hls_ctx->co->chunk_cnt), r->connection->log) != NGX_OK) {
			ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
				"mp4mux: invalid stsc atom in %V", &ctx->mp4_src[n]->fname);
			return NGX_HTTP_NOT_FOUND;
		}
		// Init other values
		atom = mp4_find_atom(&ctx->mp4_src[n]->trak->atoms, ATOM('m','d','h','d'));
		if (atom == NULL) {
			ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
				"mp4mux: no mdhd atom found in %V", &ctx->mp4_src[n]->fname);
			return NGX_HTTP_NOT_FOUND;
		}
		hls_ctx->timescale = be32toh(((mp4_atom_mdhd_t*)atom->hdr)->timescale);

		// Move to segment start
		if (ctx->hls_seg > 1) {
			sample_start = (ctx->hls_seg - 1) * ctx->segment_ms * hls_ctx->timescale / 1000;

			while (sample_start > 0) {
				i = hls_ctx->stts_ptr.value * hls_ctx->stts_ptr.samp_left;
				sample_start -= i;
				if (sample_start >= 0) {
					hls_ctx->frame_no += hls_ctx->stts_ptr.samp_left;
					hls_ctx->sample_no += i;
					if (mp4_stbl_ptr_advance_entry(&hls_ctx->stts_ptr, &hls_ctx->stts->hdr) != NGX_OK)
						hls_ctx->eof = 1;
				} else {
					i = hls_ctx->stts_ptr.samp_left + sample_start / hls_ctx->stts_ptr.value;
					hls_ctx->frame_no += i;
					hls_ctx->sample_no += i * hls_ctx->stts_ptr.value;
					if (mp4_stbl_ptr_advance_n(&hls_ctx->stts_ptr, &hls_ctx->stts->hdr, i) != NGX_OK)
						hls_ctx->eof = 1;
				}
			}
			if (!hls_ctx->eof) {
				if (hls_ctx->ctts && mp4_stbl_ptr_advance_n(&hls_ctx->ctts_ptr, &hls_ctx->ctts->hdr, hls_ctx->frame_no) != NGX_OK)
					return NGX_HTTP_INTERNAL_SERVER_ERROR;
				if (mp4_stsc_ptr_advance_n(&hls_ctx->stsc_ptr, ctx->mp4_src[n]->stsc, hls_ctx->frame_no) != NGX_OK)
					return NGX_HTTP_INTERNAL_SERVER_ERROR;

				// calculate frame offset in the chunk
				for (i = hls_ctx->frame_no - (be32toh(ctx->mp4_src[n]->stsc->tbl[hls_ctx->stsc_ptr.entry_no-1].sample_cnt)
						- hls_ctx->stsc_ptr.samp_left); i < hls_ctx->frame_no; i++)
					hls_ctx->frame_offs += be32toh(ctx->mp4_src[n]->stsz->tbl[i]);
			}
		}

		if (hls_ctx->stsc_ptr.chunk_no > be32toh(hls_ctx->co->chunk_cnt)) {
			ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
				"mp4mux: invalid stco chunk number in %V", &ctx->mp4_src[n]->fname);
			return NGX_HTTP_NOT_FOUND;
		}

		hls_ctx->sample_max = ctx->hls_seg * ctx->segment_ms * hls_ctx->timescale / 1000;
		if (hls_ctx->eof) continue;
		hls_ctx->frame_offs += hls_ctx->co64 ?
			be64toh(hls_ctx->co->u.tbl64[hls_ctx->stsc_ptr.chunk_no-1])
			: be32toh(hls_ctx->co->u.tbl[hls_ctx->stsc_ptr.chunk_no-1]);
		if ((rc = hls_count_packets(ctx, ctx->mp4_src[n])) != NGX_OK)
			return rc;
		if (mp4mux_seek(ctx->mp4_src[n], hls_ctx->frame_offs) != NGX_OK)
			return NGX_HTTP_INTERNAL_SERVER_ERROR;
		mp4mux_preread(ctx->mp4_src[n]);
		// Add calculated packet count to Content-Length
		r->headers_out.content_length_n += ((hls_ctx->packet_count + 15)/16 * 16 ) * MPEGTS_PACKET_SIZE;
	}
	memcpy(b->last, pmt_entry_template_id3, sizeof(pmt_entry_template_id3));
	b->last[2] = n;
	b->last += sizeof(pmt_entry_template_id3);
	p[7] = b->last - p - 4;
	crc = mpegts_crc32(p + 5, b->last - p - 5);
	b->last = write_uint32(b->last, crc);
	memset(b->last, 0xff, p + MPEGTS_PACKET_SIZE - b->last);
	b->last = p + MPEGTS_PACKET_SIZE;

	rc = ngx_http_send_header(r);
	if (rc == NGX_ERROR || rc > NGX_OK || r->header_only)
		return rc;

	#if (NGX_HAVE_FILE_AIO)
	ctx->aio_handler = mp4mux_hls_write;
	#endif
	return mp4mux_hls_write(ctx);
}

static ngx_buf_t *hls_newbuf(ngx_http_mp4mux_ctx_t *ctx) {
	ngx_chain_t *chain;
	ngx_buf_t *b;
	chain = ngx_chain_get_free_buf(ctx->req->pool, &ctx->free);
	b = chain->buf;
	if (b->start == NULL || b->end - b->start != ctx->hls_bufsize) {
		ngx_memzero(b, sizeof(ngx_buf_t));
		if ((b->start = ngx_palloc(ctx->req->pool, ctx->hls_bufsize)) == NULL)
			return NULL;
		b->pos = b->start;
		b->last = b->start;
		b->end = b->start + ctx->hls_bufsize;
		b->temporary = 1;
		ngx_log_debug2(NGX_LOG_DEBUG_HTTP, ctx->req->connection->log, 0,
			"created new buf %p, start = %p", b, b->start);
		b->tag = (ngx_buf_tag_t) &ngx_http_mp4mux_module;
	} else {
		ngx_log_debug2(NGX_LOG_DEBUG_HTTP, ctx->req->connection->log, 0,
			"reused existing buf %p, start = %p", b, b->start);
		b->pos = b->start;
		b->last = b->start;
	}
	if (ctx->chain == NULL) {
		ctx->chain = chain;
		ctx->chain_last = chain;
	} else if (chain != ctx->chain_last) {
		ctx->chain_last->next = chain;
		ctx->chain_last = chain;
	}
	return b;
}
static ngx_buf_t *hls_newpacket(ngx_buf_t *b, ngx_http_mp4mux_ctx_t *ctx, mp4_hls_ctx_t *hls_ctx, u_char typ1, u_char typ2) {
	hls_ctx->packet_count--;
	if (b->last > b->end) {
		ngx_log_error(NGX_LOG_ERR, ctx->req->connection->log, 0,
			"mp4mux_hls_newpacket(): buffer overflow detected: b->last = %p, b->end = %p", b->last, b->end);
		return NULL;
	}
	if (b->last == b->end)
		b = hls_newbuf(ctx);
	else if ((b->last - b->start) % MPEGTS_PACKET_SIZE != 0) {
		ngx_log_error(NGX_LOG_ERR, ctx->req->connection->log, 0,
			"mp4mux_hls_newpacket(): buffer is misaligned: b->last = %p, b->start = %p", b->last, b->start);
		return NULL;
	}
	b->last[0] = 0x47; // Sync byte
	b->last[1] = typ1;
	b->last[2] = ctx->cur_trak;
	b->last[3] = typ2 + hls_ctx->cocnt++; // Flags and continuity counter
	hls_ctx->cocnt &= 0x0f;
	b->last += 4;
	return b;
}

static ngx_int_t hls_nextframe(mp4_file_t *mp4)
{
	ngx_int_t rc;
	rc = hls_nextframe_base(mp4);
	if (rc != NGX_OK)
		return rc;
	if (mp4->hls_ctx->eof) return NGX_OK;
	uint32_t curchunk = mp4->hls_ctx->stsc_ptr.chunk_no;
	if (mp4->hls_ctx->ctts && ((mp4_stbl_ptr_advance(&mp4->hls_ctx->ctts_ptr, &mp4->hls_ctx->ctts->hdr)) != NGX_OK)) {
		ngx_log_error(NGX_LOG_ERR, mp4->log, 0,
			"mp4mux_hls_nextframe: ctts pointer is out of range, entry %i", mp4->hls_ctx->ctts_ptr.entry_no);
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}
	if ((mp4_stsc_ptr_advance(&mp4->hls_ctx->stsc_ptr, mp4->stsc)) != NGX_OK) {
		ngx_log_error(NGX_LOG_ERR, mp4->log, 0,
			"mp4mux_hls_nextframe: stsc pointer is out of range, entry %i", mp4->hls_ctx->stsc_ptr.entry_no);
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}

	if (mp4->hls_ctx->stsc_ptr.chunk_no != curchunk) {
		// Move to the next chunk
		mp4->hls_ctx->frame_offs = mp4->hls_ctx->co64 ?
			be64toh(mp4->hls_ctx->co->u.tbl64[mp4->hls_ctx->stsc_ptr.chunk_no-1])
			: be32toh(mp4->hls_ctx->co->u.tbl[mp4->hls_ctx->stsc_ptr.chunk_no-1]);
		curchunk = mp4->hls_ctx->stsc_ptr.chunk_no;
		ngx_log_debug2(NGX_LOG_DEBUG_HTTP, mp4->log, 0,
			"switched to new chunk %i, offs = %i", mp4->hls_ctx->stsc_ptr.chunk_no, mp4->hls_ctx->frame_offs);
	}
	hls_calcdts(mp4->hls_ctx);
	return NGX_OK;
}
static inline ngx_buf_t *hls_emptypacket(ngx_buf_t *b, ngx_http_mp4mux_ctx_t *ctx, mp4_hls_ctx_t *hls_ctx)
{
	b = hls_newpacket(b, ctx, hls_ctx, TS_TYP1_CONTINUE, TS_TYP2_ADAPT_PAYLD);
	if (b == NULL)
		return NULL;
	out2b(b->last, 0xb7, 0x00);
	ngx_memset(b->last, 0xff, MPEGTS_PACKET_USABLE_SIZE - 2);
	b->last += MPEGTS_PACKET_USABLE_SIZE - 2;
	return b;
}
static ngx_int_t mp4mux_hls_write(ngx_http_mp4mux_ctx_t *ctx)
{
	ngx_http_request_t *r = ctx->req;
	mp4_file_t *mp4 = NULL;
	ngx_chain_t *chain;
	ngx_buf_t *b = ctx->chain_last->buf;
	u_char *p, *p_end;
	uint16_t *len_field;
	size_t frame_end, subframe_end;
	ngx_int_t rc = NGX_OK, i;
	size_t pes_len, len;
	uint32_t sf_len = 0;
	u_char *sf_len_ptr; // mp4 subframe length field is variable-length, so we need to read to different location depending on it
	uint32_t dts;
	u_char adts_hdr[SIZEOF_ADTS_HEADER];

	while (!ctx->done) {
		if (rc != NGX_OK) {
			if (mp4mux_handle_write_rc(r, rc) != NGX_OK)
				return NGX_ERROR;
			return rc;
		}
		while (ctx->chain_last == ctx->chain) {
			// Select track
			ctx->cur_trak = -1;
			dts = NGX_MAX_UINT32_VALUE;
			for (i = 0; i < ctx->trak_cnt; i++) {
				if (ctx->mp4_src[i]->hls_ctx->eof) continue;
				if (ctx->mp4_src[i]->hls_ctx->dts < dts) {
					ctx->cur_trak = i;
					dts = ctx->mp4_src[i]->hls_ctx->dts;
				}
			}
			if (ctx->cur_trak == -1) {
				ctx->done = 1;
				break;
			}
			mp4 = ctx->mp4_src[ctx->cur_trak];
			// Init

			sf_len_ptr = ((u_char*)&sf_len) + mp4->hls_ctx->sf_len - 4;
			len = be32toh(mp4->stsz->tbl[mp4->hls_ctx->frame_no]);
			#if (NGX_HAVE_FILE_AIO)
			if (mp4->aio) {
				pes_len = len;
				if (mp4->hls_ctx->pes_typ == PES_AUDIO && pes_len < HLS_AUDIO_PACKET_LEN)
					pes_len = HLS_AUDIO_PACKET_LEN;
				rc = mp4mux_readahead(mp4, pes_len);
				if (rc == NGX_AGAIN) {
					ngx_log_debug0(NGX_LOG_DEBUG_HTTP, ctx->req->connection->log, 0,
						"mp4mux_readahead returned NGX_AGAIN");
					return NGX_AGAIN;
				}
				if (rc != NGX_OK)
					return NGX_ERROR;
			}
			#endif
			frame_end = mp4->offs + len;
			ngx_log_debug7(NGX_LOG_DEBUG_HTTP, ctx->req->connection->log, 0,
				"mp4mux: track %i frame %i, sample %i, offs: %i, len: %i, ctts = %i, ctts->entry = %i",
				ctx->cur_trak, mp4->hls_ctx->frame_no, mp4->hls_ctx->sample_no, mp4->offs, len,
				mp4->hls_ctx->ctts_ptr.value,mp4->hls_ctx->ctts_ptr.entry_no);
			///// Write MPEG-TS packet
			if ((b = hls_newpacket(b, ctx, mp4->hls_ctx, TS_TYP1_START, TS_TYP2_ADAPT_PAYLD)) == NULL)
				return NGX_HTTP_INTERNAL_SERVER_ERROR;
			p = b->last;
			p_end = p + MPEGTS_PACKET_USABLE_SIZE;
			ngx_log_debug2(NGX_LOG_DEBUG_HTTP, ctx->req->connection->log, 0,
				"mp4mux: p = %p p_end = %p", p, p_end);
			// Adaptation
			out2b(p, 0x07, 0x10)
			p = write_pcr(p, (uint64_t)dts + INITIAL_PCR);
			// PES header
			out4b(p, 0x00, 0x00, 0x01, mp4->hls_ctx->pes_id)
			len_field = (uint16_t*)p;
			p += 2;
			*p++ = 0x84;
			if (mp4->hls_ctx->ctts) {
				pes_len = 13;
				out2b(p, 0xc0, 10);
				p = write_pts(p, 3, (((int64_t)mp4->hls_ctx->sample_no + mp4->hls_ctx->ctts_ptr.value)
					* HLS_TIMESCALE + mp4->hls_ctx->timescale / 2) / mp4->hls_ctx->timescale + INITIAL_DTS);
			} else {
				pes_len = 8;
				out2b(p, 0x80, 5);
			}
			p = write_pts(p, mp4->hls_ctx->ctts ? 1 : 2, dts + INITIAL_DTS);
			// PES data
			switch (mp4->hls_ctx->pes_typ) {
			// TODO: move write_frame_video and write_frame_audio to separate function?
			case PES_VIDEO:
				out4b(p, 0x00, 0x00, 0x00, 0x01);
				out2b(p, 0x09, 0xF0);
				if (hls_is_keyframe(mp4)) {
					// keyframe, output SPS and PPS
					len = mp4->hls_ctx->cdata_len;
					ngx_memcpy(p, mp4->hls_ctx->cdata, len);
					p += len;
					pes_len += len;
				}

				*p++ = 0;
				pes_len += 7;
				// Read, convert, and output frame data
				while (mp4->offs < frame_end) {
					len = mp4->hls_ctx->sf_len;
					if (mp4mux_read(mp4, (u_char*)sf_len_ptr, len, 1) != NGX_OK)
						return NGX_HTTP_INTERNAL_SERVER_ERROR;
					len = be32toh(sf_len);
					ngx_log_debug1(NGX_LOG_DEBUG_HTTP, ctx->req->connection->log, 0,
						"mp4mux: subframe len: %i", len);
					subframe_end = mp4->offs + len;
					pes_len += len;
					if (subframe_end > frame_end) {
						ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
							"mp4mux: error converting frame %i in %V: subframe at offs %i exceeds frame bounds",
							mp4->hls_ctx->frame_no, &mp4->fname, mp4->offs);
						return NGX_HTTP_INTERNAL_SERVER_ERROR;
					}
					for (i = 0; i < 3; i++) {
						*p++ = i == 2 ? 1 : 0;
						if (p == p_end) {
							b->last = p_end;
							if ((b = hls_newpacket(b, ctx, mp4->hls_ctx, TS_TYP1_CONTINUE, TS_TYP2_PAYLD)) == NULL)
								return NGX_HTTP_INTERNAL_SERVER_ERROR;
							p = b->last;
							p_end = p + MPEGTS_PACKET_USABLE_SIZE;
						}
					}
					pes_len += 3;
					len = (p_end - p);
					while (len < subframe_end && mp4->offs <= subframe_end - len) {
						if (mp4mux_read(mp4, p, len, 1) != NGX_OK)
							return NGX_HTTP_INTERNAL_SERVER_ERROR;
						b->last = p_end;
						if ((b = hls_newpacket(b, ctx, mp4->hls_ctx, TS_TYP1_CONTINUE, TS_TYP2_PAYLD)) == NULL)
							return NGX_HTTP_INTERNAL_SERVER_ERROR;
						p = b->last;
						p_end = p + MPEGTS_PACKET_USABLE_SIZE;
						len = MPEGTS_PACKET_USABLE_SIZE;
					}
					len = subframe_end - mp4->offs;
					if (mp4mux_read(mp4, p, len, 1) != NGX_OK)
						return NGX_HTTP_INTERNAL_SERVER_ERROR;
					p += len;
				}
				// Move to the next frame
				mp4->hls_ctx->frame_offs = frame_end;

				rc = hls_nextframe(mp4);
				if (rc != NGX_OK)
					return rc;
				break;
			case PES_AUDIO:
				*(uint32_t*)adts_hdr = mp4->hls_ctx->adts_hdr;
				adts_hdr[6] = 0xfc;
				len += SIZEOF_ADTS_HEADER;
				do {
					if (len >= 8192) {
						ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
							"audio frame is too long: %i", len);
						return NGX_HTTP_INTERNAL_SERVER_ERROR;
					}
					if (p == p_end) {
						b->last = p;
						if ((b = hls_newpacket(b, ctx, mp4->hls_ctx, TS_TYP1_CONTINUE, TS_TYP2_PAYLD)) == NULL)
							return NGX_HTTP_INTERNAL_SERVER_ERROR;
						p = b->last;
						p_end = p + MPEGTS_PACKET_USABLE_SIZE;
					}
					adts_hdr[3] &= 0xfc;
					adts_hdr[3] |= len >> 11;
					adts_hdr[4] = len >> 3;
					adts_hdr[5] = len << 5 | 0x1f;
					for (i = 0; i < SIZEOF_ADTS_HEADER; i++) {
						*p++ = adts_hdr[i];
						if (p == p_end) {
							b->last = p_end;
							if ((b = hls_newpacket(b, ctx, mp4->hls_ctx, TS_TYP1_CONTINUE, TS_TYP2_PAYLD)) == NULL)
								return NGX_HTTP_INTERNAL_SERVER_ERROR;
							p = b->last;
							p_end = p + MPEGTS_PACKET_USABLE_SIZE;
						}
					}
					pes_len += len;
					len = (p_end - p);
					while (len < frame_end && mp4->offs < frame_end - len) {
						if (mp4mux_read(mp4, p, len, 1) != NGX_OK)
							return NGX_OK;
						b->last = p_end;
						if ((b = hls_newpacket(b, ctx, mp4->hls_ctx, TS_TYP1_CONTINUE, TS_TYP2_PAYLD)) == NULL)
							return NGX_HTTP_INTERNAL_SERVER_ERROR;
						p = b->last;
						p_end = p + MPEGTS_PACKET_USABLE_SIZE;
						len = MPEGTS_PACKET_USABLE_SIZE;
					}
					len = frame_end - mp4->offs;
					if (mp4mux_read(mp4, p, len, 1) != NGX_OK)
						return NGX_OK;
					p += len;
					// Move to the next frame
					mp4->hls_ctx->frame_offs = frame_end;
					rc = hls_nextframe(mp4);
					if (rc != NGX_OK)
						return rc;
					len = be32toh(mp4->stsz->tbl[mp4->hls_ctx->frame_no]);
					frame_end = mp4->offs + len;
					len += SIZEOF_ADTS_HEADER;
				} while (!mp4->hls_ctx->eof && mp4->hls_ctx->dts-dts < HLS_MAX_DELAY
					&& pes_len + len <= HLS_AUDIO_PACKET_LEN);
				break;
			default:
				ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
					"Invalid track type #", ctx->cur_trak);
			}
			#if (NGX_HAVE_FILE_AIO)
			if (mp4->aio)
				mp4mux_nextrdbuf(mp4); // prefetch next buf
			#endif
			// Flush TS packet
			if (pes_len > 65535)
				*len_field = 0;
			else
				*len_field = htobe16(pes_len);
			if (p != p_end) {
				// stuff packet
				if ((p_end[3-MPEGTS_PACKET_SIZE] & 0x20) == 0) {
					len = p-(p_end-MPEGTS_PACKET_USABLE_SIZE);
					ngx_memmove(p_end-len, p-len, len);
					p = p_end - MPEGTS_PACKET_SIZE + 3;
					*p++ |= 0x20;
					len = MPEGTS_PACKET_USABLE_SIZE-len-1;
					*p++ = len;
					if (len > 0) {
						*p++ = 0;
						ngx_memset(p, 0xff, --len);
					}
				} else {
					i = p_end[4-MPEGTS_PACKET_SIZE];
					len = p-(p_end-MPEGTS_PACKET_USABLE_SIZE+i+1);
					ngx_memmove(p_end-len, p-len, len);
					len = MPEGTS_PACKET_USABLE_SIZE-len-i-1;
					p_end[4-MPEGTS_PACKET_SIZE] += len;
					ngx_memset(p_end-MPEGTS_PACKET_USABLE_SIZE+i+1, 0xff, len);
				}
			}
			b->last = p_end;
		}
		if (ctx->done) {
			for (ctx->cur_trak = 0; ctx->cur_trak < ctx->trak_cnt; ctx->cur_trak++) {
				mp4 = ctx->mp4_src[ctx->cur_trak];
				if (mp4->hls_ctx->packet_count < 0) {
					ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
						"mp4mux_hls: wrong packet count calculation at track %i, diff: %i",
						ctx->cur_trak, mp4->hls_ctx->packet_count);
				} else if (mp4->hls_ctx->packet_count > 0) {
					ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
						"mp4mux_hls: wrong packet count calculation at track %i, diff: %i"
						", inserting empty packets to match Content-Length",
						ctx->cur_trak, mp4->hls_ctx->packet_count);
					while (mp4->hls_ctx->packet_count > 0)
						if ((b = hls_emptypacket(b, ctx, mp4->hls_ctx)) == NULL)
							return NGX_HTTP_INTERNAL_SERVER_ERROR;
				}

				// Add empty packets to the end of .ts file to reset continuity counters
				while (mp4->hls_ctx->cocnt != 0)
					if ((b = hls_emptypacket(b, ctx, mp4->hls_ctx)) == NULL)
						return NGX_HTTP_INTERNAL_SERVER_ERROR;
			}
			ctx->chain_last->buf->last_buf = 1;
		} else {
			// If not done, unlink last incomplete buf from chain, we'll continue use it
			for (chain = ctx->chain; chain->next != ctx->chain_last; chain = chain->next);
			chain->next = NULL;
		}

		if (ctx->chain_last->next != NULL || ctx->chain->next == ctx->chain) {
			ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
				"Chain loop!!!");
			return NGX_HTTP_INTERNAL_SERVER_ERROR;
		}
		ngx_log_debug4(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
			"output: chain=%p chain->buf->start=%p chain_last=%p chain_last->buf->start=%p",
			ctx->chain, ctx->chain->buf->start, ctx->chain_last, ctx->chain_last->buf->start);
		rc = ngx_http_output_filter(r, ctx->chain);
		#if nginx_version > 1001000
		ngx_chain_update_chains(r->pool, &ctx->free, &ctx->busy, &ctx->chain,
			(ngx_buf_tag_t) &ngx_http_mp4mux_module);
		#else
		ngx_chain_update_chains(&ctx->free, &ctx->busy, &ctx->chain,
			(ngx_buf_tag_t) &ngx_http_mp4mux_module);
		#endif
		ctx->chain = ctx->chain_last;
	}
	ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
		"mp4mux: DONE! rc = %i", rc);
	return rc;
}

static ngx_int_t mp4mux_write(ngx_http_mp4mux_ctx_t *ctx)
{
	ngx_buf_t   *b;
	ngx_chain_t *out;
	ngx_int_t  j;
	ngx_int_t rc;
	ngx_http_request_t *r = ctx->req;

	if (ctx->done)
		return NGX_OK;

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

			out = ngx_chain_get_free_buf(r->pool, &ctx->free);
			if (!out)
				return NGX_ERROR;

			b = out->buf;

			b->file = &ctx->mp4_src[j]->file;
			b->file_pos = ctx->mp4_src[j]->mdat_pos;
			b->file_last = ctx->mp4_src[j]->mdat_pos + ctx->mp4_src[j]->chunk_size[ctx->chunk_num];

			ctx->mp4_src[j]->mdat_pos += ctx->mp4_src[j]->chunk_size[ctx->chunk_num];
			ctx->mp4_src[j]->mdat_recv -= ctx->mp4_src[j]->chunk_size[ctx->chunk_num];

			b->in_file = 1;
			b->flush = 1;
			b->memory = 0;
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

			if (rc != NGX_OK) {
				if (mp4mux_handle_write_rc(r, rc) != NGX_OK)
					return NGX_ERROR;
				return rc;
			}
		} else
			ctx->cur_trak = j + 1;
	}

	if (!mp4mux_list_empty(&ctx->mp4f.atoms_tail)) {
		out = mp4_build_chain(ctx, &ctx->mp4f.atoms_tail);
		if (!out)
			return NGX_ERROR;

		rc = ngx_http_output_filter(r, out);

		if (rc != NGX_OK && rc != NGX_AGAIN) {
			if (mp4mux_handle_write_rc(r, rc) != NGX_OK)
				return NGX_ERROR;
			return rc;
		}
	}

	ctx->done = 1;

	ngx_log_debug1(NGX_LOG_DEBUG_HTTP, ctx->req->connection->log, 0,
		"mp4mux: done: count=%i", ctx->req->main->count);

	return NGX_OK;
}

static void ngx_http_mp4mux_write_handler(ngx_event_t *ev)
{
	ngx_connection_t *c;
	ngx_http_request_t *r;
	ngx_http_mp4mux_ctx_t *ctx;
	ngx_int_t rc;

	c = ev->data;
	r = c->data;

	c = r->connection;

	ctx = ngx_http_get_module_ctx(r, ngx_http_mp4mux_module);

	ngx_log_debug2(NGX_LOG_DEBUG_HTTP, c->log, 0,
		"mp4mux write handler: \"%V?%V\"", &r->uri, &r->args);

	ctx->write_handler(ev);
	r->blocked--;
	ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0, "blocked = %i", r->blocked);

	if ((r->blocked && ctx->fmt == FMT_HLS_SEGMENT)
			|| c->destroyed || r->done || ctx->done) {
		ev->handler = ctx->write_handler;
		return;
	}

	if (!r->out || !r->out->next) {
		ev->handler = ctx->write_handler;
		switch (ctx->fmt) {
		case FMT_MP4:
			ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0, "calling mp4mux_write()");
			rc = mp4mux_write(ctx);
			break;
		case FMT_HLS_SEGMENT:
			ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0, "calling mp4mux_hls_write()");
			rc = mp4mux_hls_write(ctx);
			break;
		default:
			ngx_log_error(NGX_LOG_ERR, c->log, 0, "ngx_http_mp4mux_write_handler: invalid fmt value: %i", ctx->fmt);
			rc = NGX_ERROR;
		}
		if (rc != NGX_AGAIN)
			ngx_http_finalize_request(ctx->req, rc);
	}
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

	for (i = 0; i < sizeof(mp4_atom_containers)/sizeof(mp4_atom_containers[0]); i++)
		if (atom->hdr->type == mp4_atom_containers[i]) {
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

				a->hdr = hdr;

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
	return 0;
}

static ngx_int_t mp4_parse(mp4_file_t *mp4f)
{
	mp4_atom_hdr_t hdr;
	mp4_atom_t *atom;
	uint32_t size;
	uint64_t size64;
	ngx_int_t n;
	char atom_name[5];

	atom_name[4] = 0;

	#if (NGX_HAVE_FILE_AIO)
	if (mp4f->aio_atom) {
		ngx_log_debug0(NGX_LOG_DEBUG_HTTP, mp4f->log, 0,
			"incomplete atom found, parsing it");
		if (mp4_parse_atom(mp4f, mp4f->aio_atom))
			return NGX_HTTP_NOT_FOUND;
		mp4f->aio_atom = NULL;
	}
	#endif

	while (mp4f->offs < mp4f->file_size) {
		n = mp4mux_read(mp4f, (u_char *)&hdr, sizeof(hdr), 0);

		if (n == NGX_AGAIN)
			return NGX_AGAIN;
		if (n != NGX_OK)
			return NGX_HTTP_INTERNAL_SERVER_ERROR;

		size = be32toh(hdr.size);

		memcpy(atom_name, &hdr.type, 4);
		ngx_log_debug2(NGX_LOG_DEBUG_HTTP, mp4f->log, 0,
			"begin atom: %s %i", atom_name, size);

		if (size == 1) {
			n = mp4mux_read(mp4f, (u_char *)&size64, 8, 0);
			if (n == NGX_AGAIN)
				return NGX_AGAIN;
			if (n != NGX_OK)
				return NGX_HTTP_INTERNAL_SERVER_ERROR;
			size64 = be64toh(size64);
			ngx_log_debug1(NGX_LOG_DEBUG_HTTP, mp4f->log, 0, "size64 %L", size64);
		}

		if (size == 0) {
			size = mp4f->file_size - mp4f->offs_restart;
			hdr.size = htobe32(size);
		} else if (size != 1 && size < 8) {
			ngx_log_error(NGX_LOG_ERR, mp4f->log, 0,
				"mp4mux: \"%V\": atom is too small:%uL",
				&mp4f->fname, size);
			return NGX_HTTP_NOT_FOUND;
		}
		switch (hdr.type) {
		case ATOM('m', 'd', 'a', 't'):
			mp4f->mdat_pos = mp4f->offs;
			mp4f->mdat_size = size == 1 ? (size64 - sizeof(hdr) - 8) : (size - sizeof(hdr));
		case ATOM('f', 'r', 'e', 'e'):
			if (size != 1) size64 = size;
			if (mp4mux_seek(mp4f, mp4f->offs_restart + size64) != NGX_OK)
				return NGX_HTTP_INTERNAL_SERVER_ERROR;
			break;
		default:
			if (size == 1 || size > MAX_ATOM_SIZE) {
				ngx_log_error(NGX_LOG_ERR, mp4f->log, 0,
					"mp4mux: \"%V\": mp4 atom is too large:%uL",
					&mp4f->fname, size);
				return NGX_HTTP_NOT_FOUND;
			}
			if (size < mp4f->rdbuf_size) {
				atom = ngx_palloc(mp4f->pool, sizeof(*atom) + size);
				if (!atom)
					return NGX_HTTP_INTERNAL_SERVER_ERROR;

				ngx_memcpy(atom->data, &hdr, sizeof(hdr));

				n = mp4mux_read(mp4f, atom->data + sizeof(hdr), size - sizeof(hdr), 0);
				if (n == NGX_AGAIN)
					return NGX_AGAIN;
				if (n != NGX_OK)
					return NGX_HTTP_INTERNAL_SERVER_ERROR;

				atom->hdr = (mp4_atom_hdr_t *)atom->data;
				mp4f->offs_restart = mp4f->offs; // no need to seek
			} else {
				// atom is large, allocate special buffer for it
				atom = ngx_palloc(mp4f->pool, sizeof(*atom));
				if (!atom)
					return NGX_HTTP_INTERNAL_SERVER_ERROR;
				mp4mux_seek(mp4f, mp4f->offs_restart);
				n = mp4mux_read_direct(mp4f, (u_char **)&atom->hdr, size);
				#if (NGX_HAVE_FILE_AIO)
				if (n == NGX_AGAIN)
					mp4f->aio_atom = atom;
				else
				#endif
					if (n != NGX_OK)
						return NGX_HTTP_INTERNAL_SERVER_ERROR;
			}
			atom->parent = NULL;

			MP4MUX_INIT_LIST_HEAD(&atom->atoms);
			mp4mux_list_add_tail(&atom->entry, &mp4f->atoms);
			#if (NGX_HAVE_FILE_AIO)
			if (mp4f->aio_atom != NULL)
				return NGX_AGAIN;
			#endif
			if (mp4_parse_atom(mp4f, atom))
				return NGX_HTTP_NOT_FOUND;
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

	// Strip out entries before start from stts (keyframes list) atom
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

	mp4_src->chunk_cnt = stco_cnt;
	mp4_src->chunk_size = ngx_palloc(pool, (stco_cnt + 1) * sizeof(ngx_uint_t));

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

	return stco;
}

static ngx_int_t mp4_add_mdat(mp4_file_t *mp4f, off_t size, ngx_int_t co64)
{
	mp4_atom_t *a;

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


// Nginx config
static void *
ngx_http_mp4mux_create_conf(ngx_conf_t *cf)
{
	ngx_http_mp4mux_conf_t  *conf;

	conf = ngx_palloc(cf->pool, sizeof(ngx_http_mp4mux_conf_t));
	if (conf == NULL) {
		return NULL;
	}

	conf->rdbuf_size = NGX_CONF_UNSET_SIZE;
	conf->wrbuf_size = NGX_CONF_UNSET_SIZE;
	conf->move_meta = NGX_CONF_UNSET;
	conf->segment_ms = NGX_CONF_UNSET;

	return conf;
}


static char *
ngx_http_mp4mux_merge_conf(ngx_conf_t *cf, void *parent, void *child)
{
	ngx_http_mp4mux_conf_t *prev = parent;
	ngx_http_mp4mux_conf_t *conf = child;

	ngx_conf_merge_size_value(conf->rdbuf_size, prev->rdbuf_size, 128 * 1024);
	ngx_conf_merge_size_value(conf->wrbuf_size, prev->wrbuf_size, 128 * 1024);
	ngx_conf_merge_value(conf->move_meta, prev->move_meta, 1);
	ngx_conf_merge_value(conf->segment_ms, prev->segment_ms, 10000);

	return NGX_CONF_OK;
}
