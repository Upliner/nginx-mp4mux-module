
/*
 * Copyright (C) Igor Sysoev
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_md5.h>
#include <nginx.h>

#if (NGX_FREEBSD)
#include <sys/endian.h>
#endif

#include "ngx_http_mp4mux_list.h"
#include "hls.h"
#include "dash.h"

#define MAX_FILE 10
#define MAX_ATOM_SIZE 16*1024*1024
#define MAX_LIST_SIZE 128*1024
#define MAX_URLLEN 4096

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
#define FMT_DASH_MANIFEST 0x20
#define FMT_DASH_INIT 0x21
#define FMT_DASH_SEGMENT 0x22

#define TS_TYP1_START 0x41
#define TS_TYP1_CONTINUE 0x01

#define TS_TYP2_PAYLD 0x10
#define TS_TYP2_ADAPT_PAYLD 0x30

#define HLS_AUDIO_PACKET_LEN 2930

#define PES_VIDEO 0xe0
#define PES_AUDIO 0xc0

#define MP4MUX_CACHE_LOADING NGX_MAX_INT32_VALUE

#define MP4MUX_HDR_NUM (-2)

#define SECTOR_SIZE 4096  // you can set it to 512 if you don't use 4Kn drives

typedef u_char bool_t;

typedef struct {
	uint32_t size;
	uint32_t type;
	union {
		u_char data[0];
		uint32_t data32[0];
		uint64_t data64[0];
	} u;
} __packed mp4_atom_hdr_t;

typedef struct {
	mp4_atom_hdr_t hdr;
	uint32_t major;
	uint32_t minor;
	uint32_t brands[0];
} __packed mp4_atom_ftyp_t;

typedef struct {
	mp4_atom_hdr_t hdr;
	u_char version;
	u_char flags[3];
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
	u_char version;
	u_char flags[3];
	uint32_t ctime;
	uint32_t mtime;
	uint32_t timescale;
	uint32_t duration;
	uint16_t lang;
	uint16_t q;
} __packed mp4_atom_mdhd_v0_t;

typedef struct {
	mp4_atom_hdr_t hdr;
	u_char version;
	u_char flags[3];
	uint64_t ctime;
	uint64_t mtime;
	uint32_t timescale;
	uint64_t duration;
	uint16_t lang;
	uint16_t q;
} __packed mp4_atom_mdhd_v1_t;

typedef struct {
	mp4_atom_hdr_t hdr;
	u_char version;
	u_char flags[3];
	uint32_t ctype;
	uint32_t subtype;
	uint32_t manufacturer;
	uint32_t cflags;
	uint32_t cflags_mask;
	u_char name[0];
} __packed mp4_atom_hdlr_t;

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
	u_char version;
	u_char flags[3];
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
	u_char version;
	u_char flags[3];
	u_char data[0];
} __packed mp4_atom_esds_t;

typedef struct {
	u_char prof_ind;
	uint32_t unused;
	uint32_t max_bitrate;
	uint32_t avg_bitrate;
} __packed esds_decconf_t;

typedef struct {
	mp4_atom_hdr_t hdr;
	u_char version;
	u_char flags[3];
	uint32_t entries;
	u_char reserved[20];
	mp4_atom_esds_t esds;
} __packed mp4_atom_mp4a_t;

typedef struct {
	uint32_t bitrate;
	u_char profile, rate_idx, chanconf;
} mp4a_audio_desc;

typedef struct {
	mp4_atom_hdr_t hdr;
	u_char version;
	u_char flags[3];
	uint32_t entries;
	union {
		mp4_atom_hdr_t hdr;
		mp4_atom_avc1_t avc1;
		mp4_atom_mp4a_t mp4a;
	} entry;
} __packed mp4_atom_stsd_t;

typedef struct {
	mp4_atom_hdr_t hdr;
	u_char version;
	u_char flags[3];
	uint32_t sample_size;
	uint32_t sample_cnt;
	uint32_t tbl[0];
} __packed mp4_atom_stsz_t;

typedef struct {
	mp4_atom_hdr_t hdr;
	u_char version;
	u_char flags[3];
	uint32_t entries;
	uint32_t tbl[0];
} __packed mp4_atom_stss_t;

typedef struct {
	uint32_t count;
	uint32_t value;
} __packed mp4_stbl_entry_t;

typedef struct {
	mp4_atom_hdr_t hdr;
	u_char version;
	u_char flags[3];
	uint32_t entries;
	mp4_stbl_entry_t tbl[0];
} __packed mp4_atom_stts_t;

typedef struct {
	mp4_atom_hdr_t hdr;
	u_char version;
	u_char flags[3];
	uint32_t entries;
	mp4_stbl_entry_t tbl[0];
} __packed mp4_atom_ctts_t;

typedef struct {
	uint32_t first_chunk;
	uint32_t sample_cnt;
	uint32_t desc_id;
} __packed mp4_stsc_entry_t;

typedef struct {
	mp4_atom_hdr_t hdr;
	u_char version;
	u_char flags[3];
	uint32_t sample_cnt;
	mp4_stsc_entry_t tbl[0];
} __packed mp4_atom_stsc_t;

typedef struct {
	mp4_atom_hdr_t hdr;
	u_char version;
	u_char flags[3];
	uint32_t chunk_cnt;
	union {
		uint32_t tbl[0];
		uint64_t tbl64[0];
	} u;
} __packed mp4_atom_stco_t;

typedef struct {
	mp4_atom_hdr_t hdr;
	u_char version;
	u_char flags[3];
	uint32_t ctime;
	uint32_t mtime;
	uint32_t track_id;
	uint32_t reserved;
	uint32_t duration;
} __packed mp4_atom_tkhd_t;

#define SIDX_SAP_START 0x80000000
#define SIDX_SAP_TYPE1 0x10000000
#define SIDX_SAP_TYPE6 0x60000000
typedef struct {
	uint32_t size;
	uint32_t duration;
	uint32_t sap_params;
} __packed mp4_sidx_entry_t;

typedef struct {
	mp4_atom_hdr_t hdr;
	u_char version;
	u_char flags[3];
	uint32_t ref_id;
	uint32_t timescale;
	uint32_t earliest_pts;
	uint32_t first_offset;
	uint16_t _unused;
	uint16_t entry_count;
	mp4_sidx_entry_t entries[0];
} __packed mp4_atom_sidx_t;

#define TRUN_F1_DURATION 0x01
#define TRUN_F1_SIZE 0x02
#define TRUN_F1_FLAGS 0x04
#define TRUN_F1_CTTS 0x08
typedef struct {
	mp4_atom_hdr_t hdr;
	u_char version;
	u_char flags[3];
	uint32_t frame_count;
	uint32_t mdat_offs;
	uint32_t data[0];
} __packed mp4_atom_trun_t;

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
	mp4mux_list_t entry;
	mp4mux_list_t atoms;
	mp4_atom_hdr_t *hdr;
	mp4_atom_hdr_t data[0];
};

typedef enum {
	atom_clone_meta,
	atom_clone_hdr,
	atom_clone_data,
} atom_clone_depth;

typedef struct mp4_atom_s mp4_atom_t;

typedef struct {
	mp4_stbl_entry_t *entry, *end;
	uint32_t samp_left;
	uint32_t value;
} mp4_stbl_ptr_t;

typedef struct {
	mp4_stsc_entry_t *entry, *end;
	uint32_t chunk_count;
	uint32_t chunk_no;
	uint32_t next;
	uint32_t samp_left;
	uint32_t samp_cnt;
} mp4_stsc_ptr_t;

typedef struct mp4mux_cache_entry_s mp4mux_cache_entry_t;

typedef struct {
	mp4mux_cache_entry_t **hashtable;
	u_char *start, *end;
	u_char *write_pos;
	mp4mux_cache_entry_t *oldest, *newest;
	uint32_t hash_mask;
} mp4mux_cache_header_t;

struct mp4mux_cache_entry_s {
	mp4mux_cache_entry_t *next;
	mp4mux_cache_entry_t *hash_next;
	u_char *start, *end;
	mp4_atom_hdr_t *hdr;
	ngx_atomic_t lock;
	size_t file_size;
	time_t file_mtime;
	uint32_t fname_hash;
	uint32_t fname_len;
	u_char fname[0];
};

typedef struct {
	u_char *cdata;        // raw codec-specific data (PPS and SPS for H.264)
	uint32_t cdata_len;
	uint32_t adts_hdr;    // First 4 bytes of ADTS frame header

	mp4_stbl_ptr_t ctts_ptr;

	u_char pes_id;        // PES stream id
	u_char pes_typ;       // video or audio
	u_char sf_len;        // Length of mp4 subframe size field
	u_char cocnt;         // MPEG-TS continuity counter

	uint32_t dts;

	off_t packet_count;

} mp4_hls_ctx_t;

typedef struct {
	mp4_atom_mvhd_t *mvhd;
	mp4_atom_t *trak;
	mp4_atom_tkhd_t *tkhd;
	mp4_atom_mdhd_v0_t *mdhd;
	mp4_atom_hdlr_t *hdlr;
	mp4_atom_t *minf;
	mp4_atom_t *stbl;
	mp4_atom_stsd_t *stsd;
	mp4_atom_stts_t *stts;
	mp4_atom_stsc_t *stsc;
	mp4_atom_stsz_t *stsz;
	mp4_atom_stco_t *co;
	mp4_atom_ctts_t *ctts;
	mp4_atom_stss_t *stss;
	bool_t co64;
} mp4_trak_t;

typedef struct {
	ngx_http_request_t *req;
	ngx_file_t file;

	ngx_str_t basename;
	ngx_str_t fname;

	mp4_atom_t moov;
	mp4_trak_t trak;

	mp4_stbl_ptr_t stts_ptr;
	mp4_stsc_ptr_t stsc_ptr;

	size_t file_size;
	time_t file_mtime;

	uint32_t *chunks;
	uint32_t *stss_ptr, *stss_end;

	// Muxer state
	uint32_t frame_no;
	uint32_t sample_no;
	uint32_t sample_max; // End of segment or end of movie sample position
	uint32_t timescale;
	uint32_t next_keyframe;

	// Read buffers
	mp4mux_list_t rdbufs;
	mp4mux_list_t free_rdbufs;
	mp4_buf_t *rdbuf_cur;
	size_t rdbuf_size;
	size_t offs, offs_restart, offs_buf;
	off_t sent_pos;

	// Cache
	ngx_uint_t moov_rd_size;
	mp4mux_cache_entry_t *cache_entry;
	u_char *moov_buf;
	#if (NGX_HAVE_FILE_AIO)
	mp4_buf_t *aio_buf;
	#endif

	mp4_hls_ctx_t *hls_ctx;
	unsigned eof:1;
	unsigned aio:1;
	unsigned check:1;
	unsigned dontcache:1;
	unsigned do_copy:1;
} mp4_file_t;

typedef struct {
	ngx_str_t lst_file;
	ngx_int_t path_len;
	ngx_list_t *list;
} mp4mux_manifest_ctx_t;
typedef struct ngx_http_mp4mux_ctx_s {
	ngx_http_request_t *req;
	ngx_event_handler_pt write_handler;
	#if (NGX_HAVE_FILE_AIO)
	ngx_int_t (*aio_handler)(struct ngx_http_mp4mux_ctx_s *);
	#endif
	ngx_chain_t *free;
	ngx_chain_t *busy;
	ngx_chain_t *chain, *chain_last;
	mp4mux_list_t atoms_head;
	mp4mux_list_t atoms_tail;
	mp4_trak_t *traks;
	mp4_file_t *mp4_src[MAX_FILE];
	mp4mux_manifest_ctx_t *mctx;
	ngx_int_t seg_no;
	ngx_int_t dash_tkid;
	ngx_int_t hls_bufsize;
	ngx_int_t cur_trak;
	ngx_int_t trak_cnt;
	ngx_uint_t chunk_num;
	ngx_uint_t chunk_cnt;
	ngx_int_t start;
	ngx_int_t chunk_rate;
	ngx_int_t segment_ms;
	ngx_pool_t *hdr_pool;
	u_char fmt;
	unsigned done:1;
	unsigned move_meta:1;
	unsigned seg_align:1;
	unsigned seg_align_url:1;
} ngx_http_mp4mux_ctx_t;

typedef struct {
	size_t    rdbuf_size;
	size_t    wrbuf_size;
	ngx_int_t chunk_rate;
	ngx_msec_t segment_ms;
	ngx_flag_t move_meta;
	ngx_flag_t seg_align;
	ngx_str_t hls_prefix;
	ngx_str_t hls_master_item;
	ngx_str_t dash_prefix;
	ngx_array_t *hp_lengths;
	ngx_array_t *hp_values;
	ngx_array_t *mp_lengths;
	ngx_array_t *mp_values;
	ngx_array_t *dp_lengths;
	ngx_array_t *dp_values;
} ngx_http_mp4mux_conf_t;

typedef struct {
	ngx_shm_zone_t *cache_zone;
	size_t cache_size;
	size_t cache_hash_size;
	ngx_int_t cache_maxskip;
} ngx_http_mp4mux_main_conf_t;

/* These two structs must be kept in sync with ngx_http_range_filter_module.c
   It seems that there are no other way to hook range-skipping.
   Fortunately, these structures changes really rarely,
   last changed 29 Dec 2006 */
typedef struct {
	off_t        start;
	off_t        end;
	ngx_str_t    content_range;
} ngx_http_range_t;
typedef struct {
	off_t        offset;
	ngx_str_t    boundary_header;
	ngx_array_t  ranges;
} ngx_http_range_filter_ctx_t;

static uint32_t mp4_atom_containers[] = {
	ATOM('m', 'o', 'o', 'v'),
	ATOM('t', 'r', 'a', 'k'),
	ATOM('m', 'd', 'i', 'a'),
	ATOM('m', 'i', 'n', 'f'),
	ATOM('s', 't', 'b', 'l')
};

#define DW_0 "\0\0\0\0"
#define DW_1 "\0\0\0\1"
static u_char ftyp[] = "\0\0\0\x20""ftypmp42"DW_1"mp41mp42isomiso2";
static u_char ftyp_dash[] = "\0\0\0\x24""ftypmp42"DW_1"mp41mp42isomiso2dash";
static u_char styp[] = "\0\0\0\x24stypiso6"DW_1"isomiso6dashmsdhmsix";
static u_char mvex[] = "\0\0\0\x28mvex\0\0\0\x20trex" DW_0 DW_0 DW_1 DW_0 DW_0 DW_0;
static u_char mfhd[] = "\0\0\0\x10mfhd" DW_0 DW_0;
static u_char tfhd[] = "\0\0\0\x10tfhd\0\2\0\0" DW_1;
static u_char tfdt[] = "\0\0\0\x10tfdt" DW_0 DW_0;
#undef DW_0
#undef DW_1

const uint32_t mp4mux_version = 0x01; // This value should be changed after every change in the muxing algorighm to change ETag

static const u_char m3u8_header[] =
	"#EXTM3U\n"
	"#EXT-X-ALLOW-CACHE:YES\n"
	"#EXT-X-PLAYLIST-TYPE:VOD\n"
	"#EXT-X-VERSION:3\n"
	"#EXT-X-MEDIA-SEQUENCE:1\n"
	"#EXT-X-TARGETDURATION:";

static const char m3u8_master_header[] = "#EXTM3U\n";
static const char m3u8_entry[] = "#EXTINF:%i.%03i,\n%Vseg-%i.ts\n";
static const char m3u8_master_video[] = "#EXT-X-STREAM-INF:BANDWIDTH=%i,CODECS=\"avc1.%02uxD%02uxD%02uxD\",AUDIO=\"audio\"\n%V\n";
static const char m3u8_master_audio[] = "#EXT-X-MEDIA:TYPE=AUDIO,GROUP-ID=\"audio\",NAME=\"%V\",AUTOSELECT=YES,LANGUAGE=\"%V\",URI=\"%V\"\n";

static const u_char m3u8_footer[] = "#EXT-X-ENDLIST\n";

extern ngx_module_t ngx_http_range_body_filter_module;

static ngx_int_t ngx_http_mp4mux_add_variables(ngx_conf_t *cf);
static char *ngx_http_mp4mux(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static void *ngx_http_mp4mux_create_main_conf(ngx_conf_t *cf);
static char *ngx_http_mp4mux_init_main_conf(ngx_conf_t *cf, void *conf);
static void *ngx_http_mp4mux_create_conf(ngx_conf_t *cf);
static char *ngx_http_mp4mux_merge_conf(ngx_conf_t *cf, void *parent, void *child);

static mp4mux_cache_entry_t *mp4mux_cache_alloc(mp4_file_t *file, ngx_uint_t size);
static mp4mux_cache_entry_t *mp4mux_cache_fetch(mp4_file_t *file);

static ngx_int_t mp4mux_do_read(mp4_file_t *f, mp4_buf_t *buf);
static ngx_int_t mp4mux_seek(mp4_file_t *f, size_t offs);
static ngx_int_t mp4mux_read(mp4_file_t *f, u_char *data, size_t size, bool_t noreturn);
static ngx_int_t mp4mux_read_chain(mp4_file_t *f, ngx_chain_t *out, ngx_chain_t **free, size_t size);
static ngx_int_t mp4mux_read_moov(mp4_file_t *f, u_char *data, ssize_t size);
static void mp4mux_free_rdbuf(mp4_file_t *f, mp4_buf_t *buf);

static ngx_int_t mp4_validate_stsd_video(ngx_log_t *log, mp4_atom_stsd_t *stsd);
static ngx_int_t mp4_parse_stsd_audio(ngx_log_t *log, mp4a_audio_desc *ad, mp4_atom_stsd_t *stsd);
static ngx_int_t mp4_stsc_ptr_init(mp4_stsc_ptr_t *ptr, mp4_atom_stsc_t *atom, uint32_t chunk_count, ngx_log_t *log);
static ngx_int_t mp4_stbl_ptr_init(mp4_stbl_ptr_t *ptr, mp4_atom_hdr_t *atom, ngx_log_t *log);
static ngx_int_t mp4_stbl_ptr_advance(mp4_stbl_ptr_t *ptr);
static ngx_int_t mp4_stbl_ptr_advance_entry(mp4_stbl_ptr_t *ptr);
static ngx_int_t mp4_init_video(mp4_file_t *f, mp4_stbl_ptr_t *ctts_ptr);
static void mp4_ff_samples(mp4_file_t *f, ngx_int_t sample_cnt);
static void mp4_stss_init(mp4_file_t *f);
static void mp4_stss_ff(mp4_file_t *f);
static void mp4_stss_align(mp4_file_t *f);
static void mp4_stss_upd(mp4_file_t *mp4);
static ngx_int_t mp4_move_to_segment(ngx_http_mp4mux_ctx_t *ctx, mp4_file_t *f, mp4_stbl_ptr_t *ctts_ptr);
static bool_t mp4_is_keyframe(mp4_file_t *mp4);
static ngx_int_t mp4mux_nextframe(mp4_file_t *mp4);

static ngx_int_t mp4_atom_to_trak(mp4_atom_t *a, mp4_trak_t *t);
static ngx_int_t mp4_parse_atom(mp4_file_t *mp4f, mp4_atom_t *atom);
static ngx_int_t mp4_parse(mp4_file_t *f);
//static mp4_atom_t *mp4_find_atom(struct mp4mux_list_head *list, uint32_t type);
static mp4_atom_t *mp4_clone_atom(mp4_atom_t *atom, mp4_trak_t *dst_trak, atom_clone_depth depth, bool_t skip_stbl, ngx_pool_t *pool);
static off_t mp4_build_atoms(mp4mux_list_t *list, ngx_log_t *log);
static off_t mp4_alloc_chunks(ngx_http_mp4mux_ctx_t *ctx, bool_t co64);
static ngx_int_t mp4_tkhd_update(mp4_trak_t *trak, ngx_uint_t id, uint64_t start, uint32_t old_timescale, uint32_t new_timescale);
static ngx_int_t mp4_build_chain_ex(ngx_http_mp4mux_ctx_t *ctx, mp4mux_list_t *list, ngx_chain_t **out, ngx_chain_t **last);
static ngx_chain_t *mp4_build_chain(ngx_http_mp4mux_ctx_t *ctx, mp4mux_list_t *list);
//static ngx_int_t mp4_adjust_pos(mp4_trak_t *trak, uint64_t start);
static ngx_int_t mp4mux_write(ngx_http_mp4mux_ctx_t *ctx);
static ngx_int_t mp4mux_hls_write(ngx_http_mp4mux_ctx_t *ctx);
static void ngx_http_mp4mux_write_handler(ngx_event_t *ev);
static ngx_int_t mp4mux_parse_filelist(ngx_http_request_t *r, mp4mux_manifest_ctx_t *mctx);
static ngx_int_t mp4mux_send_response(ngx_http_mp4mux_ctx_t *ctx);
static ngx_int_t mp4mux_send_mp4(ngx_http_mp4mux_ctx_t *ctx);
static ngx_int_t mp4mux_hls_send_master(ngx_http_mp4mux_ctx_t *ctx);
static ngx_int_t mp4mux_hls_send_index(ngx_http_mp4mux_ctx_t *ctx);
static ngx_int_t mp4mux_hls_send_segment(ngx_http_mp4mux_ctx_t *ctx);
static ngx_int_t mp4mux_dash_send_complex_manifest(ngx_http_mp4mux_ctx_t *ctx);
static ngx_int_t mp4mux_dash_send_manifest(ngx_http_mp4mux_ctx_t *ctx);
static ngx_int_t mp4mux_dash_send_init(ngx_http_mp4mux_ctx_t *ctx);
static ngx_int_t mp4mux_dash_send_segment(ngx_http_mp4mux_ctx_t *ctx);
static void mp4mux_cleanup(void *data);

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

	{ ngx_string("mp4mux_cache_size"),
	  NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
	  ngx_conf_set_size_slot,
	  NGX_HTTP_MAIN_CONF_OFFSET,
	  offsetof(ngx_http_mp4mux_main_conf_t, cache_size),
	  NULL },

	{ ngx_string("mp4mux_cache_hash_size"),
	  NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
	  ngx_conf_set_size_slot,
	  NGX_HTTP_MAIN_CONF_OFFSET,
	  offsetof(ngx_http_mp4mux_main_conf_t, cache_hash_size),
	  NULL },

	{ ngx_string("mp4mux_cache_maxskip"),
	  NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
	  ngx_conf_set_num_slot,
	  NGX_HTTP_MAIN_CONF_OFFSET,
	  offsetof(ngx_http_mp4mux_main_conf_t, cache_maxskip),
	  NULL },

	{ ngx_string("mp4mux_hls_prefix"),
	  NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
	  ngx_conf_set_str_slot,
	  NGX_HTTP_LOC_CONF_OFFSET,
	  offsetof(ngx_http_mp4mux_conf_t, hls_prefix),
	  NULL },

	{ ngx_string("mp4mux_master_item_template"),
	  NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
	  ngx_conf_set_str_slot,
	  NGX_HTTP_LOC_CONF_OFFSET,
	  offsetof(ngx_http_mp4mux_conf_t, hls_master_item),
	  NULL },

	{ ngx_string("mp4mux_dash_prefix"),
	  NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
	  ngx_conf_set_str_slot,
	  NGX_HTTP_LOC_CONF_OFFSET,
	  offsetof(ngx_http_mp4mux_conf_t, dash_prefix),
	  NULL },

	{ ngx_string("mp4mux_move_meta"),
	  NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
	  ngx_conf_set_flag_slot,
	  NGX_HTTP_LOC_CONF_OFFSET,
	  offsetof(ngx_http_mp4mux_conf_t, move_meta),
	  NULL },

	{ ngx_string("mp4mux_seg_align"),
	  NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
	  ngx_conf_set_flag_slot,
	  NGX_HTTP_LOC_CONF_OFFSET,
	  offsetof(ngx_http_mp4mux_conf_t, seg_align),
	  NULL },

	{ ngx_string("mp4mux_chunk_rate"),
	  NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
	  ngx_conf_set_num_slot,
	  NGX_HTTP_LOC_CONF_OFFSET,
	  offsetof(ngx_http_mp4mux_conf_t, chunk_rate),
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
	ngx_http_mp4mux_add_variables, /* preconfiguration */
	NULL,                          /* postconfiguration */

	ngx_http_mp4mux_create_main_conf,/* create main configuration */
	ngx_http_mp4mux_init_main_conf,  /* init main configuration */

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

static u_char* parseint(u_char *str, u_char *end, ngx_int_t *result)
{
	*result = 0;
	while (str < end && *str >= '0' && *str <= '9')
		*result = *result * 10 + *str++ - '0';
	return str;
}

static ngx_int_t intlen(ngx_int_t i)
{
	ngx_int_t x = 1;
	if (i < 0) {
		x++;
		x = -x;
	}
	while (i >= 10) {
		x++;
		i /= 10;
	}
	return x;
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
	ngx_http_range_filter_ctx_t *rangectx;
	ngx_http_cleanup_t *cln;
	u_char *p;

	ngx_log_debug0(NGX_LOG_DEBUG_HTTP, log, 0,
		"http_mp4mux_handler");

	if (!(r->method & (NGX_HTTP_GET|NGX_HTTP_HEAD)))
		return NGX_HTTP_NOT_ALLOWED;

	if (!r->args.len)
		return NGX_HTTP_NOT_FOUND;

	rc = ngx_http_discard_request_body(r);

	if (rc != NGX_OK)
		return rc;

	rangectx = ngx_http_get_module_ctx(r, ngx_http_range_body_filter_module);
	if (rangectx != NULL && rangectx->ranges.nelts != 1) {
		ngx_log_error(NGX_LOG_ERR, log, 0,
			"mp4mux: requests with multiple ranges are not supported", &value);
		return NGX_HTTP_BAD_REQUEST;
	}

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

			ctx->mp4_src[n]->req = r;

			fname.len = path.len + value.len;
			fname.data = ngx_pnalloc(r->pool, fname.len + 1);
			if (!fname.data)
				return NGX_HTTP_INTERNAL_SERVER_ERROR;
			ngx_memcpy(fname.data, path.data, path.len);
			ngx_memcpy(fname.data + path.len, value.data, value.len);
			fname.data[fname.len] = 0;

			ctx->mp4_src[n]->fname = fname;
			ctx->mp4_src[n]->basename = value;

			n++;
		}
	}
	if (ngx_http_arg(r, (u_char *) "filelist", 8, &value) == NGX_OK) {
		if (!(ctx->mctx = ngx_pcalloc(r->pool, sizeof(mp4mux_manifest_ctx_t))))
			return NGX_HTTP_INTERNAL_SERVER_ERROR;
		ctx->mctx->path_len = path.len;
		ctx->mctx->lst_file.len = path.len + value.len;
		ctx->mctx->lst_file.data = ngx_pnalloc(r->pool, ctx->mctx->lst_file.len + 1);
		if (!ctx->mctx->lst_file.data)
			return NGX_HTTP_INTERNAL_SERVER_ERROR;
		ngx_memcpy(ctx->mctx->lst_file.data, path.data, path.len);
		ngx_memcpy(ctx->mctx->lst_file.data + path.len, value.data, value.len);
		ctx->mctx->lst_file.data[ctx->mctx->lst_file.len] = 0;
	}
	if (n == 0 && ctx->mctx == NULL)
		return NGX_HTTP_NOT_FOUND;

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

	if (ngx_http_arg(r, (u_char *)"seg_align", 9, &value) == NGX_OK){
		if (value.len != 1 || (*value.data != '0' && *value.data != '1')) {
			ngx_log_error(NGX_LOG_ERR, log, 0,
				"mp4mux: invalid seg_align value \"%V\", must be '0' or '1'", &value);
			return NGX_HTTP_NOT_FOUND;
		}
		ctx->seg_align = *value.data - '0';
		ctx->seg_align_url = 1;
	} else
		ctx->seg_align = conf->seg_align;

	ctx->chunk_rate = conf->chunk_rate;
	ctx->segment_ms = conf->segment_ms;

	// Parse fmt parameter
	if (ngx_http_arg(r, (u_char *)"fmt", 3, &value) == NGX_OK) {
		if (value.len == 3 && ngx_memcmp(value.data, "mp4", 3) == 0)
			ctx->fmt = FMT_MP4;
		else if ((value.len == 14 && ngx_memcmp(value.data, "hls/index.m3u8", 14) == 0)
				|| (ctx->mctx != NULL && value.len == 15 && ngx_memcmp(value.data, "hls/master.m3u8", 15) == 0))
			ctx->fmt = FMT_HLS_INDEX;
		else if (value.len == 17 && ngx_memcmp(value.data, "dash/manifest.mpd", 17) == 0)
			ctx->fmt = FMT_DASH_MANIFEST;
		else if (value.len >= 8 && ngx_memcmp(value.data, "hls/seg-", 8) == 0) {
			last = value.data + value.len - 3;
			if (ngx_memcmp(last, ".ts", 3)) {
				ngx_log_error(NGX_LOG_ERR, log, 0,
					"mp4mux: only .ts segments are supported for HLS, queried \"%V\"", &value);
				return NGX_HTTP_NOT_FOUND;
			}
			p = parseint(value.data + 8, last, &ctx->seg_no);
			if (p != last || ctx->seg_no == 0) {
				ngx_log_error(NGX_LOG_ERR, log, 0,
					"mp4mux: invalid HLS segment number in \"%V\"", &value);
				return NGX_HTTP_NOT_FOUND;
			}
			ctx->fmt = FMT_HLS_SEGMENT;
			ctx->hls_bufsize = conf->wrbuf_size/MPEGTS_PACKET_SIZE;
			if (ctx->hls_bufsize < 5) ctx->hls_bufsize = 5;
			ctx->hls_bufsize *= MPEGTS_PACKET_SIZE;
		} else if (value.len >= 10 && ngx_memcmp(value.data, "dash/init-", 10) == 0) {
			last = value.data + value.len - 4;
			if (ngx_memcmp(last, ".mp4", 4)) {
				ngx_log_error(NGX_LOG_ERR, log, 0,
					"mp4mux: DASH init must have .mp4 extension \"%V\"", &value);
				return NGX_HTTP_NOT_FOUND;
			}
			p = parseint(value.data + 10, last, &ctx->dash_tkid);
			if (p != last || ctx->dash_tkid == 0) {
				ngx_log_error(NGX_LOG_ERR, log, 0,
					"mp4mux: invalid DASH representation ID in \"%V\"", &value);
				return NGX_HTTP_NOT_FOUND;
			}
			ctx->fmt = FMT_DASH_INIT;
		} else if (value.len >= 9 && ngx_memcmp(value.data, "dash/seg-", 9) == 0) {
			last = value.data + value.len - 4;
			if (ngx_memcmp(last, ".m4s", 4)) {
				ngx_log_error(NGX_LOG_ERR, log, 0,
					"mp4mux: DASH segment must have .m4s extension \"%V\"", &value);
				return NGX_HTTP_NOT_FOUND;
			}
			p = parseint(value.data + 9, last, &ctx->seg_no);
			if (ctx->seg_no == 0) {
				ngx_log_error(NGX_LOG_ERR, log, 0,
					"mp4mux: invalid DASH segment number in \"%V\"", &value);
				return NGX_HTTP_NOT_FOUND;
			}
			if (*p++ != '-') {
				ngx_log_error(NGX_LOG_ERR, log, 0,
					"mp4mux: invalid DASH segment format \"%V\"", &value);
				return NGX_HTTP_NOT_FOUND;
			}
			p = parseint(p, last, &ctx->dash_tkid);
			if (p != last || ctx->dash_tkid == 0) {
				ngx_log_error(NGX_LOG_ERR, log, 0,
					"mp4mux: invalid DASH representation ID \"%V\"", &value);
				return NGX_HTTP_NOT_FOUND;
			}
			ctx->fmt = FMT_DASH_SEGMENT;
		} else {
			ngx_log_error(NGX_LOG_ERR, log, 0,
				"mp4mux: invalid fmt argument \"%V\"", &value);
			return NGX_HTTP_NOT_FOUND;
		}
	} else
		ctx->fmt = FMT_MP4;

	if (n > 1 && (ctx->fmt == FMT_DASH_INIT || ctx->fmt == FMT_DASH_SEGMENT)) {
		if (ctx->dash_tkid > n) {
			ngx_log_error(NGX_LOG_ERR, log, 0,
				"mp4mux: invalid DASH track id");
			return NGX_HTTP_NOT_FOUND;
		}
		ctx->mp4_src[0] = ctx->mp4_src[ctx->dash_tkid - 1];
		n = 1;
	}

	r->allow_ranges = 1;

	if (ctx->start) {
			ngx_log_error(NGX_LOG_ERR, log, 0,
				"mp4mux: \"start\" parameter is temporary disabled");
			return NGX_HTTP_NOT_FOUND;
	}

	if (ctx->mctx != NULL) {
		if (ctx->fmt != FMT_DASH_MANIFEST && ctx->fmt != FMT_HLS_INDEX) {
			ngx_log_error(NGX_LOG_ERR, log, 0,
				"mp4mux: filelist parameter is only valid for playlists, fmt = %uD", ctx->fmt);
			return NGX_HTTP_NOT_FOUND;
		}
		if ((rc = mp4mux_parse_filelist(ctx->req, ctx->mctx)) != NGX_OK)
			return rc;
		switch (ctx->fmt) {
		case FMT_HLS_INDEX:
			#if (NGX_HAVE_FILE_AIO)
			ctx->aio_handler = mp4mux_hls_send_master;
			#endif
			return mp4mux_hls_send_master(ctx);
		case FMT_DASH_MANIFEST:
			#if (NGX_HAVE_FILE_AIO)
			ctx->aio_handler = mp4mux_dash_send_complex_manifest;
			#endif
			return mp4mux_dash_send_complex_manifest(ctx);
		}
	}

	ctx->trak_cnt = n;
	ctx->cur_trak = 0;
	ctx->write_handler = r->connection->write->handler;

	#if (NGX_HAVE_FILE_AIO)
	ctx->aio_handler = mp4mux_send_response;
	#endif
	return mp4mux_send_response(ctx);
}
static bool_t check_conn_error(ngx_http_request_t *r, ngx_connection_t *c) {
	if (c->error && !r->blocked) {
		ngx_http_free_request(r, NGX_ERROR);
		ngx_http_close_connection(c);
		return 1;
	}
	return 0;
}
#if (NGX_HAVE_FILE_AIO)
static ngx_int_t mp4mux_finish_read(mp4_file_t *f) {
	mp4_buf_t *buf = f->aio_buf;
	ngx_int_t rc, expected;
	rc = ngx_file_aio_read(&f->file, NULL, 0, 0, f->req->pool);
	f->req->blocked--;
	ngx_log_debug1(NGX_LOG_DEBUG_HTTP, f->file.log, 0, "blocked = %i", f->req->blocked);
	if (rc < 0) {
		ngx_log_error(NGX_LOG_ERR, f->file.log, 0, "async read failed, rc = %i", rc);
		return NGX_ERROR;
	}
	expected = f->moov_rd_size ? f->moov_rd_size : buf->offs_end - buf->offs;
	if (rc < expected) {
		ngx_log_error(NGX_LOG_ERR, f->file.log, 0,
			"async: wrong byte count read %i, expected %i", rc, expected);
		return NGX_ERROR;
	}
	if (f->moov_rd_size) {
		f->moov_rd_size = 0;
		if (f->cache_entry) {
			if (f->cache_entry->lock == MP4MUX_CACHE_LOADING)
				f->cache_entry->lock = f->req->done ? 0 : 1;
			else
				ngx_log_error(NGX_LOG_ERR, f->file.log, 0,
					"mp4mux_finish_read(): completed loading already loaded cache entry");
		}
        buf = f->rdbuf_cur;
	} else {
		if (buf == NULL) {
			ngx_log_error(NGX_LOG_ERR, f->file.log, 0, "mp4mux_finish_read: aio buffer is null!");
			return NGX_ERROR;
		}
		buf->aio_done = 1;
		ngx_log_debug1(NGX_LOG_DEBUG_HTTP, f->file.log, 0, "AIO done, buf %p", buf);
		f->aio_buf = NULL;
		buf = mp4mux_list_entry(buf->entry.next, mp4_buf_t, entry);
	}
	while (buf != NULL && &buf->entry != &f->rdbufs && !buf->aio_done) { // Read next bufs if any
		ngx_log_debug2(NGX_LOG_DEBUG_HTTP, f->file.log, 0, "next buf = %p, rdbufs=%p", buf, &f->rdbufs);
		rc = mp4mux_do_read(f, buf);
		if (rc == NGX_AGAIN) return rc;
		if (rc != NGX_OK) {
			ngx_log_error(NGX_LOG_ERR, f->file.log, 0,
				"ngx_http_mp4mux_read_handler: error while reading next buf");
			return NGX_ERROR;
		}
		buf = mp4mux_list_entry(buf->entry.next, mp4_buf_t, entry);
	}
	return NGX_OK;
}
static void ngx_http_mp4mux_read_handler(ngx_event_t *ev) {
	ngx_event_aio_t *aio;
	mp4_file_t *f;
	ngx_http_request_t *req;
	ngx_connection_t *c;
	ngx_http_mp4mux_ctx_t *ctx;
	ngx_int_t rc;

	aio = ev->data;
	f = aio->data;
	ngx_log_debug2(NGX_LOG_DEBUG_HTTP, f->file.log, 0, "started aio read handler, file: %p, fd = %i", f, f->file.fd);
	req = f->req;
	c = req->connection;

	rc = mp4mux_finish_read(f);
	if (rc != NGX_OK) {
		if (rc != NGX_AGAIN)
			ngx_http_finalize_request(req, NGX_HTTP_INTERNAL_SERVER_ERROR);
		return;
	}

	if (req->blocked) return;
	ctx = ngx_http_get_module_ctx(req, ngx_http_mp4mux_module);
	if (ctx->done || req->done || c->destroyed || c->error || ctx->aio_handler == NULL) {
		if (check_conn_error(req, c) == 0)
			ngx_http_finalize_request(req, NGX_OK); // Finalize properly after blocking
		return;
	}

	if (f->offs != f->offs_restart) {
		ngx_log_debug1(NGX_LOG_DEBUG_HTTP, f->file.log, 0,
			"restarting at offs %i", f->offs_restart);
		mp4mux_seek(f, f->offs_restart);
	}

	ngx_log_debug0(NGX_LOG_DEBUG_HTTP, f->file.log, 0,
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
	} else {
		buf->eof = 0;
		newsz = buf->size;
	}
	buf->data_end = buf->data + newsz;
	return newsz;
}
#if (NGX_HAVE_FILE_AIO)
static bool_t mp4mux_aio_busy(mp4_file_t *f) {
	if (f->aio_buf || f->moov_rd_size) {
		ngx_log_debug0(NGX_LOG_DEBUG_HTTP, f->file.log, 0,
			"mp4mux: avoiding second aio post");
		return 1;
	}
	return 0;
}
static ngx_int_t mp4mux_aio_read(mp4_file_t *f, u_char *data, size_t size, off_t offs) {
	ngx_int_t rc;
	rc = ngx_file_aio_read(&f->file, data, size, offs, f->req->pool);
	if (rc == NGX_AGAIN) {
		f->file.aio->data = f;
		f->file.aio->handler = ngx_http_mp4mux_read_handler;
		f->req->blocked++;
	}
	return rc;
}
#endif
static ngx_int_t mp4mux_do_read(mp4_file_t *f, mp4_buf_t *buf)
{
	ngx_int_t rc, newsz;
	if (buf == NULL) {
		ngx_log_error(NGX_LOG_ERR, f->file.log, 0,
			"mp4mux_do_read: buf is null");
		return NGX_ERROR;
	}

	newsz = mp4mux_checkeof(f, buf);

	buf->aio_done = 0;

	#if (NGX_HAVE_FILE_AIO)
	if (f->aio) {
		if (mp4mux_aio_busy(f)) return NGX_AGAIN;
		rc = mp4mux_aio_read(f, buf->data, ngx_align(newsz, SECTOR_SIZE), buf->offs);
		if (rc == NGX_AGAIN)
			f->aio_buf = buf;
	} else
	#endif
		rc = ngx_read_file(&f->file, buf->data, ngx_align(newsz, SECTOR_SIZE), buf->offs);

	if (rc < 0)
		return rc;
	if (rc != newsz)
		return NGX_ERROR;
	buf->aio_done = 1;
	return NGX_OK;
}
static void mp4mux_free_rdbuf(mp4_file_t *f, mp4_buf_t *buf)
{
	if (buf->persist || !buf->aio_done) {
		ngx_log_debug3(NGX_LOG_DEBUG_HTTP, f->file.log, 0,
			"preserving buf %p: persist = %i, aio_done = %i", buf, buf->persist, buf->aio_done);
		return;
	}
	ngx_log_debug1(NGX_LOG_DEBUG_HTTP, f->file.log, 0,
		"freeing buf %p", buf);
	mp4mux_list_del(&buf->entry);
	if (buf->size == f->rdbuf_size) {
		mp4mux_list_add(&buf->entry, &f->free_rdbufs);
	} else {
		ngx_pfree(f->req->pool, buf->data);
		ngx_pfree(f->req->pool, buf);
	}
}
static mp4_buf_t *mp4mux_alloc_rdbuf(mp4_file_t *f, size_t size)
{
	mp4_buf_t *buf = ngx_pcalloc(f->req->pool, sizeof(mp4_buf_t));
	if (buf == NULL)
		return NULL;
	if (f->file.directio)
		buf->data = ngx_pmemalign(f->req->pool, size, SECTOR_SIZE);
	else
		buf->data = ngx_palloc(f->req->pool, size);
	buf->size = size;
	if (buf->data == NULL)
		return NULL;
	return buf;
}
static mp4_buf_t *mp4mux_get_rdbuf_sz(mp4_file_t *f, size_t size, size_t offs)
{
	ngx_int_t rc;
	mp4_buf_t *buf;
	ngx_log_debug2(NGX_LOG_ERR, f->file.log, 0,
		"mp4mux_get_rdbuf_sz() size %i, offs %i", size, offs);
	if (offs >= f->file_size) {
		ngx_log_error(NGX_LOG_ERR, f->file.log, 0,
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
			ngx_pfree(f->req->pool, buf->data);
			ngx_pfree(f->req->pool, buf);
		} else {
			if (offs >= f->file_size) {
				ngx_log_error(NGX_LOG_ERR, f->file.log, 0,
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
			ngx_log_debug7(NGX_LOG_DEBUG_HTTP, f->file.log, 0,
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

	ngx_log_debug3(NGX_LOG_DEBUG_HTTP, f->file.log, 0,
		"mp4mux_preread() = %p, offs = %i, entry = %p", buf, offs, entry);

	if (buf == NULL)
		return NULL;

	mp4mux_list_add_tail(&buf->entry, entry);
	if (f->rdbuf_cur == NULL)
		f->rdbuf_cur = buf;

	return buf;
}
static ngx_int_t mp4mux_do_open_file(ngx_open_file_info_t *of, ngx_file_t *f, ngx_http_core_loc_conf_t *clcf, ngx_http_request_t *r, ngx_str_t *name)
{
	ngx_uint_t level;
	ngx_int_t rc;
	of->read_ahead = clcf->read_ahead;
	of->valid = clcf->open_file_cache_valid;
	of->min_uses = clcf->open_file_cache_min_uses;
	of->errors = clcf->open_file_cache_errors;
	of->events = clcf->open_file_cache_events;

	ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
		"mp4mux: open file: \"%V\"", name);
	if (ngx_open_cached_file(clcf->open_file_cache, name, of, r->pool) != NGX_OK)
	{
		switch (of->err) {

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
			ngx_log_error(level, r->connection->log, of->err,
				"%s \"%V\" failed", of->failed, name);
		}

		return rc;
	}

	if (!of->is_file) {

		if (ngx_close_file(of->fd) == NGX_FILE_ERROR) {
			ngx_log_error(NGX_LOG_ALERT, r->connection->log, ngx_errno,
				ngx_close_file_n " \"%V\" failed", name);
		}

		return NGX_HTTP_NOT_FOUND;
	}
	f->fd = of->fd;
	f->name = *name;
	f->directio = of->is_directio;
	f->log = r->connection->log;
	return NGX_OK;
}
static ngx_int_t mp4mux_open_file(mp4_file_t *f)
{
	ngx_http_core_loc_conf_t *clcf;
	ngx_open_file_info_t      of;
	ngx_int_t rc;

	if (f->moov.hdr)
		return NGX_OK; // Already open
	if (f->moov_rd_size)
		return NGX_AGAIN; // Still reading moov

	if (f->file_size) // File was opened, but not parsed yet
		return mp4_parse(f);


	clcf = ngx_http_get_module_loc_conf(f->req, ngx_http_core_module);
	ngx_memzero(&of, sizeof(of));
	of.directio = clcf->directio;
	
	if ((rc = mp4mux_do_open_file(&of, &f->file, clcf, f->req, &f->fname)) != NGX_OK)
		return rc;

	#if (NGX_HAVE_FILE_AIO)
	f->aio = clcf->aio;
	#endif

	// Use one-sector buffers while parsing atoms to minimize data copying
	// during relocation of moov atom
	f->rdbuf_size = SECTOR_SIZE;

	f->file_size = of.size;
	f->file_mtime = of.mtime;

	if (f->file_size < 10) {
		ngx_log_error(NGX_LOG_ERR, f->file.log, 0,
			"mp4mux: file \"%V\" is too small: %i", &f->fname, f->file_size);
		return NGX_HTTP_NOT_FOUND;
	}

	MP4MUX_INIT_LIST_HEAD(&f->moov.atoms);
	MP4MUX_INIT_LIST_HEAD(&f->rdbufs);
	MP4MUX_INIT_LIST_HEAD(&f->free_rdbufs);

	if ((f->cache_entry = mp4mux_cache_fetch(f))) {
		f->moov.hdr = f->cache_entry->hdr;
		f->do_copy = 1;
		return NGX_OK;
	}

	if (mp4mux_seek(f, 0) != NGX_OK)
		return NGX_HTTP_INTERNAL_SERVER_ERROR;

	return mp4_parse(f);
}
static ngx_int_t mp4mux_seek(mp4_file_t *f, size_t offs) {
	mp4mux_list_t *entry;
	mp4_buf_t *buf;
	size_t newoffs = offs & ~(SECTOR_SIZE-1);

	f->offs = offs;
	f->offs_restart = offs;

	ngx_log_debug2(NGX_LOG_DEBUG_HTTP, f->file.log, 0,
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
	ngx_log_debug1(NGX_LOG_DEBUG_HTTP, f->file.log, 0,
			"first buf offs: %i", buf->offs);
	if (offs > buf->offs) {
		// middle
		if (f->rdbuf_cur != NULL && offs >= f->rdbuf_cur->offs)
			buf = f->rdbuf_cur;
		while (offs >= buf->offs_end) {
			ngx_log_debug1(NGX_LOG_DEBUG_HTTP, f->file.log, 0,
					"middle, offs_end = %i", buf->offs_end);
			buf = mp4mux_list_entry(buf->entry.next, mp4_buf_t, entry);
			if (&buf->entry == &f->rdbufs) {
				ngx_log_error(NGX_LOG_ERR, f->file.log, 0,
					"mp4mux_seek(): invalid buffers list");
				return NGX_ERROR;
			}
		}
	}
	if (offs < buf->offs) {
		ngx_log_debug(NGX_LOG_DEBUG_HTTP, f->file.log, 0,
				"before first", buf->offs);
		entry = &buf->entry;
		if (buf->offs - newoffs < f->rdbuf_size)
			buf = mp4mux_get_rdbuf_sz(f, buf->offs - newoffs, newoffs);
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
		ngx_log_error(NGX_LOG_ERR, f->file.log, 0,
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
			ngx_log_error(NGX_LOG_ERR, f->file.log, 0,
				"mp4mux_read(): tried to read beyond EOF file=%p offs=%z size=%z", f, f->offs, f->file_size);
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
static ngx_int_t mp4mux_read_chain(mp4_file_t *f, ngx_chain_t *out, ngx_chain_t **free, size_t size) {
	ngx_buf_t *b = out->buf;
	size_t newsiz = size;
	if (out == NULL) {
		ngx_log_error(NGX_LOG_ERR, f->file.log, 0,
			"mp4mux_read_chain(): out chain is null");
		return NGX_ERROR;
	}
	if (f->rdbuf_cur == NULL) {
		ngx_log_error(NGX_LOG_ERR, f->file.log, 0,
			"mp4mux_read_chain(): bad seek position");
		return NGX_ERROR;
	}
	if (!f->rdbuf_cur->aio_done)
		return NGX_AGAIN;
	b->start = f->rdbuf_cur->data + f->offs_buf;
	b->end = b->start + size;
	b->pos = b->start;
	b->in_file = 0;
	b->memory = 1;
	if (b->end > f->rdbuf_cur->data_end)
		newsiz = f->rdbuf_cur->data_end - b->start;
	f->offs += newsiz;
	f->offs_restart = f->offs;
	if (b->end < f->rdbuf_cur->data_end) {
		f->offs_buf += newsiz;
		b->last = b->end;
		return NGX_OK;
	}
	b->end = f->rdbuf_cur->data_end;
	b->last = b->end;
	// next buf
	if (f->rdbuf_cur->eof) {
		if (size == newsiz)
			return NGX_OK;
		else {
			ngx_log_error(NGX_LOG_ERR, f->file.log, 0,
				"mp4mux_read(): tried to read beyond EOF");
			return NGX_ERROR;
		}
	}
	f->rdbuf_cur = mp4mux_nextrdbuf(f);
	if (f->rdbuf_cur == NULL)
		return NGX_ERROR;
	f->offs_buf = 0;
	if (size == newsiz)
		return NGX_OK;
	out->next = ngx_chain_get_free_buf(f->req->pool, free);
	return mp4mux_read_chain(f, out->next, free, size - newsiz);
}
#if (NGX_HAVE_FILE_AIO)
static ngx_int_t mp4mux_readahead(mp4_file_t *f, ngx_int_t size) {
	bool_t have_incomplete = 0;
	mp4_buf_t *buf = f->rdbuf_cur;
	size_t offs;

	ngx_log_debug2(NGX_LOG_DEBUG_HTTP, f->file.log, 0,
			"mp4mux_readahead(%p, %i)", f, size);

	size -= buf->size-f->offs_buf;
	while (1) {
		ngx_log_debug2(NGX_LOG_DEBUG_HTTP, f->file.log, 0, "size=%i buf=%p", size, buf);
		if (!buf->aio_done) {
			ngx_log_debug1(NGX_LOG_DEBUG_HTTP, f->file.log, 0,
				"buf %p is still incomplete", buf);
			have_incomplete = 1;
		}
		if (size <= 0) break;
		offs = buf->offs_end;
		buf = mp4mux_list_entry(buf->entry.next, mp4_buf_t, entry);
		if (&buf->entry == &f->rdbufs || buf->offs > offs) {
			buf = mp4mux_preread(f);
			if (buf == NULL) {
				ngx_log_error(NGX_LOG_ERR, f->file.log, 0,
					"Preread failed!");
				return NGX_ERROR;
			}
		}
		size -= buf->size;
	}
	return have_incomplete ? NGX_AGAIN : NGX_OK;
}
#endif
static ngx_int_t mp4mux_read_moov(mp4_file_t *f, u_char *data, ssize_t size) {
	u_char *pd, *pd_end, *ps;
	ssize_t rc;

	ngx_log_debug3(NGX_LOG_DEBUG_HTTP, f->file.log, 0,
			"mp4mux_read_moov(): %p %i, %i", f, f->offs, size);

	pd = data;
	pd_end = pd + size;
	ps = f->rdbuf_cur->data+(f->offs_buf & ~(SECTOR_SIZE-1));
	do {
		size = f->rdbuf_cur->data_end - ps;
		if (pd + size > pd_end)
			size = pd_end - pd;
		ngx_log_debug3(NGX_LOG_DEBUG_HTTP, f->file.log, 0,
				"memcpy %p %p %i", pd, ps, size);
		ngx_memcpy(pd, ps, size);
		if (f->rdbuf_cur->eof)
			return NGX_OK;
		pd += size;
		f->offs = f->rdbuf_cur->offs_end;
		if (pd == pd_end || f->rdbuf_cur->entry.next == &f->rdbufs) break;
		f->rdbuf_cur = mp4mux_list_entry(f->rdbuf_cur->entry.next, mp4_buf_t, entry);
		ps = f->rdbuf_cur->data;
	} while (f->rdbuf_cur->offs == f->offs);
	size = pd_end - pd;
	if (size > 0) {
		#if (NGX_HAVE_FILE_AIO)
		if (f->aio) {
			if (mp4mux_aio_busy(f)) return NGX_AGAIN;
			rc = mp4mux_aio_read(f, pd, size, f->offs);
			if (rc == NGX_AGAIN) {
				if (f->offs + size > f->file_size)
					f->moov_rd_size = f->file_size - f->offs;
				else
					f->moov_rd_size = size;
			}
		} else
		#endif
			rc = ngx_read_file(&f->file, pd, size, f->offs);
	} else rc = NGX_OK;
	if (rc < 0)
		return rc;
	if (f->offs + size > f->file_size)
		size = f->file_size - f->offs;
	if (rc != size) {
		ngx_log_error(NGX_LOG_ERR, f->file.log, 0,
				"Unable to read moov in %V: read %i bytes, expected %i",
				&f->fname, rc, size);
		return NGX_ERROR;
	}

	return NGX_OK;
}
static ngx_int_t mp4mux_handle_write_rc(ngx_http_request_t *r, ngx_int_t rc) {
	ngx_http_core_loc_conf_t  *clcf;
	ngx_event_t *ev;
	if (rc == NGX_AGAIN) {
		ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
			"mp4mux: ngx_http_output_filter() returned NGX_AGAIN, setting handler");
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
		} else {
			ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
				"event is active");
		}
	} else {
		ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
			"mp4mux: ngx_http_output_filter() failed, rc = %i", rc);
	}
	return NGX_OK;
}
static ngx_int_t mp4_validate_init(mp4_file_t *f) {
	mp4_trak_t *t;
	t = &f->trak;
	if (f->moov.hdr->type != ATOM('m','o','o','v')) {
		ngx_log_error(NGX_LOG_ERR, f->file.log, 0,
			"mp4mux: \"%V\" invalid moov header", &f->fname);
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}
	if (mp4_parse_atom(f, &f->moov) != NGX_OK) {
		ngx_log_error(NGX_LOG_ERR, f->file.log, 0,
			"mp4mux: \"%V\" moov parsing failed", &f->fname);
		return NGX_HTTP_NOT_FOUND;
	}
	// Validate file
	if (!t->mvhd || !t->trak || !t->mdhd || !t->tkhd || !t->hdlr
			|| !t->stbl	|| !t->stsz || !t->stts || !t->stsc || !t->co) {
		ngx_log_error(NGX_LOG_ERR, f->file.log, 0,
			"mp4mux: \"%V\" is invalid", &f->fname);
		return NGX_HTTP_NOT_FOUND;
	}
	// Init parameters
	if (mp4_stsc_ptr_init(&f->stsc_ptr, t->stsc, be32toh(t->co->chunk_cnt), f->file.log) != NGX_OK)
		return NGX_HTTP_NOT_FOUND;
	if (mp4_stbl_ptr_init(&f->stts_ptr, &t->stts->hdr, f->file.log) != NGX_OK)
		return NGX_ERROR;
	switch (t->mdhd->version) {
	case 0:
		f->sample_max = be32toh(t->mdhd->duration);
		f->timescale  = be32toh(t->mdhd->timescale);
		break;
	case 1:
		f->sample_max = be64toh(((mp4_atom_mdhd_v1_t*)t->mdhd)->duration);
		f->timescale  = be32toh(((mp4_atom_mdhd_v1_t*)t->mdhd)->timescale);
		break;
	default:
		ngx_log_error(NGX_LOG_ERR, f->file.log, 0,
			"mp4mux: invalid mdhd version in \"%V\"", &f->fname);
		return NGX_HTTP_NOT_FOUND;
	}
	return NGX_OK;
}
static ngx_int_t mp4mux_send_response(ngx_http_mp4mux_ctx_t *ctx)
{
	ngx_http_request_t *r = ctx->req;
	ngx_http_mp4mux_conf_t* conf = ngx_http_get_module_loc_conf(r, ngx_http_mp4mux_module);
	ngx_int_t i, rc, rdbuf_size;
	ngx_table_elt_t *hdr;
	ngx_md5_t etag_md5;
	bool_t again = 0;
	bool_t flags[2];
	u_char md5_result[16];

	rdbuf_size = conf->rdbuf_size & ~(SECTOR_SIZE-1);
	if (rdbuf_size < 32768) rdbuf_size = 32768;

	for (i = 0; i < ctx->trak_cnt; i++) {
		rc = mp4mux_open_file(ctx->mp4_src[i]);
		if (rc == NGX_AGAIN) {
			again = 1;
		} else if (rc != NGX_OK)
			return rc;
	}
	if (again)
		return NGX_AGAIN;

	#if (NGX_HAVE_FILE_AIO)
	ctx->aio_handler = NULL;
	#endif

	for (i = 0; i < ctx->trak_cnt; i++) {
		if ((rc = mp4_validate_init(ctx->mp4_src[i])) != NGX_OK)
			return rc;
		ctx->mp4_src[i]->rdbuf_size = rdbuf_size;
	}

	// Calculate ETag
	if (!(hdr = ngx_list_push(&r->headers_out.headers)))
		return NGX_HTTP_INTERNAL_SERVER_ERROR;

	hdr->hash = 1;
	ngx_str_set(&hdr->key, "ETag");
	hdr->value.len = 34;
	if (!(hdr->value.data = ngx_palloc(r->pool, 34)))
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	
	ngx_md5_init(&etag_md5);
	ngx_md5_update(&etag_md5, &mp4mux_version, sizeof(mp4mux_version));
	ngx_md5_update(&etag_md5, &ctx->segment_ms, sizeof(ngx_int_t));
	ngx_md5_update(&etag_md5, &ctx->start, sizeof(ngx_int_t));
	ngx_md5_update(&etag_md5, &ctx->chunk_rate, sizeof(ngx_int_t));
	ngx_md5_update(&etag_md5, &ctx->fmt, sizeof(u_char));
	flags[0] = ctx->seg_align;
	flags[1] = ctx->move_meta;
	ngx_md5_update(&etag_md5, &flags, sizeof(flags));

	for (i = 0; i < ctx->trak_cnt; i++) {
		ngx_md5_update(&etag_md5, &ctx->mp4_src[i]->file_mtime, sizeof(time_t));
		ngx_md5_update(&etag_md5, &ctx->mp4_src[i]->file_size, sizeof(size_t));
	}
	ngx_md5_final(md5_result, &etag_md5);
	ngx_hex_dump(hdr->value.data + 1, md5_result, 16);
	hdr->value.data[0] = '"';
	hdr->value.data[33] = '"';
	r->headers_out.etag = hdr;

	// Call format-specific functions
	switch (ctx->fmt) {
	case FMT_MP4:          return mp4mux_send_mp4(ctx);
	case FMT_HLS_INDEX:    return mp4mux_hls_send_index(ctx);
	case FMT_HLS_SEGMENT:  return mp4mux_hls_send_segment(ctx);
	case FMT_DASH_MANIFEST:return mp4mux_dash_send_manifest(ctx);
	case FMT_DASH_INIT:    return mp4mux_dash_send_init(ctx);
	case FMT_DASH_SEGMENT: return mp4mux_dash_send_segment(ctx);
	}
	ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
		"mp4mux: Invalid fmt value");
	return NGX_HTTP_INTERNAL_SERVER_ERROR;
}
static off_t mp4_curchunk_offset(mp4_file_t *mp4) {
	return mp4->trak.co64 ?
		be64toh(mp4->trak.co->u.tbl64[mp4->stsc_ptr.chunk_no-1])
		: be32toh(mp4->trak.co->u.tbl[mp4->stsc_ptr.chunk_no-1]);
}
static void mp4mux_release_cache_item(mp4_file_t *f, ngx_pool_t *pool) {
	if (f->cache_entry) {
		ngx_log_debug3(NGX_LOG_DEBUG_ALLOC, f->file.log, 0,
			"mp4mux: release cache lock for %V, entry %p, lock=%i",
			&f->fname, f->cache_entry, f->cache_entry->lock);
		if (f->cache_entry->lock != MP4MUX_CACHE_LOADING)
			ngx_atomic_fetch_add(&f->cache_entry->lock, -1);
		f->cache_entry = NULL;
	} else if (pool) {
		if (f->moov.hdr) {
			ngx_pfree(pool, f->moov.hdr);
			f->moov.hdr = NULL;
		}
	}
}
static void mp4mux_release_cache(ngx_http_mp4mux_ctx_t *ctx, bool_t pfree) {
	ngx_int_t i;
	for (i = 0; i < ctx->trak_cnt; i++)
		mp4mux_release_cache_item(ctx->mp4_src[i], pfree ? ctx->req->pool : NULL);
}
static mp4_atom_t *mp4_alloc_atom(ngx_pool_t *pool, size_t data_size) {
	mp4_atom_t *a = ngx_palloc(pool, sizeof(mp4_atom_t) + data_size);
	if (!a) return NULL;
	MP4MUX_INIT_LIST_HEAD(&a->atoms);
	if (data_size) a->hdr = a->data;
	return a;
}
static ngx_int_t mp4_add_primitive_atom(mp4mux_list_t *list, void *data, ngx_pool_t *pool) {
	mp4_atom_t *a = mp4_alloc_atom(pool, 0);
	if (!a) return NGX_ERROR;
	a->hdr = data;
	mp4mux_list_add_tail(&a->entry, list);
	return NGX_OK;
}
static ngx_int_t mp4_add_simple_atom(mp4mux_list_t *list, void *data, ngx_pool_t *pool, uint32_t offs, uint32_t value) {
	mp4_atom_hdr_t *hdr = data;
	uint32_t size = htobe32(hdr->size);
	if (!(hdr = ngx_palloc(pool, size)))
		return NGX_ERROR;
	ngx_memcpy(hdr, data, size);
	hdr->u.data32[offs] = htobe32(value);
	return mp4_add_primitive_atom(list, hdr, pool);
}
static mp4_atom_t *mp4_add_container_atom(mp4mux_list_t *list, uint32_t type, ngx_pool_t *pool) {
	mp4_atom_t *a = mp4_alloc_atom(pool, sizeof(mp4_atom_hdr_t));
	if (!a) return NULL;
	a->hdr->type = type;
	mp4mux_list_add_tail(&a->entry, list);
	return a;
}
static ngx_table_elt_t *add_content_disp(ngx_http_request_t *r, ngx_int_t size) {
	ngx_table_elt_t *cd = ngx_list_push(&r->headers_out.headers);
	if (cd == NULL)
		return NULL;
	ngx_str_set(&cd->key, "Content-Disposition");
	cd->hash = r->header_hash;
	if (size && !(cd->value.data = ngx_pnalloc(r->pool, size)))
		return NULL;
	return cd;
}
static void mp4mux_dash_set_content_type(mp4_file_t *f) {
	switch (f->trak.hdlr->subtype)
	{
	case ATOM('v','i','d','e'):
		ngx_str_set(&f->req->headers_out.content_type, "video/mp4");
		break;
	case ATOM('s','o','u','n'):
		ngx_str_set(&f->req->headers_out.content_type, "audio/mp4");
		break;
	}
	f->req->headers_out.content_type_len = f->req->headers_out.content_type.len;
}
static ngx_int_t mp4mux_dash_send_init(ngx_http_mp4mux_ctx_t *ctx)
{
	ngx_http_request_t *r = ctx->req;
	ngx_table_elt_t *content_disp;
	mp4_file_t *f = ctx->mp4_src[0];
	atom_clone_depth acd = f->do_copy ? atom_clone_data : atom_clone_meta;
	mp4_atom_t *moov, *a;
	mp4_trak_t trak;
	ngx_chain_t *out;
	static uint32_t *st_atoms = (uint32_t*)"stszsttsstscstco";
	static uint32_t st_sizes[] = { 20, 16, 16, 16 };
	ngx_int_t i;

	MP4MUX_INIT_LIST_HEAD(&ctx->atoms_head);

	// ftyp, moov, mvex
	if (mp4_add_primitive_atom(&ctx->atoms_head, ftyp_dash, r->pool) != NGX_OK)
		return NGX_HTTP_INTERNAL_SERVER_ERROR;

	ngx_memzero(&trak, sizeof(trak));
	if (!(moov = mp4_clone_atom(&f->moov, &trak, acd, 1, r->pool)))
		return NGX_HTTP_INTERNAL_SERVER_ERROR;

	mp4mux_list_add_tail(&moov->entry, &ctx->atoms_head);

	if (mp4_add_simple_atom(&trak.trak->entry, mvex, r->pool, 3, ctx->dash_tkid) != NGX_OK)
		return NGX_HTTP_INTERNAL_SERVER_ERROR;

	trak.tkhd->track_id = htobe32(ctx->dash_tkid);

	// stbl
	if (!(trak.stbl = mp4_add_container_atom(&trak.minf->atoms, ATOM('s', 't', 'b', 'l'), r->pool)))
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	if (f->do_copy) {
		i = be32toh(f->trak.stsd->hdr.size);
		trak.stsd = ngx_palloc(r->pool, i);
		ngx_memcpy(trak.stsd, f->trak.stsd, i);
	} else
		trak.stsd = f->trak.stsd;
	if (mp4_add_primitive_atom(&trak.stbl->atoms, trak.stsd, r->pool) != NGX_OK)
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	for (i = 0; i < (ngx_int_t)(sizeof(st_sizes) / sizeof(st_sizes[0])); i++) {
		a = mp4_alloc_atom(r->pool, st_sizes[i]);
		a->hdr->type = st_atoms[i];
		a->hdr->size = htobe32(st_sizes[i]);
		ngx_memzero(a->hdr->u.data, st_sizes[i] - 8);
		mp4mux_list_add_tail(&a->entry, &trak.stbl->atoms);
	}
	// Output
	r->headers_out.status = NGX_HTTP_OK;
	mp4mux_dash_set_content_type(f);
	mp4mux_release_cache(ctx, 0);
	if (!(content_disp = add_content_disp(r, sizeof("inline; filename=\"init-.mp4\"") + intlen(ctx->dash_tkid))))
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	content_disp->value.len = ngx_sprintf(content_disp->value.data,
		"inline; filename=\"init-%i.mp4\"", ctx->dash_tkid) - content_disp->value.data;
	i = mp4_build_atoms(&ctx->atoms_head, r->connection->log);
	if (i < 0)
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	r->headers_out.content_length_n = i;

	i = ngx_http_send_header(r);
	if (i == NGX_ERROR || i > NGX_OK || r->header_only)
		return i;

	if (!(out = mp4_build_chain(ctx, &ctx->atoms_head)))
		return NGX_ERROR;

	return ngx_http_output_filter(r, out);
}
static ngx_int_t mp4mux_dash_send_segment(ngx_http_mp4mux_ctx_t *ctx)
{
	ngx_http_request_t *r = ctx->req;
	ngx_table_elt_t *content_disp;
	mp4_file_t *f = ctx->mp4_src[0];
	mp4_atom_t *moof, *traf, *mdat;
	ngx_chain_t *out = NULL, *last = NULL;
	mp4_atom_sidx_t *sidx;
	mp4_atom_trun_t *trun;
	mp4_stbl_ptr_t ctts_ptr, stts_save;
	ngx_int_t rc;
	uint32_t len, sample_start, frame_start, frame_count, frame_max = NGX_MAX_UINT32_VALUE;
	uint32_t *ptr;
	uint32_t pts_min, pts_end, pts;
	off_t offs_start, head_len;
	uint32_t keyframe_pts = NGX_MAX_UINT32_VALUE;
	const ngx_int_t sidx_size = sizeof(mp4_atom_sidx_t) + sizeof(mp4_sidx_entry_t);
	const ngx_int_t moof_pos = sizeof(styp) - 1 + sidx_size;

	MP4MUX_INIT_LIST_HEAD(&ctx->atoms_head);

	// styp, sidx
	if (mp4_add_primitive_atom(&ctx->atoms_head, styp, r->pool) != NGX_OK)
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	if (!(sidx = ngx_pcalloc(r->pool, sidx_size)))
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	sidx->hdr.size = htobe32(sidx_size);
	sidx->hdr.type = ATOM('s','i','d','x');
	sidx->entry_count = htobe16(1);
	sidx->ref_id = htobe32(ctx->dash_tkid);
	sidx->timescale = htobe32(f->timescale);
	if (mp4_add_primitive_atom(&ctx->atoms_head, sidx, r->pool) != NGX_OK)
		return NGX_HTTP_INTERNAL_SERVER_ERROR;

	// moof, traf
	if (!(moof = mp4_add_container_atom(&ctx->atoms_head, ATOM('m','o','o','f'), r->pool)))
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	if (mp4_add_simple_atom(&moof->atoms, mfhd, r->pool, 1, ctx->seg_no) != NGX_OK)
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	if (!(traf = mp4_add_container_atom(&moof->atoms, ATOM('t','r','a','f'), r->pool)))
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	if (mp4_add_simple_atom(&traf->atoms, tfhd, r->pool, 1, ctx->dash_tkid) != NGX_OK)
		return NGX_HTTP_INTERNAL_SERVER_ERROR;

	// Prepare
	ctts_ptr.value = 0; // default value for cases when ctts is not present
	if (f->trak.hdlr->subtype == ATOM('v','i','d','e') && mp4_init_video(f, &ctts_ptr) != NGX_OK)
		return NGX_HTTP_NOT_FOUND;
	if (!f->trak.stss)
		ctx->seg_align = 0; // Don't align audio segments for DASH
	if ((rc = mp4_move_to_segment(ctx, f, f->trak.ctts ? &ctts_ptr  : NULL)) != NGX_OK)
		return rc;
	if (f->eof)
		return NGX_HTTP_NOT_FOUND;

	if (mp4_add_simple_atom(&traf->atoms, tfdt, r->pool, 1, f->sample_no) != NGX_OK)
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	pts_min = f->sample_no + ctts_ptr.value;
	pts_end = pts_min + f->stts_ptr.value;

	sample_start = f->sample_no;
	offs_start = f->offs;
	frame_start = f->frame_no;

	// Calculate frame count
	stts_save = f->stts_ptr;
	if (ctx->seg_align) {
		ptr = f->stss_ptr;
		mp4_ff_samples(f, (int64_t)ctx->seg_no * ctx->segment_ms * f->timescale / 1000 - f->sample_no);
		mp4_stss_ff(f);
		if (f->next_keyframe < NGX_MAX_UINT32_VALUE)
			f->frame_no = f->next_keyframe;
		else
			do f->frame_no += f->stts_ptr.samp_left;
			while (mp4_stbl_ptr_advance_entry(&f->stts_ptr) == NGX_OK);
		frame_max = f->frame_no;
		f->stss_ptr = ptr;
		mp4_stss_upd(f);
	} else
		mp4_ff_samples(f, f->sample_max - f->sample_no);
	frame_count = f->frame_no - frame_start;
	// Restore values
	f->frame_no = frame_start;
	f->sample_no = sample_start;
	f->stts_ptr = stts_save;
	f->eof = 0;

	// Write trun
	len = sizeof(mp4_atom_trun_t) + (8 + (f->trak.stss ? 4 : 0) + (f->trak.ctts ? 4 : 0)) * frame_count;
	if (!(trun = ngx_palloc(r->pool, len)))
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	trun->hdr.size = htobe32(len);
	trun->hdr.type = ATOM('t','r','u','n');
	if (mp4_add_primitive_atom(&traf->atoms, trun, r->pool) != NGX_OK)
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	trun->frame_count = htobe32(frame_count);
	ngx_memzero(&trun->version, 4);
	trun->flags[2] = 1;
	trun->flags[1] = TRUN_F1_DURATION | TRUN_F1_SIZE | (f->trak.stss ? TRUN_F1_FLAGS : 0) | (f->trak.ctts ? TRUN_F1_CTTS : 0);
	ptr = trun->data;
	while (1) {
		*ptr++ = htobe32(f->stts_ptr.value);
		len = f->trak.stsz->tbl[f->frame_no];
		*ptr++ = len;
		f->offs += be32toh(len);
		pts = f->sample_no + ctts_ptr.value;
		if (f->trak.stss) {
			if (mp4_is_keyframe(f)) {
				*ptr++ = 0;
				if (keyframe_pts == NGX_MAX_UINT32_VALUE)
					keyframe_pts = pts;
			} else
				*ptr++ = htobe32(0x10000);
		}
		if (f->trak.ctts) {
			*ptr++ = htobe32(ctts_ptr.value);
			if (pts < pts_min)
				pts_min = pts;
			pts += f->stts_ptr.value;
			if (pts > pts_end)
				pts_end = pts;
		}
		if (mp4mux_nextframe(f) != NGX_OK)
			return NGX_HTTP_INTERNAL_SERVER_ERROR;
		if (f->eof || f->frame_no >= frame_max) break;
		if (f->trak.ctts && mp4_stbl_ptr_advance(&ctts_ptr) != NGX_OK) {
			ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
				"mp4mux: ctts is out of range");
			return NGX_HTTP_NOT_FOUND;
		}
	}

	if (f->trak.ctts) {
		// Calculate minimum pts of the next segment
		f->sample_max = pts_end;
		while (f->sample_no < f->sample_max) {
			if (mp4_stbl_ptr_advance(&f->stts_ptr) != NGX_OK) break;
			if (mp4_stbl_ptr_advance(&ctts_ptr) != NGX_OK) break;
			pts = f->sample_no + ctts_ptr.value;
			if (pts < pts_end)
				pts_end = pts;
			if (pts < f->sample_max)
				f->sample_max = pts;
			f->sample_no += f->stts_ptr.value;
		}
	} else
		pts_end = f->sample_no;

	ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
		"mp4mux_dash: seg=%i pts_min=%i pts_end=%i", ctx->seg_no, pts_min, pts_end);

	sidx->entries[0].duration = htobe32(pts_end - pts_min);
	sidx->earliest_pts = htobe32(pts_min);

	if (!f->trak.stss)
		keyframe_pts = pts_min;

	if (keyframe_pts == NGX_MAX_UINT32_VALUE)
		sidx->entries[0].sap_params = htobe32(SIDX_SAP_START | SIDX_SAP_TYPE6);
	else
		sidx->entries[0].sap_params = htobe32(((keyframe_pts == pts_min ? SIDX_SAP_START : 0)
			| SIDX_SAP_TYPE1) + keyframe_pts - pts_min);

	// mdat
	if (!(mdat = mp4_alloc_atom(ctx->req->pool, sizeof(mp4_atom_hdr_t))))
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	mdat->hdr->type = ATOM('m', 'd', 'a', 't');
	mdat->hdr->size = htobe32(sizeof(mp4_atom_hdr_t));
	mp4mux_list_add_tail(&mdat->entry, &ctx->atoms_head);
	if ((head_len = mp4_build_atoms(&ctx->atoms_head, r->connection->log)) < 0)
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	mdat->hdr->size = htobe32(sizeof(mp4_atom_hdr_t) + f->offs - offs_start);
	trun->mdat_offs = htobe32(head_len - moof_pos);
	sidx->entries[0].size = htobe32(f->offs - offs_start + be32toh(moof->hdr->size));

	// Output
	r->headers_out.status = NGX_HTTP_OK;
	mp4mux_dash_set_content_type(f);
	mp4mux_release_cache(ctx, 0);
	if (!(content_disp = add_content_disp(r, sizeof("inline; filename=\"seg--.m4s\"") + intlen(ctx->seg_no) + intlen(ctx->dash_tkid))))
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	content_disp->value.len = ngx_sprintf(content_disp->value.data,
		"inline; filename=\"seg-%i-%i.m4s\"",  + ctx->seg_no, ctx->dash_tkid) - content_disp->value.data;
	r->headers_out.content_length_n = head_len + f->offs - offs_start;

	rc = ngx_http_send_header(r);
	if (rc == NGX_ERROR || rc > NGX_OK || r->header_only)
		return rc;

	if (mp4_build_chain_ex(ctx, &ctx->atoms_head, &out, &last) != NGX_OK)
		return NGX_ERROR;

	if (!(last->next = ngx_alloc_chain_link(r->pool)))
		return NGX_ERROR;
	last = last->next;
	last->next = NULL;
	if (!(last->buf = ngx_calloc_buf(r->pool)))
		return NGX_ERROR;
	last->buf->file = &f->file;
	last->buf->in_file = 1;
	last->buf->file_pos = offs_start;
	last->buf->file_last = f->offs;
	last->buf->last_buf = 1;

	return ngx_http_output_filter(r, out);
}
static ngx_int_t mp4mux_send_mp4(ngx_http_mp4mux_ctx_t *ctx)
{
	off_t offs = 0;
	ngx_chain_t *out;
	mp4_atom_t *a, *moov;
	mp4_atom_stco_t *stco;
	ngx_int_t rc, i, j, n = ctx->trak_cnt;
	off_t len_head, len_mdat, len_tail;
	ngx_pool_t *hdr_pool;
	ngx_log_t *log = ctx->req->connection->log;
	ngx_http_request_t *r = ctx->req;
	bool_t co64;

	MP4MUX_INIT_LIST_HEAD(&ctx->atoms_head);
	MP4MUX_INIT_LIST_HEAD(&ctx->atoms_tail);

	if (ctx->move_meta) {
		// Place output header buffers into separate pool so we can free memory after they're sent
		hdr_pool = ngx_create_pool(4096, log);
		if (!hdr_pool)
			return NGX_HTTP_INTERNAL_SERVER_ERROR;
		ctx->hdr_pool = hdr_pool;
	} else
		hdr_pool = r->pool;

	if (!(ctx->traks = ngx_pcalloc(hdr_pool, sizeof(mp4_trak_t) * n)))
		return NGX_HTTP_INTERNAL_SERVER_ERROR;

	if (mp4_add_primitive_atom(&ctx->atoms_head, ftyp, hdr_pool) != NGX_OK)
		return NGX_HTTP_INTERNAL_SERVER_ERROR;

	// Copy moov from first file
	if (!(moov = mp4_clone_atom(&ctx->mp4_src[0]->moov, ctx->traks,
			ctx->mp4_src[0]->do_copy ? atom_clone_data : atom_clone_meta, 0, hdr_pool)))
		return NGX_HTTP_INTERNAL_SERVER_ERROR;

	mp4mux_list_add_tail(&moov->entry, ctx->move_meta ? &ctx->atoms_head : &ctx->atoms_tail);

	for (i = 1; i < n; i++) {
		// Set movie duration to the longest track duration
		if ((uint64_t)be32toh(ctx->mp4_src[i]->trak.mvhd->duration) * be32toh(ctx->traks->mvhd->timescale) >
			(uint64_t)be32toh(ctx->traks->mvhd->duration) * be32toh(ctx->mp4_src[i]->trak.mvhd->timescale) ) {
			ctx->traks->mvhd->duration = ctx->mp4_src[i]->trak.mvhd->duration;
			ctx->traks->mvhd->timescale = ctx->mp4_src[i]->trak.mvhd->timescale;
		}
		// Copy trak atom to output mp4
		if (!(a = mp4_clone_atom(ctx->mp4_src[i]->trak.trak, ctx->traks + i,
				ctx->mp4_src[i]->do_copy ? atom_clone_data : atom_clone_meta, 0, hdr_pool)))
			return NGX_HTTP_INTERNAL_SERVER_ERROR;
		mp4mux_list_add_tail(&a->entry, &moov->atoms);
	}

	if (ctx->start) {
		if (ctx->start * be32toh(ctx->traks->mvhd->timescale) / 1000 >= be32toh(ctx->traks->mvhd->duration))
			ctx->traks->mvhd->duration = 0;
		else
			ctx->traks->mvhd->duration = htobe32(be32toh(ctx->traks->mvhd->duration) -
				ctx->start * be32toh(ctx->traks->mvhd->timescale) / 1000);
	}

	for (i = 0; i < n; i++) {
		if (mp4_tkhd_update(ctx->traks + i, i + 1, ctx->start, be32toh(ctx->mp4_src[i]->trak.mvhd->timescale), be32toh(ctx->traks->mvhd->timescale)))
			return NGX_HTTP_INTERNAL_SERVER_ERROR;

		/*if (ctx->start && mp4_adjust_pos(ctx->traks + i, ctx->start))
			return NGX_HTTP_INTERNAL_SERVER_ERROR;*/

		offs += ctx->mp4_src[i]->file_size;
	}

	ctx->traks->mvhd->next_track_id = htobe32(n + 1);

	co64 = offs > 0xfff00000l;

	ngx_log_debug3(NGX_LOG_DEBUG_HTTP, log, 0,
		"total_mdat: %O %i %i", offs, co64, sizeof(len_mdat));

	len_mdat = mp4_alloc_chunks(ctx, co64);
	if (len_mdat < 0)
		return NGX_HTTP_INTERNAL_SERVER_ERROR;

	len_head = mp4_build_atoms(&ctx->atoms_head, log);
	if (len_head < 0)
		return NGX_HTTP_INTERNAL_SERVER_ERROR;

	len_tail = mp4_build_atoms(&ctx->atoms_tail, log);
	if (len_tail < 0)
		return NGX_HTTP_INTERNAL_SERVER_ERROR;

	ngx_log_debug3(NGX_LOG_DEBUG_HTTP, log, 0,
		"head=%O mdat=%O tail=%O", len_head, len_mdat, len_tail);

	len_head += (co64 ? 16 : 8);
	for (i = 0; i < ctx->trak_cnt; i++) {
		stco = ctx->traks[i].co;
		rc = be32toh(stco->chunk_cnt);
		for (j = 0; j < rc; j++)
			if (co64)
				stco->u.tbl64[j] = htobe64(stco->u.tbl64[j]+len_head);
			else
				stco->u.tbl[j] = htobe32(stco->u.tbl[j]+len_head);
	}

	// Add mdat
	if (!(a = mp4_alloc_atom(ctx->req->pool, sizeof(mp4_atom_hdr_t) + co64 ? 8 : 0)))
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	a->hdr->type = ATOM('m', 'd', 'a', 't');
	if (co64) {
		a->hdr->size = htobe32(1);
		a->hdr->u.data64[0] = htobe64(sizeof(mp4_atom_hdr_t) + 8 + len_mdat);
	} else
		a->hdr->size = htobe32(sizeof(mp4_atom_hdr_t) + len_mdat);

	mp4mux_list_add_tail(&a->entry, &ctx->atoms_head);

	for (i = 0; i < n; i++)
		 ctx->mp4_src[i]->offs = mp4_curchunk_offset(ctx->mp4_src[i]);

	mp4mux_release_cache(ctx, 0);

	r->root_tested = !r->error_page;

	log->action = "sending mp4mux to client";

	r->headers_out.status = NGX_HTTP_OK;
	r->headers_out.content_length_n = len_head + len_mdat + len_tail;
	//r->headers_out.last_modified_time = ;
	ngx_str_set(&r->headers_out.content_type, "video/mp4");
	r->headers_out.content_type_len = r->headers_out.content_type.len;

	rc = ngx_http_send_header(r);
	if (rc == NGX_ERROR || rc > NGX_OK || r->header_only)
		return rc;

	for (i = 0; i < n; i++)
		if (ctx->mp4_src[i]->file.directio) {
			if (mp4mux_seek(ctx->mp4_src[i], ctx->mp4_src[i]->offs) != NGX_OK)
				return NGX_HTTP_INTERNAL_SERVER_ERROR;
		} else
			ctx->mp4_src[i]->offs_buf = NGX_MAX_INT_T_VALUE;

	out = mp4_build_chain(ctx, &ctx->atoms_head);
	if (!out)
		return NGX_HTTP_INTERNAL_SERVER_ERROR;

	rc = ngx_http_output_filter(r, out);

	#if nginx_version > 1001000
	ngx_chain_update_chains(r->pool, &ctx->free, &ctx->busy, &out, &ngx_http_mp4mux_module);
	#else
	ngx_chain_update_chains(&ctx->free, &ctx->busy, &out, &ngx_http_mp4mux_module);
	#endif

	ctx->chain_last = ctx->busy;
	if (ctx->chain_last)
		while (ctx->chain_last->next)
			ctx->chain_last = ctx->chain_last->next;

	ngx_log_debug1(NGX_LOG_DEBUG_HTTP, log, 0,
		"http_mp4mux rc=%i", rc);

	#if (NGX_HAVE_FILE_AIO)
	for (i = 0; i < n; i++) // Install aio handler if both aio and directio enabled
		if (ctx->mp4_src[i]->aio && ctx->mp4_src[i]->file.directio) {
			ctx->aio_handler = mp4mux_write;
			break;
		}
	#endif

	if (rc != NGX_OK) {
		if (mp4mux_handle_write_rc(r, rc) != NGX_OK)
			return NGX_ERROR;
		return rc;
	}
	return mp4mux_write(ctx);
}
static void mp4mux_cleanup(void *data)
{
	ngx_http_mp4mux_ctx_t *ctx = data;

	if (ctx->hdr_pool) {
		ngx_destroy_pool(ctx->hdr_pool);
		ctx->hdr_pool = NULL;
	}
	mp4mux_release_cache(ctx, 0);
	ctx->req->done = 1;
}
static ngx_int_t mp4mux_hls_get_baseuri(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data)
{
	u_char *match, *match_end;

	v->valid = 1;
	v->no_cacheable = 0;
	v->not_found = 0;
	v->data = ngx_palloc(r->pool, r->unparsed_uri.len);
	v->len = r->unparsed_uri.len;
	if (!v->data)
		return NGX_ERROR;
	ngx_memcpy(v->data, r->unparsed_uri.data, v->len);

	// Cut out fmt parameter from URI
	match = ngx_strnstr(v->data, "fmt=hls/index.m3u8", v->len);
	match_end = match + sizeof("fmt=hls/index.m3u8") - 1;
	if (match > v->data) {
		if (match[-1] == '&') {
			match--;
		} else if (match_end < (v->data + v->len) && *match_end == '&')
			match_end++;
		ngx_memcpy(match, match_end, v->data + v->len - match_end);
		v->len -= match_end - match;
	}
	return NGX_OK;
}
static ngx_int_t mp4mux_get_mp4_filename(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data)
{
	ngx_http_mp4mux_ctx_t *ctx = ngx_http_get_module_ctx(r, ngx_http_mp4mux_module);
	mp4_file_t *f;

	if (ctx == NULL) {
		v->not_found = 1;
		return NGX_OK;
	}

	v->valid = 1;
	v->no_cacheable = 1;
	v->not_found = 0;

	f = ctx->mp4_src[ctx->cur_trak];
	v->len = f->basename.len;
	v->data = f->basename.data;

	return NGX_OK;
}
static ngx_int_t mp4mux_longest_track(ngx_http_mp4mux_ctx_t *ctx) {
	ngx_int_t longest_track = 0, len, i;
	for (i = 0; ctx->mp4_src[i]; i++) {
		len = (int64_t)ctx->mp4_src[i]->sample_max * 1000 / ctx->mp4_src[i]->timescale;
		if (len > longest_track)
			longest_track = len;
	}
	return longest_track;
}
static ngx_int_t mp4_nextseg(ngx_http_mp4mux_ctx_t *ctx, mp4_file_t *f) {
	uint32_t spos;
	spos = f->sample_no;
	mp4_ff_samples(f, (uint64_t)ctx->segment_ms * ++ctx->seg_no * f->timescale / 1000 - spos);
	if (f->sample_no == spos)
		return 0;
	mp4_stss_ff(f);
	mp4_stss_align(f);
	return f->sample_no - spos;
}
static ngx_int_t mp4mux_hls_send_index(ngx_http_mp4mux_ctx_t *ctx)
{
	ngx_http_mp4mux_conf_t *conf;
	ngx_http_request_t *r = ctx->req;
	ngx_table_elt_t *content_disp;
	ngx_int_t rc, i, n;
	ngx_uint_t len, rem;
	mp4_file_t *f = NULL;
	ngx_int_t longest_track = 0;
	ngx_str_t prefix;
	ngx_buf_t *buf;
	ngx_chain_t out;

	conf = ngx_http_get_module_loc_conf(r, ngx_http_mp4mux_module);

	if (!ctx->seg_align)
		mp4mux_release_cache(ctx, 1);

	if (conf->hp_lengths == NULL) {
		prefix.data = conf->hls_prefix.data;
		prefix.len = conf->hls_prefix.len;
	} else {
		if (ngx_http_script_run(r, &prefix, conf->hp_lengths->elts, 0, conf->hp_values->elts) == NULL)
		{
			ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
				"mp4mux: failed to get m3u8 url prefix.");
			return NGX_HTTP_INTERNAL_SERVER_ERROR;
		}
	}

	longest_track = mp4mux_longest_track(ctx);
	n = longest_track / ctx->segment_ms;

	// Allocate buffer
	len = sizeof(m3u8_header) + sizeof(m3u8_footer) + NGX_INT_T_LEN +
		(prefix.len + sizeof(m3u8_entry) + intlen(n) + intlen(ctx->segment_ms)-3) * (n+1);
	if (!(buf = ngx_create_temp_buf(r->pool, len)))
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	buf->last_buf = 1;

	// Write m3u8 body
	len = ctx->segment_ms / 1000;
	rem = ctx->segment_ms % 1000;
	ngx_memcpy(buf->pos, m3u8_header, sizeof(m3u8_header) - 1);
	buf->last = ngx_sprintf(buf->pos + sizeof(m3u8_header) - 1, "%i\n", len);

	if (ctx->seg_align)
		for (i = 0; i < ctx->trak_cnt; i++) {
			if (!ctx->mp4_src[i]->trak.stss)
				continue;
			if (!f)
				f = ctx->mp4_src[i];
			else {
				ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
					"mp4mux: only one video track is supported with seg_align on");
				return NGX_HTTP_NOT_FOUND;
			}
		}
	if (f) {
		mp4_stss_init(f);
		while (!f->eof) {
			rc = mp4_nextseg(ctx, f);
			if (!rc) continue;
			len = (uint64_t)rc * 1000 / f->timescale;
			buf->last = ngx_sprintf(buf->last, m3u8_entry, len / 1000, len % 1000, &prefix, ctx->seg_no);
		}
	} else {
		for (i = 1; i <= n; i++)
			buf->last = ngx_sprintf(buf->last, m3u8_entry, len, rem, &prefix, i);

		len = longest_track % ctx->segment_ms;
		if (len)
			buf->last = ngx_sprintf(buf->last, m3u8_entry, len / 1000, len % 1000, &prefix, i);
	}
	if (ctx->seg_align)
		mp4mux_release_cache(ctx, 1);
	ngx_memcpy(buf->last, m3u8_footer, sizeof(m3u8_footer) - 1);
	buf->last += sizeof(m3u8_footer) - 1;

	// Output headers and data
	r->headers_out.content_length_n = buf->last - buf->pos;

	r->headers_out.status = NGX_HTTP_OK;
	ngx_str_set(&r->headers_out.content_type, "application/vnd.apple.mpegurl");
	r->headers_out.content_type_len = r->headers_out.content_type.len;
	if (!(content_disp = add_content_disp(r, 0)))
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	ngx_str_set(&content_disp->value, "inline; filename=\"index.m3u8\"");

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
static void dash_write_segm(ngx_buf_t *buf, ngx_int_t len, ngx_int_t segment_ms, ngx_str_t *prefix) {
	ngx_int_t rem;
	buf->last = ngx_sprintf(buf->last, dash_mpd_segm, prefix, prefix);
	if (len > segment_ms)
		buf->last = ngx_sprintf(buf->last, dash_mpd_tl_r,
			segment_ms, len / segment_ms - 1);
	rem = len % segment_ms;
	if (rem)
		buf->last = ngx_sprintf(buf->last, dash_mpd_tl, rem);
	buf->last = ngx_sprintf(buf->last, dash_mpd_segm_tail);
}
static uint64_t gcd(uint64_t u, uint64_t v) {
    if (u == v)
        return u;
    if (u == 0)
        return v;
    if (v == 0)
        return u;
    if ((u & 1) == 0) {
        if (v & 1)
            return gcd(u >> 1, v);
        else
            return gcd(u >> 1, v >> 1) << 1;
    }
    if ((v & 1) == 0)
        return gcd(u, v >> 1);
    if (u > v)
        return gcd((u - v) >> 1, v);
    return gcd((v - u) >> 1, u);
}
typedef struct {
	mp4_file_t *mp4[MAX_FILE];
	ngx_str_t lang;
	u_char av;
	u_char n;
} mp4mux_filegrp_t;
static ngx_int_t mp4mux_parse_filelist(ngx_http_request_t *r, mp4mux_manifest_ctx_t *mctx) {
	mp4mux_filegrp_t *fg;
	ngx_open_file_info_t of;
	ngx_file_t f;
	ngx_http_core_loc_conf_t  *clcf;
	ngx_int_t rc;
	u_char *buf, *end;
	mp4_file_t *mp4;
	ngx_int_t rootlen;
	
	clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
	ngx_memzero(&of, sizeof(of));
	ngx_memzero(&f, sizeof(f));
	of.directio = NGX_OPEN_FILE_DIRECTIO_OFF;
	if ((rc = mp4mux_do_open_file(&of, &f, clcf, r, &mctx->lst_file)) != NGX_OK)
		return rc;
	if (of.size > MAX_LIST_SIZE) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
			"mp4mux: file list \"%V\" is too big: %O", &mctx->lst_file, of.size);
		return NGX_HTTP_NOT_FOUND;
	}
	end = mctx->lst_file.data + mctx->lst_file.len - 1;
	while (end >= mctx->lst_file.data && *end != '/') end--;
	if (end < mctx->lst_file.data + mctx->path_len - 1 || end < mctx->lst_file.data) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
			"mp4mux: bad file list path: %V", &mctx->lst_file);
		return NGX_HTTP_NOT_FOUND;
	}
	rootlen = end - mctx->lst_file.data + 1;
	buf = ngx_pnalloc(r->pool, of.size);
	end = buf + of.size;
	if (ngx_read_file(&f, buf, of.size, 0) != of.size) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
			"mp4mux: error reading file list \"%V\"", &mctx->lst_file);
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}
	if (!(mctx->list = ngx_list_create(r->pool, 8, sizeof(mp4mux_filegrp_t))))
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	while (buf < end) {
		switch (*buf) {
		case '\n':
			buf++;
			continue;
		case '#':
			while (++buf < end && *buf != '\n');
			buf++;
			continue;
		case 'a':
		case 'v':
			if (!(fg = ngx_list_push(mctx->list)))
				return NGX_HTTP_INTERNAL_SERVER_ERROR;
			fg->av = *buf;
			fg->n = 0;
			buf++;
			ngx_memzero(&fg->lang, sizeof(ngx_str_t));
			if (buf >= end) continue;
			if (*buf == '\n') {
				buf++;
				break;
			}
			if (*buf == ':') {
				fg->lang.data = ++buf;
				while (buf < end && *buf != '\n')
					buf++;
				fg->lang.len = buf++ - fg->lang.data;
			}
			break;
		default:
			ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
				"mp4mux: parse error in file list \"%V\": invalid media type '%c'", &mctx->lst_file, *buf);
			return NGX_HTTP_NOT_FOUND;
		}
		if (buf >= end) break;
		while (buf < end && *buf != '\n') {
			if (*buf == '#') {
				while (++buf < end && *buf != '\n');
				buf++;
				continue;
			}
			if (fg->n >= MAX_FILE) {
				ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
					"mp4mux: too many files in list \"%V\"", &mctx->lst_file);
				return NGX_HTTP_NOT_FOUND;
			}
			if (!(mp4 = ngx_pcalloc(r->pool, sizeof(mp4_file_t))))
				return NGX_HTTP_INTERNAL_SERVER_ERROR;
			fg->mp4[fg->n++] = mp4;
			mp4->req = r;
			mp4->basename.data = buf;
			while (++buf < end && *buf != '\n');
			mp4->basename.len = buf++ - mp4->basename.data;
			mp4->fname.len = rootlen + mp4->basename.len;
			if (!(mp4->fname.data = ngx_pnalloc(r->pool, mp4->fname.len + 1)))
				return NGX_HTTP_INTERNAL_SERVER_ERROR;
			ngx_memcpy(mp4->fname.data, mctx->lst_file.data, rootlen);
			ngx_memcpy(mp4->fname.data + rootlen, mp4->basename.data, mp4->basename.len);
			mp4->fname.data[mp4->fname.len] = 0;
			mp4->basename.data = mp4->fname.data + mctx->path_len;
			mp4->basename.len = mp4->fname.len - mctx->path_len;
		}
	}
	return NGX_OK;
}
static ngx_int_t mp4mux_hls_send_master(ngx_http_mp4mux_ctx_t *ctx)
{
	ngx_http_mp4mux_conf_t *conf;
	ngx_http_request_t *r = ctx->req;
	mp4mux_manifest_ctx_t *mctx = ctx->mctx;
	mp4_file_t *f;
	ngx_table_elt_t *content_disp;
	ngx_int_t rc, j, content_len = sizeof(m3u8_master_header) + sizeof(m3u8_footer), len = 0;
	ngx_str_t *urls;
	ngx_uint_t i, trak_id = 0;
	mp4_atom_avcC_t *avcc;
	ngx_chain_t out;
	ngx_list_part_t *part;
	mp4mux_filegrp_t *fg;
	bool_t again = 0;
	
	part = &mctx->list->part;
	fg = part->elts;
 	for (i = 0;; i++) {
 		if (i >= part->nelts) {
			if (part->next == NULL)
				break;
 			part = part->next;
			fg = part->elts;
			i = 0;
		}
		for (j = 0; j < fg[i].n; j++) {
			rc = mp4mux_open_file(fg[i].mp4[j]);
			if (rc == NGX_AGAIN)
				again = 1;
			else if (rc != NGX_OK)
				return rc;
			len++;
		}
	}
	if (again)
		return NGX_AGAIN;
	#if (NGX_HAVE_FILE_AIO)
	ctx->aio_handler = NULL;
	#endif

	conf = ngx_http_get_module_loc_conf(r, ngx_http_mp4mux_module);
	urls = ngx_palloc(r->pool, sizeof(ngx_str_t) * len);
	len = 0;
	part = &mctx->list->part;
	fg = part->elts;
 	for (i = 0;; i++) {
 		if (i >= part->nelts) {
			if (part->next == NULL)
				break;
 			part = part->next;
			fg = part->elts;
			i = 0;
		}
		for (j = 0; j < fg[i].n; j++) {
			f = fg[i].mp4[j];
			ctx->mp4_src[0] = f;
			if (!conf->mp_lengths || ngx_http_script_run(r, urls + trak_id, conf->mp_lengths->elts, 0, conf->mp_values->elts) == NULL) {
				ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
					"mp4mux: failed to run m3u8 entry script.");
				return NGX_HTTP_INTERNAL_SERVER_ERROR;
			}
			if ((rc = mp4_validate_init(f)) != NGX_OK)
				return rc;
			rc = (uint64_t)f->sample_max * 1000 / f->timescale;
			if (rc > len)
				len = rc;
			switch (fg[i].av) {
				case 'v': content_len += sizeof(m3u8_master_video) + 5; break;
				case 'a': content_len += sizeof(m3u8_master_audio) + fg[i].lang.len * 2; break;
			}
			content_len += urls[trak_id].len;
			trak_id++;
		}
	}

	if (!(out.buf = ngx_create_temp_buf(r->pool, content_len)))
		return NGX_HTTP_INTERNAL_SERVER_ERROR;

	out.next = NULL;
	out.buf->last_buf = 1;
	
	ngx_memcpy(out.buf->start, m3u8_master_header, sizeof(m3u8_master_header) - 1);
	out.buf->last = out.buf->start + sizeof(m3u8_master_header) - 1;

	trak_id = 0;
	part = &mctx->list->part;
	fg = part->elts;
	for (i = 0;; i++) {
 		if (i >= part->nelts) {
			if (part->next == NULL)
				break;
 			part = part->next;
			fg = part->elts;
			i = 0;
		}
		switch (fg[i].av) {
		case 'v':
			for (j = 0; j < fg[i].n; j++) {
				f = fg[i].mp4[j];
				if (f->sample_max == 0)
					continue; // avoid division by zero
				avcc = &f->trak.stsd->entry.avc1.avcC;
				out.buf->last = ngx_sprintf(out.buf->last, m3u8_master_video,
					(ngx_int_t)((uint64_t)f->file_size * 8 * f->timescale / f->sample_max),
					avcc->prof_ind, avcc->prof_comp, avcc->level,
					urls + trak_id++);
				mp4mux_release_cache_item(f, r->pool);
			}
			break;
		case 'a':
			for (j = 0; j < fg[i].n; j++) {
				f = fg[i].mp4[j];
				out.buf->last = ngx_sprintf(out.buf->last, m3u8_master_audio,
					&fg[i].lang, &fg[i].lang, urls + trak_id++);
				mp4mux_release_cache_item(f, r->pool);
			}
			break;
		}
	}
	ngx_memcpy(out.buf->last, m3u8_footer, sizeof(m3u8_footer) - 1);
	out.buf->last += sizeof(m3u8_footer) - 1;
	
	// Output headers and data
	r->headers_out.content_length_n = out.buf->last - out.buf->start;

	r->headers_out.status = NGX_HTTP_OK;
	ngx_str_set(&r->headers_out.content_type, "application/vnd.apple.mpegurl");
	r->headers_out.content_type_len = r->headers_out.content_type.len;
	if (!(content_disp = add_content_disp(r, 0)))
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	ngx_str_set(&content_disp->value, "inline; filename=\"master.m3u8\"");

	rc = ngx_http_send_header(r);
	if (rc == NGX_ERROR || rc > NGX_OK || r->header_only)
		return rc;

	rc = ngx_http_output_filter(r, &out);
	if (rc != NGX_OK)
		return rc;
	return NGX_OK;
}
static ngx_int_t mp4mux_dash_send_complex_manifest(ngx_http_mp4mux_ctx_t *ctx)
{
	ngx_http_mp4mux_conf_t *conf;
	ngx_http_request_t *r = ctx->req;
	mp4mux_manifest_ctx_t *mctx = ctx->mctx;
	mp4_file_t *f;
	mp4a_audio_desc ad[MAX_FILE];
	ngx_table_elt_t *content_disp;
	ngx_int_t rc, j, content_len, len = 0;
	ngx_uint_t i;
	double maxfr, dtmp;
	uint16_t maxw, maxh, itmp;
	uint64_t frate_num, frate_den, div;
	mp4_atom_avcC_t *avcc;
	ngx_chain_t out, *o;
	ngx_list_part_t *part;
	mp4mux_filegrp_t *fg;
	bool_t again = 0;
	u_char url_data[MAX_URLLEN], *url_pos, *url_end = url_data + MAX_URLLEN;
	ngx_str_t url;
	
	part = &mctx->list->part;
	fg = part->elts;
 	for (i = 0;; i++) {
 		if (i >= part->nelts) {
			if (part->next == NULL)
				break;
 			part = part->next;
			fg = part->elts;
			i = 0;
		}
		for (j = 0; j < fg[i].n; j++) {
			rc = mp4mux_open_file(fg[i].mp4[j]);
			if (rc == NGX_AGAIN)
				again = 1;
			else if (rc != NGX_OK)
				return rc;
		}
	}
	if (again)
		return NGX_AGAIN;
	#if (NGX_HAVE_FILE_AIO)
	ctx->aio_handler = NULL;
	#endif

	part = &mctx->list->part;
	fg = part->elts;
 	for (i = 0;; i++) {
 		if (i >= part->nelts) {
			if (part->next == NULL)
				break;
 			part = part->next;
			fg = part->elts;
			i = 0;
		}
		for (j = 0; j < fg[i].n; j++) {
			f = fg[i].mp4[j];
			if ((rc = mp4_validate_init(f)) != NGX_OK)
				return rc;
			rc = (uint64_t)f->sample_max * 1000 / f->timescale;
			if (rc > len)
				len = rc;
		}
	}

	conf = ngx_http_get_module_loc_conf(r, ngx_http_mp4mux_module);

	if (!(out.buf = ngx_create_temp_buf(r->pool, sizeof(dash_mpd_header)+200)))
		return NGX_HTTP_INTERNAL_SERVER_ERROR;

	out.buf->last = ngx_sprintf(out.buf->last, dash_mpd_header, len / 1000, len % 1000, conf->segment_ms/1000);
	content_len = out.buf->last - out.buf->start;

	o = &out;
	#if (NGX_SSL)
	if (r->connection->ssl) {
		ngx_memcpy(url_data, "https://", 8);
		url_pos = url_data + 8;
	} else
	#endif
	{
		ngx_memcpy(url_data, "http://", 7);
		url_pos = url_data + 7;
	}
	if (!r->headers_in.host || url_pos + r->headers_in.host->value.len >= url_end)
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	ngx_memcpy(url_pos, r->headers_in.host->value.data, r->headers_in.host->value.len);
	url_pos += r->headers_in.host->value.len;
	if (url_pos + r->uri.len >= url_end)
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	ngx_memcpy(url_pos, r->uri.data, r->uri.len);
	url_pos += r->uri.len;
	*url_pos++ = '?';
	if (ctx->seg_align_url) {
		if (url_pos + 16 >= url_end)
			return NGX_HTTP_INTERNAL_SERVER_ERROR;
		url_pos = ngx_sprintf(url_pos, "seg_align=%uD&amp;", ctx->seg_align);
	}

	part = &mctx->list->part;
	fg = part->elts;
	for (i = 0;; i++) {
 		if (i >= part->nelts) {
			if (part->next == NULL)
				break;
 			part = part->next;
			fg = part->elts;
			i = 0;
		}
		url.data = url_pos;
		if (!(o->next = ngx_alloc_chain_link(r->pool)))
			return NGX_HTTP_INTERNAL_SERVER_ERROR;
		o = o->next;
		ctx->cur_trak++;
		len = 0;
		for (j = 0; j < fg[i].n; j++) {
			f = fg[i].mp4[j];
			if (url_data + f->basename.len + 25 > url_end) {
				ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
					"mp4mux: url too long in filelist %V, track %i", &mctx->lst_file, ctx->cur_trak);
				return NGX_HTTP_NOT_FOUND;
			}
			url.data = ngx_sprintf(url.data, "file%i=%V&amp;", j, &f->basename);
			rc = (int64_t)f->sample_max * 1000 / f->timescale;
			if (rc > len)
				len = rc;
		}
		ngx_memcpy(url.data, "fmt=dash/", 9);
		url.data += 9;
		url.len = url.data - url_data;
		url.data = url_data;
		switch (fg[i].av) {
		case 'v':
			maxw = 0;
			maxh = 0;
			maxfr = 0;
			frate_num = 0;
			frate_den = 1;
			for (j = 0; j < fg[i].n; j++) {
				f = fg[i].mp4[j];
				if (f->trak.hdlr->subtype != ATOM('v','i','d','e')) {
					ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
						"mp4mux: wrong av type for file %V", &f->fname);
					return NGX_HTTP_NOT_FOUND;
				}
				if (mp4_validate_stsd_video(r->connection->log, f->trak.stsd) != NGX_OK)
					return NGX_HTTP_NOT_FOUND;
				itmp = be16toh(f->trak.stsd->entry.avc1.width);
				if (itmp > maxw) maxw = itmp;
				itmp = be16toh(f->trak.stsd->entry.avc1.height);
				if (itmp > maxh ) maxh = itmp;
				dtmp = (double)be32toh(f->trak.stsz->sample_cnt) * f->timescale / f->sample_max;
				if (dtmp > maxfr) {
					maxfr = dtmp;
					frate_num = (uint64_t)be32toh(f->trak.stsz->sample_cnt) * f->timescale;
					frate_den = f->sample_max;
				}
			}
			div = gcd(frate_num, frate_den);
			frate_num /= div;
			frate_den /= div;
			rc = sizeof(dash_mpd_adapt_video) + sizeof(dash_mpd_segm) + sizeof(dash_mpd_segm_tail) + sizeof(dash_mpd_tl_r) + sizeof(dash_mpd_tl)
				+ sizeof(dash_mpd_repr_video) * fg[i].n + sizeof(dash_mpd_adapt_tail) + url.len * 2 + 500;
			if (!(o->buf = ngx_create_temp_buf(r->pool, rc)))
				return NGX_HTTP_INTERNAL_SERVER_ERROR;
			o->buf->last = ngx_sprintf(o->buf->last, dash_mpd_adapt_video,
				ctx->cur_trak, maxw, maxh, frate_num, frate_den);
			dash_write_segm(o->buf, len, conf->segment_ms, &url);
			for (j = 0; j < fg[i].n; j++) {
				f = fg[i].mp4[j];
				if (f->sample_max == 0)
					continue; // avoid division by zero
				avcc = &f->trak.stsd->entry.avc1.avcC;
				frate_num = (uint64_t)be32toh(f->trak.stsz->sample_cnt) * f->timescale;
				frate_den = f->sample_max;
				div = gcd(frate_num, frate_den);
				frate_num /= div;
				frate_den /= div;
				o->buf->last = ngx_sprintf(o->buf->last, dash_mpd_repr_video,
					j + 1, avcc->prof_ind, avcc->prof_comp, avcc->level,
					be16toh(f->trak.stsd->entry.avc1.width),
					be16toh(f->trak.stsd->entry.avc1.height),
					frate_num, frate_den, (ngx_int_t)((uint64_t)f->file_size * 8 * f->timescale / f->sample_max));
				mp4mux_release_cache_item(f, r->pool);
			}
			o->buf->last = ngx_sprintf(o->buf->last, dash_mpd_adapt_tail);
			break;
		case 'a':
			rc = -1;
			for (j = 0; j < fg[i].n; j++) {
				f = fg[i].mp4[j];
				if (f->trak.hdlr->subtype != ATOM('s','o','u','n')) {
					ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
						"mp4mux: wrong av type for file %V", &f->fname);
					return NGX_HTTP_NOT_FOUND;
				}
				if (mp4_parse_stsd_audio(r->connection->log, &ad[j], f->trak.stsd) != NGX_OK)
					return NGX_HTTP_NOT_FOUND;
				if (rc == -1)
					rc = ad[j].chanconf;
				else if (rc != ad[j].chanconf) {
					ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
						"mp4mux: different channel configurations for track %i", ctx->cur_trak);
					return NGX_HTTP_NOT_FOUND;
				}
			}
			if (!(o->buf = ngx_create_temp_buf(r->pool, sizeof(dash_mpd_adapt_audio) + sizeof(dash_mpd_segm) + sizeof(dash_mpd_segm_tail) +
					sizeof(dash_mpd_tl_r) + sizeof(dash_mpd_tl) + sizeof(dash_mpd_repr_audio) * fg[i].n + sizeof(dash_mpd_adapt_tail) + url.len * 2 + 500)))
			if (rc < 0)
				break;
			o->buf->last = ngx_sprintf(o->buf->last, dash_mpd_adapt_audio, ctx->cur_trak, &fg[i].lang, (uint32_t)rc);
			dash_write_segm(o->buf, len, conf->segment_ms, &url);
			for (j = 0; j < fg[i].n; j++) {
				f = fg[i].mp4[j];
				o->buf->last = ngx_sprintf(o->buf->last, dash_mpd_repr_audio,
					j + 1, ad[j].profile, f->timescale, ad[j].bitrate);
				mp4mux_release_cache_item(f, r->pool);
			}
			o->buf->last = ngx_sprintf(o->buf->last, dash_mpd_adapt_tail);
			break;
		}
		content_len += o->buf->last - o->buf->start;
	}
	if (!(o->next = ngx_alloc_chain_link(r->pool)))
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	o = o->next;
	o->next = NULL;
	if (!(o->buf = ngx_calloc_buf(r->pool)))
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	o->buf->memory = 1;
	o->buf->last_buf = 1;
	o->buf->start = dash_mpd_footer;
	o->buf->end = dash_mpd_footer + sizeof(dash_mpd_footer) - 1;
	o->buf->pos = o->buf->start;
	o->buf->last = o->buf->end;
	content_len += o->buf->last - o->buf->start;

	// Output headers and data
	r->headers_out.content_length_n = content_len;

	r->headers_out.status = NGX_HTTP_OK;
	ngx_str_set(&r->headers_out.content_type, "application/dash+xml");
	r->headers_out.content_type_len = r->headers_out.content_type.len;
	if (!(content_disp = add_content_disp(r, 0)))
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	ngx_str_set(&content_disp->value, "inline; filename=\"manifest.mpd\"");

	rc = ngx_http_send_header(r);
	if (rc == NGX_ERROR || rc > NGX_OK || r->header_only)
		return rc;

	rc = ngx_http_output_filter(r, &out);
	if (rc != NGX_OK)
		return rc;
	return NGX_OK;
}
static ngx_int_t mp4mux_dash_send_manifest(ngx_http_mp4mux_ctx_t *ctx)
{
	ngx_http_mp4mux_conf_t *conf;
	ngx_http_request_t *r = ctx->req;
	mp4_file_t *f;
	mp4a_audio_desc ad;
	ngx_table_elt_t *content_disp;
	ngx_int_t rc, last, content_len, len, reps;
	uint64_t frate_num, frate_den, div;
	mp4_atom_avcC_t *avcc;
	ngx_str_t prefix;
	ngx_chain_t out, *o;
	ngx_str_t nulstr = ngx_null_string;

	conf = ngx_http_get_module_loc_conf(r, ngx_http_mp4mux_module);

	if (!(out.buf = ngx_create_temp_buf(r->pool, sizeof(dash_mpd_header)+200)))
		return NGX_HTTP_INTERNAL_SERVER_ERROR;

	len = mp4mux_longest_track(ctx);

	out.buf->last = ngx_sprintf(out.buf->last, dash_mpd_header, len / 1000, len % 1000, conf->segment_ms/1000);
	content_len = out.buf->last - out.buf->start;

	o = &out;

	if (conf->dp_lengths == NULL) {
		prefix.data = conf->dash_prefix.data;
		prefix.len = conf->dash_prefix.len;
	}
	for (ctx->cur_trak = 0; ctx->mp4_src[ctx->cur_trak]; ctx->cur_trak++) {
		f = ctx->mp4_src[ctx->cur_trak];
		if (conf->dp_lengths != NULL)
			if (ngx_http_script_run(r, &prefix, conf->dp_lengths->elts, 0, conf->dp_values->elts) == NULL) {
				ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
					"mp4mux: failed to get dash url prefix.");
				return NGX_HTTP_INTERNAL_SERVER_ERROR;
			}
		len = (uint64_t)f->sample_max*1000/f->timescale;
		
		if (len == 0)
			continue;

		if (!(o->next = ngx_alloc_chain_link(r->pool)))
			return NGX_HTTP_INTERNAL_SERVER_ERROR;
		o = o->next;

		switch (f->trak.hdlr->subtype)
		{
		case ATOM('v','i','d','e'):
			rc = sizeof(dash_mpd_adapt_video) + sizeof(dash_mpd_segm) + sizeof(dash_mpd_segm_tail) + sizeof(dash_mpd_repr_video) +
				sizeof(dash_mpd_adapt_tail) + prefix.len * 2 + 500;
			if (ctx->seg_align) {
				rc += sizeof(dash_mpd_tl) * (len / ctx->segment_ms + 1);
			} else
			    rc += sizeof(dash_mpd_tl_r) + sizeof(dash_mpd_tl);
			if (!(o->buf = ngx_create_temp_buf(r->pool, rc)))
				return NGX_HTTP_INTERNAL_SERVER_ERROR;
			if (mp4_validate_stsd_video(r->connection->log, f->trak.stsd) != NGX_OK)
				return NGX_HTTP_NOT_FOUND;
			avcc = &f->trak.stsd->entry.avc1.avcC;
			frate_num = (uint64_t)be32toh(f->trak.stsz->sample_cnt) * f->timescale;
			frate_den = f->sample_max;
			div = gcd(frate_num, frate_den);
			frate_num /= div;
			frate_den /= div;
			o->buf->last = ngx_sprintf(o->buf->last, dash_mpd_adapt_video,
				ctx->cur_trak + 1,
				be16toh(f->trak.stsd->entry.avc1.width),
				be16toh(f->trak.stsd->entry.avc1.height),
				frate_num, frate_den);
			if (ctx->seg_align && !f->eof) {
				o->buf->last = ngx_sprintf(o->buf->last, dash_mpd_segm, &prefix, &prefix);
				mp4_stss_init(f);
				last = mp4_nextseg(ctx, f);
				rc = last;
				reps = 0;
				while (1)
					if (f->eof || (rc = mp4_nextseg(ctx, f)) != last) {
						if (reps == 0)
							o->buf->last = ngx_sprintf(o->buf->last, dash_mpd_tl,
								(uint64_t)last * 1000 / f->timescale);
						else
							o->buf->last = ngx_sprintf(o->buf->last, dash_mpd_tl_r,
								(uint64_t)last * 1000 / f->timescale, reps);
						if (last == rc) break;
						last = rc;
						reps = 0;
					} else
						reps++;
				o->buf->last = ngx_sprintf(o->buf->last, dash_mpd_segm_tail);
			} else
				dash_write_segm(o->buf, len, conf->segment_ms, &prefix);
			o->buf->last = ngx_sprintf(o->buf->last, dash_mpd_repr_video,
				ctx->cur_trak + 1,
				avcc->prof_ind, avcc->prof_comp, avcc->level,
				be16toh(f->trak.stsd->entry.avc1.width),
				be16toh(f->trak.stsd->entry.avc1.height),
				frate_num, frate_den, (ngx_int_t)((uint64_t)f->file_size * 8000 / len));
			o->buf->last = ngx_sprintf(o->buf->last, dash_mpd_adapt_tail);
			break;
		case ATOM('s','o','u','n'):
			if (!(o->buf = ngx_create_temp_buf(r->pool, sizeof(dash_mpd_adapt_audio) + sizeof(dash_mpd_segm) + sizeof(dash_mpd_segm_tail) +
					sizeof(dash_mpd_tl_r) + sizeof(dash_mpd_tl) + sizeof(dash_mpd_adapt_tail) + prefix.len * 2 + 500)))
				return NGX_HTTP_INTERNAL_SERVER_ERROR;
			if (mp4_parse_stsd_audio(r->connection->log, &ad, f->trak.stsd) != NGX_OK)
				return NGX_HTTP_NOT_FOUND;
			o->buf->last = ngx_sprintf(o->buf->last, dash_mpd_adapt_audio,
				ctx->cur_trak + 1, &nulstr,	ad.chanconf);
			dash_write_segm(o->buf, len, conf->segment_ms, &prefix);
			o->buf->last = ngx_sprintf(o->buf->last, dash_mpd_repr_audio,
				ctx->cur_trak + 1, ad.profile, f->timescale, ad.bitrate);
			o->buf->last = ngx_sprintf(o->buf->last, dash_mpd_adapt_tail);
			break;
		default:
			ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
				"mp4mux: invalid media handler in %V", &f->fname);
			return NGX_HTTP_NOT_FOUND;
		}
		content_len += o->buf->last - o->buf->start;
		mp4mux_release_cache_item(f, r->pool);
	}
	if (!(o->next = ngx_alloc_chain_link(r->pool)))
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	o = o->next;
	o->next = NULL;
	if (!(o->buf = ngx_calloc_buf(r->pool)))
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	o->buf->memory = 1;
	o->buf->last_buf = 1;
	o->buf->start = dash_mpd_footer;
	o->buf->end = dash_mpd_footer + sizeof(dash_mpd_footer) - 1;
	o->buf->pos = o->buf->start;
	o->buf->last = o->buf->end;
	content_len += o->buf->last - o->buf->start;

	// Output headers and data
	r->headers_out.content_length_n = content_len;

	r->headers_out.status = NGX_HTTP_OK;
	ngx_str_set(&r->headers_out.content_type, "application/dash+xml");
	r->headers_out.content_type_len = r->headers_out.content_type.len;
	if (!(content_disp = add_content_disp(r, 0)))
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	ngx_str_set(&content_disp->value, "inline; filename=\"manifest.mpd\"");

	rc = ngx_http_send_header(r);
	if (rc == NGX_ERROR || rc > NGX_OK || r->header_only)
		return rc;

	rc = ngx_http_output_filter(r, &out);
	if (rc != NGX_OK)
		return rc;
	return NGX_OK;
}

static ngx_int_t mp4_stbl_ptr_init(mp4_stbl_ptr_t *ptr, mp4_atom_hdr_t *atom, ngx_log_t *log) {
	uint32_t entry_count = be32toh(atom->u.data32[1]);
	if (be32toh(atom->size) != entry_count * sizeof(mp4_stbl_entry_t) + 16) {
		ngx_log_error(NGX_LOG_ERR, log, 0,
			"mp4_stbl_ptr_init: atom size doesn't match entry count");
		return NGX_ERROR;
	}
	if (!entry_count) {
		ngx_log_error(NGX_LOG_ERR, log, 0, "mp4_stbl_ptr_init: atom is empty");
		return NGX_ERROR;
	}

	ptr->entry = (mp4_stbl_entry_t*)&atom->u.data + 1;
	ptr->end = ptr->entry + entry_count;
	ptr->samp_left = be32toh(ptr->entry->count);
	ptr->value = be32toh(ptr->entry->value);
	return NGX_OK;
}

static ngx_int_t mp4_stbl_ptr_advance_entry(mp4_stbl_ptr_t *ptr) {
	if (++ptr->entry >= ptr->end) {
		ptr->samp_left = 1; // Make sure that subsequent calls will return error too
		return NGX_ERROR;
	}
	ptr->samp_left = be32toh(ptr->entry->count);
	ptr->value = be32toh(ptr->entry->value);
	return NGX_OK;
}
static ngx_int_t mp4_stbl_ptr_advance(mp4_stbl_ptr_t *ptr) {
	if (--ptr->samp_left)
		return NGX_OK;
	return mp4_stbl_ptr_advance_entry(ptr);
}
static ngx_int_t mp4_stbl_ptr_advance_n(mp4_stbl_ptr_t *ptr, uint32_t n) {
	while (n >= ptr->samp_left) {
		n -= ptr->samp_left;
		if (mp4_stbl_ptr_advance_entry(ptr) != NGX_OK)
			return NGX_ERROR;
	}
	ptr->samp_left -= n;
	return NGX_OK;
}
static ngx_int_t mp4_stsc_ptr_init(mp4_stsc_ptr_t *ptr, mp4_atom_stsc_t *atom, uint32_t chunk_count, ngx_log_t *log)
{
	uint32_t entry_cnt = be32toh(atom->sample_cnt);
	if (be32toh(atom->hdr.size) != sizeof(mp4_atom_stsc_t) + sizeof(mp4_stsc_entry_t) * entry_cnt) {
		ngx_log_error(NGX_LOG_ERR, log, 0,
			"mp4_stsc_ptr_init: stsc atom size doesn't match entry count");
		return NGX_ERROR;
	}
	if (entry_cnt == 0) {
		ngx_log_error(NGX_LOG_ERR, log, 0,
			"mp4_stsc_ptr_init: stsc table is empty!");
		return NGX_ERROR;
	}
	ptr->chunk_count = chunk_count;
	ptr->chunk_no = be32toh(atom->tbl[0].first_chunk);
	ptr->samp_cnt = be32toh(atom->tbl[0].sample_cnt);
	ptr->samp_left = be32toh(atom->tbl[0].sample_cnt);
	ptr->entry = atom->tbl + 1;
	ptr->end = atom->tbl + entry_cnt;
	if (entry_cnt == 1)
		ptr->next = ptr->chunk_count;
	else
		ptr->next = be32toh(atom->tbl[1].first_chunk);
	return NGX_OK;
}

static ngx_int_t mp4_stsc_ptr_advance_entry(mp4_stsc_ptr_t *ptr) {
	if (++ptr->chunk_no >= ptr->next) {
		if (ptr->entry >= ptr->end) {
			ptr->samp_left = 1;
			return NGX_ERROR;
		}
		ptr->samp_cnt = be32toh(ptr->entry++->sample_cnt);
		if (ptr->entry == ptr->end)
			ptr->next = ptr->chunk_count + 1;
		else
			ptr->next = be32toh(ptr->entry->first_chunk);
	}
	ptr->samp_left = ptr->samp_cnt;
	return NGX_OK;
}
/*static ngx_int_t mp4_stsc_ptr_advance(mp4_file_t *f) {
	if (--f->stsc_ptr.samp_left)
		return NGX_OK;
	if (mp4_stsc_ptr_advance_entry(&f->stsc_ptr)) {
		ngx_log_error(NGX_LOG_ERR, f->log, 0,
			"mp4mux: stsc pointer is out of range");
		return NGX_ERROR;
	}
	return NGX_OK;
}*/

static ngx_int_t mp4_stsc_ptr_advance_n(mp4_stsc_ptr_t *ptr, uint32_t n) {
	while (n > ptr->samp_left) {
		n -= ptr->samp_left;
		if (mp4_stsc_ptr_advance_entry(ptr) != NGX_OK)
			return NGX_ERROR;
	}
	ptr->samp_left -= n;
	return NGX_OK;
}

static ngx_int_t mp4_validate_stsd_video(ngx_log_t *log, mp4_atom_stsd_t *stsd) {
	if (be32toh(stsd->entries) != 1) {
		ngx_log_error(NGX_LOG_ERR, log, 0,
			"mp4mux: number of entries in stsd must be 1");
		return NGX_ERROR;
	}
	if (stsd->entry.hdr.type != ATOM('a','v','c','1')
		&& stsd->entry.hdr.type != ATOM('h','2','6','4')
		&& stsd->entry.hdr.type != ATOM('H','2','6','4')) {
		ngx_log_error(NGX_LOG_ERR, log, 0,
			"mp4mux: only avc1(h264) format is supported now");
		return NGX_ERROR;
	}
	if (be32toh(stsd->entry.avc1.entries) != 1) {
		ngx_log_error(NGX_LOG_ERR, log, 0,
			"mp4mux: number of entries in avc1 must be 1");
		return NGX_ERROR;
	}
	if (stsd->entry.avc1.avcC.hdr.type != ATOM('a','v','c','C')) {
		ngx_log_error(NGX_LOG_ERR, log, 0,
			"mp4mux: avcC atom is not found in avc1");
		return NGX_ERROR;
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
	if (mp4_validate_stsd_video(ctx->req->connection->log, stsd) != NGX_OK)
		return NGX_ERROR;
	in_end = (u_char*)stsd + be32toh(stsd->hdr.size);
	avc1 = &stsd->entry.avc1;
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

static uint32_t mp4_parse_esds_len(u_char **data, u_char *end) {
    uint32_t i = 0;
    do {
		if (*data >= end) return 0;
		i <<= 7;
		i += **data & 0x7f;
    } while (*(*data)++ & 0x80);
	return i;
}
static ngx_int_t mp4_parse_stsd_audio(ngx_log_t *log, mp4a_audio_desc *ad, mp4_atom_stsd_t *stsd) {
	mp4_atom_mp4a_t *mp4a;
	mp4_atom_esds_t *esds;
	u_char *data, *end;
	esds_decconf_t *decconf;

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
	if (esds->hdr.type != ATOM('e','s','d','s')) {
		ngx_log_error(NGX_LOG_ERR, log, 0,
			"mp4mux: esds atom is not found in mp4a");
		return NGX_ERROR;
	}
	data = esds->data;
	end = (u_char*)esds + be32toh(esds->hdr.size);
	if (*data++ != 3 || !mp4_parse_esds_len(&data, end)) {
		ngx_log_error(NGX_LOG_ERR, log, 0,
			"mp4mux: ES_Descriptor not found in esds");
		return NGX_ERROR;
	}
	data += 3;
	if (*data++ != 4 || !mp4_parse_esds_len(&data, end)) {
		ngx_log_error(NGX_LOG_ERR, log, 0,
			"mp4mux: DecoderConfigDescriptor not found in esds");
		return NGX_ERROR;
	}
	decconf = (esds_decconf_t*)data;
	if (decconf->prof_ind != 0x40) {
		ngx_log_error(NGX_LOG_ERR, log, 0,
			"mp4mux: audio type must be MPEG-4 (0x40)");
		return NGX_ERROR;
	}
	ad->bitrate = be32toh(decconf->max_bitrate);
	data += sizeof(esds_decconf_t);
	if (*data++ != 5 || !mp4_parse_esds_len(&data, end)) {
		ngx_log_error(NGX_LOG_ERR, log, 0,
			"mp4mux: DecoderSpecificInfo not found in esds");
		return NGX_ERROR;
	}
	ad->profile = data[0] >> 3;
	if (ad->profile > 4 || ad->profile == 0) {
		ngx_log_error(NGX_LOG_ERR, log, 0,
			"mp4mux: only AAC audio is supported, requested format id %i", ad->profile);
		return NGX_ERROR;
	}
	ad->rate_idx = ((data[0] & 7) << 1) | (data[1] >> 7);
	ad->chanconf = (data[1] >> 3) & 0x0f;
	if (ad->chanconf > 7) {
		ngx_log_error(NGX_LOG_ERR, log, 0,
			"mp4mux: invalid channel configuration %i", ad->chanconf);
		return NGX_ERROR;
	}
	return NGX_OK;
}

static void hls_calcdts(mp4_file_t *f) {
	f->hls_ctx->dts = ((int64_t)f->sample_no * HLS_TIMESCALE + f->timescale/2) / f->timescale;
}
// Advances stts, frame_no and sample_no but not ctts, stsc and dts
static ngx_int_t mp4mux_nextframe(mp4_file_t *mp4) {
	if (mp4->eof) {
		ngx_log_error(NGX_LOG_ERR, mp4->file.log, 0,
			"mp4mux_nextframe: called on EOF track");
		return NGX_ERROR;
	}
	mp4->frame_no++;
	mp4->sample_no += mp4->stts_ptr.value;
	if (mp4->sample_no >= mp4->sample_max) {
		mp4->eof = 1;
		return NGX_OK;
	}
	if ((mp4_stbl_ptr_advance(&mp4->stts_ptr)) != NGX_OK) {
		mp4->eof = 1;
		return NGX_OK;
	}
	return NGX_OK;
}
static void mp4_stss_upd(mp4_file_t *mp4) {
	if (mp4->stss_ptr >= mp4->stss_end)
		mp4->next_keyframe = NGX_MAX_UINT32_VALUE;
	else
		mp4->next_keyframe = be32toh(*mp4->stss_ptr) - 1;
}
static bool_t mp4_is_keyframe(mp4_file_t *mp4) {
	if (mp4->stss_ptr && mp4->frame_no >= mp4->next_keyframe) {
		mp4->stss_ptr++;
		mp4_stss_upd(mp4);
		return 1;
	}
	return 0;
}
static ngx_int_t hls_count_packets(ngx_http_mp4mux_ctx_t *ctx, mp4_file_t *mp4)
{
	uint32_t frame_no, sample_no, sample_max = NGX_MAX_UINT32_VALUE, len, dts, size;
	uint32_t *stss_start;
	mp4_stbl_entry_t *stptr;
	mp4_hls_ctx_t *hls_ctx = mp4->hls_ctx;
	mp4_stbl_ptr_t stts_save;
	ngx_int_t i;
	off_t offs;
	if (mp4->eof)
		return NGX_OK;
	// Save pointer values before simulation
	frame_no = mp4->frame_no;
	sample_no = mp4->sample_no;
	stts_save = mp4->stts_ptr;
	offs = mp4->offs;
	switch (hls_ctx->pes_typ) {
	case PES_VIDEO:
		if (ctx->seg_align)
			sample_max = (int64_t)ctx->seg_no * ctx->segment_ms * mp4->timescale / 1000;
		stss_start = mp4->stss_ptr;
		// Use unconverted mp4 frame length to determine packet count
		do {
			if (mp4_is_keyframe(mp4)) {
				len = hls_ctx->cdata_len;
				if (mp4->sample_no >= sample_max) {
					mp4->sample_max = mp4->sample_no;
					break;
				}
			} else
				len = 0;
			size = be32toh(mp4->trak.stsz->tbl[mp4->frame_no]);
			len += size;
			offs += size;
			len += 8; // Adaptation
			len += 14; // Minimal PES header
			if (mp4->trak.ctts) len += 5; // additional timestamp
			len += 7; // frame header
			hls_ctx->packet_count += (len + MPEGTS_PACKET_USABLE_SIZE - 1) / MPEGTS_PACKET_USABLE_SIZE;
			if (mp4mux_nextframe(mp4) != NGX_OK)
				return NGX_HTTP_NOT_FOUND;
		} while (!mp4->eof);
		if (mp4->do_copy) {
			// copy stss
			len = mp4->stss_ptr - stss_start;
			if (len) {
				mp4->stss_ptr = ngx_palloc(mp4->req->pool, len * 4);
				mp4->stss_end = mp4->stss_ptr + len;
				ngx_memcpy(mp4->stss_ptr, stss_start, len * 4);
				mp4->next_keyframe = be32toh(*stss_start)-1;
			} else
				mp4->next_keyframe = NGX_MAX_UINT32_VALUE;

			// copy ctts
			if (mp4->trak.ctts) {
				len = mp4->frame_no-frame_no;
				i = hls_ctx->ctts_ptr.entry - mp4->trak.ctts->tbl;
				if (i + len > be32toh(mp4->trak.ctts->entries))
					len = be32toh(mp4->trak.ctts->entries) - i;
				stptr = hls_ctx->ctts_ptr.entry;
				hls_ctx->ctts_ptr.entry = ngx_palloc(mp4->req->pool, len * 8);
				hls_ctx->ctts_ptr.end = hls_ctx->ctts_ptr.entry + len;
				ngx_memcpy(hls_ctx->ctts_ptr.entry, stptr, len * 8);
			}
		} else {
			mp4->stss_end = mp4->stss_ptr;
			mp4->stss_ptr = stss_start;
			mp4_stss_upd(mp4);
		}
		break;
	case PES_AUDIO:
		do {
			len = 8; // Initial PES length
			size = be32toh(mp4->trak.stsz->tbl[mp4->frame_no]);
			hls_calcdts(mp4);
			dts = hls_ctx->dts;
			do {
				len += size + SIZEOF_ADTS_HEADER;
				offs += size;
				if (mp4mux_nextframe(mp4) != NGX_OK)
					return NGX_HTTP_NOT_FOUND;
				if (mp4->eof) break;
				hls_calcdts(mp4);
				size = be32toh(mp4->trak.stsz->tbl[mp4->frame_no]);
			} while (hls_ctx->dts-dts < HLS_MAX_DELAY && len + size + SIZEOF_ADTS_HEADER <= HLS_AUDIO_PACKET_LEN);
			hls_ctx->packet_count += (len + 8 + 6 + MPEGTS_PACKET_USABLE_SIZE - 1) / MPEGTS_PACKET_USABLE_SIZE;
		} while (!mp4->eof);
		break;
	default:
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}
	if (mp4->do_copy) {
		// copy stsz
		len = mp4->frame_no - frame_no;
		mp4->chunks = ngx_palloc(mp4->req->pool, len * 4);
		ngx_memcpy(mp4->chunks, mp4->trak.stsz->tbl + frame_no, len * 4);
		mp4->chunks -= frame_no;
		// copy stts
		len = mp4->stts_ptr.entry - stts_save.entry + 1;
		mp4->stts_ptr.entry = ngx_palloc(mp4->req->pool, len * 8);
		mp4->stts_ptr.end = mp4->stts_ptr.entry + len;
		ngx_memcpy(mp4->stts_ptr.entry, stts_save.entry, len * 8);
		mp4->stts_ptr.samp_left = stts_save.samp_left;
		mp4->stts_ptr.value = stts_save.value;
	} else {
		mp4->chunks = mp4->trak.stsz->tbl;
		mp4->stts_ptr = stts_save;
	}
	// Restore pointer values
	mp4->frame_no = frame_no;
	mp4->sample_no = sample_no;
	mp4->eof = 0;
	mp4->file_size = offs; // virtually truncate the file to avoid excessive reads
	hls_calcdts(mp4);

	ngx_log_debug2(NGX_LOG_DEBUG_HTTP, mp4->file.log, 0,
		"hls_count_packets: %O packets for %V", hls_ctx->packet_count, &mp4->fname);

	mp4mux_release_cache_item(mp4, NULL);
	mp4->req->headers_out.content_length_n += ngx_align(hls_ctx->packet_count, 16) * MPEGTS_PACKET_SIZE;

	return NGX_OK;
}
static void mp4_ff_samples(mp4_file_t *f, ngx_int_t sample_cnt) {
	ngx_int_t i;
	while (!f->eof && sample_cnt > 0) {
		i = f->stts_ptr.value * f->stts_ptr.samp_left;
		sample_cnt -= i;
		if (sample_cnt >= 0) {
			f->frame_no += f->stts_ptr.samp_left;
			f->sample_no += i;
			if (mp4_stbl_ptr_advance_entry(&f->stts_ptr) != NGX_OK)
				f->eof = 1;
		} else {
			i = f->stts_ptr.samp_left + sample_cnt / f->stts_ptr.value;
			f->frame_no += i;
			f->sample_no += i * f->stts_ptr.value;
			if (mp4_stbl_ptr_advance_n(&f->stts_ptr, i) != NGX_OK)
				f->eof = 1;
		}
	}
}
static void mp4_stss_init(mp4_file_t *f) {
	f->stss_ptr = f->trak.stss->tbl;
	f->stss_end = f->stss_ptr + be32toh(f->trak.stss->entries);
	mp4_stss_upd(f);
}
static void mp4_stss_ff(mp4_file_t *f) {
	while (f->next_keyframe < f->frame_no) {
		if (++f->stss_ptr >= f->stss_end) {
			f->next_keyframe = NGX_MAX_UINT32_VALUE;
			return;
		}
		f->next_keyframe = be32toh(*f->stss_ptr)-1;
	}
}
static void mp4_stss_align(mp4_file_t *f) {
	while (f->stts_ptr.samp_left <= (f->next_keyframe - f->frame_no)) {
		f->frame_no += f->stts_ptr.samp_left;
		f->sample_no += f->stts_ptr.samp_left * f->stts_ptr.value;
		if (mp4_stbl_ptr_advance_entry(&f->stts_ptr) != NGX_OK) {
			f->eof = 1;
			return;
		}
	}
	f->sample_no += (f->next_keyframe - f->frame_no) * f->stts_ptr.value;
	mp4_stbl_ptr_advance_n(&f->stts_ptr, f->next_keyframe - f->frame_no);
	f->frame_no = f->next_keyframe;
}
static ngx_int_t mp4_seek_to_frame(mp4_file_t *f) {
	ngx_int_t i;
	f->offs = 0;
	if (mp4_stsc_ptr_advance_n(&f->stsc_ptr, f->frame_no) != NGX_OK)
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	// calculate frame offset in the chunk
	for (i = f->frame_no - (be32toh(f->stsc_ptr.entry[-1].sample_cnt)
			- f->stsc_ptr.samp_left); i < f->frame_no; i++)
		f->offs += be32toh(f->trak.stsz->tbl[i]);
	f->offs += mp4_curchunk_offset(f);
	return NGX_OK;
}
static ngx_int_t mp4_move_to_segment(ngx_http_mp4mux_ctx_t *ctx, mp4_file_t *f, mp4_stbl_ptr_t *ctts_ptr) {
	uint32_t tmp;
	if (ctx->seg_no > 1)
		mp4_ff_samples(f, (ctx->seg_no - 1) * ctx->segment_ms * f->timescale / 1000);
	if (f->eof) return NGX_OK;
	if (f->trak.stss) {
		mp4_stss_init(f);
		mp4_stss_ff(f);
		if (ctx->seg_align) {
			mp4_stss_align(f);
			if (f->eof) return NGX_OK;
		}
	}
	if (ctx->seg_align && !f->trak.stss) return NGX_OK;
	if (ctts_ptr && mp4_stbl_ptr_advance_n(ctts_ptr, f->frame_no) != NGX_OK)
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	if (mp4_seek_to_frame(f) != NGX_OK)
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	if (ctx->seg_align) return NGX_OK;
	tmp = ctx->seg_no * ctx->segment_ms * f->timescale / 1000;
	if (tmp < f->sample_max) f->sample_max = tmp;
	return NGX_OK;
}
ngx_int_t mp4_init_video(mp4_file_t* f, mp4_stbl_ptr_t* ctts_ptr) {
	if (f->trak.stss == NULL) {
		ngx_log_error(NGX_LOG_ERR, f->file.log, 0,
			"mp4mux: stss atom not found in %V", &f->fname);
		return NGX_ERROR;
	}
	if (f->trak.ctts &&	mp4_stbl_ptr_init(ctts_ptr, &f->trak.ctts->hdr, f->file.log) != NGX_OK) {
		ngx_log_error(NGX_LOG_ERR, f->file.log, 0,
			"mp4mux: invalid ctts atom in %V", &f->fname);
		return NGX_ERROR;
	}
	return NGX_OK;
}
static ngx_int_t mp4mux_hls_send_segment(ngx_http_mp4mux_ctx_t *ctx)
{
	ngx_http_request_t *r = ctx->req;
	ngx_table_elt_t *content_disp;
	mp4a_audio_desc ad;
	mp4_hls_ctx_t *hls_ctx;
	ngx_str_t str;
	ngx_int_t rc, n;
	uint32_t tmp, sample_pos = 0, sample_max = 0, timescale = 0;
	ngx_buf_t *b;
	u_char *p;
	u_char vid = PES_VIDEO, aid = PES_AUDIO;

	r->headers_out.status = NGX_HTTP_OK;
	ngx_str_set(&r->headers_out.content_type, "video/MP2T");
	r->headers_out.content_type_len = r->headers_out.content_type.len;
	if (!(content_disp = add_content_disp(r, sizeof("inline; filename=\"seg-.ts\"") + intlen(ctx->seg_no))))
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	content_disp->value.len = ngx_sprintf(content_disp->value.data,
		"inline; filename=\"seg-%i.ts\"", ctx->seg_no) - content_disp->value.data;
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
	b->last[3] += (ctx->seg_no - 1) & 0x0f;
	b->last += MPEGTS_PACKET_SIZE;
	// output PMT
	p = b->last;
	memcpy(b->last, pmt_header_template, sizeof(pmt_header_template));
	b->last[3] += (ctx->seg_no - 1) & 0x0f;
	b->last += sizeof(pmt_header_template);
	for (n = 0; n < ctx->trak_cnt; n++) {
		ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
			"mp4mux_hls: init %V", &ctx->mp4_src[n]->fname);
		// Detect track type and parse codec data
		hls_ctx = ngx_pcalloc(r->pool, sizeof(mp4_hls_ctx_t));
		ctx->mp4_src[n]->hls_ctx = hls_ctx;
		switch (ctx->mp4_src[n]->trak.hdlr->subtype)
		{
		case ATOM('v','i','d','e'):
			ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
				"mp4mux_hls: found video");
			hls_ctx->pes_id = vid++;
			hls_ctx->pes_typ = PES_VIDEO;
			if (mp4mux_hls_parse_stsd_video(ctx, hls_ctx, ctx->mp4_src[n]->trak.stsd) != NGX_OK)
				return NGX_HTTP_NOT_FOUND;
			if (hls_ctx->sf_len < 3) {
				ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
					"mp4mux: invalid codec settings in %V: subframe field length must be >=3", &ctx->mp4_src[n]->fname);
				return NGX_HTTP_NOT_FOUND;
			}
			memcpy(b->last, pmt_entry_template_avc, sizeof(pmt_entry_template_avc));
			b->last[2] = n;
			b->last += sizeof(pmt_entry_template_avc);
			if (mp4_init_video(ctx->mp4_src[n], &hls_ctx->ctts_ptr) != NGX_OK)
				return NGX_HTTP_NOT_FOUND;
			break;
		case ATOM('s','o','u','n'):
			ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
				"mp4mux_hls: found audio");
			hls_ctx->pes_id = aid++;
			hls_ctx->pes_typ = PES_AUDIO;
			if (mp4_parse_stsd_audio(r->connection->log, &ad, ctx->mp4_src[n]->trak.stsd) != NGX_OK)
				return NGX_HTTP_NOT_FOUND;
			if (ctx->mp4_src[n]->trak.ctts) {
				ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
					"mp4mux: ctts for audio tracks is not supported");
				return NGX_HTTP_NOT_FOUND;
			}
			hls_ctx->adts_hdr = htobe32(0xfff10000 | (ad.profile - 1) << 14 | ad.rate_idx << 10 | ad.chanconf << 6);
			memcpy(b->last, pmt_entry_template_aac, sizeof(pmt_entry_template_aac));
			b->last[2] = n;
			b->last += sizeof(pmt_entry_template_aac);
			break;
		default:
			str.len = 4;
			str.data = (u_char*)&ctx->mp4_src[n]->trak.hdlr->subtype;
			ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
				"mp4mux: invalid media handler %V", &str);
			return NGX_HTTP_NOT_FOUND;
		}
		if ((rc = mp4_move_to_segment(ctx, ctx->mp4_src[n], ctx->mp4_src[n]->trak.ctts ? &hls_ctx->ctts_ptr : NULL)) != NGX_OK)
			return rc;
		if ((!ctx->seg_align || ctx->mp4_src[n]->trak.stss) && (rc = hls_count_packets(ctx, ctx->mp4_src[n])) != NGX_OK)
			return rc;
	}
	if (ctx->seg_align) {
		// Sync audio with video
		for (n = 0; n < ctx->trak_cnt; n++)
			if (ctx->mp4_src[n]->trak.stss) {
				if (!timescale) {
					sample_pos = ctx->mp4_src[n]->sample_no;
					sample_max = ctx->mp4_src[n]->sample_max;
					timescale = ctx->mp4_src[n]->timescale;
				} else {
					ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
						"mp4mux: only one video track is supported with seg_align on");
					return NGX_HTTP_NOT_FOUND;
				}
			}
		if (!timescale)
			ctx->seg_align = 0;
		for (n = 0; n < ctx->trak_cnt; n++)
			if (!ctx->mp4_src[n]->trak.stss) {
				if (!ctx->seg_align) {
					sample_pos = ctx->mp4_src[n]->sample_no;
					timescale = ctx->mp4_src[n]->timescale;
					sample_max = ctx->seg_no * ctx->segment_ms * timescale / 1000;
				}
				mp4_ff_samples(ctx->mp4_src[n], ((uint64_t)sample_pos * ctx->mp4_src[n]->timescale / timescale) - ctx->mp4_src[n]->sample_no);
				if (mp4_seek_to_frame(ctx->mp4_src[n]) != NGX_OK)
					return NGX_HTTP_INTERNAL_SERVER_ERROR;
				tmp = (uint64_t)sample_max * ctx->mp4_src[n]->timescale / timescale;
				if (tmp < ctx->mp4_src[n]->sample_max)
					ctx->mp4_src[n]->sample_max = tmp;
				if (ctx->mp4_src[n]->sample_no >= ctx->mp4_src[n]->sample_max)
					ctx->mp4_src[n]->eof = 1;
				if ((rc = hls_count_packets(ctx, ctx->mp4_src[n])) != NGX_OK)
					return rc;
			}
	}
	memcpy(b->last, pmt_entry_template_id3, sizeof(pmt_entry_template_id3));
	b->last[2] = n;
	b->last += sizeof(pmt_entry_template_id3);
	p[7] = b->last - p - 4;
	tmp = mpegts_crc32(p + 5, b->last - p - 5);
	b->last = write_uint32(b->last, tmp);
	memset(b->last, 0xff, p + MPEGTS_PACKET_SIZE - b->last);
	b->last = p + MPEGTS_PACKET_SIZE;

	rc = ngx_http_send_header(r);
	if (rc == NGX_ERROR || rc > NGX_OK || r->header_only)
		return rc;

	for (n = 0; n < ctx->trak_cnt; n++)
		if (mp4mux_seek(ctx->mp4_src[n], ctx->mp4_src[n]->offs) != NGX_OK)
			return NGX_ERROR;

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
	if (b->last == b->end)
		b = hls_newbuf(ctx);
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
	rc = mp4mux_nextframe(mp4);
	if (rc != NGX_OK)
		return rc;
	if (mp4->eof) return NGX_OK;
	//uint32_t curchunk = mp4->stsc_ptr.chunk_no;
	if (mp4->trak.ctts && ((mp4_stbl_ptr_advance(&mp4->hls_ctx->ctts_ptr)) != NGX_OK)) {
		ngx_log_error(NGX_LOG_ERR, mp4->file.log, 0,
			"mp4mux_hls_nextframe: ctts pointer is out of range");
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}
	/*if (mp4_stsc_ptr_advance(mp4) != NGX_OK)
		return NGX_HTTP_INTERNAL_SERVER_ERROR;

	if (mp4->stsc_ptr.chunk_no != curchunk) {
		// Move to the next chunk
		mp4mux_seek(mp4,mp4->co64 ?
			be64toh(mp4->co->u.tbl64[mp4->stsc_ptr.chunk_no-1])
			: be32toh(mp4->co->u.tbl[mp4->stsc_ptr.chunk_no-1]));
		ngx_log_debug2(NGX_LOG_DEBUG_HTTP, mp4->log, 0,
			"switched to new chunk %i, offs = %i", mp4->stsc_ptr.chunk_no, mp4->offs);
	}*/
	hls_calcdts(mp4);
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
	ngx_log_t *log = r->connection->log;
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
				if (ctx->mp4_src[i]->eof) continue;
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
			len = be32toh(mp4->chunks[mp4->frame_no]);
			#if (NGX_HAVE_FILE_AIO)
			if (mp4->aio) {
				pes_len = len;
				if (mp4->hls_ctx->pes_typ == PES_AUDIO && pes_len < HLS_AUDIO_PACKET_LEN)
					pes_len = HLS_AUDIO_PACKET_LEN;
				rc = mp4mux_readahead(mp4, pes_len);
				if (rc == NGX_AGAIN) {
					ngx_log_debug0(NGX_LOG_DEBUG_HTTP, log, 0,
						"mp4mux_readahead returned NGX_AGAIN");
					return NGX_AGAIN;
				}
				if (rc != NGX_OK)
					return NGX_ERROR;
			}
			#endif
			frame_end = mp4->offs + len;
			ngx_log_debug6(NGX_LOG_DEBUG_HTTP, log, 0,
				"mp4mux: track %i frame %uD, sample %uD, offs: %z, len: %z, ctts = %uD",
				ctx->cur_trak, mp4->frame_no, mp4->sample_no, mp4->offs, len,
				mp4->hls_ctx->ctts_ptr.value);
			///// Write MPEG-TS packet
			if ((b = hls_newpacket(b, ctx, mp4->hls_ctx, TS_TYP1_START, TS_TYP2_ADAPT_PAYLD)) == NULL)
				return NGX_HTTP_INTERNAL_SERVER_ERROR;
			p = b->last;
			p_end = p + MPEGTS_PACKET_USABLE_SIZE;
			// Adaptation
			out2b(p, 0x07, 0x10)
			p = write_pcr(p, (uint64_t)dts + INITIAL_PCR);
			// PES header
			out4b(p, 0x00, 0x00, 0x01, mp4->hls_ctx->pes_id)
			len_field = (uint16_t*)p;
			p += 2;
			*p++ = 0x84;
			if (mp4->trak.ctts) {
				pes_len = 13;
				out2b(p, 0xc0, 10);
				p = write_pts(p, 3, (((int64_t)mp4->sample_no + mp4->hls_ctx->ctts_ptr.value)
					* HLS_TIMESCALE + mp4->timescale / 2) / mp4->timescale + INITIAL_DTS);
			} else {
				pes_len = 8;
				out2b(p, 0x80, 5);
			}
			p = write_pts(p, mp4->trak.ctts ? 1 : 2, dts + INITIAL_DTS);
			// PES data
			switch (mp4->hls_ctx->pes_typ) {
			// TODO: move write_frame_video and write_frame_audio to separate function?
			case PES_VIDEO:
				out4b(p, 0x00, 0x00, 0x00, 0x01);
				out2b(p, 0x09, 0xF0);
				if (mp4_is_keyframe(mp4)) {
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
					ngx_log_debug1(NGX_LOG_DEBUG_HTTP, log, 0, "mp4mux: subframe len: %i", len);
					subframe_end = mp4->offs + len;
					pes_len += len;
					if (subframe_end > frame_end) {
						ngx_log_error(NGX_LOG_ERR, log, 0,
							"mp4mux: error converting frame %i in %V: subframe at offs %i exceeds frame bounds",
							mp4->frame_no, &mp4->fname, mp4->offs);
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
				rc = hls_nextframe(mp4);
				if (rc != NGX_OK)
					return rc;
				break;
			case PES_AUDIO:
				ngx_memcpy(adts_hdr, &mp4->hls_ctx->adts_hdr, 4);
				adts_hdr[6] = 0xfc;
				len += SIZEOF_ADTS_HEADER;
				do {
					if (len >= 8192) {
						ngx_log_error(NGX_LOG_ERR, log, 0, "audio frame is too long: %i", len);
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
						return NGX_ERROR;
					p += len;
					// Move to the next frame
					rc = hls_nextframe(mp4);
					if (rc != NGX_OK)
						return rc;
					if (mp4->eof) break;
					len = be32toh(mp4->chunks[mp4->frame_no]);
					frame_end = mp4->offs + len;
					len += SIZEOF_ADTS_HEADER;
				} while (mp4->hls_ctx->dts-dts < HLS_MAX_DELAY && pes_len + len <= HLS_AUDIO_PACKET_LEN);
				break;
			default:
				ngx_log_error(NGX_LOG_ERR, log, 0, "Invalid track type #", ctx->cur_trak);
				return NGX_ERROR;
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
					ngx_log_error(NGX_LOG_ERR, log, 0,
						"mp4mux_hls: wrong packet count calculation at track %i, diff: %i",
						ctx->cur_trak, mp4->hls_ctx->packet_count);
				} else if (mp4->hls_ctx->packet_count > 0) {
					ngx_log_error(NGX_LOG_WARN, log, 0,
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
	ngx_log_debug1(NGX_LOG_DEBUG_HTTP, log, 0, "mp4mux_hls: DONE! rc = %i", rc);
	return rc;
}

void mp4mux_update_chains(ngx_http_mp4mux_ctx_t *ctx, ngx_chain_t *out)
{
	ngx_chain_t  *cl;

	if (ctx->busy == NULL) {
		ctx->busy = out;
		ctx->chain_last = out;
	} else {
		ctx->chain_last->next = out;
		ctx->chain_last = out;
	}
	while (ctx->chain_last->next)
		ctx->chain_last = ctx->chain_last->next;

	while (ctx->busy) {
		cl = ctx->busy;
		if (ngx_buf_size(cl->buf) != 0)
			break;
		if (cl->buf->num >= 0 && cl->buf->file_last > ctx->mp4_src[cl->buf->num]->sent_pos)
			ctx->mp4_src[cl->buf->num]->sent_pos = cl->buf->file_last;
		ctx->busy = cl->next;
		cl->next = ctx->free;
		ctx->free = cl;
	}
}
static ngx_int_t mp4mux_write(ngx_http_mp4mux_ctx_t *ctx)
{
	ngx_buf_t *b;
	mp4_buf_t *rdbuf;
	mp4mux_list_t *pos, *pos2;
	ngx_chain_t *out;
	mp4_file_t *f;
	ngx_int_t rc = NGX_OK, i;
	ngx_http_request_t *r = ctx->req;
	uint32_t size;
	ngx_http_range_filter_ctx_t *rangectx;
	ngx_http_range_t *range = NULL;
	bool_t skipping = 0;

	rangectx = ngx_http_get_module_ctx(r, ngx_http_range_body_filter_module);
	if (rangectx != NULL)
		range = rangectx->ranges.elts;

	if (range && rangectx->offset < range->start)
		skipping = 1;

	for (;ctx->chunk_num < ctx->chunk_cnt; ctx->chunk_num++, ctx->cur_trak = 0)
		for (;ctx->cur_trak < ctx->trak_cnt; ctx->cur_trak++) {
			if (rc != NGX_OK) {
				if (mp4mux_handle_write_rc(r, rc) != NGX_OK)
					return NGX_ERROR;
				return rc;
			}
			f = ctx->mp4_src[ctx->cur_trak];
			size = f->chunks[ctx->chunk_num];
			ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
				"mp4mux: chunk %i, trak %i", ctx->chunk_num, ctx->cur_trak);

			if (range) {
				if (rangectx->offset >= range->end) {
					ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
						"mp4mux: rangeskipped done");
					ctx->done = 1;
					return NGX_OK;
				}
			}
			if (skipping) {
				if (rangectx->offset + size <= range->start) {
					ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
						"mp4mux: range skip: offs %i start %i", rangectx->offset, range->start);
					f->offs += size;
					rangectx->offset += size;
					continue;
				} else {
					for (i = 0; i < ctx->trak_cnt; i++)
						if (f->file.directio && mp4mux_seek(ctx->mp4_src[i], ctx->mp4_src[i]->offs) != NGX_OK)
							return NGX_ERROR;
					skipping = 0;
				}
			}
			if (!size) continue;

			#if (NGX_HAVE_FILE_AIO)
			if (f->file.directio && f->aio) {
				rc = mp4mux_readahead(f, size);
				if (rc != NGX_OK) return rc;
			}
			#endif
			out = ngx_chain_get_free_buf(r->pool, &ctx->free);
			if (!out)
				return NGX_ERROR;

			b = out->buf;

			b->flush = 1;
			b->tag = &ngx_http_mp4mux_module;
			b->num = ctx->cur_trak;

			if (f->file.directio) {
				// nginx doesn't use sendfile in directio mode, it uses temporary buffers anyway
				// use our own buffers for more effective reading and to avoid memory leaks
				if (mp4mux_read_chain(f, out, &ctx->free, size) != NGX_OK)
					return NGX_ERROR;
				b->in_file = 0;
				b->memory = 1;
			} else {
				b->file = &f->file;
				b->file_pos = f->offs;
				f->offs += size;

				b->in_file = 1;
				b->memory = 0;
			}

			b->file_last = f->offs;

			rc = ngx_http_output_filter(r, out);

			mp4mux_update_chains(ctx, out);

			if (f->file.directio && f->offs_buf <= size)
				f->check = 1;

			if (f->check) {
				// Free all successfully sent buffers
				mp4mux_list_for_each_safe(pos, pos2, &f->rdbufs) {
					rdbuf = mp4mux_list_entry(pos, mp4_buf_t, entry);
					ngx_log_debug4(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
						"checking buf %p %i-%i sent_pos=%i", rdbuf, rdbuf->offs, rdbuf->offs_end, f->sent_pos);
					if ((off_t)rdbuf->offs_end > f->sent_pos) break;
					if (rdbuf->offs_end == f->rdbuf_cur->offs)
						f->check = 0;
					mp4mux_free_rdbuf(f, rdbuf);
				}
				if (!f->check)
					mp4mux_nextrdbuf(f); // prefetch next buf after freeing previous one
			}
			// Free headers if they were sent
			if (ctx->hdr_pool && (ctx->busy == NULL || ctx->busy->buf->num != MP4MUX_HDR_NUM)) {
				ngx_destroy_pool(ctx->hdr_pool);
				ctx->hdr_pool = NULL;
				for (i = 0; i < ctx->trak_cnt; i++)
					if (f->moov_buf) {
						ngx_pfree(f->req->pool, f->moov_buf);
						f->moov_buf = NULL;
					}
			}
		}

	if (rc != NGX_OK) {
		if (mp4mux_handle_write_rc(r, rc) != NGX_OK)
			return NGX_ERROR;
		return rc;
	}

	if (!mp4mux_list_empty(&ctx->atoms_tail)) {
		out = mp4_build_chain(ctx, &ctx->atoms_tail);
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

#if (NGX_HAVE_FILE_AIO)
extern ngx_module_t ngx_http_copy_filter_module;
#endif

static void ngx_http_mp4mux_write_handler(ngx_event_t *ev)
{
	ngx_connection_t *c;
	ngx_http_request_t *r;
	ngx_http_mp4mux_ctx_t *ctx;
	ngx_int_t rc;
	#if (NGX_HAVE_FILE_AIO)
	ngx_output_chain_ctx_t *outctx;
	#endif

	c = ev->data;
	r = c->data;

	c = r->connection;

	ctx = ngx_http_get_module_ctx(r, ngx_http_mp4mux_module);

	ngx_log_debug2(NGX_LOG_DEBUG_HTTP, c->log, 0,
		"mp4mux write handler: \"%V?%V\"", &r->uri, &r->args);

	ctx->write_handler(ev);

	#if (NGX_HAVE_FILE_AIO)
	if (r->aio) {
		outctx = ngx_http_get_module_ctx(r, ngx_http_copy_filter_module);
		if (outctx != NULL && outctx->in && outctx->in->next)
			return;
	}
	#endif

	if (c->destroyed || c->error || r->done || ctx->done) {
		ev->handler = ctx->write_handler;
		r->blocked--;
		ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0, "blocked = %i", r->blocked);
		check_conn_error(r, c);
		return;
	}

	if (!r->out || !r->out->next) {
		ev->handler = ctx->write_handler;
		r->blocked--;
		ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0, "blocked = %i", r->blocked);
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
static ngx_int_t mp4_atom_to_trak(mp4_atom_t *a, mp4_trak_t *t) {
	switch (a->hdr->type) {
	case ATOM('m', 'v', 'h', 'd'):
		if (t->mvhd) return NGX_ERROR;
		t->mvhd = (mp4_atom_mvhd_t *)a->hdr;
		break;
	case ATOM('t', 'r', 'a', 'k'):
		if (t->trak) {
			return NGX_ERROR; // Temporarily allow only one single-track source files
			//return NGX_DECLINED; // Ignore tracks except first one
		}
		t->trak = a;
		break;
	case ATOM('t', 'k', 'h', 'd'):
		if (t->tkhd || !t->trak) return NGX_ERROR;
		t->tkhd = (mp4_atom_tkhd_t *)a->hdr;
		break;
	case ATOM('m', 'd', 'h', 'd'):
		if (t->mdhd || !t->trak) return NGX_ERROR;
		t->mdhd = (mp4_atom_mdhd_v0_t *)a->hdr;
		break;
	case ATOM('h', 'd', 'l', 'r'):
		if (t->hdlr || !t->trak) return NGX_ERROR;
		t->hdlr = (mp4_atom_hdlr_t *)a->hdr;
		break;
	case ATOM('m', 'i', 'n', 'f'):
		if (t->minf || !t->trak) return NGX_ERROR;
		t->minf = a;
		break;
	case ATOM('s', 't', 'b', 'l'):
		if (t->stbl || !t->minf) return NGX_ERROR;
		t->stbl = a;
		break;
	case ATOM('s', 't', 's', 'd'):
		if (t->stsd || !t->stbl) return NGX_ERROR;
		t->stsd = (mp4_atom_stsd_t *)a->hdr;
		break;
	case ATOM('s', 't', 's', 'z'):
		if (t->stsz || !t->stbl) return NGX_ERROR;
		t->stsz = (mp4_atom_stsz_t *)a->hdr;
		break;
	case ATOM('c', 'o', '6', '4'):
		t->co64 = 1;
	case ATOM('s', 't', 'c', 'o'):
		if (t->co || !t->stbl) return NGX_ERROR;
		t->co = (mp4_atom_stco_t *)a->hdr;
		break;
	case ATOM('s', 't', 's', 'c'):
		if (t->stsc || !t->stbl) return NGX_ERROR;
		t->stsc = (mp4_atom_stsc_t *)a->hdr;
		break;
	case ATOM('s', 't', 't', 's'):
		if (t->stts || !t->stbl) return NGX_ERROR;
		t->stts = (mp4_atom_stts_t *)a->hdr;
		break;
	case ATOM('c', 't', 't', 's'):
		if (t->ctts || !t->stbl) return NGX_ERROR;
		t->ctts = (mp4_atom_ctts_t *)a->hdr;
		break;
	case ATOM('s', 't', 's', 's'):
		if (t->stss || !t->stbl) return NGX_ERROR;
		t->stss = (mp4_atom_stss_t *)a->hdr;
		break;
	}
	return NGX_OK;
}
static ngx_int_t mp4_parse_atom(mp4_file_t *mp4f, mp4_atom_t *atom)
{
	ngx_uint_t i;
	mp4_atom_hdr_t *hdr;
	off_t pos;
	uint32_t size, atom_size;
	char atom_name[5];

	atom_name[4] = 0;

	if (mp4_atom_to_trak(atom, &mp4f->trak) != NGX_OK)
		return NGX_ERROR;

	for (i = 0; i < sizeof(mp4_atom_containers)/sizeof(mp4_atom_containers[0]); i++)
		if (atom->hdr->type == mp4_atom_containers[i]) {
			atom_size = be32toh(atom->hdr->size) - sizeof(*hdr);
			for (pos = 0; pos < atom_size; pos += size) {
				hdr = (mp4_atom_hdr_t *)(atom->hdr->u.data + pos);
				size = be32toh(hdr->size);

				ngx_memcpy(atom_name, &hdr->type, 4);
				ngx_log_debug2(NGX_LOG_DEBUG_HTTP, mp4f->file.log, 0,
					"begin atom: %s %i", atom_name, size);

				if (size < 8) {
					ngx_log_error(NGX_LOG_ERR, mp4f->file.log, 0,
						"mp4mux: \"%V\": atom is too small:%uL",
						&mp4f->fname, size);
					return NGX_ERROR;
				}

				if (hdr->type == ATOM('e', 'd', 't', 's'))
					continue;

				if (mp4_add_primitive_atom(&atom->atoms, hdr, mp4f->req->pool) != NGX_OK)
					return NGX_ERROR;

				if (mp4_parse_atom(mp4f, mp4mux_list_entry(atom->atoms.prev, mp4_atom_t, entry))) {
					ngx_log_error(NGX_LOG_ERR, mp4f->file.log, 0,
						"mp4mux: \"%V\": error while parsing \"%s\" atom",
						&mp4f->fname, atom_name);
					return NGX_ERROR;
				}

				ngx_log_debug2(NGX_LOG_DEBUG_HTTP, mp4f->file.log, 0,
					"end atom: %s %i", atom_name, size);
			}
			return NGX_OK;
		}
	return NGX_OK;
}

static ngx_int_t mp4_parse(mp4_file_t *mp4f)
{
	mp4_atom_hdr_t hdr;
	uint32_t size, size_aligned;
	uint64_t size64;
	u_char *buf;
	ngx_int_t n;
	char atom_name[5];

	atom_name[4] = 0;

	while (mp4f->offs < mp4f->file_size) {
		n = mp4mux_read(mp4f, (u_char *)&hdr, sizeof(hdr), 0);

		if (n == NGX_AGAIN)
			return NGX_AGAIN;
		if (n != NGX_OK)
			return NGX_HTTP_INTERNAL_SERVER_ERROR;

		size = be32toh(hdr.size);

		memcpy(atom_name, &hdr.type, 4);
		ngx_log_debug2(NGX_LOG_DEBUG_HTTP, mp4f->file.log, 0,
			"atom: %s %i", atom_name, size);

		if (size == 1) {
			n = mp4mux_read(mp4f, (u_char *)&size64, 8, 0);
			if (n == NGX_AGAIN)
				return NGX_AGAIN;
			if (n != NGX_OK)
				return NGX_HTTP_INTERNAL_SERVER_ERROR;
			size64 = be64toh(size64);
			ngx_log_debug1(NGX_LOG_DEBUG_HTTP, mp4f->file.log, 0, "size64 %L", size64);
		}

		if (size == 0) {
			size = mp4f->file_size - mp4f->offs_restart;
			hdr.size = htobe32(size);
		} else if (size != 1 && size < 8) {
			ngx_log_error(NGX_LOG_ERR, mp4f->file.log, 0,
				"mp4mux: \"%V\": atom is too small:%uL",
				&mp4f->fname, size);
			return NGX_HTTP_NOT_FOUND;
		}
		if (hdr.type == ATOM('m', 'o', 'o', 'v')) {
			if (size == 1 || size > MAX_ATOM_SIZE) {
				ngx_log_error(NGX_LOG_ERR, mp4f->file.log, 0,
					"mp4mux: \"%V\": moov atom is too large:%uL",
					&mp4f->fname, size);
				return NGX_HTTP_NOT_FOUND;
			}
			if (mp4mux_seek(mp4f, mp4f->offs_restart) != NGX_OK)
				return NGX_HTTP_INTERNAL_SERVER_ERROR;
			size_aligned = ngx_align(mp4f->offs_restart + size, SECTOR_SIZE) - (mp4f->offs_restart & ~(SECTOR_SIZE-1));
			if (!mp4f->dontcache)
				mp4f->cache_entry = mp4mux_cache_alloc(mp4f, size_aligned);
			if (mp4f->cache_entry) {
				buf = mp4f->cache_entry->start;
				mp4f->cache_entry->hdr = (mp4_atom_hdr_t*)(buf + (mp4f->offs_restart & (SECTOR_SIZE-1)));
				mp4f->moov.hdr = mp4f->cache_entry->hdr;
				mp4f->do_copy = 1;
			} else {
				buf = ngx_pmemalign(mp4f->req->pool, size_aligned, SECTOR_SIZE);
				if (!buf)
					return NGX_HTTP_INTERNAL_SERVER_ERROR;
				mp4f->moov.hdr = (mp4_atom_hdr_t*)(buf + (mp4f->offs_restart & (SECTOR_SIZE-1)));
				mp4f->moov_buf = buf;
			}
			n = mp4mux_read_moov(mp4f, buf, size_aligned);
			mp4f->offs_restart = mp4f->offs; // Prevent unnecessary seeks
			if (n == NGX_AGAIN)
				return NGX_AGAIN;
			if (n != NGX_OK)
				return NGX_HTTP_INTERNAL_SERVER_ERROR;
			if (mp4f->cache_entry)
				mp4f->cache_entry->lock = 1;
			return NGX_OK;
		} else {
			if (size != 1) size64 = size;
			if (mp4mux_seek(mp4f, mp4f->offs_restart + size64) != NGX_OK)
				return NGX_HTTP_INTERNAL_SERVER_ERROR;
		}
	}
	ngx_log_error(NGX_LOG_ERR, mp4f->file.log, 0,
		"mp4mux: \"%V\": moov atom is not found", mp4f->fname);
	return NGX_HTTP_NOT_FOUND;
}

static mp4_atom_t *mp4_clone_atom(mp4_atom_t *atom, mp4_trak_t *dst_trak, atom_clone_depth depth, bool_t skip_stbl, ngx_pool_t *pool)
{
	mp4_atom_t *anew, *asub, *nsub;
	ngx_int_t size = 0;
	char atom_name[5] = {0,0,0,0,0};

	memcpy(atom_name, &atom->hdr->type, 4);
	ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pool->log, 0,
		"clone atom: %s ", atom_name);

	switch (depth) {
	case atom_clone_meta: break;
	case atom_clone_data:
		if (mp4mux_list_empty(&atom->atoms)) {
			size = be32toh(atom->hdr->size);
			break;
		}
	case atom_clone_hdr:
		size = sizeof(mp4_atom_hdr_t);
	}

	if (!(anew = mp4_alloc_atom(pool, size)))
		return NULL;

	if (depth == atom_clone_meta)
		anew->hdr = atom->hdr;
	else
		ngx_memcpy(anew->data, atom->hdr, size);

	if (mp4_atom_to_trak(anew, dst_trak) != NGX_OK)
		return NULL;

	mp4mux_list_for_each_entry(asub, &atom->atoms, entry) {
		switch(asub->hdr->type) {
		case ATOM('s', 't', 'b', 'l'): if (!skip_stbl) break;
		case ATOM('s', 't', 'c', 'o'):
		case ATOM('c', 'o', '6', '4'):
		case ATOM('s', 't', 's', 'c'):
			continue;
		}

		if (!(nsub = mp4_clone_atom(asub, dst_trak, depth, skip_stbl, pool)))
			return NULL;
		mp4mux_list_add_tail(&nsub->entry, &anew->atoms);
	}

	return anew;
}

static off_t mp4_build_atoms(mp4mux_list_t *list, ngx_log_t *log)
{
	off_t len = 0, n;
	mp4_atom_t *a;
	char atom_name[5] = {0,0,0,0,0};

	mp4mux_list_for_each_entry(a, list, entry) {
		memcpy(atom_name, &a->hdr->type, 4);

		ngx_log_debug1(NGX_LOG_DEBUG_HTTP, log, 0,
			"build atom: %s", atom_name);

		if (mp4mux_list_empty(&a->atoms))
			len += be32toh(a->hdr->size);
		else {
			n = (off_t)sizeof(mp4_atom_hdr_t) + mp4_build_atoms(&a->atoms, log);
			a->hdr->size = htobe32(n);
			len += n;
		}
	}

	return len;
}

/*static mp4_atom_t *mp4_find_atom(struct mp4mux_list_head *list, uint32_t type)
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
}*/

static ngx_int_t mp4_tkhd_update(mp4_trak_t *trak, ngx_uint_t id, uint64_t start, uint32_t old_timescale, uint32_t new_timescale)
{
	uint64_t duration;

	trak->tkhd->track_id = htobe32(id);

	duration = (uint64_t)be32toh(trak->tkhd->duration) * 1000 / old_timescale;

	if (start > duration)
		trak->tkhd->duration = 0;
	else
		trak->tkhd->duration = htobe32((duration - start) * new_timescale / 1000);

	return 0;
}

/*
static ngx_int_t mp4_adjust_pos(mp4_trak_t *trak, uint64_t start)
{
	mp4_atom_t *a, *stss_a, *ctts_a;
	mp4_atom_stss_t *stss = NULL;
	mp4_atom_ctts_t *ctts = NULL;
	ngx_uint_t i, skip_samples = 0, skip_duration = 0, n, s, cnt;
	uint32_t samples, duration = 1;

	stss_a = mp4_find_atom(&trak->stbl->atoms, ATOM('s', 't', 's', 's'));
	if (stss_a)
		stss = (mp4_atom_stss_t *)stss_a->hdr;

	ctts_a = mp4_find_atom(&trak->stbl->atoms, ATOM('c', 't', 't', 's'));
	if (ctts_a)
		ctts = (mp4_atom_ctts_t *)ctts_a->hdr;

	start = start * mp4f->timescale / 1000;
	ngx_log_debug2(NGX_LOG_DEBUG_HTTP, mp4f->log, 0,
		"adjust_pos: start=%L duration=%i", start, mp4f->sample_max);
	if (start >= mp4f->sample_max) {
		mp4f->mdhd->duration = 0;
		mp4f->stts->entries = 0;
		mp4f->stts->hdr.size = htobe32(sizeof(*mp4f->stts));
		mp4f->stsz->sample_cnt = 0;
		mp4f->stsz->hdr.size = htobe32(sizeof(*mp4f->stsz));
		if (stss_a) {
			stss->entries = 0;
			stss->hdr.size = htobe32(sizeof(*stss));
		}
		return 0;
	}

	n = be32toh(mp4f->stts->entries);
	for (i = 0; i < n; i++) {
		samples = be32toh(mp4f->stts->tbl[i].count);
		duration = be32toh(mp4f->stts->tbl[i].duration);
		ngx_log_debug3(NGX_LOG_DEBUG_HTTP, mp4f->log, 0,
			"stts[%i]=%i %i", i, samples, duration);
		if (start < (uint64_t)samples * duration)
			break;
		skip_samples += samples;
		skip_duration += (uint64_t)samples * duration;
		start -= (uint64_t)samples * duration;
		mp4f->stts->tbl[i].count = 0;
	}

	skip_samples += start / duration;
	skip_duration += (start / duration) * duration;
	mp4f->stts->tbl[i].count = htobe32(be32toh(mp4f->stts->tbl[i].count) - start / duration);

	ngx_log_debug2(NGX_LOG_DEBUG_HTTP, mp4f->log, 0,
		"adjust_pos: skip_samples=%i skip_duration=%i", skip_samples, skip_duration);

	mp4f->mdhd->duration = htobe32(be32toh(mp4f->mdhd->duration) - skip_duration);

	if (mp4f->stsz->sample_size) {
		mp4f->mdat_pos += be32toh(mp4f->stsz->sample_size) * skip_samples;
		mp4f->mdat_size -= be32toh(mp4f->stsz->sample_size) * skip_samples;
		mp4f->stsz->sample_cnt = htobe32(be32toh(mp4f->stsz->sample_cnt) - skip_samples);
	} else {
		for (i = 0; i < skip_samples; i++) {
			//ngx_log_debug2(NGX_LOG_DEBUG_HTTP, mp4f->log, 0,
			//	"stsz[%i]=%i", i, be32toh(stsz->tbl[i]));
			mp4f->mdat_pos += be32toh(mp4f->stsz->tbl[i]);
			mp4f->mdat_size -= be32toh(mp4f->stsz->tbl[i]);
		}
		//ngx_log_debug2(NGX_LOG_DEBUG_HTTP, mp4f->log, 0,
		//	"stsz[%i]=%i", i, be32toh(stsz->tbl[i]));
		//ngx_log_debug2(NGX_LOG_DEBUG_HTTP, mp4f->log, 0,
		//"stsz[%i]=%i", i+1, be32toh(stsz->tbl[i+1]));
		mp4f->stsz->sample_cnt = htobe32(be32toh(mp4f->stsz->sample_cnt) - skip_samples);
		mp4f->stsz->hdr.size = htobe32(sizeof(*mp4f->stsz) + be32toh(mp4f->stsz->sample_cnt) * 4);
		a = mp4_find_atom(&trak->atoms, ATOM('s', 't', 's', 'z'));
		mp4f->stsz = (mp4_atom_stsz_t *)((char *)(mp4f->stsz->tbl + i) - sizeof(*mp4f->stsz));
		memmove(mp4f->stsz, a->hdr, sizeof(*mp4f->stsz));
		a->hdr = &mp4f->stsz->hdr;
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
}*/

static void *mp4_create_table(mp4_atom_t *stbl, uint32_t atom_type, ngx_int_t size, ngx_pool_t *pool)
{
	mp4_atom_t *a = mp4_alloc_atom(pool, size);
	if (!a)
		return NULL;

	a->hdr->type = atom_type;
	mp4mux_list_add_tail(&a->entry, &stbl->atoms);
	a->hdr->u.data32[0] = 0;
	return a->hdr;
}

static off_t mp4_alloc_chunks(ngx_http_mp4mux_ctx_t *ctx, bool_t co64)
{
	mp4_file_t *f;
	mp4_trak_t *t;
	ngx_pool_t *pool = ctx->hdr_pool ? ctx->hdr_pool : ctx->req->pool;
	ngx_int_t i;
	uint32_t stsc_ptr[MAX_FILE], stco_ptr[MAX_FILE];
	off_t pos = 0;
	ngx_uint_t n;
	uint32_t samples, chunk_size, size;
	uint32_t prev_samples[MAX_FILE];

	ngx_memzero(stsc_ptr, sizeof(stsc_ptr));
	ngx_memzero(stco_ptr, sizeof(stco_ptr));
	ngx_memzero(prev_samples, sizeof(prev_samples));

	ngx_log_debug(NGX_LOG_DEBUG_HTTP, ctx->req->connection->log, 0,
		"alloc chunks");

	ctx->chunk_cnt = 0;
	for (i = 0; i < ctx->trak_cnt; i++) {
		n = (uint64_t)(ctx->mp4_src[i]->sample_max*ctx->chunk_rate+ctx->mp4_src[i]->timescale-1)/ctx->mp4_src[i]->timescale;
		if (n > ctx->chunk_cnt)
			ctx->chunk_cnt = n;
		if (n > htobe32(ctx->mp4_src[i]->trak.stsz->sample_cnt))
			n = htobe32(ctx->mp4_src[i]->trak.stsz->sample_cnt);

		ngx_log_debug2(NGX_LOG_DEBUG_HTTP, ctx->req->connection->log, 0,
			"allocating stsc %i entries %i bytes", n, sizeof(mp4_atom_stsc_t) + n * 12);
		if (!(ctx->traks[i].stsc = mp4_create_table(ctx->traks[i].stbl,
				ATOM('s', 't', 's', 'c'), sizeof(mp4_atom_stsc_t) + n * 12, pool)))
			return NGX_ERROR;

		ngx_log_debug1(NGX_LOG_DEBUG_HTTP, ctx->req->connection->log, 0,
			"allocating stco %i entries", n);
		if (co64)
			ctx->traks[i].co = mp4_create_table(ctx->traks[i].stbl, ATOM('c', 'o', '6', '4'), sizeof(mp4_atom_stco_t) + n * 8, pool);
		else
			ctx->traks[i].co = mp4_create_table(ctx->traks[i].stbl, ATOM('s', 't', 'c', 'o'), sizeof(mp4_atom_stco_t) + n * 4, pool);
		if (!ctx->traks[i].co)
			return NGX_ERROR;
	}

	for (i = 0; i < ctx->trak_cnt; i++)
		ctx->mp4_src[i]->chunks = ngx_palloc(ctx->req->pool, ctx->chunk_cnt * 4);

	for (n = 0; n < ctx->chunk_cnt; n++)
		for (i = 0; i < ctx->trak_cnt; i++) {
			f = ctx->mp4_src[i];
			t = &ctx->traks[i];
			if (!f->eof && (uint64_t)f->sample_no * ctx->chunk_rate < (uint64_t)f->timescale * (n + 1)) {
				if (co64)
					t->co->u.tbl64[stco_ptr[i]++] = pos;
				else
					t->co->u.tbl[stco_ptr[i]++] = pos;
				samples = 0;
				chunk_size = 0;
				do {
					size = be32toh(f->trak.stsz->tbl[f->frame_no]);
					pos += size;
					chunk_size += size;
					samples++;
					if (mp4mux_nextframe(f) != NGX_OK)
						return NGX_ERROR;
				} while (!f->eof && (uint64_t)f->sample_no * ctx->chunk_rate < (uint64_t)f->timescale * (n + 1));
				f->chunks[n] = chunk_size;
				if (samples != prev_samples[i]) {
					t->stsc->tbl[stsc_ptr[i]].first_chunk = htobe32(stco_ptr[i]);
					t->stsc->tbl[stsc_ptr[i]].sample_cnt = htobe32(samples);
					t->stsc->tbl[stsc_ptr[i]].desc_id = htobe32(1);
					stsc_ptr[i]++;
					prev_samples[i] = samples;
				}
            } else
				f->chunks[n] = 0;
		}
	for (i = 0; i < ctx->trak_cnt; i++) {
		t = &ctx->traks[i];
		t->stsc->sample_cnt = htobe32(stsc_ptr[i]);
		t->co  ->chunk_cnt  = htobe32(stco_ptr[i]);
		t->stsc->hdr.size = htobe32(sizeof(mp4_atom_stsc_t) + stsc_ptr[i] * 12);
		t->co  ->hdr.size = htobe32(sizeof(mp4_atom_stco_t) + stco_ptr[i] * (co64 ? 8 : 4));
	}
	return pos;
}

static ngx_int_t mp4_build_chain_ex(ngx_http_mp4mux_ctx_t *ctx, mp4mux_list_t *list, ngx_chain_t **out, ngx_chain_t **last)
{
	mp4_atom_t *a;
	ngx_chain_t *tl;
	ngx_buf_t *b;
	char atom_name[5] = {0,0,0,0,0};

	mp4mux_list_for_each_entry(a, list, entry) {
		tl = ngx_chain_get_free_buf(ctx->req->pool, &ctx->free);
		if (!tl) {
			return NGX_ERROR;
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
		ngx_log_debug2(NGX_LOG_DEBUG_HTTP, ctx->req->connection->log, 0,
			"build_chain: %s %i", atom_name, ngx_buf_size(b));

		b->tag = (ngx_buf_tag_t) &ngx_http_mp4mux_module;
		b->num = MP4MUX_HDR_NUM;

		if (*out)
			(*last)->next = tl;
		else
			*out = tl;
		*last = tl;

		if (!mp4mux_list_empty(&a->atoms)) {
			if (mp4_build_chain_ex(ctx, &a->atoms, out, last))
				return NGX_ERROR;
		}
	}

	return NGX_OK;
}

static ngx_chain_t *mp4_build_chain(ngx_http_mp4mux_ctx_t *ctx, mp4mux_list_t *list)
{
	ngx_chain_t *out = NULL, *last = NULL;

	if (mp4_build_chain_ex(ctx, list, &out, &last) != NGX_OK)
		return NULL;

	last->buf->flush = 1;

	return out;
}

// Cache
static ngx_int_t mp4mux_cache_init(ngx_shm_zone_t *shm_zone, void *data)
{
	ngx_http_mp4mux_main_conf_t *conf = shm_zone->data;
	ngx_slab_pool_t *slab = (ngx_slab_pool_t *)shm_zone->shm.addr;
	mp4mux_cache_header_t *hdr;
	u_char *p;

	ngx_log_debug4(NGX_LOG_DEBUG_HTTP, shm_zone->shm.log, 0,
		"mp4mux_cache_init: shm_zone=%p data=%p conf = %p, chs = %i", shm_zone, data, conf, conf->cache_hash_size);

	if (data) {
		shm_zone->data = data;
		return NGX_OK;
	}
	if (shm_zone->shm.exists) {
		shm_zone->data = slab->data;
		return NGX_OK;
	}
	p = ngx_align_ptr(shm_zone->shm.addr + sizeof(ngx_slab_pool_t), NGX_ALIGNMENT);
	hdr = (void*)p;
	p = ngx_align_ptr(p + sizeof(mp4mux_cache_header_t), NGX_ALIGNMENT);
	hdr->hashtable = (void*)p;
	ngx_memzero(p, conf->cache_hash_size);
	p += conf->cache_hash_size;
	hdr->start = p;
	hdr->end = shm_zone->shm.addr + shm_zone->shm.size;
	hdr->hash_mask = conf->cache_hash_size/sizeof(void*)-1;

	ngx_log_debug5(NGX_LOG_DEBUG_HTTP, shm_zone->shm.log, 0,
		"mp4mux: cache init success, addr=%p hdr=%p hashtable=%p start=%p end=%p",
		shm_zone->shm.addr, hdr, hdr->hashtable, hdr->start, hdr->end);

	hdr->oldest = NULL;
	hdr->newest = NULL;
	hdr->write_pos = hdr->start;
	shm_zone->data = hdr;
	slab->data = hdr;
	return NGX_OK;
}
/*static ngx_int_t mp4mux_cache_reset(ngx_shm_zone_t *shm_zone) {
	mp4mux_cache_header_t *hdr;
	hdr->root = NULL;
	hdr->write_pos = hdr->start;
}*/
static void cache_del_hash(mp4mux_cache_header_t *hdr, mp4mux_cache_entry_t *e) {
	mp4mux_cache_entry_t **he = hdr->hashtable + (e->fname_hash & hdr->hash_mask);
	while (*he != e) he = &(*he)->hash_next;
	*he = e->hash_next;
}
typedef struct {
	mp4mux_cache_header_t *hdr;
	mp4mux_cache_entry_t *e;
	u_char *write_pos, *alloc_start, *alloc_end;
	u_char wrapped;
} alloc_struct;
static ngx_int_t __cache_alloc(alloc_struct *as, mp4_file_t *f, ngx_int_t size) {
	ngx_log_debug3(NGX_LOG_DEBUG_ALLOC, f->file.log, 0,
		"cache_alloc: f=%V size=%i write_pos=%p", &f->fname, size, as->write_pos);
	as->alloc_start = ngx_align_ptr(as->write_pos + sizeof(mp4mux_cache_entry_t) + f->fname.len, SECTOR_SIZE);
	as->alloc_end = ngx_align_ptr(as->alloc_start + size, NGX_ALIGNMENT);
	if (as->wrapped) {
		if (as->write_pos >= as->hdr->write_pos || as->alloc_end > as->hdr->end)
			return NGX_ERROR;
	} else if (as->alloc_end > as->hdr->end) {
		as->wrapped = 1;
		as->write_pos = as->hdr->start;
		if (__cache_alloc(as, f, size) != NGX_OK)
			return NGX_ERROR;
		while ((u_char*)as->e >= as->hdr->write_pos) {
			if ((u_char*)as->e < as->alloc_end && as->e->lock)
				return NGX_ERROR;
			as->e = as->e->next;
		}
		if (!as->e) {
			as->e = as->hdr->oldest;
			as->wrapped = 2;
		}
	}
	ngx_log_debug3(NGX_LOG_DEBUG_ALLOC, f->file.log, 0,
		"cache_alloc: write_pos=%p start=%p end=%p", as->write_pos, as->alloc_start, as->alloc_end);
	return NGX_OK;
}
static mp4mux_cache_entry_t *mp4mux_cache_alloc(mp4_file_t *file, ngx_uint_t size)
{
	ngx_http_mp4mux_main_conf_t *conf = ngx_http_get_module_main_conf(file->req, ngx_http_mp4mux_module);
	ngx_shm_zone_t *shm_zone = conf->cache_zone;
	mp4mux_cache_entry_t **he;
	ngx_slab_pool_t *slab;
	ngx_int_t skip = 0;
	alloc_struct as;

	if (shm_zone == NULL) return NULL;

	slab = (ngx_slab_pool_t *)shm_zone->shm.addr;

	ngx_shmtx_lock(&slab->mutex);

	as.hdr = shm_zone->data;
	as.write_pos = as.hdr->write_pos;
	as.wrapped = 0;
	as.e = as.hdr->oldest;

	if (__cache_alloc(&as, file, size) != NGX_OK)
		goto err;

	if ((u_char*)as.e >= as.write_pos) {
		while ((u_char*)as.e >= as.write_pos && (u_char*)as.e < as.alloc_end) {
			if (as.e->lock) {
				ngx_log_debug2(NGX_LOG_DEBUG_ALLOC, file->file.log, 0,
					"mp4mux_cache_alloc: cache entry %p is locked: %i", as.e, as.e->lock);
				skip++;
				if (skip > conf->cache_maxskip)
					goto err;
				as.write_pos = as.e->end;
				as.e = as.e->next;
				if (!as.e)
					goto err;
				if (__cache_alloc(&as, file, size) != NGX_OK)
					goto err;
			} else
				as.e = as.e->next;
			if (!as.e && as.wrapped == 1) {
				as.e = as.hdr->oldest;
				as.wrapped = 2;
			}
		}
		while (as.hdr->oldest != as.e || as.wrapped-- > 1) {
			if ((u_char*)as.hdr->oldest < as.write_pos || (u_char*)as.hdr->oldest >= as.alloc_end) {
				ngx_log_debug1(NGX_LOG_DEBUG_ALLOC, file->file.log, 0,
					"mp4mux_cache_alloc: skipping entry %p", as.hdr->oldest);
				if (!as.e)
					as.e = as.hdr->oldest;
				as.hdr->newest->next = as.hdr->oldest;
				as.hdr->newest = as.hdr->oldest;
				as.hdr->oldest = as.hdr->oldest->next;
				as.hdr->newest->next = NULL;
			} else {
				ngx_log_debug1(NGX_LOG_DEBUG_ALLOC, file->file.log, 0,
					"mp4mux_cache_alloc: deleting cache entry %p", as.hdr->oldest);
				cache_del_hash(as.hdr, as.hdr->oldest);
				as.hdr->oldest = as.hdr->oldest->next;
				if (!as.hdr->oldest) {
					as.hdr->newest = NULL;
					break;
				}
			}
		}
	}
	ngx_log_debug0(NGX_LOG_DEBUG_ALLOC, file->file.log, 0,
		"mp4mux_cache_alloc: success");
	as.e = (mp4mux_cache_entry_t*)as.write_pos;
	if (as.hdr->newest)
		as.hdr->newest->next = as.e;
	else
		as.hdr->oldest = as.e;
	as.hdr->newest = as.e;

	as.e->lock = MP4MUX_CACHE_LOADING;
	as.e->next = NULL;
	as.e->start = as.alloc_start;
	as.e->end = as.alloc_end;
	as.e->fname_hash = ngx_hash_key(file->fname.data, file->fname.len);
	as.e->fname_len = file->fname.len;
	as.e->file_size = file->file_size;
	as.e->file_mtime = file->file_mtime;
	ngx_memcpy(as.e->fname, file->fname.data, file->fname.len);
	he = as.hdr->hashtable + (as.e->fname_hash & as.hdr->hash_mask);
	as.e->hash_next = *he;
	*he = as.e;
	as.hdr->write_pos = as.alloc_end == as.hdr->end ? as.hdr->start : as.alloc_end;
	ngx_shmtx_unlock(&slab->mutex);
	return as.e;
err:
	ngx_log_debug0(NGX_LOG_DEBUG_ALLOC, file->file.log, 0,
		"mp4mux_cache_alloc: failed");
	ngx_shmtx_unlock(&slab->mutex);
	return NULL;
}
static mp4mux_cache_entry_t *mp4mux_cache_fetch(mp4_file_t *file)
{
	ngx_slab_pool_t *slab;
	mp4mux_cache_header_t *hdr;
	mp4mux_cache_entry_t *e;
	uint32_t hash;
	ngx_shm_zone_t *shm_zone = ((ngx_http_mp4mux_main_conf_t*)ngx_http_get_module_main_conf(
		file->req, ngx_http_mp4mux_module))->cache_zone;

	if (shm_zone == NULL) return NULL;

	slab = (ngx_slab_pool_t *)shm_zone->shm.addr;
	hdr = shm_zone->data;

	ngx_shmtx_lock(&slab->mutex);
	hash = ngx_hash_key(file->fname.data, file->fname.len);
	ngx_log_debug2(NGX_LOG_DEBUG_HTTP, file->file.log, 0,
		"mp4mux_cache_fetch: file %V hash %xd", &file->fname, hash);
	for (e = hdr->hashtable[hash & hdr->hash_mask]; e != NULL; e = e->hash_next) {
		ngx_log_debug1(NGX_LOG_DEBUG_HTTP, file->file.log, 0,
			"mp4mux_cache_fetch: entry %p", e);
		if ((e->fname_hash & hdr->hash_mask) != (hash & hdr->hash_mask)) {
			ngx_log_error(NGX_LOG_ERR, file->file.log, 0,
				"mp4mux cache is broken: invalid hash table entry for %V expected %xd, got %xd",
				&file->fname, hash, e->fname_hash);
			break;
		}
		if (e->fname_hash != hash || e->fname_len != file->fname.len) continue;
		if (ngx_memcmp(e->fname, file->fname.data, e->fname_len)) continue;
		if (e->lock == MP4MUX_CACHE_LOADING) {
			// Another process is loading this cache entry, but we can't get a signal when load gets done
			// file->dontcache will prevent this process from creating duplicate cache entries
			file->dontcache = 1;
			break;
		}
		if(e->file_size != file->file_size
				|| e->file_mtime != file->file_mtime) {
			break;
		}
		ngx_atomic_fetch_add(&e->lock, 1);
		ngx_log_debug3(NGX_LOG_DEBUG_ALLOC, file->file.log, 0,
			"mp4mux cache hit: file=%V ptr=%p lock=%i", &file->fname, e, e->lock);
		ngx_shmtx_unlock(&slab->mutex);
		return e;
	}
	ngx_log_debug1(NGX_LOG_DEBUG_ALLOC, file->file.log, 0,
		"mp4mux cache miss: %V", &file->fname);
	ngx_shmtx_unlock(&slab->mutex);
	return NULL;
}
// Nginx config
static ngx_str_t hls_baseuri_var = ngx_string("hls_baseuri");
static ngx_str_t mp4_filename_var = ngx_string("mp4_filename");
static ngx_int_t ngx_http_mp4mux_add_variables(ngx_conf_t *cf)
{
	ngx_http_variable_t  *var;

	var = ngx_http_add_variable(cf, &hls_baseuri_var, 0);
	if (!var) return NGX_ERROR;
	var->get_handler = mp4mux_hls_get_baseuri;

	var = ngx_http_add_variable(cf, &mp4_filename_var, 0);
	if (!var) return NGX_ERROR;
	var->get_handler = mp4mux_get_mp4_filename;

	return NGX_OK;
}
static void *ngx_http_mp4mux_create_main_conf(ngx_conf_t *cf)
{
	ngx_http_mp4mux_main_conf_t  *conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_mp4mux_main_conf_t));
	if (conf == NULL) return NULL;

	conf->cache_size = NGX_CONF_UNSET_SIZE;
	conf->cache_hash_size = NGX_CONF_UNSET_SIZE;
	conf->cache_maxskip = NGX_CONF_UNSET;

	return conf;
}
static ngx_str_t cache_name = ngx_string("mp4mux_cache");
static char getshift(size_t s)
{
	char result = 0, i;
	for (i = 32; i; i >>= 1)
		if (s >> i) {
			result |= i;
			s >>= i;
		}
	return result;
}
static char *ngx_http_mp4mux_init_main_conf(ngx_conf_t *cf, void *conf)
{
	ngx_http_mp4mux_main_conf_t *myconf = conf;

	if (myconf->cache_zone) {
		ngx_log_error(NGX_LOG_ERR, cf->log, 0,
			"mp4mux: duplicate main conf initialization");
		return NGX_CONF_ERROR;
	}

	if (myconf->cache_maxskip == NGX_CONF_UNSET)
		myconf->cache_maxskip = 3;

	if (myconf->cache_size == NGX_CONF_UNSET_SIZE)
		myconf->cache_size = 128 * 1024 * 1024;

	if (myconf->cache_size) {
		// Sanity checks
		if (myconf->cache_size < 65536)
			myconf->cache_size = 65536;

		if (myconf->cache_hash_size == NGX_CONF_UNSET_SIZE)
			myconf->cache_hash_size = 16384;

		if (myconf->cache_hash_size > myconf->cache_size / 4)
			myconf->cache_hash_size = myconf->cache_size / 4;
		// Adjust hash table size to be power of 2
		myconf->cache_hash_size = 1 << getshift(myconf->cache_hash_size);

		if (myconf->cache_hash_size < 128)
			myconf->cache_hash_size = 128;
	}


	if (myconf->cache_size) {
		if (!(myconf->cache_zone = ngx_shared_memory_add(cf, &cache_name, myconf->cache_size, &ngx_http_mp4mux_module))) {
			ngx_log_error(NGX_LOG_ERR, cf->log, 0,
				"mp4mux: failed to allocate cache, continuing without it");
			return NGX_CONF_OK;
		}
		myconf->cache_zone->init = mp4mux_cache_init;
		myconf->cache_zone->data = conf;
	}
	return NGX_CONF_OK;
}
static void *ngx_http_mp4mux_create_conf(ngx_conf_t *cf)
{
	ngx_http_mp4mux_conf_t  *conf;

	conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_mp4mux_conf_t));
	if (conf == NULL)
		return NULL;

	conf->rdbuf_size = NGX_CONF_UNSET_SIZE;
	conf->wrbuf_size = NGX_CONF_UNSET_SIZE;
	conf->move_meta = NGX_CONF_UNSET;
	conf->seg_align = NGX_CONF_UNSET;
	conf->segment_ms = NGX_CONF_UNSET_MSEC;
	conf->chunk_rate = NGX_CONF_UNSET;

	return conf;
}


static char *ngx_http_mp4mux_merge_conf(ngx_conf_t *cf, void *parent, void *child)
{
	ngx_http_mp4mux_conf_t *prev = parent;
	ngx_http_mp4mux_conf_t *conf = child;
	ngx_http_script_compile_t sc;

	ngx_conf_merge_size_value(conf->rdbuf_size, prev->rdbuf_size, 128 * 1024);
	ngx_conf_merge_size_value(conf->wrbuf_size, prev->wrbuf_size, 128 * 1024);
	ngx_conf_merge_value(conf->move_meta, prev->move_meta, 1);
	ngx_conf_merge_value(conf->seg_align, prev->seg_align, 0);
	ngx_conf_merge_msec_value(conf->segment_ms, prev->segment_ms, 10000);
	ngx_conf_merge_value(conf->chunk_rate, prev->chunk_rate, 10);
	ngx_conf_merge_str_value(conf->hls_prefix,  prev->hls_prefix,  "$scheme://$http_host$hls_baseuri&fmt=hls/");
	ngx_conf_merge_str_value(conf->hls_master_item,  prev->hls_master_item,  "$scheme://$http_host$uri?file0=$mp4_filename&fmt=hls/index.m3u8");
	ngx_conf_merge_str_value(conf->dash_prefix, prev->dash_prefix, "$scheme://$http_host$uri?file0=$mp4_filename&fmt=dash/");

	ngx_memzero(&sc, sizeof(ngx_http_script_compile_t));

	sc.cf = cf;
	sc.complete_lengths = 1;
	sc.complete_values = 1;

	sc.source = &conf->hls_prefix;
	sc.lengths = &conf->hp_lengths;
	sc.values = &conf->hp_values;
	sc.variables = ngx_http_script_variables_count(sc.source);

	if (sc.variables && ngx_http_script_compile(&sc) != NGX_OK)
		return NGX_CONF_ERROR;

	sc.source = &conf->hls_master_item;
	sc.lengths = &conf->mp_lengths;
	sc.values = &conf->mp_values;
	sc.variables = ngx_http_script_variables_count(sc.source);

	if (sc.variables && ngx_http_script_compile(&sc) != NGX_OK)
		return NGX_CONF_ERROR;

	sc.source = &conf->dash_prefix;
	sc.lengths = &conf->dp_lengths;
	sc.values = &conf->dp_values;
	sc.variables = ngx_http_script_variables_count(sc.source);

	if (sc.variables && ngx_http_script_compile(&sc) != NGX_OK)
		return NGX_CONF_ERROR;

	return NGX_CONF_OK;
}
