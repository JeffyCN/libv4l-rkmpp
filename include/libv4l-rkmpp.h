/*
 *  Copyright (c) 2019, Fuzhou Rockchip Electronics Co., Ltd
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 */

#ifndef LIBV4L_RKMPP_H
#define LIBV4L_RKMPP_H

#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <inttypes.h>
#include <sys/queue.h>
#include <sys/syscall.h>

#include <rockchip/rk_mpi.h>

#include "config.h"
#include "linux/videodev2.h"

#define LIBV4L_RKMPP_VERSION "1.5.1~20221108"

extern int rkmpp_log_level;

#define gettid() syscall(SYS_gettid)

#define LOG(fmt, ...) do { \
	struct timeval tv; \
	gettimeofday(&tv, NULL); \
	printf("[%03ld.%03ld] [RKMPP] [%ld] %s(%d): " fmt, \
	       tv.tv_sec % 1000, tv.tv_usec / 1000, gettid(), \
	       __func__, __LINE__, ##__VA_ARGS__); \
	fflush(stdout); \
	} while (0)

#define LOGV(level, fmt, ...) \
	do { if (rkmpp_log_level >= level) LOG(fmt, ##__VA_ARGS__); } while (0)

#define LOGE(fmt, ...) LOG("ERR: " fmt, ##__VA_ARGS__)

#define RETURN_ERR(err, ret) \
	{ errno = err; LOGV(2, "errno: %d\n", errno); return ret; }

#define ENTER()			LOGV(5, "ctx(%p): ENTER\n", (void *)ctx)
#define LEAVE()			LOGV(5, "ctx(%p): LEAVE\n", (void *)ctx)

#define min(x, y) ((x) < (y) ? (x) : (y))
#define max(x, y) ((x) > (y) ? (x) : (y))

/* From kernel's linux/kernel.h */
#define ARRAY_SIZE(arr)		(sizeof(arr) / sizeof((arr)[0]))

#define clamp(val, lo, hi) 	min((typeof(val))max(val, lo), hi)

#define __round_mask(x, y)	((__typeof__(x))((y)-1))
#define round_up(x, y)		((((x)-1) | __round_mask(x, y))+1)

/* From kernel's linux/stddef.h */
#ifndef offsetof
#define offsetof(TYPE, MEMBER)	((size_t)&((TYPE *)0)->MEMBER)
#endif

/* From kernel's v4l2-core/v4l2-ioctl.c */
#define CLEAR_AFTER_FIELD(p, field) \
	memset((uint8_t *)(p) + \
	       offsetof(typeof(*(p)), field) + sizeof((p)->field), \
	       0, sizeof(*(p)) - \
	       offsetof(typeof(*(p)), field) - sizeof((p)->field))

#define MPP_VIDEO_CodingNone	MPP_VIDEO_CodingUnused

#define RKMPP_MB_DIM		16
#define RKMPP_SB_DIM		64

#define RKMPP_MAX_PLANE		3

#define RKMPP_MEM_OFFSET(type, index) \
	((int64_t) ((type) << 16 | (index)))
#define RKMPP_MEM_OFFSET_TYPE(offset)	(int)((offset) >> 16)
#define RKMPP_MEM_OFFSET_INDEX(offset)	(int)((offset) & ((1 << 16) - 1))

#define RKMPP_HAS_FORMAT(ctx, format) \
	(!((format)->type != MPP_VIDEO_CodingNone && (ctx)->codecs && \
	   !strstr((ctx)->codecs, (format)->name)))

/**
 * struct rkmpp_fmt - Information about mpp supported format
 * @name:		Format's name.
 * @fourcc:		Format's forcc.
 * @num_planes:		Number of planes.
 * @type:		Format's mpp coding type.
 * @format:		Format's mpp frame format.
 * @depth:		Format's pixel depth.
 * @frmsize:		V4L2 frmsize_stepwise.
 */
struct rkmpp_fmt {
	char *name;
	uint32_t fourcc;
	int num_planes;
	MppCodingType type;
	MppFrameFormat format;
	uint8_t depth[VIDEO_MAX_PLANES];
	struct v4l2_frmsize_stepwise frmsize;
};

/**
 * enum rkmpp_buffer_flag - Flags of rkmpp buffer
 * @ERROR:		Something wrong in the buffer.
 * @LOCKED:		Buffer been locked from mpp buffer group.
 * @EXPORTED:		Buffer been exported to userspace.
 * @QUEUED:		Buffer been queued.
 * @PENDING:		Buffer is in pending queue.
 * @AVAILABLE:		Buffer is in available queue.
 */
enum rkmpp_buffer_flag {
	RKMPP_BUFFER_ERROR	= 1 << 0,
	RKMPP_BUFFER_LOCKED	= 1 << 1,
	RKMPP_BUFFER_EXPORTED	= 1 << 2,
	RKMPP_BUFFER_QUEUED	= 1 << 3,
	RKMPP_BUFFER_PENDING	= 1 << 4,
	RKMPP_BUFFER_AVAILABLE	= 1 << 5,
	RKMPP_BUFFER_KEYFRAME	= 1 << 6,
};

/**
 * struct rkmpp_buffer - Information about mpp buffer
 * @entry:		Queue entry.
 * @rkmpp_buf:		Handle of mpp buffer.
 * @index:		Buffer's index.
 * @fd:			Buffer's dma fd.
 * @timestamp:		Buffer's timestamp.
 * @bytesused:		Number of bytes occupied by data in the buffer.
 * @length:		Buffer's length(planes).
 * @size:		Buffer's size.
 * @flags:		Buffer's flags.
 * @planes:		Buffer's planes info.
 */
struct rkmpp_buffer {
	TAILQ_ENTRY(rkmpp_buffer) entry;
	MppBuffer rkmpp_buf;

	int index;

	int fd;
	uint64_t timestamp;
	uint32_t bytesused;
	uint32_t length;
	uint32_t flags;
	uint32_t size;
	uint32_t type;

	struct {
		unsigned long userptr;
		int fd;
		uint32_t data_offset;
		uint32_t bytesused;
		uint32_t plane_size; /* bytesused - data_offset */
		uint32_t length;
	} planes[RKMPP_MAX_PLANE];
};

TAILQ_HEAD(rkmpp_buf_head, rkmpp_buffer);

/**
 * struct rkmpp_buf_head - Information about mpp buffer queue
 * @memory:		V4L2 memory type.
 * @streaming:		The queue is streaming.
 * @internal_group:	Handle of mpp internal buffer group.
 * @external_group:	Handle of mpp external buffer group.
 * @buffers:		List of buffers.
 * @num_buffers:	Number of buffers.
 * @avail_buffers:	Buffers ready to be dequeued.
 * @pending_buffers:	Pending buffers for mpp.
 * @queue_mutex:	Mutex for buffer lists.
 * @rkmpp_format:	Mpp format.
 * @format:		V4L2 multi-plane format.
 */
struct rkmpp_buf_queue {
	enum v4l2_memory memory;

	bool streaming;

	MppBufferGroup internal_group;
	MppBufferGroup external_group;
	struct rkmpp_buffer *buffers;
	uint32_t num_buffers;

	struct rkmpp_buf_head avail_buffers;
	struct rkmpp_buf_head pending_buffers;
	pthread_mutex_t queue_mutex;

	const struct rkmpp_fmt *rkmpp_format;
	struct v4l2_pix_format_mplane format;
};

/**
 * struct rkmpp_context - Context data
 * @formats:		Supported formats.
 * @num_formats:	Number of formats.
 * @is_decoder:		Is decoder mode.
 * @nonblock:		Nonblock mode.
 * @eventfd:		File descriptor of eventfd.
 * @avail_buffers:	Buffers ready to be dequeued.
 * @pending_buffers:	Pending buffers for mpp.
 * @mpp:		Handler of mpp context.
 * @mpi:		Handler of mpp api.
 * @output:		Output queue.
 * @capture:		Capture queue.
 * @ioctl_mutex:	Mutex.
 * @frames:		Number of frames reported.
 * @last_fps_time:	The last time to count fps.
 * @data:		Private data.
 */
struct rkmpp_context {
	struct rkmpp_fmt *formats;
	uint32_t num_formats;

	bool is_decoder;
	bool nonblock;
	int eventfd;

	MppCtx mpp;
	MppApi *mpi;

	struct rkmpp_buf_queue output;
	struct rkmpp_buf_queue capture;

	pthread_mutex_t ioctl_mutex;

	uint64_t frames;
	uint64_t last_fps_time;

	unsigned int max_width;
	unsigned int max_height;
	char *codecs;

	void *data;
};

static inline
struct rkmpp_buf_queue *rkmpp_get_queue(struct rkmpp_context *ctx,
					enum v4l2_buf_type type)
{
	LOGV(4, "type = %d\n", type);

	switch (type) {
	case V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE:
		return &ctx->capture;
	case V4L2_BUF_TYPE_VIDEO_OUTPUT_MPLANE:
		return &ctx->output;
	default:
		LOGE("invalid buf type\n");
		RETURN_ERR(EINVAL, NULL);
	}
}

static inline
const char* rkmpp_cmd2str(unsigned long cmd)
{
#define RKMPP_CMD2STR(cmd) case cmd: return #cmd

	switch (cmd) {
	RKMPP_CMD2STR(VIDIOC_QUERYCAP);
	RKMPP_CMD2STR(VIDIOC_ENUM_FMT);
	RKMPP_CMD2STR(VIDIOC_G_FMT);
	RKMPP_CMD2STR(VIDIOC_S_FMT);
	RKMPP_CMD2STR(VIDIOC_REQBUFS);
	RKMPP_CMD2STR(VIDIOC_QUERYBUF);
	RKMPP_CMD2STR(VIDIOC_G_FBUF);
	RKMPP_CMD2STR(VIDIOC_S_FBUF);
	RKMPP_CMD2STR(VIDIOC_OVERLAY);
	RKMPP_CMD2STR(VIDIOC_QBUF);
	RKMPP_CMD2STR(VIDIOC_EXPBUF);
	RKMPP_CMD2STR(VIDIOC_DQBUF);
	RKMPP_CMD2STR(VIDIOC_STREAMON);
	RKMPP_CMD2STR(VIDIOC_STREAMOFF);
	RKMPP_CMD2STR(VIDIOC_G_PARM);
	RKMPP_CMD2STR(VIDIOC_S_PARM);
	RKMPP_CMD2STR(VIDIOC_G_STD);
	RKMPP_CMD2STR(VIDIOC_S_STD);
	RKMPP_CMD2STR(VIDIOC_ENUMSTD);
	RKMPP_CMD2STR(VIDIOC_ENUMINPUT);
	RKMPP_CMD2STR(VIDIOC_G_CTRL);
	RKMPP_CMD2STR(VIDIOC_S_CTRL);
	RKMPP_CMD2STR(VIDIOC_G_TUNER);
	RKMPP_CMD2STR(VIDIOC_S_TUNER);
	RKMPP_CMD2STR(VIDIOC_G_AUDIO);
	RKMPP_CMD2STR(VIDIOC_S_AUDIO);
	RKMPP_CMD2STR(VIDIOC_QUERYCTRL);
	RKMPP_CMD2STR(VIDIOC_QUERYMENU);
	RKMPP_CMD2STR(VIDIOC_G_INPUT);
	RKMPP_CMD2STR(VIDIOC_S_INPUT);
	RKMPP_CMD2STR(VIDIOC_G_EDID);
	RKMPP_CMD2STR(VIDIOC_S_EDID);
	RKMPP_CMD2STR(VIDIOC_G_OUTPUT);
	RKMPP_CMD2STR(VIDIOC_S_OUTPUT);
	RKMPP_CMD2STR(VIDIOC_ENUMOUTPUT);
	RKMPP_CMD2STR(VIDIOC_G_AUDOUT);
	RKMPP_CMD2STR(VIDIOC_S_AUDOUT);
	RKMPP_CMD2STR(VIDIOC_G_MODULATOR);
	RKMPP_CMD2STR(VIDIOC_S_MODULATOR);
	RKMPP_CMD2STR(VIDIOC_G_FREQUENCY);
	RKMPP_CMD2STR(VIDIOC_S_FREQUENCY);
	RKMPP_CMD2STR(VIDIOC_CROPCAP);
	RKMPP_CMD2STR(VIDIOC_G_CROP);
	RKMPP_CMD2STR(VIDIOC_S_CROP);
	RKMPP_CMD2STR(VIDIOC_G_JPEGCOMP);
	RKMPP_CMD2STR(VIDIOC_S_JPEGCOMP);
	RKMPP_CMD2STR(VIDIOC_QUERYSTD);
	RKMPP_CMD2STR(VIDIOC_TRY_FMT);
	RKMPP_CMD2STR(VIDIOC_ENUMAUDIO);
	RKMPP_CMD2STR(VIDIOC_ENUMAUDOUT);
	RKMPP_CMD2STR(VIDIOC_G_PRIORITY);
	RKMPP_CMD2STR(VIDIOC_S_PRIORITY);
	RKMPP_CMD2STR(VIDIOC_G_SLICED_VBI_CAP);
	RKMPP_CMD2STR(VIDIOC_LOG_STATUS);
	RKMPP_CMD2STR(VIDIOC_G_EXT_CTRLS);
	RKMPP_CMD2STR(VIDIOC_S_EXT_CTRLS);
	RKMPP_CMD2STR(VIDIOC_TRY_EXT_CTRLS);
	RKMPP_CMD2STR(VIDIOC_ENUM_FRAMESIZES);
	RKMPP_CMD2STR(VIDIOC_ENUM_FRAMEINTERVALS);
	RKMPP_CMD2STR(VIDIOC_G_ENC_INDEX);
	RKMPP_CMD2STR(VIDIOC_ENCODER_CMD);
	RKMPP_CMD2STR(VIDIOC_TRY_ENCODER_CMD);
	RKMPP_CMD2STR(VIDIOC_DBG_S_REGISTER);
	RKMPP_CMD2STR(VIDIOC_DBG_G_REGISTER);
	RKMPP_CMD2STR(VIDIOC_S_HW_FREQ_SEEK);
	RKMPP_CMD2STR(VIDIOC_S_DV_TIMINGS);
	RKMPP_CMD2STR(VIDIOC_G_DV_TIMINGS);
	RKMPP_CMD2STR(VIDIOC_DQEVENT);
	RKMPP_CMD2STR(VIDIOC_SUBSCRIBE_EVENT);
	RKMPP_CMD2STR(VIDIOC_UNSUBSCRIBE_EVENT);
	RKMPP_CMD2STR(VIDIOC_CREATE_BUFS);
	RKMPP_CMD2STR(VIDIOC_PREPARE_BUF);
	RKMPP_CMD2STR(VIDIOC_G_SELECTION);
	RKMPP_CMD2STR(VIDIOC_S_SELECTION);
	RKMPP_CMD2STR(VIDIOC_DECODER_CMD);
	RKMPP_CMD2STR(VIDIOC_TRY_DECODER_CMD);
	RKMPP_CMD2STR(VIDIOC_ENUM_DV_TIMINGS);
	RKMPP_CMD2STR(VIDIOC_QUERY_DV_TIMINGS);
	RKMPP_CMD2STR(VIDIOC_DV_TIMINGS_CAP);
	RKMPP_CMD2STR(VIDIOC_ENUM_FREQ_BANDS);
	RKMPP_CMD2STR(VIDIOC_DBG_G_CHIP_INFO);
	RKMPP_CMD2STR(VIDIOC_QUERY_EXT_CTRL);
	default:
		return "UNKNOWN";
	}
}

#define RKMPP_BUFFER_FLAG_HELPER_GET(flag, name) \
static inline bool rkmpp_buffer_## name(struct rkmpp_buffer *buffer) \
{ \
	return !!(buffer->flags & flag); \
}

#define RKMPP_BUFFER_FLAG_HELPER_SET(flag, name) \
static inline void rkmpp_buffer_set_ ## name(struct rkmpp_buffer *buffer) \
{ \
	LOGV(4, "buffer: %d type: %d\n", buffer->index, buffer->type); \
	if (rkmpp_buffer_ ## name(buffer)) \
		LOGE("buffer: %d type: %d is already " #name "\n", \
		     buffer->index, buffer->type); \
	buffer->flags |= flag; \
}

#define RKMPP_BUFFER_FLAG_HELPER_CLR(flag, name) \
static inline void rkmpp_buffer_clr_ ## name(struct rkmpp_buffer *buffer) \
{ \
	LOGV(4, "buffer: %d type: %d\n", buffer->index, buffer->type); \
	if (!rkmpp_buffer_ ## name(buffer)) \
		LOGE("buffer: %d type: %d is not " #name "\n", \
		     buffer->index, buffer->type); \
	buffer->flags &= ~flag; \
}

#define RKMPP_BUFFER_FLAG_HELPERS(flag, name) \
	RKMPP_BUFFER_FLAG_HELPER_GET(flag, name) \
	RKMPP_BUFFER_FLAG_HELPER_SET(flag, name) \
	RKMPP_BUFFER_FLAG_HELPER_CLR(flag, name)

RKMPP_BUFFER_FLAG_HELPERS(RKMPP_BUFFER_ERROR, error)
RKMPP_BUFFER_FLAG_HELPERS(RKMPP_BUFFER_LOCKED, locked)
RKMPP_BUFFER_FLAG_HELPERS(RKMPP_BUFFER_EXPORTED, exported)
RKMPP_BUFFER_FLAG_HELPERS(RKMPP_BUFFER_QUEUED, queued)
RKMPP_BUFFER_FLAG_HELPERS(RKMPP_BUFFER_PENDING, pending)
RKMPP_BUFFER_FLAG_HELPERS(RKMPP_BUFFER_AVAILABLE, available)
RKMPP_BUFFER_FLAG_HELPERS(RKMPP_BUFFER_KEYFRAME, keyframe)

void rkmpp_new_frame(struct rkmpp_context *ctx);
int rkmpp_update_poll_event(struct rkmpp_context *ctx);
int rkmpp_querycap(struct rkmpp_context *ctx, struct v4l2_capability *cap);
int rkmpp_enum_fmt(struct rkmpp_context *ctx, struct v4l2_fmtdesc *f);
int rkmpp_enum_framesizes(struct rkmpp_context *ctx,
			  struct v4l2_frmsizeenum *fsize);
int rkmpp_try_fmt(struct rkmpp_context *ctx, struct v4l2_format *f);
int rkmpp_s_fmt(struct rkmpp_context *ctx, struct v4l2_format *f);
int rkmpp_g_fmt(struct rkmpp_context *ctx, struct v4l2_format *f);
int rkmpp_reqbufs(struct rkmpp_context *ctx,
		  struct v4l2_requestbuffers *reqbufs);
int rkmpp_querybuf(struct rkmpp_context *ctx, struct v4l2_buffer *buffer);
int rkmpp_expbuf(struct rkmpp_context *ctx,
		 struct v4l2_exportbuffer *expbuf);
int rkmpp_qbuf(struct rkmpp_context *ctx, struct v4l2_buffer *buffer);
int rkmpp_dqbuf(struct rkmpp_context *ctx, struct v4l2_buffer *buffer);

/* Utils */

int rkmpp_to_v4l2_buffer(struct rkmpp_context *ctx,
			 struct rkmpp_buffer *rkmpp_buffer,
			 struct v4l2_buffer *buffer);
int rkmpp_from_v4l2_buffer(struct rkmpp_context *ctx,
			   struct v4l2_buffer *buffer,
			   struct rkmpp_buffer *rkmpp_buffer);

#endif //LIBV4L_RKMPP_H
