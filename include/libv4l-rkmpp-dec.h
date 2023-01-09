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

#ifndef LIBV4L_RKMPP_DEC_H
#define LIBV4L_RKMPP_DEC_H

#include "libv4l-rkmpp.h"

#ifndef V4L2_PIX_FMT_VP9
#define V4L2_PIX_FMT_VP9	v4l2_fourcc('V', 'P', '9', '0') /* VP9 */
#endif

#ifndef V4L2_PIX_FMT_HEVC
#define V4L2_PIX_FMT_HEVC	v4l2_fourcc('H', 'E', 'V', 'C') /* HEVC */
#endif

#ifndef V4L2_PIX_FMT_AV1
#define V4L2_PIX_FMT_AV1	v4l2_fourcc('A', 'V', '0', '1') /* AV1 */
#endif

/**
 * struct rkmpp_video_info - Video information
 * @valid:		Data is valid.
 * @dirty:		Data is dirty(have not applied to mpp).
 * @event:		Pending V4L2 src_change event.
 * @width:		Video width.
 * @height:		Video height.
 * @hor_stride:		Video horizontal stride.
 * @ver_stride:		Video vertical stride.
 * @size:		Required video buffer size.
 */
struct rkmpp_video_info {
	bool valid;
	bool dirty;
	bool event;

	uint32_t width;
	uint32_t height;
	uint32_t hor_stride;
	uint32_t ver_stride;

	uint32_t size;
};

/**
 * struct rkmpp_dec_context - Context private data for decoder
 * @ctx:		Common context data.
 * @video_info:		Video information.
 * @event_subscribed:	V4L2 event subscribed.
 * @mpp_streaming:	The mpp is streaming.
 * @decoder_thread:	Handler of the decoder thread.
 * @decoder_cond:	Condition variable for streaming flag.
 * @decoder_mutex:	Mutex for streaming flag and buffers.
 */
struct rkmpp_dec_context {
	struct rkmpp_context *ctx;
	struct rkmpp_video_info video_info;

	bool event_subscribed;

	bool mpp_streaming;

	struct rkmpp_buffer *eos_packet;

	pthread_t decoder_thread;
	pthread_cond_t decoder_cond;
	pthread_mutex_t decoder_mutex;
};

bool rkmpp_dec_has_event(void *data);
void *rkmpp_dec_init(struct rkmpp_context *ctx);
int rkmpp_dec_ioctl(void *data, unsigned long cmd, void *arg);
void rkmpp_dec_deinit(void *data);

#endif //LIBV4L_RKMPP_DEC_H
