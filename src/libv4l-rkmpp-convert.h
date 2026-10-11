/*
 *  libv4l-rkmpp: format conversion dispatch
 *
 *  The convert frame function is the single entry point used by the
 *  decoder worker thread. It tries, in order:
 *
 *    1. RGA2 (librga)        - DMA, 0% CPU, the preferred path
 *    2. Mali GPU (GLES2/EGL) - GPU color-space convert + CPU chroma
 *    3. CPU (this file)      - slow but always works
 *
 *  Each tier may return -ENOTSUP for "I don't know how to convert
 *  this format"; the dispatcher falls through to the next tier.
 *
 *  Copyright (c) 2024, Fuzhou Rockchip Electronics Co., Ltd
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 */

#ifndef LIBV4L_RKMPP_CONVERT_H
#define LIBV4L_RKMPP_CONVERT_H

#include "libv4l-rkmpp.h"

int rkmpp_dec_convert_rga(struct rkmpp_context *ctx,
			  struct rkmpp_buffer *src,
			  struct rkmpp_buffer *dst,
			  MppFrameFormat src_fmt,
			  MppFrameFormat dst_fmt,
			  uint32_t width, uint32_t height,
			  uint32_t hor_stride, uint32_t ver_stride);

int rkmpp_dec_convert_gpu(struct rkmpp_context *ctx,
			  struct rkmpp_buffer *src,
			  struct rkmpp_buffer *dst,
			  MppFrameFormat src_fmt,
			  MppFrameFormat dst_fmt,
			  uint32_t width, uint32_t height,
			  uint32_t hor_stride, uint32_t ver_stride);

int rkmpp_dec_convert_cpu(struct rkmpp_context *ctx,
			  struct rkmpp_buffer *src,
			  struct rkmpp_buffer *dst,
			  MppFrameFormat src_fmt,
			  MppFrameFormat dst_fmt,
			  uint32_t width, uint32_t height,
			  uint32_t hor_stride, uint32_t ver_stride);

/* Dispatcher: tries RGA, then GPU, then CPU. Logs which tier won. */
int rkmpp_dec_convert_frame(struct rkmpp_context *ctx,
			    struct rkmpp_buffer *src,
			    struct rkmpp_buffer *dst,
			    MppFrameFormat src_fmt,
			    MppFrameFormat dst_fmt,
			    uint32_t width, uint32_t height,
			    uint32_t hor_stride, uint32_t ver_stride);

#endif
