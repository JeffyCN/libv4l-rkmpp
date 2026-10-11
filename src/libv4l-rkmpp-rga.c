/*
 *  libv4l-rkmpp: format conversion via Rockchip RGA2
 *
 *  Used as a fallback when MPP_DEC_SET_OUTPUT_FORMAT cannot force
 *  the decoder to emit the format advertised in the V4L2 capture
 *  queue (e.g. 8-bit NV12). The two cases that hit this path today
 *  are:
 *
 *    10-bit HEVC Main10 -> MPP_FMT_YUV420SP_10BIT (P010 packed)
 *    H.264 High 4:2:2  -> MPP_FMT_YUV422SP        (NV16)
 *
 *  Implemented with librga 2.x (im2d_*). The board this plugin
 *  ships on has RGA2 nodes (fdb60000.rga / fdb70000.rga) and
 *  librga.so.2.1.0, so a 4K@30 blit fits comfortably in DMA
 *  bandwidth and costs essentially zero CPU.
 *
 *  Copyright (c) 2024, Fuzhou Rockchip Electronics Co., Ltd
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 */

#include <errno.h>
#include <stdint.h>
#include <string.h>

#include "config.h"
#include "libv4l-rkmpp.h"
#include "libv4l-rkmpp-convert.h"

#if HAVE_RGA

#include <rga/RgaApi.h>
#include <rga/drmrga.h>
#include <rga/im2d.h>
#include <rga/im2d_type.h>

static int rga_format_of(MppFrameFormat fmt)
{
	switch (fmt) {
	case MPP_FMT_YUV420SP:
		return RK_FORMAT_YCbCr_420_SP;
	case MPP_FMT_YUV420SP_VU:
		return RK_FORMAT_YCrCb_420_SP;
	case MPP_FMT_YUV420SP_10BIT:
		return RK_FORMAT_YCbCr_420_SP_10B;
	case MPP_FMT_YUV422SP:
		return RK_FORMAT_YCbCr_422_SP;
	case MPP_FMT_YUV422SP_VU:
		return RK_FORMAT_YCrCb_422_SP;
	default:
		return RK_FORMAT_UNKNOWN;
	}
}

static bool rga_avail;

static void rga_try_init(void)
{
	if (rga_avail)
		return;
	if (c_RkRgaInit() == 0)
		rga_avail = true;
}

int rkmpp_dec_convert_rga(struct rkmpp_context *ctx,
			  struct rkmpp_buffer *src,
			  struct rkmpp_buffer *dst,
			  MppFrameFormat src_fmt,
			  MppFrameFormat dst_fmt,
			  uint32_t width, uint32_t height,
			  uint32_t hor_stride, uint32_t ver_stride)
{
	rga_info_t src_info = { 0 };
	rga_info_t dst_info = { 0 };
	int sfmt, dfmt;
	int ret;

	(void)ctx;

	if (src_fmt == dst_fmt) {
		LOGV(2, "no conversion needed (fmt=%d)\n", src_fmt);
		return 0;
	}

	rga_try_init();
	if (!rga_avail) {
		LOGE("rga not available, cannot convert fmt %d -> %d\n",
		     src_fmt, dst_fmt);
		return -ENOTSUP;
	}

	sfmt = rga_format_of(src_fmt);
	dfmt = rga_format_of(dst_fmt);
	if (sfmt == RK_FORMAT_UNKNOWN || dfmt == RK_FORMAT_UNKNOWN) {
		LOGE("rga: unsupported fmt %d -> %d\n", src_fmt, dst_fmt);
		return -ENOTSUP;
	}

	src_info.fd = src->fd;
	src_info.mmuFlag = 1;
	rga_set_rect(&src_info.rect, 0, 0,
		     width, height,
		     hor_stride, ver_stride,
		     sfmt);

	dst_info.fd = dst->fd;
	dst_info.mmuFlag = 1;
	rga_set_rect(&dst_info.rect, 0, 0,
		     width, height,
		     hor_stride, ver_stride,
		     dfmt);

	ret = c_RkRgaBlit(&src_info, &dst_info, NULL);
	if (ret) {
		LOGE("rga blit failed: %d (src fmt=%d dst fmt=%d)\n",
		     ret, src_fmt, dst_fmt);
		return -EIO;
	}

	LOGV(1, "rga blit: fmt %d -> %d %ux%u ok\n",
	     src_fmt, dst_fmt, width, height);
	return 0;
}

#else /* !HAVE_RGA */

int rkmpp_dec_convert_rga(struct rkmpp_context *ctx,
			  struct rkmpp_buffer *src,
			  struct rkmpp_buffer *dst,
			  MppFrameFormat src_fmt,
			  MppFrameFormat dst_fmt,
			  uint32_t width, uint32_t height,
			  uint32_t hor_stride, uint32_t ver_stride)
{
	(void)ctx; (void)src; (void)dst;
	(void)width; (void)height; (void)hor_stride; (void)ver_stride;
	LOGE("format conversion (mpp fmt %d -> %d) requested but built without librga\n",
	     src_fmt, dst_fmt);
	return -ENOTSUP;
}

#endif
