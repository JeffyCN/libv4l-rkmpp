/*
 *  libv4l-rkmpp: format conversion via CPU fallback
 *
 *  Used when neither MPP_DEC_SET_OUTPUT_FORMAT nor librga can do the
 *  conversion. Handles:
 *
 *    MPP_FMT_YUV420SP         -> NV12    (identity)
 *    MPP_FMT_YUV420SP_10BIT   -> NV12    (compact 10-bit -> NV12, take high 8 bits)
 *    MPP_FMT_YUV422SP         -> NV12    (NV16 -> NV12, 2:1 horiz + 2:1 vert)
 *    MPP_FMT_YUV422_YUYV      -> NV12    (YUYV -> NV12)
 *
 *  Slow on big frames (4K@30 takes ~25% of one A76) but correct. The
 *  point of this path is to never deadlock and never crash, even when
 *  the user has neither an RGA2 driver nor an OK kernel MPP setup.
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
#include <sys/mman.h>
#include <unistd.h>

#include "libv4l-rkmpp.h"
#include "libv4l-rkmpp-convert.h"

/* MPP's reported frame size is unreliable for some layouts (e.g. NV16
 * frames report 2.5 bytes/px while the decoder pool actually allocates
 * the full 3.0). lseek(SEEK_END) on a dmabuf returns the real
 * allocation size -- use that when it is larger. */
static size_t dmabuf_real_size(int fd, size_t reported)
{
	off_t real = lseek(fd, 0, SEEK_END);

	if (real > 0 && (size_t)real > reported)
		return (size_t)real;
	return reported;
}

static int mmap_buffer(int fd, size_t size, void **out_ptr)
{
	void *p = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (p == MAP_FAILED)
		return -errno;
	*out_ptr = p;
	return 0;
}

static void munmap_buffer(void *ptr, size_t size)
{
	if (ptr && ptr != MAP_FAILED)
		munmap(ptr, size);
}

int rkmpp_dec_convert_cpu(struct rkmpp_context *ctx,
			  struct rkmpp_buffer *src,
			  struct rkmpp_buffer *dst,
			  MppFrameFormat src_fmt,
			  MppFrameFormat dst_fmt,
			  uint32_t width, uint32_t height,
			  uint32_t hor_stride, uint32_t ver_stride)
{
	void *src_y = NULL, *dst_y = NULL;
	size_t src_size, dst_size, src_size_real;
	uint32_t y_size, uv_size;
	int ret;

	(void)ctx;

	if (dst_fmt != MPP_FMT_YUV420SP) {
		LOGE("cpu: dst must be NV12 (got %d)\n", dst_fmt);
		return -ENOTSUP;
	}

	/*
	 * Both buffers are sized to the same NV12 layout by rkmpp_reqbufs
	 * (capture queue uses NV12 sizeimage for every buffer including
	 * the spare).
	 */
	y_size = hor_stride * ver_stride;
	uv_size = y_size / 2;
	dst_size = y_size + uv_size;
	/* NOTE for MPP_FMT_YUV422SP: rkvdec H.264 4:2:2 frames are NOT
	 * standard NV16. The chroma plane holds CbCr pairs at FULL width
	 * but HALF height (hor_stride pairs x ver_stride/2 rows), so the
	 * frame spans 2.0 bytes/px (Y 1.0 + chroma 1.0), not NV16's 3.0.
	 * Verified by dumping a frame and cross-checking against a
	 * software-decoded reference.
	 *
	 * NOTE for MPP_FMT_YUV420SP_10BIT: the compact 10-bit packing
	 * (4 samples in 5 bytes) spans 1.5 bytes/px (Y 1.0 + chroma
	 * 0.5, hor_stride being a BYTE pitch), NOT P010's 3.0. MPP
	 * reports the frame size accordingly (1.8 bytes/px including
	 * padding). */
	src_size = (src_fmt == MPP_FMT_YUV420SP_10BIT) ? y_size + y_size / 2
		: (src_fmt == MPP_FMT_YUV422SP) ? y_size * 2
		: (src_fmt == MPP_FMT_YUV422_YUYV) ? y_size * 2
		: y_size + uv_size;

	/*
	 * The size check must use the real allocation, not the reported
	 * frame size: for NV16 MPP reports 2.5 bytes/px but the pool
	 * allocates the full 3.0, and the chroma downsampler below reads
	 * every chroma row up to ver_stride. If the real allocation is
	 * genuinely too small, fail cleanly instead of faulting.
	 */
	src_size_real = dmabuf_real_size(src->fd, src->size);
	if (src_size_real < src_size || dst->size < dst_size) {
		LOGE("cpu: buffer too small (src=%zu/%u dst=%zu/%u)\n",
		     src_size_real, (unsigned)src_size, dst->size,
		     (unsigned)dst_size);
		return -EINVAL;
	}

	ret = mmap_buffer(src->fd, src_size, &src_y);
	if (ret) {
		LOGE("cpu: mmap src failed: %d\n", ret);
		return ret;
	}
	ret = mmap_buffer(dst->fd, dst_size, &dst_y);
	if (ret) {
		LOGE("cpu: mmap dst failed: %d\n", ret);
		munmap_buffer(src_y, src_size);
		return ret;
	}

	switch (src_fmt) {
	case MPP_FMT_YUV420SP: {
		/* Identity copy (with stride fix-up if hor_stride != width) */
		const uint8_t *sy = (const uint8_t *)src_y;
		const uint8_t *suv = (const uint8_t *)src_y + y_size;
		uint8_t *dy = (uint8_t *)dst_y;
		uint8_t *duv = (uint8_t *)dst_y + y_size;
		uint32_t row;

		if (hor_stride == width) {
			memcpy(dy, sy, y_size);
			memcpy(duv, suv, uv_size);
		} else {
			for (row = 0; row < ver_stride; row++) {
				memcpy(dy + row * hor_stride,
				       sy + row * hor_stride,
				       hor_stride);
			}
			for (row = 0; row < ver_stride / 2; row++) {
				memcpy(duv + row * hor_stride,
				       suv + row * hor_stride,
				       hor_stride);
			}
		}
		ret = 0;
		break;
	}

	case MPP_FMT_YUV420SP_10BIT: {
		/*
		 * rkvdec compact 10-bit (the NV12_10LE40 / NV15 packing,
		 * NOT P010): 4 x 10-bit samples in 5 bytes, LSB-first,
		 * and hor_stride is a BYTE pitch (ALIGN(w * 10 / 8)).
		 * Luma plane: hor_stride x ver_stride bytes; chroma:
		 * same packing at half height, right behind it. Take the
		 * high 8 bits of every sample for NV12 output, matching
		 * MPP's own dump helper (utils.c rearrange_pix).
		 */
		const uint8_t *sy = (const uint8_t *)src_y;
		const uint8_t *sc = sy + y_size;
		uint8_t *dy = (uint8_t *)dst_y;
		uint8_t *duv = (uint8_t *)dst_y + y_size;
		uint32_t i, j;

		for (i = 0; i < height; i++) {
			const uint8_t *p = sy + i * hor_stride;
			for (j = 0; j < width; j++) {
				uint32_t bit = j * 10;
				uint32_t o = bit >> 3, sh = bit & 7;
				uint32_t v = ((p[o] | (p[o + 1] << 8)) >>
					      sh) & 0x3FF;
				dy[i * hor_stride + j] = (uint8_t)(v >> 2);
			}
		}
		for (i = 0; i < height / 2; i++) {
			const uint8_t *p = sc + i * hor_stride;
			for (j = 0; j < width / 2; j++) {
				uint32_t bit = j * 20;
				uint32_t o = bit >> 3, sh = bit & 7;
				uint32_t u = ((p[o] | (p[o + 1] << 8)) >>
					      sh) & 0x3FF;
				uint32_t v = ((p[o + 1] | (p[o + 2] << 8)) >>
					      (sh + 2)) & 0x3FF;
				duv[i * hor_stride + 2 * j] =
					(uint8_t)(u >> 2);
				duv[i * hor_stride + 2 * j + 1] =
					(uint8_t)(v >> 2);
			}
		}
		ret = 0;
		break;
	}

	case MPP_FMT_YUV422SP: {
		/* rkvdec H.264 "4:2:2": chroma pairs sit at FULL width
		 * but HALF height (hor_stride pairs x ver_stride/2 rows).
		 * Downsample into NV12: dst pair dx averages the src
		 * pairs of luma cols 2dx and 2dx+1 (bytes 4dx..4dx+3
		 * of chroma row y). */
		const uint8_t *sy = (const uint8_t *)src_y;
		const uint8_t *sch = (const uint8_t *)src_y + y_size;
		uint8_t *dy = (uint8_t *)dst_y;
		uint8_t *duv = (uint8_t *)dst_y + y_size;
		uint32_t y, x;

		for (y = 0; y < height; y++) {
			memcpy(dy + y * hor_stride,
			       sy + y * hor_stride,
			       hor_stride);
		}
		for (y = 0; y < height / 2; y++) {
			const uint8_t *r0 = sch + y * hor_stride * 2;
			uint32_t dx;

			for (dx = 0; dx < width / 2; dx++) {
				uint32_t p0 = 4 * dx, p1 = 4 * dx + 2;
				uint32_t cb = ((uint32_t)r0[p0] + r0[p1] + 1) / 2;
				uint32_t cr = ((uint32_t)r0[p0 + 1] +
					       r0[p1 + 1] + 1) / 2;
				duv[y * hor_stride + 2 * dx]     = (uint8_t)cb;
				duv[y * hor_stride + 2 * dx + 1] = (uint8_t)cr;
			}
		}
		ret = 0;
		break;
	}

	case MPP_FMT_YUV422_YUYV: {
		/* YUYV: per 2-pixel pair, byte layout is Y0 Cb Y1 Cr. */
		const uint8_t *s = (const uint8_t *)src_y;
		uint8_t *dy = (uint8_t *)dst_y;
		uint8_t *duv = (uint8_t *)dst_y + y_size;
		uint32_t y, x;

		for (y = 0; y < ver_stride; y++) {
			if (y < height) {
				for (x = 0; x < hor_stride; x++)
					dy[y * hor_stride + x] =
						s[y * hor_stride * 2 + 2 * x];
			}
		}
		for (y = 0; y + 1 < ver_stride; y += 2) {
			for (x = 0; x + 1 < hor_stride; x += 2) {
				/* Cb is at +1, Cr is at +3 of each 4-byte pair */
				uint32_t cb00 = (y + 0) * hor_stride * 2 + 2 * x + 1;
				uint32_t cb01 = (y + 0) * hor_stride * 2 + 2 * (x + 1) + 1;
				uint32_t cb10 = (y + 1) * hor_stride * 2 + 2 * x + 1;
				uint32_t cb11 = (y + 1) * hor_stride * 2 + 2 * (x + 1) + 1;
				uint32_t cr00 = cb00 + 2;
				uint32_t cr01 = cb01 + 2;
				uint32_t cr10 = cb10 + 2;
				uint32_t cr11 = cb11 + 2;
				uint32_t cb = ((uint32_t)s[cb00] +
					       (uint32_t)s[cb01] +
					       (uint32_t)s[cb10] +
					       (uint32_t)s[cb11] + 2) / 4;
				uint32_t cr = ((uint32_t)s[cr00] +
					       (uint32_t)s[cr01] +
					       (uint32_t)s[cr10] +
					       (uint32_t)s[cr11] + 2) / 4;
				duv[(y / 2) * hor_stride + x]     = (uint8_t)cb;
				duv[(y / 2) * hor_stride + x + 1] = (uint8_t)cr;
			}
		}
		ret = 0;
		break;
	}

	default:
		LOGE("cpu: unsupported src fmt %d\n", src_fmt);
		ret = -ENOTSUP;
		break;
	}

	munmap_buffer(src_y, src_size);
	munmap_buffer(dst_y, dst_size);

	if (ret == 0)
		LOGV(1, "cpu convert: fmt %d -> 0 %ux%u ok\n",
		     src_fmt, width, height);
	return ret;
}

int rkmpp_dec_convert_frame(struct rkmpp_context *ctx,
			    struct rkmpp_buffer *src,
			    struct rkmpp_buffer *dst,
			    MppFrameFormat src_fmt,
			    MppFrameFormat dst_fmt,
			    uint32_t width, uint32_t height,
			    uint32_t hor_stride, uint32_t ver_stride)
{
	int ret;

	/* Identity (NV12 -> NV12 with stride fix-up) -- just memcpy. */
	if (src_fmt == MPP_FMT_YUV420SP) {
		return rkmpp_dec_convert_cpu(ctx, src, dst, src_fmt, dst_fmt,
					     width, height,
					     hor_stride, ver_stride);
	}

	/* Try RGA first (DMA, 0% CPU). Returns -ENOTSUP for unknown fmts. */
	ret = rkmpp_dec_convert_rga(ctx, src, dst, src_fmt, dst_fmt,
				    width, height, hor_stride, ver_stride);
	if (ret == 0) {
		LOGV(1, "convert: rga fmt %d -> 0 %ux%u\n",
		     src_fmt, width, height);
		return 0;
	}
	if (ret != -ENOTSUP && ret != -ENODEV && ret != -EIO) {
		LOGE("convert: rga failed (%d), not retrying\n", ret);
		return ret;
	}
	LOGV(1, "convert: rga not available (ret=%d), trying gpu\n", ret);

	/* Try Mali GPU (EGL + GLES2). Returns -ENOTSUP on init failure. */
	ret = rkmpp_dec_convert_gpu(ctx, src, dst, src_fmt, dst_fmt,
				    width, height, hor_stride, ver_stride);
	if (ret == 0) {
		LOGV(1, "convert: gpu fmt %d -> 0 %ux%u\n",
		     src_fmt, width, height);
		return 0;
	}
	if (ret != -ENOTSUP && ret != -ENODEV) {
		LOGE("convert: gpu failed (%d), not retrying\n", ret);
		return ret;
	}
	LOGV(1, "convert: gpu not available (ret=%d), falling back to cpu\n", ret);

	/* Last resort: CPU path. */
	return rkmpp_dec_convert_cpu(ctx, src, dst, src_fmt, dst_fmt,
				     width, height, hor_stride, ver_stride);
}
