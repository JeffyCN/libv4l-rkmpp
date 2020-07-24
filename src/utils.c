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

#include <xf86drm.h>
#include <sys/mman.h>

#include "libv4l-rkmpp.h"

#ifdef HAVE_RGA
#include <rga/rga.h>
#include <rga/RgaApi.h>
#endif

static int rkmpp_rga_copy(struct rkmpp_context *ctx,
			  const struct v4l2_pix_format_mplane *format,
			  const struct rkmpp_fmt *rkmpp_format,
			  int rkmpp_fd, void *v4l2_addr,
			  int copy_to)
{
#ifdef HAVE_RGA
	RgaSURF_FORMAT rga_format;
	rga_info_t src_info = {0};
	rga_info_t dst_info = {0};
	uint32_t pix_fmt = format->pixelformat;
	int width = format->width;
	int height = format->height;
	int vir_w = format->plane_fmt[0].bytesperline * 8 /
		rkmpp_format->depth[0];
	int vir_h = format->plane_fmt[0].sizeimage /
		format->plane_fmt[0].bytesperline;

	static int rga_supported = 1;
	static int rga_inited = 0;

	if (!rga_supported)
		return -1;

	if (!rga_inited) {
		if (c_RkRgaInit() < 0) {
			LOGE("failed to init rga\n");
			rga_supported = 0;
			return -1;
		}
		rga_inited = 1;
	}

	switch (pix_fmt) {
	case V4L2_PIX_FMT_NV12:
	case V4L2_PIX_FMT_NV12M:
		rga_format = RK_FORMAT_YCbCr_420_SP;
		break;
	case V4L2_PIX_FMT_NV21:
	case V4L2_PIX_FMT_NV21M:
		rga_format = RK_FORMAT_YCrCb_420_SP;
		break;
	case V4L2_PIX_FMT_YUV420:
	case V4L2_PIX_FMT_YUV420M:
		rga_format = RK_FORMAT_YCbCr_420_P;
		break;
	case V4L2_PIX_FMT_YVU420:
	case V4L2_PIX_FMT_YVU420M:
		rga_format = RK_FORMAT_YCrCb_420_P;
		break;
	case V4L2_PIX_FMT_YUYV:
		rga_format = RK_FORMAT_YCbCr_422_P;
		break;
	case V4L2_PIX_FMT_YVYU:
		rga_format = RK_FORMAT_YCrCb_422_P;
		break;
	default:
		LOGV(3, "unsupported format\n");
		return -1;
	}

	src_info.fd = rkmpp_fd;
	src_info.mmuFlag = 1;
	rga_set_rect(&src_info.rect, 0, 0, width, height,
		     vir_w, vir_h, rga_format);

	dst_info.virAddr = v4l2_addr;
	dst_info.mmuFlag = 1;
	rga_set_rect(&dst_info.rect, 0, 0, width, height,
		     vir_w, vir_h, rga_format);

	if (copy_to)
		return c_RkRgaBlit(&src_info, &dst_info, NULL) >= 0;
	else
		return c_RkRgaBlit(&dst_info, &src_info, NULL) >= 0;
#else
	return -1;
#endif
}

static int rkmpp_copy_buffer(struct rkmpp_context *ctx,
			     struct rkmpp_buffer *rkmpp_buffer,
			     struct v4l2_buffer *buffer, int copy_to)
{
	struct rkmpp_buf_queue *queue;
	const struct rkmpp_fmt *rkmpp_format;
	const struct v4l2_pix_format_mplane *format;
	void *rkmpp_ptr;
	void *addrs[3] = {0};
	uint32_t sizes[3], offsets[3];
	int i, ret = -1;

	ENTER();

	if (buffer->length > 3) {
		LOGE("wrong buffer planes: %d\n", buffer->length);
		return -1;
	}

	/* Nothing to do for mmap buffer */
	if (buffer->memory == V4L2_MEMORY_MMAP)
		return 0;

	queue = rkmpp_get_queue(ctx, buffer->type);
	if (!queue)
		return -1;

	rkmpp_ptr = mpp_buffer_get_ptr(rkmpp_buffer->rkmpp_buf);
	rkmpp_format = queue->rkmpp_format;
	format = &queue->format;

	/* Prepare access */
	for (i = 0; i < buffer->length; i++) {
		sizes[i] = rkmpp_buffer->planes[i].plane_size;
		offsets[i] = rkmpp_buffer->planes[i].data_offset;

		if (!sizes[i])
			goto out;

		if (buffer->memory == V4L2_MEMORY_DMABUF) {
			int fd = rkmpp_buffer->planes[i].fd;
			addrs[i] = mmap(NULL, sizes[i],
					PROT_READ | PROT_WRITE,
					MAP_SHARED, fd, offsets[i]);
			if (addrs[i] == MAP_FAILED)
				goto out;
		} else {
			addrs[i] = (void *)rkmpp_buffer->planes[i].userptr;
			if (!addrs[i])
				goto out;

			addrs[i] += offsets[i];
		}

		offsets[i] = i == 0 ? 0 : offsets[i - 1] + sizes[i - 1];
	}

	/* Copy compressed data directly */
	if (rkmpp_format->type != MPP_VIDEO_CodingNone)
		goto bail;

	/* Check contig buffer for RGA */
	for (i = 0; i < buffer->length; i++) {
		if (addrs[i] != addrs[0] + offsets[i])
			goto bail;
	}

	if (rkmpp_rga_copy(ctx, format, rkmpp_format,
			   rkmpp_buffer->fd, addrs[0], copy_to) < 0)
		goto bail;

	ret = 0;
	goto out;
bail:
	LOGV(4, "fallback to software copy\n");

	for (i = 0; i < buffer->length; i++) {
		if (offsets[i] + sizes[i] > rkmpp_buffer->size) {
			LOGE("buffer overflow!\n");
			goto out;
		}

		if (copy_to) {
			uint32_t size = rkmpp_buffer->planes[i].bytesused;

			if (!size)
				size = sizes[i];

			memcpy(addrs[i], rkmpp_ptr + offsets[i], size);
			buffer->m.planes[i].bytesused = size;
		} else {
			uint32_t size = buffer->m.planes[i].bytesused;

			if (!size)
				size = sizes[i];

			memcpy(rkmpp_ptr + offsets[i], addrs[i], size);
			rkmpp_buffer->planes[i].bytesused = size;
		}
	}

	ret = 0;
out:
	if (buffer->memory == V4L2_MEMORY_DMABUF) {
		/* Finish access for dma buffer */
		for (i = 0; i < buffer->length; i++) {
			if (!addrs[i] || addrs[i] == MAP_FAILED)
				break;

			munmap(addrs[i], sizes[i]);
		}
	}

	LEAVE();
	return ret;
}

int rkmpp_to_v4l2_buffer(struct rkmpp_context *ctx,
			 struct rkmpp_buffer *rkmpp_buffer,
			 struct v4l2_buffer *buffer)
{
	struct drm_mode_map_dumb args = {0};
	int i, ret;

	ENTER();

	if (buffer->length != rkmpp_buffer->length) {
		LOGE("wrong buffer planes: %d(expected: %d)\n",
		     buffer->length, rkmpp_buffer->length);
		return -1;
	}

	ret = drmPrimeFDToHandle(ctx->drm_fd, rkmpp_buffer->fd, &args.handle);
	if (ret < 0) {
		LOGE("failed to get drm handle from fd: %d)\n",
		     rkmpp_buffer->fd);
		return ret;
	}

	ret = drmIoctl(ctx->drm_fd, DRM_IOCTL_MODE_MAP_DUMB, &args);
	if (ret < 0) {
		LOGE("failed to map drm dumb from fd: %d)\n",
		     rkmpp_buffer->fd);
		return ret;
	}

	rkmpp_buffer->mem_offset = args.offset;

	for (i = 0; i < buffer->length; i++) {
		buffer->m.planes[i].length = rkmpp_buffer->planes[i].length;
		buffer->m.planes[i].data_offset =
			rkmpp_buffer->planes[i].data_offset;
		buffer->m.planes[i].bytesused = 0;

		if (buffer->memory == V4L2_MEMORY_MMAP)
			/* Only support mem_offset for plane 0 */
			buffer->m.planes[i].m.mem_offset = i ? 0 :
				RKMPP_MEM_OFFSET(buffer->type, buffer->index);
		else if (buffer->memory == V4L2_MEMORY_USERPTR)
			buffer->m.planes[i].m.userptr =
				rkmpp_buffer->planes[i].userptr;
		else if (buffer->memory == V4L2_MEMORY_DMABUF)
			buffer->m.planes[i].m.fd =
				rkmpp_buffer->planes[i].fd;
	}

	if (rkmpp_buffer_available(rkmpp_buffer) && rkmpp_buffer->bytesused) {
		/* Returning data are always in plane 0 */
		rkmpp_buffer->planes[0].bytesused = rkmpp_buffer->bytesused;
		buffer->m.planes[0].bytesused = rkmpp_buffer->bytesused;

		if (rkmpp_copy_buffer(ctx, rkmpp_buffer, buffer, 1) < 0)
			return -1;
	}

	buffer->timestamp.tv_sec = rkmpp_buffer->timestamp / 1000000;
	buffer->timestamp.tv_usec = rkmpp_buffer->timestamp % 1000000;

	buffer->flags = 0;
	if (rkmpp_buffer_keyframe(rkmpp_buffer))
		buffer->flags |= V4L2_BUF_FLAG_KEYFRAME;
	if (rkmpp_buffer_error(rkmpp_buffer))
		buffer->flags |= V4L2_BUF_FLAG_ERROR;
	if (rkmpp_buffer_queued(rkmpp_buffer)) {
		buffer->flags |= V4L2_BUF_FLAG_QUEUED;
		if (rkmpp_buffer_available(rkmpp_buffer))
			buffer->flags |= V4L2_BUF_FLAG_DONE;
		else
			buffer->flags |= V4L2_BUF_FLAG_PREPARED;
	}

	buffer->field = V4L2_FIELD_NONE;
	memset(&buffer->timecode, 0, sizeof(buffer->timecode));
	buffer->sequence = 0;

	buffer->index = rkmpp_buffer->index;

	LEAVE();
	return 0;
}

int rkmpp_from_v4l2_buffer(struct rkmpp_context *ctx,
			   struct v4l2_buffer *buffer,
			   struct rkmpp_buffer *rkmpp_buffer)
{
	int i;

	ENTER();

	rkmpp_buffer->length = buffer->length;

	for (i = 0; i < buffer->length; i++) {
		rkmpp_buffer->planes[i].length = buffer->m.planes[i].length;
		rkmpp_buffer->planes[i].data_offset =
			buffer->m.planes[i].data_offset;
		rkmpp_buffer->planes[i].bytesused =
			buffer->m.planes[i].bytesused;
		rkmpp_buffer->planes[i].plane_size =
			rkmpp_buffer->planes[i].bytesused -
			rkmpp_buffer->planes[i].data_offset;

		rkmpp_buffer->bytesused +=
			rkmpp_buffer->planes[i].plane_size;

		if (buffer->memory == V4L2_MEMORY_USERPTR)
			rkmpp_buffer->planes[i].userptr =
				buffer->m.planes[i].m.userptr;
		else if (buffer->memory == V4L2_MEMORY_DMABUF)
			rkmpp_buffer->planes[i].fd =
				buffer->m.planes[i].m.fd;
	}

	if (rkmpp_buffer->bytesused) {
		if (rkmpp_copy_buffer(ctx, rkmpp_buffer, buffer, 0) < 0)
			return -1;
	}

	rkmpp_buffer->timestamp =
		(uint64_t)buffer->timestamp.tv_sec * 1000000 +
		buffer->timestamp.tv_usec;

	LEAVE();
	return 0;
}
