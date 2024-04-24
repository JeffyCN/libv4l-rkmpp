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

#include <sys/mman.h>

#include "libv4l-rkmpp.h"

static int rkmpp_copy_buffer(struct rkmpp_context *ctx,
			     struct rkmpp_buffer *rkmpp_buffer,
			     struct v4l2_buffer *buffer, int copy_to)
{
	struct rkmpp_buf_queue *queue;
	char *rkmpp_ptr;
	char *addrs[3] = {0};
	uint32_t sizes[3], offsets[3];
	unsigned int i;
	int ret = -1;

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

	LOGV(3, "doing software copy\n");

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
	unsigned int i;

	ENTER();

	if (buffer->length != rkmpp_buffer->length) {
		LOGE("wrong buffer planes: %d(expected: %d)\n",
		     buffer->length, rkmpp_buffer->length);
		return -1;
	}

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
	if (rkmpp_buffer_last(rkmpp_buffer))
		buffer->flags |= V4L2_BUF_FLAG_LAST;
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
	unsigned int i;

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

	/* Clear special flags */
	if (rkmpp_buffer_keyframe(rkmpp_buffer))
		rkmpp_buffer_clr_keyframe(rkmpp_buffer);
	if (rkmpp_buffer_error(rkmpp_buffer))
		rkmpp_buffer_clr_error(rkmpp_buffer);
	if (rkmpp_buffer_last(rkmpp_buffer))
		rkmpp_buffer_clr_last(rkmpp_buffer);

	LEAVE();
	return 0;
}
