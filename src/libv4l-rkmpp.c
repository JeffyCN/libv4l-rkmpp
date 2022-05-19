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

#include <fcntl.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/mman.h>
#include <linux/version.h>

#include "libv4l-plugin.h"
#include "libv4l-rkmpp.h"
#include "libv4l-rkmpp-dec.h"
#include "libv4l-rkmpp-enc.h"

#if HAVE_VISIBILITY
#define PLUGIN_PUBLIC __attribute__ ((__visibility__("default")))
#else
#define PLUGIN_PUBLIC
#endif

#define FPS_UPDATE_INTERVAL 120

#ifdef DEBUG
int rkmpp_log_level = 10;
static bool rkmpp_log_fps = true;
#else
int rkmpp_log_level = 0;
static bool rkmpp_log_fps = false;
#endif

static pthread_once_t g_rkmpp_global_init_once = PTHREAD_ONCE_INIT;

static void rkmpp_global_init()
{
	char *env = getenv("LIBV4L_RKMPP_LOG_LEVEL");
	if (env != NULL)
		rkmpp_log_level = atoi(env);

	env = getenv("LIBV4L_RKMPP_LOG_FPS");
	if (env != NULL)
		rkmpp_log_fps = !!atoi(env);

	LOGV(1, "libv4l-rkmpp version: %s log_level: %d, log_fps: %d\n",
	     LIBV4L_RKMPP_VERSION, rkmpp_log_level, rkmpp_log_fps);
}

void rkmpp_new_frame(struct rkmpp_context *ctx)
{
	struct timeval tv;
	uint64_t curr_time;
	float fps;

	if (!rkmpp_log_fps)
		return;

	if (!ctx->last_fps_time) {
		gettimeofday(&tv, NULL);
		ctx->last_fps_time = tv.tv_sec * 1000 + tv.tv_usec / 1000;
	}

	if (++ctx->frames % FPS_UPDATE_INTERVAL)
		return;

	gettimeofday(&tv, NULL);
	curr_time = tv.tv_sec * 1000 + tv.tv_usec / 1000;

	fps = 1000.0f * FPS_UPDATE_INTERVAL / (curr_time - ctx->last_fps_time);
	ctx->last_fps_time = curr_time;

	LOG("%s FPS: %6.1f || Frames: %" PRIu64 "\n",
	    ctx->is_decoder ? "DEC" : "ENC", fps, ctx->frames);
}

static void rkmpp_destroy_buffers(struct rkmpp_context *ctx,
				  struct rkmpp_buf_queue *queue)
{
	int i;

	if (!queue->num_buffers)
		return;

	if (queue->buffers) {
		for (i = 0; i < queue->num_buffers; i++) {
			if (rkmpp_buffer_locked(&queue->buffers[i]))
				mpp_buffer_put(queue->buffers[i].rkmpp_buf);
		}

		free(queue->buffers);
		queue->buffers = NULL;
	}

	mpp_buffer_group_clear(queue->internal_group);

	if (queue->external_group)
		mpp_buffer_group_clear(queue->external_group);

	queue->num_buffers = 0;
}

static const
struct rkmpp_fmt *rkmpp_find_fmt(struct rkmpp_context *ctx,
				 uint32_t fourcc)
{
	int i;
	for (i = 0; i < ctx->num_formats; i++) {
		if (ctx->formats[i].fourcc == fourcc)
			return &ctx->formats[i];
	}

	return NULL;
}

int rkmpp_querycap(struct rkmpp_context *ctx, struct v4l2_capability *cap)
{
	ENTER();

	strncpy((char *)cap->driver, "rkmpp", sizeof(cap->driver));
	strncpy((char *)cap->card, "rkmpp", sizeof(cap->card));
	strncpy((char *)cap->bus_info, "platform: rkmpp",
		sizeof(cap->bus_info));

	cap->version = LINUX_VERSION_CODE;

	/* This is only a mem-to-mem video device. */
	cap->device_caps = V4L2_CAP_VIDEO_M2M_MPLANE | V4L2_CAP_STREAMING;
	cap->capabilities = cap->device_caps | V4L2_CAP_DEVICE_CAPS;

	cap->capabilities |= V4L2_CAP_EXT_PIX_FORMAT;
	cap->device_caps |= V4L2_CAP_EXT_PIX_FORMAT;

	LEAVE();
	return 0;
}

int rkmpp_enum_fmt(struct rkmpp_context *ctx, struct v4l2_fmtdesc *f)
{
	const struct rkmpp_fmt *fmt;
	bool compressed;
	int i, j;

	ENTER();

	switch (f->type) {
	case V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE:
		compressed = !ctx->is_decoder;
		break;
	case V4L2_BUF_TYPE_VIDEO_OUTPUT_MPLANE:
		compressed = ctx->is_decoder;
		break;
	default:
		LOGE("invalid buf type\n");
		RETURN_ERR(EINVAL, -1);
	}

	for (i = 0, j = 0; i < ctx->num_formats; ++i) {
		fmt = &ctx->formats[i];
		if (!compressed && (fmt->type != MPP_VIDEO_CodingNone))
			continue;
		else if (compressed && (fmt->type == MPP_VIDEO_CodingNone))
			continue;

		if (j == f->index) {
			strncpy((char *)f->description, fmt->name,
				sizeof(f->description));
			f->pixelformat = fmt->fourcc;

			f->flags = 0;
			if (fmt->type != MPP_VIDEO_CodingNone)
				f->flags |= V4L2_FMT_FLAG_COMPRESSED;

			LEAVE();
			return 0;
		}

		++j;
	}

	LOGV(1, "%s format(%d) not found\n",
	     compressed ? "compressed" : "raw", f->index);
	RETURN_ERR(EINVAL, -1);
}

int rkmpp_enum_framesizes(struct rkmpp_context *ctx,
			  struct v4l2_frmsizeenum *fsize)
{
	const struct rkmpp_fmt *fmt;

	ENTER();

	if (fsize->index != 0) {
		LOGE("invalid frame size index (expected 0, got %d)\n",
		     fsize->index);
		RETURN_ERR(EINVAL, -1);
	}

	fmt = rkmpp_find_fmt(ctx, fsize->pixel_format);
	if (!fmt) {
		LOGE("unsupported bitstream format (%08x)\n",
		     fsize->pixel_format);
		RETURN_ERR(EINVAL, -1);
	}

	fsize->type = V4L2_FRMSIZE_TYPE_STEPWISE;
	fsize->stepwise = fmt->frmsize;

	LEAVE();
	return 0;
}

static void calculate_plane_sizes(const struct rkmpp_fmt *fmt,
                                  struct v4l2_pix_format_mplane *pix_fmt_mp)
{
	unsigned int w = pix_fmt_mp->width;
	unsigned int h = pix_fmt_mp->height;
	int i;

	for (i = 0; i < fmt->num_planes; ++i) {
		pix_fmt_mp->plane_fmt[i].bytesperline = w * fmt->depth[i] / 8;
		pix_fmt_mp->plane_fmt[i].sizeimage = h *
			pix_fmt_mp->plane_fmt[i].bytesperline;
		/*
		 * All of multiplanar formats we support have chroma
		 * planes subsampled by 2 vertically.
		 */
		if (i != 0)
			pix_fmt_mp->plane_fmt[i].sizeimage /= 2;
	}
}

int rkmpp_try_fmt(struct rkmpp_context *ctx, struct v4l2_format *f)
{
	const struct rkmpp_fmt *fmt;
	struct v4l2_pix_format_mplane *pix_fmt_mp = &f->fmt.pix_mp;
	bool compressed;

	ENTER();

	switch (f->type) {
	case V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE:
		compressed = !ctx->is_decoder;
		break;
	case V4L2_BUF_TYPE_VIDEO_OUTPUT_MPLANE:
		compressed = ctx->is_decoder;
		break;
	default:
		LOGE("invalid buf type\n");
		RETURN_ERR(EINVAL, -1);
	}

	fmt = rkmpp_find_fmt(ctx, pix_fmt_mp->pixelformat);
	if (!fmt) {
		LOGE("failed to find %s format\n",
		     compressed ? "compressed" : "raw");
		RETURN_ERR(EINVAL, -1);
	}

	if (compressed) {
		if (pix_fmt_mp->plane_fmt[0].sizeimage == 0) {
			LOGE("sizeimage of compressed format must be given\n");
			RETURN_ERR(EINVAL, -1);
		}

		pix_fmt_mp->num_planes = fmt->num_planes;
		pix_fmt_mp->plane_fmt[0].bytesperline = 0;
	} else {
		struct rkmpp_buf_queue *queue =
			ctx->is_decoder ? &ctx->output : &ctx->capture;

		pix_fmt_mp->num_planes = fmt->num_planes;

		/* Limit to hardware min/max. */
		pix_fmt_mp->width = clamp(pix_fmt_mp->width,
					  queue->rkmpp_format->frmsize.min_width,
					  queue->rkmpp_format->frmsize.max_width);
		pix_fmt_mp->height = clamp(pix_fmt_mp->height,
					   queue->rkmpp_format->frmsize.min_height,
					   queue->rkmpp_format->frmsize.max_height);
		/* Round up to macroblocks. */
		pix_fmt_mp->width = round_up(pix_fmt_mp->width, RKMPP_MB_DIM);
		pix_fmt_mp->height = round_up(pix_fmt_mp->height, RKMPP_MB_DIM);

		/* Fill in remaining fields. */
		calculate_plane_sizes(fmt, pix_fmt_mp);
	}

	LEAVE();
	return 0;
}

int rkmpp_s_fmt(struct rkmpp_context *ctx, struct v4l2_format *f)
{
	struct v4l2_pix_format_mplane *pix_fmt_mp = &f->fmt.pix_mp;
	struct rkmpp_buf_queue *queue;
	int ret;

	ENTER();

	queue = rkmpp_get_queue(ctx, f->type);
	if (!queue)
		RETURN_ERR(errno, -1);

	if (queue->streaming) {
		LOGE("cannot do s_fmt during streaming\n");
		RETURN_ERR(EBUSY, -1);
	}

	if (queue->num_buffers) {
		LOGE("cannot do s_fmt after reqbufs\n");
		RETURN_ERR(EBUSY, -1);
	}

	CLEAR_AFTER_FIELD(f, fmt.pix_mp);

	ret = rkmpp_try_fmt(ctx, f);
	if (ret) {
		LOGE("failed to try fmt\n");
		RETURN_ERR(EINVAL, -1);
	}

	queue->rkmpp_format =
		rkmpp_find_fmt(ctx, pix_fmt_mp->pixelformat);
	queue->format = *pix_fmt_mp;

	LEAVE();
	return 0;
}

int rkmpp_g_fmt(struct rkmpp_context *ctx, struct v4l2_format *f)
{
	struct rkmpp_buf_queue *queue;

	ENTER();

	LOGV(4, "f->type = %d\n", f->type);

	queue = rkmpp_get_queue(ctx, f->type);
	if (!queue)
		RETURN_ERR(errno, -1);

	f->fmt.pix_mp = queue->format;

	LEAVE();
	return 0;
}

int rkmpp_reqbufs(struct rkmpp_context *ctx,
		  struct v4l2_requestbuffers *reqbufs)
{
	struct rkmpp_buf_queue *queue;
	MppBufferInfo commit;
	MppBuffer buffer;
	MPP_RET ret;
	uint32_t sizeimage;
	int i;

	ENTER();

	queue = rkmpp_get_queue(ctx, reqbufs->type);
	if (!queue)
		RETURN_ERR(errno, -1);

	if (queue->streaming) {
		LOGE("cannot do reqbufs during streaming\n");
		RETURN_ERR(EBUSY, -1);
	}

	if (!reqbufs->count) {
		LOGV(1, "release buffers\n");
		rkmpp_destroy_buffers(ctx, queue);
		goto out;
	}

	if (queue->num_buffers)
		rkmpp_destroy_buffers(ctx, queue);

	for (i = 0, sizeimage = 0; i < queue->format.num_planes; i++)
		sizeimage += queue->format.plane_fmt[i].sizeimage;

	if (!sizeimage) {
		LOGE("unable to create buffers\n");
		goto err;
	}

	LOGV(1, "sizeimage: %d, count: %d\n", sizeimage, reqbufs->count);

	pthread_mutex_lock(&queue->queue_mutex);
	TAILQ_INIT(&queue->avail_buffers);
	TAILQ_INIT(&queue->pending_buffers);
	pthread_mutex_unlock(&queue->queue_mutex);

	/* Update poll event after avail list changed */
	rkmpp_update_poll_event(ctx);

	queue->memory = reqbufs->memory;
	queue->num_buffers = reqbufs->count;

	queue->buffers = (struct rkmpp_buffer *)
		calloc(queue->num_buffers, sizeof(struct rkmpp_buffer));
	if (!queue->buffers)
		goto err;

	/* Allocate all buffers from main buffer pool */
	for (i = 0; i < queue->num_buffers; i++) {
		ret = mpp_buffer_get(queue->internal_group,
				     &buffer, sizeimage);
		if (ret != MPP_OK) {
			LOGE("unable to alloc buffer\n");
			goto err;
		}

		mpp_buffer_set_index(buffer, i);
		queue->buffers[i].rkmpp_buf = buffer;
		queue->buffers[i].fd = mpp_buffer_get_fd(buffer);
		queue->buffers[i].size = sizeimage;
		queue->buffers[i].index = i;
		queue->buffers[i].length = queue->format.num_planes;
		queue->buffers[i].planes[0].length = sizeimage;
		rkmpp_buffer_set_locked(&queue->buffers[i]);

		LOGV(1, "create buffer(%d), fd: %d\n",
		     i, queue->buffers[i].fd);
	}

	if (!queue->external_group)
		goto out;

	/* External buffer mode (for pre-allocated buffers) */
	for (i = 0; i < queue->num_buffers; i++) {
		buffer = queue->buffers[i].rkmpp_buf;

		/* Move buffers into queue's buffer pool */
		mpp_buffer_info_get(buffer, &commit);
		ret = mpp_buffer_commit(queue->external_group, &commit);
		if (ret != MPP_OK) {
			LOGE("unable to commit buffer\n");
			goto err;
		}
		mpp_buffer_put(buffer);

		/* Lock all buffers again */
		ret = mpp_buffer_get(queue->external_group, &buffer, sizeimage);
		if (ret != MPP_OK) {
			LOGE("unable to lock buffer\n");
			goto err;
		}

		queue->buffers[i].rkmpp_buf = buffer;
		queue->buffers[i].fd = mpp_buffer_get_fd(buffer);

		LOGV(1, "create external buffer(%d), fd: %d\n",
		     i, queue->buffers[i].fd);
	}

out:
	LEAVE();
	return 0;
err:
	rkmpp_destroy_buffers(ctx, queue);
	RETURN_ERR(EIO, -1);
}

int rkmpp_querybuf(struct rkmpp_context *ctx, struct v4l2_buffer *buffer)
{
	struct rkmpp_buf_queue *queue;
	struct rkmpp_buffer *rkmpp_buffer;
	int ret;

	ENTER();

	queue = rkmpp_get_queue(ctx, buffer->type);
	if (!queue)
		RETURN_ERR(errno, -1);

	if (queue->num_buffers <= buffer->index) {
		LOGE("invalid buf index: %d\n", buffer->index);
		RETURN_ERR(EINVAL, -1);
	}

	rkmpp_buffer = &queue->buffers[buffer->index];

	ret = rkmpp_to_v4l2_buffer(ctx, rkmpp_buffer, buffer);
	if (ret < 0) {
		LOGE("failed to convert buffer\n");
		RETURN_ERR(EINVAL, -1);
	}

	LEAVE();
	return 0;
}

int rkmpp_expbuf(struct rkmpp_context *ctx, struct v4l2_exportbuffer *expbuf)
{
	struct rkmpp_buf_queue *queue;
	struct rkmpp_buffer *rkmpp_buffer;

	ENTER();

	queue = rkmpp_get_queue(ctx, expbuf->type);
	if (!queue)
		RETURN_ERR(errno, -1);

	if (queue->num_buffers <= expbuf->index) {
		LOGE("invalid buf index: %d\n", expbuf->index);
		RETURN_ERR(EINVAL, -1);
	}

	if (expbuf->plane != 0) {
		LOGE("invalid buf plane: %d\n", expbuf->plane);
		RETURN_ERR(EINVAL, -1);
	}

	if (queue->memory != V4L2_MEMORY_MMAP) {
		LOGE("only support expbuf for MMAP\n");
		RETURN_ERR(EINVAL, -1);
	}

	rkmpp_buffer = &queue->buffers[expbuf->index];

	/* The userspace would close it at the end */
	expbuf->fd = dup(rkmpp_buffer->fd);

	LOGV(1, "export buf(%d), type: %d, fd: %d(%d)\n",
	     expbuf->index, expbuf->type, expbuf->fd, rkmpp_buffer->fd);

	rkmpp_buffer_set_exported(rkmpp_buffer);

	LEAVE();
	return 0;
}

int rkmpp_qbuf(struct rkmpp_context *ctx, struct v4l2_buffer *buffer)
{
	struct rkmpp_buf_queue *queue;
	struct rkmpp_buffer *rkmpp_buffer;
	int ret;

	ENTER();

	queue = rkmpp_get_queue(ctx, buffer->type);
	if (!queue)
		RETURN_ERR(errno, -1);

	if (queue->num_buffers <= buffer->index) {
		LOGE("invalid buf index: %d\n", buffer->index);
		RETURN_ERR(EINVAL, -1);
	}

	rkmpp_buffer = &queue->buffers[buffer->index];

	ret = rkmpp_from_v4l2_buffer(ctx, buffer, rkmpp_buffer);
	if (ret < 0) {
		LOGE("failed to convert buffer\n");
		RETURN_ERR(EINVAL, -1);
	}

	LOGV(3, "enqueue buffer: %d(%ld), size: %d, type: %d, fd: %d\n",
	     buffer->index, buffer->timestamp.tv_sec,
	     rkmpp_buffer->bytesused, buffer->type,
	     rkmpp_buffer->fd);

	rkmpp_buffer_set_queued(rkmpp_buffer);

	pthread_mutex_lock(&queue->queue_mutex);
	TAILQ_INSERT_TAIL(&queue->pending_buffers,
			  rkmpp_buffer, entry);
	rkmpp_buffer_set_pending(rkmpp_buffer);
	pthread_mutex_unlock(&queue->queue_mutex);

	LEAVE();
	return 0;
}

int rkmpp_dqbuf(struct rkmpp_context *ctx, struct v4l2_buffer *buffer)
{
	struct rkmpp_buf_queue *queue;
	struct rkmpp_buffer *rkmpp_buffer;
	int ret;

	ENTER();

	queue = rkmpp_get_queue(ctx, buffer->type);
	if (!queue)
		RETURN_ERR(errno, -1);

	/* Wait for buffers in block mode */
	while (TAILQ_EMPTY(&queue->avail_buffers)) {
		if (ctx->nonblock) {
			LOGV(5, "queue is empty\n");
			errno = EAGAIN;
			return -1;
		}

		usleep(1000);
	}

	pthread_mutex_lock(&queue->queue_mutex);
	rkmpp_buffer = TAILQ_FIRST(&queue->avail_buffers);
	TAILQ_REMOVE(&queue->avail_buffers, rkmpp_buffer, entry);
	pthread_mutex_unlock(&queue->queue_mutex);

	/* Update poll event after avail list changed */
	rkmpp_update_poll_event(ctx);

	ret = rkmpp_to_v4l2_buffer(ctx, rkmpp_buffer, buffer);
	if (ret < 0) {
		LOGE("failed to convert buffer\n");
		RETURN_ERR(EINVAL, -1);
	}

	if (rkmpp_buffer_keyframe(rkmpp_buffer))
		rkmpp_buffer_clr_keyframe(rkmpp_buffer);
	if (rkmpp_buffer_error(rkmpp_buffer))
		rkmpp_buffer_clr_error(rkmpp_buffer);
	rkmpp_buffer_clr_available(rkmpp_buffer);
	rkmpp_buffer_clr_queued(rkmpp_buffer);

	LOGV(3, "dequeue buffer: %d(%" PRIu64 "), size: %d, type: %d\n",
	     buffer->index, rkmpp_buffer->timestamp,
	     rkmpp_buffer->bytesused, buffer->type);

	LEAVE();
	return 0;
}

int rkmpp_update_poll_event(struct rkmpp_context *ctx)
{
	eventfd_t event;
	bool has_event;
	int ret;

	ENTER();

	if (ctx->is_decoder)
		has_event = rkmpp_dec_has_event(ctx->data);
	else
		has_event = rkmpp_enc_has_event(ctx->data);

	has_event |= !TAILQ_EMPTY(&ctx->output.avail_buffers);
	has_event |= !TAILQ_EMPTY(&ctx->capture.avail_buffers);

	/* Report POLLIN event */
	if (has_event)
		ret = eventfd_write(ctx->eventfd, 1);
	else
		ret = eventfd_read(ctx->eventfd, &event);

	LEAVE();
	return ret;
}

static int rkmpp_parse_options(struct rkmpp_context *ctx, int fd)
{
	char options[1024] = {0};
	int ret;

	ENTER();

	// TODO: Support more options
	ret = read(fd, options, sizeof(options) - 1);

	LOGV(1, "parsing options: %s\n", options);

	if (!ret || !strncmp(options, "dec", 3)) {
		ctx->is_decoder = true;
	} else if (!strncmp(options, "enc", 3)) {
		ctx->is_decoder = false;
	} else {
		LOGV(1, "unknown options\n");
		RETURN_ERR(ENODEV, -1);
	}

	if (fcntl(fd, F_GETFL) & O_NONBLOCK)
		ctx->nonblock = true;

	LEAVE();
	return 0;
}

static void *plugin_init(int fd)
{
	struct rkmpp_context *ctx = NULL;
	struct epoll_event ev;
	int epollfd;
	MPP_RET ret;

	ENTER();

	pthread_once(&g_rkmpp_global_init_once, rkmpp_global_init);

	ctx = (struct rkmpp_context *)
		calloc(1, sizeof(struct rkmpp_context));
	if (!ctx)
		RETURN_ERR(ENOMEM, NULL);

	if (rkmpp_parse_options(ctx, fd) < 0){
		LOGV(1, "failed to parse option\n");
		goto err_free_ctx;
	}

	/* Create eventfd to fake poll events */
	ctx->eventfd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
	if (ctx->eventfd < 0) {
		LOGE("failed to create eventfd\n");
		goto err_free_ctx;
	}

	epollfd = epoll_create(1);
	if (epollfd < 0) {
		LOGE("failed to create epollfd\n");
		goto err_close_eventfd;
	}

	/* Filter out eventfd's POLLOUT, since it would be always generated */
	ev.events = EPOLLIN | EPOLLET;
	ev.data.fd = ctx->eventfd;
	if (epoll_ctl(epollfd, EPOLL_CTL_ADD, ctx->eventfd, &ev) < 0) {
		LOGE("failed to add eventfd\n");
		goto err_close_epollfd;
	}

	if (dup2(epollfd, fd) < 0) {
		LOGE("failed to dup fd\n");
		goto err_close_epollfd;
	}
	close(epollfd);

	pthread_mutex_init(&ctx->ioctl_mutex, NULL);
	pthread_mutex_init(&ctx->output.queue_mutex, NULL);
	pthread_mutex_init(&ctx->capture.queue_mutex, NULL);

	ret = mpp_buffer_group_get_internal(&ctx->output.internal_group,
					    MPP_BUFFER_TYPE_DRM);
	if (ret != MPP_OK) {
		LOGE("failed to use mpp drm buf group\n");
		errno = ENODEV;
		goto err_close_eventfd;
	}

	ret = mpp_buffer_group_get_internal(&ctx->capture.internal_group,
					    MPP_BUFFER_TYPE_DRM);
	if (ret != MPP_OK) {
		LOGE("failed to use mpp drm buf group\n");
		errno = ENODEV;
		goto err_put_group;
	}

	if (ctx->is_decoder)
		ctx->data = rkmpp_dec_init(ctx);
	else
		ctx->data = rkmpp_enc_init(ctx);

	if (!ctx->data)
		goto err_put_group;

	LOGV(1, "ctx(%p): plugin inited\n", ctx);

	LEAVE();
	return ctx;
err_put_group:
	if (ctx->output.internal_group)
		mpp_buffer_group_put(ctx->output.internal_group);

	if (ctx->capture.internal_group)
		mpp_buffer_group_put(ctx->capture.internal_group);
err_close_epollfd:
	close(epollfd);
err_close_eventfd:
	close(ctx->eventfd);
err_free_ctx:
	free(ctx);
	RETURN_ERR(errno, NULL);
}

static void plugin_close(void *dev_ops_priv)
{
	struct rkmpp_context *ctx = dev_ops_priv;

	ENTER();

	LOGV(1, "ctx(%p): closing plugin\n", ctx);

	if (ctx->is_decoder)
		rkmpp_dec_deinit(ctx->data);
	else
		rkmpp_enc_deinit(ctx->data);

	rkmpp_destroy_buffers(ctx, &ctx->output);

	if (ctx->output.internal_group)
		mpp_buffer_group_put(ctx->output.internal_group);

	if (ctx->output.external_group)
		mpp_buffer_group_put(ctx->output.external_group);

	rkmpp_destroy_buffers(ctx, &ctx->capture);

	if (ctx->capture.external_group)
		mpp_buffer_group_put(ctx->capture.external_group);

	if (ctx->capture.internal_group)
		mpp_buffer_group_put(ctx->capture.internal_group);

	close(ctx->eventfd);
	free(ctx);

	LEAVE();
}

static int plugin_ioctl(void *dev_ops_priv, int fd,
			unsigned long cmd, void *arg)
{
	(void)fd; /* unused */

	struct rkmpp_context *ctx = dev_ops_priv;
	int ret;

	ENTER();

	pthread_mutex_lock(&ctx->ioctl_mutex);

	LOGV(4, "ctx(%p): %s\n", ctx, rkmpp_cmd2str(cmd));

	if (ctx->is_decoder)
		ret = rkmpp_dec_ioctl(ctx->data, cmd, arg);
	else
		ret = rkmpp_enc_ioctl(ctx->data, cmd, arg);

	LOGV(4, "ctx(%p): %s  ret: %d\n", ctx, rkmpp_cmd2str(cmd), ret);

	pthread_mutex_unlock(&ctx->ioctl_mutex);

	LEAVE();
	return ret;
}

static void *plugin_mmap(void *dev_ops_priv, void *start,
			 size_t length, int prot, int flags,
			 int fd, int64_t offset)
{
	(void)fd; /* unused */

	struct rkmpp_context *ctx = dev_ops_priv;
	struct rkmpp_buffer *rkmpp_buffer;
	struct rkmpp_buf_queue *queue;
	void *ptr;
	int index;

	ENTER();

	if (start) {
		LOGE("only support start=NULL\n");
		RETURN_ERR(EINVAL, NULL);
	}

	if (!offset) {
		LOGE("only support mapping plane 0\n");
		RETURN_ERR(EINVAL, NULL);
	}

	queue = rkmpp_get_queue(ctx, RKMPP_MEM_OFFSET_TYPE(offset));
	if (!queue)
		RETURN_ERR(errno, NULL);

	if (queue->memory != V4L2_MEMORY_MMAP) {
		LOGE("only support mmap for V4L2_MEMORY_MMAP\n");
		RETURN_ERR(EINVAL, NULL);
	}

	index = RKMPP_MEM_OFFSET_INDEX(offset);
	if (queue->num_buffers <= index) {
		LOGE("invalid buf index: %d\n", index);
		RETURN_ERR(EINVAL, NULL);
	}

	rkmpp_buffer = &queue->buffers[index];
	ptr = mmap(start, length, prot, flags, rkmpp_buffer->fd, 0);

	LOGV(1, "mmap buffer(%d): %p, fd: %d\n", index, ptr, rkmpp_buffer->fd);

	LEAVE();
	return ptr;
}

PLUGIN_PUBLIC const struct libv4l_dev_ops libv4l2_plugin = {
	.init = &plugin_init,
	.close = &plugin_close,
	.ioctl = &plugin_ioctl,
	.mmap = &plugin_mmap,
};
