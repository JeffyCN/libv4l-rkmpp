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

#include <signal.h>

#include "libv4l-rkmpp-dec.h"

#define RKMPP_DEC_POLL_TIMEOUT_MS	500

static const struct rkmpp_fmt rkmpp_dec_fmts[] = {
	{
		.name = "4:2:0 1 plane Y/CbCr",
		.fourcc = V4L2_PIX_FMT_NV12,
		.num_planes = 1,
		.type = MPP_VIDEO_CodingNone,
		.format = MPP_FMT_YUV420SP,
		.depth = { 12 },
	},
	{
		.name = "H.264",
		.fourcc = V4L2_PIX_FMT_H264,
		.num_planes = 1,
		.type = MPP_VIDEO_CodingAVC,
		.format = MPP_FMT_BUTT,
		.frmsize = {
			.min_width = 48,
			.max_width = 3840,
			.step_width = RKMPP_MB_DIM,
			.min_height = 48,
			.max_height = 2160,
			.step_height = RKMPP_MB_DIM,
		},
	},
	{
		.name = "VP8",
		.fourcc = V4L2_PIX_FMT_VP8,
		.num_planes = 1,
		.type = MPP_VIDEO_CodingVP8,
		.format = MPP_FMT_BUTT,
		.frmsize = {
			.min_width = 48,
			.max_width = 3840,
			.step_width = RKMPP_MB_DIM,
			.min_height = 48,
			.max_height = 2160,
			.step_height = RKMPP_MB_DIM,
		},
	},
	/* VP9 only enabled in chromeos */
	{
		.name = "VP9",
		.fourcc = V4L2_PIX_FMT_VP9,
		.num_planes = 1,
		.type = MPP_VIDEO_CodingVP9,
		.format = MPP_FMT_BUTT,
		.frmsize = {
			.min_width = 48,
			.max_width = 3840,
			.step_width = RKMPP_SB_DIM,
			.min_height = 48,
			.max_height = 2176,
			.step_height = RKMPP_SB_DIM,
		},
	},
};

/* Feed all available packets to mpp */
static void rkmpp_put_packets(struct rkmpp_dec_context *dec)
{
	struct rkmpp_context *ctx = dec->ctx;
	struct rkmpp_buffer *rkmpp_buffer;
	MppPacket packet;
	MPP_RET ret;
	bool is_eos;

	ENTER();

	pthread_mutex_lock(&ctx->output.queue_mutex);
	while (!TAILQ_EMPTY(&ctx->output.pending_buffers)) {
		rkmpp_buffer = TAILQ_FIRST(&ctx->output.pending_buffers);

		mpp_packet_init(&packet,
				mpp_buffer_get_ptr(rkmpp_buffer->rkmpp_buf),
				rkmpp_buffer->bytesused);
		mpp_packet_set_pts(packet, rkmpp_buffer->timestamp);

		// TODO: Support start/stop decode cmd
		/* The chromium uses -2 as special flush timestamp. */
		is_eos = rkmpp_buffer->timestamp == (uint64_t)-2000000;
		if (is_eos)
			mpp_packet_set_eos(packet);

		ret = ctx->mpi->decode_put_packet(ctx->mpp, packet);
		mpp_packet_deinit(&packet);

		if (ret != MPP_OK)
			break;

		TAILQ_REMOVE(&ctx->output.pending_buffers,
			     rkmpp_buffer, entry);
		rkmpp_buffer_clr_pending(rkmpp_buffer);

		/* Hold eos packet until eos frame received(flushed) */
		if (is_eos) {
			LOGV(1, "hold eos packet: %d\n",
			     rkmpp_buffer->index);
			dec->eos_packet = rkmpp_buffer;
			break;
		}

		LOGV(3, "put packet(%" PRIu64 "): %d len=%d\n",
		     rkmpp_buffer->timestamp, rkmpp_buffer->index,
		     rkmpp_buffer->bytesused);

		rkmpp_buffer->bytesused = 0;

		LOGV(3, "return packet: %d\n",
		     rkmpp_buffer->index);

		TAILQ_INSERT_TAIL(&ctx->output.avail_buffers,
				  rkmpp_buffer, entry);
		rkmpp_buffer_set_available(rkmpp_buffer);
	}
	pthread_mutex_unlock(&ctx->output.queue_mutex);

	LEAVE();
}

/* Feed all available frames to mpp */
static void rkmpp_put_frames(struct rkmpp_dec_context *dec)
{
	struct rkmpp_context *ctx = dec->ctx;
	struct rkmpp_buffer *rkmpp_buffer;

	ENTER();

	pthread_mutex_lock(&ctx->capture.queue_mutex);
	while (!TAILQ_EMPTY(&ctx->capture.pending_buffers)) {
		rkmpp_buffer =
			TAILQ_FIRST(&ctx->capture.pending_buffers);
		TAILQ_REMOVE(&ctx->capture.pending_buffers,
			     rkmpp_buffer, entry);
		rkmpp_buffer_clr_pending(rkmpp_buffer);

		LOGV(3, "put frame: %d fd: %d\n", rkmpp_buffer->index,
		     rkmpp_buffer->fd);

		mpp_buffer_put(rkmpp_buffer->rkmpp_buf);
		rkmpp_buffer_clr_locked(rkmpp_buffer);
	}
	pthread_mutex_unlock(&ctx->capture.queue_mutex);

	LEAVE();
}

static void rkmpp_apply_info_change(struct rkmpp_dec_context *dec,
				    MppFrame frame)
{
	struct rkmpp_context *ctx = dec->ctx;
	struct rkmpp_video_info video_info;

	ENTER();

	memcpy((void *)&video_info,
	       (void *)&dec->video_info, sizeof(video_info));

	video_info.width = mpp_frame_get_width(frame);
	video_info.height = mpp_frame_get_height(frame);
	video_info.hor_stride = mpp_frame_get_hor_stride(frame);
	video_info.ver_stride = mpp_frame_get_ver_stride(frame);
	video_info.size = mpp_frame_get_buf_size(frame);
	video_info.valid = true;

	if (!memcmp((void *)&video_info,
		    (void *)&dec->video_info, sizeof(video_info))) {
		LOGV(1, "ignore unchanged frame info\n");

		ctx->mpi->control(ctx->mpp,
				  MPP_DEC_SET_INFO_CHANGE_READY,
				  NULL);
		return;
	}

	dec->video_info = video_info;
	dec->video_info.dirty = true;
	dec->video_info.event = dec->event_subscribed;

	/*
	 * Use ver_stride as new height, the visible rect would be returned
	 * in g_selection.
	 */
	ctx->capture.format.width = dec->video_info.hor_stride;
	ctx->capture.format.height = dec->video_info.ver_stride;
	ctx->capture.format.num_planes = 1;
	ctx->capture.format.plane_fmt[0].bytesperline =
		dec->video_info.hor_stride;
	ctx->capture.format.plane_fmt[0].sizeimage =
		dec->video_info.size;

	LOGV(1, "frame info changed: %dx%d(%dx%d:%d)\n",
	     dec->video_info.width, dec->video_info.height,
	     dec->video_info.hor_stride,
	     dec->video_info.ver_stride,
	     dec->video_info.size);

	LEAVE();
}

static void *decoder_thread_fn(void *data)
{
	struct rkmpp_dec_context *dec = data;
	struct rkmpp_context *ctx = dec->ctx;
	struct rkmpp_buffer *rkmpp_buffer;
	MppFrame frame;
	MppBuffer buffer;
	MPP_RET ret;
	int index;

	ENTER();

	LOGV(1, "ctx(%p): starting decoder thread\n", ctx);

	while (1) {
		pthread_mutex_lock(&dec->decoder_mutex);

		while (!dec->mpp_streaming)
			pthread_cond_wait(&dec->decoder_cond,
					  &dec->decoder_mutex);

		/* Feed available packets and frames to mpp */
		rkmpp_put_packets(dec);
		rkmpp_put_frames(dec);

		frame = NULL;
		ret = ctx->mpi->decode_get_frame(ctx->mpp, &frame);

		pthread_mutex_unlock(&dec->decoder_mutex);

		if (ret != MPP_OK || !frame) {
			if (ret != MPP_ERR_TIMEOUT)
				LOGE("failed to get frame\n");

			goto next;
		}

		pthread_mutex_lock(&ctx->ioctl_mutex);

		if (!dec->mpp_streaming)
			goto next_locked;

		/* Handle info change frame */
		if (mpp_frame_get_info_change(frame)) {
			rkmpp_apply_info_change(dec, frame);

			goto next_locked;
		}

		/* Handle eos frame, returning eos packet to userspace */
		if (mpp_frame_get_eos(frame)) {
			if (dec->eos_packet) {
				dec->eos_packet->bytesused = 0;

				LOGV(1, "return eos packet: %d\n",
				     dec->eos_packet->index);

				TAILQ_INSERT_TAIL(&ctx->output.avail_buffers,
						  dec->eos_packet, entry);
				rkmpp_buffer_set_available(dec->eos_packet);
				dec->eos_packet = NULL;
			}

			goto next_locked;
		}

		/* Handle normal frame */
		buffer = mpp_frame_get_buffer(frame);
		if (!buffer) {
			LOGE("frame(%lld) doesn't have buf\n",
			     mpp_frame_get_pts(frame));

			goto next_locked;
		}

		mpp_buffer_inc_ref(buffer);

		index = mpp_buffer_get_index(buffer);
		rkmpp_buffer = &ctx->capture.buffers[index];

		rkmpp_buffer->timestamp = mpp_frame_get_pts(frame);
		rkmpp_buffer_set_locked(rkmpp_buffer);

		if (mpp_frame_get_errinfo(frame) ||
		    mpp_frame_get_discard(frame)) {
			LOGE("frame err or discard\n");
			rkmpp_buffer->bytesused = 0;
			rkmpp_buffer_set_error(rkmpp_buffer);
		} else {
			/* Size of NV12 image */
			rkmpp_buffer->bytesused = dec->video_info.hor_stride *
				dec->video_info.ver_stride * 3 / 2;
		}

		LOGV(3, "return frame(%" PRIu64 "): %d\n",
		     rkmpp_buffer->timestamp, index);

		/* Report new frame to count fps */
		rkmpp_new_frame(ctx);

		pthread_mutex_lock(&ctx->capture.queue_mutex);
		TAILQ_INSERT_TAIL(&ctx->capture.avail_buffers,
				  rkmpp_buffer, entry);
		rkmpp_buffer_set_available(rkmpp_buffer);
		pthread_mutex_unlock(&ctx->capture.queue_mutex);
next_locked:
		pthread_mutex_unlock(&ctx->ioctl_mutex);
next:
		/* Update poll event after every loop */
		pthread_mutex_lock(&ctx->ioctl_mutex);
		rkmpp_update_poll_event(ctx);
		pthread_mutex_unlock(&ctx->ioctl_mutex);

		if (frame)
			mpp_frame_deinit(&frame);
	}

	LEAVE();
	return NULL;
}

static int rkmpp_dec_g_fmt(struct rkmpp_dec_context *dec,
			   struct v4l2_format *f)
{
	struct rkmpp_context *ctx = dec->ctx;
	int ret;

	ENTER();

	LOGV(4, "f->type = %d\n", f->type);

	/* The chromium expected EINVAL when resolution not available */
	if (f->type == V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE &&
	    !dec->video_info.valid) {
		LOGV(1, "cannot provide resolution yet\n");
		RETURN_ERR(EINVAL, -1);
	}

	ret = rkmpp_g_fmt(dec->ctx, f);

	LEAVE();
	return ret;
}

static int rkmpp_dec_subscribe_event(struct rkmpp_dec_context *dec,
				     struct v4l2_event_subscription *sub,
				     bool subscribe)
{
	struct rkmpp_context *ctx = dec->ctx;

	ENTER();

	if (sub->type != V4L2_EVENT_SOURCE_CHANGE) {
		LOGE("unsupported event type: %x\n", sub->type);
		RETURN_ERR(EINVAL, -1);
	}

	dec->event_subscribed = subscribe;

	LEAVE();
	return 0;
}

static int rkmpp_dec_dqevent(struct rkmpp_dec_context *dec,
			     struct v4l2_event *event)
{
	struct rkmpp_context *ctx = dec->ctx;

	ENTER();

	if (!dec->event_subscribed || !dec->video_info.event) {
		LOGV(4, "no available event\n");
		errno = ENOENT;
		return -1;
	}

	event->type = V4L2_EVENT_SOURCE_CHANGE;
	event->u.src_change.changes = V4L2_EVENT_SRC_CH_RESOLUTION;
	dec->video_info.event = false;
	LOGV(1, "dequeue resolution change event\n");

	LEAVE();
	return 0;
}

static int rkmpp_dec_streamon(struct rkmpp_dec_context *dec,
			      enum v4l2_buf_type *type)
{
	struct rkmpp_context *ctx = dec->ctx;
	struct rkmpp_buf_queue *queue;
	MppPollType poll_type;
	uint32_t split;
	MPP_RET ret;

	ENTER();

	queue = rkmpp_get_queue(ctx, *type);
	if (!queue)
		RETURN_ERR(errno, -1);

	if (queue->streaming)
		goto out;
	queue->streaming = true;

	/* Commit pending info change to mpp */
	if (dec->mpp_streaming && dec->video_info.dirty &&
	    *type == V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE) {
		LOGV(1, "send info change ready\n");

		ctx->mpi->control(ctx->mpp,
				  MPP_DEC_SET_INFO_CHANGE_READY, NULL);
		dec->video_info.dirty = false;
	}

	/* The chromium will stream output queue firstly to get video info */
	if (!ctx->output.streaming || dec->mpp_streaming)
		goto out;

	LOGV(1, "mpp start streaming\n");

	ret = mpp_create(&ctx->mpp, &ctx->mpi);
	if (ret != MPP_OK) {
		LOGE("failed to create mpp\n");
		errno = ENOMEM;
		goto err;
	}

	ret = 1;
	ctx->mpi->control(ctx->mpp, MPP_DEC_SET_PARSER_FAST_MODE, &ret);

	ret = mpp_init(ctx->mpp, MPP_CTX_DEC,
		       ctx->output.rkmpp_format->type);
	if (ret != MPP_OK) {
		LOGE("failed to init mpp\n");
		goto err_destroy_mpp;
	}

	/* The chromium will do the split */
	split = 0;
	ret = ctx->mpi->control(ctx->mpp,
				MPP_DEC_SET_PARSER_SPLIT_MODE,
				&split);
	if (ret != MPP_OK) {
		LOGE("failed to set mpp split mode\n");
		goto err_destroy_mpp;
	}

	/* Enable timeout mode to avoid hang during get_frame */
	poll_type = RKMPP_DEC_POLL_TIMEOUT_MS;
	ret = ctx->mpi->control(ctx->mpp, MPP_SET_OUTPUT_TIMEOUT,
				(MppParam)&poll_type);
	if (ret != MPP_OK) {
		LOGE("failed to set mpp timeout\n");
		goto err_destroy_mpp;
	}

	/* Use external buffer mode for capture queue */
	ret = ctx->mpi->control(ctx->mpp,
				MPP_DEC_SET_EXT_BUF_GROUP,
				ctx->capture.external_group);
	if (ret != MPP_OK) {
		LOGE("failed to set buffer group\n");
		goto err_destroy_mpp;
	}

	/* Notify decoder thread to start streaming */
	pthread_mutex_lock(&dec->decoder_mutex);
	dec->mpp_streaming = true;
	pthread_cond_signal(&dec->decoder_cond);
	pthread_mutex_unlock(&dec->decoder_mutex);
out:
	LEAVE();
	return 0;
err_destroy_mpp:
	ctx->mpi->reset(ctx->mpp);
	mpp_destroy(ctx->mpp);
err:
	queue->streaming = false;
	RETURN_ERR(EPIPE, -1);
}

static int rkmpp_dec_streamoff(struct rkmpp_dec_context *dec,
			       enum v4l2_buf_type *type)
{
	struct rkmpp_context *ctx = dec->ctx;
	struct rkmpp_buffer *rkmpp_buffer;
	struct rkmpp_buf_queue *queue;
	int i;

	ENTER();

	queue = rkmpp_get_queue(ctx, *type);
	if (!queue)
		RETURN_ERR(errno, -1);

	if (!queue->streaming)
		goto out;
	queue->streaming = false;

	pthread_mutex_lock(&dec->decoder_mutex);

	/* Hand over all buffers to userspace */
	pthread_mutex_lock(&queue->queue_mutex);
	TAILQ_INIT(&queue->avail_buffers);
	TAILQ_INIT(&queue->pending_buffers);
	pthread_mutex_unlock(&queue->queue_mutex);

	/* Update poll event after avail list changed */
	rkmpp_update_poll_event(ctx);

	/* Reset buffer states */
	for (i = 0; i < queue->num_buffers; i++) {
		rkmpp_buffer = &queue->buffers[i];

		if (rkmpp_buffer_error(rkmpp_buffer))
			rkmpp_buffer_clr_error(rkmpp_buffer);

		if (!rkmpp_buffer_locked(rkmpp_buffer)) {
			mpp_buffer_inc_ref(rkmpp_buffer->rkmpp_buf);
			rkmpp_buffer_set_locked(rkmpp_buffer);
		}

		if (rkmpp_buffer_queued(rkmpp_buffer))
			rkmpp_buffer_clr_queued(rkmpp_buffer);

		if (rkmpp_buffer_pending(rkmpp_buffer))
			rkmpp_buffer_clr_pending(rkmpp_buffer);

		if (rkmpp_buffer_available(rkmpp_buffer))
			rkmpp_buffer_clr_available(rkmpp_buffer);
	}

	/* Clear eos packet */
	if (*type == V4L2_BUF_TYPE_VIDEO_OUTPUT_MPLANE)
		dec->eos_packet = NULL;

	/* Stop mpp streaming when all queues stopped */
	if (!dec->mpp_streaming ||
	    ctx->output.streaming || ctx->capture.streaming) {
		pthread_mutex_unlock(&dec->decoder_mutex);
		goto out;
	}

	LOGV(1, "mpp stop streaming\n");

	dec->mpp_streaming = false;

	pthread_mutex_unlock(&dec->decoder_mutex);

	ctx->mpi->reset(ctx->mpp);
	mpp_destroy(ctx->mpp);
out:
	LEAVE();
	return 0;
}

static int rkmpp_dec_g_selection(struct rkmpp_dec_context *dec,
				 struct v4l2_selection *selection)
{
	struct rkmpp_context *ctx = dec->ctx;

	ENTER();

	if (selection->type != V4L2_BUF_TYPE_VIDEO_CAPTURE ||
	    selection->target != V4L2_SEL_TGT_COMPOSE) {
		LOGE("invalid type or target\n");
		RETURN_ERR(EINVAL, -1);
	}

	/* The chromium uses g_selection to get visible rect */
	if (!dec->video_info.valid) {
		LOGV(1, "cannot provide visible resolution yet\n");
		RETURN_ERR(EBUSY, -1);
	}

	/* Return visible rect */
	selection->r.top = selection->r.left = 0;
	selection->r.width = dec->video_info.width;
	selection->r.height = dec->video_info.height;

	LOGV(1, "visible rect: %dx%d\n",
	     selection->r.width, selection->r.height);

	LEAVE();
	return 0;
}

static int rkmpp_dec_g_ctrl(struct rkmpp_dec_context *dec,
			    struct v4l2_control *ctrl)
{
	struct rkmpp_context *ctx = dec->ctx;

	ENTER();

	if (ctrl->id != V4L2_CID_MIN_BUFFERS_FOR_CAPTURE) {
		LOGE("only support V4L2_CID_MIN_BUFFERS_FOR_CAPTURE now\n");
		RETURN_ERR(EINVAL, -1);
	}

	if (!ctx->output.rkmpp_format) {
		LOGE("cannot get min buffers before s_fmt\n");
		RETURN_ERR(EBUSY, -1);
	}

	/* Information provided by Herman Chen <herman.chen@rock-chips.com> */
	switch (ctx->output.rkmpp_format->fourcc) {
	case V4L2_PIX_FMT_H264:
		ctrl->value = 20;
		break;
	case V4L2_PIX_FMT_VP9:
		ctrl->value = 12;
		break;
	case V4L2_PIX_FMT_VP8:
		ctrl->value = 8;
		break;
	default:
		LOGE("unsupported format\n");
		RETURN_ERR(EINVAL, -1);
	}

	/* The chromium would try to require at least 5 extra buffers */
	ctrl->value -= 5;

	LEAVE();
	return 0;
}

static int rkmpp_dec_g_ext_ctrls(struct rkmpp_dec_context *dec,
				 struct v4l2_ext_controls *ext_ctrls)
{
	struct rkmpp_context *ctx = dec->ctx;
	struct v4l2_control ctrl;
	int i;

	ENTER();

	for (i = 0; i < ext_ctrls->count; i++) {
		struct v4l2_ext_control *ext_ctrl = &ext_ctrls->controls[i];

		ctrl.id = ext_ctrl->id;
		if (rkmpp_dec_g_ctrl(dec, &ctrl) < 0)
			return -1;

		ext_ctrl->value = ctrl.value;
	}

	LEAVE();
	return 0;
}

bool rkmpp_dec_has_event(void *data)
{
	struct rkmpp_dec_context *dec = data;

	return dec->video_info.event;
}

void *rkmpp_dec_init(struct rkmpp_context *ctx)
{
	struct rkmpp_dec_context *dec;
	MPP_RET ret;

	ENTER();

	dec = (struct rkmpp_dec_context *)
		calloc(1, sizeof(struct rkmpp_dec_context));
	if (!dec)
		RETURN_ERR(ENOMEM, NULL);

	/* Using external buffer mode to limit buffers */
	ret = mpp_buffer_group_get_external(&ctx->capture.external_group,
					    MPP_BUFFER_TYPE_DRM);
	if (ret != MPP_OK) {
		LOGE("failed to use mpp ext drm buf group\n");
		errno = ENODEV;
		goto err_free_dec;
	}

	ctx->formats = rkmpp_dec_fmts;
	ctx->num_formats = ARRAY_SIZE(rkmpp_dec_fmts);
	dec->ctx = ctx;

	pthread_cond_init(&dec->decoder_cond, NULL);
	pthread_mutex_init(&dec->decoder_mutex, NULL);
	pthread_create(&dec->decoder_thread, NULL,
		       decoder_thread_fn, dec);

	LEAVE();
	return dec;
err_free_dec:
	free(dec);
	RETURN_ERR(errno, NULL);
}

void rkmpp_dec_deinit(void *data)
{
	struct rkmpp_dec_context *dec = data;
	struct rkmpp_context *ctx = dec->ctx;

	ENTER();

	if (dec->decoder_thread) {
		pthread_cancel(dec->decoder_thread);
		pthread_join(dec->decoder_thread, NULL);
	}

	if (dec->mpp_streaming) {
		ctx->mpi->reset(ctx->mpp);
		mpp_destroy(ctx->mpp);
	}

	free(dec);

	LEAVE();
}

int rkmpp_dec_ioctl(void *data, unsigned long cmd, void *arg)
{
	struct rkmpp_dec_context *dec = data;
	struct rkmpp_context *ctx = dec->ctx;
	int ret;

	ENTER();

	switch (cmd) {

	/* Common ioctls */
	case VIDIOC_QUERYCAP:
		ret = rkmpp_querycap(ctx, arg);
		break;
	case VIDIOC_ENUM_FMT:
		ret = rkmpp_enum_fmt(ctx, arg);
		break;
	case VIDIOC_ENUM_FRAMESIZES:
		ret = rkmpp_enum_framesizes(ctx, arg);
		break;
	case VIDIOC_TRY_FMT:
		ret = rkmpp_try_fmt(ctx, arg);
		break;
	case VIDIOC_S_FMT:
		ret = rkmpp_s_fmt(ctx, arg);
		break;
	case VIDIOC_REQBUFS:
		ret = rkmpp_reqbufs(ctx, arg);
		break;
	case VIDIOC_QUERYBUF:
		ret = rkmpp_querybuf(ctx, arg);
		break;
	case VIDIOC_EXPBUF:
		ret = rkmpp_expbuf(ctx, arg);
		break;
	case VIDIOC_QBUF:
		ret = rkmpp_qbuf(ctx, arg);

		/* Feed available packets and frames to mpp */
		if (dec->mpp_streaming) {
			rkmpp_put_packets(dec);
			rkmpp_put_frames(dec);
		}
		break;
	case VIDIOC_DQBUF:
		ret = rkmpp_dqbuf(ctx, arg);
		break;

	/* Decoder special ioctls */
	case VIDIOC_G_FMT:
		ret = rkmpp_dec_g_fmt(dec, arg);
		break;
	case VIDIOC_SUBSCRIBE_EVENT:
		ret = rkmpp_dec_subscribe_event(dec, arg, true);
		break;
	case VIDIOC_UNSUBSCRIBE_EVENT:
		ret = rkmpp_dec_subscribe_event(dec, arg, false);
		break;
	case VIDIOC_DQEVENT:
		ret = rkmpp_dec_dqevent(dec, arg);
		break;
	case VIDIOC_STREAMON:
		ret = rkmpp_dec_streamon(dec, arg);
		break;
	case VIDIOC_STREAMOFF:
		ret = rkmpp_dec_streamoff(dec, arg);
		break;
	case VIDIOC_G_SELECTION:
		ret = rkmpp_dec_g_selection(dec, arg);
		break;
	case VIDIOC_G_CTRL:
		ret = rkmpp_dec_g_ctrl(dec, arg);
		break;
	case VIDIOC_G_EXT_CTRLS:
		ret = rkmpp_dec_g_ext_ctrls(dec, arg);
		break;
	default:
		LOGV(1, "unsupported ioctl cmd: %s(%lu)!\n",
		     rkmpp_cmd2str(cmd), cmd);
		RETURN_ERR(ENOTTY, -1);
	}

	LEAVE();
	return ret;
}
