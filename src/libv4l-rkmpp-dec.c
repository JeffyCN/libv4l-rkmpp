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

static struct rkmpp_fmt rkmpp_dec_fmts[] = {
	{
		.name = "4:2:0 1 plane Y/CbCr",
		.fourcc = V4L2_PIX_FMT_NV12,
		.num_planes = 1,
		.type = MPP_VIDEO_CodingNone,
		.format = MPP_FMT_YUV420SP,
		.depth = { 12 },
	},
	{
		.name = "AV1",
		.fourcc = V4L2_PIX_FMT_AV1,
		.num_planes = 1,
		.type = MPP_VIDEO_CodingAV1,
		.format = MPP_FMT_BUTT,
		.frmsize = {
			.min_width = 48,
			.max_width = 7680,
			.step_width = RKMPP_MB_DIM,
			.min_height = 48,
			.max_height = 4320,
			.step_height = RKMPP_MB_DIM,
		},
	},
	{
		.name = "H.265",
		.fourcc = V4L2_PIX_FMT_HEVC,
		.num_planes = 1,
		.type = MPP_VIDEO_CodingHEVC,
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

	ENTER();

	pthread_mutex_lock(&ctx->output.queue_mutex);
	while (!TAILQ_EMPTY(&ctx->output.pending_buffers)) {
		/* Don't feed packets when pausing */
		if (ctx->pausing)
			break;

		rkmpp_buffer = TAILQ_FIRST(&ctx->output.pending_buffers);
		if (rkmpp_buffer == &ctx->eos_buffer) {
			LOGV(1, "processing flush request\n");

			ctx->pausing = true;

			mpp_packet_init(&packet, NULL, 0);
			mpp_packet_set_eos(packet);
		} else {
			mpp_packet_init(&packet,
					mpp_buffer_get_ptr(rkmpp_buffer->rkmpp_buf),
					rkmpp_buffer->bytesused);
			mpp_packet_set_pts(packet, rkmpp_buffer->timestamp);
		}

		ret = ctx->mpi->decode_put_packet(ctx->mpp, packet);
		mpp_packet_deinit(&packet);

		if (ret != MPP_OK)
			break;

		TAILQ_REMOVE(&ctx->output.pending_buffers,
			     rkmpp_buffer, entry);
		rkmpp_buffer_clr_pending(rkmpp_buffer);

		/* Done with internal EOS buffer */
		if (rkmpp_buffer == &ctx->eos_buffer)
			break;

		LOGV(2, "put packet: %d(%" PRIu64 ") len=%d\n",
		     rkmpp_buffer->index, rkmpp_buffer->timestamp,
		     rkmpp_buffer->bytesused);

		rkmpp_buffer->bytesused = 0;

		LOGV(2, "return packet: %d\n",
		     rkmpp_buffer->index);

		TAILQ_INSERT_TAIL(&ctx->output.avail_buffers,
				  rkmpp_buffer, entry);
		rkmpp_buffer_set_available(rkmpp_buffer);
	}
	pthread_mutex_unlock(&ctx->output.queue_mutex);

	LEAVE();
}

static void rkmpp_try_send_eos(struct rkmpp_dec_context *dec)
{
	struct rkmpp_context *ctx = dec->ctx;
	struct rkmpp_buffer *rkmpp_buffer;
	MppBuffer buffer = NULL;
	MPP_RET ret;
	int index;

	if (!ctx->capture.streaming)
		return;

	/* Require an unused buffer for EOS */
	ret = mpp_buffer_get(ctx->capture.external_group, &buffer, 1);
	if (ret != MPP_OK) {
		LOGV(2, "unable to lock buffer for EOS\n");
		goto err;
	}

	index = mpp_buffer_get_index(buffer);
	if (index < 0 || index >= (int)ctx->capture.num_buffers) {
		LOGE("invalid buffer index for EOS\n");
		goto err;
	}

	rkmpp_buffer = &ctx->capture.buffers[index];
	if (buffer != rkmpp_buffer->rkmpp_buf) {
		LOGE("invalid buffer for EOS\n");
		goto err;
	}

	rkmpp_buffer_set_locked(rkmpp_buffer);

	rkmpp_finish_flushing(ctx, rkmpp_buffer);

	LOGV(1, "return EOS frame: %d\n", rkmpp_buffer->index);

	dec->pending_eos = false;
	return;
err:
	if (buffer)
		mpp_buffer_put(buffer);

	dec->pending_eos = true;
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

		LOGV(2, "put frame: %d fd: %d\n", rkmpp_buffer->index,
		     rkmpp_buffer->fd);

		mpp_buffer_put(rkmpp_buffer->rkmpp_buf);
		rkmpp_buffer_clr_locked(rkmpp_buffer);
	}
	pthread_mutex_unlock(&ctx->capture.queue_mutex);

	if (dec->pending_eos)
		rkmpp_try_send_eos(dec);

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

	video_info.mpp_format = mpp_frame_get_fmt(frame);
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

	LOGV(1, "frame info changed: %dx%d(%dx%d:%d), mpp format(%d)\n",
	     dec->video_info.width, dec->video_info.height,
	     dec->video_info.hor_stride,
	     dec->video_info.ver_stride,
	     dec->video_info.size, dec->video_info.mpp_format);

	/*
	 * Use ver_stride as new height, the visible rect would be returned
	 * in g_selection.
	 */
	ctx->capture.format.num_planes = 1;
	ctx->capture.format.width = dec->video_info.hor_stride;
	ctx->capture.format.height = dec->video_info.ver_stride;
	ctx->capture.format.plane_fmt[0].bytesperline =
		dec->video_info.hor_stride;
	ctx->capture.format.plane_fmt[0].sizeimage =
		dec->video_info.size;

	assert(dec->video_info.mpp_format == MPP_FMT_YUV420SP);
	ctx->capture.format.pixelformat = V4L2_PIX_FMT_NV12;

	LEAVE();
}

/* Feed available packets and frames to mpp */
/* NOTE: should be locked with either ioctl_mutex or worker_mutex */
static void rkmpp_feed_mpp(struct rkmpp_dec_context *dec)
{
	struct rkmpp_context *ctx = dec->ctx;

	if (!ctx->mpp_streaming)
		return;

	rkmpp_put_packets(dec);
	rkmpp_put_frames(dec);
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

	LOGV(1, "ctx(%p): starting decoder thread\n", (void *)ctx);

	while (1) {
		pthread_mutex_lock(&ctx->worker_mutex);

		while (!ctx->mpp_streaming)
			pthread_cond_wait(&ctx->worker_cond,
					  &ctx->worker_mutex);

		rkmpp_feed_mpp(dec);

		frame = NULL;
		ret = ctx->mpi->decode_get_frame(ctx->mpp, &frame);

		if (ret != MPP_OK || !frame) {
			if (ret != MPP_ERR_TIMEOUT)
				LOGE("failed to get frame\n");

			pthread_mutex_unlock(&ctx->worker_mutex);
			goto next;
		}

		ctx->mpp_produced = true;

		pthread_mutex_unlock(&ctx->worker_mutex);

		pthread_mutex_lock(&ctx->ioctl_mutex);

		if (!ctx->mpp_streaming || !ctx->mpp_produced)
			goto next_locked;

		/* Handle info change frame */
		if (mpp_frame_get_info_change(frame)) {
			rkmpp_apply_info_change(dec, frame);

			goto next_locked;
		}

		/* Handle flushing */
		if (mpp_frame_get_eos(frame)) {
			LOGV(1, "seen EOS frame\n");

			rkmpp_try_send_eos(dec);
			goto next_locked;
		}

		if (!ctx->capture.streaming)
			goto next_locked;

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

		LOGV(2, "return frame: %d(%" PRIu64 ")\n",
		     index, rkmpp_buffer->timestamp);

		/* Report new frame to count fps */
		rkmpp_new_frame(ctx);

		pthread_mutex_lock(&ctx->capture.queue_mutex);
		TAILQ_INSERT_TAIL(&ctx->capture.avail_buffers,
				  rkmpp_buffer, entry);
		rkmpp_buffer_set_available(rkmpp_buffer);
		pthread_mutex_unlock(&ctx->capture.queue_mutex);
		pthread_cond_signal(&ctx->ioctl_cond);
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

static int rkmpp_dec_qbuf(struct rkmpp_dec_context *dec,
			  struct v4l2_buffer *buffer)
{
	struct rkmpp_context *ctx = dec->ctx;
	int ret;

	ENTER();

	ret = rkmpp_qbuf(ctx, buffer);
	if (ret < 0)
		RETURN_ERR(errno, -1);

	rkmpp_feed_mpp(dec);

	LEAVE();
	return ret;
}

static int rkmpp_dec_g_fmt(struct rkmpp_dec_context *dec,
			   struct v4l2_format *f)
{
	struct rkmpp_context *ctx = dec->ctx;
	int ret;

	ENTER();

	LOGV(1, "f->type = %d\n", f->type);

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

	/* The chromium's stateful decoder needs a last buffer for flushing */
	if (ctx->mpp_streaming)
		rkmpp_try_send_eos(dec);

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

	LOGV(1, "queue(%d) start streaming\n", *type);

	/* Commit pending info change to mpp */
	if (ctx->mpp_streaming && dec->video_info.dirty &&
	    *type == V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE) {
		LOGV(1, "send info change ready\n");

		ctx->mpi->control(ctx->mpp,
				  MPP_DEC_SET_INFO_CHANGE_READY, NULL);
		dec->video_info.dirty = false;
	}

	if (ctx->mpp_streaming)
		goto out;

	LOGV(1, "mpp initializing\n");

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

	rkmpp_streamon(ctx);
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
	struct rkmpp_buf_queue *queue;

	ENTER();

	queue = rkmpp_get_queue(ctx, *type);
	if (!queue)
		RETURN_ERR(errno, -1);

	if (!queue->streaming)
		goto out;

	LOGV(1, "queue(%d) stop streaming\n", *type);

	rkmpp_reset_queue(ctx, queue);

	if (queue == &ctx->capture)
		dec->pending_eos = false;

	/* Stop mpp streaming only when all queues stopped */
	if (ctx->mpp_streaming &&
	    !ctx->output.streaming && !ctx->capture.streaming)
		rkmpp_streamoff(ctx);
out:
	LEAVE();
	return 0;
}

static int rkmpp_dec_g_selection(struct rkmpp_dec_context *dec,
				 struct v4l2_selection *selection)
{
	struct rkmpp_context *ctx = dec->ctx;

	ENTER();

	if ((selection->type != V4L2_BUF_TYPE_VIDEO_CAPTURE &&
	     selection->type != V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE) ||
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
	case V4L2_PIX_FMT_HEVC:
		ctrl->value = 20;
		break;
	case V4L2_PIX_FMT_AV1:
		ctrl->value = 12;
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

	/* The chromium would try to require at least 2 extra buffers */
	ctrl->value -= 2;

	LEAVE();
	return 0;
}

static int rkmpp_dec_g_ext_ctrls(struct rkmpp_dec_context *dec,
				 struct v4l2_ext_controls *ext_ctrls)
{
	struct rkmpp_context *ctx = dec->ctx;
	struct v4l2_control ctrl;
	unsigned int i;

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

static int rkmpp_dec_queryctrl(struct rkmpp_dec_context *dec,
			       struct v4l2_queryctrl *query_ctrl)
{
	struct rkmpp_context *ctx = dec->ctx;

	ENTER();

	switch (query_ctrl->id) {
	case V4L2_CID_MPEG_VIDEO_H264_PROFILE:
		query_ctrl->minimum = V4L2_MPEG_VIDEO_H264_PROFILE_BASELINE;
		query_ctrl->maximum = V4L2_MPEG_VIDEO_H264_PROFILE_HIGH_10;
		break;
	case V4L2_CID_MPEG_VIDEO_HEVC_PROFILE:
		query_ctrl->minimum = V4L2_MPEG_VIDEO_HEVC_PROFILE_MAIN;
		query_ctrl->maximum = V4L2_MPEG_VIDEO_HEVC_PROFILE_MAIN_10;
		break;
	case V4L2_CID_MPEG_VIDEO_AV1_PROFILE:
		query_ctrl->minimum = V4L2_MPEG_VIDEO_AV1_PROFILE_MAIN;
		query_ctrl->maximum = query_ctrl->minimum;
		break;
	case V4L2_CID_MPEG_VIDEO_VP8_PROFILE:
		query_ctrl->minimum = V4L2_MPEG_VIDEO_VP8_PROFILE_0;
		query_ctrl->maximum = query_ctrl->minimum;
		break;
	case V4L2_CID_MPEG_VIDEO_VP9_PROFILE:
		query_ctrl->minimum = V4L2_MPEG_VIDEO_VP9_PROFILE_0;
		query_ctrl->maximum = V4L2_MPEG_VIDEO_VP9_PROFILE_2;
		break;
	/* TODO: fill info for other supported ctrls */
	default:
		LOGV(1, "unsupported ctrl: %x\n", query_ctrl->id);
		RETURN_ERR(EINVAL, -1);
	}

	LEAVE();
	return 0;
}

static int rkmpp_dec_querymenu(struct rkmpp_dec_context *dec,
			       struct v4l2_querymenu *query_menu)
{
	struct rkmpp_context *ctx = dec->ctx;

	ENTER();

	switch (query_menu->id) {
	case V4L2_CID_MPEG_VIDEO_H264_PROFILE:
		switch (query_menu->index) {
		case V4L2_MPEG_VIDEO_H264_PROFILE_BASELINE:
		case V4L2_MPEG_VIDEO_H264_PROFILE_MAIN:
		case V4L2_MPEG_VIDEO_H264_PROFILE_HIGH:
		case V4L2_MPEG_VIDEO_H264_PROFILE_HIGH_10:
			break;
		default:
			LOGV(1, "unsupported H264 profile: %x\n",
			     query_menu->index);
			RETURN_ERR(EINVAL, -1);
		}
		break;
	case V4L2_CID_MPEG_VIDEO_HEVC_PROFILE:
		switch (query_menu->index) {
		case V4L2_MPEG_VIDEO_HEVC_PROFILE_MAIN:
		case V4L2_MPEG_VIDEO_HEVC_PROFILE_MAIN_10:
			break;
		default:
			LOGV(1, "unsupported HEVC profile: %x\n",
			     query_menu->index);
			RETURN_ERR(EINVAL, -1);
		}
		break;
	case V4L2_CID_MPEG_VIDEO_AV1_PROFILE:
		if (query_menu->index != V4L2_MPEG_VIDEO_AV1_PROFILE_MAIN) {
			LOGV(1, "unsupported VP8 profile: %x\n",
			     query_menu->index);
			RETURN_ERR(EINVAL, -1);
		}
		break;
	case V4L2_CID_MPEG_VIDEO_VP8_PROFILE:
		if (query_menu->index != V4L2_MPEG_VIDEO_VP8_PROFILE_0) {
			LOGV(1, "unsupported VP8 profile: %x\n",
			     query_menu->index);
			RETURN_ERR(EINVAL, -1);
		}
		break;
	case V4L2_CID_MPEG_VIDEO_VP9_PROFILE:
		switch (query_menu->index) {
		case V4L2_MPEG_VIDEO_VP9_PROFILE_0:
		case V4L2_MPEG_VIDEO_VP9_PROFILE_2:
			break;
		default:
			LOGV(1, "unsupported VP9 profile: %x\n",
			     query_menu->index);
			RETURN_ERR(EINVAL, -1);
		}
		break;
	default:
		LOGV(1, "unsupported menu: %x\n", query_menu->id);
		RETURN_ERR(EINVAL, -1);
	}

	LEAVE();
	return 0;
}

static int rkmpp_try_dec_cmd(struct rkmpp_dec_context *dec,
			     struct v4l2_decoder_cmd *cmd)
{
	struct rkmpp_context *ctx = dec->ctx;

	ENTER();

	if (cmd->cmd != V4L2_DEC_CMD_START && cmd->cmd != V4L2_DEC_CMD_STOP) {
		LOGE("unsupported cmd: %x\n", cmd->cmd);
		RETURN_ERR(EINVAL, -1);
	}

	LEAVE();
	return 0;
}

static int rkmpp_dec_cmd(struct rkmpp_dec_context *dec,
			 struct v4l2_decoder_cmd *cmd)
{
	struct rkmpp_context *ctx = dec->ctx;

	ENTER();

	if (cmd->cmd == V4L2_DEC_CMD_START) {
		LOGV(1, "handle start decoding cmd\n");

		rkmpp_exit_flushing(ctx);
	} else if (cmd->cmd == V4L2_DEC_CMD_STOP) {
		LOGV(1, "handle stop decoding cmd\n");

		rkmpp_start_flushing(ctx);
	} else {
		LOGE("unsupported cmd: %x\n", cmd->cmd);
		RETURN_ERR(EINVAL, -1);
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

	if (!ctx->max_width)
		ctx->max_width = MAX_DEC_WIDTH;

	if (!ctx->max_height)
		ctx->max_height = MAX_DEC_HEIGHT;

	pthread_create(&ctx->worker_thread, NULL,
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
	case VIDIOC_DQBUF:
		ret = rkmpp_dqbuf(ctx, arg);
		break;

	/* Decoder special ioctls */
	case VIDIOC_QBUF:
		ret = rkmpp_dec_qbuf(dec, arg);
		break;
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
	case VIDIOC_QUERYCTRL:
		ret = rkmpp_dec_queryctrl(dec, arg);
		break;
	case VIDIOC_QUERYMENU:
		ret = rkmpp_dec_querymenu(dec, arg);
		break;
	case VIDIOC_TRY_DECODER_CMD:
		ret = rkmpp_try_dec_cmd(dec, arg);
		break;
	case VIDIOC_DECODER_CMD:
		ret = rkmpp_dec_cmd(dec, arg);
		break;
	default:
		LOGV(1, "unsupported ioctl cmd: %s(%lu)!\n",
		     rkmpp_cmd2str(cmd), cmd);
		RETURN_ERR(ENOTTY, -1);
	}

	LEAVE();
	return ret;
}
