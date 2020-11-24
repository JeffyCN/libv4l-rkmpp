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
#include <unistd.h>

#include "libv4l-rkmpp-enc.h"

#ifndef V4L2_CID_MPEG_VIDEO_FORCE_KEY_FRAME
#define V4L2_CID_MPEG_VIDEO_FORCE_KEY_FRAME	(V4L2_CID_MPEG_BASE+229)
#endif

#define RKMPP_ENC_POLL_TIMEOUT_MS	100

static const struct rkmpp_fmt rkmpp_enc_fmts[] = {
	{
		.name = "4:2:0 3 plane Y/Cb/Cr",
		.fourcc = V4L2_PIX_FMT_YUV420M,
		.num_planes = 3,
		.type = MPP_VIDEO_CodingNone,
		.format = MPP_FMT_YUV420P,
		.depth = { 8, 4, 4 },
	},
	{
		.name = "4:2:0 2 plane Y/CbCr",
		.fourcc = V4L2_PIX_FMT_NV12M,
		.num_planes = 2,
		.type = MPP_VIDEO_CodingNone,
		.format = MPP_FMT_YUV420SP,
		.depth = { 8, 8 },
	},
	{
		.name = "4:2:2 1 plane YUYV",
		.fourcc = V4L2_PIX_FMT_YUYV,
		.num_planes = 1,
		.type = MPP_VIDEO_CodingNone,
		.format = MPP_FMT_YUV422_YUYV,
		.depth = { 16 },
	},
	{
		.name = "4:2:2 1 plane UYVY",
		.fourcc = V4L2_PIX_FMT_UYVY,
		.num_planes = 1,
		.type = MPP_VIDEO_CodingNone,
		.format = MPP_FMT_YUV422_UYVY,
		.depth = { 16 },
	},
	{
		.name = "H.264",
		.fourcc = V4L2_PIX_FMT_H264,
		.num_planes = 1,
		.type = MPP_VIDEO_CodingAVC,
		.format = MPP_FMT_BUTT,
		.frmsize = {
			.min_width = 96,
			.max_width = 1920,
			.step_width = RKMPP_MB_DIM,
			.min_height = 96,
			.max_height = 1088,
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
			.min_width = 96,
			.max_width = 1920,
			.step_width = RKMPP_MB_DIM,
			.min_height = 96,
			.max_height = 1088,
			.step_height = RKMPP_MB_DIM,
		},
	},
};

static int rkmpp_enc_apply_rc_cfg(struct rkmpp_enc_context *enc);

static int rkmpp_put_frame(struct rkmpp_enc_context *enc)
{
	struct rkmpp_context *ctx = enc->ctx;
	const struct rkmpp_fmt *rkmpp_fmt = ctx->output.rkmpp_format;
	struct rkmpp_buffer *rkmpp_buffer;
	MppFrame frame;
	MPP_RET ret;

	ENTER();

	ret = mpp_frame_init(&frame);
	if (ret != MPP_OK) {
		LOGE("failed to init frame\n");
		return -1;
	}

	mpp_frame_set_width(frame, enc->width);
	mpp_frame_set_height(frame, enc->height);
	mpp_frame_set_hor_stride(frame, enc->hstride);
	mpp_frame_set_ver_stride(frame, enc->vstride);
	mpp_frame_set_fmt(frame, rkmpp_fmt->format);

	pthread_mutex_lock(&ctx->output.queue_mutex);
	rkmpp_buffer = TAILQ_FIRST(&ctx->output.pending_buffers);
	TAILQ_REMOVE(&ctx->output.pending_buffers, rkmpp_buffer, entry);
	rkmpp_buffer_clr_pending(rkmpp_buffer);
	pthread_mutex_unlock(&ctx->output.queue_mutex);

	mpp_frame_set_buffer(frame, rkmpp_buffer->rkmpp_buf);

	/* Use pts to track frame buffer */
	mpp_frame_set_pts(frame, rkmpp_buffer->index);

	ret = ctx->mpi->encode_put_frame(ctx->mpp, frame);
	mpp_frame_deinit(&frame);

	if (ret != MPP_OK) {
		LOGE("failed to put frame\n");
		return -1;
	}

	LOGV(3, "put frame(%" PRIu64 "): %d\n",
	     rkmpp_buffer->timestamp, rkmpp_buffer->index);

	rkmpp_buffer->bytesused = 0;

	LEAVE();
	return 0;
}

static void rkmpp_packet_to_buffer(struct rkmpp_enc_context *enc,
				   MppPacket packet,
				   struct rkmpp_buffer *rkmpp_buffer)
{
	void *src = mpp_packet_get_pos(packet);
	void *dst = mpp_buffer_get_ptr(rkmpp_buffer->rkmpp_buf);
	uint32_t src_size = mpp_packet_get_length(packet);
	uint32_t offset = rkmpp_buffer->bytesused;
	uint32_t dst_size = rkmpp_buffer->size;

	if (src_size > dst_size - offset) {
		LOGE("packet overflow! %d > (%d - %d)\n",
		     src_size, dst_size, offset);
		src_size = dst_size - offset;
	}

	memcpy(dst + offset, src, src_size);
	rkmpp_buffer->bytesused += src_size;
}

static MppPacket rkmpp_get_header(struct rkmpp_enc_context *enc)
{
	struct rkmpp_context *ctx = enc->ctx;
	MppPacket tmp, header;
	MPP_RET ret;
	uint8_t buf[MAX_HEADER_BYTES];

	ENTER();

	LOGV(1, "get header packet\n");

	mpp_packet_init(&tmp, buf, sizeof(buf));
	ret = ctx->mpi->control(ctx->mpp, MPP_ENC_GET_HDR_SYNC, tmp);
	if (ret != MPP_OK) {
		LOGE("failed to get header\n");
		mpp_packet_deinit(&tmp);
		return NULL;
	}

	mpp_packet_copy_init(&header, tmp);
	mpp_packet_deinit(&tmp);
	LOGV(1, "header packet size: %ld\n", mpp_packet_get_length(header));

	LEAVE();
	return header;
}

static void rkmpp_send_header(struct rkmpp_enc_context *enc)
{
	struct rkmpp_context *ctx = enc->ctx;
	struct rkmpp_buffer *rkmpp_buffer;

	ENTER();

	LOGV(1, "sending header\n");

	pthread_mutex_lock(&ctx->capture.queue_mutex);
	rkmpp_buffer = TAILQ_FIRST(&ctx->capture.pending_buffers);
	TAILQ_REMOVE(&ctx->capture.pending_buffers,
		     rkmpp_buffer, entry);
	rkmpp_buffer_clr_pending(rkmpp_buffer);

	rkmpp_buffer->bytesused = 0;
	rkmpp_packet_to_buffer(enc, enc->header, rkmpp_buffer);

	TAILQ_INSERT_TAIL(&ctx->capture.avail_buffers,
			  rkmpp_buffer, entry);
	rkmpp_buffer_set_available(rkmpp_buffer);
	pthread_mutex_unlock(&ctx->capture.queue_mutex);

	LEAVE();
}

static void *encoder_thread_fn(void *data)
{
	struct rkmpp_enc_context *enc = data;
	struct rkmpp_context *ctx = enc->ctx;
	struct rkmpp_buffer *rkmpp_buffer, *frame_buffer;
	MppPacket packet = NULL;
	MppMeta meta;
	MPP_RET ret;
	int index, is_keyframe;

	ENTER();

	LOGV(1, "ctx(%p): starting encoder thread\n", ctx);

	while (1) {
		pthread_mutex_lock(&enc->encoder_mutex);

		while (!enc->mpp_streaming)
			pthread_cond_wait(&enc->encoder_cond,
					  &enc->encoder_mutex);

		/* Store header before 1st frame */
		if (enc->needs_header && !enc->header)
			enc->header = rkmpp_get_header(enc);

		/* Wait for buffers */
		while (TAILQ_EMPTY(&ctx->capture.pending_buffers) ||
		       TAILQ_EMPTY(&ctx->output.pending_buffers))
			pthread_cond_wait(&enc->encoder_cond,
					  &enc->encoder_mutex);

		if (enc->type == H264 && enc->needs_header &&
		    enc->h264.separate_header) {
			if (enc->header) {
				/* Send separate header before 1st frame */
				rkmpp_send_header(enc);
				enc->needs_header = false;
			}
			pthread_mutex_unlock(&enc->encoder_mutex);
			goto next;
		}

		if (rkmpp_put_frame(enc) < 0) {
			pthread_mutex_unlock(&enc->encoder_mutex);
			continue;
		}

		packet = NULL;
		while (!packet) {
			ret = ctx->mpi->encode_get_packet(ctx->mpp, &packet);
			if (ret != MPP_OK) {
				LOGE("failed to get packet\n");
				goto next;
			}
		}

		pthread_mutex_unlock(&enc->encoder_mutex);

		pthread_mutex_lock(&ctx->ioctl_mutex);

		if (!enc->mpp_streaming)
			goto next_locked;

		pthread_mutex_lock(&ctx->capture.queue_mutex);
		rkmpp_buffer = TAILQ_FIRST(&ctx->capture.pending_buffers);
		TAILQ_REMOVE(&ctx->capture.pending_buffers,
			     rkmpp_buffer, entry);
		rkmpp_buffer_clr_pending(rkmpp_buffer);
		pthread_mutex_unlock(&ctx->capture.queue_mutex);

		rkmpp_buffer->bytesused = 0;

		if (enc->type == H264 && enc->needs_header &&
		    !enc->h264.separate_header) {
			/* Join the header to the 1st frame */
			rkmpp_packet_to_buffer(enc, enc->header, rkmpp_buffer);
			enc->needs_header = false;
		}

		rkmpp_packet_to_buffer(enc, packet, rkmpp_buffer);

		meta = mpp_packet_get_meta(packet);
		if (meta) {
			mpp_meta_get_s32(meta, KEY_OUTPUT_INTRA, &is_keyframe);

			if (is_keyframe) {
				rkmpp_buffer_set_keyframe(rkmpp_buffer);

				if (enc->keyframe_requested > 0) {
					enc->keyframe_requested--;
					rkmpp_enc_apply_rc_cfg(enc);
				}
			}
		}

		/* Use pts to track frame buffer */
		index = mpp_packet_get_pts(packet);
		frame_buffer = &ctx->output.buffers[index];

		rkmpp_buffer->timestamp = frame_buffer->timestamp;

		LOGV(3, "return frame(%" PRIu64 "): %d\n",
		     frame_buffer->timestamp, index);

		pthread_mutex_lock(&ctx->output.queue_mutex);
		TAILQ_INSERT_TAIL(&ctx->output.avail_buffers,
				  frame_buffer, entry);
		rkmpp_buffer_set_available(frame_buffer);
		pthread_mutex_unlock(&ctx->output.queue_mutex);

		/* Report new frame to count fps */
		rkmpp_new_frame(ctx);

		LOGV(3, "return packet(%" PRIu64 "): %d len=%d\n",
		     rkmpp_buffer->timestamp, rkmpp_buffer->index,
		     rkmpp_buffer->bytesused);

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

		if (packet)
			mpp_packet_deinit(&packet);
	}

	LEAVE();
	return NULL;
}

static int rkmpp_enc_qbuf(struct rkmpp_enc_context *enc,
			  struct v4l2_buffer *buffer)
{
	struct rkmpp_context *ctx = enc->ctx;
	int ret;

	ENTER();

	ret = rkmpp_qbuf(enc->ctx, buffer);
	if (ret < 0)
		RETURN_ERR(errno, -1);

	/* Notify new buffer */
	pthread_mutex_lock(&enc->encoder_mutex);
	pthread_cond_signal(&enc->encoder_cond);
	pthread_mutex_unlock(&enc->encoder_mutex);

	LEAVE();
	return ret;
}

static int rkmpp_enc_apply_h264_cfg(struct rkmpp_enc_context *enc)
{
	struct rkmpp_context *ctx = enc->ctx;
	MppEncCfg cfg;
	MPP_RET ret;

	if (mpp_enc_cfg_init(&cfg)) {
		LOGE("failed to init enc config\n");
		RETURN_ERR(ENOMEM, -1);
	}

	ret = ctx->mpi->control(ctx->mpp, MPP_ENC_GET_CFG, cfg);
	if (ret != MPP_OK) {
		LOGE("failed to get enc config\n");
		goto err;
	}

	mpp_enc_cfg_set_s32(cfg, "h264:profile", enc->h264.profile);
	mpp_enc_cfg_set_s32(cfg, "h264:level", enc->h264.level);

	mpp_enc_cfg_set_s32(cfg, "h264:trans8x8",
			    enc->h264.profile == MPP_H264_PROFILE_HIGH);
	mpp_enc_cfg_set_s32(cfg, "h264:cabac_en",
			    enc->h264.profile != MPP_H264_PROFILE_BASELINE);
	mpp_enc_cfg_set_s32(cfg, "h264:cabac_idc", 0);

	mpp_enc_cfg_set_s32(cfg, "h264:qp_max", enc->h264.max_qp);

	ret = ctx->mpi->control(ctx->mpp, MPP_ENC_SET_CFG, cfg);
	if (ret != MPP_OK) {
		LOGE("failed to set enc config: %d\n", ret);
		goto err;
	}

	mpp_enc_cfg_deinit(cfg);
	return 0;
err:
	mpp_enc_cfg_deinit(cfg);
	RETURN_ERR(EINVAL, -1);
}

static int rkmpp_enc_apply_vp8_cfg(struct rkmpp_enc_context *enc)
{
	struct rkmpp_context *ctx = enc->ctx;
	MppEncCfg cfg;
	MPP_RET ret;

	if (mpp_enc_cfg_init(&cfg)) {
		LOGE("failed to init enc config\n");
		RETURN_ERR(ENOMEM, -1);
	}

	ret = ctx->mpi->control(ctx->mpp, MPP_ENC_GET_CFG, cfg);
	if (ret != MPP_OK) {
		LOGE("failed to get enc config\n");
		goto err;
	}

	mpp_enc_cfg_set_s32(cfg, "vp8:qp_init", 40);
	mpp_enc_cfg_set_s32(cfg, "vp8:qp_max", 127);
	mpp_enc_cfg_set_s32(cfg, "vp8:qp_min", 0);

	mpp_enc_cfg_set_s32(cfg, "vp8:disable_ivf", 1);

	ret = ctx->mpi->control(ctx->mpp, MPP_ENC_SET_CFG, cfg);
	if (ret != MPP_OK) {
		LOGE("failed to set enc config: %d\n", ret);
		goto err;
	}

	mpp_enc_cfg_deinit(cfg);
	return 0;
err:
	mpp_enc_cfg_deinit(cfg);
	RETURN_ERR(EINVAL, -1);
}

static int rkmpp_enc_apply_input_cfg(struct rkmpp_enc_context *enc)
{
	struct rkmpp_context *ctx = enc->ctx;
	struct v4l2_pix_format_mplane *fmt = &ctx->output.format;
	const struct rkmpp_fmt *rkmpp_fmt = ctx->output.rkmpp_format;
	MppEncCfg cfg;
	MPP_RET ret;

	if (mpp_enc_cfg_init(&cfg)) {
		LOGE("failed to init enc config\n");
		RETURN_ERR(ENOMEM, -1);
	}

	ret = ctx->mpi->control(ctx->mpp, MPP_ENC_GET_CFG, cfg);
	if (ret != MPP_OK) {
		LOGE("failed to get enc config\n");
		goto err;
	}

	enc->width = enc->crop.width ? enc->crop.width : fmt->width;
	enc->height = enc->crop.height ? enc->crop.height : fmt->height;
	enc->hstride = fmt->plane_fmt[0].bytesperline * 8 / rkmpp_fmt->depth[0];
	enc->vstride = fmt->plane_fmt[0].sizeimage /
		fmt->plane_fmt[0].bytesperline;

	mpp_enc_cfg_set_s32(cfg, "prep:format", rkmpp_fmt->format);
	mpp_enc_cfg_set_s32(cfg, "prep:width", enc->width);
	mpp_enc_cfg_set_s32(cfg, "prep:height", enc->height);
	mpp_enc_cfg_set_s32(cfg, "prep:hor_stride", enc->hstride);
	mpp_enc_cfg_set_s32(cfg, "prep:ver_stride", enc->vstride);

	LOGV(1, "apply input size: %dx%d(%dx%d)\n",
	     enc->width, enc->height, enc->hstride, enc->vstride);

	ret = ctx->mpi->control(ctx->mpp, MPP_ENC_SET_CFG, cfg);
	if (ret != MPP_OK) {
		LOGE("failed to set enc config: %d\n", ret);
		goto err;
	}

	mpp_enc_cfg_deinit(cfg);
	return 0;
err:
	mpp_enc_cfg_deinit(cfg);
	RETURN_ERR(EINVAL, -1);
}

static int rkmpp_enc_apply_rc_cfg(struct rkmpp_enc_context *enc)
{
	struct rkmpp_context *ctx = enc->ctx;
	MppEncCfg cfg;
	MppEncRcMode rc_mode;
	MPP_RET ret;
	int bitrate;

	if (mpp_enc_cfg_init(&cfg)) {
		LOGE("failed to init enc config\n");
		RETURN_ERR(ENOMEM, -1);
	}

	ret = ctx->mpi->control(ctx->mpp, MPP_ENC_GET_CFG, cfg);
	if (ret != MPP_OK) {
		LOGE("failed to get enc config\n");
		goto err;
	}

	if (enc->mb_rc) {
		if (enc->rc_reaction_coeff < 10)
			/* The "tight" bitrate mode */
			rc_mode = MPP_ENC_RC_MODE_CBR;
		else
			rc_mode = MPP_ENC_RC_MODE_VBR;
	} else {
		/* Disable macroblock-level bitrate control */
		rc_mode = MPP_ENC_RC_MODE_FIXQP;
	}

	mpp_enc_cfg_set_s32(cfg, "rc:mode", rc_mode);

	mpp_enc_cfg_set_u32(cfg, "rc:max_reenc_times", 1);

	mpp_enc_cfg_set_s32(cfg, "rc:fps_in_flex", 0);
	mpp_enc_cfg_set_s32(cfg, "rc:fps_in_num", enc->numerator);
	mpp_enc_cfg_set_s32(cfg, "rc:fps_in_denorm", enc->denominator);
	mpp_enc_cfg_set_s32(cfg, "rc:fps_out_flex", 0);
	mpp_enc_cfg_set_s32(cfg, "rc:fps_out_num", enc->numerator);
	mpp_enc_cfg_set_s32(cfg, "rc:fps_out_denorm", enc->denominator);

	/* Use gop(1) for keyframe requests */
	mpp_enc_cfg_set_s32(cfg, "rc:gop",
			    !enc->keyframe_requested ? enc->gop_size : 1);

	bitrate = enc->bitrate;
	if (!bitrate)
		bitrate = enc->width * enc->height / 8 *
			enc->numerator / enc->denominator;

	if (enc->fixed_bitrate) {
		mpp_enc_cfg_set_s32(cfg, "rc:bps_target", bitrate);
		mpp_enc_cfg_set_s32(cfg, "rc:bps_max", bitrate);
		mpp_enc_cfg_set_s32(cfg, "rc:bps_min", bitrate);
	} else if (rc_mode == MPP_ENC_RC_MODE_FIXQP) {
		/* BPS settings are ignored in FIXQP mode */
		mpp_enc_cfg_set_s32(cfg, "rc:bps_target", -1);
		mpp_enc_cfg_set_s32(cfg, "rc:bps_max", -1);
		mpp_enc_cfg_set_s32(cfg, "rc:bps_min", -1);
	} else if (rc_mode == MPP_ENC_RC_MODE_CBR) {
		/* Constant bitrate has very small bps range of 1/16 bps */
		mpp_enc_cfg_set_s32(cfg, "rc:bps_target", bitrate);
		mpp_enc_cfg_set_s32(cfg, "rc:bps_max", bitrate * 17 / 16);
		mpp_enc_cfg_set_s32(cfg, "rc:bps_min", bitrate * 15 / 16);
	} else {
		/* Variable bitrate has large bps range */
		mpp_enc_cfg_set_s32(cfg, "rc:bps_target", bitrate);
		mpp_enc_cfg_set_s32(cfg, "rc:bps_max", bitrate * 17 / 16);
		mpp_enc_cfg_set_s32(cfg, "rc:bps_min", bitrate * 1 / 16);
	}

	ret = ctx->mpi->control(ctx->mpp, MPP_ENC_SET_CFG, cfg);
	if (ret != MPP_OK) {
		LOGE("failed to set enc config: %d\n", ret);
		goto err;
	}

	mpp_enc_cfg_deinit(cfg);
	return 0;
err:
	mpp_enc_cfg_deinit(cfg);
	RETURN_ERR(EINVAL, -1);
}

static int rkmpp_enc_streamon(struct rkmpp_enc_context *enc,
			      enum v4l2_buf_type *type)
{
	struct rkmpp_context *ctx = enc->ctx;
	const struct rkmpp_fmt *rkmpp_fmt = ctx->capture.rkmpp_format;
	struct rkmpp_buf_queue *queue;
	MppPollType poll_type;
	MPP_RET ret;

	ENTER();

	queue = rkmpp_get_queue(ctx, *type);
	if (!queue)
		RETURN_ERR(errno, -1);

	if (queue->streaming)
		goto out;
	queue->streaming = true;

	if (enc->mpp_streaming)
		goto out;

	switch (rkmpp_fmt->fourcc) {
	case V4L2_PIX_FMT_H264:
		enc->type = H264;
		break;
	case V4L2_PIX_FMT_VP8:
		enc->type = VP8;
		break;
	default:
		RETURN_ERR(errno, -1);
	}

	LOGV(1, "mpp start streaming\n");

	ret = mpp_create(&ctx->mpp, &ctx->mpi);
	if (ret != MPP_OK) {
		LOGE("failed to create mpp\n");
		errno = ENOMEM;
		goto err;
	}

	ret = mpp_init(ctx->mpp, MPP_CTX_ENC,
		       ctx->capture.rkmpp_format->type);
	if (ret != MPP_OK) {
		LOGE("failed to init mpp\n");
		goto err_destroy_mpp;
	}

	/* The mpp encoder only work in block mode */
	poll_type = MPP_POLL_BLOCK;
	ret = ctx->mpi->control(ctx->mpp, MPP_SET_OUTPUT_TIMEOUT,
				(MppParam)&poll_type);
	if (ret != MPP_OK) {
		LOGE("failed to set mpp timeout\n");
		goto err_destroy_mpp;
	}

	if (enc->type == H264) {
		/* Apply h264's special configs */
		if (rkmpp_enc_apply_h264_cfg(enc) < 0) {
			LOGE("failed to apply h264 cfg\n");
			goto err_destroy_mpp;
		}

		enc->needs_header = true;
	} else if (enc->type == VP8) {
		/* Apply vp8's special configs */
		if (rkmpp_enc_apply_vp8_cfg(enc) < 0) {
			LOGE("failed to apply vp8 cfg\n");
			goto err_destroy_mpp;
		}
	}

	if (enc->header)
		mpp_packet_deinit(&enc->header);
	enc->header = NULL;

	/* Apply configs about input frames */
	if (rkmpp_enc_apply_input_cfg(enc) < 0) {
		LOGE("failed to apply input cfg\n");
		goto err_destroy_mpp;
	}

	/* Apply configs about rate control */
	if (rkmpp_enc_apply_rc_cfg(enc) < 0) {
		LOGE("failed to apply rc cfg\n");
		goto err_destroy_mpp;
	}

	/* Notify encoder thread to start streaming */
	pthread_mutex_lock(&enc->encoder_mutex);
	enc->mpp_streaming = true;
	pthread_cond_signal(&enc->encoder_cond);
	pthread_mutex_unlock(&enc->encoder_mutex);
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

static int rkmpp_enc_streamoff(struct rkmpp_enc_context *enc,
			       enum v4l2_buf_type *type)
{
	struct rkmpp_context *ctx = enc->ctx;
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

	pthread_mutex_lock(&enc->encoder_mutex);

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

	/* Stop mpp streaming when all queues stopped */
	if (!enc->mpp_streaming) {
		pthread_mutex_unlock(&enc->encoder_mutex);
		goto out;
	}

	LOGV(1, "mpp stop streaming\n");

	enc->mpp_streaming = false;

	pthread_mutex_unlock(&enc->encoder_mutex);

	ctx->mpi->reset(ctx->mpp);
	mpp_destroy(ctx->mpp);
out:
	LEAVE();
	return 0;
}

static int rkmpp_enc_s_selection(struct rkmpp_enc_context *enc,
				 struct v4l2_selection *selection)
{
	struct rkmpp_context *ctx = enc->ctx;
	struct v4l2_pix_format_mplane *fmt = &ctx->output.format;
	struct v4l2_rect *rect = &selection->r;

	ENTER();

	if (selection->type != V4L2_BUF_TYPE_VIDEO_OUTPUT ||
	    selection->target != V4L2_SEL_TGT_CROP) {
		LOGE("invalid type or target\n");
		RETURN_ERR(EINVAL, -1);
	}

	if (ctx->output.streaming) {
		LOGE("output is streaming\n");
		RETURN_ERR(EBUSY, -1);
	}

	if (rect->top || rect->left) {
		LOGE("not support offsets\n");
		rect->width += rect->left;
		rect->height += rect->top;
		rect->top = rect->left = 0;
	}

	/* We can crop only inside right- or bottom-most macroblocks. */
	if (round_up(rect->width, RKMPP_MB_DIM) != fmt->width
	    || round_up(rect->height, RKMPP_MB_DIM) != fmt->height) {
		rect->width = fmt->width;
		rect->height = fmt->height;
	}

	/* We support widths aligned to 4 pixels and arbitrary heights. */
	rect->width = round_up(rect->width, 4);

	enc->crop = *rect;

	LOGV(1, "crop rect: %dx%d\n", enc->crop.width, enc->crop.height);

	LEAVE();
	return 0;
}

static int rkmpp_enc_s_parm(struct rkmpp_enc_context *enc,
			    struct v4l2_streamparm *parms)
{
	struct rkmpp_context *ctx = enc->ctx;

	ENTER();

	if (parms->type != V4L2_BUF_TYPE_VIDEO_OUTPUT_MPLANE) {
		LOGE("only support s_parm for output now\n");
		RETURN_ERR(EINVAL, -1);
	}

	/* V4L2 provide "time per frame", but mpp needs "frames per second" */
	enc->denominator = parms->parm.output.timeperframe.numerator;
	enc->numerator = parms->parm.output.timeperframe.denominator;

	LOGV(3, "numerator: %d, denominator: %d\n",
	     parms->parm.output.timeperframe.numerator,
	     parms->parm.output.timeperframe.denominator);

	if (enc->mpp_streaming &&
	    rkmpp_enc_apply_rc_cfg(enc) < 0) {
		LOGE("failed to apply framerate\n");
		RETURN_ERR(errno, -1);
	}

	LEAVE();
	return 0;
}

static int rkmpp_enc_queryctrl(struct rkmpp_enc_context *enc,
			       struct v4l2_queryctrl *query_ctrl)
{
	struct rkmpp_context *ctx = enc->ctx;

	ENTER();

	switch (query_ctrl->id) {
		/* TODO: fill info for supported ctrls */
	default:
		LOGV(1, "unsupported ctrl: %x\n", query_ctrl->id);
		RETURN_ERR(EINVAL, -1);
	}

	LEAVE();
	return 0;
}

static int rkmpp_enc_s_ext_ctrls(struct rkmpp_enc_context *enc,
				 struct v4l2_ext_controls *ext_ctrls)
{
	struct rkmpp_context *ctx = enc->ctx;
	struct v4l2_ext_control *ctrl;
	int i;

	ENTER();

	if (ext_ctrls->ctrl_class != V4L2_CTRL_CLASS_MPEG)
		RETURN_ERR(EINVAL, -1);

	for (i = 0; i < ext_ctrls->count; i++) {
		ctrl = &ext_ctrls->controls[i];

		switch (ctrl->id) {
		case V4L2_CID_MPEG_VIDEO_FORCE_KEY_FRAME:
			enc->keyframe_requested++;
			LOGV(3, "request keyframes: %d\n",
			     enc->keyframe_requested);

			if (enc->mpp_streaming &&
			    rkmpp_enc_apply_rc_cfg(enc) < 0) {
				LOGE("failed to request keyframe\n");
				RETURN_ERR(errno, -1);
			}
			break;
		case V4L2_CID_MPEG_VIDEO_BITRATE:
			enc->bitrate = ctrl->value;
			LOGV(3, "bitrate: %d\n", enc->bitrate);

			if (enc->mpp_streaming &&
			    rkmpp_enc_apply_rc_cfg(enc) < 0) {
				LOGE("failed to apply bitrate\n");
				RETURN_ERR(errno, -1);
			}
			break;
		case V4L2_CID_MPEG_VIDEO_FRAME_RC_ENABLE:
			if (!ctrl->value) {
				LOGE("unable to disable bitrate control\n");
				RETURN_ERR(EINVAL, -1);
			}
			break;
		case V4L2_CID_MPEG_VIDEO_B_FRAMES:
			if (ctrl->value) {
				LOGE("not supporting B-frames\n");
				RETURN_ERR(EINVAL, -1);
			}
			break;
		case V4L2_CID_MPEG_VIDEO_H264_MAX_QP:
			enc->h264.max_qp = ctrl->value;
			LOGV(3, "h264 max qp: %d\n", enc->h264.max_qp);

			if (enc->mpp_streaming &&
			    rkmpp_enc_apply_h264_cfg(enc) < 0) {
				LOGE("failed to apply h264 max qp\n");
				RETURN_ERR(errno, -1);
			}
			break;
		case V4L2_CID_MPEG_VIDEO_H264_PROFILE:
			if (ctrl->value != MPP_H264_PROFILE_BASELINE &&
			    ctrl->value != MPP_H264_PROFILE_MAIN &&
			    ctrl->value != MPP_H264_PROFILE_HIGH) {
				LOGE("only support baseline|main|high\n");
				RETURN_ERR(EINVAL, -1);
			}

			enc->h264.profile = ctrl->value;
			LOGV(3, "h264 profile: %d\n", enc->h264.profile);

			if (enc->mpp_streaming &&
			    rkmpp_enc_apply_h264_cfg(enc) < 0) {
				LOGE("failed to apply h264 profile\n");
				RETURN_ERR(errno, -1);
			}
			break;
		case V4L2_CID_MPEG_VIDEO_H264_LEVEL:
			enc->h264.level = ctrl->value;
			LOGV(3, "h264 level: %d\n", enc->h264.level);

			if (enc->mpp_streaming &&
			    rkmpp_enc_apply_h264_cfg(enc) < 0) {
				LOGE("failed to apply h264 level\n");
				RETURN_ERR(errno, -1);
			}
			break;
		case V4L2_CID_MPEG_VIDEO_HEADER_MODE:
			if (ctrl->value == V4L2_MPEG_VIDEO_HEADER_MODE_SEPARATE)
				enc->h264.separate_header = true;
			else
				enc->h264.separate_header = false;

			LOGV(3, "h264 separate header: %d\n", enc->h264.separate_header);
			break;
		case V4L2_CID_MPEG_VIDEO_MB_RC_ENABLE:
			enc->mb_rc = !!ctrl->value;
			LOGV(3, "mb rc: %d\n", enc->mb_rc);

			if (enc->mpp_streaming &&
			    rkmpp_enc_apply_rc_cfg(enc) < 0) {
				LOGE("failed to apply mb bitrate control\n");
				RETURN_ERR(errno, -1);
			}
			break;
		case V4L2_CID_MPEG_VIDEO_GOP_SIZE:
			enc->gop_size = ctrl->value;
			LOGV(3, "gop size: %d\n", enc->gop_size);

			if (enc->mpp_streaming &&
			    rkmpp_enc_apply_rc_cfg(enc) < 0) {
				LOGE("failed to apply gop size\n");
				RETURN_ERR(errno, -1);
			}
			break;
		case V4L2_CID_MPEG_MFC51_VIDEO_RC_REACTION_COEFF:
			enc->rc_reaction_coeff = ctrl->value;
			LOGV(3, "rc reaction coeff: %d\n",
			     enc->rc_reaction_coeff);

			if (enc->mpp_streaming &&
			    rkmpp_enc_apply_rc_cfg(enc) < 0) {
				LOGE("failed to apply rc reaction coeff\n");
				RETURN_ERR(errno, -1);
			}
			break;
		case V4L2_CID_MPEG_MFC51_VIDEO_RC_FIXED_TARGET_BIT:
			enc->fixed_bitrate = !!ctrl->value;
			LOGV(3, "fixed bitrate: %d\n", enc->fixed_bitrate);

			if (enc->mpp_streaming &&
			    rkmpp_enc_apply_rc_cfg(enc) < 0) {
				LOGE("failed to apply fixed bitrate\n");
				RETURN_ERR(errno, -1);
			}
			break;
		default:
			LOGE("unsupported ctrl: %x\n", ctrl->id);
			RETURN_ERR(EINVAL, -1);
		}
	}

	LEAVE();
	return 0;
}

bool rkmpp_enc_has_event(void *data)
{
	return false;
}

void *rkmpp_enc_init(struct rkmpp_context *ctx)
{
	struct rkmpp_enc_context *enc;

	ENTER();

	enc = (struct rkmpp_enc_context *)
		calloc(1, sizeof(struct rkmpp_enc_context));
	if (!enc)
		RETURN_ERR(ENOMEM, NULL);

	ctx->formats = rkmpp_enc_fmts;
	ctx->num_formats = ARRAY_SIZE(rkmpp_enc_fmts);
	enc->ctx = ctx;

	enc->h264.profile = MPP_H264_PROFILE_HIGH;
	enc->h264.level = 40; /* 1080p@30fps */
	enc->h264.max_qp = 28;
	enc->h264.separate_header = true;

	enc->mb_rc = true;
	enc->rc_reaction_coeff = 1;
	enc->gop_size = 30;
	enc->fixed_bitrate = false;

	enc->bitrate = 0;
	enc->denominator = 1;
	enc->numerator = 30;

	pthread_cond_init(&enc->encoder_cond, NULL);
	pthread_mutex_init(&enc->encoder_mutex, NULL);
	pthread_create(&enc->encoder_thread, NULL,
		       encoder_thread_fn, enc);

	LEAVE();
	return enc;
}

void rkmpp_enc_deinit(void *data)
{
	struct rkmpp_enc_context *enc = data;
	struct rkmpp_context *ctx = enc->ctx;

	ENTER();

	if (enc->encoder_thread) {
		pthread_cancel(enc->encoder_thread);
		pthread_join(enc->encoder_thread, NULL);
	}

	if (enc->header)
		mpp_packet_deinit(&enc->header);

	if (enc->mpp_streaming) {
		ctx->mpi->reset(ctx->mpp);
		mpp_destroy(ctx->mpp);
	}

	free(enc);

	LEAVE();
}

int rkmpp_enc_ioctl(void *data, unsigned long cmd, void *arg)
{
	struct rkmpp_enc_context *enc = data;
	struct rkmpp_context *ctx = enc->ctx;
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
	case VIDIOC_G_FMT:
		ret = rkmpp_g_fmt(ctx, arg);
		break;

	/* Encoder special ioctls */
	case VIDIOC_QBUF:
		ret = rkmpp_enc_qbuf(enc, arg);
		break;
	case VIDIOC_STREAMON:
		ret = rkmpp_enc_streamon(enc, arg);
		break;
	case VIDIOC_STREAMOFF:
		ret = rkmpp_enc_streamoff(enc, arg);
		break;
	case VIDIOC_S_SELECTION:
		ret = rkmpp_enc_s_selection(enc, arg);
		break;
	case VIDIOC_S_PARM:
		ret = rkmpp_enc_s_parm(enc, arg);
		break;
	case VIDIOC_QUERYCTRL:
		ret = rkmpp_enc_queryctrl(enc, arg);
		break;
	case VIDIOC_S_EXT_CTRLS:
		ret = rkmpp_enc_s_ext_ctrls(enc, arg);
		break;
	default:
		LOGV(1, "unsupported ioctl cmd: %s(%lu)!\n",
		     rkmpp_cmd2str(cmd), cmd);
		RETURN_ERR(ENOTTY, -1);
	}

	LEAVE();
	return ret;
}
