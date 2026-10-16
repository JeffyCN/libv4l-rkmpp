/*
 *  libv4l-rkmpp: format conversion via Mali GPU (GLES2 + EGL dma-buf)
 *
 *  Second-tier fallback used when librga is missing or cannot handle
 *  the format. Uses the same approach as weston's libweston/backend-drm
 *  fb-convert.c: bind a YUV dma-buf as an OES_EGL_image_external
 *  texture, render through a fragment shader to an intermediate ARGB
 *  FBO, read back to CPU memory, then convert ARGB to NV12 in software
 *  (this final step is cheap -- 4K@30 is a few hundred us on a single
 *  A76 core). The GPU is fast enough that the readback is the
 *  real cost, so this path is only meant for low-rate or
 *  format-unusual content.
 *
 *  Copyright (c) 2024, Fuzhou Rockchip Electronics Co., Ltd
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include "config.h"
#include "libv4l-rkmpp.h"
#include "libv4l-rkmpp-convert.h"

#if HAVE_GPU

#include <gbm.h>
#include <EGL/egl.h>
#include <EGL/eglext.h>
#include <GLES2/gl2.h>
#include <GLES2/gl2ext.h>
#include <xf86drm.h>

#define EGL_LOAD_PROC(val, type, func) do { val = (type)eglGetProcAddress(func); } while (0)

static const char *vs_src =
	"attribute vec4 position;\n"
	"varying vec2 texcoord;\n"
	"void main() {\n"
	"   gl_Position = position;\n"
	/* No y-flip: FBO fragment row 0 lands at dmabuf offset 0, and
	 * glReadPixels reads bottom-up; flipping would invert output. */
	"   texcoord = position.xy * 0.5 + 0.5;\n"
	"}\n";

/* Plane-based YUV import. Mali's samplerExternalOES only converts the
 * 4:2:0 family (NV12/P010); an NV16 image imports fine but samples
 * black, and two-component GR88 imports are rejected outright
 * (EGL_BAD_MATCH) -- single-component R8 imports do work. So bind
 * luma and the interleaved chroma row as two single-plane R8 images
 * (the chroma texel grid spans the whole CbCr row: one texel == one
 * byte) and reconstruct Cb/Cr in the shader: the Cb texel is snapped
 * to the nearest pair-start (even byte), then Cr is one texel right.
 * BT.601 limited-range YUV -> RGB.
 *
 * Compact 10-bit (MPP_FMT_YUV420SP_10BIT) is a different beast: on
 * rkvdec it is the Rockchip NV12_10LE40 / NV15 packing (4 x 10-bit
 * samples in 5 bytes, LSB-first, hor_stride being a BYTE pitch), NOT
 * P010. The Mali DDK advertises this layout as DRM_FORMAT_NV15, so
 * the whole frame goes through ONE OES-textured EGLImage import (with
 * REC601 + narrow-range hints) and the hardware sampler does the
 * unpack plus the limited-range expansion; the 10-bit fragment shader
 * is a passthrough. Plain R16 plane imports of this buffer fail
 * (EGL_BAD_MATCH), and reading it as P010 would be wrong anyway.
 *
 * NOTE on rkvdec H.264 4:2:2 (MPP_FMT_YUV422SP): the buffer layout is
 * standard NV16, verified bit-exact against a software-decoded
 * reference frame on RK3588 (RK3576 reported the same, GitHub issue
 * #35):
 *   Y    @ 0,                hor_stride x ver_stride, 1 B/sample
 *   CbCr @ hor_stride*ver_stride, hor_stride bytes per row,
 *        ver_stride rows (one chroma row per luma row)
 * MPP over-allocates the pool buffer (2.5 B/px reported, 2.0 needed). */

/*
 * Direct plane render shaders.
 *
 * 8-bit src (only rkvdec 4:2:2 reaches this path; plain NV12 takes
 * the memcpy fast path): the dst Y plane (R8 attachment) is a
 * bit-exact texel copy from the src Y R8 texture.  The dst UV plane
 * (ABGR8888 attachment, one texel = 4 bytes = 2 CbCr pairs) picks
 * the 4:2:2 chroma pairs of the even luma columns, with
 * pair-boundary quantization to avoid cross-pair reads.
 *
 * 10-bit src: the OES sampler already outputs expanded RGB (NV15
 * import with hints); the dst planes need the BT.601 limited-range
 * inverse (RGB -> Y and RGB -> Cb/Cr pairs). */

/* 8-bit Y: bit-exact texel copy at 1:1 */
static const char *fs_plane_y8 =
	"precision highp float;\n"
	"uniform sampler2D tex_y;\n"
	"uniform vec2 t_step;\n"
	"void main() {\n"
	"   vec2 t = (floor(gl_FragCoord.xy) + 0.5) * t_step;\n"
	"   float v = texture2D(tex_y, t).r;\n"
	"   gl_FragColor = vec4(v, v, v, 1.0);\n"
	"}\n";

/* 8-bit UV (rkvdec 4:2:2 chroma, standard NV16): dst ABGR8888 texel
 * (tx,ty) holds the two NV12 pairs for luma cols 4tx..4tx+3 and luma
 * rows 2ty..2ty+1: the vertical average of the NV16 CbCr pairs at
 * bytes 4tx..4tx+3 of chroma rows 2ty and 2ty+1. Each channel samples
 * the same byte in both rows and averages: vec4(Cb(4tx), Cr(4tx),
 * Cb(4tx+2), Cr(4tx+2)). Sampling uses texel centers, so the mapping
 * is exact up to the +/-1 rounding of the average.
 *
 * Byte-order note (measured on RK3588, Mali BIF/G52 DDK): a vec4 store
 * to the ABGR8888 attachment lands in the plane as [.a, .r, .g, .b],
 * so the components are emitted rotated once (g, b, a, r) to make the
 * plane bytes read Cb, Cr, Cb, Cr as NV12 needs. */
static const char *fs_plane_uv8 =
	"precision highp float;\n"
	"uniform sampler2D tex_c;\n"
	"uniform vec2 c_step;\n"
	"void main() {\n"
	"   float bx = floor(gl_FragCoord.x) * 4.0;\n"
	"   float y0 = floor(gl_FragCoord.y) * 2.0 + 0.5;\n"
	"   float y1 = y0 + 1.0;\n"
	"   float b0 = 0.5 * (texture2D(tex_c, vec2((bx + 0.5) * c_step.x,\n"
	"       y0 * c_step.y)).r + texture2D(tex_c, vec2((bx + 0.5) * c_step.x,\n"
	"       y1 * c_step.y)).r);\n"
	"   float b1 = 0.5 * (texture2D(tex_c, vec2((bx + 1.5) * c_step.x,\n"
	"       y0 * c_step.y)).r + texture2D(tex_c, vec2((bx + 1.5) * c_step.x,\n"
	"       y1 * c_step.y)).r);\n"
	"   float b2 = 0.5 * (texture2D(tex_c, vec2((bx + 2.5) * c_step.x,\n"
	"       y0 * c_step.y)).r + texture2D(tex_c, vec2((bx + 2.5) * c_step.x,\n"
	"       y1 * c_step.y)).r);\n"
	"   float b3 = 0.5 * (texture2D(tex_c, vec2((bx + 3.5) * c_step.x,\n"
	"       y0 * c_step.y)).r + texture2D(tex_c, vec2((bx + 3.5) * c_step.x,\n"
	"       y1 * c_step.y)).r);\n"
	"   gl_FragColor = vec4(b1, b2, b3, b0);\n"
	"}\n";

/*
 * Compact 10-bit passthrough: the NV15 EGLImage import carries the
 * REC601 / narrow-range hints, so the hardware sampler unpacks the
 * 4-in-5 samples and expands limited-range Y by itself. Just forward
 * the expanded RGB; the CPU repack below does the BT.601 encode.
 */
static const char *fs_src_c10 =
	"#extension GL_OES_EGL_image_external : require\n"
	"precision highp float;\n"
	"varying vec2 texcoord;\n"
	"uniform samplerExternalOES tex_y;\n"
	"uniform vec2 src_scale;\n"
	"void main() {\n"
	"   gl_FragColor = vec4(texture2D(tex_y, texcoord * src_scale).rgb,"
	" 1.0);\n"
	"}\n";

struct gpu_ctx {
	int drm_fd;
	struct gbm_device *gbm;
	EGLDisplay display;
	EGLContext context;
	GLuint program_c10;
	GLuint program_plane_y8, program_plane_uv8;
	GLuint src_tex[2], src_tex_oes, dst_fbo, dst_tex;
	GLuint vbo;
	GLint pos_c10_loc;
	GLint src_scale_c10_loc;
	uint32_t tex_w, tex_h;
	bool inited;
	bool unavailable;
	MppFrameFormat unavailable_fmt;
};

static struct gpu_ctx gctx;

static GLuint compile_shader(GLenum type, const char *src)
{
	GLuint s = glCreateShader(type);
	glShaderSource(s, 1, &src, NULL);
	glCompileShader(s);
	GLint ok;
	glGetShaderiv(s, GL_COMPILE_STATUS, &ok);
	if (!ok) {
		char log[512];
		glGetShaderInfoLog(s, sizeof(log), NULL, log);
		LOGE("gpu: shader compile error: %s\n", log);
		glDeleteShader(s);
		return 0;
	}
	return s;
}


static GLuint build_program(const char *vs, const char *fs)
{
	GLuint p, s;
	GLint v;

	p = glCreateProgram();
	s = compile_shader(GL_VERTEX_SHADER, vs);
	glAttachShader(p, s);
	glDeleteShader(s);
	s = compile_shader(GL_FRAGMENT_SHADER, fs);
	glAttachShader(p, s);
	glDeleteShader(s);
	glLinkProgram(p);
	glGetProgramiv(p, GL_LINK_STATUS, &v);
	if (!v) {
		glDeleteProgram(p);
		return 0;
	}
	return p;
}

static bool gpu_init(void)
{
	PFNEGLGETPLATFORMDISPLAYEXTPROC get_platform_display;
	EGLint context_attrs[] = { EGL_CONTEXT_CLIENT_VERSION, 2, EGL_NONE };

	if (gctx.inited)
		return true;
	if (gctx.unavailable)
		return false;

	get_platform_display = (PFNEGLGETPLATFORMDISPLAYEXTPROC)
		eglGetProcAddress("eglGetPlatformDisplayEXT");
	if (!get_platform_display) {
		gctx.unavailable = true;
		return false;
	}

	gctx.drm_fd = drmOpen("rockchip", NULL);
	LOGV(1, "gpu init: drm opened fd=%d\n", gctx.drm_fd);
	if (gctx.drm_fd < 0)
		goto err;

	gctx.gbm = gbm_create_device(gctx.drm_fd);
	LOGV(1, "gpu init: gbm created\n");
	if (!gctx.gbm)
		goto err;

	gctx.display = get_platform_display(EGL_PLATFORM_GBM_KHR,
					   (void *)gctx.gbm, NULL);
	LOGV(1, "gpu init: display obtained\n");
	if (gctx.display == EGL_NO_DISPLAY)
		goto err;
	if (!eglInitialize(gctx.display, NULL, NULL))
		goto err;
	LOGV(1, "gpu init: egl initialized\n");
	if (!eglBindAPI(EGL_OPENGL_ES_API))
		goto err;

	gctx.context = eglCreateContext(gctx.display, NULL, EGL_NO_CONTEXT,
				       context_attrs);
	LOGV(1, "gpu init: context created\n");
	if (gctx.context == EGL_NO_CONTEXT)
		goto err;

	if (!eglMakeCurrent(gctx.display, EGL_NO_SURFACE, EGL_NO_SURFACE,
			    gctx.context))
		goto err;

	/* Build ALL programs before linking any: this DDK breaks
	 * subsequent glCreateShader/glCompileShader calls after a
	 * glLinkProgram. */
	gctx.program_plane_y8 = build_program(vs_src, fs_plane_y8);
	gctx.program_plane_uv8 = build_program(vs_src, fs_plane_uv8);
	gctx.program_c10 = build_program(vs_src, fs_src_c10);
	if (!gctx.program_plane_y8 || !gctx.program_plane_uv8 ||
	    !gctx.program_c10) {
		LOGE("gpu: plane program build failed\n");
		goto err;
	}

	glGenTextures(2, gctx.src_tex);
	glGenTextures(1, &gctx.src_tex_oes);
	glGenTextures(1, &gctx.dst_tex);
	glGenFramebuffers(1, &gctx.dst_fbo);
	for (int i = 0; i < 2; i++) {
		glBindTexture(GL_TEXTURE_2D, gctx.src_tex[i]);
		glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_LINEAR);
		glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_LINEAR);
		glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, GL_CLAMP_TO_EDGE);
		glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, GL_CLAMP_TO_EDGE);
	}
	glBindTexture(GL_TEXTURE_EXTERNAL_OES, gctx.src_tex_oes);
	glTexParameteri(GL_TEXTURE_EXTERNAL_OES, GL_TEXTURE_MIN_FILTER, GL_LINEAR);
	glTexParameteri(GL_TEXTURE_EXTERNAL_OES, GL_TEXTURE_MAG_FILTER, GL_LINEAR);
	glTexParameteri(GL_TEXTURE_EXTERNAL_OES, GL_TEXTURE_WRAP_S, GL_CLAMP_TO_EDGE);
	glTexParameteri(GL_TEXTURE_EXTERNAL_OES, GL_TEXTURE_WRAP_T, GL_CLAMP_TO_EDGE);

	/* All plane shaders read from TEXTURE0; set the sampler
	 * uniforms while the context is still current. */
	glUseProgram(gctx.program_plane_y8);
	glUniform1i(glGetUniformLocation(gctx.program_plane_y8, "tex_y"), 0);
	glUseProgram(gctx.program_plane_uv8);
	glUniform1i(glGetUniformLocation(gctx.program_plane_uv8, "tex_c"), 0);
	glUseProgram(gctx.program_c10);
	glUniform1i(glGetUniformLocation(gctx.program_c10, "tex_y"), 0);
	gctx.src_scale_c10_loc =
		glGetUniformLocation(gctx.program_c10, "src_scale");
	gctx.pos_c10_loc =
		glGetAttribLocation(gctx.program_c10, "position");

	/* Fullscreen quad for glDrawArrays. Without this the position
	 * attribute stays at its default constant value, every vertex
	 * collapses to the same point and nothing is ever rasterized. */
	{
		static const GLfloat quad[4][4] = {
			{ -1.0f, -1.0f, 0.0f, 1.0f },
			{  1.0f, -1.0f, 0.0f, 1.0f },
			{ -1.0f,  1.0f, 0.0f, 1.0f },
			{  1.0f,  1.0f, 0.0f, 1.0f },
		};

		glGenBuffers(1, &gctx.vbo);
		glBindBuffer(GL_ARRAY_BUFFER, gctx.vbo);
		glBufferData(GL_ARRAY_BUFFER, sizeof(quad), quad,
			     GL_STATIC_DRAW);
		glBindBuffer(GL_ARRAY_BUFFER, 0);
	}

	eglMakeCurrent(gctx.display, EGL_NO_SURFACE, EGL_NO_SURFACE,
		       EGL_NO_CONTEXT);

	gctx.inited = true;
	return true;
err:
	LOGE("gpu: egl init failed\n");
	gctx.unavailable = true;
	return false;
}

/* Whole-frame NV15 import for the compact 10-bit format, following
 * the glamor XV dmabuf path: width derived from the byte stride,
 * chroma plane right behind luma, REC601 + narrow-range hints so the
 * hardware sampler unpacks the 4-in-5 samples and expands limited
 * range for us. */

/* Zero-copy: render straight into the dst NV12 dmabuf planes.
 * Two passes: Y (R8 FBO) then UV (ABGR8888 FBO), a bit-exact copy
 * for the rkvdec 4:2:2 source. No readback, no CPU pack. */
static bool gpu_convert_planes(int dst_fd, uint32_t width, uint32_t height,
			       uint32_t hor_stride, uint32_t ver_stride)
{
	struct {
		GLuint tex, fbo;
		uint32_t fourcc;
		uint32_t w, h, pitch;
		uint32_t offset;
		GLuint program;
		GLuint dst_vw, dst_vh;
	} pass[2] = {
		{ 0, 0, 0x20203852 /* DRM_FORMAT_R8 */,
		  hor_stride, ver_stride, hor_stride, 0,
		  gctx.program_plane_y8, hor_stride, ver_stride },
		{ 0, 0, 0x34324142 /* AB24 */,
		  hor_stride / 4, ver_stride / 2, hor_stride, hor_stride * ver_stride,
		  gctx.program_plane_uv8, hor_stride / 4, ver_stride / 2 },
	};
	int p;
	bool ok = false;

	PFNGLEGLIMAGETARGETTEXTURE2DOESPROC image_target;
	PFNEGLCREATEIMAGEKHRPROC create_image;
	PFNEGLDESTROYIMAGEKHRPROC destroy_image;
	EGL_LOAD_PROC(image_target, PFNGLEGLIMAGETARGETTEXTURE2DOESPROC,
		      "glEGLImageTargetTexture2DOES");
	EGL_LOAD_PROC(create_image, PFNEGLCREATEIMAGEKHRPROC,
		      "eglCreateImageKHR");
	EGL_LOAD_PROC(destroy_image, PFNEGLDESTROYIMAGEKHRPROC,
		      "eglDestroyImageKHR");
	if (!image_target || !create_image || !destroy_image)
		return false;

	for (p = 0; p < 2; p++) {
		EGLint attrs[] = {
			EGL_WIDTH, (EGLint)pass[p].w,
			EGL_HEIGHT, (EGLint)pass[p].h,
			EGL_LINUX_DRM_FOURCC_EXT, (EGLint)pass[p].fourcc,
			EGL_DMA_BUF_PLANE0_FD_EXT, dst_fd,
			EGL_DMA_BUF_PLANE0_OFFSET_EXT, (EGLint)pass[p].offset,
			EGL_DMA_BUF_PLANE0_PITCH_EXT, (EGLint)pass[p].pitch,
			EGL_NONE,
		};
		EGLImageKHR img = create_image(gctx.display, EGL_NO_CONTEXT,
					       EGL_LINUX_DMA_BUF_EXT, NULL,
					       attrs);
		if (img == EGL_NO_IMAGE_KHR) {
			LOGE("gpu: planes: dst plane %d import failed\n", p);
			goto out;
		}

		glGenTextures(1, &pass[p].tex);
		glBindTexture(GL_TEXTURE_2D, pass[p].tex);
		image_target(GL_TEXTURE_2D, img);
		destroy_image(gctx.display, img);

		glGenFramebuffers(1, &pass[p].fbo);
		glBindFramebuffer(GL_FRAMEBUFFER, pass[p].fbo);
		glFramebufferTexture2D(GL_FRAMEBUFFER, GL_COLOR_ATTACHMENT0,
				       GL_TEXTURE_2D, pass[p].tex, 0);
		if (glCheckFramebufferStatus(GL_FRAMEBUFFER) !=
		    GL_FRAMEBUFFER_COMPLETE) {
			LOGE("gpu: planes: fbo incomplete (plane %d)\n", p);
			goto out;
		}
	}

	/* Pass 0: Y plane, bit-exact texel copy. */
	glBindFramebuffer(GL_FRAMEBUFFER, pass[0].fbo);
	glViewport(0, 0, pass[0].dst_vw, pass[0].dst_vh);
	glUseProgram(pass[0].program);
	glUniform2f(glGetUniformLocation(pass[0].program, "t_step"),
		    1.0f / hor_stride, 1.0f / ver_stride);
	glActiveTexture(GL_TEXTURE0);
	glBindTexture(GL_TEXTURE_2D, gctx.src_tex[0]);
	{
		GLint pl = glGetAttribLocation(pass[0].program, "position");
		glBindBuffer(GL_ARRAY_BUFFER, gctx.vbo);
		glEnableVertexAttribArray(pl);
		glVertexAttribPointer(pl, 4, GL_FLOAT, GL_FALSE, 0, 0);
		glDrawArrays(GL_TRIANGLE_STRIP, 0, 4);
		glDisableVertexAttribArray(pl);
	}

	/* Pass 1: UV plane, rkvdec 4:2:2 pair pick. */
	glBindFramebuffer(GL_FRAMEBUFFER, pass[1].fbo);
	glViewport(0, 0, pass[1].dst_vw, pass[1].dst_vh);
	glUseProgram(pass[1].program);
	/* c_step: the NV16 chroma plane is hor_stride bytes wide and
	 * ver_stride rows tall (one chroma row per luma row). */
	glUniform2f(glGetUniformLocation(pass[1].program, "c_step"),
		    1.0f / hor_stride, 1.0f / ver_stride);
	glActiveTexture(GL_TEXTURE0);
	glBindTexture(GL_TEXTURE_2D, gctx.src_tex[1]);
	{
		GLint pl = glGetAttribLocation(pass[1].program, "position");
		glBindBuffer(GL_ARRAY_BUFFER, gctx.vbo);
		glEnableVertexAttribArray(pl);
		glVertexAttribPointer(pl, 4, GL_FLOAT, GL_FALSE, 0, 0);
		glDrawArrays(GL_TRIANGLE_STRIP, 0, 4);
		glDisableVertexAttribArray(pl);
	}

	glFinish();
	ok = true;
out:
	glBindFramebuffer(GL_FRAMEBUFFER, 0);
	/* The dst-plane textures and FBOs are per-call: release them
	 * every time or they accumulate frame after frame. */
	for (p = 0; p < 2; p++) {
		if (pass[p].fbo)
			glDeleteFramebuffers(1, &pass[p].fbo);
		if (pass[p].tex)
			glDeleteTextures(1, &pass[p].tex);
	}
	return ok;
}

static bool bind_src_oes(int src_fd, uint32_t hor_stride,
			 uint32_t ver_stride)
{
	EGLDisplay dpy = gctx.display;
	EGLImageKHR img;
	uint32_t claimed_w = hor_stride / 10 * 8;
	EGLint attrs[] = {
		EGL_WIDTH, (EGLint)claimed_w,
		EGL_HEIGHT, (EGLint)ver_stride,
		EGL_LINUX_DRM_FOURCC_EXT, 0x3531564E, /* DRM_FORMAT_NV15 */
		EGL_DMA_BUF_PLANE0_FD_EXT, src_fd,
		EGL_DMA_BUF_PLANE0_OFFSET_EXT, 0,
		EGL_DMA_BUF_PLANE0_PITCH_EXT, (EGLint)hor_stride,
		EGL_DMA_BUF_PLANE1_FD_EXT, src_fd,
		EGL_DMA_BUF_PLANE1_OFFSET_EXT,
			(EGLint)((long)hor_stride * ver_stride),
		EGL_DMA_BUF_PLANE1_PITCH_EXT, (EGLint)hor_stride,
		EGL_YUV_COLOR_SPACE_HINT_EXT, EGL_ITU_REC601_EXT,
		EGL_SAMPLE_RANGE_HINT_EXT, EGL_YUV_NARROW_RANGE_EXT,
		EGL_NONE
	};

	PFNGLEGLIMAGETARGETTEXTURE2DOESPROC image_target;
	PFNEGLCREATEIMAGEKHRPROC create_image;
	PFNEGLDESTROYIMAGEKHRPROC destroy_image;

	EGL_LOAD_PROC(image_target, PFNGLEGLIMAGETARGETTEXTURE2DOESPROC,
		      "glEGLImageTargetTexture2DOES");
	EGL_LOAD_PROC(create_image, PFNEGLCREATEIMAGEKHRPROC,
		      "eglCreateImageKHR");
	EGL_LOAD_PROC(destroy_image, PFNEGLDESTROYIMAGEKHRPROC,
		      "eglDestroyImageKHR");
	if (!image_target || !create_image || !destroy_image)
		return false;

	img = create_image(dpy, EGL_NO_CONTEXT, EGL_LINUX_DMA_BUF_EXT,
			   NULL, attrs);
	if (img == EGL_NO_IMAGE_KHR) {
		LOGE("gpu: failed to import NV15 image (egl error 0x%x)\n",
		     (unsigned)eglGetError());
		return false;
	}

	glBindTexture(GL_TEXTURE_EXTERNAL_OES, gctx.src_tex_oes);
	image_target(GL_TEXTURE_EXTERNAL_OES, img);
	(void)glGetError();

	destroy_image(dpy, img);

	/* the OES image is claimed at hor_stride / 10 * 8 wide; sample
	 * the visible width within it. Viewport spans hor_stride x
	 * ver_stride, so x scales by hor_stride / claimed_w. */
	glUseProgram(gctx.program_c10);
	glUniform2f(gctx.src_scale_c10_loc,
		    (GLfloat)((double)hor_stride / claimed_w), 1.0f);
	(void)glGetError();
	return true;
}

static bool bind_yuv_to_tex(int src_fd, uint32_t hor_stride,
			    uint32_t ver_stride, MppFrameFormat fmt)
{
	PFNGLEGLIMAGETARGETTEXTURE2DOESPROC image_target;
	PFNEGLCREATEIMAGEKHRPROC create_image;
	PFNEGLDESTROYIMAGEKHRPROC destroy_image;
	EGLDisplay dpy = gctx.display;
	EGLImageKHR imgs[2] = { EGL_NO_IMAGE_KHR, EGL_NO_IMAGE_KHR };
	/* Plane geometry: { fourcc, width_texels, height, pitch_bytes,
	 * offset_bytes }. The chroma plane is imported as ONE
	 * single-component image spanning the whole interleaved CbCr row
	 * (one texel == one byte for R8); the dst shader snaps Cb reads
	 * to the nearest pair start and reads Cr one texel to the
	 * right. */
	EGLint fcc[2], pw[2], ph[2], pp[2], off[2];
	int i;
	bool ok = false;

	image_target = (PFNGLEGLIMAGETARGETTEXTURE2DOESPROC)
		eglGetProcAddress("glEGLImageTargetTexture2DOES");
	create_image = (PFNEGLCREATEIMAGEKHRPROC)
		eglGetProcAddress("eglCreateImageKHR");
	destroy_image = (PFNEGLDESTROYIMAGEKHRPROC)
		eglGetProcAddress("eglDestroyImageKHR");
	if (!image_target || !create_image || !destroy_image)
		return false;

	switch (fmt) {
	case MPP_FMT_YUV420SP:
		/* NV12: chroma row = hor_stride/2 CbCr pairs (hs bytes). */
		fcc[0] = 0x20203852; /* DRM_FORMAT_R8 */
		pw[0] = hor_stride;     ph[0] = ver_stride;
		pp[0] = hor_stride;     off[0] = 0;
		fcc[1] = 0x20203852; /* DRM_FORMAT_R8 */
		pw[1] = hor_stride;     ph[1] = ver_stride / 2;
		pp[1] = hor_stride;     off[1] = hor_stride * ver_stride;
		break;
	case MPP_FMT_YUV422SP:
		/* rkvdec H.264 4:2:2 output is standard NV16: chroma
		 * rows of hor_stride bytes, ver_stride rows (verified
		 * bit-exact against a software decode on RK3588). One
		 * chroma texel == one CbCr byte. */
		fcc[0] = 0x20203852; /* DRM_FORMAT_R8 */
		pw[0] = hor_stride;     ph[0] = ver_stride;
		pp[0] = hor_stride;     off[0] = 0;
		fcc[1] = 0x20203852; /* DRM_FORMAT_R8 */
		pw[1] = hor_stride;     ph[1] = ver_stride;
		pp[1] = hor_stride;     off[1] = hor_stride * ver_stride;
		break;
	default:
		LOGE("gpu: unsupported src fmt %d\n", fmt);
		return false;
	}

	for (i = 0; i < 2; i++) {
		imgs[i] = create_image(dpy, EGL_NO_CONTEXT,
				       EGL_LINUX_DMA_BUF_EXT, NULL,
				       (EGLint[]){
				EGL_WIDTH, pw[i],
				EGL_HEIGHT, ph[i],
				EGL_LINUX_DRM_FOURCC_EXT, fcc[i],
				EGL_DMA_BUF_PLANE0_FD_EXT, src_fd,
				EGL_DMA_BUF_PLANE0_OFFSET_EXT, off[i],
				EGL_DMA_BUF_PLANE0_PITCH_EXT, pp[i],
				EGL_NONE });
		if (imgs[i] == EGL_NO_IMAGE_KHR) {
			LOGE("gpu: eglCreateImageKHR (plane %d fourcc 0x%x "
			     "off %d) failed, disabling gpu convert\n",
			     i, fcc[i], off[i]);
			goto out_latch;
		}
	}

	glBindTexture(GL_TEXTURE_2D, gctx.src_tex[0]);
	image_target(GL_TEXTURE_2D, imgs[0]);
	glBindTexture(GL_TEXTURE_2D, gctx.src_tex[1]);
	image_target(GL_TEXTURE_2D, imgs[1]);
	ok = true;
out:
	if (imgs[0] != EGL_NO_IMAGE_KHR)
		destroy_image(dpy, imgs[0]);
	if (imgs[1] != EGL_NO_IMAGE_KHR)
		destroy_image(dpy, imgs[1]);
	return ok;
out_latch:
	/* Import failures are format/usage capability gaps, not transient
	 * errors. Latch the failing src format only -- a P010 import
	 * failure must not disable the GPU tier for NV12 / 4:2:2 streams
	 * in the same process. The caller falls back to the CPU tier. */
	gctx.unavailable_fmt = fmt;
	ok = false;
	goto out;
}

/* ARGB -> NV12. Simple BT.601 limited range conversion. */
static void argb_to_nv12(const uint8_t *argb, uint32_t w, uint32_t h,
			 uint32_t src_stride, uint8_t *dy, uint8_t *duv)
{
	uint32_t y, x;
	for (y = 0; y < h; y++) {
		for (x = 0; x < w; x++) {
			const uint8_t *p = &argb[y * src_stride + 4 * x];
			int r = p[0], g = p[1], b = p[2];
			int yy  = ((66 * r + 129 * g +  25 * b + 128) >> 8) + 16;
			int uu  = ((-38 * r -  74 * g + 112 * b + 128) >> 8) + 128;
			int vv  = ((112 * r -  94 * g -  18 * b + 128) >> 8) + 128;
			dy[y * w + x] = (uint8_t)(yy < 0 ? 0 : yy > 255 ? 255 : yy);
			if ((y & 1) == 1 && (x & 1) == 0) {
				/* dst chroma row y / 2: average rgb
				 * rows y - 1 and y, per column. */
				const uint8_t *q = p - src_stride;
				int rq = q[0], gq = q[1], bq = q[2];
				int uu2 = ((-38 * rq - 74 * gq + 112 * bq + 128) >> 8) + 128;
				int vv2 = ((112 * rq - 94 * gq - 18 * bq + 128) >> 8) + 128;
				int cu = (uu2 + uu + 1) / 2;
				int cv = (vv2 + vv + 1) / 2;

				duv[(y / 2) * w + x]     = (uint8_t)(cu < 0 ? 0 : cu > 255 ? 255 : cu);
				duv[(y / 2) * w + x + 1] = (uint8_t)(cv < 0 ? 0 : cv > 255 ? 255 : cv);
			}
		}
	}
}

int rkmpp_dec_convert_gpu(struct rkmpp_context *ctx,
			  struct rkmpp_buffer *src,
			  struct rkmpp_buffer *dst,
			  MppFrameFormat src_fmt,
			  MppFrameFormat dst_fmt,
			  uint32_t width, uint32_t height,
			  uint32_t hor_stride, uint32_t ver_stride)
{
	bool use_c10;
	uint8_t *rgba = NULL;
	uint8_t *dst_y_ptr, *dst_uv_ptr;
	uint32_t y_size, uv_size, dst_size;
	GLuint fbo_status;
	int ret;

	(void)ctx;

	if (dst_fmt != MPP_FMT_YUV420SP) {
		LOGE("gpu: dst must be NV12 (got %d)\n", dst_fmt);
		return -ENOTSUP;
	}
	if (!gpu_init())
		return -ENOTSUP;
	if (gctx.unavailable_fmt == src_fmt)
		return -ENOTSUP;

	/* Must be current before creating/attaching the dst texture. */
	if (!eglMakeCurrent(gctx.display, EGL_NO_SURFACE, EGL_NO_SURFACE,
			    gctx.context))
		return -EIO;

	/* Compact 10-bit goes through the whole-frame NV15 OES import
	 * with the hardware sampler doing unpack + CSC, then a
	 * readback + CPU repack into the dst NV12. (The direct
	 * plane-render encode misdecodes this format: the DDK's NV15
	 * sampler grid does not match the claimed import geometry.)
	 * The 8-bit formats use the zero-copy plane-based shader. */
	use_c10 = (src_fmt == MPP_FMT_YUV420SP_10BIT);

	if (use_c10) {
		if (!bind_src_oes(src->fd, hor_stride, ver_stride)) {
			eglMakeCurrent(gctx.display, EGL_NO_SURFACE,
				       EGL_NO_SURFACE, EGL_NO_CONTEXT);
			goto out_latch_fmt;
		}
	} else if (!bind_yuv_to_tex(src->fd, hor_stride,
				    ver_stride, src_fmt)) {
		eglMakeCurrent(gctx.display, EGL_NO_SURFACE,
			       EGL_NO_SURFACE, EGL_NO_CONTEXT);
		goto out_latch_fmt;
	}

	if (!use_c10) {
		/* Zero-copy planes path: render into the dst dmabuf
		 * planes directly. A failure here (dst plane import
		 * rejected or the FBO not renderable) is a DDK
		 * capability gap, not a transient error: latch the
		 * src format and let the caller fall back to the CPU
		 * tier. */
		int dfd = dst->fd;
		bool ok = dfd >= 0 &&
			  gpu_convert_planes(dfd, width, height,
					     hor_stride, ver_stride);

		eglMakeCurrent(gctx.display, EGL_NO_SURFACE,
			       EGL_NO_SURFACE, EGL_NO_CONTEXT);
		if (ok) {
			LOGV(1, "gpu convert (planes): fmt %d -> 0 %ux%u ok\n",
			     src_fmt, width, height);
			return 0;
		}
		goto out_latch_fmt;
	}

	if (gctx.tex_w != hor_stride || gctx.tex_h != ver_stride) {
		glDeleteTextures(1, &gctx.dst_tex);
		glBindTexture(GL_TEXTURE_2D, 0);
		glGenTextures(1, &gctx.dst_tex);
		glBindTexture(GL_TEXTURE_2D, gctx.dst_tex);
		glTexImage2D(GL_TEXTURE_2D, 0, GL_RGBA, hor_stride, ver_stride,
			     0, GL_RGBA, GL_UNSIGNED_BYTE, NULL);
		glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_LINEAR);
		glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_LINEAR);
		gctx.tex_w = hor_stride;
		gctx.tex_h = ver_stride;
	}

	glBindFramebuffer(GL_FRAMEBUFFER, gctx.dst_fbo);
	glFramebufferTexture2D(GL_FRAMEBUFFER, GL_COLOR_ATTACHMENT0,
			       GL_TEXTURE_2D, gctx.dst_tex, 0);
	fbo_status = glCheckFramebufferStatus(GL_FRAMEBUFFER);
	if (fbo_status != GL_FRAMEBUFFER_COMPLETE) {
		LOGE("gpu: fbo incomplete: 0x%x\n", fbo_status);
		glBindFramebuffer(GL_FRAMEBUFFER, 0);
		eglMakeCurrent(gctx.display, EGL_NO_SURFACE, EGL_NO_SURFACE,
			       EGL_NO_CONTEXT);
		return -EIO;
	}

	glViewport(0, 0, hor_stride, ver_stride);
	glClearColor(0, 0, 0, 1);
	glClear(GL_COLOR_BUFFER_BIT);
	glUseProgram(gctx.program_c10);
	glActiveTexture(GL_TEXTURE0);
	glBindTexture(GL_TEXTURE_EXTERNAL_OES, gctx.src_tex_oes);
	glBindBuffer(GL_ARRAY_BUFFER, gctx.vbo);
	glEnableVertexAttribArray(gctx.pos_c10_loc);
	glVertexAttribPointer(gctx.pos_c10_loc, 4, GL_FLOAT, GL_FALSE, 0, 0);
	glDrawArrays(GL_TRIANGLE_STRIP, 0, 4);
	glDisableVertexAttribArray(gctx.pos_c10_loc);
	glBindBuffer(GL_ARRAY_BUFFER, 0);

	rgba = malloc((size_t)hor_stride * ver_stride * 4);
	if (!rgba) {
		glBindFramebuffer(GL_FRAMEBUFFER, 0);
		eglMakeCurrent(gctx.display, EGL_NO_SURFACE, EGL_NO_SURFACE,
			       EGL_NO_CONTEXT);
		return -ENOMEM;
	}
	glReadPixels(0, 0, hor_stride, ver_stride, GL_RGBA, GL_UNSIGNED_BYTE, rgba);

	glBindFramebuffer(GL_FRAMEBUFFER, 0);
	eglMakeCurrent(gctx.display, EGL_NO_SURFACE, EGL_NO_SURFACE,
		       EGL_NO_CONTEXT);

	y_size = hor_stride * ver_stride;
	uv_size = y_size / 2;
	dst_size = y_size + uv_size;
	if (dst->size < dst_size) {
		free(rgba);
		LOGE("gpu: dst buffer too small\n");
		return -EINVAL;
	}
	dst_y_ptr = mmap(NULL, dst_size, PROT_READ | PROT_WRITE, MAP_SHARED,
			 dst->fd, 0);
	if (dst_y_ptr == MAP_FAILED) {
		free(rgba);
		return -errno;
	}
	dst_uv_ptr = dst_y_ptr + y_size;
	argb_to_nv12(rgba, hor_stride, ver_stride,
		     hor_stride * 4, dst_y_ptr, dst_uv_ptr);
	munmap(dst_y_ptr, dst_size);
	free(rgba);

	LOGV(1, "gpu convert: fmt %d -> 0 %ux%u ok\n", src_fmt, width, height);
	return 0;

out_latch_fmt:
	/* Latch the failing src format so we do not hammer the driver
	 * every frame; the caller falls back to the CPU tier. */
	gctx.unavailable_fmt = src_fmt;
	return -ENOTSUP;
}

#else /* !HAVE_GPU */

int rkmpp_dec_convert_gpu(struct rkmpp_context *ctx,
			  struct rkmpp_buffer *src,
			  struct rkmpp_buffer *dst,
			  MppFrameFormat src_fmt,
			  MppFrameFormat dst_fmt,
			  uint32_t width, uint32_t height,
			  uint32_t hor_stride, uint32_t ver_stride)
{
	(void)ctx; (void)src; (void)dst;
	(void)width; (void)height; (void)hor_stride; (void)ver_stride;
	LOGE("format conversion (mpp fmt %d -> %d) requested but built without GPU\n",
	     src_fmt, dst_fmt);
	return -ENOTSUP;
}

#endif
