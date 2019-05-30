# libv4l-rkmpp

A V4L2 plugin that wraps [rockchip-mpp](http://opensource.rock-chips.com/wiki_Mpp) for the chromium's V4L2 VDA.

The original idea comes from [v4l-gst](https://github.com/igel-oss/v4l-gst).

## Dependencies

* [v4l-utils](https://git.linuxtv.org/v4l-utils.git) - with this patch:  
  [0001-libv4l2-Support-mmap-to-libv4l-plugin.patch](https://github.com/JeffyCN/meta-rockchip/blob/master/common/recipes-multimedia/v4l2apps/v4l-utils/0001-libv4l2-Support-mmap-to-libv4l-plugin.patch)
* [rockchip-mpp](https://github.com/rockchip-linux/mpp)

## Building

```
   $ autoreconf -i --force
   $ ./configure
```

## Quick Start

1. Install libv4l-rkmpp.so into /usr/lib/libv4l/plugins/
2. Create a dummy V4L2 device file for chromium VDA:
```
   # touch /dev/video-dec0
   # chmod 666 /dev/video-dec0
```
3. Run chromium's [video_decode_accelerator_unittest](https://chromium.googlesource.com/chromium/src/+/HEAD/docs/media/gpu/vdatest_usage.md)  
   The thumbnail tests should fail, which is harmless since we are not in [the md5 checksum list](https://cs.chromium.org/chromium/src/media/test/data/test-25fps.h264.json)

4. Run with chromium browser:  
   This plugin is tested with [this chromium browser](https://github.com/JeffyCN/meta-rockchip/tree/master/dynamic-layers/recipes-browser/chromium) on rk3326/rk3288 and need a special version of [gpu library](https://github.com/JeffyCN/misc/tree/master/libmali-chromium):  
```
   export XDG_RUNTIME_DIR=/run/user/0
   chromium --no-sandbox --gpu-sandbox-start-early --ozone-platform=wayland --ignore-gpu-blacklist
```

## Limitation

1. Only support decoder now.
2. Only support V4L2_MEMORY_MMAP/V4L2_MEMORY_USERPTR.
3. Switching resolutions would not work, since there's no way to generate POLLPRI event for v4l2 events.
4. There're a lot of chromium related hacks in it, might not work for other apps.

## FAQ

1. The chromium complaining about "Failed creating a VDA"?  

   Make sure "/usr/lib/libv4l2.so" exists and linked to "/usr/lib/libv4l2.so.0".  

   Then run the [mpi_dec_test](https://github.com/rockchip-linux/mpp/blob/release/test/mpi_dec_test.c) to check if the mpp works:
```
# mpi_dec_test -t 7 -i test-25fps.h264
```  

2. How to get more verbose logs?  

   For chromium, use these command line flags to change the log level: [--enable-logging --v=1](https://www.chromium.org/for-testers/enable-logging)  

   For libv4l-rkmpp, set the "LIBV4L_RKMPP_LOG_LEVEL" environment variable to change the log level. And set "LIBV4L_RKMPP_LOG_FPS" to enable logging fps.  

   For mpp, set the environment variable "mpp_debug", "rkv_h264d_debug", "mpp_dec_debug", "mpi_debug", etc. to change the modules' log levels.  

   For vpu driver, write verbose log level to "/sys/module/rk_vcodec/parameters/debug".

3. What about the performance?  

   The decoding performance apart from sourcing and rendering, should be much the same as other mpp based decoders (e.g. mpi_dec_test and gstreamer mpp plugin).  

   And the performance would mostly related to the video source's attributes (e.g. resolution and bitrate) and the vpu clock rates.

4. Why the VDA test crashes a lot?  

   That might due to buggy chromium version, the tested ones are 73.0.3683.103/74.0.3729.157.

## Maintainers

* Jeffy Chen `<jeffy.chen@rock-chips.com>`
