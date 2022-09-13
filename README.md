# libv4l-rkmpp

A V4L2 plugin that wraps [rockchip-mpp](http://opensource.rock-chips.com/wiki_Mpp) for the chromium's V4L2 VDA/VEA (requires custom patches to enable those features).

The original idea comes from [v4l-gst](https://github.com/igel-oss/v4l-gst).

## Dependencies

* [v4l-utils](https://git.linuxtv.org/v4l-utils.git) - with this patch:  
  [0001-libv4l2-Support-mmap-to-libv4l-plugin.patch](https://github.com/JeffyCN/meta-rockchip/blob/release-1.3.0_20200915/recipes-multimedia/v4l2apps/v4l-utils/0001-libv4l2-Support-mmap-to-libv4l-plugin.patch)
* [rockchip-mpp](https://github.com/rockchip-linux/mpp)
* [linux-rga](https://github.com/rockchip-linux/linux-rga)

## Building

```
   $ meson build
   $ meson compile -C build
```

## Quick Start

1. Install libv4l-rkmpp.so into /usr/lib/libv4l/plugins/
2. Create dummy V4L2 device files for chromium VDA/VEA:
```
   # echo dec > /dev/video-dec0
   # chmod 666 /dev/video-dec0
   # echo enc > /dev/video-enc0
   # chmod 666 /dev/video-enc0
```
3. Run chromium's [VDA/VEA](https://chromium.googlesource.com/chromium/src/+/HEAD/docs/media/gpu/vdatest_usage.md)  

   The VDA's thumbnail tests would fail, which is harmless since we are not in [the md5 checksum list](https://cs.chromium.org/chromium/src/media/test/data/test-25fps.h264.json)  

   The VEA's CacheLineUnalignedInputTest test might crash, which is due to VEA buffer managing issue.  

4. Run with chromium browser:  
```
   export XDG_RUNTIME_DIR=/run/user/0
   chromium --no-sandbox --gpu-sandbox-start-early --ignore-gpu-blacklist
```
   This plugin is tested with [custom chromium](https://github.com/JeffyCN/meta-rockchip/tree/release-1.3.0_20200915/dynamic-layers/recipes-browser/chromium) on rk3399

## Limitation

1. There're a lot of chromium related hacks in it, might not work for other apps.  

   For proper decoding usage, there's a [ffmpeg solution](https://github.com/JeffyCN/FFmpeg) with a few extra buffer copies.

## FAQ

1. MPP reports errors?  

   Try the newest [MPP](https://github.com/rockchip-linux/mpp) release branch or develop branch or the commit with the closest commit date.  

   Also test with the [mpi_dec_test](https://github.com/rockchip-linux/mpp/blob/release/test/mpi_dec_test.c) to check if the MPP works:
```
# mpi_dec_test -t 7 -i test-25fps.h264
```  

2. The plugin complaining about "ERR: failed to init rga"?  

   Make sure "/dev/rga" exists and accessable by the chromium.

3. How to get more verbose logs?  

   For chromium, use these command line flags to change the log level: [--enable-logging --vmodule=*/media/gpu*=4](https://www.chromium.org/for-testers/enable-logging)  

   For libv4l-rkmpp, set the "LIBV4L_RKMPP_LOG_LEVEL" environment variable to change the log level. And set "LIBV4L_RKMPP_LOG_FPS" to enable logging fps.  

   For MPP, set the environment variable "mpp_debug", "rkv_h264d_debug", "mpp_dec_debug", "mpi_debug", etc. to change the modules' log levels.  

   For vpu driver, write verbose log level to "/sys/module/rk_vcodec/parameters/debug".

4. What about the performance?  

   The performance should be much the same as other MPP based decoders/encoders (e.g. mpi_dec_test and gstreamer MPP plugin).  

   And the performance would mostly related to the video's attributes (e.g. resolution and bitrate) and the vpu clock rates.

## Maintainers

* Jeffy Chen `<jeffy.chen@rock-chips.com>`
