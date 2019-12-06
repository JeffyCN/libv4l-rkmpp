# libv4l-rkmpp

A V4L2 plugin that wraps [rockchip-mpp](http://opensource.rock-chips.com/wiki_Mpp) for the chromium's V4L2 VDA/VEA.

The original idea comes from [v4l-gst](https://github.com/igel-oss/v4l-gst).

## Dependencies

* [v4l-utils](https://git.linuxtv.org/v4l-utils.git) - with this patch:  
  [0001-libv4l2-Support-mmap-to-libv4l-plugin.patch](https://github.com/JeffyCN/meta-rockchip/blob/release-1.1.0_20191030/recipes-multimedia/v4l2apps/v4l-utils/0001-libv4l2-Support-mmap-to-libv4l-plugin.patch)
* [rockchip-mpp](https://github.com/rockchip-linux/mpp)
* [linux-rga](https://github.com/rockchip-linux/linux-rga)

## Building

```
   $ autoreconf -i --force
   $ ./configure
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

   The VEA's MultipleEncoders test might fail, which is due to MPP's rate control accuracy.

4. Run with chromium browser:  
   This plugin is tested with [this chromium browser](https://github.com/JeffyCN/meta-rockchip/tree/master/dynamic-layers/recipes-browser/chromium) on rk3326/rk3288 and need the newest version of [gpu library](https://github.com/rockchip-linux/libmali)
```
   export XDG_RUNTIME_DIR=/run/user/0
   chromium --no-sandbox --gpu-sandbox-start-early --ignore-gpu-blacklist
```

## Limitation

1. Switching resolutions would not work, since there's no way to generate POLLPRI event for v4l2 events.
2. There're a lot of chromium related hacks in it, might not work for other apps.  

   For proper decoding usage, there's a [ffmpeg solution](https://github.com/JeffyCN/FFmpeg) with a few extra buffer copies.

## FAQ

1. The chromium complaining about "Failed creating a VDA"?  

   Make sure "/usr/lib/libv4l2.so" exists and linked to "/usr/lib/libv4l2.so.0".  

   Then run the [mpi_dec_test](https://github.com/rockchip-linux/mpp/blob/release/test/mpi_dec_test.c) to check if the mpp works:
```
# mpi_dec_test -t 7 -i test-25fps.h264
```  

2. The plugin complaining about "ERR: failed to init rga"?  

   Make sure "/dev/rga" exists and accessable by the chromium.

3. How to get more verbose logs?  

   For chromium, use these command line flags to change the log level: [--enable-logging --v=1](https://www.chromium.org/for-testers/enable-logging)  

   For libv4l-rkmpp, set the "LIBV4L_RKMPP_LOG_LEVEL" environment variable to change the log level. And set "LIBV4L_RKMPP_LOG_FPS" to enable logging fps.  

   For mpp, set the environment variable "mpp_debug", "rkv_h264d_debug", "mpp_dec_debug", "mpi_debug", etc. to change the modules' log levels.  

   For vpu driver, write verbose log level to "/sys/module/rk_vcodec/parameters/debug".

4. What about the performance?  

   The performance should be much the same as other mpp based decoders/encoders (e.g. mpi_dec_test and gstreamer mpp plugin).  

   And the performance would mostly related to the video's attributes (e.g. resolution and bitrate) and the vpu clock rates.

5. Why the VDA test crashes a lot?  

   That might due to buggy chromium version, the tested ones are 73.0.3683.103/74.0.3729.157.

## Maintainers

* Jeffy Chen `<jeffy.chen@rock-chips.com>`
