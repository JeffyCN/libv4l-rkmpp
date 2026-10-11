project(
  'libv4l-rkmpp',
  'c',
  version : '1.9.0',
  meson_version : '>=0.50.0',
  default_options : ['buildtype=release', 'warning_level=3'],
)

libthreads_dep = dependency('threads')
libv4l_dep = dependency('libv4l2')
mpp_dep = dependency('rockchip_mpp')
rga_dep = dependency('librga', required : false)
egl_dep = dependency('egl', required : false)
glesv2_dep = dependency('glesv2', required : false)
gbm_dep = dependency('gbm', required : false)
drm_dep = dependency('libdrm', required : false)

# GPU conversion requires all four
gpu_dep = (egl_dep.found() and glesv2_dep.found() and
           gbm_dep.found() and drm_dep.found()) ? true : false

cdata = configuration_data()

if get_option('verbose')
  cdata.set10('DEBUG', 1)
endif

cdata.set10('HAVE_RGA', rga_dep.found())
cdata.set10('HAVE_GPU', gpu_dep)
cdata.set('MAX_DEC_WIDTH', get_option('max-dec-width'))
cdata.set('MAX_DEC_HEIGHT', get_option('max-dec-height'))
cdata.set('MAX_ENC_WIDTH', get_option('max-enc-width'))
cdata.set('MAX_ENC_HEIGHT', get_option('max-enc-height'))

configure_file(output : 'config.h', configuration : cdata)

deps = [
  libthreads_dep,
  libv4l_dep,
  mpp_dep,
]

if rga_dep.found()
  deps += rga_dep
endif

if gpu_dep
  deps += [egl_dep, glesv2_dep, gbm_dep, drm_dep]
endif

srcs = [
  'src/libv4l-rkmpp.c',
  'src/libv4l-rkmpp-dec.c',
  'src/libv4l-rkmpp-enc.c',
  'src/utils.c',
  'src/libv4l-rkmpp-cpu.c',
  'src/libv4l-rkmpp-rga.c',
  'src/libv4l-rkmpp-gpu.c',
]

shared_library(
  'v4l-rkmpp',
  srcs,
  include_directories : include_directories('.', 'include'),
  dependencies : deps,
  install : true,
  install_dir : get_option('libdir') / get_option('libv4l2subdir') / 'plugins',
)
