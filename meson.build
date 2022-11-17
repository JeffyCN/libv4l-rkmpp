project(
  'libv4l-rkmpp',
  'c',
  version : '1.5.1',
  meson_version : '>=0.49.0',
  default_options : ['buildtype=release', 'warning_level=3'],
)

libthreads_dep = dependency('threads')
libv4l_dep = dependency('libv4l2')
mpp_dep = dependency('rockchip_mpp')
rga_dep = dependency('librga', required : get_option('rga'))

cdata = configuration_data()

if get_option('verbose')
  cdata.set10('DEBUG', 1)
endif

if rga_dep.found() and not get_option('rga').disabled()
  cdata.set10('HAVE_RGA', 1)
endif

cdata.set('MAX_DEC_WIDTH', get_option('max-dec-width'))
cdata.set('MAX_DEC_HEIGHT', get_option('max-dec-height'))
cdata.set('MAX_ENC_WIDTH', get_option('max-enc-width'))
cdata.set('MAX_ENC_HEIGHT', get_option('max-enc-height'))

configure_file(output : 'config.h', configuration : cdata)

deps = [
  libthreads_dep,
  libv4l_dep,
  mpp_dep,
  rga_dep,
]

srcs = [
  'src/libv4l-rkmpp.c',
  'src/libv4l-rkmpp-dec.c',
  'src/libv4l-rkmpp-enc.c',
  'src/utils.c',
]

shared_library(
  'v4l-rkmpp',
  srcs,
  include_directories : include_directories('.', 'include'),
  dependencies : deps,
  install : true,
  install_dir : get_option('libdir') / get_option('libv4l2subdir') / 'plugins',
)
