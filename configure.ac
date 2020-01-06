# -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([libv4l-rkmpp], [1.0.0])

AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_SRCDIR([src/libv4l-rkmpp.c])
AC_CONFIG_HEADERS([config.h])

AC_GNU_SOURCE
AC_SYS_LARGEFILE

AM_INIT_AUTOMAKE([1.9 subdir-objects no-dist-gzip dist-bzip2 -Wno-portability])

m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])

# Checks for programs.
AC_PROG_CXX
AC_PROG_AWK
AC_PROG_CC
AC_PROG_CPP
AC_PROG_INSTALL
AC_PROG_LIBTOOL
AC_PROG_LN_S
AC_PROG_MAKE_SET
AC_PROG_RANLIB

# Checks for libraries.
AC_CHECK_LIB([pthread], [pthread_create])
PKG_PROG_PKG_CONFIG
PKG_CHECK_MODULES(DRM, [libdrm >= 2.4.0])
PKG_CHECK_MODULES(RKMPP, rockchip_mpp >= 1.3.8)
PKG_CHECK_MODULES(LIBV4L2, libv4l2 >= 1.4.1)
AC_CHECK_LIB([rga], [c_RkRgaInit])

# Checks for header files.
AC_CHECK_HEADERS([fcntl.h inttypes.h stdint.h stdlib.h string.h unistd.h])
AC_CHECK_HEADERS([rga/RgaApi.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_CHECK_HEADER_STDBOOL
AC_C_INLINE
AC_TYPE_INT64_T
AC_TYPE_SIZE_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T
AC_TYPE_UINT8_T

# Checks for library functions.
AC_FUNC_MMAP
AC_CHECK_FUNCS([dup2 gettimeofday memset munmap])

# Setup libv4l2 plugin dir
AC_ARG_WITH(libv4l2subdir,
        AS_HELP_STRING([--with-libv4l2subdir=DIR], [set libv4l2 library subdir (default=libv4l)]),
        [],
        [with_libv4l2subdir="libv4l"])

AC_SUBST([libv4l2plugindir], [$libdir/$with_libv4l2subdir/plugins])

AC_DEFINE_DIR([LIBV4L2_PLUGIN_DIR], [libv4l2plugindir], [libv4l2 plugin directory])

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
