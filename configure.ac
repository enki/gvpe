dnl Process this file with autoconf to produce a configure script.

AC_PREREQ(2.57)
AC_INIT(src/vped.C)
AC_CANONICAL_TARGET
AM_INIT_AUTOMAKE(vpe, 0.1)
AM_CONFIG_HEADER(config.h)
AM_MAINTAINER_MODE

AH_TOP([
#ifndef CONFIG_H__
#define CONFIG_H__

#ifdef __cplusplus
   using namespace std;
#endif

])

AH_BOTTOM([
#if __CYGWIN__

typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;

#else
#include <inttypes.h>

/* old modula-2 habits */
typedef unsigned char u8;
typedef uint16_t u16;
typedef uint32_t u32;
#endif

#endif
])

dnl Include the macros from the m4/ directory
AM_ACLOCAL_INCLUDE(m4)

AM_GNU_GETTEXT([external])
AM_GNU_GETTEXT_VERSION(0.11.5)

# Enable GNU extensions.
# Define this here, not in acconfig's @TOP@ section, since definitions
# in the latter don't make it into the configure-time tests.
AC_DEFINE([_GNU_SOURCE], 1, [Enable GNU extenstions])
AC_DEFINE([__USE_BSD], 1, [Enable BSD extensions])

ALL_LINGUAS=""

dnl Checks for programs.
AC_PROG_CC
AC_PROG_CPP
AC_PROG_CXX
AC_PROG_GCC_TRADITIONAL
AC_PROG_AWK
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_MAKE_SET
AC_PROG_RANLIB

AC_ISC_POSIX

m4_if([
dnl Check and set OS

case $target_os in
  *linux*)
    AC_DEFINE(HAVE_LINUX, 1, [Linux])
    [ rm -f src/device.c; ln -sf linux/device.c src/device.c ]
  ;;
  *freebsd*)
    AC_DEFINE(HAVE_FREEBSD, 1, [FreeBSD])
    [ rm -f src/device.c; ln -sf freebsd/device.c src/device.c ]
  ;;
  *darwin*)
    AC_DEFINE(HAVE_DARWIN, 1, [Darwin (MacOS/X)])
    [ rm -f src/device.c; ln -sf darwin/device.c src/device.c ]
  ;;
  *solaris*)
    AC_DEFINE(HAVE_SOLARIS, 1, [Solaris/SunOS])
    [ rm -f src/device.c; ln -sf solaris/device.c src/device.c ]
  ;;
  *openbsd*)
    AC_DEFINE(HAVE_OPENBSD, 1, [OpenBSD])
    [ rm -f src/device.c; ln -sf openbsd/device.c src/device.c ]
  ;;
  *netbsd*)
    AC_DEFINE(HAVE_NETBSD, 1, [NetBSD])
    [ rm -f src/device.c; ln -sf netbsd/device.c src/device.c ]
  ;;
  *cygwin*)
    AC_DEFINE(HAVE_CYGWIN, 1, [Cygwin])
    [ rm -f src/device.c; ln -sf cygwin/device.c src/device.c ]
  ;;
  *)
    AC_MSG_ERROR("Unknown operating system.")
  ;;
esac
])

AC_CACHE_SAVE

dnl Checks for libraries.

AC_LANG(C++)
AC_CHECK_HEADERS(ext/hash_map)

dnl Checks for header files.
AC_CHECK_HEADERS([fcntl.h inttypes.h limits.h malloc.h stdint.h strings.h syslog.h unistd.h \
	sys/file.h sys/ioctl.h sys/param.h sys/time.h netinet/in_systm.h cygwin.h])
AC_CHECK_HEADERS([net/ethernet.h net/if.h netinet/ip.h netinet/tcp.h], [], [],
	[#include <sys/types.h>
	 #include <sys/socket.h>
	 #ifdef HAVE_NETINET_IN_SYSTM_H
     #include <netinet/in_systm.h>
	 #endif])

dnl Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_HEADER_TIME
AC_STRUCT_TM

AC_CACHE_CHECK([for socklen_t], ac_cv_type_socklen_t,
[
  AC_TRY_COMPILE(
  [#include <sys/types.h>
  #include <sys/socket.h>],
  [socklen_t len = 42; return len;],
  ac_cv_type_socklen_t=yes,
  ac_cv_type_socklen_t=no)
])
if test $ac_cv_type_socklen_t = yes; then
  AC_DEFINE(HAVE_SOCKLEN_T, 1, [socklen_t available])
fi

AC_CACHE_CHECK([for struct addrinfo], ac_cv_struct_addrinfo,
[
  AC_TRY_COMPILE(
  [#include <sys/types.h>
  #include <sys/socket.h>
  #include <netdb.h>],
  [struct addrinfo ai; ai.ai_family = AF_INET; return ai.ai_family;],
  ac_cv_struct_addrinfo=yes,
  ac_cv_struct_addrinfo=no)
])
if test $ac_cv_struct_addrinfo = yes; then
  AC_DEFINE(HAVE_STRUCT_ADDRINFO, 1, [struct addrinfo available])
fi

dnl Checks for library functions.
AC_TYPE_SIGNAL

AC_LANG_PUSH(C)

AC_HEADER_STDC

AC_CHECK_FUNCS(asprintf daemon get_current_dir_name putenv select strerror strsignal strtol unsetenv mlockall)

AC_FUNC_ALLOCA

dnl Support for SunOS

AC_CHECK_FUNC(socket, [], [
  AC_CHECK_LIB(socket, connect)
])
AC_CHECK_FUNC(gethostbyname, [], [
  AC_CHECK_LIB(nsl, gethostbyname)
])

AC_LANG_POP

dnl AC_CHECK_FUNCS([freeaddrinfo gai_strerror getaddrinfo getnameinfo])

AC_CACHE_SAVE

dnl These are defined in files in m4/
tinc_TUNTAP
tinc_OPENSSL
dnl tinc_ZLIB

HMAC=16    dnl see also the AC_HELP_STRING
AC_ARG_ENABLE(hmac-length,
  [AC_HELP_STRING(--enable-hmac-length=BYTES, [use a hmac of length BYTES bytes (default 16). Allowed values are 4, 8, 12, 16.])],
  HMAC=$enableval
)
AC_DEFINE_UNQUOTED(HMACLENGTH, $HMAC, [Size of HMAC in each packet in bytes.])

RAND=8   dnl see also the AC_HELP_STRING
AC_ARG_ENABLE(rand-length,
  [AC_HELP_STRING(--enable-rand-length=BYTES, [use BYTES bytes of extra randomness (default 8). Allowed values are 0, 4, 8.])],
  RAND=$enableval
)
AC_DEFINE_UNQUOTED(RAND_SIZE, $RAND, [Add this many bytes of randomness to each packet.])

MTU=1500   dnl see also the AC_HELP_STRING
AC_ARG_ENABLE(mtu,
  [AC_HELP_STRING(--enable-max-mtu=BYTES, enable mtu sizes upto BYTES bytes (default 1500). Use 9100 for jumbogram support.)],
  MTU=$enableval
)
AC_DEFINE_UNQUOTED(MAX_MTU, $MTU + 14, [Maximum MTU supported.])

COMPRESS=1
AC_ARG_ENABLE(compression,
  [AC_HELP_STRING(--disable-compression, Disable compression support.)],
  if test "x$enableval" = xno; then
     COMPRESS=0
  fi
)
AC_DEFINE_UNQUOTED(ENABLE_COMPRESSION, $COMPRESS, [Enable compression support.])

CIPHER=bf_cbc
AC_ARG_ENABLE(cipher,
  [AC_HELP_STRING(--enable-cipher, [
     Select the symmetric cipher (default "bf"). Must be one of
     "bf" (blowfish), "aes-128", "aes-192" or "aes-256".])],
  if test "x$enableval" = xbf     ; then CIPHER=bf_cbc     ; fi
  if test "x$enableval" = xaes-128; then CIPHER=aes_128_cbc; fi
  if test "x$enableval" = xaes-192; then CIPHER=aes_192_cbc; fi
  if test "x$enableval" = xaes-256; then CIPHER=aes_256_cbc; fi
)
AC_DEFINE_UNQUOTED(ENABLE_CIPHER, EVP_${CIPHER}, [Select the symmetric cipher to use.])

DIGEST=sha1
AC_ARG_ENABLE(digest,
  [AC_HELP_STRING(--enable-digest, [
     Select the digets algorithm to use (default "sha1"). Must be one of
     "sha1", "ripemd160", "md4" or "md5".])],
  if test "x$enableval" = xsha1     ; then DIGEST=sha1     ; fi
  if test "x$enableval" = xripemd160; then DIGEST=ripemd160; fi
  if test "x$enableval" = xmd4      ; then DIGEST=md4      ; fi
  if test "x$enableval" = xmd5      ; then DIGEST=md5      ; fi
)
AC_DEFINE_UNQUOTED(ENABLE_DIGEST, EVP_${DIGEST}, [Select the digest algorithm to use.])

TRUST=1
m4_if([
AC_ARG_ENABLE(trust,
  [AC_HELP_STRING(--enable-trust, [
     Make authentication faster but allow decoding by all hosts of a VPN.
     Use this when the VPN hosts DO trust each other and you don't care
     wether man-in-the-middle sniffing attacks are possible by admins
     of other VPN hosts. On pentiums or similar machines this can cut down
     the time for reconnects by 0.4 seconds or more.])],
  if test "x$enableval" = xyes; then
     TRUST=1
  fi
)
])
AC_DEFINE_UNQUOTED(ENABLE_TRUST, $TRUST, [Faster, but VPN hosts may sniff each others data.])

if $CXX -v --help 2>&1 | grep -q fno-rtti; then
   CXXFLAGS="$CXXFLAGS -fno-rtti"
fi

if $CXX -v --help 2>&1 | grep -q fexceptions; then
   CXXFLAGS="$CXXFLAGS -fno-exceptions"
fi

if $CXX -v --help 2>&1 | grep -q ffunction-sections; then
   CXXFLAGS="$CXXFLAGS -ffunction-sections"
fi

if $LD -v --help 2>&1 | grep -q gc-sections; then
   LDFLAGS="$LDFLAGS -Wl,--gc-sections"
fi

AC_CONFIG_COMMANDS_POST([

echo
echo "***"
echo "*** Configuration Summary"
echo "***"
echo "*** Cipher used:  $CIPHER"
echo "*** Digest used:  $DIGEST"
echo "*** HMAC length:  $HMAC"
echo "*** RAND used:    $RAND"
echo "*** Max. MTU:     $MTU"
echo "*** Compression:  $COMPRESS"
dnl echo "*** Trusted Mode: $TRUST"
echo "***"
echo

])

AC_SUBST(INCLUDES)

AC_OUTPUT(Makefile po/Makefile.in
src/Makefile
doc/Makefile
lib/Makefile
m4/Makefile
)
