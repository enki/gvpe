dnl Process this file with autoconf to produce a configure script.

AC_PREREQ(2.57)
AC_INIT(src/vped.C)
AC_CANONICAL_TARGET
AM_INIT_AUTOMAKE(vpe, 1.2)
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

AC_ARG_ENABLE(iftype,
  [AC_HELP_STRING(--enable-iftype[=TYPE/SUBTYPE], [
     Use kernel/net device interface TYPE/SUBTYPE.
     Working combinations are:
        "native/linux" "tincd/linux" "tincd/freebsd";
     Untested combinations are:
        "tincd/netbsd" "tincd/darwin" "tincd/solaris"
        "tincd/openbsd" "tincd/cygwin";
     Broken combinations are:
        "native/cygwin";
     The default is to autodetect.
  ])],
  [
    IFTYPE=`echo $enableval | sed s%/.*%%`
    IFSUBTYPE=`echo $enableval | sed s%.*/%%`
  ]
)

dnl Check and set OS
AC_MSG_CHECKING(for kernel networking interface type)

if test "x$IFTYPE" = "x"; then
   case $target_os in
     *linux*)
       IFTYPE=native
       IFSUBTYPE=linux
       AC_DEFINE(HAVE_LINUX, 1, [Linux])
     ;;
     *freebsd*)
       IFTYPE=tincd
       IFSUBTYPE=freebsd
       AC_DEFINE(HAVE_FREEBSD, 1, [FreeBSD])
     ;;
     *darwin*)
       IFTYPE=tincd
       IFSUBTYPE=darwin
       AC_DEFINE(HAVE_DARWIN, 1, [Darwin (MacOS/X)])
     ;;
     *solaris*)
       IFTYPE=tincd
       IFSUBTYPE=solaris
       AC_DEFINE(HAVE_SOLARIS, 1, [Solaris/SunOS])
     ;;
     *openbsd*)
       IFTYPE=tincd
       IFSUBTYPE=openbsd
       AC_DEFINE(HAVE_OPENBSD, 1, [OpenBSD])
     ;;
     *netbsd*)
       IFTYPE=tincd
       IFSUBTYPE=netbsd
       AC_DEFINE(HAVE_NETBSD, 1, [NetBSD])
     ;;
     *cygwin*)
       IFTYPE=tincd
       IFSUBTYPE=cygwin
       AC_DEFINE(HAVE_CYGWIN, 1, [Cygwin])
     ;;
     *)
       AC_MSG_ERROR("Unknown operating system.")
     ;;
   esac
fi
AC_MSG_RESULT($IFTYPE/$IFSUBTYPE)
AC_SUBST(IFTYPE,$IFTYPE)
AC_SUBST(IFSUBTYPE,$IFSUBTYPE)

AC_CACHE_SAVE

dnl Checks for libraries.

AC_LANG(C++)
AC_CHECK_HEADERS(ext/hash_map)

dnl Checks for header files.
AC_CHECK_HEADERS([fcntl.h inttypes.h limits.h malloc.h stdint.h strings.h syslog.h unistd.h \
	sys/file.h sys/ioctl.h sys/param.h sys/time.h netinet/in_systm.h cygwin.h arpa/inet.h \
        sys/poll.h sys/mman.h netinet/in.h])
AC_CHECK_HEADERS([net/ethernet.h net/if.h netinet/ip.h netinet/tcp.h netinet/in_systm.h], [], [],
[
#include <sys/types.h>
#include <sys/socket.h>
#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif
#ifdef HAVE_ARPA_INET_H
# include <arpa/inet.h>
#endif
#ifdef HAVE_NETINET_IN_SYSTM_H
# include <netinet/in_systm.h>
#endif
])

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

dnl argl, could somebody catapult darwin into the 21st century???
AC_CHECK_FUNCS(asprintf daemon get_current_dir_name putenv select strerror strsignal strtol unsetenv mlockall poll)

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
CXXFLAGS="$CXXFLAGS -I$openssl_include"
dnl tinc_ZLIB

AC_ARG_ENABLE(rohc,
  [AC_HELP_STRING(--enable-rohc, [enable robust header compression (rfc3095).])],
  [
  echo
  echo "**********************************************************************"
  echo "**********************************************************************"
  echo "**** --enable-rohc not yet implemented *******************************"
  echo "**********************************************************************"
  echo "**** uuh sorry, I am such an ass, but I didn't find any rfc3095 (ROHC)"
  echo "**** implementation to be used in GPL code on the web."
  echo "**** so this option is just a fake. Please implement one and send it"
  echo "**** to me ;)"
  echo "**********************************************************************"
  echo "**********************************************************************"
  echo "**********************************************************************"
  echo "**********************************************************************"
  echo
  ]
)

AC_ARG_ENABLE(icmp,
  [AC_HELP_STRING(--enable-icmp, [enable icmp protocol support (default disabled).])],
  AC_DEFINE_UNQUOTED(ENABLE_ICMP, 1, [ICMP protocol support.])
)

AC_ARG_ENABLE(tcp,
  [AC_HELP_STRING(--enable-tcp, [enable tcp protocol support (default disabled).])],
  AC_DEFINE_UNQUOTED(ENABLE_TCP, 1, [TCP protocol support.])
)

AC_ARG_ENABLE(http-proxy,
  [AC_HELP_STRING(--enable-http-proxy, [enable http proxy connect support (default disabled).])],
  AC_DEFINE_UNQUOTED(ENABLE_HTTP_PROXY, 1, [http proxy connect support.])
)

HMAC=12    dnl see also the AC_HELP_STRING
AC_ARG_ENABLE(hmac-length,
  [AC_HELP_STRING(--enable-hmac-length=BYTES, [use a hmac of length BYTES bytes (default 12). Allowed values are 4, 8, 12, 16.])],
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
     "bf" (blowfish), "aes-128" (rijndael), "aes-192" or "aes-256".])],
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
     "sha1", "ripemd160", "md5" or "md4" (insecure).])],
  if test "x$enableval" = xsha1     ; then DIGEST=sha1     ; fi
  if test "x$enableval" = xripemd160; then DIGEST=ripemd160; fi
  if test "x$enableval" = xmd5      ; then DIGEST=md5      ; fi
  if test "x$enableval" = xmd4      ; then DIGEST=md4      ; fi
)
AC_DEFINE_UNQUOTED(ENABLE_DIGEST, EVP_${DIGEST}, [Select the digest algorithm to use.])

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
echo "*** Kernel Iface: $IFTYPE/$IFSUBTYPE"
echo "*** Cipher used:  $CIPHER"
echo "*** Digest used:  $DIGEST"
echo "*** HMAC length:  $HMAC"
echo "*** RAND used:    $RAND"
echo "*** Max. MTU:     $MTU"
echo "*** Compression:  $COMPRESS"
echo "***"

if test "x$DIGEST" = xmd4; then
echo "*** WARNING"
echo "*** The digest you have chosen ($DIGEST) is known to be insecure"
echo "***"
fi

echo

])

AC_SUBST(INCLUDES)

AC_OUTPUT(Makefile po/Makefile.in
src/Makefile
doc/Makefile
lib/Makefile
m4/Makefile
)
