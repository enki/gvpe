## Produce this file with automake to get Makefile.in

sbin_PROGRAMS = vped
bin_PROGRAMS = vpectrl

EXTRA_DIST = device-linux.C device-cygwin.C device-tincd.C callback.pl	\
   tincd/apply tincd/fixit	\
   tincd/cygwin/device.c tincd/darwin/device.c tincd/freebsd/device.c	\
   tincd/linux/device.c tincd/mingw/device.c tincd/netbsd/device.c	\
   tincd/openbsd/device.c tincd/raw_socket/device.c tincd/solaris/device.c


INCLUDES = @INCLUDES@ -I$(top_builddir) -I$(top_srcdir)/lib

LIBS = @LIBS@ @LIBINTL@

COMMON = global.h conf.h conf.C util.h util.C device.h device.C \
         slog.h slog.C netcompat.h

vped_SOURCES = vped.C hash_map.h vpn.h vpn.C vpn_tcp.C sockinfo.h sockinfo.C \
               lzf/lzf.h lzf/lzfP.h lzf/lzf_c.c lzf/lzf_d.c iom.h iom.C \
               connection.h connection.C callback.h \
               $(COMMON)
vped_LDADD = $(top_builddir)/lib/libvpe.a
vpectrl_SOURCES = vpectrl.C \
                  $(COMMON)
vpectrl_LDADD = $(top_builddir)/lib/libvpe.a

localedir = $(datadir)/locale

DEFINES = -DPKGLIBDIR=$(pkglibdir) -DCONFDIR=\"$(sysconfdir)\"	\
	  -DLOCALEDIR=\"$(localedir)\" -DLOCALSTATEDIR=\"$(localstatedir)\" \
          -DIFTYPE_@IFTYPE@=1 -DIF_@IFSUBTYPE@=1

AM_CFLAGS = $(DEFINES)
AM_CXXFLAGS = $(DEFINES)

dist-hook:
	rm -f `find . -type l`

