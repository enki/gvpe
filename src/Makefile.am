## Produce this file with automake to get Makefile.in

sbin_PROGRAMS = vped
bin_PROGRAMS = vpectrl

EXTRA_DIST = device-linux.C device-cygwin.C

INCLUDES = @INCLUDES@ -I$(top_builddir) -I$(top_srcdir)/lib

LIBS = @LIBS@ @LIBINTL@

COMMON = global.h conf.h conf.C util.h util.C device.h device.C \
         slog.h slog.C

vped_SOURCES = vped.C hash_map.h vpn.h vpn.C sockinfo.h sockinfo.C \
               lzf/lzf.h lzf/lzfP.h lzf/lzf_c.c lzf/lzf_d.c iom.h iom.C \
               connection.h connection.C callback.h \
               $(COMMON)
vped_LDADD = $(top_builddir)/lib/libvpe.a
vpectrl_SOURCES = vpectrl.C \
                  $(COMMON)
vpectrl_LDADD = $(top_builddir)/lib/libvpe.a

localedir = $(datadir)/locale

DEFINES = -DPKGLIBDIR=$(pkglibdir) -DCONFDIR=\"$(sysconfdir)\"	\
	  -DLOCALEDIR=\"$(localedir)\" -DLOCALSTATEDIR=\"$(localstatedir)\"

AM_CFLAGS = $(DEFINES)
AM_CXXFLAGS = $(DEFINES)

dist-hook:
	rm -f `find . -type l`

