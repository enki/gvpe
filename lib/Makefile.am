noinst_LIBRARIES = libvpe.a

INCLUDES = @INCLUDES@ -I. -I$(top_builddir)

libvpe_a_SOURCES = pidfile.c getopt.c getopt1.c dropin.c

libvpe_a_LIBADD = @LIBOBJS@ @ALLOCA@
libvpe_a_DEPENDENCIES = $(libvpn_a_LIBADD)

noinst_HEADERS = pidfile.h getopt.h dropin.h gettext.h

