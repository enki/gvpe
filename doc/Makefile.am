## Process this file with automake to get Makefile.in

info_TEXINFOS = gvpe.texi

man_MANS = gvpe.5 gvpe.8 gvpectrl.8 gvpe.conf.5 gvpe.protocol.7 gvpe.osdep.5

PERL = @PERL@
MAINTAINERCLEANFILES = gvpe.texi gvpe.5 gvpe.8 gvpectrl.8 gvpe.conf.5 gvpe.protocol.7 gvpe.osdep.5

EXTRA_DIST = $(man_MANS) gvpe.texi \
  Makefile.maint \
  gvpe.texi.pod gvpe.5.pod gvpe.8.pod gvpectrl.8.pod gvpe.conf.5.pod gvpe.protocol.7.pod gvpe.osdep.5.pod \
  complex-example/README complex-example/if-up complex-example/node-up complex-example/gvpe.conf


# Use `ginstall' in the definition of man_MANS to avoid
# confusion with the `install' target.  The install rule transforms `ginstall'
# to install before applying any user-specified name transformations.
transform = s/ginstall/install/; @program_transform_name@

# For additional rules usually of interest only to the maintainer,
# see GNUmakefile and Makefile.maint.

