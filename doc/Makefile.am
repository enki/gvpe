## Process this file with automake to get Makefile.in

# commented out, no use to distribute yet
info_TEXINFOS = vpe.texi

man_MANS = vpe.5 vped.8 vpectrl.8 vped.conf.5 vpe.protocol.7 vpe.osdep.5

PERL = @PERL@
MAINTAINERCLEANFILES = vpe.texi vpe.5 vped.8 vpectrl.8 vped.conf.5 vpe.protocol.7 vpe.osdep.5

EXTRA_DIST = $(man_MANS) vpe.texi \
  Makefile.maint GNUmakefile Makefile.summ \
  vpe.texi.in vpe.5.pod vped.8.pod vpectrl.8.pod vped.conf.5.pod vpe.protocol.7.pod vpe.osdep.5.pod \
  complex-example/README complex-example/if-up complex-example/node-up complex-example/vped.conf


# Use `ginstall' in the definition of man_MANS to avoid
# confusion with the `install' target.  The install rule transforms `ginstall'
# to install before applying any user-specified name transformations.
transform = s/ginstall/install/; @program_transform_name@

# For additional rules usually of interest only to the maintainer,
# see GNUmakefile and Makefile.maint.

