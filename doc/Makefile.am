## Process this file with automake to get Makefile.in

# commented out, no use to distribute yet
info_TEXINFOS = vpe.texi

man_MANS = vpe.5 vped.8 vpectrl.8 vped.conf.5

PERL = @PERL@
MAINTAINERCLEANFILES = vpe.texi vpe.5 vped.8 vpectrl.8 vped.conf.5

EXTRA_DIST = $(man_MANS) vpe.texi \
  Makefile.maint GNUmakefile Makefile.summ \
  vpe.texi.in vpe.5.pod vped.8.pod vpectrl.8.pod vped.conf.5.pod

# Use `ginstall' in the definition of man_MANS to avoid
# confusion with the `install' target.  The install rule transforms `ginstall'
# to install before applying any user-specified name transformations.
transform = s/ginstall/install/; @program_transform_name@

# For additional rules usually of interest only to the maintainer,
# see GNUmakefile and Makefile.maint.
