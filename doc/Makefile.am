## Process this file with automake to get Makefile.in

# commented out, no use to distribute yet
#info_TEXINFOS = vpe.texi

dyn_MANS =
man_aux = $(dyn_MANS:.8=.x)

man_MANS = vpe.8 vped.8 vpectrl.8 vped.conf.5 $(dyn_MANS)

PERL = @PERL@
HELP2MAN = help2man
MAINTAINERCLEANFILES = $(dyn_MANS)

EXTRA_DIST = $(man_MANS) $(HELP2MAN) $(man_aux) \
  Makefile.maint GNUmakefile Makefile.summ vped.conf.pod

# Use `ginstall' in the definition of man_MANS to avoid
# confusion with the `install' target.  The install rule transforms `ginstall'
# to install before applying any user-specified name transformations.
transform = s/ginstall/install/; @program_transform_name@

# For additional rules usually of interest only to the maintainer,
# see GNUmakefile and Makefile.maint.
