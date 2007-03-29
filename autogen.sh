#!/bin/sh 

AUTOCONF_REQUIRED_VERSION=2.57
AUTOMAKE_REQUIRED_VERSION=1.7
INTLTOOL_REQUIRED_VERSION=0.17


srcdir=`dirname $0`
test -z "$srcdir" && srcdir=.
ORIGDIR=`pwd`
cd $srcdir


check_version ()
{
    if expr $1 \>= $2 > /dev/null; then
	echo "yes (version $1)"
    else
	echo "Too old (found version $1)!"
#	DIE=1
    fi
}

DIE=0

echo -n "checking for autoconf >= $AUTOCONF_REQUIRED_VERSION ... "
if (autoconf --version) < /dev/null > /dev/null 2>&1; then
    VER=`autoconf --version \
         | grep -iw autoconf | sed "s/.* \([0-9.]*\)[-a-z0-9]*$/\1/"`
    check_version $VER $AUTOCONF_REQUIRED_VERSION
else
    echo
    echo "  You must have autoconf installed to compile $PROJECT."
    echo "  Download the appropriate package for your distribution,"
    echo "  or get the source tarball at ftp://ftp.gnu.org/pub/gnu/"
    DIE=1;
fi

echo -n "checking for automake >= $AUTOMAKE_REQUIRED_VERSION ... "
if (automake-1.7 --version) < /dev/null > /dev/null 2>&1; then
   AUTOMAKE=automake-1.7
   ACLOCAL=aclocal-1.7
else
    echo
    echo "  You must have automake 1.7 installed to compile $PROJECT."
    echo "  (or a newer version if it is available)"
#    DIE=1
fi

if test x$AUTOMAKE != x; then
    VER=`$AUTOMAKE --version \
         | grep automake | sed "s/.* \([0-9.]*\)[-a-z0-9]*$/\1/"`
    check_version $VER $AUTOMAKE_REQUIRED_VERSION
fi

: <<EOF
echo -n "checking for intltool >= $INTLTOOL_REQUIRED_VERSION ... "
if (intltoolize --version) < /dev/null > /dev/null 2>&1; then
    VER=`intltoolize --version \
         | grep intltoolize | sed "s/.* \([0-9.]*\)/\1/"`
    check_version $VER $INTLTOOL_REQUIRED_VERSION
else
    echo
    echo "  You must have intltool installed to compile $PROJECT."
    echo "  Get the latest version from"
    echo "  ftp://ftp.gnome.org/pub/GNOME/sources/intltool/"
    DIE=1
fi
EOF

if test "$DIE" -eq 1; then
    echo
    echo "Please install/upgrade the missing tools and call me again."
    echo	
    exit 1
fi

if test -z "$*"; then
    echo
    echo "I am going to run ./configure with no arguments - if you wish "
    echo "to pass any to it, please specify them on the $0 command line."
    echo
fi

$ACLOCAL -I m4

# optionally feature autoheader
(autoheader --version)  < /dev/null > /dev/null 2>&1 && autoheader

(cd m4 && make -f Makefile.am.in Makefile.am)
touch doc/gvpe.texi
$AUTOMAKE -f --add-missing
rm doc/gvpe.texi
autoconf
autoheader


#intltoolize --copy --force --automake

cd $ORIGDIR

if $srcdir/configure --enable-maintainer-mode "$@"; then
  echo
  echo "Now type 'make' to compile $PROJECT."
else
  echo
  echo "Configure failed or did not finish!"
fi

