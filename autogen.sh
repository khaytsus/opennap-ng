#!/bin/sh

# Borrowed from the dspam project.

echo -n "Detecting locations of autoconf/automake binaries.."

PROG=`basename $0`

# Some OS's have multiple versions (autoconf259, etc.) and don't have an 
# autoconf binary

AUTOCONF=`which autoconf`
if test x"${AUTOCONF}" != x -a -f ${AUTOCONF}
then
    AUTOCONF=autoconf
    AUTOMAKE=automake
    ACLOCAL=aclocal
    AUTOHEADER=autoheader
else
    FINDPATH=`echo ${PATH}|sed -e 's,:, ,g'` 
    AUTOCONF=`find ${FINDPATH} -name "autoconf*"|sort -r|head -1`
    AUTOMAKE=`find ${FINDPATH} -name "automake*"|sort -r|head -1`
    ACLOCAL=`find ${FINDPATH} -name "aclocal*"|sort -r|head -1`
    AUTOHEADER=`find /usr/bin /usr/local/bin -name "autoheader*"|sort -r|head -1`
    echo "$0: autoconf: using ${AUTOCONF}"
    echo "$0: automake: using ${AUTOMAKE}"
    echo "$0: aclocal: using ${ACLOCAL}"
    echo "$0: autoheader: using ${AUTOHEADER}"
fi

echo "done."

AUTOPOINT_FLAGS=

# Some OS's require /usr/local/share/aclocal

if test ! -d /usr/local/share/aclocal
then
  ACLOCAL_FLAGS=''
else
  ACLOCAL_FLAGS='-I /usr/local/share/aclocal'
fi
#AUTOHEADER_FLAGS=-Wall
AUTOMAKE_FLAGS='--add-missing -c'
AUTOCONF_FLAGS=-Wno-obsolete

die()
{
    err=$?
    echo "$PROG: exited by previous error(s), return code was $err" >&2
    exit 1
}

echo "Running automake/autoconf binaries..  This could take a minute.."

echo "Running aclocal.."
${ACLOCAL} ${ACLOCAL_FLAGS}        || die
echo "Running autoheader.."
${AUTOHEADER} ${AUTOHEADER_FLAGS}  || die
echo "Running automake.."
${AUTOMAKE} ${AUTOMAKE_FLAGS}      || die
echo "Running autoconf.."
${AUTOCONF} ${AUTOCONF_FLAGS}      || die

if [ -z $1 ]; then
  echo "Ready to run configure with no arguments in 5s.."
  echo "If this is not what you want, ^c and run ./configure yourself."
  sleep 5s
  echo
  ./configure
else
  echo
  ./configure $*
fi

