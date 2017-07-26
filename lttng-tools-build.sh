#!/bin/sh

BUILD_DIR=$1

TOPDIR=`realpath $BUILD_DIR`

rpmbuild -ba ${BUILD_DIR}/rpmbuild/SPECS/lttng-tools.spec  --define "_topdir $TOPDIR/rpmbuild"

cp ${BUILD_DIR}/rpmbuild/RPMS/x86_64/*.rpm ${BUILD_DIR}/output_rpms
