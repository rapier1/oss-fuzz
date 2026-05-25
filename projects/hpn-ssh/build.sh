#!/bin/bash -eu
# Copyright 2024 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
################################################################################

# Enable null cipher
sed -i 's/#define CFLAG_INTERNAL.*/#define CFLAG_INTERNAL 0/' cipher.c

# Turn off agent unlock password failure delays
sed -i 's|\(usleep.*\)|// \1|' ssh-agent.c

# Build project
autoreconf
env
if ! env CFLAGS="" ./configure \
    --without-hardening \
    --without-zlib-version-check \
    --with-cflags="-DWITH_XMSS=1" \
    --with-cflags-after="$CFLAGS" \
    --with-ldflags-after="-g $CFLAGS" ; then
	echo "------ config.log:" 1>&2
	cat config.log 1>&2
	echo "ERROR: configure failed" 1>&2
	exit 1
fi
make -j$(nproc) all

# Build fuzzers
EXTRA_CFLAGS="-DCIPHER_NONE_AVAIL=1 -D_GNU_SOURCE -Iopenbsd-compat/include"
STATIC_CRYPTO="-Wl,-Bstatic -lcrypto -Wl,-Bdynamic"

SK_NULL=ssh-sk-null.o
SK_DUMMY=sk-dummy.o
COMMON_DEPS="ssh-pkcs11-client.o -lssh -lopenbsd-compat"

$CC $CFLAGS $EXTRA_CFLAGS -I. -g -c \
	regress/misc/fuzz-harness/ssh-sk-null.cc -o ssh-sk-null.o
$CC $CFLAGS $EXTRA_CFLAGS -I. -g -c \
	-DSK_DUMMY_INTEGRATE=1 regress/misc/sk-dummy/sk-dummy.c -o sk-dummy.o

$CXX $CXXFLAGS -std=c++11 $EXTRA_CFLAGS -I. -L. -Lopenbsd-compat -g \
	regress/misc/fuzz-harness/pubkey_fuzz.cc -o $OUT/pubkey_fuzz \
	$COMMON_DEPS $SK_NULL $STATIC_CRYPTO $LIB_FUZZING_ENGINE
$CXX $CXXFLAGS -std=c++11 $EXTRA_CFLAGS -I. -L. -Lopenbsd-compat -g \
	regress/misc/fuzz-harness/privkey_fuzz.cc -o $OUT/privkey_fuzz \
	$COMMON_DEPS $SK_NULL $STATIC_CRYPTO $LIB_FUZZING_ENGINE
$CXX $CXXFLAGS -std=c++11 $EXTRA_CFLAGS -I. -L. -Lopenbsd-compat -g \
	regress/misc/fuzz-harness/sig_fuzz.cc -o $OUT/sig_fuzz \
	$COMMON_DEPS $SK_NULL $STATIC_CRYPTO $LIB_FUZZING_ENGINE
$CXX $CXXFLAGS -std=c++11 $EXTRA_CFLAGS -I. -L. -Lopenbsd-compat -g \
	regress/misc/fuzz-harness/authopt_fuzz.cc -o $OUT/authopt_fuzz \
	auth-options.o $COMMON_DEPS $SK_NULL $STATIC_CRYPTO \
	$LIB_FUZZING_ENGINE
$CXX $CXXFLAGS -std=c++11 $EXTRA_CFLAGS -I. -L. -Lopenbsd-compat -g \
	regress/misc/fuzz-harness/sshsig_fuzz.cc -o $OUT/sshsig_fuzz \
	sshsig.o $COMMON_DEPS $SK_NULL $STATIC_CRYPTO \
	$LIB_FUZZING_ENGINE
$CXX $CXXFLAGS -std=c++11 $EXTRA_CFLAGS -I. -L. -Lopenbsd-compat -g \
	regress/misc/fuzz-harness/sshsigopt_fuzz.cc -o $OUT/sshsigopt_fuzz \
	sshsig.o $COMMON_DEPS $SK_NULL $STATIC_CRYPTO \
	$LIB_FUZZING_ENGINE
$CXX $CXXFLAGS -std=c++11 $EXTRA_CFLAGS -I. -L. -Lopenbsd-compat -g \
	regress/misc/fuzz-harness/kex_fuzz.cc -o $OUT/kex_fuzz \
	$COMMON_DEPS -lz $SK_NULL $STATIC_CRYPTO \
	$LIB_FUZZING_ENGINE

$CC $CFLAGS $EXTRA_CFLAGS -I. -g -c \
	regress/misc/fuzz-harness/agent_fuzz_helper.c -o agent_fuzz_helper.o
# Rebuild ssh-sk.c with ENABLE_SK_INTERNAL=1 for agent_fuzz, but write
# to a different .o so the make-built ssh-sk.o (no ENABLE_SK_INTERNAL)
# isn't clobbered.  If clobbered, the hpnssh-sk-helper link fails on a
# subsequent build because sk-usbhid.o no longer satisfies references
# that only exist in the internal-mode build.  Harmless in ephemeral
# oss-fuzz CI; bites local-mount development builds.
$CC $CFLAGS $EXTRA_CFLAGS -I. -g -c -DENABLE_SK_INTERNAL=1 \
	ssh-sk.c -o ssh-sk-internal.o
$CXX $CXXFLAGS -std=c++11 $EXTRA_CFLAGS -I. -L. -Lopenbsd-compat -g \
	regress/misc/fuzz-harness/agent_fuzz.cc -o $OUT/agent_fuzz \
	$SK_DUMMY agent_fuzz_helper.o ssh-sk-internal.o $COMMON_DEPS -lz \
	$STATIC_CRYPTO $LIB_FUZZING_ENGINE

# HPN-SSH SFTP-extension fuzzers (not present upstream).
# sftp_bundle_extract_fuzz exercises the server-side tar reader path
# (hpn-bundle-open@hpnssh.org); statically links libarchive because
# oss-fuzz's base-runner image doesn't ship libarchive.so.13.  Same
# -Bstatic/-Bdynamic pattern the existing $STATIC_CRYPTO uses.
$CXX $CXXFLAGS -std=c++11 $EXTRA_CFLAGS -I. -g \
	regress/misc/fuzz-harness/sftp_bundle_extract_fuzz.cc \
	-o $OUT/sftp_bundle_extract_fuzz \
	-Wl,-Bstatic -larchive -Wl,-Bdynamic $LIB_FUZZING_ENGINE

# sftp_fs_info_fuzz exercises the client-side reply parser for
# hpn-fs-info@hpnssh.org; needs libssh (for sshbuf) and ssh-sk-null.o
# to stub the SK functions that sshkey.o pulls in transitively.
$CXX $CXXFLAGS -std=c++11 $EXTRA_CFLAGS -I. -L. -Lopenbsd-compat -g \
	regress/misc/fuzz-harness/sftp_fs_info_fuzz.cc \
	-o $OUT/sftp_fs_info_fuzz \
	$COMMON_DEPS $SK_NULL $STATIC_CRYPTO $LIB_FUZZING_ENGINE

# Prepare seed corpora
CASES="$SRC/openssh-fuzz-cases"
(set -e ; cd ${CASES}/key ; zip -r $OUT/pubkey_fuzz_seed_corpus.zip .)
(set -e ; cd ${CASES}/privkey ; zip -r $OUT/privkey_fuzz_seed_corpus.zip .)
(set -e ; cd ${CASES}/sig ; zip -r $OUT/sig_fuzz_seed_corpus.zip .)
(set -e ; cd ${CASES}/authopt ; zip -r $OUT/authopt_fuzz_seed_corpus.zip .)
(set -e ; cd ${CASES}/sshsig ; zip -r $OUT/sshsig_fuzz_seed_corpus.zip .)
(set -e ; cd ${CASES}/sshsigopt ; zip -r $OUT/sshsigopt_fuzz_seed_corpus.zip .)
(set -e ; cd ${CASES}/kex ; zip -r $OUT/kex_fuzz_seed_corpus.zip .)
(set -e ; cd ${CASES}/agent ; zip -r $OUT/agent_fuzz_seed_corpus.zip .)

# HPN-SSH SFTP-extension seed corpora: generated in-place by checked-in
# C programs (matches the mkcorpus_sntrup761 pattern).  Build the
# generators with the unsanitized host CC so they're plain executables,
# run them, then zip the resulting directories.  -larchive is needed
# for the bundle generator.
$CC -O2 -g -o mkcorpus_sftp_bundle_extract \
	regress/misc/fuzz-harness/mkcorpus_sftp_bundle_extract.c -larchive
$CC -O2 -g -o mkcorpus_sftp_fs_info \
	regress/misc/fuzz-harness/mkcorpus_sftp_fs_info.c
./mkcorpus_sftp_bundle_extract
./mkcorpus_sftp_fs_info
(set -e ; cd sftp_bundle_extract_corpus ; \
    zip -r $OUT/sftp_bundle_extract_fuzz_seed_corpus.zip .)
(set -e ; cd sftp_fs_info_corpus ; \
    zip -r $OUT/sftp_fs_info_fuzz_seed_corpus.zip .)
