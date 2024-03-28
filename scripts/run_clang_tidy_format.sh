#!/usr/bin/env bash
set -eo pipefail
if [ ! -f network_stack.rego ] ; then
	echo Please run this script from the root of the network-stack repository.
	exit 1
fi
CLANG_TIDY=/cheriot-tools/bin/clang-tidy
CLANG_FORMAT=/cheriot-tools/bin/clang-format

if [ -n "$1" ] ; then
	CLANG_TIDY=$1/clang-tidy
	CLANG_FORMAT=$1/clang-format
fi
if [ ! -x ${CLANG_TIDY} ] ; then
	echo Usage: $0 path/to/cheriot/tools/bin
	echo clang-tidy not found at ${CLANG_TIDY}
	exit 1
fi
if [ ! -x ${CLANG_FORMAT} ] ; then
	echo Usage: $0 path/to/cheriot/tools/bin
	echo clang-tidy not found at ${CLANG_FORMAT}
	exit 1
fi

if which nproc ; then
	PARALLEL_JOBS=$(nproc)
else
	PARALLEL_JOBS=$(sysctl -n kern.smp.cpus)
fi
DIRECTORIES="lib include"
HEADERS=$(find ${DIRECTORIES} -name '*.h' -or -name '*.hh' | grep -v FreeRTOSIPConfig.h | grep -v pack_struct_end.h)
# The only .c files are wrappers around C sources from other projects, so omit
# them here.
SOURCES=$(find ${DIRECTORIES} -name '*.cc')

echo Headers: ${HEADERS}
echo Sources: ${SOURCES}
rm -f tidy-*.fail

# Silence a static analyser false positive where it fails to see the
# initialisation of isOwned (on one of two identical code paths - the other one
# is fine).
EXCLUSIONS='[{"name":"locks.hh","lines":[[258,1],[263,1]]}]'

# sh syntax is -c "string" [name [args ...]], so "tidy" here is the name and not included in "$@"
echo ${HEADERS} ${SOURCES} | xargs -P${PARALLEL_JOBS} -n5 sh -c "${CLANG_TIDY} -export-fixes=\$(mktemp -p. tidy.fail-XXXX) -line-filter='${EXCLUSIONS}' \$@" tidy
if [ $(find . -maxdepth 1 -name 'tidy.fail-*' -size +0 | wc -l) -gt 0 ] ; then
	# clang-tidy put non-empty output in one of the tidy-*.fail files
	cat tidy.fail-*
	rm tidy-fail-*
	exit 1
fi

${CLANG_FORMAT} -i ${HEADERS} ${SOURCES}
if git diff --exit-code ${HEADERS} ${SOURCES} ; then
	exit 0
fi
echo clang-format applied changes
exit 1
