# The build image an OSS-Fuzz or ClusterFuzzLite run uses for this
# project. It carries the jazzer.js toolchain and the
# `compile_javascript_fuzzer` helper that build.sh calls.
#
# The tag is deliberately absent, which is the OSS-Fuzz convention: the
# infrastructure rebuilds these base images continuously and resolves the
# name at build time. Hadolint does not read this file; the CI job names
# the shipped Dockerfile at the repository root.
FROM gcr.io/oss-fuzz-base/base-builder-javascript

# The whole tree, because the harnesses read lib/store/ and
# lib/vendor/blamejs/ directly rather than through a build artifact.
#
# Both sources reach the context through Dockerfile.dockerignore beside this
# file. The context root's own .dockerignore excludes fuzz/ and this
# directory, since the shipped image reads neither, and BuildKit reads the
# adjacent file instead of it. Build this with BuildKit, which is the
# default from Docker 23 on: the legacy builder does not read the adjacent
# file, applies the context root's exclusions, and then cannot locate this
# Dockerfile at all, because that file excludes the directory it sits in.
COPY . $SRC/blamepost
COPY .clusterfuzzlite/build.sh $SRC/

WORKDIR $SRC/blamepost
