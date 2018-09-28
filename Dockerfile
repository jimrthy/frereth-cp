# TODO: Look into inheriting from the plain clojure
# image instead.
# c.f. https://github.com/Quantisav/docker-clojure
#FROM adzerk/boot-clj:latest
FROM clojure:boot-2.7.2-alpine

ENV CURVE_CP_DIR=/opt/frereth/curvecp

RUN mkdir -p ${CURVE_CP_DIR}
WORKDIR ${CURVE_CP_DIR}

# Make the directories that build.boot requires
RUN mkdir -p src/clojure && \
    mkdir -p src/java && \
    mkdir dev && \
    mkdir dev-resources && \
    mkdir test

COPY .boot-jvm-options boot.properties profile.boot ./

# Get the fundamental dependencies cached
RUN boot help

# It's tempting to just do one COPY command. But build.boot
# is going to change more often than the others. So might
# as well try to minimize the overlap, since downloading its
# dependencies takes a while.
COPY build.boot .

# Pull in extras that go with day-to-day dev work.
# These still leave out several dependencies, like the various nrepl
# tools.
# Q: How do I get them downloaded/cached?
RUN boot dev testing javac check-conflicts

COPY . .

RUN chmod u+x boot.sh

RUN ./boot.sh cider repl -s

# Want to run local boot.sh to pick up local overrides.
# So override base image entrypoint to nothing.
ENTRYPOINT []

# This is a pretty safe bet for dev work
CMD ./boot.sh cider-repl

# Q: Worth running apt-update && apt-upgrade in
# this vicinity?