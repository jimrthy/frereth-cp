FROM clojure:boot-2.7.2-alpine

RUN apk add git

ENV CURVE_CP_DIR=/opt/frereth/curvecp

RUN mkdir -p ${CURVE_CP_DIR}
WORKDIR ${CURVE_CP_DIR}

# Make the directories that build.boot requires
RUN mkdir -p src/clojure && \
    mkdir -p src/java && \
    mkdir dev && \
    mkdir dev-resources && \
    mkdir test

# It seems like it would be good to do this now. And it would,
# if we were using another image as our base. As it stands, the
# image comes with the pieces this would include already
# downloaded.
# RUN boot help

COPY .boot-jvm-options boot.properties profile.boot build.boot ./

# Pull in extras that go with day-to-day dev work.
# These still leave out several dependencies, like the various nrepl
# tools.
# Q: How do I get them downloaded/cached?
RUN boot dev testing javac check-conflicts

COPY . .

RUN boot build install && \
    boot cider repl -s && \
    chmod u+x boot.sh

# Want to run local boot.sh to pick up local overrides.
# So override base image entrypoint to nothing.
ENTRYPOINT []

# This is a pretty safe bet for dev work
CMD ./boot.sh cider-repl

# Q: Worth running apt-update && apt-upgrade in
# this vicinity?