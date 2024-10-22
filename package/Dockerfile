#
# Builder
#
FROM registry.suse.com/bci/golang:1.22.7 AS builder
ARG VULNDB_SERVER=https://d29ey0gy8sfz57.cloudfront.net
ARG VERSION=LATEST # Also used as vulndb ver
ARG SIGSTORE_VERSION=main

RUN zypper in -y wget

# Build controller
COPY . /src
WORKDIR /src
RUN git clone --depth=1 https://github.com/neuvector/sigstore-interface --branch "${SIGSTORE_VERSION}" --single-branch sigstore-interface && make -C sigstore-interface/
RUN mkdir -p data/ && wget $VULNDB_SERVER/${VERSION:1}/cvedb.regular -O data/cvedb.regular
RUN make slsa_all

#
# Base images
#
FROM registry.suse.com/bci/bci-micro:15.6 AS micro
FROM registry.suse.com/bci/bci-base:15.6 AS base

COPY --from=micro / /chroot/
RUN zypper --installroot /chroot -n --gpg-auto-import-keys in --no-recommends \
    ca-certificates procps grep && \
    zypper --installroot /chroot clean -a && \
    rm -rf /chroot/var/log/

RUN cd /chroot/usr/bin/ && rm -rf basename chcon chgrp chmod chown chroot cksum dd df dircolors dirname du install install-info join locale localedef mkdir mkfifo mknod mktemp paste pathchk readlink realpath sync smidiff smidump smilink smiquery smistrip smixlate tee tiemout tload top truncate unlink watch

RUN mkdir -p /chroot/etc/neuvector/certs/internal/ && mkdir -p /chroot/share && touch /chroot/share/.nvcontainer

#
# Artifact
#
FROM micro
WORKDIR /
COPY --from=base /chroot/ /
COPY --from=builder /src/stage /

ARG COMMIT
ARG VERSION

LABEL name="scanner" \
      vendor="SUSE Security" \
      version=${VERSION} \
      release=${VERSION} \
      neuvector.image="neuvector/scanner" \
      neuvector.role="scanner" \
      neuvector.rev="${COMMIT}" \
      neuvector.vuln_db="${VULNDBVER}" \
      "io.artifacthub.package.logo-url"=https://avatars2.githubusercontent.com/u/19367275 \
      "io.artifacthub.package.readme-url"="https://raw.githubusercontent.com/neuvector/scanner/${VERSION}/README.md" \
      "org.opencontainers.image.description"="SUSE Security Scanner" \
      "org.opencontainers.image.title"="SUSE Security Scanner" \
      "org.opencontainers.image.source"="https://github.com/neuvector/scanner/" \
      "org.opencontainers.image.version"="${VERSION}" \
      "org.opensuse.reference"="neuvector/scanner:${VERSION}"

ENTRYPOINT ["/usr/local/bin/monitor"]
