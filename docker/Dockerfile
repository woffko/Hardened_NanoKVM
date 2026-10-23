# Pinned inputs: the base image by digest, the toolchain archive and the
# Python packages by SHA-256, MaixCDK by commit. The apt packages come from the
# Ubuntu archive at build time and are not pinned.
FROM ubuntu:24.04@sha256:68ee22004a9109b44973313b02ff7b1de250f1de0f5ecb628d73f579aaff33ac AS base_apt

# RUN echo 'Acquire::http::Proxy "http://cache.lan:3142";' > /etc/apt/apt.conf.d/00cacher
RUN userdel -r ubuntu
RUN apt update \
    && apt install wget git cmake build-essential python3 python3-venv python3-pip autoconf automake libtool gosu xz-utils -y

ARG DOCKER_USER=build
RUN useradd -m "$DOCKER_USER"
USER $DOCKER_USER

FROM base_apt AS host_tools

USER root
# The toolchain MaixCDK pins in dl/pkgs_info.json and the native builds use.
ARG HOST_TOOLS_URL=https://github.com/sipeed/MaixCDK/releases/download/v0.0.0/host-tools-2025.7.28.tar.xz
ARG HOST_TOOLS_SHA256=968b179a7faebfe8914e5163b2d85038b71824780fccde0b4b3ee9f67472d007
RUN wget -O /tmp/host-tools.tar.xz "$HOST_TOOLS_URL" \
    && echo "$HOST_TOOLS_SHA256  /tmp/host-tools.tar.xz" | sha256sum -c - \
    && tar -C /usr/local -xJf /tmp/host-tools.tar.xz \
    && rm -f /tmp/host-tools.tar.xz \
    && export PATH=$PATH:/usr/local/host-tools/gcc/riscv64-linux-musl-x86_64/bin \
    && echo "Installed host-tools gcc" && riscv64-unknown-linux-musl-gcc -v

FROM base_apt AS sdk

ARG MAIXCDK_COMMIT=5b0aa5b1a8c91d213433189cfab8c999775fa13a
COPY --chown=$DOCKER_USER docker/maixcdk-requirements.lock /home/$DOCKER_USER/maixcdk-requirements.lock
RUN cd ~ \
    && git clone https://github.com/Sipeed/MaixCDK \
    && cd MaixCDK \
    && git checkout --detach "$MAIXCDK_COMMIT" \
    && test "$(git rev-parse HEAD)" = "$MAIXCDK_COMMIT" \
    && python3 -m venv . \
    && . ./bin/activate \
    && pip install --require-hashes --no-deps -r ~/maixcdk-requirements.lock

# Keep the image inputs explicit as well as filtering the transmitted context.
# Never COPY the repository root: it also contains local build and lab state.
COPY --chown=$DOCKER_USER support/sg2002/build /home/$DOCKER_USER/NanoKVM/support/sg2002/build
COPY --chown=$DOCKER_USER support/sg2002/additional/kvm/ /home/$DOCKER_USER/NanoKVM/support/sg2002/additional/kvm/
COPY --chown=$DOCKER_USER support/sg2002/additional/kvm_mmf/ /home/$DOCKER_USER/NanoKVM/support/sg2002/additional/kvm_mmf/
COPY --chown=$DOCKER_USER support/sg2002/additional/vision/ /home/$DOCKER_USER/NanoKVM/support/sg2002/additional/vision/
COPY --chown=$DOCKER_USER support/sg2002/additional/peripheral/port/maixcam/maix_i2c.cpp /home/$DOCKER_USER/NanoKVM/support/sg2002/additional/peripheral/port/maixcam/maix_i2c.cpp
COPY --chown=$DOCKER_USER support/sg2002/additional/sophgo-middleware/v2/sample/common/sample_common_sensor.c /home/$DOCKER_USER/NanoKVM/support/sg2002/additional/sophgo-middleware/v2/sample/common/sample_common_sensor.c
COPY --chown=$DOCKER_USER support/sg2002/kvm_system/main/ /home/$DOCKER_USER/NanoKVM/support/sg2002/kvm_system/main/
COPY --chown=$DOCKER_USER support/sg2002/kvm_vision_test/main/ /home/$DOCKER_USER/NanoKVM/support/sg2002/kvm_vision_test/main/

RUN cd ~/MaixCDK \
    && . ./bin/activate \
    && cd ~/NanoKVM/support/sg2002 \
    && ./build kvm_system

FROM base_apt

# Install host tools
COPY --from=host_tools /usr/local/host-tools /usr/local/host-tools
ENV PATH="$PATH:/usr/local/host-tools/gcc/riscv64-linux-musl-x86_64/bin"

# Install SDK
COPY --from=sdk /home/$DOCKER_USER/MaixCDK /home/$DOCKER_USER/MaixCDK
COPY --chmod=+x docker/entrypoint /entrypoint

RUN echo "Verify build tools" \
    && echo "Installed host-tools gcc" && riscv64-unknown-linux-musl-gcc -v

USER root
RUN chmod 0755 /entrypoint \
 && sed "s/\$DOCKER_USER/$DOCKER_USER/g" -i /entrypoint

ENTRYPOINT ["/entrypoint"]
