FROM ubuntu:24.04 AS base_apt

# RUN echo 'Acquire::http::Proxy "http://cache.lan:3142";' > /etc/apt/apt.conf.d/00cacher
RUN userdel -r ubuntu
RUN apt update \
    && apt install wget git cmake build-essential python3 python3-venv python3-pip autoconf automake libtool gosu -y

ARG DOCKER_USER=build
RUN useradd -m "$DOCKER_USER"
USER $DOCKER_USER

FROM base_apt AS host_tools

USER root
RUN wget -O /tmp/host-tools.tar.gz https://sophon-file.sophon.cn/sophon-prod-s3/drive/23/03/07/16/host-tools.tar.gz \
    && tar -C /usr/local -zxvf /tmp/host-tools.tar.gz  \
    && rm -f /tmp/host-tools.tar.gz \
    && export PATH=$PATH:/usr/local/host-tools/gcc/riscv64-linux-musl-x86_64/bin \
    && echo "Installed host-tools gcc" && riscv64-unknown-linux-musl-gcc -v

FROM base_apt AS sdk

RUN cd ~ \
    && git clone https://github.com/Sipeed/MaixCDK \
    && cd MaixCDK \
    && python3 -m venv . \
    && . ./bin/activate \
    && pip install -U -r requirements.txt 

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
