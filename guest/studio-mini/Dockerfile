ARG ALPINE_IMAGE=alpine@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b
FROM ${ALPINE_IMAGE} AS rootfs
ARG TARGETARCH

COPY packages.lock /tmp/squirrelops-packages.lock
COPY packages.world /tmp/squirrelops-packages.world
COPY install-packages.sh /tmp/install-packages.sh

RUN --network=none --mount=type=bind,from=package-inputs,target=/package-inputs \
    sh /tmp/install-packages.sh \
    && test -x /usr/sbin/sshd \
    && test -x /usr/sbin/smbd \
    && test -x /usr/bin/socat \
    && socat -V 2>&1 | grep -q WITH_VSOCK \
    && find /usr/lib/samba -type f -name fruit.so -print -quit | grep -q fruit.so \
    && rm -f /tmp/squirrelops-packages.lock /tmp/install-packages.sh

COPY rootfs/ /
# BuildKit injects /etc/{hosts,hostname,resolv.conf} into RUN containers.
# Keep the reviewed guest files elsewhere until the rootfs is staged.
COPY network/ /tmp/squirrelops-network/

RUN --network=none test ! -e /package-inputs \
    && chmod 0755 /sbin/init /usr/local/bin/macos-shim \
    && for command in sw_vers system_profiler scutil launchctl dscl defaults security xcodebuild brew uname; do \
        ln -sf macos-shim "/usr/local/bin/$command"; \
    done \
    && mkdir -p /bundle /dev /proc /run /sys \
    && if [ "$TARGETARCH" = "arm64" ]; then \
        gzip_offset="$(grep -aob "$(printf '\037\213\010')" /boot/vmlinuz-virt | head -1 | cut -d: -f1)"; \
        test -n "$gzip_offset"; \
        dd if=/boot/vmlinuz-virt bs=1 skip="$gzip_offset" 2>/dev/null \
            | gzip -dc > /bundle/vmlinuz 2>/dev/null || test -s /bundle/vmlinuz; \
        file /bundle/vmlinuz | grep -q 'Linux kernel ARM64 boot executable Image'; \
      else \
        cp /boot/vmlinuz-virt /bundle/vmlinuz; \
        file /bundle/vmlinuz | grep -q 'Linux kernel x86 boot executable'; \
      fi \
    && mkdir /guest-root \
    && cd / \
    && find . -xdev \
        -path './bundle' -prune -o \
        -path './guest-root' -prune -o \
        -path './tmp/squirrelops-network' -prune -o \
        -path './dev/*' -prune -o \
        -path './proc/*' -prune -o \
        -path './sys/*' -prune -o \
        -print0 \
        | cpio --null -pdm /guest-root \
    && cp /tmp/squirrelops-network/hosts /guest-root/etc/hosts \
    && cp /tmp/squirrelops-network/hostname /guest-root/etc/hostname \
    && cp /tmp/squirrelops-network/resolv.conf /guest-root/etc/resolv.conf \
    && chmod 0644 /guest-root/etc/hosts /guest-root/etc/hostname /guest-root/etc/resolv.conf \
    && cd /guest-root \
    && find . -xdev -print0 \
        | cpio --null -o --format=newc \
        | gzip -9 > /bundle/studio-mini.initramfs \
    && test -s /bundle/vmlinuz \
    && test -s /bundle/studio-mini.initramfs

FROM scratch
COPY --from=rootfs /bundle/ /
