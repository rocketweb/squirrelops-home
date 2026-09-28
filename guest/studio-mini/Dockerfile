ARG ALPINE_IMAGE=alpine:3.24.1
FROM ${ALPINE_IMAGE} AS rootfs
ARG TARGETARCH

COPY packages.lock /tmp/squirrelops-packages.lock

RUN apk add --no-cache \
        acl \
        attr \
        cpio \
        file \
        git \
        grep \
        iproute2 \
        jq \
        linux-virt \
        openssh-server \
        openssh-sftp-server \
        samba-common-tools \
        samba-server \
        socat \
        tar \
        zsh \
    && test -x /usr/sbin/sshd \
    && test -x /usr/sbin/smbd \
    && test -x /usr/bin/socat \
    && socat -V 2>&1 | grep -q WITH_VSOCK \
    && find /usr/lib/samba -type f -name fruit.so -print -quit | grep -q fruit.so \
    && apk info -vv | sort > /etc/squirrelops-guest-packages.txt \
    && diff -u /tmp/squirrelops-packages.lock /etc/squirrelops-guest-packages.txt \
    && rm -f /tmp/squirrelops-packages.lock

COPY rootfs/ /

RUN chmod 0755 /sbin/init /usr/local/bin/macos-shim \
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
    && cd / \
    && find . -xdev \
        -path './bundle' -prune -o \
        -path './dev/*' -prune -o \
        -path './proc/*' -prune -o \
        -path './sys/*' -prune -o \
        -print0 \
        | cpio --null -o --format=newc \
        | gzip -9 > /bundle/studio-mini.initramfs \
    && test -s /bundle/vmlinuz \
    && test -s /bundle/studio-mini.initramfs

FROM scratch
COPY --from=rootfs /bundle/ /
