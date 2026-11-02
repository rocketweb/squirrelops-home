#!/bin/bash
# One approved SMB-only diagnostic of the installed build. No installation.
set -euo pipefail
export PATH=/usr/bin:/bin:/usr/sbin:/sbin
umask 077
if [ "$(/usr/bin/id -u)" -ne 0 ] || [ "$#" -ne 0 ] || [ ! -t 0 ]; then
    echo "Run with sudo and no arguments in Terminal on the Mini." >&2
    exit 1
fi
source_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
task_dir="$(/usr/bin/mktemp -d /private/var/root/squirrelops-mini-smb.XXXXXXXX)"
for name in candidate.pkg mini_acceptance.py mini_upgrade_acceptance.py mini_ownership_acceptance.py mini_launchd_acceptance.py mini_single_ip_acceptance.py mini_post_reboot_acceptance.py mini_relay_diagnostic_acceptance.py mini_installed_protocol_window.py mini_filter_retest.py mini_smb_diagnostic_window.py single-ip-config.yaml approved-scope.md; do
    if [ ! -f "$source_dir/$name" ] || [ -L "$source_dir/$name" ]; then
        echo "Missing or linked input: $name. No product change attempted." >&2
        exit 1
    fi
    /usr/bin/install -o root -g wheel -m 600 "$source_dir/$name" "$task_dir/$name"
done
verify_digest() {
    local name="$1" expected="$2" actual
    actual="$(/usr/bin/shasum -a 256 "$task_dir/$name" | /usr/bin/awk '{print $1}')"
    if [ "$actual" != "$expected" ]; then
        echo "Checksum mismatch: $name. No product change attempted." >&2
        exit 1
    fi
}
verify_digest candidate.pkg 3d18ebac2fae343fd9c710ad2a187ec3f4bf6e4fd9cfda3bc3654214db7c67ea
verify_digest mini_acceptance.py 46f441987cf092c0cf4cb38eb6b76bbef1452eca54d66b37ff1e98523a2dcb3f
verify_digest mini_upgrade_acceptance.py bb5e7b1c8155f7301f25139e6bd6091a3d5c116f6dc4efe39207937b08e3ae5a
verify_digest mini_ownership_acceptance.py 1edd5706b7dd5f0fc8285b50ce2d895a9952208218c19d1ddf66934715191287
verify_digest mini_launchd_acceptance.py d03b69614bfb1cfae3eb4e545ac54717b083361ced1cdc12ffab5cd45a6e91f0
verify_digest mini_single_ip_acceptance.py d2bd94df4abd88663cd07ed5df316ae667eb51c66f8fd2dacc6045225e7d4cde
verify_digest mini_post_reboot_acceptance.py 5aeabcf7cb3a99a852a35c9582c3042642de49c4968d107824328f0c00b33c21
verify_digest mini_relay_diagnostic_acceptance.py 4e80676aa412417106317f6b140716069c1f0138c6846280e84071dfca558b8e
verify_digest mini_installed_protocol_window.py aedd37a278710ee221bd9b137df51bd987ec716438ebc672e2672722eaac1ff9
verify_digest mini_filter_retest.py 7d2cbb6fa804960a8a2a3ea9696c634ee8382aec1da7fa03d0d1038e9e5b9e4d
verify_digest mini_smb_diagnostic_window.py 874b3db55ce6e096b2c78f60497027a746021dc4e0a2c156432b49b221ef2db3
verify_digest single-ip-config.yaml 1318489677a7143395487f4a07703cac31b77577daf276000c36ca39414c2aa5
verify_digest approved-scope.md c435a3458ff5bd47a38c35e4de445591e14f049ab1cccbbc84f968cd91538a17

echo "SMB diagnostic inputs verified. Preparing pinned private Python; no installation or rule changes."
/usr/sbin/pkgutil --expand-full "$task_dir/candidate.pkg" "$task_dir/expanded"
runtime="$task_dir/expanded/sensor.pkg/Payload/Library/SquirrelOps/sensor/python/bin/python3.12"
/usr/bin/codesign --verify --strict "$runtime"
exec /usr/bin/env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin LC_ALL=C \
    "$runtime" -I -B "$task_dir/mini_smb_diagnostic_window.py" --run "$task_dir"
