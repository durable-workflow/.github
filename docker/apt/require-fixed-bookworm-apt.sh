#!/bin/sh
# Shared read-only image preflight. No Python, APT, download, or repair path.
set -eu
LC_ALL=C
export LC_ALL
RELEASE=/etc/os-release
QUERY=/usr/bin/dpkg-query
DPKG=/usr/bin/dpkg
readonly RELEASE QUERY DPKG

refuse() {
    printf '%s\n' 'fixed_bookworm_apt=false: effective Debian 12 native APT pair did not prove the 2.6.2 floor' >&2
    exit 1
}

[ "$#" -eq 0 ] || refuse
os=
release=
while IFS= read -r line || [ -n "$line" ]; do
    case "$line" in
        ID=*)
            [ -z "$os" ] || refuse
            case "$line" in ID=debian|ID=\"debian\") os=debian ;; *) refuse ;; esac
            ;;
        VERSION_ID=*)
            [ -z "$release" ] || refuse
            case "$line" in VERSION_ID=12|VERSION_ID=\"12\") release=12 ;; *) refuse ;; esac
            ;;
        *) : ;;
    esac
done < "$RELEASE"
[ "$os:$release" = debian:12 ] || refuse

rows=$(/usr/bin/env -i PATH=/usr/bin:/bin LC_ALL=C "$QUERY" --show \
    '--showformat=${Package}|${Status}|${Version}|${Architecture}\n' apt libapt-pkg6.0) || refuse
apt=
library=
architecture=
while IFS= read -r line; do
    case "$line" in *'|'*'|'*'|'*'|'*) refuse ;; *'|'*'|'*'|'*) ;; *) refuse ;; esac
    IFS='|' read -r package status version arch <<EOF
$line
EOF
    [ "$status" = 'install ok installed' ] || refuse
    case "$version" in ''|[!0-9]*|*[!0-9A-Za-z.+:~\-]*) refuse ;; *) : ;; esac
    [ "${#version}" -le 100 ] || refuse
    case "$arch" in amd64|arm64) ;; *) refuse ;; esac
    [ -z "$architecture" ] || [ "$architecture" = "$arch" ] || refuse
    architecture=$arch
    case "$package" in
        apt) [ -z "$apt" ] || refuse; apt=$version ;;
        libapt-pkg6.0) [ -z "$library" ] || refuse; library=$version ;;
        *) refuse ;;
    esac
done <<EOF
$rows
EOF
[ -n "$apt" ] && [ -n "$library" ] || refuse
native=$(/usr/bin/env -i PATH=/usr/bin:/bin LC_ALL=C "$DPKG" --print-architecture) || refuse
[ "$native" = "$architecture" ] || refuse
for version in "$apt" "$library"; do
    /usr/bin/env -i PATH=/usr/bin:/bin LC_ALL=C "$DPKG" --compare-versions "$version" ge 2.6.2 || refuse
done
printf 'fixed_bookworm_apt=true os=debian release=12 architecture=%s apt=%s libapt-pkg6.0=%s minimum=2.6.2\n' \
    "$architecture" "$apt" "$library"
