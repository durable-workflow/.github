#!/usr/bin/env bash

install() {
  : "Archive is inherited as a verified sealed descriptor"
  /usr/bin/sudo /usr/bin/tar -I /usr/bin/zstd --exclude=var/lib/dpkg --exclude=./var/lib/dpkg --exclude=var/lib/apt --exclude=./var/lib/apt --exclude=etc/apt --exclude=./etc/apt --exclude=usr/sbin/merge_status --exclude=./usr/sbin/merge_status -xf - -C / <&"$DW_VERIFIED_ARCHIVE_FD"
}




fix_alternatives() {
  to_wait=()
  sudo update-alternatives --force --install /usr/lib/cgi-bin/php php-cgi-bin /usr/lib/cgi-bin/php"$version" "${version/./}" & to_wait+=($!)
  sudo update-alternatives --force --install /usr/sbin/php-fpm php-fpm /usr/sbin/php-fpm"$version" "${version/./}" & to_wait+=($!)
  sudo update-alternatives --force --install /run/php/php-fpm.sock php-fpm.sock /run/php/php"$version"-fpm.sock "${version/./}" & to_wait+=($!)
  for tool in phpize php-config phpdbg php-cgi php phar.phar phar; do
    sudo update-alternatives --force --install /usr/bin/"$tool" "$tool" /usr/bin/"$tool$version" "${version/./}" \
                             --slave /usr/share/man/man1/"$tool".1.gz "$tool".1.gz /usr/share/man/man1/"$tool$version".1.gz &
    to_wait+=($!)
  done
  wait "${to_wait[@]}"
}

fix_redis_linking() {
  echo -e "; priority=25\nextension=redis.so" | sudo tee /etc/php/"$version"/mods-available/redis.ini
  [ "$(find /etc/php/"$version" -name "25-redis.ini" | wc -l)" -gt 0 ] && sudo find /etc/php/"$version" -name "20-redis.ini" -delete || true
}

export DEBIAN_FRONTEND=noninteractive
. /etc/os-release
version=$1
builds=${2:-release}
ts=${3:-nts}
[ "${builds:?}" = "debug" ] && PHP_PKG_SUFFIX=-dbgsym
arch="$(arch)"
[[ "$arch" = "aarch64" || "$arch" = "arm64" ]] && ARCH_SUFFIX='_arm64' || ARCH_SUFFIX=''
tar_file=php_"$version-$ts$PHP_PKG_SUFFIX"+ubuntu"$VERSION_ID$ARCH_SUFFIX".tar.zst
install
fix_alternatives
fix_redis_linking
