# Maintainer: Your Name <you@example.com>
pkgname=lksu
pkgver=1.0.0
pkgrel=1
pkgdesc="Liska Superuser privilege escalation tool"
arch=('x86_64')
url="https://github.com/source-liskalinux/lksu"
license=('MIT')
depends=('pam' 'glibc')
makedepends=('rustup' 'clang')
backup=(
    'etc/lksu.d/config.lua'
    'etc/lksu.d/user-lists.lua'
    'etc/pam.d/lksu'
)
options=('!lto')

prepare() {
    export RUSTUP_TOOLCHAIN=stable
    cargo fetch
}

build() {
    cargo build --release
}

check() {
    cargo test --release
}

package() {
    # Binary, installed setuid-root: lksu needs to already be running
    # as root (via this bit) before it can setuid(0)/setgid(0) itself
    # to hand off to the target command, see src/exec.rs.
    install -Dm755 target/release/lksu "$pkgdir/usr/bin/lksu"
    chmod 4755 "$pkgdir/usr/bin/lksu"
    chown root:root "$pkgdir/usr/bin/lksu"
    install -Dm644 etc/pam.d/lksu "$pkgdir/etc/pam.d/lksu"
    # Config, shipped with safe working defaults so the package is
    # usable immediately after install (root is permitted, everyone
    # else is denied until an admin edits user-lists.lua).
    install -Dm640 -o root -g root etc/lksu.d/config.lua "$pkgdir/etc/lksu.d/config.lua"
    install -Dm640 -o root -g root etc/lksu.d/user-lists.lua "$pkgdir/etc/lksu.d/user-lists.lua"
    install -Dm640 -o root -g root log/lksu.log "$pkgdir/var/log/lksu.log"
}
