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
    'etc/pam.d/lksu'
    'var/db/lksu/lksuers.db'
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
    install -Dm 755 target/release/lksu "$pkgdir/usr/bin/lksu"
    chmod 4755 "$pkgdir/usr/bin/lksu"
    chown root:root "$pkgdir/usr/bin/lksu"
    install -Dm 644 etc/pam.d/lksu "$pkgdir/etc/pam.d/lksu"
    # Config, shipped with safe working defaults so the package is
    # usable immediately after install (root is permitted, everyone
    # else is denied until an admin adds them with lksu --add-user).
    install -Dm 700 etc/lksu.d/config.lua "$pkgdir/etc/lksu.d/config.lua"
    chmod 700 "$pkgdir/etc/lksu.d/config.lua"
    chown root:root "$pkgdir/etc/lksu.d/config.lua"
    chmod 700 "$pkgdir/etc/lksu.d"
    chown root:root "$pkgdir/etc/lksu.d"
    # Permitted-users list (sqlite), seeded with root => ALL so lksu is
    # usable out of the box. Gets rewritten in place by
    # --add-user / --edit-user / --remove-user, so pacman will likely flag
    # it as locally modified after first use, that's expected, same
    # as any other stateful database pacman happens to track.
    install -Dm 700 var/db/lksu/lksuers.db "$pkgdir/var/db/lksu/lksuers.db"
    chmod 700 "$pkgdir/var/db/lksu/lksuers.db"
    chown root:root "$pkgdir/var/db/lksu/lksuers.db"
    chmod 700 "$pkgdir/var/db/lksu"
    chown root:root "$pkgdir/var/db/lksu"
    # Per-user log directory (/var/log/lksu/<user>) created empty,
    # lksu populates files under it as commands are run.
    install -dm 700 "$pkgdir/var/log/lksu"
    chmod 700 "$pkgdir/var/log/lksu"
    chown root:root "$pkgdir/var/log/lksu"
    install -dm 700 "$pkgdir/run/lksu"
    chmod 700 "$pkgdir/run/lksu"
    chown root:root "$pkgdir/run/lksu"
}
