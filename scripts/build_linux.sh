#!/usr/bin/env bash
# Execute em Linux x86_64. CI usa Ubuntu 22.04 (glibc 2.35).
set -euo pipefail
version="${1:-2.1.0}"
[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo 'Versão inválida.' >&2; exit 1; }
[[ "$(uname -s)" == Linux && "$(uname -m)" == x86_64 ]] || { echo 'Compile em Linux x86_64.' >&2; exit 1; }
project_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$project_root"
asset_args=()
if [[ -d labguard/assets ]]; then
  asset_args=(--add-data 'labguard/assets:labguard/assets')
fi
python3 -m PyInstaller --noconfirm --clean --onedir --windowed --noupx --name LabGuard \
  --add-data 'gateway/ai_services.json:gateway' --add-data 'docs:docs' --add-data 'README.md:.' \
  --collect-data reportlab --collect-submodules labguard --collect-submodules winrm "${asset_args[@]}" main.py
cp packaging/LEIA-ME.html dist/LabGuard/LEIA-ME.html
cp -R docs dist/LabGuard/docs
cp README.md dist/LabGuard/README.md
install -m 0755 packaging/linux/iniciar.sh dist/LabGuard/iniciar.sh
mkdir -p dist/release
tar -C dist -czf dist/release/LabGuard-Linux-x86_64.tar.gz LabGuard

package_root="$project_root/build/deb-labguard"
rm -rf "$package_root"
install -d "$package_root/DEBIAN" "$package_root/opt/labguard" "$package_root/usr/bin" \
  "$package_root/usr/share/applications" "$package_root/usr/share/icons/hicolor/scalable/apps"
cp -R dist/LabGuard/. "$package_root/opt/labguard/"
install -m 0755 packaging/linux/labguard-launcher "$package_root/usr/bin/labguard"
install -m 0644 packaging/linux/labguard.desktop "$package_root/usr/share/applications/labguard.desktop"
install -m 0644 packaging/linux/labguard.svg "$package_root/usr/share/icons/hicolor/scalable/apps/labguard.svg"
installed_size="$(du -sk "$package_root/opt/labguard" | cut -f1)"
cat > "$package_root/DEBIAN/control" <<EOF
Package: labguard
Version: $version
Section: education
Priority: optional
Architecture: amd64
Maintainer: LabGuard <noreply@users.noreply.github.com>
Installed-Size: $installed_size
Depends: libc6 (>= 2.35), libx11-6, libxext6, libxrender1, libxft2, libfontconfig1, libfreetype6, libxcb1, openssh-client, iproute2
Homepage: https://perabru.github.io/LabGuard/
Description: Painel de administracao de laboratorios escolares
 Interface grafica de observacao local e controle direto de equipamentos compativeis.
EOF
chmod -R go-w "$package_root"
dpkg-deb --root-owner-group --build "$package_root" dist/release/LabGuard-Linux-amd64.deb

python3 -m PyInstaller --noconfirm --clean --onedir --console --noupx --name LabGuardServer \
  --add-data 'gateway/ai_services.json:gateway' --add-data 'server/assets:server/assets' --add-data 'docs:docs' \
  --collect-data reportlab --collect-submodules labguard --exclude-module labguard.gui --exclude-module labguard.simple_gui --exclude-module labguard.integration_gui \
  --exclude-module labguard.network_map_gui --exclude-module labguard.remote_gui --exclude-module labguard.banlist_gui \
  --exclude-module labguard.ui --exclude-module tkinter server_main.py
cp -R server dist/LabGuardServer/server
cp -R docs dist/LabGuardServer/docs
find dist/LabGuardServer/server -name '*.sh' -exec chmod 0755 {} +
tar -C dist -czf dist/release/LabGuard-Server-Linux-x86_64.tar.gz LabGuardServer
printf '%s\n' 'Pacotes Linux gerados em dist/release.'
