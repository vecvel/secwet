#!/usr/bin/env bash
# One-time server setup, run as root by the "Relay: bootstrap server" workflow
# (or by hand: ssh root@server 'bash -s' < bootstrap.sh). Safe to run again.
#
#   - creates the `deploy` user with the given SSH public key
#   - installs Docker Engine + Compose from Docker's apt repository
#   - firewall: only SSH, 80 and 443 open
#   - SSH: keys only, no root login, no passwords
#   - fail2ban for SSH, automatic security updates
#
# Needs: DEPLOY_SSH_PUBLIC_KEY (the public half of the workflow's deploy key).
# Supported: Ubuntu 22.04 / 24.04, Debian 12.
set -euo pipefail

: "${DEPLOY_SSH_PUBLIC_KEY:?DEPLOY_SSH_PUBLIC_KEY is required}"
DEPLOY_USER="${DEPLOY_USER:-deploy}"
APP_DIR="${APP_DIR:-/opt/secwet}"
SSH_PORT="${SSH_PORT:-22}"

[ "$(id -u)" -eq 0 ] || { echo "bootstrap: run as root" >&2; exit 1; }
export DEBIAN_FRONTEND=noninteractive

echo "bootstrap: packages"
apt-get update -q
apt-get install -yq ca-certificates curl gnupg ufw fail2ban unattended-upgrades

echo "bootstrap: Docker"
if ! command -v docker >/dev/null; then
	. /etc/os-release
	install -m 0755 -d /etc/apt/keyrings
	curl -fsSL "https://download.docker.com/linux/${ID}/gpg" -o /etc/apt/keyrings/docker.asc
	chmod a+r /etc/apt/keyrings/docker.asc
	echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/${ID} ${VERSION_CODENAME} stable" \
		>/etc/apt/sources.list.d/docker.list
	apt-get update -q
	apt-get install -yq docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
fi
# Rotate container logs and keep the daemon from opening extra ports.
cat >/etc/docker/daemon.json <<'JSON'
{
  "log-driver": "json-file",
  "log-opts": { "max-size": "10m", "max-file": "5" },
  "live-restore": true,
  "no-new-privileges": true
}
JSON
systemctl enable --now docker
systemctl restart docker

echo "bootstrap: deploy user"
id "$DEPLOY_USER" >/dev/null 2>&1 || useradd --create-home --shell /bin/bash "$DEPLOY_USER"
usermod -aG docker "$DEPLOY_USER"
install -d -m 0700 -o "$DEPLOY_USER" -g "$DEPLOY_USER" "/home/$DEPLOY_USER/.ssh"
keys="/home/$DEPLOY_USER/.ssh/authorized_keys"
touch "$keys"
grep -qxF "$DEPLOY_SSH_PUBLIC_KEY" "$keys" || echo "$DEPLOY_SSH_PUBLIC_KEY" >>"$keys"
chown "$DEPLOY_USER:$DEPLOY_USER" "$keys"
chmod 0600 "$keys"
install -d -m 0750 -o "$DEPLOY_USER" -g "$DEPLOY_USER" "$APP_DIR"

echo "bootstrap: firewall"
ufw default deny incoming
ufw default allow outgoing
ufw allow "${SSH_PORT}/tcp"
ufw allow 80/tcp
ufw allow 443/tcp
ufw allow 443/udp
ufw --force enable

echo "bootstrap: SSH (keys only)"
# Only lock passwords out once the deploy key is in place.
[ -s "$keys" ] || { echo "bootstrap: no deploy key installed, leaving SSH unchanged" >&2; exit 1; }
cat >/etc/ssh/sshd_config.d/10-secwet.conf <<CONF
Port ${SSH_PORT}
PermitRootLogin no
PasswordAuthentication no
KbdInteractiveAuthentication no
PubkeyAuthentication yes
AllowUsers ${DEPLOY_USER}
MaxAuthTries 3
X11Forwarding no
CONF
sshd -t
systemctl reload ssh 2>/dev/null || systemctl reload sshd

echo "bootstrap: fail2ban and automatic security updates"
cat >/etc/fail2ban/jail.d/secwet.conf <<CONF
[sshd]
enabled = true
port = ${SSH_PORT}
maxretry = 5
bantime = 1h
CONF
systemctl enable --now fail2ban
systemctl restart fail2ban
dpkg-reconfigure -f noninteractive unattended-upgrades

echo "bootstrap: done. Log in from now on as ${DEPLOY_USER} with the deploy key; root and passwords are off."
