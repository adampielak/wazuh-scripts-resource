<!-- Source: https://wazuh.com/blog/detecting-kubernetes-attacks-with-wazuh-2/ | Article: Detecting Kubernetes attacks with Wazuh -->
#!/bin/bash
set -euo pipefail

# Disable SELinux
setenforce 0 || true
sed -i --follow-symlinks 's/^SELINUX=enforcing/SELINUX=disabled/g' /etc/selinux/config || true
sed -i --follow-symlinks's/^SELINUX=permissive/SELINUX=disabled/g' /etc/selinux/config || true

# Disable swap (required by kubelet)
swapoff -a || true
sed -ri '/\sswap\s/s/^#?/#/' /etc/fstab || true

# Base prerequisites
dnf -y install dnf-plugins-core
dnf -y install \
  conntrack socat iptables ebtables ethtool \
  curl wget tar \
  containernetworking-plugins

# Install Docker Engine (Docker CE repo)
dnf config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo
dnf -y install docker-ce docker-ce-cli containerd.io docker-compose-plugin --allowerasing
systemctl enable --now docker

# Install kubectl
KUBECTL_VER="v1.26.0"
curl -fsSLo /usr/bin/kubectl "https://dl.k8s.io/release/${KUBECTL_VER}/bin/linux/amd64/kubectl"
chmod +x /usr/bin/kubectl

# Install Minikube
MINIKUBE_VER="v1.28.0"
curl -fsSLo /usr/bin/minikube \
  "https://github.com/kubernetes/minikube/releases/download/${MINIKUBE_VER}/minikube-linux-amd64"
chmod +x /usr/bin/minikube

# Install crictl
CRICTL_VER="v1.25.0"
curl -fsSLo /tmp/crictl.tgz \
  "https://github.com/kubernetes-sigs/cri-tools/releases/download/${CRICTL_VER}/crictl-${CRICTL_VER}-linux-amd64.tar.gz"
tar -xzf /tmp/crictl.tgz -C /usr/bin/
rm -f /tmp/crictl.tgz

# Install cri-dockerd (tarball; extract to /tmp to avoid directory collision)
CRID_VER="v0.3.24"
curl -fsSLo /tmp/cri-dockerd.tgz \
  "https://github.com/Mirantis/cri-dockerd/releases/download/${CRID_VER}/cri-dockerd-0.3.24.amd64.tgz"
tar -xzf /tmp/cri-dockerd.tgz -C /tmp
mv -f /tmp/cri-dockerd/cri-dockerd /usr/local/bin/cri-dockerd
chmod +x /usr/local/bin/cri-dockerd
ln -sf /usr/local/bin/cri-dockerd /usr/bin/cri-dockerd
rm -rf /tmp/cri-dockerd /tmp/cri-dockerd.tgz

# systemd units for cri-dockerd
cat >/etc/systemd/system/cri-docker.socket <<'EOF'
[Unit]
Description=CRI Docker Socket for the API

[Socket]
ListenStream=/var/run/cri-dockerd.sock
SocketMode=0660
SocketUser=root
SocketGroup=docker

[Install]
WantedBy=sockets.target
EOF

cat >/etc/systemd/system/cri-docker.service <<'EOF'
[Unit]
Description=CRI interface for Docker Application Container Engine
Documentation=https://github.com/Mirantis/cri-dockerd
After=network-online.target docker.service
Wants=network-online.target
Requires=docker.service

[Service]
Type=notify
ExecStart=/usr/bin/cri-dockerd --container-runtime-endpoint fd://
Restart=always
RestartSec=2

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now cri-docker.socket cri-docker.service

# Ensure directories Minikube expects for CNI
mkdir -p /etc/cni/net.d
mkdir -p /opt/cni/bin

if [ -d /usr/libexec/cni ]; then
  cp -a /usr/libexec/cni/* /opt/cni/bin/ || true
elif [ -d /usr/lib/cni ]; then
  cp -a /usr/lib/cni/* /opt/cni/bin/ || true
fi

# Kernel networking settings
modprobe br_netfilter || true
cat >/etc/sysctl.d/99-k8s.conf <<'EOF'
net.bridge.bridge-nf-call-iptables=1
net.bridge.bridge-nf-call-ip6tables=1
net.ipv4.ip_forward=1
EOF
sysctl --system >/dev/null

# Start clean to avoid loading an existing profile
minikube delete --all --purge || true

# Start Minikube
minikube start --driver=none --cni=bridge