<!-- Source: https://wazuh.com/blog/auditing-kubernetes-with-wazuh/ | Article: Auditing Kubernetes with Wazuh -->
#!/bin/bash
set -e

# Disable SELinux
setenforce 0 || true
sed -i --follow-symlinks 's/^SELINUX=enforcing/SELINUX=disabled/g' /etc/sysconfig/selinux || true
sed -i --follow-symlinks 's/^SELINUX=permissive/SELINUX=disabled/g' /etc/sysconfig/selinux || true

# Disable swap (required for kubelet)
swapoff -a || true
sed -ri '/\sswap\s/s/^#?/#/' /etc/fstab || true

# Base prerequisites (none driver needs these)
yum install -y yum-utils conntrack socat iptables ebtables ethtool curl wget tar containernetworking-plugins

# Install Docker
yum-config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo
yum install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin --allowerasing
systemctl enable --now docker

# Install Kubectl
curl -fsSLo /usr/bin/kubectl https://dl.k8s.io/release/v1.26.0/bin/linux/amd64/kubectl
chmod +x /usr/bin/kubectl

# Install Minikube
curl -fsSLo /usr/bin/minikube https://github.com/kubernetes/minikube/releases/download/v1.28.0/minikube-linux-amd64
chmod +x /usr/bin/minikube

# Install crictl
VERSION="v1.25.0"
curl -fsSLo /tmp/crictl.tgz https://github.com/kubernetes-sigs/cri-tools/releases/download/${VERSION}/crictl-${VERSION}-linux-amd64.tar.gz
tar -xzf /tmp/crictl.tgz -C /usr/bin/
rm -f /tmp/crictl.tgz

# Install cri-dockerd (RPM)
curl -fsSLo /tmp/cri-dockerd.rpm https://github.com/Mirantis/cri-dockerd/releases/download/v0.2.6/cri-dockerd-0.2.6-3.el8.x86_64.rpm
rpm -Uvh /tmp/cri-dockerd.rpm
rm -f /tmp/cri-dockerd.rpm

# Ensure cri-dockerd is running (required for docker runtime on k8s v1.24+)
systemctl daemon-reload || true
systemctl enable --now cri-docker.socket || true
systemctl enable --now cri-docker.service || true

# Ensure directories Minikube expects for CNI
mkdir -p /etc/cni/net.d
mkdir -p /opt/cni/bin

# Copy CNI plugin binaries to /opt/cni/bin (CentOS installs them under /usr/libexec/cni)
if [ -d /usr/libexec/cni ]; then
  cp -a /usr/libexec/cni/* /opt/cni/bin/
elif [ -d /usr/lib/cni ]; then
  cp -a /usr/lib/cni/* /opt/cni/bin/
fi

# Kernel networking settings 
modprobe br_netfilter || true
cat >/etc/sysctl.d/99-k8s.conf <<'EOF'
net.bridge.bridge-nf-call-iptables=1
net.bridge.bridge-nf-call-ip6tables=1
net.ipv4.ip_forward=1
EOF
sysctl --system >/dev/null

# Start clean to avoid loading an existing profile.
minikube delete --all --purge || true

# Start Minikube 
minikube start --driver=none --cni=bridge