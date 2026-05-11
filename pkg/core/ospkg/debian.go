package ospkg

type debianPkgMgr struct{}

func (d *debianPkgMgr) UpdateCmd() []string {
	return []string{"apt-get", "update"}
}

func (d *debianPkgMgr) InstallCmd(pkgs []string) []string {
	cmd := []string{"apt-get", "install", "-y"}
	return append(cmd, pkgs...)
}

func (d *debianPkgMgr) CreateUserCmd(username, gecos string) []string {
	if gecos == "" {
		gecos = ""
	}
	return []string{"adduser", "--disabled-password", "--gecos", gecos, username}
}

func (d *debianPkgMgr) SudoGroup() string {
	return "sudo"
}

func (d *debianPkgMgr) SSHServiceName() string {
	return "ssh"
}

func (d *debianPkgMgr) BasePackages() []string {
	return []string{
		"openssh-server",
		"sudo",
		"curl",
		"git",
		"vim",
		"htop",
		"net-tools",
		"iputils-ping",
	}
}

func (d *debianPkgMgr) PodmanAvailableInBaseRepos() bool {
	return false
}

func (d *debianPkgMgr) PodmanRepoScript() string {
	return `
mkdir -p /etc/apt/keyrings
curl -fsSL https://download.opensuse.org/repositories/devel:/kubic:/libcontainers:/unstable/xUbuntu_24.04/Release.key | gpg --dearmor -o /etc/apt/keyrings/devel_kubic_libcontainers_unstable.gpg
echo "deb [signed-by=/etc/apt/keyrings/devel_kubic_libcontainers_unstable.gpg] https://download.opensuse.org/repositories/devel:/kubic:/libcontainers:/unstable/xUbuntu_24.04/ /" > /etc/apt/sources.list.d/devel:kubic:libcontainers:unstable.list
apt-get update
`
}

func (d *debianPkgMgr) PipInstallCmd() []string {
	return []string{"apt-get", "install", "-y", "python3-pip"}
}

func (d *debianPkgMgr) CleanCmd() []string {
	return []string{"apt-get", "clean"}
}
