package ospkg

type rhelPkgMgr struct{}

func (r *rhelPkgMgr) UpdateCmd() []string {
	return []string{"dnf", "makecache"}
}

func (r *rhelPkgMgr) InstallCmd(pkgs []string) []string {
	cmd := []string{"dnf", "install", "-y"}
	return append(cmd, pkgs...)
}

func (r *rhelPkgMgr) CreateUserCmd(username, gecos string) []string {
	cmd := []string{"useradd", "-m", "-s", "/bin/bash"}
	if gecos != "" {
		cmd = append(cmd, "-c", gecos)
	}
	cmd = append(cmd, username)
	return cmd
}

func (r *rhelPkgMgr) SudoGroup() string {
	return "wheel"
}

func (r *rhelPkgMgr) SSHServiceName() string {
	return "sshd"
}

func (r *rhelPkgMgr) BasePackages() []string {
	return []string{
		"openssh-server",
		"sudo",
		"curl",
		"git",
		"vim-enhanced",
		"htop",
		"net-tools",
		"iputils",
	}
}

func (r *rhelPkgMgr) PodmanAvailableInBaseRepos() bool {
	return true
}

func (r *rhelPkgMgr) PodmanRepoScript() string {
	return "" // Podman is in RHEL/Rocky base repos
}

func (r *rhelPkgMgr) PipInstallCmd() []string {
	return []string{"dnf", "install", "-y", "python3-pip"}
}

func (r *rhelPkgMgr) CleanCmd() []string {
	return []string{"dnf", "clean", "all"}
}
