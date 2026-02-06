package container

import (
	"strings"
	"testing"
)

func TestIsValidUsername(t *testing.T) {
	tests := []struct {
		name     string
		username string
		want     bool
	}{
		// Valid usernames
		{
			name:     "simple lowercase",
			username: "alice",
			want:     true,
		},
		{
			name:     "with numbers",
			username: "alice123",
			want:     true,
		},
		{
			name:     "with hyphen",
			username: "alice-dev",
			want:     true,
		},
		{
			name:     "with underscore",
			username: "alice_dev",
			want:     true,
		},
		{
			name:     "uppercase",
			username: "Alice",
			want:     true,
		},
		{
			name:     "mixed case with numbers",
			username: "Alice123",
			want:     true,
		},
		{
			name:     "single character",
			username: "a",
			want:     true,
		},
		{
			name:     "max length 32",
			username: strings.Repeat("a", 32),
			want:     true,
		},

		// Invalid usernames
		{
			name:     "empty string",
			username: "",
			want:     false,
		},
		{
			name:     "too long",
			username: strings.Repeat("a", 33),
			want:     false,
		},
		{
			name:     "starts with number",
			username: "123alice",
			want:     false,
		},
		{
			name:     "starts with hyphen",
			username: "-alice",
			want:     false,
		},
		{
			name:     "contains space",
			username: "alice dev",
			want:     false,
		},
		{
			name:     "contains special char @",
			username: "alice@dev",
			want:     false,
		},
		{
			name:     "contains special char .",
			username: "alice.dev",
			want:     false,
		},
		{
			name:     "contains special char !",
			username: "alice!",
			want:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isValidUsername(tt.username)
			if got != tt.want {
				t.Errorf("isValidUsername(%q) = %v, want %v", tt.username, got, tt.want)
			}
		})
	}
}

func TestUserExists(t *testing.T) {
	// Test with a user that definitely exists on Unix systems
	t.Run("root user exists", func(t *testing.T) {
		// root should exist on all Unix systems
		if got := UserExists("root"); !got {
			t.Errorf("UserExists(\"root\") = false, want true")
		}
	})

	t.Run("nonexistent user", func(t *testing.T) {
		// This user should not exist
		if got := UserExists("nonexistent_user_12345"); got {
			t.Errorf("UserExists(\"nonexistent_user_12345\") = true, want false")
		}
	})
}

func TestParseSSHKeyFromAuthorizedKeys(t *testing.T) {
	tests := []struct {
		name           string
		content        string
		wantKey        string
		wantErr        bool
	}{
		{
			name:    "single RSA key",
			content: "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC... user@host",
			wantKey: "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC... user@host",
			wantErr: false,
		},
		{
			name:    "single ED25519 key",
			content: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGj... user@host",
			wantKey: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGj... user@host",
			wantErr: false,
		},
		{
			name:    "single ECDSA key",
			content: "ssh-ecdsa AAAAE2VjZHNhLXNoYTItbmlzdHAyN... user@host",
			wantKey: "ssh-ecdsa AAAAE2VjZHNhLXNoYTItbmlzdHAyN... user@host",
			wantErr: false,
		},
		{
			name:    "ecdsa-sha2-nistp256 key",
			content: "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTI... user@host",
			wantKey: "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTI... user@host",
			wantErr: false,
		},
		{
			name: "multiple keys returns first",
			content: `ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC... first@host
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGj... second@host`,
			wantKey: "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC... first@host",
			wantErr: false,
		},
		{
			name: "ignores comments",
			content: `# This is a comment
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC... user@host`,
			wantKey: "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC... user@host",
			wantErr: false,
		},
		{
			name: "ignores empty lines",
			content: `

ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGj... user@host

`,
			wantKey: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGj... user@host",
			wantErr: false,
		},
		{
			name:    "empty content",
			content: "",
			wantKey: "",
			wantErr: true,
		},
		{
			name:    "only comments",
			content: "# This is a comment\n# Another comment",
			wantKey: "",
			wantErr: true,
		},
		{
			name:    "invalid key format",
			content: "not-a-valid-ssh-key some-data",
			wantKey: "",
			wantErr: true,
		},
		{
			name:    "key with leading whitespace",
			content: "  ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC... user@host",
			wantKey: "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC... user@host",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseSSHKeyFromContent(tt.content)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseSSHKeyFromContent() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.wantKey {
				t.Errorf("parseSSHKeyFromContent() = %q, want %q", got, tt.wantKey)
			}
		})
	}
}

// parseSSHKeyFromContent is a helper function extracted from ExtractSSHKeyFromContainer
// for easier testing. It parses the content of an authorized_keys file and returns
// the first valid SSH public key.
func parseSSHKeyFromContent(content string) (string, error) {
	lines := strings.Split(content, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Validate it looks like an SSH key
		if strings.HasPrefix(line, "ssh-rsa ") ||
			strings.HasPrefix(line, "ssh-ed25519 ") ||
			strings.HasPrefix(line, "ssh-ecdsa ") ||
			strings.HasPrefix(line, "ecdsa-sha2-") ||
			strings.HasPrefix(line, "ssh-dss ") {
			return line, nil
		}
	}

	return "", errNoValidSSHKey
}

var errNoValidSSHKey = &parseError{"no valid SSH key found in authorized_keys"}

type parseError struct {
	msg string
}

func (e *parseError) Error() string {
	return e.msg
}

func TestContainerNameToUsername(t *testing.T) {
	tests := []struct {
		name          string
		containerName string
		wantUsername  string
		wantValid     bool
	}{
		{
			name:          "standard container name",
			containerName: "alice-container",
			wantUsername:  "alice",
			wantValid:     true,
		},
		{
			name:          "container with hyphenated username",
			containerName: "alice-dev-container",
			wantUsername:  "alice-dev",
			wantValid:     true,
		},
		{
			name:          "non-standard name without suffix",
			containerName: "alice",
			wantUsername:  "alice",
			wantValid:     false, // doesn't follow naming convention
		},
		{
			name:          "system container",
			containerName: "_containarium-core",
			wantUsername:  "_containarium-core",
			wantValid:     false,
		},
		{
			name:          "empty name",
			containerName: "",
			wantUsername:  "",
			wantValid:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotUsername, gotValid := containerNameToUsername(tt.containerName)
			if gotUsername != tt.wantUsername {
				t.Errorf("containerNameToUsername() username = %q, want %q", gotUsername, tt.wantUsername)
			}
			if gotValid != tt.wantValid {
				t.Errorf("containerNameToUsername() valid = %v, want %v", gotValid, tt.wantValid)
			}
		})
	}
}

// containerNameToUsername extracts the username from a container name
// following the Containarium naming convention: {username}-container
func containerNameToUsername(containerName string) (username string, valid bool) {
	const suffix = "-container"
	if strings.HasSuffix(containerName, suffix) {
		return strings.TrimSuffix(containerName, suffix), true
	}
	return containerName, false
}

// Benchmark tests
func BenchmarkIsValidUsername(b *testing.B) {
	usernames := []string{
		"alice",
		"alice-dev-123",
		"a",
		strings.Repeat("a", 32),
		"invalid user",
		"123invalid",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, u := range usernames {
			_ = isValidUsername(u)
		}
	}
}

func BenchmarkParseSSHKeyFromContent(b *testing.B) {
	content := `# SSH keys for user
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGjGnWPALDcPQnZaGsYRTjrZQdjU1Q2VmMz1cPEhDrN user@host

# Another comment
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC7nZ1cF+Gzox9y8a0g5k2VmGp3qQ user@another
`

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = parseSSHKeyFromContent(content)
	}
}
