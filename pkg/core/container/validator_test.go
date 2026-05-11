package container

import (
	"errors"
	"strings"
	"testing"
)

func TestValidateContainerName(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		wantErr   bool
		expectErr error
	}{
		// Valid names
		{
			name:    "valid simple name",
			input:   "alice",
			wantErr: false,
		},
		{
			name:    "valid with hyphen",
			input:   "alice-dev",
			wantErr: false,
		},
		{
			name:    "valid with numbers",
			input:   "alice-dev-2024",
			wantErr: false,
		},
		{
			name:    "valid with multiple hyphens",
			input:   "team-api-prod-v2",
			wantErr: false,
		},
		{
			name:    "valid single character",
			input:   "a",
			wantErr: false,
		},
		{
			name:    "valid all numbers",
			input:   "123456",
			wantErr: false,
		},

		// Invalid - reserved prefix
		{
			name:      "invalid system prefix",
			input:     "_containarium-core",
			wantErr:   true,
			expectErr: ErrReservedPrefix,
		},
		{
			name:      "invalid single underscore",
			input:     "_",
			wantErr:   true,
			expectErr: ErrReservedPrefix,
		},
		{
			name:      "invalid underscore prefix with valid name",
			input:     "_alice",
			wantErr:   true,
			expectErr: ErrReservedPrefix,
		},

		// Invalid - format
		{
			name:      "invalid uppercase",
			input:     "Alice",
			wantErr:   true,
			expectErr: ErrInvalidFormat,
		},
		{
			name:      "invalid with underscore in middle",
			input:     "alice_dev",
			wantErr:   true,
			expectErr: ErrInvalidFormat,
		},
		{
			name:      "invalid with space",
			input:     "alice dev",
			wantErr:   true,
			expectErr: ErrInvalidFormat,
		},
		{
			name:      "invalid with special chars",
			input:     "alice@dev",
			wantErr:   true,
			expectErr: ErrInvalidFormat,
		},
		{
			name:      "invalid with dot",
			input:     "alice.dev",
			wantErr:   true,
			expectErr: ErrInvalidFormat,
		},

		// Invalid - empty/length
		{
			name:      "invalid empty string",
			input:     "",
			wantErr:   true,
			expectErr: ErrEmpty,
		},
		{
			name:      "invalid too long",
			input:     strings.Repeat("a", 64),
			wantErr:   true,
			expectErr: ErrTooLong,
		},
		{
			name:    "valid at max length",
			input:   strings.Repeat("a", 63),
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateContainerName(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateContainerName() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.expectErr != nil && !errors.Is(err, tt.expectErr) {
				t.Errorf("ValidateContainerName() error = %v, expectErr %v", err, tt.expectErr)
			}
		})
	}
}

func TestIsSystemContainer(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  bool
	}{
		{
			name:  "system container with valid name",
			input: "_containarium-core",
			want:  true,
		},
		{
			name:  "system container single underscore",
			input: "_",
			want:  true,
		},
		{
			name:  "user container",
			input: "alice",
			want:  false,
		},
		{
			name:  "user container with hyphen",
			input: "alice-dev",
			want:  false,
		},
		{
			name:  "empty string",
			input: "",
			want:  false,
		},
		{
			name:  "underscore in middle",
			input: "alice_dev",
			want:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsSystemContainer(tt.input)
			if got != tt.want {
				t.Errorf("IsSystemContainer() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestValidateSystemContainerName(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		wantErr   bool
		expectErr error
	}{
		// Valid system names
		{
			name:    "valid system container",
			input:   "_containarium-core",
			wantErr: false,
		},
		{
			name:    "valid system with numbers",
			input:   "_containarium-monitoring-v2",
			wantErr: false,
		},
		{
			name:    "valid system single char after underscore",
			input:   "_a",
			wantErr: false,
		},

		// Invalid - missing prefix
		{
			name:    "invalid no prefix",
			input:   "containarium-core",
			wantErr: true,
		},
		{
			name:      "invalid empty",
			input:     "",
			wantErr:   true,
			expectErr: ErrEmpty,
		},

		// Invalid - format
		{
			name:      "invalid uppercase",
			input:     "_Containarium-core",
			wantErr:   true,
			expectErr: ErrInvalidFormat,
		},
		{
			name:      "invalid special chars",
			input:     "_containarium@core",
			wantErr:   true,
			expectErr: ErrInvalidFormat,
		},
		{
			name:      "invalid too long",
			input:     "_" + strings.Repeat("a", 63),
			wantErr:   true,
			expectErr: ErrTooLong,
		},
		{
			name:    "valid at max length",
			input:   "_" + strings.Repeat("a", 62),
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateSystemContainerName(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateSystemContainerName() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.expectErr != nil && !errors.Is(err, tt.expectErr) {
				t.Errorf("ValidateSystemContainerName() error = %v, expectErr %v", err, tt.expectErr)
			}
		})
	}
}

func TestValidateUserContainerName(t *testing.T) {
	// This is an alias for ValidateContainerName, so just test it exists
	// and works correctly
	err := ValidateUserContainerName("alice")
	if err != nil {
		t.Errorf("ValidateUserContainerName() unexpected error = %v", err)
	}

	err = ValidateUserContainerName("_system")
	if err != ErrReservedPrefix {
		t.Errorf("ValidateUserContainerName() error = %v, want %v", err, ErrReservedPrefix)
	}
}

// Benchmark tests for performance
func BenchmarkValidateContainerName(b *testing.B) {
	validNames := []string{
		"alice",
		"alice-dev",
		"team-api-prod-v2",
		strings.Repeat("a", 63),
	}

	invalidNames := []string{
		"_system",
		"Alice",
		"alice_dev",
		strings.Repeat("a", 64),
	}

	b.Run("valid names", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			for _, name := range validNames {
				_ = ValidateContainerName(name)
			}
		}
	})

	b.Run("invalid names", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			for _, name := range invalidNames {
				_ = ValidateContainerName(name)
			}
		}
	})
}

func BenchmarkIsSystemContainer(b *testing.B) {
	names := []string{
		"_containarium-core",
		"alice",
		"alice-dev",
		"_",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, name := range names {
			_ = IsSystemContainer(name)
		}
	}
}
