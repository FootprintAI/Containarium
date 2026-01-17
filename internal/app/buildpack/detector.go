package buildpack

import (
	"fmt"
	"path/filepath"
	"strings"
)

// Language represents a detected programming language
type Language struct {
	Name    string
	Version string
}

// GenerateOptions contains options for generating a Dockerfile
type GenerateOptions struct {
	Port          int
	Files         []string
	NodeVersion   string
	PythonVersion string
	GoVersion     string
	RustVersion   string
}

// LanguageDetector detects languages and generates Dockerfiles
type LanguageDetector interface {
	Name() string
	Detect(files []string) (bool, string)
	GenerateDockerfile(opts GenerateOptions) (string, error)
}

// Detector orchestrates language detection
type Detector struct {
	detectors []LanguageDetector
}

// NewDetector creates a new detector with default language detectors
func NewDetector() *Detector {
	return &Detector{
		detectors: []LanguageDetector{
			&NodeJSDetector{},
			&PythonDetector{},
			&GoDetector{},
			&RustDetector{},
			&RubyDetector{},
			&PHPDetector{},
			&StaticDetector{},
		},
	}
}

// Detect detects the language from the given files
// Returns language name, detected version, and error
func (d *Detector) Detect(files []string) (string, string, error) {
	for _, detector := range d.detectors {
		if detected, version := detector.Detect(files); detected {
			return detector.Name(), version, nil
		}
	}

	return "", "", fmt.Errorf("could not detect application type. Supported languages:\n" +
		"  - Node.js (package.json)\n" +
		"  - Python (requirements.txt, Pipfile, pyproject.toml)\n" +
		"  - Go (go.mod)\n" +
		"  - Rust (Cargo.toml)\n" +
		"  - Ruby (Gemfile)\n" +
		"  - PHP (composer.json)\n" +
		"  - Static (index.html)\n" +
		"\nOr provide a Dockerfile manually.")
}

// GenerateDockerfile generates a Dockerfile for the detected language
func (d *Detector) GenerateDockerfile(langName string, opts GenerateOptions) (string, error) {
	for _, detector := range d.detectors {
		if strings.EqualFold(detector.Name(), langName) {
			return detector.GenerateDockerfile(opts)
		}
	}

	return "", fmt.Errorf("unsupported language: %s", langName)
}

// Helper functions used by detectors

// containsFile checks if a filename exists in the file list
func containsFile(files []string, filename string) bool {
	for _, f := range files {
		base := filepath.Base(f)
		if base == filename || f == filename {
			return true
		}
	}
	return false
}

// containsFileWithExt checks if any file with the given extension exists
func containsFileWithExt(files []string, ext string) bool {
	for _, f := range files {
		if strings.HasSuffix(f, ext) {
			return true
		}
	}
	return false
}

// getFileContent would read file content - placeholder for now
// In practice, this would need access to the actual files
func getFileContent(files []string, filename string) string {
	// This is a placeholder - actual implementation would need file access
	return ""
}
