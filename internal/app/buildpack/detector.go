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

	return "", "", fmt.Errorf("could not detect application type; supported languages are " +
		"Node.js (package.json), Python (requirements.txt, Pipfile, pyproject.toml), " +
		"Go (go.mod), Rust (Cargo.toml), Ruby (Gemfile), PHP (composer.json), " +
		"Static (index.html) — or provide a Dockerfile manually")
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
