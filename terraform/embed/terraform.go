package embed

import (
	_ "embed"
)

// Terraform configuration files
//
//go:embed ../gce/main.tf
var MainTF string

//go:embed ../gce/spot-instance.tf
var SpotInstanceTF string

//go:embed ../gce/horizontal-scaling.tf
var HorizontalScalingTF string

//go:embed ../gce/variables.tf
var VariablesTF string

//go:embed ../gce/outputs.tf
var OutputsTF string

// Note: providers.tf doesn't exist in terraform/gce/, commenting out
// //go:embed ../gce/providers.tf
// var ProvidersTF string

// Startup scripts
//
//go:embed ../gce/scripts/startup-spot.sh
var StartupSpotSH string

//go:embed ../gce/scripts/startup.sh
var StartupSH string

// TerraformFiles returns a map of filename to content for all Terraform files
func TerraformFiles() map[string]string {
	return map[string]string{
		"main.tf":               MainTF,
		"spot-instance.tf":      SpotInstanceTF,
		"horizontal-scaling.tf": HorizontalScalingTF,
		"variables.tf":          VariablesTF,
		"outputs.tf":            OutputsTF,
		// "providers.tf":          ProvidersTF, // Commented out - file doesn't exist
	}
}

// ScriptFiles returns a map of filename to content for all script files
func ScriptFiles() map[string]string {
	return map[string]string{
		"scripts/startup-spot.sh": StartupSpotSH,
		"scripts/startup.sh":      StartupSH,
	}
}

// AllFiles returns all Terraform and script files
func AllFiles() map[string]string {
	files := make(map[string]string)

	for k, v := range TerraformFiles() {
		files[k] = v
	}

	for k, v := range ScriptFiles() {
		files[k] = v
	}

	return files
}
