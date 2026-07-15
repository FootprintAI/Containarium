package config

import "testing"

// allK8sEnvKeys lists every variable LoadK8s reads, so tests can isolate from
// ambient environment.
var allK8sEnvKeys = []string{
	EnvK8sKubeconfig, EnvK8sGatewayNamespace, EnvK8sGatewayHost, EnvK8sGatewaySSHPort,
	EnvK8sTenantNSPrefix, EnvK8sBoxImage, EnvK8sStorageClass,
	EnvK8sGatewayUpstreamPublicKey, EnvK8sGatewayUpstreamKeySecret,
	EnvK8sInsecureIgnoreHostKey, EnvK8sDefaultMemoryRequest, EnvK8sDefaultMemoryLimit,
	EnvK8sDisableMemoryFloor, EnvK8sGatewayService, EnvK8sGatewayAdvertisePort,
}

func clearK8sEnv(t *testing.T) {
	t.Helper()
	for _, k := range allK8sEnvKeys {
		t.Setenv(k, "")
	}
}

// TestLoadK8sDefaults verifies the documented defaults apply when nothing is set.
func TestLoadK8sDefaults(t *testing.T) {
	clearK8sEnv(t)
	got := LoadK8s()
	want := K8s{
		GatewayNamespace:      defaultK8sGatewayNamespace,
		TenantNamespacePrefix: defaultK8sTenantNSPrefix,
		GatewaySSHPort:        defaultK8sGatewaySSHPort,
		GatewayService:        defaultK8sGatewayService,
	}
	if got != want {
		t.Errorf("LoadK8s defaults = %+v, want %+v", got, want)
	}
}

// TestLoadK8sReadsEnv verifies each variable maps to its field, including the
// int and bool conversions.
func TestLoadK8sReadsEnv(t *testing.T) {
	clearK8sEnv(t)
	t.Setenv(EnvK8sKubeconfig, "/home/agent/.kube/config")
	t.Setenv(EnvK8sGatewayNamespace, "gw")
	t.Setenv(EnvK8sGatewayHost, "gw.example.com")
	t.Setenv(EnvK8sGatewaySSHPort, "2222")
	t.Setenv(EnvK8sTenantNSPrefix, "t-")
	t.Setenv(EnvK8sBoxImage, "ghcr.io/x/agent-box:latest")
	t.Setenv(EnvK8sStorageClass, "standard")
	t.Setenv(EnvK8sGatewayUpstreamPublicKey, "ssh-ed25519 AAA")
	t.Setenv(EnvK8sGatewayUpstreamKeySecret, "gw-upstream-key")
	t.Setenv(EnvK8sInsecureIgnoreHostKey, "1")
	t.Setenv(EnvK8sGatewayService, "my-gw")
	t.Setenv(EnvK8sGatewayAdvertisePort, "31000")
	t.Setenv(EnvK8sDefaultMemoryRequest, "512Mi")
	t.Setenv(EnvK8sDefaultMemoryLimit, "2Gi")
	t.Setenv(EnvK8sDisableMemoryFloor, "true")

	got := LoadK8s()
	want := K8s{
		Kubeconfig:                "/home/agent/.kube/config",
		GatewayNamespace:          "gw",
		GatewayHost:               "gw.example.com",
		GatewaySSHPort:            2222,
		TenantNamespacePrefix:     "t-",
		BoxImage:                  "ghcr.io/x/agent-box:latest",
		StorageClass:              "standard",
		GatewayUpstreamPublicKey:  "ssh-ed25519 AAA",
		GatewayUpstreamKeySecret:  "gw-upstream-key",
		InsecureIgnoreHostKey:     true,
		GatewayService:            "my-gw",
		GatewayAdvertisePort:      31000,
		DefaultMemoryRequest:      "512Mi",
		DefaultMemoryLimit:        "2Gi",
		DisableDefaultMemoryFloor: true,
	}
	if got != want {
		t.Errorf("LoadK8s = %+v\nwant %+v", got, want)
	}
}

// TestLoadK8sInvalidPortFallsBackToDefault verifies a non-numeric port degrades
// to the default rather than 0 (which would fail Validate).
func TestLoadK8sInvalidPortFallsBackToDefault(t *testing.T) {
	clearK8sEnv(t)
	t.Setenv(EnvK8sGatewaySSHPort, "notaport")
	if got := LoadK8s().GatewaySSHPort; got != defaultK8sGatewaySSHPort {
		t.Errorf("GatewaySSHPort = %d, want default %d", got, defaultK8sGatewaySSHPort)
	}
}

// TestK8sValidate covers the gateway-port range check.
func TestK8sValidate(t *testing.T) {
	if err := (K8s{GatewaySSHPort: 22}).Validate(); err != nil {
		t.Errorf("port 22 should be valid: %v", err)
	}
	if err := (K8s{GatewaySSHPort: 0}).Validate(); err == nil {
		t.Error("port 0 should be invalid")
	}
	if err := (K8s{GatewaySSHPort: 70000}).Validate(); err == nil {
		t.Error("port 70000 should be invalid")
	}
}

// TestGetBoolTruthyValues verifies the accepted truthy spellings (superset of
// the historical "1").
func TestGetBoolTruthyValues(t *testing.T) {
	for _, v := range []string{"1", "true", "TRUE", "Yes", "on"} {
		t.Setenv(EnvK8sDisableMemoryFloor, v)
		if !getBool(EnvK8sDisableMemoryFloor) {
			t.Errorf("getBool(%q) = false, want true", v)
		}
	}
	for _, v := range []string{"", "0", "false", "no", "off", "maybe"} {
		t.Setenv(EnvK8sDisableMemoryFloor, v)
		if getBool(EnvK8sDisableMemoryFloor) {
			t.Errorf("getBool(%q) = true, want false", v)
		}
	}
}
