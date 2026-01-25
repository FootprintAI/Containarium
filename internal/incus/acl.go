package incus

import (
	"fmt"

	"github.com/lxc/incus/shared/api"
)

// ACLRule represents a single firewall rule
type ACLRule struct {
	Action          string // "allow", "drop", "reject"
	Source          string // CIDR, "@internal", "@external", or empty
	Destination     string // CIDR, "@internal", "@external", or empty
	DestinationPort string // "80", "80,443", "1000-2000", or empty
	Protocol        string // "tcp", "udp", "icmp", or empty
	Description     string
}

// ACLConfig holds configuration for creating a network ACL
type ACLConfig struct {
	Name         string
	Description  string
	IngressRules []ACLRule
	EgressRules  []ACLRule
}

// ACLPreset represents predefined firewall configurations
type ACLPreset string

const (
	// ACLPresetFullIsolation blocks inter-container traffic, allows only proxy ingress
	ACLPresetFullIsolation ACLPreset = "full-isolation"

	// ACLPresetHTTPOnly allows HTTP/HTTPS ingress from any source
	ACLPresetHTTPOnly ACLPreset = "http-only"

	// ACLPresetPermissive allows all traffic
	ACLPresetPermissive ACLPreset = "permissive"
)

// GetPresetACL returns ACL rules for a given preset
func GetPresetACL(preset ACLPreset, proxyIP string, containerNetwork string) ACLConfig {
	switch preset {
	case ACLPresetFullIsolation:
		return ACLConfig{
			Name:        string(preset),
			Description: "Full isolation: only allow HTTP from proxy, block inter-container traffic",
			IngressRules: []ACLRule{
				{
					Action:          "allow",
					Source:          proxyIP,
					DestinationPort: "80,443,3000,8080",
					Protocol:        "tcp",
					Description:     "Allow HTTP/HTTPS from reverse proxy",
				},
				{
					Action:      "drop",
					Source:      containerNetwork, // e.g., "10.100.0.0/24"
					Description: "Block all inter-container traffic",
				},
				{
					Action:      "drop",
					Source:      "@external",
					Description: "Block all other external traffic",
				},
			},
			EgressRules: []ACLRule{
				{
					Action:          "allow",
					DestinationPort: "53",
					Protocol:        "udp",
					Description:     "Allow DNS",
				},
				{
					Action:          "allow",
					DestinationPort: "443",
					Protocol:        "tcp",
					Description:     "Allow HTTPS outbound for APIs",
				},
				{
					Action:      "drop",
					Destination: containerNetwork,
					Description: "Block egress to other containers",
				},
				{
					Action:      "allow",
					Description: "Allow other outbound traffic",
				},
			},
		}

	case ACLPresetHTTPOnly:
		return ACLConfig{
			Name:        string(preset),
			Description: "HTTP only: allow HTTP/HTTPS inbound, standard egress",
			IngressRules: []ACLRule{
				{
					Action:          "allow",
					DestinationPort: "80,443",
					Protocol:        "tcp",
					Description:     "Allow HTTP/HTTPS",
				},
				{
					Action:      "drop",
					Description: "Block all other inbound",
				},
			},
			EgressRules: []ACLRule{
				{
					Action:      "allow",
					Description: "Allow all outbound",
				},
			},
		}

	case ACLPresetPermissive:
		return ACLConfig{
			Name:        string(preset),
			Description: "Permissive: allow all traffic (development only)",
			IngressRules: []ACLRule{
				{
					Action:      "allow",
					Description: "Allow all inbound",
				},
			},
			EgressRules: []ACLRule{
				{
					Action:      "allow",
					Description: "Allow all outbound",
				},
			},
		}

	default:
		// Default to full isolation
		return GetPresetACL(ACLPresetFullIsolation, proxyIP, containerNetwork)
	}
}

// convertRuleToAPI converts our ACLRule to Incus API format
func convertRuleToAPI(rule ACLRule) api.NetworkACLRule {
	return api.NetworkACLRule{
		Action:          rule.Action,
		Source:          rule.Source,
		Destination:     rule.Destination,
		DestinationPort: rule.DestinationPort,
		Protocol:        rule.Protocol,
		Description:     rule.Description,
		State:           "enabled",
	}
}

// CreateNetworkACL creates a new network ACL
func (c *Client) CreateNetworkACL(config ACLConfig) error {
	// Convert rules to API format
	var ingressRules []api.NetworkACLRule
	for _, rule := range config.IngressRules {
		ingressRules = append(ingressRules, convertRuleToAPI(rule))
	}

	var egressRules []api.NetworkACLRule
	for _, rule := range config.EgressRules {
		egressRules = append(egressRules, convertRuleToAPI(rule))
	}

	acl := api.NetworkACLsPost{
		NetworkACLPost: api.NetworkACLPost{
			Name: config.Name,
		},
		NetworkACLPut: api.NetworkACLPut{
			Description: config.Description,
			Ingress:     ingressRules,
			Egress:      egressRules,
		},
	}

	if err := c.server.CreateNetworkACL(acl); err != nil {
		return fmt.Errorf("failed to create network ACL %s: %w", config.Name, err)
	}

	return nil
}

// GetNetworkACL gets a network ACL by name
func (c *Client) GetNetworkACL(name string) (*api.NetworkACL, error) {
	acl, _, err := c.server.GetNetworkACL(name)
	if err != nil {
		return nil, fmt.Errorf("failed to get network ACL %s: %w", name, err)
	}
	return acl, nil
}

// UpdateNetworkACL updates an existing network ACL
func (c *Client) UpdateNetworkACL(name string, config ACLConfig) error {
	// Get current ACL to preserve ETag
	_, etag, err := c.server.GetNetworkACL(name)
	if err != nil {
		return fmt.Errorf("failed to get network ACL %s: %w", name, err)
	}

	// Convert rules to API format
	var ingressRules []api.NetworkACLRule
	for _, rule := range config.IngressRules {
		ingressRules = append(ingressRules, convertRuleToAPI(rule))
	}

	var egressRules []api.NetworkACLRule
	for _, rule := range config.EgressRules {
		egressRules = append(egressRules, convertRuleToAPI(rule))
	}

	aclPut := api.NetworkACLPut{
		Description: config.Description,
		Ingress:     ingressRules,
		Egress:      egressRules,
	}

	if err := c.server.UpdateNetworkACL(name, aclPut, etag); err != nil {
		return fmt.Errorf("failed to update network ACL %s: %w", name, err)
	}

	return nil
}

// DeleteNetworkACL deletes a network ACL
func (c *Client) DeleteNetworkACL(name string) error {
	if err := c.server.DeleteNetworkACL(name); err != nil {
		return fmt.Errorf("failed to delete network ACL %s: %w", name, err)
	}
	return nil
}

// ListNetworkACLs lists all network ACLs
func (c *Client) ListNetworkACLs() ([]api.NetworkACL, error) {
	acls, err := c.server.GetNetworkACLs()
	if err != nil {
		return nil, fmt.Errorf("failed to list network ACLs: %w", err)
	}
	return acls, nil
}

// AttachACLToContainer attaches a network ACL to a container's network device
func (c *Client) AttachACLToContainer(containerName, aclName, deviceName string) error {
	// Get current container configuration
	inst, etag, err := c.server.GetInstance(containerName)
	if err != nil {
		return fmt.Errorf("failed to get container %s: %w", containerName, err)
	}

	// Find the network device
	device, exists := inst.Devices[deviceName]
	if !exists {
		return fmt.Errorf("device %s not found in container %s", deviceName, containerName)
	}

	// Add ACL to the device
	device["security.acls"] = aclName
	inst.Devices[deviceName] = device

	// Update the container
	op, err := c.server.UpdateInstance(containerName, inst.Writable(), etag)
	if err != nil {
		return fmt.Errorf("failed to attach ACL to container: %w", err)
	}

	if err := op.Wait(); err != nil {
		return fmt.Errorf("failed to attach ACL (operation failed): %w", err)
	}

	return nil
}

// DetachACLFromContainer removes a network ACL from a container's network device
func (c *Client) DetachACLFromContainer(containerName, deviceName string) error {
	// Get current container configuration
	inst, etag, err := c.server.GetInstance(containerName)
	if err != nil {
		return fmt.Errorf("failed to get container %s: %w", containerName, err)
	}

	// Find the network device
	device, exists := inst.Devices[deviceName]
	if !exists {
		return fmt.Errorf("device %s not found in container %s", deviceName, containerName)
	}

	// Remove ACL from the device
	delete(device, "security.acls")
	inst.Devices[deviceName] = device

	// Update the container
	op, err := c.server.UpdateInstance(containerName, inst.Writable(), etag)
	if err != nil {
		return fmt.Errorf("failed to detach ACL from container: %w", err)
	}

	if err := op.Wait(); err != nil {
		return fmt.Errorf("failed to detach ACL (operation failed): %w", err)
	}

	return nil
}

// GetContainerACL gets the ACL attached to a container's network device
func (c *Client) GetContainerACL(containerName, deviceName string) (string, error) {
	inst, _, err := c.server.GetInstance(containerName)
	if err != nil {
		return "", fmt.Errorf("failed to get container %s: %w", containerName, err)
	}

	device, exists := inst.Devices[deviceName]
	if !exists {
		return "", nil // No device found
	}

	aclName, _ := device["security.acls"]
	return aclName, nil
}

// EnsureACLForApp ensures an ACL exists for an app and returns its name
func (c *Client) EnsureACLForApp(appName, username string, preset ACLPreset, proxyIP, containerNetwork string) (string, error) {
	aclName := fmt.Sprintf("acl-%s-%s", username, appName)

	// Check if ACL already exists
	_, err := c.GetNetworkACL(aclName)
	if err == nil {
		// ACL exists, update it with new preset
		config := GetPresetACL(preset, proxyIP, containerNetwork)
		config.Name = aclName
		return aclName, c.UpdateNetworkACL(aclName, config)
	}

	// Create new ACL
	config := GetPresetACL(preset, proxyIP, containerNetwork)
	config.Name = aclName
	return aclName, c.CreateNetworkACL(config)
}

// EnsureACLForContainer ensures an ACL exists for a DevBox container and returns its name
// This creates a per-container firewall (not per-app) named "acl-{username}"
func (c *Client) EnsureACLForContainer(username string, preset ACLPreset, proxyIP, containerNetwork string) (string, error) {
	aclName := fmt.Sprintf("acl-%s", username)

	// Check if ACL already exists
	_, err := c.GetNetworkACL(aclName)
	if err == nil {
		// ACL exists, update it with new preset
		config := GetPresetACL(preset, proxyIP, containerNetwork)
		config.Name = aclName
		return aclName, c.UpdateNetworkACL(aclName, config)
	}

	// Create new ACL
	config := GetPresetACL(preset, proxyIP, containerNetwork)
	config.Name = aclName
	return aclName, c.CreateNetworkACL(config)
}

// ACLInfo holds information about an ACL attached to a container
type ACLInfo struct {
	Name         string
	Description  string
	IngressRules []ACLRule
	EgressRules  []ACLRule
}

// convertAPIRuleToACLRule converts Incus API rule to our ACLRule
func convertAPIRuleToACLRule(rule api.NetworkACLRule) ACLRule {
	return ACLRule{
		Action:          rule.Action,
		Source:          rule.Source,
		Destination:     rule.Destination,
		DestinationPort: rule.DestinationPort,
		Protocol:        rule.Protocol,
		Description:     rule.Description,
	}
}

// GetACLInfo gets full ACL information
func (c *Client) GetACLInfo(name string) (*ACLInfo, error) {
	acl, err := c.GetNetworkACL(name)
	if err != nil {
		return nil, err
	}

	info := &ACLInfo{
		Name:        acl.Name,
		Description: acl.Description,
	}

	for _, rule := range acl.Ingress {
		info.IngressRules = append(info.IngressRules, convertAPIRuleToACLRule(rule))
	}

	for _, rule := range acl.Egress {
		info.EgressRules = append(info.EgressRules, convertAPIRuleToACLRule(rule))
	}

	return info, nil
}
