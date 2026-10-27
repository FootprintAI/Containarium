package incus

import "fmt"

// GetNetworkConfigValue returns one key of a managed network's config, or ""
// when the key is unset.
func (c *Client) GetNetworkConfigValue(network, key string) (string, error) {
	n, _, err := c.server.GetNetwork(network)
	if err != nil {
		return "", fmt.Errorf("failed to get network %s: %w", network, err)
	}
	return n.Config[key], nil
}

// SetNetworkConfigValue sets one key of a managed network's config, leaving
// every other key as it was. An empty value unsets the key. It is the API
// equivalent of `incus network set <network> <key> <value>`.
func (c *Client) SetNetworkConfigValue(network, key, value string) error {
	n, etag, err := c.server.GetNetwork(network)
	if err != nil {
		return fmt.Errorf("failed to get network %s: %w", network, err)
	}
	put := n.Writable()
	if put.Config == nil {
		put.Config = map[string]string{}
	}
	if value == "" {
		delete(put.Config, key)
	} else {
		put.Config[key] = value
	}
	if err := c.server.UpdateNetwork(network, put, etag); err != nil {
		return fmt.Errorf("failed to update network %s: %w", network, err)
	}
	return nil
}
