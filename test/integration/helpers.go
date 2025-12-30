package integration

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// RebootTestState stores information needed to verify data after reboot
type RebootTestState struct {
	Username      string    `json:"username"`
	ContainerName string    `json:"container_name"`
	TestData      string    `json:"test_data"`
	TestDataHash  string    `json:"test_data_hash"`
	CreatedAt     time.Time `json:"created_at"`
	RebootedAt    time.Time `json:"rebooted_at,omitempty"`
}

// saveRebootTestState saves the test state to a JSON file
func saveRebootTestState(filePath string, state *RebootTestState) error {
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal state: %w", err)
	}

	err = os.WriteFile(filePath, data, 0644)
	if err != nil {
		return fmt.Errorf("failed to write state file: %w", err)
	}

	return nil
}

// loadRebootTestState loads the test state from a JSON file
func loadRebootTestState(filePath string) (*RebootTestState, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read state file: %w", err)
	}

	var state RebootTestState
	err = json.Unmarshal(data, &state)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal state: %w", err)
	}

	return &state, nil
}

// isRebootTestContinuation checks if this is a continuation of a reboot test
func isRebootTestContinuation(stateFile string) bool {
	_, err := os.Stat(stateFile)
	return err == nil
}

// markRebootCompleted updates the state file to mark reboot as completed
func markRebootCompleted(stateFile string) error {
	state, err := loadRebootTestState(stateFile)
	if err != nil {
		return err
	}

	state.RebootedAt = time.Now()
	return saveRebootTestState(stateFile, state)
}
