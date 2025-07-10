package proxy

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRandomBytes(t *testing.T) {
	// Test that randomBytes returns the requested number of bytes
	result := randomBytes(10)
	assert.Len(t, result, 10)

	// Test that randomBytes returns different values on subsequent calls
	result1 := randomBytes(20)
	result2 := randomBytes(20)
	assert.Len(t, result1, 20)
	assert.Len(t, result2, 20)
	assert.NotEqual(t, result1, result2)

	// Test edge cases
	result = randomBytes(0)
	assert.Empty(t, result)

	result = randomBytes(1)
	assert.Len(t, result, 1)

	// Test with larger values
	result = randomBytes(100)
	assert.Len(t, result, 100)
}
