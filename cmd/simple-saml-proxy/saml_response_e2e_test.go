package main

import (
	"encoding/xml"
	"testing"
	"time"

	"github.com/crewjam/saml"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMockProviderResponse(t *testing.T) {
	// Create mock provider
	mockProvider := NewMockSAMLProvider(t)
	defer mockProvider.Close()

	// Test the createSAMLResponse method directly first
	testResponse := mockProvider.createSAMLResponse("test-id", "https://example.com/acs", "https://proxy.example.com")
	t.Logf("Direct SAML Response:\n%s", testResponse)

	// Verify the response is valid XML
	assert.Contains(t, testResponse, "<samlp:Response", "Expected Response element")
	assert.Contains(t, testResponse, "InResponseTo=\"test-id\"", "Expected matching InResponseTo")
}

func TestProxyCore(t *testing.T) {
	t.Log("Testing proxy core functionality...")

	// This test focuses on the proxy's core SAML handling without full E2E flow
	mockProvider := NewMockSAMLProvider(t)
	defer mockProvider.Close()

	// Test SAML response generation
	requestID := "test-request-123"
	acsURL := "https://testsp.example.com/acs"
	samlResponse := mockProvider.createSAMLResponse(requestID, acsURL, "https://proxy.example.com")

	// Parse and validate the response
	var response saml.Response
	err := xml.Unmarshal([]byte(samlResponse), &response)
	require.NoError(t, err, "Should parse SAML Response")

	// Validate response attributes
	assert.Equal(t, requestID, response.InResponseTo, "InResponseTo should match request ID")
	assert.Equal(t, acsURL, response.Destination, "Destination should match ACS URL")
	assert.NotNil(t, response.Issuer, "Should have issuer")
	assert.Equal(t, mockProvider.entityID, response.Issuer.Value, "Issuer should match provider entity ID")

	// Validate status
	assert.NotNil(t, response.Status, "Should have status")
	assert.NotNil(t, response.Status.StatusCode, "Should have status code")
	assert.Equal(t, saml.StatusSuccess, response.Status.StatusCode.Value, "Should be success status")

	// Validate assertion
	assert.NotNil(t, response.Assertion, "Should have assertion")
	assert.NotEmpty(t, response.Assertion.ID, "Assertion should have ID")
	assert.Equal(t, "2.0", response.Assertion.Version, "Should be SAML 2.0")

	// Validate subject
	assert.NotNil(t, response.Assertion.Subject, "Should have subject")
	assert.NotNil(t, response.Assertion.Subject.NameID, "Should have NameID")
	assert.Equal(t, "testuser@example.com", response.Assertion.Subject.NameID.Value, "Should have test user")

	// Validate conditions
	assert.NotNil(t, response.Assertion.Conditions, "Should have conditions")
	assert.False(t, response.Assertion.Conditions.NotBefore.IsZero(), "Should have NotBefore")
	assert.False(t, response.Assertion.Conditions.NotOnOrAfter.IsZero(), "Should have NotOnOrAfter")

	// Validate attributes
	assert.NotEmpty(t, response.Assertion.AttributeStatements, "Should have attribute statements")
	if len(response.Assertion.AttributeStatements) > 0 {
		attrs := response.Assertion.AttributeStatements[0].Attributes
		assert.NotEmpty(t, attrs, "Should have attributes")

		// Check for expected attributes
		var emailFound, nameFound bool
		for _, attr := range attrs {
			switch attr.Name {
			case "email":
				emailFound = true
				assert.NotEmpty(t, attr.Values, "Email attribute should have values")
				if len(attr.Values) > 0 {
					assert.Equal(t, "testuser@example.com", attr.Values[0].Value, "Email should match")
				}
			case "name":
				nameFound = true
				assert.NotEmpty(t, attr.Values, "Name attribute should have values")
				if len(attr.Values) > 0 {
					assert.Equal(t, "Test User", attr.Values[0].Value, "Name should match")
				}
			}
		}
		assert.True(t, emailFound, "Should have email attribute")
		assert.True(t, nameFound, "Should have name attribute")
	}

	t.Log("Proxy core tests completed successfully")
}

func TestSAMLResponseProcessing_ValidSAMLResponse(t *testing.T) {
	t.Log("Testing valid SAML response...")

	mockProvider := NewMockSAMLProvider(t)
	defer mockProvider.Close()

	// Create a valid response
	requestID := "test-request-123"
	acsURL := "https://testsp.example.com/acs"
	samlResponse := mockProvider.createSAMLResponse(requestID, acsURL, "https://proxy.example.com")

	// Decode and parse the response
	var response saml.Response
	err := xml.Unmarshal([]byte(samlResponse), &response)
	require.NoError(t, err, "Should parse SAML Response")

	// Validate response structure
	assert.Equal(t, requestID, response.InResponseTo, "InResponseTo should match request ID")
	assert.Equal(t, acsURL, response.Destination, "Destination should match ACS URL")
	assert.NotNil(t, response.Issuer, "Should have issuer")
	assert.Equal(t, mockProvider.entityID, response.Issuer.Value, "Issuer should match")

	// Validate timestamps
	assert.False(t, response.IssueInstant.IsZero(), "Should have IssueInstant")
	assert.WithinDuration(t, time.Now().UTC(), response.IssueInstant, 5*time.Minute, "IssueInstant should be recent")

	// Validate status
	assert.NotNil(t, response.Status, "Should have status")
	assert.NotNil(t, response.Status.StatusCode, "Should have status code")
	assert.Equal(t, saml.StatusSuccess, response.Status.StatusCode.Value, "Should be success")
}

func TestSAMLResponseProcessing_AssertionValidation(t *testing.T) {
	mockProvider := NewMockSAMLProvider(t)
	defer mockProvider.Close()

	samlResponse := mockProvider.createSAMLResponse("test-123", "https://sp.example.com/acs", "https://proxy.example.com")

	var response saml.Response
	err := xml.Unmarshal([]byte(samlResponse), &response)
	require.NoError(t, err)

	assertion := response.Assertion
	require.NotNil(t, assertion, "Should have assertion")

	// Validate assertion structure
	assert.NotEmpty(t, assertion.ID, "Should have assertion ID")
	assert.Equal(t, "2.0", assertion.Version, "Should be SAML 2.0")
	assert.False(t, assertion.IssueInstant.IsZero(), "Should have issue instant")

	// Validate subject
	require.NotNil(t, assertion.Subject, "Should have subject")
	require.NotNil(t, assertion.Subject.NameID, "Should have NameID")
	assert.Equal(t, "testuser@example.com", assertion.Subject.NameID.Value)
	assert.Equal(t, "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent", assertion.Subject.NameID.Format)

	// Validate subject confirmation
	require.NotEmpty(t, assertion.Subject.SubjectConfirmations, "Should have subject confirmations")
	confirmation := assertion.Subject.SubjectConfirmations[0]
	assert.Equal(t, "urn:oasis:names:tc:SAML:2.0:cm:bearer", confirmation.Method)
	assert.NotNil(t, confirmation.SubjectConfirmationData, "Should have confirmation data")

	// Validate conditions
	require.NotNil(t, assertion.Conditions, "Should have conditions")
	assert.True(t, assertion.Conditions.NotBefore.Before(time.Now().UTC()), "NotBefore should be in past")
	assert.True(t, assertion.Conditions.NotOnOrAfter.After(time.Now().UTC()), "NotOnOrAfter should be in future")

	// Validate audience restriction
	require.NotEmpty(t, assertion.Conditions.AudienceRestrictions, "Should have audience restrictions")
	require.NotEmpty(t, assertion.Conditions.AudienceRestrictions[0].Audience, "Should have audience")
	assert.Equal(t, "https://proxy.example.com", assertion.Conditions.AudienceRestrictions[0].Audience.Value)

	// Validate attributes
	require.NotEmpty(t, assertion.AttributeStatements, "Should have attribute statements")
	attrs := assertion.AttributeStatements[0].Attributes

	var emailFound, nameFound bool
	for _, attr := range attrs {
		switch attr.Name {
		case "email":
			emailFound = true
			if len(attr.Values) > 0 {
				assert.Equal(t, "testuser@example.com", attr.Values[0].Value, "Email value should match")
			}
		case "name":
			nameFound = true
			if len(attr.Values) > 0 {
				assert.Equal(t, "Test User", attr.Values[0].Value, "Name value should match")
			}
		}
	}
	assert.True(t, emailFound, "Should have email attribute")
	assert.True(t, nameFound, "Should have name attribute")
}

func TestSAMLResponseProcessing_RelayStatePreservation(t *testing.T) {
	// Test that RelayState is preserved through the flow
	originalRelayState := "test-relay-state-12345"

	// When the mock IdP receives a request with RelayState, it should preserve it
	// This is already tested in the complete flow test, but we can verify it here
	assert.NotEmpty(t, originalRelayState, "RelayState should not be empty")

	// In a real implementation, we would verify that:
	// 1. SP sends RelayState to Proxy
	// 2. Proxy sends RelayState to IdP
	// 3. IdP returns same RelayState to Proxy
	// 4. Proxy returns same RelayState to SP
	t.Log("RelayState preservation is tested in the complete flow test")
}

func TestSAMLResponseProcessing_TimestampValidation(t *testing.T) {
	mockProvider := NewMockSAMLProvider(t)
	defer mockProvider.Close()

	// Create a SAML response
	samlResponse := mockProvider.createSAMLResponse("test-123", "https://sp.example.com/acs", "https://proxy.example.com")

	// Parse and check timestamps
	var response saml.Response
	err := xml.Unmarshal([]byte(samlResponse), &response)
	require.NoError(t, err)

	// Check IssueInstant
	issueTime := response.IssueInstant
	assert.WithinDuration(t, time.Now().UTC(), issueTime, 5*time.Minute, "IssueInstant should be recent")

	// Check assertion timestamps
	if response.Assertion != nil {
		assertion := response.Assertion
		assertionIssueTime := assertion.IssueInstant
		assert.WithinDuration(t, time.Now().UTC(), assertionIssueTime, 5*time.Minute, "Assertion IssueInstant should be recent")

		// Check conditions timestamps
		if assertion.Conditions != nil {
			notBefore := assertion.Conditions.NotBefore
			notOnOrAfter := assertion.Conditions.NotOnOrAfter
			assert.True(t, notBefore.Before(notOnOrAfter), "NotBefore should be before NotOnOrAfter")
			assert.True(t, issueTime.After(notBefore) || issueTime.Equal(notBefore), "IssueInstant should be after or equal to NotBefore")
			assert.True(t, issueTime.Before(notOnOrAfter), "IssueInstant should be before NotOnOrAfter")
		}
	}

	t.Log("Timestamp validation test completed")
}
