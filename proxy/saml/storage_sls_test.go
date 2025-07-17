package saml

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zitadel/saml/pkg/provider/serviceprovider"
	"github.com/zitadel/saml/pkg/provider/xml/md"
)

func TestExtractSingleLogoutService(t *testing.T) {
	t.Run("Valid SP with HTTP-Redirect binding", func(t *testing.T) {
		sp := &serviceprovider.ServiceProvider{
			Metadata: &md.EntityDescriptorType{
				SPSSODescriptor: &md.SPSSODescriptorType{
					SingleLogoutService: []md.EndpointType{
						{
							Binding:  "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
							Location: "https://sp.example.com/slo",
						},
					},
				},
			},
		}

		sls, err := extractSingleLogoutService(sp)
		require.NoError(t, err)
		require.NotNil(t, sls)
		assert.Equal(t, "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect", sls.Binding)
		assert.Equal(t, "https://sp.example.com/slo", sls.Location)
	})

	t.Run("Valid SP with HTTP-POST binding only", func(t *testing.T) {
		sp := &serviceprovider.ServiceProvider{
			Metadata: &md.EntityDescriptorType{
				SPSSODescriptor: &md.SPSSODescriptorType{
					SingleLogoutService: []md.EndpointType{
						{
							Binding:  "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
							Location: "https://sp.example.com/slo/post",
						},
					},
				},
			},
		}

		sls, err := extractSingleLogoutService(sp)
		require.NoError(t, err)
		require.NotNil(t, sls)
		assert.Equal(t, "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST", sls.Binding)
		assert.Equal(t, "https://sp.example.com/slo/post", sls.Location)
	})

	t.Run("SP with multiple bindings - HTTP-Redirect preferred", func(t *testing.T) {
		sp := &serviceprovider.ServiceProvider{
			Metadata: &md.EntityDescriptorType{
				SPSSODescriptor: &md.SPSSODescriptorType{
					SingleLogoutService: []md.EndpointType{
						{
							Binding:  "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
							Location: "https://sp.example.com/slo/post",
						},
						{
							Binding:  "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
							Location: "https://sp.example.com/slo/redirect",
						},
						{
							Binding:  "urn:oasis:names:tc:SAML:2.0:bindings:SOAP",
							Location: "https://sp.example.com/slo/soap",
						},
					},
				},
			},
		}

		sls, err := extractSingleLogoutService(sp)
		require.NoError(t, err)
		require.NotNil(t, sls)
		// Should prefer HTTP-Redirect over HTTP-POST
		assert.Equal(t, "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect", sls.Binding)
		assert.Equal(t, "https://sp.example.com/slo/redirect", sls.Location)
	})

	t.Run("SP without SingleLogoutService", func(t *testing.T) {
		sp := &serviceprovider.ServiceProvider{
			Metadata: &md.EntityDescriptorType{
				SPSSODescriptor: &md.SPSSODescriptorType{
					SingleLogoutService: []md.EndpointType{},
				},
			},
		}

		sls, err := extractSingleLogoutService(sp)
		require.Error(t, err)
		assert.Nil(t, sls)
		assert.Equal(t, ErrNoSingleLogoutService, err)
	})

	t.Run("SP without SPSSODescriptor", func(t *testing.T) {
		sp := &serviceprovider.ServiceProvider{
			Metadata: &md.EntityDescriptorType{
				SPSSODescriptor: nil,
			},
		}

		sls, err := extractSingleLogoutService(sp)
		require.Error(t, err)
		assert.Nil(t, sls)
		assert.Equal(t, ErrNoSPSSODescriptor, err)
	})

	t.Run("SP without metadata", func(t *testing.T) {
		sp := &serviceprovider.ServiceProvider{
			Metadata: nil,
		}

		sls, err := extractSingleLogoutService(sp)
		require.Error(t, err)
		assert.Nil(t, sls)
		assert.Equal(t, ErrNoSPSSODescriptor, err)
	})

	t.Run("SP with unsupported binding only", func(t *testing.T) {
		sp := &serviceprovider.ServiceProvider{
			Metadata: &md.EntityDescriptorType{
				SPSSODescriptor: &md.SPSSODescriptorType{
					SingleLogoutService: []md.EndpointType{
						{
							Binding:  "urn:oasis:names:tc:SAML:2.0:bindings:SOAP",
							Location: "https://sp.example.com/slo/soap",
						},
					},
				},
			},
		}

		sls, err := extractSingleLogoutService(sp)
		require.Error(t, err)
		assert.Nil(t, sls)
		assert.Equal(t, ErrNoSingleLogoutService, err)
	})

	t.Run("Multiple endpoints with same binding - first is returned", func(t *testing.T) {
		sp := &serviceprovider.ServiceProvider{
			Metadata: &md.EntityDescriptorType{
				SPSSODescriptor: &md.SPSSODescriptorType{
					SingleLogoutService: []md.EndpointType{
						{
							Binding:  "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
							Location: "https://sp.example.com/slo/1",
						},
						{
							Binding:  "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
							Location: "https://sp.example.com/slo/2",
						},
					},
				},
			},
		}

		sls, err := extractSingleLogoutService(sp)
		require.NoError(t, err)
		require.NotNil(t, sls)
		assert.Equal(t, "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect", sls.Binding)
		assert.Equal(t, "https://sp.example.com/slo/1", sls.Location)
	})
}