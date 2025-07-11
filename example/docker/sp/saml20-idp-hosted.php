<?php

// This would typically be populated with the proxy's metadata
// The SP will fetch it from http://simple-saml-proxy:8080/metadata
$metadata['http://simple-saml-proxy:8080'] = [
    'SingleSignOnService' => 'http://simple-saml-proxy:8080/sso',
    'SingleLogoutService' => 'http://simple-saml-proxy:8080/slo',
    'certificate' => '/certs/proxy.crt',
];