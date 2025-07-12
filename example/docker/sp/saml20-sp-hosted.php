<?php
/**
 * SAML 2.0 SP configuration for SimpleSAMLphp.
 */

$metadata['default-sp'] = [
    'entityID' => 'http://test-sp:8000',
    'privatekey' => 'sp.key',
    'certificate' => 'sp.crt',
    
    'assertion.encryption' => false,
    'redirect.sign' => true,
    'redirect.validate' => true,
    
    'AssertionConsumerService' => [
        [
            'Binding' => 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
            'Location' => 'http://test-sp:8000/simplesaml/module.php/saml/sp/saml2-acs.php/default-sp',
            'index' => 0,
        ],
    ],
    
    'SingleLogoutService' => [
        [
            'Binding' => 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect',
            'Location' => 'http://test-sp:8000/simplesaml/module.php/saml/sp/saml2-logout.php/default-sp',
        ],
    ],
];