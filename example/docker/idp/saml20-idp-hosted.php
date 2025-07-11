<?php
/**
 * SAML 2.0 IdP configuration for SimpleSAMLphp.
 */

$metadata['http://test-idp:8000/simplesaml/saml2/idp/metadata.php'] = [
    /*
     * The hostname of the server (VHOST) that will use this SAML entity.
     */
    'host' => '__DEFAULT__',

    /*
     * X.509 key and certificate. The private key and certificate are used to sign responses.
     */
    'privatekey' => 'idp.key',
    'certificate' => 'idp.crt',

    /*
     * Authentication source to use. It must be one that is configured in authsources.php.
     */
    'auth' => 'example-userpass',

    /*
     * What sign.* options should be used for this IdP.
     */
    'sign.authnrequest' => true,
    'redirect.sign' => true,
    'redirect.validate' => true,
];