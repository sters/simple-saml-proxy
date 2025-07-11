<?php
/**
 * SimpleSAMLphp configuration for the SP
 */

$config = [
    'baseurlpath' => 'simplesaml/',
    'certdir' => '/certs/',
    'loggingdir' => '/var/log/',
    'datadir' => '/var/simplesamlphp/data/',
    'tempdir' => '/tmp/simplesaml/',
    'technicalcontact_name' => 'Administrator',
    'technicalcontact_email' => 'admin@example.com',
    'secretsalt' => getenv('SIMPLESAMLPHP_SECRET_SALT') ?: 'defaultsecret',
    'auth.adminpassword' => getenv('SIMPLESAMLPHP_ADMIN_PASSWORD') ?: 'admin123',
    
    'admin.protectindexpage' => false,
    'admin.protectmetadata' => false,

    'enable.saml20-idp' => false,
    'enable.shib13-idp' => false,
    'enable.adfs-idp' => false,
    'enable.wsfed-sp' => false,
    'enable.authmemcookie' => false,

    'session.duration' => 8 * (60 * 60), // 8 hours
    'session.datastore.timeout' => (4 * 60 * 60), // 4 hours
    'session.state.timeout' => (60 * 60), // 1 hour
    'session.cookie.lifetime' => 0,
    'session.cookie.secure' => false,

    'language.default' => 'en',
    'theme.use' => 'default',

    'metadata.sources' => [
        ['type' => 'flatfile'],
    ],
];