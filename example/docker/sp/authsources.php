<?php

$config = [
    // This is a authentication source which handles admin authentication.
    'admin' => [
        'core:AdminPassword',
    ],

    // Default SP configuration
    'default-sp' => [
        'saml:SP',
        'entityID' => 'http://test-sp:8001',
        'idp' => 'http://simple-saml-proxy:8080',
        'discoURL' => null,
    ],
];