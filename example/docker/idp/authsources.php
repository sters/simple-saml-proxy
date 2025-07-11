<?php

$config = [
    // This is a authentication source which handles admin authentication.
    'admin' => [
        'core:AdminPassword',
    ],

    // An authentication source for testing
    'example-userpass' => [
        'exampleauth:UserPass',
        'user1:password' => [
            'uid' => ['user1'],
            'eduPersonAffiliation' => ['member', 'employee'],
            'email' => 'user1@example.com',
            'displayName' => 'Test User 1',
        ],
        'user2:password' => [
            'uid' => ['user2'],
            'eduPersonAffiliation' => ['member', 'student'],
            'email' => 'user2@example.com',
            'displayName' => 'Test User 2',
        ],
    ],
];