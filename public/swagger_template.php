<?php
$baseUrl = sprintf(
  '%s://%s',
  (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on' ? 'https' : 'http'),
  ($_SERVER['HTTP_HOST'] ?? 'localhost')
);
return [
  'openapi' => '3.0.0',
  'info' => ['title' => 'Mini Vault API', 'version' => '0.1'],
  'servers' => [['url' => $baseUrl]],
  'components' => [
    'securitySchemes' => [
      'bearerAuth' => ['type' => 'http', 'scheme' => 'bearer', 'bearerFormat' => 'JWT']
    ]
  ],
  'security' => [['bearerAuth' => []]],
  'paths' => [
    '/login' => [
      'post' => [
        'summary' => 'Login with username, password, and optional TOTP code',
        'tags' => ['Authentication'],
        'requestBody' => [
          'required' => true,
          'content' => [
            'application/json' => [
              'schema' => [
                'type' => 'object',
                'properties'=> [
                  'username'=> ['type'=>'string'],
                  'password'=>['type'=>'string'],
                  'totp_code'=>['type'=>'string', 'description'=>'6-digit TOTP code if TOTP is enabled']
                ],
                'required' => ['username', 'password']
              ]
            ]
          ]
        ],
        'responses' => [
          '200' => ['description' => 'JWT Token'],
          '401' => ['description' => 'TOTP required or invalid credentials']
        ]
      ]
    ],
    '/totp/setup' => [
      'post' => [
        'summary' => 'Initialize TOTP setup (returns QR code and manual entry key)',
        'tags' => ['Authentication'],
        'security' => [['bearerAuth' => []]],
        'responses' => [
          '200' => ['description' => 'Setup data with secret, secret_display (for manual entry without padding), QR code image, and backup codes']
        ]
      ]
    ],
    '/totp/confirm' => [
      'post' => [
        'summary' => 'Confirm TOTP setup with verification code',
        'tags' => ['Authentication'],
        'security' => [['bearerAuth' => []]],
        'requestBody' => [
          'required' => true,
          'content' => [
            'application/json' => [
              'schema' => [
                'type' => 'object',
                'properties'=> [
                  'secret'=> ['type'=>'string', 'description'=>'The secret from /totp/setup'],
                  'code'=> ['type'=>'string', 'description'=>'6-digit code from authenticator app']
                ],
                'required' => ['secret', 'code']
              ]
            ]
          ]
        ],
        'responses' => [
          '200' => ['description' => 'TOTP enabled successfully'],
          '400' => ['description' => 'Invalid verification code']
        ]
      ]
    ],
    '/totp/disable' => [
      'post' => [
        'summary' => 'Disable TOTP for the account',
        'tags' => ['Authentication'],
        'security' => [['bearerAuth' => []]],
        'requestBody' => [
          'required' => true,
          'content' => [
            'application/json' => [
              'schema' => [
                'type' => 'object',
                'properties'=> [
                  'totp_code'=> ['type'=>'string', 'description'=>'6-digit TOTP code or backup code']
                ],
                'required' => ['totp_code']
              ]
            ]
          ]
        ],
        'responses' => [
          '200' => ['description' => 'TOTP disabled'],
          '401' => ['description' => 'Invalid TOTP code']
        ]
      ]
    ],
    '/secret' => [
      'post' => [
        'summary' => 'Create new secret version',
        'security' => [['bearerAuth' => []]],
        'requestBody' => [
          'required' => true,
          'content' => [
            'application/json' => [
              'schema' => [
                'type' => 'object',
                'properties'=> [
                  'name'=> ['type'=>'string'],
                  'secret'=> ['type'=>'string']
                ]
              ]
            ]
          ]
        ],
        'responses' => ['200' => ['description' => 'Created']]
      ]
    ],
    '/secret/{name}' => [
      'get' => [
        'summary' => 'Get latest secret',
        'security' => [['bearerAuth' => []]],
        'parameters' => [
          ['name'=>'name','in'=>'path','required'=>true,'schema'=>['type'=>'string']]
        ],
        'responses' => ['200' => ['description' => 'Secret']]
      ]
    ],
    '/secret/{name}/{version}' => [
      'get' => [
        'summary' => 'Get specific version',
        'security' => [['bearerAuth' => []]],
        'parameters' => [
          ['name'=>'name','in'=>'path','required'=>true,'schema'=>['type'=>'string']],
          ['name'=>'version','in'=>'path','required'=>true,'schema'=>['type'=>'integer']]
        ],
        'responses' => ['200' => ['description' => 'Secret']]
      ]
    ],
    '/docs' => [
      'get' => [
        'summary' => 'Swagger UI (protected)', 
        'security' => [['bearerAuth' => []]],
        'responses' => ['200'=>['description'=>'Swagger UI']]
      ]
    ],
  ]
];
