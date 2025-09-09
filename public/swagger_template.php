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
        'summary' => 'Login',
        'requestBody' => [
          'required' => true,
          'content' => [
            'application/json' => [
              'schema' => [
                'type' => 'object',
                'properties'=> [
                  'username'=> ['type'=>'string'],
                  'password'=>['type'=>'string']
                ]
              ]
            ]
          ]
        ],
        'responses' => ['200' => ['description' => 'JWT Token']]
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
