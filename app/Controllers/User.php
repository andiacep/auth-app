<?php

namespace App\Controllers;

use App\Models\UserModel;
use CodeIgniter\RESTful\ResourceController;
use Exception;
use \Firebase\JWT\JWT;

class User extends ResourceController
{
    public function register()
    {
        $rules = [
            "nik" => "required|min_length[16]|max_length[16]",
            "role" => "required",
            "password" => "required|min_length[6]",
        ];

        $messages = [
            "nik" => [
                "required" => "NIK is required"
            ],
            "role" => [
                "required" => "Role Number is required"
            ],
            "password" => [
                "required" => "Password is required"
            ],
        ];

        if (!$this->validate($rules, $messages)) {

            $response = [
                'status' => 500,
                'error' => true,
                'message' => $this->validator->getErrors(),
                'data' => []
            ];
        } else {

            $userModel = new UserModel();

            $data = [
                "nik" => $this->request->getVar("nik"),
                "role" => $this->request->getVar("role"),
                "password" => password_hash($this->request->getVar("password"), PASSWORD_DEFAULT)
            ];

            if(count($userModel->where("nik", $this->request->getVar("nik"))->first()) <= 0){
                if ($userModel->insert($data)) {

                    $response = [
                        'status' => 200,
                        "error" => false,
                        'messages' => 'Successfully, user has been registered',
                        'data' => []
                    ];
                } else {
    
                    $response = [
                        'status' => 500,
                        "error" => true,
                        'messages' => 'Failed to create user',
                        'data' => []
                    ];
                }
            }else{
                $response = [
                    'status' => 500,
                    "error" => true,
                    'messages' => 'User is already',
                    'data' => []
                ];
            }
        }

        return $this->respondCreated($response);
    }

    private function getKey()
    {
        return "my_application_secret";
    }

    public function login()
    {
        $rules = [
            "nik" => "required|min_length[16]|max_length[16]",
            "password" => "required",
        ];

        $messages = [
            "nik" => [
                "required" => "NIK required"
            ],
            "password" => [
                "required" => "Password is required"
            ],
        ];

        if (!$this->validate($rules, $messages)) {

            $response = [
                'status' => 500,
                'error' => true,
                'message' => $this->validator->getErrors(),
                'data' => []
            ];

            return $this->respondCreated($response);
            
        } else {
            $userModel = new UserModel();

            $userdata = $userModel->where("nik", $this->request->getVar("nik"))->first();

            if (!empty($userdata)) {

                if (password_verify($this->request->getVar("password"), $userdata['password'])) {

                    $key = $this->getKey();

                    $iat = time(); 
                    $nbf = $iat + 10;
                    $exp = $iat + 3600;

                    $payload = array(
                        "iss" => "The_claim",
                        "aud" => "The_Aud",
                        "iat" => $iat, 
                        "nbf" => $nbf, 
                        "exp" => $exp, 
                        "data" => $userdata,
                    );

                    $token = JWT::encode($payload, $key);

                    $response = [
                        'status' => 200,
                        'error' => false,
                        'messages' => 'User logged In successfully',
                        'data' => [
                            'token' => $token
                        ]
                    ];
                    return $this->respondCreated($response);
                } else {

                    $response = [
                        'status' => 500,
                        'error' => true,
                        'messages' => 'Incorrect details',
                        'data' => []
                    ];
                    return $this->respondCreated($response);
                }
            } else {
                $response = [
                    'status' => 500,
                    'error' => true,
                    'messages' => 'User not found',
                    'data' => []
                ];
                return $this->respondCreated($response);
            }
        }
    }

    public function details()
    {
        $key = $this->getKey();
        $authHeader = $this->request->getHeader("Authorization");
        $authHeader = $authHeader->getValue();
        $token = $authHeader;

        try {
            $decoded = JWT::decode($token, $key, array("HS256"));

            if ($decoded) {

                $response = [
                    'status' => 200,
                    'error' => false,
                    'messages' => 'User details',
                    'data' => [
                        'profile' => $decoded
                    ]
                ];
                return $this->respondCreated($response);
            }
        } catch (Exception $ex) {
          
            $response = [
                'status' => 401,
                'error' => true,
                'messages' => 'Access denied',
                'data' => []
            ];
            return $this->respondCreated($response);
        }
    }
}