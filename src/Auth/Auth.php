<?php
namespace DocuStream\Auth;

use MongoDB\BSON\ObjectId;
use DocuStream\Database\MongoDB;

class Auth
{
    private $usersCollection;

    public function __construct()
    {
        $mongo = new MongoDB();
        $this->usersCollection = $mongo->getCollection('users');
    }

    public function register($username, $email, $password)
    {
        try {
            // Sanitize inputs
            $username = filter_var(trim($username), FILTER_SANITIZE_STRING);
            $email = filter_var(trim($email), FILTER_SANITIZE_EMAIL);
            
            // Validate inputs
            if (!$username || !$email || !$password) {
                error_log("Registration failed: Invalid input data");
                return false;
            }

            // Additional email validation
            if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
                error_log("Registration failed: Invalid email format");
                return false;
            }

            // Check for existing user by email OR username
            $existingUser = $this->usersCollection->findOne([
                '$or' => [
                    ['email' => $email],
                    ['username' => $username]
                ]
            ]);
            
            if ($existingUser) {
                error_log("Registration failed: User already exists with email or username");
                return false;
            }

            // Validate password policy before hashing
            require_once __DIR__ . '/../../public/auth/register.php'; // Adjust path as needed
            $passwordValidation = PasswordPolicy::validatePassword($password, [
                'username' => $username,
                'email' => $email
            ]);
            
            if (!$passwordValidation['isValid']) {
                error_log("Registration failed: Password policy violation - " . implode(', ', $passwordValidation['errors']));
                return false;
            }

            // Hash password with strong settings
            $hashedPassword = password_hash($password, PASSWORD_ARGON2ID, [
                'memory_cost' => 65536, // 64 MB
                'time_cost' => 4,       // 4 iterations
                'threads' => 3          // 3 threads
            ]);

            // If Argon2ID not available, fall back to bcrypt with higher cost
            if (!$hashedPassword) {
                $hashedPassword = password_hash($password, PASSWORD_BCRYPT, ['cost' => 12]);
            }

            $result = $this->usersCollection->insertOne([
                'username' => $username,
                'email' => $email,
                'password' => $hashedPassword,
                'isAdmin' => false,
                'permissions' => VALID_PERMISSIONS,
                'created_at' => new \MongoDB\BSON\UTCDateTime(),
                'last_login' => null,
                'failed_login_attempts' => 0,
                'locked_until' => null
            ]);
            
            if ($result->getInsertedCount() === 1) {
                error_log("User registered successfully: " . $email);
                return true;
            }
            
            return false;
        } catch (\Exception $e) {
            error_log("Registration error: " . $e->getMessage());
            return false;
        }
    }

    public function login($email, $password)
    {
        try {
            $email = filter_var(trim($email), FILTER_SANITIZE_EMAIL);
            
            if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
                error_log("Login failed: Invalid email format");
                return false;
            }

            $user = $this->usersCollection->findOne(['email' => $email]);
            
            if (!$user) {
                error_log("Login failed: User not found for email: $email");
                // Add small delay to prevent timing attacks
                usleep(250000); // 0.25 seconds
                return false;
            }

            // Check if account is locked
            if ($this->isAccountLocked($user)) {
                error_log("Login failed: Account locked for email: $email");
                return false;
            }

            if (password_verify($password, $user['password'])) {
                // Check if password needs rehashing (for security upgrades)
                if (password_needs_rehash($user['password'], PASSWORD_ARGON2ID, [
                    'memory_cost' => 65536,
                    'time_cost' => 4,
                    'threads' => 3
                ])) {
                    $newHash = password_hash($password, PASSWORD_ARGON2ID, [
                        'memory_cost' => 65536,
                        'time_cost' => 4,
                        'threads' => 3
                    ]);
                    
                    if (!$newHash) {
                        $newHash = password_hash($password, PASSWORD_BCRYPT, ['cost' => 12]);
                    }
                    
                    $this->usersCollection->updateOne(
                        ['_id' => $user['_id']],
                        ['$set' => ['password' => $newHash]]
                    );
                }

                // Reset failed login attempts and update last login
                $this->usersCollection->updateOne(
                    ['_id' => $user['_id']],
                    [
                        '$set' => [
                            'last_login' => new \MongoDB\BSON\UTCDateTime(),
                            'failed_login_attempts' => 0
                        ],
                        '$unset' => ['locked_until' => '']
                    ]
                );

                // Regenerate session ID
                session_regenerate_id(true);
                
                $_SESSION['user_id'] = (string) $user['_id'];
                $_SESSION['last_activity'] = time();
                $_SESSION['permissions'] = isset($user['permissions']) && is_array($user['permissions'])
                    ? array_intersect($user['permissions'], VALID_PERMISSIONS)
                    : VALID_PERMISSIONS;
                
                error_log("Login successful for user: $email");
                return true;
            } else {
                // Increment failed login attempts
                $this->handleFailedLogin($user);
                error_log("Login failed: Invalid password for email: $email");
                return false;
            }
        } catch (\Exception $e) {
            error_log("Login error: " . $e->getMessage());
            return false;
        }
    }

    private function isAccountLocked($user)
    {
        if (!isset($user['locked_until']) || !$user['locked_until']) {
            return false;
        }

        $lockedUntil = $user['locked_until']->toDateTime()->getTimestamp();
        $now = time();

        if ($now >= $lockedUntil) {
            // Lock expired, remove it
            $this->usersCollection->updateOne(
                ['_id' => $user['_id']],
                [
                    '$unset' => ['locked_until' => ''],
                    '$set' => ['failed_login_attempts' => 0]
                ]
            );
            return false;
        }

        return true;
    }

    private function handleFailedLogin($user)
    {
        $attempts = ($user['failed_login_attempts'] ?? 0) + 1;
        $updateData = ['failed_login_attempts' => $attempts];

        // Lock account after 5 failed attempts
        if ($attempts >= 5) {
            $lockDuration = min(300 * pow(2, $attempts - 5), 3600); // Max 1 hour
            $updateData['locked_until'] = new \MongoDB\BSON\UTCDateTime((time() + $lockDuration) * 1000);
        }

        $this->usersCollection->updateOne(
            ['_id' => $user['_id']],
            ['$set' => $updateData]
        );
    }

    public function logout()
    {
        session_unset();
        session_destroy();
        session_start(); // Restart session for new CSRF token
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
        return true;
    }

    // Rest of your methods remain the same...
    public function getUserById($userId) {
        try {
            if (!preg_match('/^[a-f\d]{24}$/i', $userId)) {
                error_log("Invalid user ID: $userId");
                return null;
            }
            $user = $this->usersCollection->findOne(
                ['_id' => new \MongoDB\BSON\ObjectId($userId)],
                ['typeMap' => ['root' => 'array', 'document' => 'array', 'array' => 'array']]
            );
            if (!$user) {
                error_log("User not found for ID: $userId");
            }
            return $user;
        } catch (\Exception $e) {
            error_log("Get user error: " . $e->getMessage());
            return null;
        }
    }

    public function hasPermission($permission) {
        if (!$this->isAuthenticated()) {
            error_log("hasPermission: Not authenticated for permission: $permission");
            return false;
        }
        $user = $this->getUserById($_SESSION['user_id']);
        if (!$user) {
            error_log("hasPermission: User not found for ID: {$_SESSION['user_id']}");
            return false;
        }
        
        $permissions = isset($user['permissions']) && $user['permissions'] instanceof \MongoDB\Model\BSONArray
            ? (array) $user['permissions']
            : (is_array($user['permissions']) ? $user['permissions'] : []);
            
        if (!in_array($permission, VALID_PERMISSIONS)) {
            error_log("hasPermission: Invalid permission requested: $permission");
            return false;
        }
        
        $hasPermission = in_array($permission, $permissions);
        error_log("hasPermission: Checking '$permission' for user {$_SESSION['user_id']}: " . ($hasPermission ? 'granted' : 'denied'));
        return $hasPermission;
    }

    public function isAdmin() {
        if (!isset($_SESSION['user_id'])) {
            error_log("No user_id in session.");
            return false;
        }
        $user = $this->usersCollection->findOne(['_id' => new \MongoDB\BSON\ObjectId($_SESSION['user_id'])]);
        if (!$user) {
            error_log("User not found for ID: " . $_SESSION['user_id']);
            return false;
        }
        error_log("isAdmin check: " . ($user['isAdmin'] ? "true" : "false"));
        return !empty($user['isAdmin']) && $user['isAdmin'] === true;
    }

    public function isAuthenticated()
    {
        try {
            if (!isset($_SESSION['user_id']) || !isset($_SESSION['last_activity'])) {
                return false;
            }
            
            if (time() - $_SESSION['last_activity'] > SESSION_TIMEOUT) {
                $this->logout();
                return false;
            }
            
            $user = $this->getUserById($_SESSION['user_id']);
            if (!$user) {
                $this->logout();
                return false;
            }
            
            $_SESSION['last_activity'] = time();
            return true;
        } catch (\Exception $e) {
            error_log("Authentication check error: " . $e->getMessage());
            return false;
        }
    }

    public function validateCsrfToken($token)
    {
        return isset($_SESSION['csrf_token']) && hash_equals($_SESSION['csrf_token'], $token);
    }

    // Add other existing methods as needed...
}