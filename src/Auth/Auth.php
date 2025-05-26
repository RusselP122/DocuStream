<?php
namespace DocuStream\Auth;

use MongoDB\BSON\ObjectId;
use MongoDB\BSON\UTCDateTime;
use DocuStream\Database\MongoDB;

// Define required constants
define('DocuStream\Auth\LOGIN_LOCKOUT_DURATION', 900); // 15 minutes in seconds
define('DocuStream\Auth\MAX_LOGIN_ATTEMPTS', 5); // Max login attempts before lockout
define('DocuStream\Auth\REGISTER_LOCKOUT_DURATION', 3600); // 1 hour in seconds
define('DocuStream\Auth\MAX_REGISTER_ATTEMPTS', 3); // Max registration attempts before lockout
define('DocuStream\Auth\VALID_PERMISSIONS', ['read', 'write', 'delete', 'upload', 'search', 'download', 'view', 'archive']); // Added 'archive'
define('DocuStream\Auth\SESSION_TIMEOUT', 1800); // 30 minutes in seconds
define('DocuStream\Auth\BASE_URL', 'http://localhost/DocuStream/public'); // Base URL for password reset links
define('DocuStream\Auth\FROM_EMAIL', 'no-reply@docustream.com'); // Sender email for password resets

class Auth
{
    private $usersCollection;
    private $loginAttemptsCollection;
    private $registerAttemptsCollection;
    private $maxLoginAttempts = 5;
    private $lockoutTime = 180; 

public function recordFailedLogin($email, $ip)
{
    try {
        $this->usersCollection->updateOne(
            ['email' => $email],
            [
                '$inc' => ['login_attempts' => 1],
                '$set' => [
                    'last_failed_login' => new \MongoDB\BSON\UTCDateTime(),
                    'last_failed_ip' => $ip
                ]
            ],
            ['upsert' => true]
        );
    } catch (\Exception $e) {
        error_log("Record failed login error: " . $e->getMessage());
    }
}

public function isLoginLockedOut($email, $ip)
{
    try {
        $user = $this->usersCollection->findOne(['email' => $email]);
        if ($user && isset($user['login_attempts']) && $user['login_attempts'] >= $this->maxLoginAttempts) {
            $lastFailed = $user['last_failed_login'] ?? null;
            if ($lastFailed instanceof \MongoDB\BSON\UTCDateTime) {
                $lastFailedTime = $lastFailed->toDateTime()->getTimestamp();
                if (time() - $lastFailedTime < $this->lockoutTime) {
                    return true;
                } else {
                    $this->clearLoginAttempts($email, $ip);
                }
            }
        }
        return false;
    } catch (\Exception $e) {
        error_log("Check lockout error: " . $e->getMessage());
        return false;
    }
}

public function clearLoginAttempts($email, $ip)
{
    try {
        // Reset in users collection
        $result = $this->usersCollection->updateOne(
            ['email' => $email],
            ['$set' => ['login_attempts' => 0, 'last_failed_login' => null]]
        );
        error_log("Cleared login attempts for email=$email in users collection: " . $result->getModifiedCount());

        // Clear in login_attempts collection
        $result = $this->loginAttemptsCollection->deleteMany([
            '$or' => [['email' => $email], ['ip' => $ip]]
        ]);
        error_log("Cleared login attempts for email=$email, ip=$ip in login_attempts collection: " . $result->getDeletedCount());
    } catch (\Exception $e) {
        error_log("Clear login attempts error: " . $e->getMessage());
    }
}


    public function __construct()
    {
        $mongo = new MongoDB();
        $this->usersCollection = $mongo->getCollection('users');
        $this->loginAttemptsCollection = $mongo->getCollection('login_attempts');
        $this->registerAttemptsCollection = $mongo->getCollection('register_attempts');
    }

    /**
     * Validate password against policy
     * @param string $password
     * @param array $userInfo
     * @return array [isValid, errors, strength, requirements]
     */
    private function validatePassword($password, $userInfo = [])
    {
        $minLength = 12;
        $maxLength = 128;
        $requireUppercase = true;
        $requireLowercase = true;
        $requireNumbers = true;
        $requireSpecialChars = true;
        $minUniqueChars = 8;
        $preventUserInfo = true;
        $checkCommonPasswords = true;

        $commonPasswords = [
            '123456', 'password', '123456789', '12345678', '12345',
            '1234567', '1234567890', 'qwerty', 'abc123', 'million2',
            '000000', '1234', 'iloveyou', 'aaron431', 'password1',
            'qqww1122', '123123', 'omgpop', '123321', '654321',
            'qwertyuiop', 'qwer1234', '123abc', 'a123456', 'welcome',
            'letmein', 'monkey', '1q2w3e4r', 'shadow', 'sunshine',
            'princess', 'dragon', 'passw0rd', 'master', 'hello',
            'freedom', 'whatever', 'qazwsx', 'trustno1', 'batman',
            'zaq1zaq1', 'password123', 'football', 'jesus', 'hunter',
            'mustang', 'maggie', 'starwars', 'klaster', 'cheese',
            'summer', 'michelle', 'biteme', '2000', 'jordan23',
            'andrea', 'ferrari', 'justice', 'gemini', 'yankees',
            'eagles', 'senior', 'alexandra', 'creative', 'hammer',
            'test', 'dallas', 'tennis', 'cookie', 'apple',
            'london', 'iceman', 'money', 'andrew', 'martin',
            'chicken', 'gateway', 'scorpio', 'dakota', 'tigers',
            'melissa', 'sophie', 'soccer', 'steelers', 'diamond',
            'admin', 'login', 'guest', 'root', 'user', 'test123'
        ];

        $errors = [];
        $requirements = [
            'length' => false,
            'uppercase' => false,
            'lowercase' => false,
            'number' => false,
            'special' => false,
            'unique' => false,
            'common' => false,
            'personal' => false
        ];

        // Check minimum length
        $requirements['length'] = strlen($password) >= $minLength;
        if (!$requirements['length']) {
            $errors[] = "Password must be at least $minLength characters long";
        }

        // Check maximum length
        if (strlen($password) > $maxLength) {
            $errors[] = "Password must be no more than $maxLength characters long";
        }

        // Check character requirements
        if ($requireUppercase) {
            $requirements['uppercase'] = preg_match('/[A-Z]/', $password);
            if (!$requirements['uppercase']) {
                $errors[] = "Password must contain at least one uppercase letter";
            }
        }

        if ($requireLowercase) {
            $requirements['lowercase'] = preg_match('/[a-z]/', $password);
            if (!$requirements['lowercase']) {
                $errors[] = "Password must contain at least one lowercase letter";
            }
        }

        if ($requireNumbers) {
            $requirements['number'] = preg_match('/[0-9]/', $password);
            if (!$requirements['number']) {
                $errors[] = "Password must contain at least one number";
            }
        }

        if ($requireSpecialChars) {
            $requirements['special'] = preg_match('/[!@#$%^&*()_+\-=\[\]{};\':"\\|,.<>\/?]/', $password);
            if (!$requirements['special']) {
                $errors[] = "Password must contain at least one special character";
            }
        }

        // Check unique characters
        $uniqueChars = count(array_unique(str_split($password)));
        $requirements['unique'] = $uniqueChars >= $minUniqueChars;
        if (!$requirements['unique']) {
            $errors[] = "Password must contain at least $minUniqueChars unique characters";
        }

        // Check against common passwords
        if ($checkCommonPasswords) {
            $requirements['common'] = !in_array(strtolower($password), $commonPasswords);
            if (!$requirements['common']) {
                $errors[] = "Password is too common. Please choose a more unique password";
            }
        }

        // Check against user information
        if ($preventUserInfo) {
            $requirements['personal'] = !$this->containsUserInfo($password, $userInfo);
            if (!$requirements['personal']) {
                $errors[] = "Password should not contain personal information";
            }
        }

        // Check for sequential characters
        if ($this->hasSequentialChars($password)) {
            $errors[] = "Password should not contain sequential characters (e.g., 123, abc)";
        }

        // Check for repeated patterns
        if ($this->hasRepeatedPatterns($password)) {
            $errors[] = "Password should not contain repeated patterns";
        }

        return [
            'isValid' => empty($errors),
            'errors' => $errors,
            'strength' => $this->calculatePasswordStrength($password),
            'requirements' => $requirements
        ];
    }

    private function containsUserInfo($password, $userInfo)
    {
        $lowerPassword = strtolower($password);
        $infoFields = ['username', 'email'];

        foreach ($infoFields as $field) {
            if (isset($userInfo[$field]) && !empty($userInfo[$field])) {
                $fieldValue = strtolower($userInfo[$field]);
                if (strpos($lowerPassword, $fieldValue) !== false) {
                    return true;
                }
                if ($field === 'email' && strpos($fieldValue, '@') !== false) {
                    $emailUsername = substr($fieldValue, 0, strpos($fieldValue, '@'));
                    if (strlen($emailUsername) > 2 && strpos($lowerPassword, $emailUsername) !== false) {
                        return true;
                    }
                }
            }
        }
        return false;
    }

    private function hasSequentialChars($password)
    {
        $sequences = [
            'abcdefghijklmnopqrstuvwxyz',
            '0123456789',
            'qwertyuiopasdfghjklzxcvbnm'
        ];

        $lowerPassword = strtolower($password);

        foreach ($sequences as $sequence) {
            for ($i = 0; $i <= strlen($sequence) - 3; $i++) {
                $substr = substr($sequence, $i, 3);
                if (strpos($lowerPassword, $substr) !== false || strpos($lowerPassword, strrev($substr)) !== false) {
                    return true;
                }
            }
        }
        return false;
    }

    private function hasRepeatedPatterns($password)
    {
        for ($len = 2; $len <= strlen($password) / 2; $len++) {
            for ($i = 0; $i <= strlen($password) - $len * 2; $i++) {
                $pattern = substr($password, $i, $len);
                $next = substr($password, $i + $len, $len);
                if ($pattern === $next) {
                    return true;
                }
            }
        }
        return false;
    }

    private function calculatePasswordStrength($password)
    {
        $score = 0;

        $score += min(strlen($password) * 2, 50);

        if (preg_match('/[a-z]/', $password)) $score += 5;
        if (preg_match('/[A-Z]/', $password)) $score += 5;
        if (preg_match('/[0-9]/', $password)) $score += 5;
        if (preg_match('/[^A-Za-z0-9]/', $password)) $score += 10;

        $uniqueChars = count(array_unique(str_split($password)));
        $score += $uniqueChars * 2;

        if ($this->hasSequentialChars($password)) $score -= 10;
        if ($this->hasRepeatedPatterns($password)) $score -= 10;

        $score = max(0, min(100, $score));

        if ($score >= 80) return 'Very Strong';
        if ($score >= 60) return 'Strong';
        if ($score >= 40) return 'Medium';
        if ($score >= 20) return 'Weak';
        return 'Very Weak';
    }

    /**
     * Check registration attempts for IP
     * @return array [bool, string|null]
     */
    private function checkRegisterAttempts($ip)
    {
        try {
            $now = time();
            $cutoff = new UTCDateTime(($now - REGISTER_LOCKOUT_DURATION) * 1000);

            $ipRecord = $this->registerAttemptsCollection->findOne([
                'ip' => $ip,
                'last_attempt' => ['$gte' => $cutoff]
            ]);

            if ($ipRecord && $ipRecord['attempt_count'] >= MAX_REGISTER_ATTEMPTS) {
                $remaining = ($ipRecord['last_attempt']->toDateTime()->getTimestamp() + REGISTER_LOCKOUT_DURATION - $now);
                return [false, "Too many registration attempts. Please try again in " . ceil($remaining / 60) . " minutes."];
            }

            return [true, null];
        } catch (\Exception $e) {
            error_log("Check register attempts error: " . $e->getMessage());
            return [false, "Registration attempt check failed."];
        }
    }

    /**
     * Record a registration attempt
     */
    private function recordRegisterAttempt($ip)
    {
        try {
            $now = new UTCDateTime();
            $cutoff = new UTCDateTime((time() - REGISTER_LOCKOUT_DURATION) * 1000);

            $this->registerAttemptsCollection->updateOne(
                [
                    'ip' => $ip,
                    'last_attempt' => ['$gte' => $cutoff]
                ],
                [
                    '$inc' => ['attempt_count' => 1],
                    '$set' => ['last_attempt' => $now],
                    '$setOnInsert' => ['created_at' => $now]
                ],
                ['upsert' => true]
            );

            $this->registerAttemptsCollection->deleteMany([
                'last_attempt' => ['$lt' => $cutoff]
            ]);
        } catch (\Exception $e) {
            error_log("Record register attempt error: " . $e->getMessage());
        }
    }

    /**
     * Register a new user
     * @return bool
     */
    public function register($username, $email, $password)
    {
        try {
            $username = filter_var($username, FILTER_SANITIZE_STRING);
            $email = filter_var($email, FILTER_SANITIZE_EMAIL);
            if (!$username || !$email || !$password) {
                $_SESSION['error'] = "Invalid input data.";
                return false;
            }

            $ip = $_SERVER['REMOTE_ADDR'];
            [$isAllowed, $errorMessage] = $this->checkRegisterAttempts($ip);
            if (!$isAllowed) {
                $_SESSION['error'] = $errorMessage;
                return false;
            }

            $passwordValidation = $this->validatePassword($password, [
                'username' => $username,
                'email' => $email
            ]);
            if (!$passwordValidation['isValid']) {
                $_SESSION['error'] = "Password does not meet requirements: " . implode(', ', $passwordValidation['errors']);
                $this->recordRegisterAttempt($ip);
                return false;
            }

            $existingUser = $this->usersCollection->findOne(['$or' => [
                ['email' => $email],
                ['username' => $username]
            ]]);
            if ($existingUser) {
                $_SESSION['error'] = "Username or email already exists.";
                $this->recordRegisterAttempt($ip);
                return false;
            }

            $result = $this->usersCollection->insertOne([
                'username' => $username,
                'email' => $email,
                'password' => password_hash($password, PASSWORD_ARGON2ID, [
                    'memory_cost' => 65536,
                    'time_cost' => 4,
                    'threads' => 3
                ]),
                'isAdmin' => false,
                'permissions' => VALID_PERMISSIONS,
                'created_at' => new UTCDateTime()
            ]);

            $this->registerAttemptsCollection->deleteMany(['ip' => $ip]);

            return $result->getInsertedCount() === 1;
        } catch (\Exception $e) {
            error_log("Registration error: " . $e->getMessage());
            $_SESSION['error'] = "Registration failed due to a server error.";
            $this->recordRegisterAttempt($_SERVER['REMOTE_ADDR']);
            return false;
        }
    }

    /**
     * Authenticate a user
     * @return bool
     */
public function login($email, $password)
{
    try {
        $email = filter_var($email, FILTER_SANITIZE_EMAIL);
        $ip = $_SERVER['REMOTE_ADDR'];
        $userAgent = $_SERVER['HTTP_USER_AGENT'] ?? 'Unknown';

        if ($this->isLoginLockedOut($email, $ip)) {
            $_SESSION['error'] = "Too many failed login attempts. Try again in 3 minutes.";
            $this->logLoginAttempt($email, $ip, $userAgent, false);
            return false;
        }

        $user = $this->usersCollection->findOne(['email' => $email]);
        if ($user && password_verify($password, $user['password'])) {
            session_regenerate_id(true);
            $_SESSION['user_id'] = (string) $user['_id'];
            $_SESSION['last_activity'] = time();
            $_SESSION['permissions'] = isset($user['permissions']) && is_array($user['permissions'])
                ? array_intersect($user['permissions'], VALID_PERMISSIONS)
                : VALID_PERMISSIONS;
            $this->clearLoginAttempts($email, $ip);
            $this->logLoginAttempt($email, $ip, $userAgent, true);
            return true;
        }

        $this->recordFailedLogin($email, $ip);
        $this->logLoginAttempt($email, $ip, $userAgent, false);
        $_SESSION['error'] = "Invalid email or password.";
        return false;
    } catch (\Exception $e) {
        error_log("Login error: " . $e->getMessage());
        $_SESSION['error'] = "Login failed due to a server error.";
        $this->logLoginAttempt($email, $ip, $userAgent, false);
        return false;
    }
}

private function logLoginAttempt($email, $ip, $userAgent, $success)
{
    try {
        $this->loginAttemptsCollection->insertOne([
            'email' => $email,
            'ip' => $ip,
            'user_agent' => $userAgent,
            'timestamp' => new \MongoDB\BSON\UTCDateTime(),
            'success' => $success
        ]);
    } catch (\Exception $e) {
        error_log("Log login attempt error: " . $e->getMessage());
    }
}


    /**
     * Log out the current user
     * @return bool
     */
    public function logout()
    {
        session_unset();
        session_destroy();
        session_start();
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
        return true;
    }

    /**
     * Get user by ID
     * @return array|null
     */
    public function getUserById($userId)
    {
        try {
            if (!preg_match('/^[a-f\d]{24}$/i', $userId)) {
                error_log("Invalid user ID: $userId");
                return null;
            }
            $user = $this->usersCollection->findOne(
                ['_id' => new ObjectId($userId)],
                ['typeMap' => ['root' => 'array', 'document' => 'array', 'array' => 'array']]
            );
            return $user;
        } catch (\Exception $e) {
            error_log("Get user error: " . $e->getMessage());
            return null;
        }
    }

    /**
     * Check if user has a specific permission
     * @return bool
     */
    public function hasPermission($permission)
    {
        if (!$this->isAuthenticated()) {
            return false;
        }
        $user = $this->getUserById($_SESSION['user_id']);
        if (!$user) {
            return false;
        }
        $permissions = isset($user['permissions']) && is_array($user['permissions'])
            ? $user['permissions']
            : [];
        return in_array($permission, VALID_PERMISSIONS) && in_array($permission, $permissions);
    }

    /**
     * Check if user is an admin
     * @return bool
     */
    public function isAdmin()
    {
        if (!$this->isAuthenticated()) {
            return false;
        }
        $user = $this->usersCollection->findOne(['_id' => new ObjectId($_SESSION['user_id'])]);
        return $user && !empty($user['isAdmin']) && $user['isAdmin'] === true;
    }

    /**
     * Update user details
     * @return bool
     */
    public function manageUser($userId, $updates, $currentUserId)
    {
        try {
            if (!preg_match('/^[a-f\d]{24}$/i', $userId)) {
                return false;
            }
            if ($userId === $currentUserId && isset($updates['isAdmin']) && !$updates['isAdmin']) {
                return false;
            }
            $updateData = [];
            if (isset($updates['username'])) {
                $updateData['username'] = filter_var($updates['username'], FILTER_SANITIZE_STRING);
            }
            if (isset($updates['email'])) {
                $updateData['email'] = filter_var($updates['email'], FILTER_SANITIZE_EMAIL);
            }
            if (isset($updates['password']) && !empty($updates['password'])) {
                $passwordValidation = $this->validatePassword($updates['password'], [
                    'username' => $updates['username'] ?? '',
                    'email' => $updates['email'] ?? ''
                ]);
                if (!$passwordValidation['isValid']) {
                    $_SESSION['error'] = "Password does not meet requirements: " . implode(', ', $passwordValidation['errors']);
                    return false;
                }
                $updateData['password'] = password_hash($updates['password'], PASSWORD_ARGON2ID, [
                    'memory_cost' => 65536,
                    'time_cost' => 4,
                    'threads' => 3
                ]);
            }
            if (isset($updates['isAdmin'])) {
                $updateData['isAdmin'] = filter_var($updates['isAdmin'], FILTER_VALIDATE_BOOLEAN);
            }
            if (isset($updates['permissions'])) {
                $updateData['permissions'] = is_array($updates['permissions'])
                    ? array_intersect($updates['permissions'], VALID_PERMISSIONS)
                    : [];
            }
            if (empty($updateData)) {
                return true;
            }
            $result = $this->usersCollection->updateOne(
                ['_id' => new ObjectId($userId)],
                ['$set' => $updateData]
            );
            if ($userId === $currentUserId && isset($updateData['permissions'])) {
                $_SESSION['permissions'] = $updateData['permissions'];
            }
            return $result->getModifiedCount() === 1 || $result->getMatchedCount() === 1;
        } catch (\Exception $e) {
            error_log("Manage user error: " . $e->getMessage());
            return false;
        }
    }

    /**
     * Initiate password reset
     * @return bool
     */
    public function initiatePasswordReset($email)
    {
        try {
            $email = filter_var($email, FILTER_SANITIZE_EMAIL);
            $user = $this->usersCollection->findOne(['email' => $email]);
            if (!$user) {
                return false;
            }
            $token = bin2hex(random_bytes(32));
            $this->usersCollection->updateOne(
                ['_id' => $user['_id']],
                ['$set' => [
                    'reset_token' => $token,
                    'reset_expiry' => new UTCDateTime((time() + 3600) * 1000)
                ]]
            );
            $resetLink = BASE_URL . "?action=reset_password&token=$token";
            $subject = "DocuStream Password Reset";
            $message = "Click here to reset your password: $resetLink\nThis link expires in 1 hour.";
            $headers = "From: " . FROM_EMAIL . "\r\nContent-Type: text/plain; charset=UTF-8";
            return mail($email, $subject, $message, $headers);
        } catch (\Exception $e) {
            error_log("Password reset error: " . $e->getMessage());
            return false;
        }
    }

    /**
     * Reset password with token
     * @return bool
     */
    public function resetPassword($token, $newPassword)
    {
        try {
            $token = filter_var($token, FILTER_SANITIZE_STRING);
            $user = $this->usersCollection->findOne([
                'reset_token' => $token,
                'reset_expiry' => ['$gte' => new UTCDateTime()]
            ]);
            if (!$user) {
                return false;
            }
            $passwordValidation = $this->validatePassword($newPassword, [
                'email' => $user['email']
            ]);
            if (!$passwordValidation['isValid']) {
                $_SESSION['error'] = "Password does not meet requirements: " . implode(', ', $passwordValidation['errors']);
                return false;
            }
            $result = $this->usersCollection->updateOne(
                ['_id' => $user['_id']],
                [
                    '$set' => [
                        'password' => password_hash($newPassword, PASSWORD_ARGON2ID, [
                            'memory_cost' => 65536,
                            'time_cost' => 4,
                            'threads' => 3
                        ])
                    ],
                    '$unset' => ['reset_token' => '', 'reset_expiry' => '']
                ]
            );
            return $result->getModifiedCount() === 1;
        } catch (\Exception $e) {
            error_log("Reset password error: " . $e->getMessage());
            return false;
        }
    }

    /**
     * Get all users
     * @return array
     */
    public function getUsers()
    {
        return iterator_to_array(
            $this->usersCollection->find(
                [],
                ['typeMap' => ['root' => 'array', 'document' => 'array', 'array' => 'array']]
            )
        );
    }

    /**
     * Check if user is authenticated
     * @return bool
     */
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

    /**
     * Validate CSRF token
     * @return bool
     */
    public function validateCsrfToken($token)
    {
        return isset($_SESSION['csrf_token']) && hash_equals($_SESSION['csrf_token'], $token);
    }

    /**
     * Check login attempts for IP and email
     * @return array [bool, string|null]
     */
    private function checkLoginAttempts($ip, $email)
    {
        try {
            $now = time();
            $cutoff = new UTCDateTime(($now - LOGIN_LOCKOUT_DURATION) * 1000);

            $ipRecord = $this->loginAttemptsCollection->findOne([
                'ip' => $ip,
                'last_attempt' => ['$gte' => $cutoff]
            ]);

            if ($ipRecord && $ipRecord['attempt_count'] >= MAX_LOGIN_ATTEMPTS) {
                $remaining = ($ipRecord['last_attempt']->toDateTime()->getTimestamp() + LOGIN_LOCKOUT_DURATION - $now);
                return [false, "Too many login attempts from this IP. Try again in " . ceil($remaining / 60) . " minutes."];
            }

            $emailRecord = $this->loginAttemptsCollection->findOne([
                'email' => $email,
                'last_attempt' => ['$gte' => $cutoff]
            ]);

            if ($emailRecord && $emailRecord['attempt_count'] >= MAX_LOGIN_ATTEMPTS) {
                $remaining = ($emailRecord['last_attempt']->toDateTime()->getTimestamp() + LOGIN_LOCKOUT_DURATION - $now);
                return [false, "Too many login attempts for this email. Try again in " . ceil($remaining / 60) . " minutes."];
            }

            return [true, null];
        } catch (\Exception $e) {
            error_log("Check login attempts error: " . $e->getMessage());
            return [false, "Login attempt check failed."];
        }
    }

    /**
     * Record a login attempt
     */
    private function recordLoginAttempt($ip, $email)
    {
        try {
            $now = new UTCDateTime();
            $cutoff = new UTCDateTime((time() - LOGIN_LOCKOUT_DURATION) * 1000);

            // Update or insert IP-based attempt
            $this->loginAttemptsCollection->updateOne(
                [
                    'ip' => $ip,
                    'last_attempt' => ['$gte' => $cutoff]
                ],
                [
                    '$inc' => ['attempt_count' => 1],
                    '$set' => ['last_attempt' => $now, 'email' => $email],
                    '$setOnInsert' => ['created_at' => $now]
                ],
                ['upsert' => true]
            );

            // Update or insert email-based attempt
            $this->loginAttemptsCollection->updateOne(
                [
                    'email' => $email,
                    'last_attempt' => ['$gte' => $cutoff]
                ],
                [
                    '$inc' => ['attempt_count' => 1],
                    '$set' => ['last_attempt' => $now, 'ip' => $ip],
                    '$setOnInsert' => ['created_at' => $now]
                ],
                ['upsert' => true]
            );

            // Cleanup old attempts
            $this->loginAttemptsCollection->deleteMany([
                'last_attempt' => ['$lt' => $cutoff]
            ]);
        } catch (\Exception $e) {
            error_log("Record login attempt error: " . $e->getMessage());
        }
    }
}