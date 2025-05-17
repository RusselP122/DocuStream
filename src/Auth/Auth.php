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
            $username = filter_var($username, FILTER_SANITIZE_STRING);
            $email = filter_var($email, FILTER_SANITIZE_EMAIL);
            if (!$username || !$email || !$password) {
                return false;
            }

            $existingUser = $this->usersCollection->findOne(['email' => $email]);
            if ($existingUser) {
                return false;
            }

            $result = $this->usersCollection->insertOne([
                'username' => $username,
                'email' => $email,
                'password' => password_hash($password, PASSWORD_DEFAULT),
                'isAdmin' => false,
                'permissions' => VALID_PERMISSIONS,
                'created_at' => new \MongoDB\BSON\UTCDateTime()
            ]);
            return $result->getInsertedCount() === 1;
        } catch (\Exception $e) {
            error_log("Registration error: " . $e->getMessage());
            return false;
        }
    }

public function login($email, $password)
{
    try {
        $email = filter_var($email, FILTER_SANITIZE_EMAIL);
        $user = $this->usersCollection->findOne(['email' => $email]);
        if ($user && password_verify($password, $user['password'])) {
            session_regenerate_id(true);
            $_SESSION['user_id'] = (string) $user['_id'];
            $_SESSION['last_activity'] = time();
            $_SESSION['permissions'] = isset($user['permissions']) && is_array($user['permissions'])
                ? array_intersect($user['permissions'], VALID_PERMISSIONS)
                : VALID_PERMISSIONS;
            error_log("Login successful. user_id: {$_SESSION['user_id']}, Session: " . print_r($_SESSION, true));
            return true;
        }
        error_log("Login failed for email: $email");
        return false;
    } catch (\Exception $e) {
        error_log("Login error: " . $e->getMessage());
        return false;
    }
}
    public function logout()
    {
        session_unset();
        session_destroy();
        session_start(); // Restart session for new CSRF token
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
        return true;
    }

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
    // Convert BSONArray to PHP array if necessary
    $permissions = isset($user['permissions']) && $user['permissions'] instanceof \MongoDB\Model\BSONArray
        ? (array) $user['permissions']
        : (is_array($user['permissions']) ? $user['permissions'] : []);
    // Validate permission against VALID_PERMISSIONS
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

    public function manageUser($userId, $updates, $currentUserId)
    {
        try {
            if (!preg_match('/^[a-f\d]{24}$/i', $userId)) {
                return false;
            }

            // Prevent self-editing admin status
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
                $updateData['password'] = password_hash($updates['password'], PASSWORD_DEFAULT);
            }
            if (isset($updates['isAdmin'])) {
                $updateData['isAdmin'] = filter_var($updates['isAdmin'], FILTER_VALIDATE_BOOLEAN);
            }

            // Validate and sanitize permissions
            if (isset($updates['permissions'])) {
                $updateData['permissions'] = is_array($updates['permissions'])
                    ? array_intersect($updates['permissions'], VALID_PERMISSIONS)
                    : [];
            } else {
                $updateData['permissions'] = []; // Explicitly set to empty if no permissions selected
            }

            if (empty($updateData)) {
                return true; // No changes to apply
            }

            $result = $this->usersCollection->updateOne(
                ['_id' => new ObjectId($userId)],
                ['$set' => $updateData]
            );

            // Update session permissions if current user
            if ($userId === $currentUserId && isset($updateData['permissions'])) {
                $_SESSION['permissions'] = $updateData['permissions'];
            }

            return $result->getModifiedCount() === 1 || $result->getMatchedCount() === 1;
        } catch (\Exception $e) {
            error_log("Manage user error: " . $e->getMessage());
            return false;
        }
    }

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
                    'reset_expiry' => new \MongoDB\BSON\UTCDateTime((time() + 3600) * 1000)
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

    public function resetPassword($token, $newPassword)
    {
        try {
            $token = filter_var($token, FILTER_SANITIZE_STRING);
            $user = $this->usersCollection->findOne([
                'reset_token' => $token,
                'reset_expiry' => ['$gte' => new \MongoDB\BSON\UTCDateTime()]
            ]);
            if (!$user) {
                return false;
            }
            $result = $this->usersCollection->updateOne(
                ['_id' => $user['_id']],
                ['$set' => ['password' => password_hash($newPassword, PASSWORD_DEFAULT)],
                 '$unset' => ['reset_token' => '', 'reset_expiry' => '']]
            );
            return $result->getModifiedCount() === 1;
        } catch (\Exception $e) {
            error_log("Reset password error: " . $e->getMessage());
            return false;
        }
    }

public function getUsers() {
    return iterator_to_array(
        $this->usersCollection->find(
            [],
            ['typeMap' => ['root' => 'array', 'document' => 'array', 'array' => 'array']]
        )
    );
}


    public function isAuthenticated()
    {
        try {
            if (!isset($_SESSION['user_id']) || !isset($_SESSION['last_activity'])) {
                return false;
            }
            // Check session timeout
            if (time() - $_SESSION['last_activity'] > SESSION_TIMEOUT) {
                $this->logout();
                return false;
            }
            $user = $this->getUserById($_SESSION['user_id']);
            if (!$user) {
                $this->logout();
                return false;
            }
            $_SESSION['last_activity'] = time(); // Update last activity
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
}