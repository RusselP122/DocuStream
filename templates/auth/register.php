<?php
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

// Generate CSRF token if not set
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

// Password Policy Configuration
class PasswordPolicy {
    const MIN_LENGTH = 12;
    const MAX_LENGTH = 128;
    const REQUIRE_UPPERCASE = true;
    const REQUIRE_LOWERCASE = true;
    const REQUIRE_NUMBERS = true;
    const REQUIRE_SPECIAL_CHARS = true;
    const MIN_UNIQUE_CHARS = 8;
    const PREVENT_USER_INFO = true;
    const CHECK_COMMON_PASSWORDS = true;
    
    // Top 100 most common passwords (abbreviated for space)
    private static $commonPasswords = [
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
    
    public static function validatePassword($password, $userInfo = []) {
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
        $requirements['length'] = strlen($password) >= self::MIN_LENGTH;
        if (!$requirements['length']) {
            $errors[] = "Password must be at least " . self::MIN_LENGTH . " characters long";
        }
        
        // Check maximum length
        if (strlen($password) > self::MAX_LENGTH) {
            $errors[] = "Password must be no more than " . self::MAX_LENGTH . " characters long";
        }
        
        // Check character requirements
        if (self::REQUIRE_UPPERCASE) {
            $requirements['uppercase'] = preg_match('/[A-Z]/', $password);
            if (!$requirements['uppercase']) {
                $errors[] = "Password must contain at least one uppercase letter";
            }
        }
        
        if (self::REQUIRE_LOWERCASE) {
            $requirements['lowercase'] = preg_match('/[a-z]/', $password);
            if (!$requirements['lowercase']) {
                $errors[] = "Password must contain at least one lowercase letter";
            }
        }
        
        if (self::REQUIRE_NUMBERS) {
            $requirements['number'] = preg_match('/[0-9]/', $password);
            if (!$requirements['number']) {
                $errors[] = "Password must contain at least one number";
            }
        }
        
        if (self::REQUIRE_SPECIAL_CHARS) {
            $requirements['special'] = preg_match('/[!@#$%^&*()_+\-=\[\]{};\':"\\|,.<>\/?]/', $password);
            if (!$requirements['special']) {
                $errors[] = "Password must contain at least one special character";
            }
        }
        
        // Check unique characters
        $uniqueChars = count(array_unique(str_split($password)));
        $requirements['unique'] = $uniqueChars >= self::MIN_UNIQUE_CHARS;
        if (!$requirements['unique']) {
            $errors[] = "Password must contain at least " . self::MIN_UNIQUE_CHARS . " unique characters";
        }
        
        // Check against common passwords
        if (self::CHECK_COMMON_PASSWORDS) {
            $requirements['common'] = !in_array(strtolower($password), self::$commonPasswords);
            if (!$requirements['common']) {
                $errors[] = "Password is too common. Please choose a more unique password";
            }
        }
        
        // Check against user information
        if (self::PREVENT_USER_INFO) {
            $requirements['personal'] = !self::containsUserInfo($password, $userInfo);
            if (!$requirements['personal']) {
                $errors[] = "Password should not contain personal information";
            }
        }
        
        // Check for sequential characters
        if (self::hasSequentialChars($password)) {
            $errors[] = "Password should not contain sequential characters (e.g., 123, abc)";
        }
        
        // Check for repeated patterns
        if (self::hasRepeatedPatterns($password)) {
            $errors[] = "Password should not contain repeated patterns";
        }
        
        return [
            'isValid' => empty($errors),
            'errors' => $errors,
            'strength' => self::calculateStrength($password),
            'requirements' => $requirements
        ];
    }
    
    private static function containsUserInfo($password, $userInfo) {
        $lowerPassword = strtolower($password);
        $infoFields = ['username', 'email'];
        
        foreach ($infoFields as $field) {
            if (isset($userInfo[$field]) && !empty($userInfo[$field])) {
                $fieldValue = strtolower($userInfo[$field]);
                if (strpos($lowerPassword, $fieldValue) !== false) {
                    return true;
                }
                // Also check email username part
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
    
    private static function hasSequentialChars($password) {
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
    
    private static function hasRepeatedPatterns($password) {
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
    
    private static function calculateStrength($password) {
        $score = 0;
        
        // Length bonus
        $score += min(strlen($password) * 2, 50);
        
        // Character variety bonus
        if (preg_match('/[a-z]/', $password)) $score += 5;
        if (preg_match('/[A-Z]/', $password)) $score += 5;
        if (preg_match('/[0-9]/', $password)) $score += 5;
        if (preg_match('/[^A-Za-z0-9]/', $password)) $score += 10;
        
        // Unique characters bonus
        $uniqueChars = count(array_unique(str_split($password)));
        $score += $uniqueChars * 2;
        
        // Penalty for common patterns
        if (self::hasSequentialChars($password)) $score -= 10;
        if (self::hasRepeatedPatterns($password)) $score -= 10;
        if (in_array(strtolower($password), self::$commonPasswords)) $score -= 20;
        
        // Normalize to 0-100 scale
        $score = max(0, min(100, $score));
        
        if ($score >= 80) return 'Very Strong';
        if ($score >= 60) return 'Strong';
        if ($score >= 40) return 'Medium';
        if ($score >= 20) return 'Weak';
        return 'Very Weak';
    }
}

// Handle form submission
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_GET['action']) && $_GET['action'] === 'register') {
    // Verify CSRF token
    if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
        $error = "Invalid request. Please try again.";
    } else {
        $username = trim($_POST['username'] ?? '');
        $email = trim($_POST['email'] ?? '');
        $password = $_POST['password'] ?? '';
        
        // Basic validation
        if (empty($username) || empty($email) || empty($password)) {
            $error = "All fields are required.";
        } elseif (strlen($username) > 50) {
            $error = "Username must be 50 characters or less.";
        } elseif (strlen($email) > 100) {
            $error = "Email must be 100 characters or less.";
        } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            $error = "Please enter a valid email address.";
        } else {
            // Validate password policy
            $passwordValidation = PasswordPolicy::validatePassword($password, [
                'username' => $username,
                'email' => $email
            ]);
            
            if (!$passwordValidation['isValid']) {
                $error = "Password does not meet security requirements: " . implode(', ', $passwordValidation['errors']);
                $passwordErrors = $passwordValidation['errors'];
                $passwordRequirements = $passwordValidation['requirements'];
            } else {
                // Hash password securely
                $hashedPassword = password_hash($password, PASSWORD_ARGON2ID, [
                    'memory_cost' => 65536, // 64 MB
                    'time_cost' => 4,       // 4 iterations
                    'threads' => 3          // 3 threads
                ]);
                
                // Here you would typically save to database
                // Example database insertion (uncomment and modify as needed):
                /*
                try {
                    $pdo = new PDO("mysql:host=localhost;dbname=docustream", $username, $password);
                    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
                    
                    $stmt = $pdo->prepare("INSERT INTO users (username, email, password_hash, created_at) VALUES (?, ?, ?, NOW())");
                    $stmt->execute([$username, $email, $hashedPassword]);
                    
                    $_SESSION['message'] = "Registration successful! You can now log in.";
                    header("Location: ?action=login");
                    exit;
                } catch (PDOException $e) {
                    if ($e->getCode() == 23000) { // Duplicate entry
                        $error = "Username or email already exists.";
                    } else {
                        $error = "Registration failed. Please try again.";
                    }
                }
                */
                
                // For demo purposes, just show success
                $_SESSION['message'] = "Registration successful! Password meets all security requirements.";
                
                // Clear form data
                $username = $email = $password = '';
            }
        }
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>DocuStream - Register</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <style>
        .password-meter {
            transition: all 0.3s ease;
        }
        .password-meter.very-weak { background-color: #ef4444; color: white; }
        .password-meter.weak { background-color: #f59e0b; color: white; }
        .password-meter.medium { background-color: #eab308; color: #1f2937; }
        .password-meter.strong { background-color: #10b981; color: white; }
        .password-meter.very-strong { background-color: #059669; color: white; }
        
        .requirement-met { color: #10b981; }
        .requirement-unmet { color: #6b7280; }
        
        .error-item {
            animation: slideIn 0.3s ease-out;
        }
        
        @keyframes slideIn {
            from { opacity: 0; transform: translateY(-10px); }
            to { opacity: 1; transform: translateY(0); }
        }
    </style>
</head>
<body class="bg-gray-100 min-h-screen flex items-center justify-center">
    <div class="w-full max-w-6xl mx-auto grid grid-cols-1 lg:grid-cols-2 gap-8 p-6">
        <!-- Left Side: Form -->
        <div class="bg-white p-8 rounded-xl shadow-lg max-w-md w-full mx-auto lg:mx-0">
            <!-- Branding -->
            <div class="text-center mb-6">
                <h1 class="text-3xl font-bold text-gray-900">DocuStream</h1>
                <p class="mt-2 text-sm text-gray-600">Secure Document Management</p>
            </div>

            <!-- Success Message -->
            <?php if (isset($_SESSION['message'])): ?>
                <div class="mb-6 p-4 bg-green-50 text-green-700 rounded-lg flex items-center" role="alert" aria-live="assertive">
                    <svg class="w-5 h-5 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"></path>
                    </svg>
                    <span><?php echo htmlspecialchars($_SESSION['message'], ENT_QUOTES, 'UTF-8'); ?></span>
                </div>
                <?php unset($_SESSION['message']); ?>
            <?php endif; ?>

            <!-- Error Message -->
            <?php if (isset($error)): ?>
                <div class="mb-6 p-4 bg-red-50 text-red-700 rounded-lg flex items-center" role="alert" aria-live="assertive">
                    <svg class="w-5 h-5 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"></path>
                    </svg>
                    <span><?php echo htmlspecialchars($error, ENT_QUOTES, 'UTF-8'); ?></span>
                </div>
            <?php endif; ?>

            <!-- Registration Form -->
            <form method="POST" action="?action=register" class="space-y-6" aria-label="Registration form">
                <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token'], ENT_QUOTES, 'UTF-8'); ?>">
                
                <div>
                    <label for="username" class="block text-sm font-semibold text-gray-700">Username</label>
                    <div class="relative">
                        <input 
                            type="text" 
                            id="username" 
                            name="username" 
                            value="<?php echo htmlspecialchars($username ?? '', ENT_QUOTES, 'UTF-8'); ?>"
                            class="mt-1 block w-full p-3 pl-10 border border-gray-300 rounded-lg focus:ring-blue-500 focus:border-blue-500 focus:outline-none transition-colors" 
                            placeholder="Enter your username" 
                            required 
                            aria-required="true" 
                            maxlength="50"
                        >
                        <svg class="absolute left-3 top-1/2 transform -translate-y-1/2 w-5 h-5 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z"></path>
                        </svg>
                    </div>
                </div>
                
                <div>
                    <label for="email" class="block text-sm font-semibold text-gray-700">Email</label>
                    <div class="relative">
                        <input 
                            type="email" 
                            id="email" 
                            name="email" 
                            value="<?php echo htmlspecialchars($email ?? '', ENT_QUOTES, 'UTF-8'); ?>"
                            class="mt-1 block w-full p-3 pl-10 border border-gray-300 rounded-lg focus:ring-blue-500 focus:border-blue-500 focus:outline-none transition-colors" 
                            placeholder="Enter your email" 
                            required 
                            aria-required="true" 
                            maxlength="100"
                        >
                        <svg class="absolute left-3 top-1/2 transform -translate-y-1/2 w-5 h-5 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M16 12a4 4 0 10-8 0 4 4 0 008 0zm0 0v1.5a2.5 2.5 0 005 0V12a9 9 0 10-9 9m4.5-1.206a8.959 8.959 0 01-4.5 1.207"></path>
                        </svg>
                    </div>
                </div>
                
                <div>
                    <label for="password" class="block text-sm font-semibold text-gray-700">Password</label>
                    <div class="relative">
                        <input 
                            type="password" 
                            id="password" 
                            name="password" 
                            class="mt-1 block w-full p-3 pl-10 pr-10 border border-gray-300 rounded-lg focus:ring-blue-500 focus:border-blue-500 focus:outline-none transition-colors" 
                            placeholder="Enter a strong password (12+ characters)" 
                            required 
                            aria-required="true" 
                            minlength="12"
                        >
                        <svg class="absolute left-3 top-1/2 transform -translate-y-1/2 w-5 h-5 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"></path>
                        </svg>
                        <button type="button" id="togglePassword" class="absolute right-3 top-1/2 transform -translate-y-1/2 text-gray-400 hover:text-gray-600">
                            <svg id="eyeIcon" class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"></path>
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z"></path>
                            </svg>
                        </button>
                    </div>
                    
                    <!-- Password Strength Meter -->
                    <div id="passwordMeter" class="mt-2 p-2 rounded text-center text-sm font-medium password-meter" style="display: none;">
                        Strength: Not evaluated
                    </div>
                    
                    <!-- Password Requirements -->
                    <div class="mt-3 p-3 bg-gray-50 rounded-lg">
                        <h4 class="text-sm font-medium text-gray-700 mb-2">Password Requirements:</h4>
                        <div class="space-y-1 text-xs">
                            <div class="flex items-center requirement-unmet" id="req-length">
                                <span class="mr-2">•</span>
                                <span>At least 12 characters long</span>
                            </div>
                            <div class="flex items-center requirement-unmet" id="req-uppercase">
                                <span class="mr-2">•</span>
                                <span>Contains uppercase letter (A-Z)</span>
                            </div>
                            <div class="flex items-center requirement-unmet" id="req-lowercase">
                                <span class="mr-2">•</span>
                                <span>Contains lowercase letter (a-z)</span>
                            </div>
                            <div class="flex items-center requirement-unmet" id="req-number">
                                <span class="mr-2">•</span>
                                <span>Contains number (0-9)</span>
                            </div>
                            <div class="flex items-center requirement-unmet" id="req-special">
                                <span class="mr-2">•</span>
                                <span>Contains special character (!@#$%^&*)</span>
                            </div>
                            <div class="flex items-center requirement-unmet" id="req-unique">
                                <span class="mr-2">•</span>
                                <span>At least 8 unique characters</span>
                            </div>
                            <div class="flex items-center requirement-unmet" id="req-common">
                                <span class="mr-2">•</span>
                                <span>Not a common password</span>
                            </div>
                            <div class="flex items-center requirement-unmet" id="req-personal">
                                <span class="mr-2">•</span>
                                <span>Doesn't contain personal info</span>
                            </div>
                        </div>
                    </div>
                    
                    <!-- Password Errors -->
                    <div id="passwordErrors" class="mt-2"></div>
                </div>
                
                <div class="flex justify-end">
                    <button 
                        type="submit" 
                        id="submitBtn"
                        class="px-6 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 focus:ring-2 focus:ring-blue-500 focus:ring-offset-2 transition-colors disabled:bg-gray-400 disabled:cursor-not-allowed"
                    >
                        Register
                    </button>
                </div>
            </form>
            
            <p class="mt-6 text-center text-sm text-gray-600">
                Already have an account? 
                <a href="?action=login" class="text-blue-700 hover:text-blue-900 font-medium" aria-label="Login to your account">Login</a>
            </p>
        </div>

        <!-- Right Side: Decorative Element (Visible on Large Screens) -->
        <div class="hidden lg:block bg-gradient-to-br from-blue-500 to-blue-700 rounded-xl p-8 text-white">
            <div class="max-w-md mx-auto">
                <h2 class="text-2xl font-bold mb-4">Join DocuStream</h2>
                <p class="text-sm mb-6">
                    Create an account to manage your documents securely and streamline your workflow with our advanced document management system.
                </p>
                
                <!-- Security Features -->
                <div class="bg-blue-600 bg-opacity-50 rounded-lg p-4 mb-6">
                    <h3 class="font-semibold mb-3 flex items-center">
                        <svg class="w-5 h-5 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"></path>
                        </svg>
                        Security Features
                    </h3>
                    <ul class="space-y-2 text-sm opacity-90">
                        <li class="flex items-center">
                            <span class="w-2 h-2 bg-green-300 rounded-full mr-3"></span>
                            Strong password enforcement
                        </li>
                        <li class="flex items-center">
                            <span class="w-2 h-2 bg-green-300 rounded-full mr-3"></span>
                            Advanced encryption
                        </li>
                        <li class="flex items-center">
                            <span class="w-2 h-2 bg-green-300 rounded-full mr-3"></span>
                            Secure document storage
                        </li>
                        <li class="flex items-center">
                            <span class="w-2 h-2 bg-green-300 rounded-full mr-3"></span>
                            CSRF protection
                        </li>
                    </ul>
                </div>
                
                <!-- Placeholder for illustration -->
                <div class="flex justify-center">
                    <svg class="w-32 h-32 opacity-75" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"></path>
                    </svg>
                </div>
            </div>
        </div>
    </div>

    <script>
        // Password validation JavaScript
        const PASSWORD_POLICY = {
            MIN_LENGTH: 12,
            REQUIRE_UPPERCASE: true,
            REQUIRE_LOWERCASE: true,
            REQUIRE_NUMBERS: true,
            REQUIRE_SPECIAL_CHARS: true,
            MIN_UNIQUE_CHARS: 8,
            CHECK_COMMON_PASSWORDS: true
        };

        const COMMON_PASSWORDS = new Set([
            '123456', 'password', '123456789', '12345678', '12345',
            'qwerty', 'abc123', 'password1', 'admin', 'letmein',
            'welcome', 'monkey', '1234567890', 'dragon', 'master',
            'hello', 'freedom', 'whatever', 'login', 'passw0rd'
        ]);

        class PasswordValidator {
            validatePassword(password, userInfo = {}) {
                const errors = [];
                const requirements = {
                    length: false,
                    uppercase: false,
                    lowercase: false,
                    number: false,
                    special: false,
                    unique: false,
                    common: false,
                    personal: false
                };
                
                // Check requirements
                requirements.length = password.length >= PASSWORD_POLICY.MIN_LENGTH;
                requirements.uppercase = /[A-Z]/.test(password);
                requirements.lowercase = /[a-z]/.test(password);
                requirements.number = /[0-9]/.test(password);
                requirements.special = /[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password);
                
                const uniqueChars = new Set(password).size;
                requirements.unique = uniqueChars >= PASSWORD_POLICY.MIN_UNIQUE_CHARS;
                requirements.common = !COMMON_PASSWORDS.has(password.toLowerCase());
                requirements.personal = !this.containsUserInfo(password, userInfo);
                
                // Add errors for failed requirements
                if (!requirements.length) errors.push(`Password must be at least ${PASSWORD_POLICY.MIN_LENGTH} characters long`);
                if (!requirements.uppercase) errors.push('Password must contain at least one uppercase letter');
                if (!requirements.lowercase) errors.push('Password must contain at least one lowercase letter');
                if (!requirements.number) errors.push('Password must contain at least one number');
                if (!requirements.special) errors.push('Password must contain at least one special character');
                if (!requirements.unique) errors.push(`Password must contain at least ${PASSWORD_POLICY.MIN_UNIQUE_CHARS} unique characters`);
                if (!requirements.common) errors.push('Password is too common. Please choose a more unique password');
                if (!requirements.personal) errors.push('Password should not contain personal information');
                
                return {
                    isValid: errors.length === 0,
                    errors: errors,
                    strength: this.calculateStrength(password),
                    requirements: requirements
                };
            }
            
            containsUserInfo(password, userInfo) {
                const lowerPassword = password.toLowerCase();
                const infoFields = ['username', 'email'];
                
                for (const field of infoFields) {
                    if (userInfo[field] && userInfo[field].length > 2) {
                        const fieldValue = userInfo[field].toLowerCase();
                        if (lowerPassword.includes(fieldValue)) {
                            return true;
                        }
                        // Check email username part
                        if (field === 'email' && fieldValue.includes('@')) {
                            const emailUsername = fieldValue.split('@')[0];
                            if (emailUsername.length > 2 && lowerPassword.includes(emailUsername)) {
                                return true;
                            }
                        }
                    }
                }
                return false;
            }
            
            calculateStrength(password) {
                let score = 0;
                
                // Length bonus
                score += Math.min(password.length * 2, 50);
                
                // Character variety bonus
                if (/[a-z]/.test(password)) score += 5;
                if (/[A-Z]/.test(password)) score += 5;
                if (/[0-9]/.test(password)) score += 5;
                if (/[^A-Za-z0-9]/.test(password)) score += 10;
                
                // Unique characters bonus
                const uniqueChars = new Set(password).size;
                score += uniqueChars * 2;
                
                // Penalty for common passwords
                if (COMMON_PASSWORDS.has(password.toLowerCase())) score -= 20;
                
                // Normalize to 0-100 scale
                score = Math.max(0, Math.min(100, score));
                
                if (score >= 80) return 'Very Strong';
                if (score >= 60) return 'Strong';
                if (score >= 40) return 'Medium';
                if (score >= 20) return 'Weak';
                return 'Very Weak';
            }
        }

        // Initialize components
        const validator = new PasswordValidator();
        const passwordInput = document.getElementById('password');
        const usernameInput = document.getElementById('username');
        const emailInput = document.getElementById('email');
        const meterElement = document.getElementById('passwordMeter');
        const errorsElement = document.getElementById('passwordErrors');
        const submitBtn = document.getElementById('submitBtn');
        const togglePasswordBtn = document.getElementById('togglePassword');

        // Password visibility toggle
        togglePasswordBtn.addEventListener('click', function() {
            const type = passwordInput.getAttribute('type') === 'password' ? 'text' : 'password';
            passwordInput.setAttribute('type', type);
            
            const eyeIcon = document.getElementById('eyeIcon');
            if (type === 'text') {
                eyeIcon.innerHTML = `
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13.875 18.825A10.05 10.05 0 0112 19c-4.478 0-8.268-2.943-9.542-7a9.97 9.97 0 011.563-3.029m5.858.908a3 3 0 114.243 4.243M9.878 9.878l4.242 4.242M9.878 9.878L3 3m6.878 6.878L21 21"></path>
                `;
            } else {
                eyeIcon.innerHTML = `
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"></path>
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z"></path>
                `;
            }
        });

        // Update password validation
        function updatePasswordValidation() {
            const password = passwordInput.value;
            const userInfo = {
                username: usernameInput.value,
                email: emailInput.value
            };
            
            if (password) {
                meterElement.style.display = 'block';
                const validation = validator.validatePassword(password, userInfo);
                
                // Update strength meter
                const strength = validation.strength;
                const strengthClass = strength.toLowerCase().replace(' ', '-');
                meterElement.className = `mt-2 p-2 rounded text-center text-sm font-medium password-meter ${strengthClass}`;
                meterElement.textContent = `Strength: ${strength}`;
                
                // Show validation errors
                if (validation.errors.length > 0) {
                    errorsElement.innerHTML = validation.errors
                        .map(error => `<div class="error-item mt-1 p-2 bg-red-50 text-red-600 rounded text-sm">${error}</div>`)
                        .join('');
                } else {
                    errorsElement.innerHTML = '';
                }
                
                // Update requirements indicators
                updateRequirements(validation.requirements);
                
                // Enable/disable submit button
                submitBtn.disabled = !validation.isValid;
                if (validation.isValid) {
                    submitBtn.classList.remove('bg-gray-400', 'cursor-not-allowed');
                    submitBtn.classList.add('bg-blue-600', 'hover:bg-blue-700');
                } else {
                    submitBtn.classList.add('bg-gray-400', 'cursor-not-allowed');
                    submitBtn.classList.remove('bg-blue-600', 'hover:bg-blue-700');
                }
            } else {
                meterElement.style.display = 'none';
                errorsElement.innerHTML = '';
                resetRequirements();
                submitBtn.disabled = true;
                submitBtn.classList.add('bg-gray-400', 'cursor-not-allowed');
                submitBtn.classList.remove('bg-blue-600', 'hover:bg-blue-700');
            }
        }

        function updateRequirements(requirements) {
            Object.keys(requirements).forEach(req => {
                const element = document.getElementById(`req-${req}`);
                if (element) {
                    if (requirements[req]) {
                        element.classList.remove('requirement-unmet');
                        element.classList.add('requirement-met');
                        element.querySelector('span:first-child').textContent = '✓';
                    } else {
                        element.classList.remove('requirement-met');
                        element.classList.add('requirement-unmet');
                        element.querySelector('span:first-child').textContent = '•';
                    }
                }
            });
        }

        function resetRequirements() {
            const reqElements = document.querySelectorAll('[id^="req-"]');
            reqElements.forEach(el => {
                el.classList.remove('requirement-met');
                el.classList.add('requirement-unmet');
                el.querySelector('span:first-child').textContent = '•';
            });
        }

        // Event listeners
        passwordInput.addEventListener('input', updatePasswordValidation);
        usernameInput.addEventListener('input', updatePasswordValidation);
        emailInput.addEventListener('input', updatePasswordValidation);

        // Form submission validation
        document.querySelector('form').addEventListener('submit', function(e) {
            const password = passwordInput.value;
            const userInfo = {
                username: usernameInput.value,
                email: emailInput.value
            };
            
            const validation = validator.validatePassword(password, userInfo);
            
            if (!validation.isValid) {
                e.preventDefault();
                alert('Please fix all password requirements before submitting.');
                return false;
            }
        });

        // Initialize validation on page load
        document.addEventListener('DOMContentLoaded', function() {
            updatePasswordValidation();
        });
    </script>
</body>
</html>