<?php
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

// Generate CSRF token if not set
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>DocuStream - Register</title>
    <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-gray-100 min-h-screen flex items-center justify-center">
    <div class="w-full max-w-5xl mx-auto grid grid-cols-1 lg:grid-cols-2 gap-8 p-6">
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
                            class="mt-1 block w-full p-3 pl-10 border border-gray-300 rounded-lg focus:ring-blue-500 focus:border-blue-500 focus:outline-none transition-colors" 
                            placeholder="Enter your password (8+ characters)" 
                            required 
                            aria-required="true" 
                            minlength="8"
                        >
                        <svg class="absolute left-3 top-1/2 transform -translate-y-1/2 w-5 h-5 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 11c0-1.104-.896-2-2-2s-2 .896-2 2c0 .738.402 1.378 1 1.723V15h2v-2.277c.598-.345 1-.985 1-1.723zm9-2v6a2 2 0 01-2 2H5a2 2 0 01-2-2V9a2 2 0 012-2h1V5a4 4 0 018 0v2h1a2 2 0 012 2z"></path>
                        </svg>
                    </div>
                </div>
                <div class="flex justify-end">
                    <button 
                        type="submit" 
                        class="px-6 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 focus:ring-2 focus:ring-blue-500 focus:ring-offset-2 transition-colors"
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
                <p class="text-sm">
                    Create an account to manage your documents securely and streamline your workflow with our advanced document management system.
                </p>
                <!-- Placeholder for illustration or logo -->
                <div class="mt-8 flex justify-center">
                    <svg class="w-32 h-32 opacity-75" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"></path>
                    </svg>
                </div>
            </div>
        </div>
    </div>
</body>
</html>