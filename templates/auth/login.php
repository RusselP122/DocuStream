<?php
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>DocuStream - Login</title>
    <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-gray-50 min-h-screen flex items-center justify-center">
    <div class="bg-white p-6 rounded-lg shadow-md max-w-md w-full">
        <h1 class="text-2xl font-bold text-gray-900 mb-6 text-center">Login</h1>

        <?php if (isset($error)): ?>
            <div class="mb-4 p-4 bg-red-100 text-red-700 rounded-lg text-center" role="alert">
                <?php echo htmlspecialchars($error, ENT_QUOTES, 'UTF-8'); ?>
            </div>
        <?php endif; ?>

        <form method="POST" action="?action=login" class="space-y-4" aria-label="Login form">
            <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token'] ?? '', ENT_QUOTES, 'UTF-8'); ?>">
            <div>
                <label for="email" class="block text-sm font-medium text-gray-700">Email</label>
                <input type="email" id="email" name="email" class="mt-1 block w-full p-2 border border-gray-300 rounded-lg focus:ring-blue-500 focus:border-blue-500" required aria-required="true" maxlength="100">
            </div>
            <div>
                <label for="password" class="block text-sm font-medium text-gray-700">Password</label>
                <input type="password" id="password" name="password" class="mt-1 block w-full p-2 border border-gray-300 rounded-lg focus:ring-blue-500 focus:border-blue-500" required aria-required="true">
            </div>
            <div class="flex justify-between">
                <a href="?action=forgot_password" class="text-sm text-blue-600 hover:text-blue-800">Forgot Password?</a>
                <button type="submit" class="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700">Login</button>
            </div>
        </form>
        <p class="mt-4 text-center text-sm text-gray-600">
            Don't have an account? <a href="?action=register" class="text-blue-600 hover:text-blue-800">Register</a>
        </p>
    </div>
</body>
</html>