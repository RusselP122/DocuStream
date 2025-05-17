<?php
// templates/admin/edit_user.php

// Ensure session is started
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

// Validate session and admin privileges
if (!isset($_SESSION['user_id']) || !isset($auth) || !$auth->isAdmin()) {
    $_SESSION['error'] = 'You must be logged in as an admin to access this page.';
    header('Location: ?action=login');
    exit();
}

// Sanitize and validate user ID
$userId = filter_input(INPUT_GET, 'id', FILTER_SANITIZE_STRING) ?? '';
if (empty($userId) || !preg_match('/^[a-f\d]{24}$/i', $userId)) {
    $_SESSION['error'] = 'Invalid user ID.';
    header('Location: ?action=admin');
    exit();
}

// Fetch user data
$user = $auth->getUserById($userId);
if (!$user) {
    $_SESSION['error'] = 'User not found.';
    header('Location: ?action=admin');
    exit();
}

// CSRF token generation
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>DocuStream - Edit User</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script>
        function confirmSubmit() {
            return confirm('Are you sure you want to save these changes?');
        }
    </script>
</head>
<body class="bg-gray-50 min-h-screen">
    <?php include dirname(__DIR__) . '/partials/header.php'; ?>
    
    <main class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        <div class="bg-white p-6 rounded-lg shadow-md max-w-lg mx-auto">
            <h1 class="text-2xl font-bold text-gray-900 mb-6 text-center">Edit User</h1>

            <?php if (isset($_SESSION['message'])): ?>
                <div class="mb-4 p-4 bg-green-100 text-green-700 rounded-lg text-center" role="alert">
                    <?php echo htmlspecialchars($_SESSION['message'], ENT_QUOTES, 'UTF-8'); ?>
                    <?php unset($_SESSION['message']); ?>
                </div>
            <?php endif; ?>
            <?php if (isset($_SESSION['error'])): ?>
                <div class="mb-4 p-4 bg-red-100 text-red-700 rounded-lg text-center" role="alert">
                    <?php echo htmlspecialchars($_SESSION['error'], ENT_QUOTES, 'UTF-8'); ?>
                    <?php unset($_SESSION['error']); ?>
                </div>
            <?php endif; ?>

            <form method="POST" action="?action=admin" class="space-y-6" onsubmit="return confirmSubmit();" aria-label="Edit user form">
                <input type="hidden" name="user_id" value="<?php echo htmlspecialchars($userId, ENT_QUOTES, 'UTF-8'); ?>">
                <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token'], ENT_QUOTES, 'UTF-8'); ?>">
                
                <div>
                    <label for="username" class="block text-sm font-medium text-gray-700">Username</label>
                    <input type="text" id="username" name="username" value="<?php echo htmlspecialchars($user['username'] ?? '', ENT_QUOTES, 'UTF-8'); ?>" class="mt-1 block w-full p-3 border border-gray-300 rounded-lg focus:ring-blue-500 focus:border-blue-500" required aria-required="true" maxlength="50">
                </div>
                <div>
                    <label for="email" class="block text-sm font-medium text-gray-700">Email</label>
                    <input type="email" id="email" name="email" value="<?php echo htmlspecialchars($user['email'] ?? '', ENT_QUOTES, 'UTF-8'); ?>" class="mt-1 block w-full p-3 border border-gray-300 rounded-lg focus:ring-blue-500 focus:border-blue-500" required aria-required="true" maxlength="100">
                </div>
                <div>
                    <label for="password" class="block text-sm font-medium text-gray-700">New Password (optional)</label>
                    <input type="password" id="password" name="password" class="mt-1 block w-full p-3 border border-gray-300 rounded-lg focus:ring-blue-500 focus:border-blue-500" placeholder="Leave blank to keep current password" aria-describedby="password-help">
                    <p id="password-help" class="mt-1 text-sm text-gray-500">Leave blank to keep the current password.</p>
                </div>
                <div class="flex items-center">
                    <input type="checkbox" id="is_admin" name="is_admin" value="1" <?php echo (!empty($user['isAdmin']) && $user['isAdmin']) ? 'checked' : ''; ?> class="h-4 w-4 text-blue-600 focus:ring-blue-500 border-gray-300 rounded" <?php echo $userId === $_SESSION['user_id'] ? 'disabled' : ''; ?>>
                    <label for="is_admin" class="ml-2 block text-sm text-gray-900">Is Admin</label>
                </div>
                <div>
                    <label class="block text-sm font-medium text-gray-700">Permissions</label>
                    <div class="mt-2 space-y-2">
                        <?php foreach (VALID_PERMISSIONS as $perm): ?>
                            <div class="flex items-center">
                                <input type="checkbox" id="perm_<?php echo htmlspecialchars($perm, ENT_QUOTES, 'UTF-8'); ?>" name="permissions[]" value="<?php echo htmlspecialchars($perm, ENT_QUOTES, 'UTF-8'); ?>" <?php echo in_array($perm, $user['permissions'] ?? []) ? 'checked' : ''; ?> class="h-4 w-4 text-blue-600 focus:ring-blue-500 border-gray-300 rounded">
                                <label for="perm_<?php echo htmlspecialchars($perm, ENT_QUOTES, 'UTF-8'); ?>" class="ml-2 block text-sm text-gray-900"><?php echo ucfirst(htmlspecialchars($perm, ENT_QUOTES, 'UTF-8')); ?></label>
                            </div>
                        <?php endforeach; ?>
                    </div>
                </div>
                <div class="flex justify-end space-x-2">
                    <a href="?action=admin" class="px-4 py-2 bg-gray-200 text-gray-700 rounded-lg hover:bg-gray-300">Cancel</a>
                    <button type="submit" class="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700">Save Changes</button>
                </div>
            </form>
        </div>
    </main>

    <?php include dirname(__DIR__) . '/partials/footer.php'; ?>
</body>
</html>