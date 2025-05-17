<?php
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}
?>

<header class="bg-white shadow">
    <nav class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-4 flex items-center justify-between" aria-label="Main navigation">
        <div class="flex items-center">
            <a href="?action=dashboard" class="text-xl font-bold text-gray-900">DocuStream</a>
        </div>
        <div class="flex items-center space-x-4">
            <?php if (isset($_SESSION['user_id']) && isset($auth) && $auth->isAuthenticated()): ?>
                <a href="?action=dashboard" class="text-gray-600 hover:text-gray-900">Dashboard</a>
                <?php if ($auth->hasPermission('view')): ?>
                    <a href="?action=search" class="text-gray-600 hover:text-gray-900">Search</a>
                <?php endif; ?>
                <?php if ($auth->isAdmin()): ?>
                    <a href="?action=admin" class="text-gray-600 hover:text-gray-900">Admin</a>
                <?php endif; ?>
                <a href="?action=logout" class="text-red-600 hover:text-red-800">Logout</a>
            <?php else: ?>
                <a href="?action=login" class="text-gray-600 hover:text-gray-900">Login</a>
                <a href="?action=register" class="text-gray-600 hover:text-gray-900">Register</a>
            <?php endif; ?>
        </div>
    </nav>
</header>