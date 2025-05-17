<?php
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

if (!isset($_SESSION['user_id']) || !isset($auth) || !$auth->isAuthenticated() || !$auth->hasPermission('view')) {
    $_SESSION['error'] = 'You must be logged in with view permissions to access this page.';
    header('Location: ?action=login');
    exit();
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>DocuStream - View Text Document</title>
    <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-gray-50 min-h-screen">
    <?php include dirname(__DIR__) . '/partials/header.php'; ?>

    <main class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        <h1 class="text-2xl font-bold text-gray-900 mb-6">View Text Document</h1>

        <?php if (isset($error)): ?>
            <div class="mb-4 p-4 bg-red-100 text-red-700 rounded-lg text-center" role="alert">
                <?php echo htmlspecialchars($error, ENT_QUOTES, 'UTF-8'); ?>
            </div>
        <?php endif; ?>

        <div class="bg-white p-6 rounded-lg shadow-sm">
            <pre class="text-sm text-gray-800 whitespace-pre-wrap"><?php echo htmlspecialchars($content ?? 'No content available.', ENT_QUOTES, 'UTF-8'); ?></pre>
        </div>

        <div class="mt-4 flex justify-end">
            <a href="?action=dashboard" class="px-4 py-2 bg-gray-200 text-gray-700 rounded-lg hover:bg-gray-300">Back to Dashboard</a>
        </div>
    </main>

    <?php include dirname(__DIR__) . '/partials/footer.php'; ?>
</body>
</html>