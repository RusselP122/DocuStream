<?php
// templates/admin/index.php

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
    <title>DocuStream - Admin Panel</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script>
        function confirmAction(message) {
            return confirm(message);
        }
    </script>
</head>
<body class="bg-gray-50 min-h-screen">
    <?php include dirname(__DIR__) . '/partials/header.php'; ?>

    <main class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
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

        <div class="bg-white shadow rounded-lg mb-6">
            <div class="px-4 py-5 sm:px-6 border-b border-gray-200">
                <h3 class="text-lg leading-6 font-medium text-gray-900">User Management</h3>
            </div>
            <div class="overflow-x-auto">
                <table class="min-w-full divide-y divide-gray-200" aria-label="User management table">
                    <thead class="bg-gray-50">
                        <tr>
                            <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                                Username
                            </th>
                            <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                                Email
                            </th>
                            <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                                Role
                            </th>
                            <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                                Permissions
                            </th>
                            <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                                Actions
                            </th>
                        </tr>
                    </thead>
                    <tbody class="bg-white divide-y divide-gray-200">
                        <?php if (isset($users) && is_array($users) && !empty($users)): ?>
                            <?php foreach ($users as $user): ?>
                                <tr>
                                    <td class="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900">
                                        <?php echo htmlspecialchars($user['username'] ?? 'N/A', ENT_QUOTES, 'UTF-8'); ?>
                                    </td>
                                    <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                                        <?php echo htmlspecialchars($user['email'] ?? 'N/A', ENT_QUOTES, 'UTF-8'); ?>
                                    </td>
                                    <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                                        <?php echo !empty($user['isAdmin']) && $user['isAdmin'] ? 'Admin' : 'User'; ?>
                                    </td>
  <td class="px-6 py-4 text-sm">
    <div class="flex flex-wrap gap-2">
        <?php
        // Use permissions as-is (already a PHP array)
        $userPermissions = is_array($user['permissions']) ? $user['permissions'] : [];
        
        // Define badge colors for permissions
        $colorMap = [
            'upload' => 'blue',
            'view' => 'purple',
            'download' => 'indigo',
            'archive' => 'yellow',
            'delete' => 'red'
        ];
        
        // If user has permissions, display them; otherwise, show "None"
        if (!empty($userPermissions)) {
            foreach ($userPermissions as $perm) {
                // Only display valid permissions
                if (in_array($perm, VALID_PERMISSIONS)) {
                    $color = $colorMap[$perm] ?? 'gray';
                    $badgeClass = "bg-{$color}-100 text-{$color}-800";
                    ?>
                    <span class="px-2.5 py-1.5 rounded-full text-xs font-medium <?php echo $badgeClass; ?>">
                        <svg class="w-4 h-4 inline mr-1.5" fill="currentColor" viewBox="0 0 20 20" aria-hidden="true">
                            <path fill-rule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clip-rule="evenodd"/>
                        </svg>
                        <?php echo ucfirst(htmlspecialchars($perm, ENT_QUOTES, 'UTF-8')); ?>
                    </span>
                    <?php
                }
            }
        } else {
            ?>
            <span class="px-2.5 py-1.5 rounded-full text-xs font-medium bg-gray-100 text-gray-400">
                None
            </span>
            <?php
        }
        ?>
    </div>
</td>
                                    <td class="px-6 py-4 whitespace-nowrap text-right text-sm font-medium">
                                        <a href="?action=edit_user&id=<?php echo htmlspecialchars((string)($user['_id'] ?? ''), ENT_QUOTES, 'UTF-8'); ?>" class="text-blue-600 hover:text-blue-900">Edit</a>
                                    </td>
                                </tr>
                            <?php endforeach; ?>
                        <?php else: ?>
                            <tr>
                                <td colspan="5" class="px-6 py-4 text-sm text-gray-500 text-center">No users found.</td>
                            </tr>
                        <?php endif; ?>
                    </tbody>
                </table>
            </div>
        </div>

        <?php if (isset($pendingDocuments) && is_array($pendingDocuments) && !empty($pendingDocuments)): ?>
            <div class="bg-white shadow rounded-lg">
                <div class="px-4 py-5 sm:px-6 border-b border-gray-200">
                    <h3 class="text-lg leading-6 font-medium text-gray-900">Pending Documents</h3>
                </div>
                <div class="overflow-x-auto">
                    <table class="min-w-full divide-y divide-gray-200" aria-label="Pending documents table">
                        <thead class="bg-gray-50">
                            <tr>
                                <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                                    Name
                                </th>
                                <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                                    Category
                                </th>
                                <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                                    Uploaded By
                                </th>
                                <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                                    Date
                                </th>
                                <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                                    Actions
                                </th>
                            </tr>
                        </thead>
                        <tbody class="bg-white divide-y divide-gray-200">
                            <?php foreach ($pendingDocuments as $doc): ?>
                                <tr>
                                    <td class="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900">
                                        <?php echo htmlspecialchars($doc['original_name'] ?? 'N/A', ENT_QUOTES, 'UTF-8'); ?>
                                    </td>
                                    <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                                        <?php echo htmlspecialchars($doc['category'] ?? 'N/A', ENT_QUOTES, 'UTF-8'); ?>
                                    </td>
                                    <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                                        <?php
                                        $uploader = isset($doc['user_id']) ? $auth->getUserById($doc['user_id']) : null;
                                        echo $uploader ? htmlspecialchars($uploader['username'], ENT_QUOTES, 'UTF-8') : 'Unknown User';
                                        ?>
                                    </td>
                                    <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                                        <?php
                                        $date = isset($doc['uploaded_at']) && method_exists($doc['uploaded_at'], 'toDateTime')
                                            ? $doc['uploaded_at']->toDateTime()->format('Y-m-d H:i')
                                            : 'N/A';
                                        echo htmlspecialchars($date, ENT_QUOTES, 'UTF-8');
                                        ?>
                                    </td>
                                    <td class="px-6 py-4 whitespace-nowrap text-sm font-medium">
                                        <a href="?action=view&id=<?php echo htmlspecialchars((string)($doc['_id'] ?? ''), ENT_QUOTES, 'UTF-8'); ?>" class="text-blue-600 hover:text-blue-900 mr-3">View</a>
                                        <a href="?action=approve_document&id=<?php echo htmlspecialchars((string)($doc['_id'] ?? ''), ENT_QUOTES, 'UTF-8'); ?>&csrf_token=<?php echo htmlspecialchars($_SESSION['csrf_token'], ENT_QUOTES, 'UTF-8'); ?>"
                                           onclick="return confirmAction('Are you sure you want to approve this document?');"
                                           class="text-green-600 hover:text-green-900 mr-3">Approve</a>
                                        <a href="?action=reject_document&id=<?php echo htmlspecialchars((string)($doc['_id'] ?? ''), ENT_QUOTES, 'UTF-8'); ?>&csrf_token=<?php echo htmlspecialchars($_SESSION['csrf_token'], ENT_QUOTES, 'UTF-8'); ?>"
                                           onclick="return confirmAction('Are you sure you want to reject this document?');"
                                           class="text-red-600 hover:text-red-900">Reject</a>
                                    </td>
                                </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                </div>
            </div>
        <?php else: ?>
            <div class="bg-white shadow rounded-lg p-6 text-center">
                <p class="text-sm text-gray-500">No pending documents found.</p>
            </div>
        <?php endif; ?>
    </main>

    <?php include dirname(__DIR__) . '/partials/footer.php'; ?>
</body>
</html>