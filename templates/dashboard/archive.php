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
    <title>DocuStream - Archived Documents</title>
    <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-gray-50 min-h-screen">
    <?php include dirname(__DIR__) . '/partials/header.php'; ?>

    <main class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        <h1 class="text-2xl font-bold text-gray-900 mb-6">Archived Documents</h1>

        <?php if (isset($_SESSION['message'])): ?>
            <div class="mb-4 p-4 bg-green-100 text-green-700 rounded-lg" role="alert">
                <?php echo htmlspecialchars($_SESSION['message'], ENT_QUOTES, 'UTF-8'); ?>
                <?php unset($_SESSION['message']); ?>
            </div>
        <?php endif; ?>
        <?php if (isset($_SESSION['error'])): ?>
            <div class="mb-4 p-4 bg-red-100 text-red-700 rounded-lg" role="alert">
                <?php echo htmlspecialchars($_SESSION['error'], ENT_QUOTES, 'UTF-8'); ?>
                <?php unset($_SESSION['error']); ?>
            </div>
        <?php endif; ?>

        <div class="bg-white rounded-lg shadow">
            <div class="px-6 py-4 border-b border-gray-200">
                <h3 class="text-lg font-medium text-gray-900">Archived Documents</h3>
            </div>
            <div class="divide-y divide-gray-200">
                <?php if (empty($archivedDocs)): ?>
                    <div class="px-6 py-4 text-gray-500">No archived documents found.</div>
                <?php else: ?>
                    <?php foreach ($archivedDocs as $doc): ?>
                        <div class="px-6 py-4 hover:bg-gray-50 transition-colors">
                            <div class="flex items-center justify-between">
                                <div class="flex items-center space-x-4">
                                    <div class="flex-shrink-0 bg-yellow-100 p-2 rounded-lg">
                                        <svg class="w-6 h-6 text-yellow-600" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
                                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 8h14M5 8a2 2 0 110-4h14a2 2 0 110 4M5 8v10a2 2 0 002 2h10a2 2 0 002-2V8m-9 4h4"></path>
                                        </svg>
                                    </div>
                                    <div>
                                        <div class="text-sm font-medium text-gray-900"><?php echo htmlspecialchars($doc['original_name'] ?? 'Untitled', ENT_QUOTES, 'UTF-8'); ?></div>
                                        <div class="text-sm text-gray-500">
                                            Archived 
                                            <?php 
                                                $date = isset($doc['archived_at']) && $doc['archived_at'] instanceof \MongoDB\BSON\UTCDateTime
                                                    ? $doc['archived_at']->toDateTime()->format('Y-m-d H:i')
                                                    : (isset($doc['uploaded_at']) && $doc['uploaded_at'] instanceof \MongoDB\BSON\UTCDateTime
                                                        ? $doc['uploaded_at']->toDateTime()->format('Y-m-d H:i')
                                                        : 'Unknown date');
                                                echo htmlspecialchars($date, ENT_QUOTES, 'UTF-8');
                                            ?>
                                        </div>
                                    </div>
                                </div>
                                <div class="flex items-center space-x-4">
                                    <?php if ($auth->hasPermission('view')): ?>
                                        <a href="?action=view&id=<?php echo htmlspecialchars((string)($doc['_id'] ?? ''), ENT_QUOTES, 'UTF-8'); ?>" class="text-indigo-600 hover:text-indigo-900" aria-label="View document">View</a>
                                    <?php endif; ?>
                                    <?php if ($auth->hasPermission('download')): ?>
                                        <a href="?action=download&id=<?php echo htmlspecialchars((string)($doc['_id'] ?? ''), ENT_QUOTES, 'UTF-8'); ?>" class="text-green-600 hover:text-green-900" aria-label="Download document">Download</a>
                                    <?php endif; ?>
                                    <?php if ($auth->hasPermission('archive')): ?>
                                        <a href="?action=unarchive&id=<?php echo htmlspecialchars((string)($doc['_id'] ?? ''), ENT_QUOTES, 'UTF-8'); ?>" class="text-blue-600 hover:text-blue-900" aria-label="Unarchive document" onclick="return confirm('Are you sure you want to unarchive this document?');">Unarchive</a>
                                    <?php endif; ?>
                                </div>
                            </div>
                        </div>
                    <?php endforeach; ?>
                <?php endif; ?>
            </div>
            <?php if ($archiveTotalPages > 1): ?>
                <div class="px-6 py-4 flex items-center justify-between border-t border-gray-200">
                    <div class="flex-1 flex justify-between sm:justify-end">
                        <div class="mr-4 text-sm text-gray-700">
                            Page <?php echo $archivePage; ?> of <?php echo $archiveTotalPages; ?>
                        </div>
                        <div class="flex space-x-2">
                            <?php
                            $params = $_GET;
                            $params['page'] = max(1, $archivePage - 1);
                            $prevUrl = '?' . http_build_query($params);
                            $params['page'] = min($archiveTotalPages, $archivePage + 1);
                            $nextUrl = '?' . http_build_query($params);
                            ?>
                            <a href="<?php echo htmlspecialchars($prevUrl, ENT_QUOTES, 'UTF-8'); ?>" 
                               class="px-4 py-2 border border-gray-300 text-sm font-medium rounded-md text-gray-700 bg-white hover:bg-gray-50 <?php echo $archivePage === 1 ? 'opacity-50 cursor-not-allowed' : ''; ?>" 
                               <?php echo $archivePage === 1 ? 'aria-disabled="true"' : ''; ?>>
                                Previous
                            </a>
                            <?php
                            $startPage = max(1, $archivePage - 2);
                            $endPage = min($archiveTotalPages, $startPage + 4);
                            $startPage = max(1, $endPage - 4);
                            for ($i = $startPage; $i <= $endPage; $i++):
                                $params['page'] = $i;
                                $pageUrl = '?' . http_build_query($params);
                            ?>
                                <a href="<?php echo htmlspecialchars($pageUrl, ENT_QUOTES, 'UTF-8'); ?>" 
                                   class="px-4 py-2 border border-gray-300 text-sm font-medium rounded-md <?php echo $i === $archivePage ? 'bg-blue-600 text-white' : 'text-gray-700 bg-white hover:bg-gray-50'; ?>">
                                    <?php echo $i; ?>
                                </a>
                            <?php endfor; ?>
                            <a href="<?php echo htmlspecialchars($nextUrl, ENT_QUOTES, 'UTF-8'); ?>" 
                               class="px-4 py-2 border border-gray-300 text-sm font-medium rounded-md text-gray-700 bg-white hover:bg-gray-50 <?php echo $archivePage === $archiveTotalPages ? 'opacity-50 cursor-not-allowed' : ''; ?>" 
                               <?php echo $archivePage === $archiveTotalPages ? 'aria-disabled="true"' : ''; ?>>
                                Next
                            </a>
                        </div>
                    </div>
                </div>
            <?php endif; ?>
        </div>
    </main>

    <?php include dirname(__DIR__) . '/partials/footer.php'; ?>
</body>
</html>