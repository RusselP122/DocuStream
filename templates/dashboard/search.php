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
    <title>DocuStream - Search</title>
    <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-gray-50 min-h-screen">
    <?php include dirname(__DIR__) . '/partials/header.php'; ?>

    <main class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        <h1 class="text-2xl font-bold text-gray-900 mb-6">Search Documents</h1>

        <form method="GET" action="?action=search" class="mb-8 bg-white p-6 rounded-lg shadow-sm" aria-label="Search documents form">
            <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token'] ?? '', ENT_QUOTES, 'UTF-8'); ?>">
            <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                    <label for="keyword" class="block text-sm font-medium text-gray-700">Keyword</label>
                    <input type="text" id="keyword" name="keyword" class="mt-1 block w-full p-2 border border-gray-300 rounded-lg focus:ring-blue-500 focus:border-blue-500" placeholder="e.g., invoice" value="<?php echo htmlspecialchars($_GET['keyword'] ?? '', ENT_QUOTES, 'UTF-8'); ?>" maxlength="100">
                </div>
                <div>
                    <label for="category" class="block text-sm font-medium text-gray-700">Category</label>
                    <input type="text" id="category" name="category" class="mt-1 block w-full p-2 border border-gray-300 rounded-lg focus:ring-blue-500 focus:border-blue-500" placeholder="e.g., Contracts" value="<?php echo htmlspecialchars($_GET['category'] ?? '', ENT_QUOTES, 'UTF-8'); ?>" maxlength="50">
                </div>
                <div>
                    <label for="tags" class="block text-sm font-medium text-gray-700">Tags</label>
                    <input type="text" id="tags" name="metadata[tags]" class="mt-1 block w-full p-2 border border-gray-300 rounded-lg focus:ring-blue-500 focus:border-blue-500" placeholder="e.g., urgent" value="<?php echo htmlspecialchars($_GET['metadata']['tags'] ?? '', ENT_QUOTES, 'UTF-8'); ?>" maxlength="100">
                </div>
                <div>
                    <label for="start_date" class="block text-sm font-medium text-gray-700">Date Range</label>
                    <div class="flex space-x-2">
                        <input type="date" id="start_date" name="date_range[start]" class="mt-1 block w-full p-2 border border-gray-300 rounded-lg focus:ring-blue-500 focus:border-blue-500" value="<?php echo htmlspecialchars($_GET['date_range']['start'] ?? '', ENT_QUOTES, 'UTF-8'); ?>">
                        <input type="date" id="end_date" name="date_range[end]" class="mt-1 block w-full p-2 border border-gray-300 rounded-lg focus:ring-blue-500 focus:border-blue-500" value="<?php echo htmlspecialchars($_GET['date_range']['end'] ?? '', ENT_QUOTES, 'UTF-8'); ?>">
                    </div>
                </div>
            </div>
            <div class="mt-4 flex justify-end">
                <button type="submit" class="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700">Search</button>
            </div>
        </form>

        <div class="bg-white rounded-lg shadow">
            <div class="px-6 py-4 border-b border-gray-200">
                <h3 class="text-lg font-medium text-gray-900">Search Results</h3>
            </div>
            <div class="divide-y divide-gray-200">
                <?php if (empty($results)): ?>
                    <div class="px-6 py-4 text-gray-500">No documents found.</div>
                <?php else: ?>
                    <?php foreach ($results as $doc): ?>
                        <div class="px-6 py-4 hover:bg-gray-50 transition-colors">
                            <div class="flex items-center justify-between">
                                <div class="flex items-center space-x-4">
                                    <div class="flex-shrink-0 bg-blue-100 p-2 rounded-lg">
                                        <svg class="w-6 h-6 text-blue-600" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
                                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"></path>
                                        </svg>
                                    </div>
                                    <div>
                                        <div class="text-sm font-medium text-gray-900"><?php echo htmlspecialchars($doc['original_name'] ?? 'Untitled', ENT_QUOTES, 'UTF-8'); ?></div>
                                        <div class="text-sm text-gray-500">
                                            Category: <?php echo htmlspecialchars($doc['category'] ?? 'Uncategorized', ENT_QUOTES, 'UTF-8'); ?> |
                                            Uploaded: 
                                            <?php 
                                                $date = isset($doc['uploaded_at']) && $doc['uploaded_at'] instanceof \MongoDB\BSON\UTCDateTime
                                                    ? $doc['uploaded_at']->toDateTime()->format('Y-m-d H:i')
                                                    : 'Unknown date';
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
                                    <?php if ($auth->hasPermission('archive') && !($doc['archived'] ?? false)): ?>
                                        <a href="?action=archive&id=<?php echo htmlspecialchars((string)($doc['_id'] ?? ''), ENT_QUOTES, 'UTF-8'); ?>" class="text-yellow-600 hover:text-yellow-900" aria-label="Archive document" onclick="return confirm('Are you sure you want to archive this document?');">Archive</a>
                                    <?php endif; ?>
                                    <?php if ($auth->hasPermission('delete')): ?>
                                        <a href="?action=delete&id=<?php echo htmlspecialchars((string)($doc['_id'] ?? ''), ENT_QUOTES, 'UTF-8'); ?>" class="text-red-600 hover:text-red-900" aria-label="Move document to trash" onclick="return confirm('Are you sure you want to move this document to trash?');">
                                            <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
                                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"></path>
                                            </svg>
                                        </a>
                                    <?php endif; ?>
                                </div>
                            </div>
                        </div>
                    <?php endforeach; ?>
                <?php endif; ?>
            </div>
            <?php if ($totalPages > 1): ?>
                <div class="px-6 py-4 flex items-center justify-between border-t border-gray-200">
                    <div class="flex-1 flex justify-between sm:justify-end">
                        <div class="mr-4 text-sm text-gray-700">
                            Page <?php echo $currentPage; ?> of <?php echo $totalPages; ?>
                        </div>
                        <div class="flex space-x-2">
                            <?php
                            $params = $_GET;
                            $params['page'] = max(1, $currentPage - 1);
                            $prevUrl = '?' . http_build_query($params);
                            $params['page'] = min($totalPages, $currentPage + 1);
                            $nextUrl = '?' . http_build_query($params);
                            ?>
                            <a href="<?php echo htmlspecialchars($prevUrl, ENT_QUOTES, 'UTF-8'); ?>" 
                               class="px-4 py-2 border border-gray-300 text-sm font-medium rounded-md text-gray-700 bg-white hover:bg-gray-50 <?php echo $currentPage === 1 ? 'opacity-50 cursor-not-allowed' : ''; ?>" 
                               <?php echo $currentPage === 1 ? 'aria-disabled="true"' : ''; ?>>
                                Previous
                            </a>
                            <?php
                            $startPage = max(1, $currentPage - 2);
                            $endPage = min($totalPages, $startPage + 4);
                            $startPage = max(1, $endPage - 4);
                            for ($i = $startPage; $i <= $endPage; $i++):
                                $params['page'] = $i;
                                $pageUrl = '?' . http_build_query($params);
                            ?>
                                <a href="<?php echo htmlspecialchars($pageUrl, ENT_QUOTES, 'UTF-8'); ?>" 
                                   class="px-4 py-2 border border-gray-300 text-sm font-medium rounded-md <?php echo $i === $currentPage ? 'bg-blue-600 text-white' : 'text-gray-700 bg-white hover:bg-gray-50'; ?>">
                                    <?php echo $i; ?>
                                </a>
                            <?php endfor; ?>
                            <a href="<?php echo htmlspecialchars($nextUrl, ENT_QUOTES, 'UTF-8'); ?>" 
                               class="px-4 py-2 border border-gray-300 text-sm font-medium rounded-md text-gray-700 bg-white hover:bg-gray-50 <?php echo $currentPage === $totalPages ? 'opacity-50 cursor-not-allowed' : ''; ?>" 
                               <?php echo $currentPage === $totalPages ? 'aria-disabled="true"' : ''; ?>>
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