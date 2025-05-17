<?php
// templates/dashboard/index.php

if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

if (!isset($_SESSION['user_id']) || !isset($auth) || !$auth->isAuthenticated()) {
    $_SESSION['error'] = 'Please log in to access the dashboard.';
    header('Location: ?action=login');
    exit();
}

try {
    $user = $auth->getUserById($_SESSION['user_id']);
    $username = $user ? htmlspecialchars($user['username'], ENT_QUOTES, 'UTF-8') : 'Guest';
    $weekStart = new \MongoDB\BSON\UTCDateTime(strtotime('monday this week') * 1000);
    $newDocsCount = $document->getDocumentsCount([
        'user_id' => $_SESSION['user_id'],
        'status' => 'approved',
        'uploaded_at' => ['$gte' => $weekStart]
    ]);
    $recentDocs = iterator_to_array($document->search('', '', [], [], ['uploaded_at' => -1], 5));
} catch (\Exception $e) {
    error_log("Dashboard error: " . $e->getMessage());
    $username = 'Guest';
    $newDocsCount = 0;
    $recentDocs = [];
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>DocuStream - Dashboard</title>
    <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-gray-50 min-h-screen">
    <?php include dirname(__DIR__) . '/partials/header.php'; ?>
    
    <main class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
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
        
        <div class="mb-8 flex items-center justify-between">
            <div>
                <h1 class="text-2xl font-bold text-gray-900">
                    Welcome back, <?php echo $username; ?>
                </h1>
                <p class="mt-1 text-sm text-gray-600">
                    You have <?php echo $newDocsCount; ?> new document<?php echo $newDocsCount !== 1 ? 's' : ''; ?> this week
                </p>
            </div>
            <?php if ($auth->hasPermission('upload')): ?>
                <button id="open-upload-modal" class="inline-flex items-center bg-blue-600 text-white px-4 py-2 rounded-lg hover:bg-blue-700 transition" aria-label="Open upload modal">
                    <svg class="w-5 h-5 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4v16m8-8H4"></path>
                    </svg>
                    Upload New
                </button>
            <?php endif; ?>
        </div>

        <div id="upload-modal" class="fixed inset-0 bg-gray-600 bg-opacity-50 flex items-center justify-center hidden" role="dialog" aria-labelledby="upload-modal-title">
            <div class="bg-white p-6 rounded-lg shadow-lg max-w-lg w-full">
                <div class="flex justify-between items-center mb-4">
                    <h2 id="upload-modal-title" class="text-xl font-bold text-gray-900">Upload Document</h2>
                    <button id="close-upload-modal" class="text-gray-500 hover:text-gray-700" aria-label="Close modal">
                        <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path>
                        </svg>
                    </button>
                </div>
                <?php if ($auth->hasPermission('upload')): ?>
                    <form method="POST" enctype="multipart/form-data" action="?action=upload" aria-label="Upload document form">
                        <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token'], ENT_QUOTES, 'UTF-8'); ?>">
                        <div class="mb-4">
                            <label for="document" class="block text-sm font-medium text-gray-700">Select Document</label>
                            <input type="file" id="document" name="document" class="mt-1 block w-full p-2 border border-gray-300 rounded-lg focus:ring-blue-500 focus:border-blue-500" accept="<?php echo implode(',', array_map(fn($type) => ".$type", ALLOWED_FILE_TYPES)); ?>" required aria-required="true">
                            <p class="mt-1 text-sm text-gray-500">Supported formats: <?php echo implode(', ', array_map('strtoupper', ALLOWED_FILE_TYPES)); ?> (Max <?php echo MAX_FILE_SIZE / 1024 / 1024; ?>MB)</p>
                        </div>
                        <div class="mb-4">
                            <label for="category" class="block text-sm font-medium text-gray-700">Category</label>
                            <input type="text" id="category" name="category" class="mt-1 block w-full p-2 border border-gray-300 rounded-lg focus:ring-blue-500 focus:border-blue-500" placeholder="e.g., Invoices, Contracts" maxlength="50">
                        </div>
                        <div class="mb-4">
                            <label for="tags" class="block text-sm font-medium text-gray-700">Tags (optional)</label>
                            <input type="text" id="tags" name="metadata[tags]" class="mt-1 block w-full p-2 border border-gray-300 rounded-lg focus:ring-blue-500 focus:border-blue-500" placeholder="e.g., urgent, finance" maxlength="100">
                            <p class="mt-1 text-sm text-gray-500">Comma-separated tags for easy searching</p>
                        </div>
                        <div class="flex justify-end space-x-2">
                            <button type="button" id="cancel-upload" class="px-4 py-2 bg-gray-200 text-gray-700 rounded-lg hover:bg-gray-300" aria-label="Cancel upload">Cancel</button>
                            <button type="submit" class="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700">Upload</button>
                        </div>
                    </form>
                <?php else: ?>
                    <p class="text-gray-500">Contact an administrator to request upload permissions.</p>
                    <div class="flex justify-end">
                        <button id="close-upload-modal-perm" class="px-4 py-2 bg-gray-200 text-gray-700 rounded-lg hover:bg-gray-300" aria-label="Close modal">Close</button>
                    </div>
                <?php endif; ?>
            </div>
        </div>

        <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6 mb-8">
            <a href="?action=search" class="action-card bg-white p-6 rounded-lg shadow-sm hover:shadow-md transition-shadow">
                <div class="flex items-center">
                    <div class="flex-shrink-0 bg-blue-100 p-3 rounded-lg">
                        <svg class="w-6 h-6 text-blue-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 11H5m14 0a2 2 0 012 2v6a2 2 0 01-2 2H5a2 2 0 01-2-2v-6a2 2 0 012-2m14 0V9a2 2 0 00-2-2M5 11V9a2 2 0 012-2m0 0V5a2 2 0 012-2h6a2 2 0 012 2v2M7 7h10"></path>
                        </svg>
                    </div>
                    <div class="ml-4">
                        <h3 class="text-lg font-medium text-gray-900">My Documents</h3>
                        <p class="mt-1 text-sm text-gray-500">Access your personal files</p>
                    </div>
                </div>
            </a>

            <a href="?action=search" class="action-card bg-white p-6 rounded-lg shadow-sm hover:shadow-md transition-shadow">
                <div class="flex items-center">
                    <div class="flex-shrink-0 bg-green-100 p-3 rounded-lg">
                        <svg class="w-6 h-6 text-green-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"></path>
                        </svg>
                    </div>
                    <div class="ml-4">
                        <h3 class="text-lg font-medium text-gray-900">Advanced Search</h3>
                        <p class="mt-1 text-sm text-gray-500">Find documents quickly</p>
                    </div>
                </div>
            </a>

            <?php if ($auth->isAdmin()): ?>
                <a href="?action=admin" class="action-card bg-white p-6 rounded-lg shadow-sm hover:shadow-md transition-shadow">
                    <div class="flex items-center">
                        <div class="flex-shrink-0 bg-purple-100 p-3 rounded-lg">
                            <svg class="w-6 h-6 text-purple-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z"></path>
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"></path>
                            </svg>
                        </div>
                        <div class="ml-4">
                            <h3 class="text-lg font-medium text-gray-900">Admin Panel</h3>
                            <p class="mt-1 text-sm text-gray-500">System management</p>
                        </div>
                    </div>
                </a>
            <?php endif; ?>
        </div>

        <div class="bg-white rounded-lg shadow">
            <div class="px-6 py-4 border-b border-gray-200">
                <h3 class="text-lg font-medium text-gray-900">Recent Documents</h3>
            </div>
            <div class="divide-y divide-gray-200">
                <?php if (empty($recentDocs)): ?>
                    <div class="px-6 py-4 text-gray-500">No recent documents found.</div>
                <?php else: ?>
                    <?php foreach ($recentDocs as $doc): ?>
                        <div class="px-6 py-4 hover:bg-gray-50 transition-colors">
                            <div class="flex items-center justify-between">
                                <div class="flex items-center space-x-4">
                                    <div class="flex-shrink-0 bg-blue-100 p-2 rounded-lg">
                                        <svg class="w-6 h-6 text-blue-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"></path>
                                        </svg>
                                    </div>
                                    <div>
                                        <div class="text-sm font-medium text-gray-900"><?php echo htmlspecialchars($doc['original_name'] ?? 'Untitled', ENT_QUOTES, 'UTF-8'); ?></div>
                                        <div class="text-sm text-gray-500">
                                            Uploaded 
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
                                            <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
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
        </div>

        <div class="bg-white rounded-lg shadow mt-8">
            <div class="px-6 py-4 border-b border-gray-200">
                <h3 class="text-lg font-medium text-gray-900">Trash</h3>
            </div>
            <div class="divide-y divide-gray-200">
                <?php
                $trashedDocs = iterator_to_array($document->getTrashedDocuments($_SESSION['user_id']));
                if (empty($trashedDocs)): ?>
                    <div class="px-6 py-4 text-gray-500">No documents in trash.</div>
                <?php else: ?>
                    <?php foreach ($trashedDocs as $doc): ?>
                        <div class="px-6 py-4 hover:bg-gray-50 transition-colors">
                            <div class="flex items-center justify-between">
                                <div class="flex items-center space-x-4">
                                    <div class="flex-shrink-0 bg-blue-100 p-2 rounded-lg">
                                        <svg class="w-6 h-6 text-blue-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"></path>
                                        </svg>
                                    </div>
                                    <div>
                                        <div class="text-sm font-medium text-gray-900"><?php echo htmlspecialchars($doc['original_name'] ?? 'Untitled', ENT_QUOTES, 'UTF-8'); ?></div>
                                        <div class="text-sm text-gray-500">
                                            Deleted 
                                            <?php 
                                                $date = isset($doc['deleted_at']) && $doc['deleted_at'] instanceof \MongoDB\BSON\UTCDateTime
                                                    ? $doc['deleted_at']->toDateTime()->format('Y-m-d H:i')
                                                    : (isset($doc['uploaded_at']) && $doc['uploaded_at'] instanceof \MongoDB\BSON\UTCDateTime
                                                        ? $doc['uploaded_at']->toDateTime()->format('Y-m-d H:i')
                                                        : 'Unknown date');
                                                echo htmlspecialchars($date, ENT_QUOTES, 'UTF-8');
                                            ?>
                                        </div>
                                    </div>
                                </div>
                                <div class="flex items-center space-x-4">
                                    <?php if ($auth->hasPermission('delete')): ?>
                                        <a href="?action=restore&id=<?php echo htmlspecialchars((string)($doc['_id'] ?? ''), ENT_QUOTES, 'UTF-8'); ?>" class="text-green-600 hover:text-green-900" aria-label="Restore document" onclick="return confirm('Are you sure you want to restore this document?');">Restore</a>
                                    <?php endif; ?>
                                </div>
                            </div>
                        </div>
                    <?php endforeach; ?>
                <?php endif; ?>
            </div>
        </div>
    </main>

    <?php include dirname(__DIR__) . '/partials/footer.php'; ?>

    <script>
        const openModalBtn = document.getElementById('open-upload-modal');
        const modal = document.getElementById('upload-modal');
        const closeModalBtn = document.getElementById('close-upload-modal');
        const cancelBtn = document.getElementById('cancel-upload');
        const closePermBtn = document.getElementById('close-upload-modal-perm');

        if (openModalBtn) {
            openModalBtn.addEventListener('click', () => {
                modal.classList.remove('hidden');
                modal.focus();
            });
        }

        if (closeModalBtn) {
            closeModalBtn.addEventListener('click', () => {
                modal.classList.add('hidden');
            });
        }

        if (cancelBtn) {
            cancelBtn.addEventListener('click', () => {
                modal.classList.add('hidden');
            });
        }

        if (closePermBtn) {
            closePermBtn.addEventListener('click', () => {
                modal.classList.add('hidden');
            });
        }

        modal.addEventListener('click', (e) => {
            if (e.target === modal) {
                modal.classList.add('hidden');
            }
        });

        modal.addEventListener('keydown', (e) => {
            if (e.key === 'Escape') {
                modal.classList.add('hidden');
            }
        });
    </script>
</body>
</html>