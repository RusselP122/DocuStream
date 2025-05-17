<?php
session_start();
if (isset($_SESSION['last_activity'])) {
    $_SESSION['last_activity'] = time();
}

require_once __DIR__ . '/../vendor/autoload.php';
require_once __DIR__ . '/../config/config.php';
require_once __DIR__ . '/../src/Auth/Auth.php';
require_once __DIR__ . '/../src/Document/Document.php';

use DocuStream\Auth\Auth;
use DocuStream\Document\Document;

$auth = new Auth();
$document = new Document();

// Generate CSRF token if not set
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

$action = filter_input(INPUT_GET, 'action', FILTER_SANITIZE_STRING) ?? 'dashboard';
$protectedActions = [
    'dashboard', 'upload', 'search', 'admin', 'edit_user',
    'view', 'download', 'archive', 'delete', 'restore',
    'approve_document', 'reject_document'
];

if (in_array($action, $protectedActions) && !$auth->isAuthenticated()) {
    $_SESSION['error'] = 'Please log in to access this page.';
    header('Location: ?action=login');
    exit;
}

// Centralized permission check
function requirePermission(Auth $auth, string $permission, string $redirect = '?action=dashboard'): void
{
    if (!$auth->hasPermission($permission)) {
        $_SESSION['error'] = 'Permission denied.';
        header("Location: $redirect");
        exit;
    }
}

switch ($action) {
    case 'register':
        if ($_SERVER['REQUEST_METHOD'] === 'POST') {
            $username = filter_input(INPUT_POST, 'username', FILTER_SANITIZE_STRING);
            $email = filter_input(INPUT_POST, 'email', FILTER_SANITIZE_EMAIL);
            $password = $_POST['password'] ?? '';
            if ($username && $email && $password) {
                if ($auth->register($username, $email, $password)) {
                    $_SESSION['message'] = 'Registration successful. Please log in.';
                    header('Location: ?action=login');
                    exit;
                } else {
                    $error = 'Registration failed. Email may already be in use.';
                }
            } else {
                $error = 'All fields are required.';
            }
        }
        include __DIR__ . '/../templates/auth/register.php';
        break;

    case 'login':
        if ($_SERVER['REQUEST_METHOD'] === 'POST') {
            $email = filter_input(INPUT_POST, 'email', FILTER_SANITIZE_EMAIL);
            $password = $_POST['password'] ?? '';
            if ($email && $password) {
                if ($auth->login($email, $password)) {
                    header('Location: ?action=dashboard');
                    exit;
                } else {
                    $error = 'Invalid email or password.';
                }
            } else {
                $error = 'Email and password are required.';
            }
        }
        include __DIR__ . '/../templates/auth/login.php';
        break;

    case 'logout':
        $auth->logout();
        $_SESSION['message'] = 'Logged out successfully.';
        header('Location: ?action=login');
        exit;

    case 'forgot_password':
        if ($_SERVER['REQUEST_METHOD'] === 'POST') {
            $email = filter_input(INPUT_POST, 'email', FILTER_SANITIZE_EMAIL);
            if ($email) {
                if ($auth->initiatePasswordReset($email)) {
                    $message = 'Password reset link sent to your email.';
                } else {
                    $error = 'Failed to send reset link. Please check your email.';
                }
            } else {
                $error = 'Email is required.';
            }
        }
        include __DIR__ . '/../templates/auth/forgot_password.php';
        break;

    case 'reset_password':
        if ($_SERVER['REQUEST_METHOD'] === 'POST') {
            $token = filter_input(INPUT_POST, 'token', FILTER_SANITIZE_STRING);
            $password = $_POST['password'] ?? '';
            if ($token && $password) {
                if ($auth->resetPassword($token, $password)) {
                    $_SESSION['message'] = 'Password reset successful. Please log in.';
                    header('Location: ?action=login');
                    exit;
                } else {
                    $error = 'Invalid or expired reset token.';
                }
            } else {
                $error = 'Token and password are required.';
            }
        }
        include __DIR__ . '/../templates/auth/reset_password.php';
        break;

    case 'dashboard':
        include __DIR__ . '/../templates/dashboard/index.php';
        break;

    case 'upload':
        requirePermission($auth, 'upload');
        if ($_SERVER['REQUEST_METHOD'] === 'POST') {
            if (!$auth->validateCsrfToken($_POST['csrf_token'] ?? '')) {
                $_SESSION['error'] = 'Invalid CSRF token.';
                header('Location: ?action=dashboard');
                exit;
            }
            $file = $_FILES['document'] ?? null;
            $category = filter_input(INPUT_POST, 'category', FILTER_SANITIZE_STRING);
            $metadata = isset($_POST['metadata']) && is_array($_POST['metadata'])
                ? array_map('filter_var', $_POST['metadata'], array_fill(0, count($_POST['metadata']), FILTER_SANITIZE_STRING))
                : [];
            $requiresApproval = !$auth->isAdmin();
            $result = $document->upload($file, $category, $metadata, $_SESSION['user_id'], $requiresApproval);
            $_SESSION[$result['success'] ? 'message' : 'error'] = $result['message'];
            header('Location: ?action=dashboard');
            exit;
        }
        include __DIR__ . '/../templates/dashboard/index.php';
        break;

    case 'search':
        requirePermission($auth, 'view');
        $keyword = filter_input(INPUT_GET, 'keyword', FILTER_SANITIZE_STRING) ?? '';
        $category = filter_input(INPUT_GET, 'category', FILTER_SANITIZE_STRING) ?? '';
        $metadata = isset($_GET['metadata']) && is_array($_GET['metadata'])
            ? array_map('filter_var', $_GET['metadata'], array_fill(0, count($_GET['metadata']), FILTER_SANITIZE_STRING))
            : [];
        $dateRange = isset($_GET['date_range']) && is_array($_GET['date_range'])
            ? array_map('filter_var', $_GET['date_range'], array_fill(0, count($_GET['date_range']), FILTER_SANITIZE_STRING))
            : [];
        $results = iterator_to_array($document->search($keyword, $category, $metadata, $dateRange));
        include __DIR__ . '/../templates/dashboard/search.php';
        break;

    case 'view':
        requirePermission($auth, 'view');
        $documentId = filter_input(INPUT_GET, 'id', FILTER_SANITIZE_STRING);
        if ($documentId && preg_match('/^[a-f\d]{24}$/i', $documentId)) {
            $doc = $document->getDocument($documentId);
            if ($doc && ($doc['user_id'] === $_SESSION['user_id'] || $auth->isAdmin())) {
                $filePath = UPLOAD_DIR . $doc['file_name'];
                if (file_exists($filePath)) {
                    $fileType = strtolower(pathinfo($filePath, PATHINFO_EXTENSION));
                    if ($fileType === 'pdf') {
                        header('Content-Type: application/pdf');
                        header('Content-Disposition: inline; filename="' . $doc['original_name'] . '"');
                        readfile($filePath);
                        exit;
                    } elseif ($fileType === 'txt') {
                        $content = file_get_contents($filePath);
                        include __DIR__ . '/../templates/dashboard/view_text.php';
                        exit;
                    } else {
                        $_SESSION['error'] = 'This file type can only be downloaded.';
                    }
                } else {
                    $_SESSION['error'] = 'File not found.';
                }
            } else {
                $_SESSION['error'] = 'Document not found or access denied.';
            }
        } else {
            $_SESSION['error'] = 'Invalid document ID.';
        }
        header('Location: ?action=dashboard');
        exit;

    case 'download':
        requirePermission($auth, 'download');
        $documentId = filter_input(INPUT_GET, 'id', FILTER_SANITIZE_STRING);
        if ($documentId && preg_match('/^[a-f\d]{24}$/i', $documentId)) {
            $doc = $document->getDocument($documentId);
            if ($doc && ($doc['user_id'] === $_SESSION['user_id'] || $auth->isAdmin())) {
                $filePath = UPLOAD_DIR . $doc['file_name'];
                if (file_exists($filePath)) {
                    header('Content-Type: application/octet-stream');
                    header('Content-Disposition: attachment; filename="' . $doc['original_name'] . '"');
                    header('Content-Length: ' . filesize($filePath));
                    readfile($filePath);
                    exit;
                }
            }
            $_SESSION['error'] = 'Document not found or access denied.';
        } else {
            $_SESSION['error'] = 'Invalid document ID.';
        }
        header('Location: ?action=dashboard');
        exit;

    case 'archive':
        requirePermission($auth, 'archive');
        $documentId = filter_input(INPUT_GET, 'id', FILTER_SANITIZE_STRING);
        if ($documentId && preg_match('/^[a-f\d]{24}$/i', $documentId)) {
            if ($document->archive($documentId)) {
                $_SESSION['message'] = 'Document archived successfully.';
            } else {
                $_SESSION['error'] = 'Failed to archive document.';
            }
        } else {
            $_SESSION['error'] = 'Invalid document ID.';
        }
        header('Location: ?action=dashboard');
        exit;

    case 'delete':
        requirePermission($auth, 'delete');
        $documentId = filter_input(INPUT_GET, 'id', FILTER_SANITIZE_STRING);
        if ($documentId && preg_match('/^[a-f\d]{24}$/i', $documentId)) {
            if ($document->delete($documentId)) {
                $_SESSION['message'] = 'Document moved to trash.';
            } else {
                $_SESSION['error'] = 'Failed to delete document.';
            }
        } else {
            $_SESSION['error'] = 'Invalid document ID.';
        }
        header('Location: ?action=dashboard');
        exit;

    case 'restore':
        requirePermission($auth, 'delete');
        $documentId = filter_input(INPUT_GET, 'id', FILTER_SANITIZE_STRING);
        if ($documentId && preg_match('/^[a-f\d]{24}$/i', $documentId)) {
            if ($document->restore($documentId)) {
                $_SESSION['message'] = 'Document restored successfully.';
            } else {
                $_SESSION['error'] = 'Failed to restore document.';
            }
        } else {
            $_SESSION['error'] = 'Invalid document ID.';
        }
        header('Location: ?action=dashboard');
        exit;

    case 'approve_document':
        if ($auth->isAdmin()) {
            $documentId = filter_input(INPUT_GET, 'id', FILTER_SANITIZE_STRING);
            $csrfToken = filter_input(INPUT_GET, 'csrf_token', FILTER_SANITIZE_STRING);
            if ($documentId && preg_match('/^[a-f\d]{24}$/i', $documentId) && $auth->validateCsrfToken($csrfToken)) {
                if ($document->approveDocument($documentId)) {
                    $_SESSION['message'] = 'Document approved successfully.';
                } else {
                    $_SESSION['error'] = 'Failed to approve document.';
                }
            } else {
                $_SESSION['error'] = 'Invalid document ID or CSRF token.';
            }
            header('Location: ?action=admin');
            exit;
        }
        $_SESSION['error'] = 'Admin access required.';
        header('Location: ?action=dashboard');
        exit;

    case 'reject_document':
        if ($auth->isAdmin()) {
            $documentId = filter_input(INPUT_GET, 'id', FILTER_SANITIZE_STRING);
            $csrfToken = filter_input(INPUT_GET, 'csrf_token', FILTER_SANITIZE_STRING);
            if ($documentId && preg_match('/^[a-f\d]{24}$/i', $documentId) && $auth->validateCsrfToken($csrfToken)) {
                if ($document->rejectDocument($documentId)) {
                    $_SESSION['message'] = 'Document rejected and moved to trash.';
                } else {
                    $_SESSION['error'] = 'Failed to reject document.';
                }
            } else {
                $_SESSION['error'] = 'Invalid document ID or CSRF token.';
            }
            header('Location: ?action=admin');
            exit;
        }
        $_SESSION['error'] = 'Admin access required.';
        header('Location: ?action=dashboard');
        exit;

    case 'admin':
        if ($auth->isAdmin()) {
            if ($_SERVER['REQUEST_METHOD'] === 'POST') {
                $csrfToken = filter_input(INPUT_POST, 'csrf_token', FILTER_SANITIZE_STRING);
                if (!$auth->validateCsrfToken($csrfToken)) {
                    $_SESSION['error'] = 'Invalid CSRF token.';
                    header('Location: ?action=admin');
                    exit;
                }
                $userId = filter_input(INPUT_POST, 'user_id', FILTER_SANITIZE_STRING);
                if ($userId && preg_match('/^[a-f\d]{24}$/i', $userId)) {
                    $updates = [
                        'username' => filter_input(INPUT_POST, 'username', FILTER_SANITIZE_STRING),
                        'email' => filter_input(INPUT_POST, 'email', FILTER_SANITIZE_EMAIL),
                        'isAdmin' => filter_var(isset($_POST['is_admin']), FILTER_VALIDATE_BOOLEAN),
                        'permissions' => isset($_POST['permissions']) && is_array($_POST['permissions'])
                            ? array_intersect($_POST['permissions'], VALID_PERMISSIONS)
                            : []
                    ];
                    if (!empty($_POST['password'])) {
                        $updates['password'] = $_POST['password'];
                    }
                    if ($updates['username'] && $updates['email']) {
                        if ($auth->manageUser($userId, $updates, $_SESSION['user_id'])) {
                            $_SESSION['message'] = 'User updated successfully.';
                        } else {
                            $_SESSION['error'] = 'Failed to update user. Ensure the email is unique and you are not removing your own admin status.';
                        }
                    } else {
                        $_SESSION['error'] = 'Username and email are required.';
                    }
                } else {
                    $_SESSION['error'] = 'Invalid user ID.';
                }
                header('Location: ?action=admin');
                exit;
            }
            $users = $auth->getUsers();
            $pendingDocuments = iterator_to_array($document->getPendingDocuments());
            include __DIR__ . '/../templates/admin/index.php';
        } else {
            $_SESSION['error'] = 'Admin access required.';
            header('Location: ?action=dashboard');
            exit;
        }
        break;

    case 'edit_user':
        if ($auth->isAdmin()) {
            $userId = filter_input(INPUT_GET, 'id', FILTER_SANITIZE_STRING);
            if ($userId && preg_match('/^[a-f\d]{24}$/i', $userId)) {
                $user = $auth->getUserById($userId);
                if ($user) {
                    include __DIR__ . '/../templates/admin/edit_user.php';
                    exit;
                }
                $_SESSION['error'] = 'User not found.';
            } else {
                $_SESSION['error'] = 'Invalid user ID.';
            }
            header('Location: ?action=admin');
            exit;
        }
        $_SESSION['error'] = 'Admin access required.';
        header('Location: ?action=dashboard');
        exit;

    default:
        if ($auth->isAuthenticated()) {
            header('Location: ?action=dashboard');
        } else {
            header('Location: ?action=login');
        }
        exit;
}