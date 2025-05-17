<?php
// config/config.php
define('UPLOAD_DIR', __DIR__ . '/../uploads/');
define('ALLOWED_FILE_TYPES', ['pdf', 'doc', 'docx', 'txt']);
define('MAX_FILE_SIZE', 5 * 1024 * 1024); // 5MB
define('FROM_EMAIL', 'no-reply@docustream.com');
define('BASE_URL', 'https://localhost/DocuStream/public/'); // Use HTTPS in production
define('SESSION_TIMEOUT', 1800); // 30 minutes
define('VALID_PERMISSIONS', ['upload', 'view', 'download', 'archive', 'delete']);

// Ensure upload directory exists and is writable
if (!is_dir(UPLOAD_DIR)) {
    mkdir(UPLOAD_DIR, 0755, true);
}
if (!is_writable(UPLOAD_DIR)) {
    chmod(UPLOAD_DIR, 0755);
}