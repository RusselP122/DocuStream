<?php
namespace DocuStream\Document;

use MongoDB\BSON\ObjectId;
use MongoDB\BSON\UTCDateTime;
use DocuStream\Database\MongoDB;

class Document
{
    private $documentsCollection;
    private $trashCollection;

    public function __construct()
    {
        $mongo = new MongoDB();
        $this->documentsCollection = $mongo->getCollection('documents');
        $this->trashCollection = $mongo->getCollection('trash');
    }

    public function upload($file, $category, $metadata, $userId, $requiresApproval = false)
    {
        try {
            if (!$file || $file['error'] !== UPLOAD_ERR_OK) {
                return ['success' => false, 'message' => 'No file uploaded or upload error.'];
            }

            $fileType = strtolower(pathinfo($file['name'], PATHINFO_EXTENSION));
            if (!in_array($fileType, ALLOWED_FILE_TYPES)) {
                return ['success' => false, 'message' => 'Invalid file type. Allowed: ' . implode(', ', ALLOWED_FILE_TYPES)];
            }

            if ($file['size'] > MAX_FILE_SIZE) {
                return ['success' => false, 'message' => 'File exceeds maximum size of ' . (MAX_FILE_SIZE / 1024 / 1024) . 'MB.'];
            }

            // Basic file content validation (e.g., check for valid PDF)
            if ($fileType === 'pdf' && !str_starts_with(file_get_contents($file['tmp_name']), '%PDF-')) {
                return ['success' => false, 'message' => 'Invalid PDF file.'];
            }

            $fileName = uniqid('doc_', true) . '.' . $fileType;
            $destination = UPLOAD_DIR . $fileName;

            if (!move_uploaded_file($file['tmp_name'], $destination)) {
                return ['success' => false, 'message' => 'Failed to save file to server.'];
            }

            $category = filter_var($category, FILTER_SANITIZE_STRING) ?: 'Uncategorized';
            $metadata = array_map('filter_var', $metadata, array_fill(0, count($metadata), FILTER_SANITIZE_STRING));

            $status = $requiresApproval ? 'pending' : 'approved';
            $result = $this->documentsCollection->insertOne([
                'file_name' => $fileName,
                'original_name' => filter_var($file['name'], FILTER_SANITIZE_STRING),
                'category' => $category,
                'metadata' => $metadata,
                'user_id' => $userId,
                'status' => $status,
                'uploaded_at' => new UTCDateTime(),
                'archived' => false
            ]);

            return [
                'success' => $result->getInsertedCount() === 1,
                'message' => $requiresApproval ? 'File uploaded, pending approval.' : 'File uploaded successfully.',
                'document_id' => (string) $result->getInsertedId()
            ];
        } catch (\Exception $e) {
            error_log("Upload error: " . $e->getMessage());
            return ['success' => false, 'message' => 'Upload failed due to a server error.'];
        }
    }

    public function getDocument($documentId)
    {
        try {
            if (!preg_match('/^[a-f\d]{24}$/i', $documentId)) {
                return null;
            }
            return $this->documentsCollection->findOne(['_id' => new ObjectId($documentId)]);
        } catch (\Exception $e) {
            error_log("Get document error: " . $e->getMessage());
            return null;
        }
    }

    public function archive($documentId)
    {
        try {
            if (!preg_match('/^[a-f\d]{24}$/i', $documentId)) {
                return false;
            }
            $result = $this->documentsCollection->updateOne(
                ['_id' => new ObjectId($documentId)],
                ['$set' => ['archived' => true, 'archived_at' => new UTCDateTime()]]
            );
            return $result->getModifiedCount() === 1;
        } catch (\Exception $e) {
            error_log("Archive error: " . $e->getMessage());
            return false;
        }
    }

    public function unarchive($documentId)
    {
        try {
            if (!preg_match('/^[a-f\d]{24}$/i', $documentId)) {
                return false;
            }
            $result = $this->documentsCollection->updateOne(
                ['_id' => new ObjectId($documentId)],
                ['$set' => ['archived' => false], '$unset' => ['archived_at' => '']]
            );
            return $result->getModifiedCount() === 1;
        } catch (\Exception $e) {
            error_log("Unarchive error: " . $e->getMessage());
            return false;
        }
    }

    public function delete($documentId)
    {
        try {
            if (!preg_match('/^[a-f\d]{24}$/i', $documentId)) {
                return false;
            }
            $doc = $this->documentsCollection->findOne(['_id' => new ObjectId($documentId)]);
            if (!$doc) {
                return false;
            }
            $result = $this->trashCollection->insertOne([
                'file_name' => $doc['file_name'],
                'original_name' => $doc['original_name'],
                'category' => $doc['category'],
                'metadata' => $doc['metadata'],
                'user_id' => $doc['user_id'],
                'status' => $doc['status'],
                'uploaded_at' => $doc['uploaded_at'],
                'archived' => $doc['archived'],
                'deleted_at' => new UTCDateTime()
            ]);
            if ($result->getInsertedCount() === 1) {
                $this->documentsCollection->deleteOne(['_id' => new ObjectId($documentId)]);
                return true;
            }
            return false;
        } catch (\Exception $e) {
            error_log("Delete error: " . $e->getMessage());
            return false;
        }
    }

    public function approveDocument($documentId)
    {
        try {
            if (!preg_match('/^[a-f\d]{24}$/i', $documentId)) {
                return false;
            }
            $result = $this->documentsCollection->updateOne(
                ['_id' => new ObjectId($documentId)],
                ['$set' => ['status' => 'approved']]
            );
            return $result->getModifiedCount() === 1;
        } catch (\Exception $e) {
            error_log("Approve error: " . $e->getMessage());
            return false;
        }
    }

public function rejectDocument($documentId)
    {
        try {
            if (!preg_match('/^[a-f\d]{24}$/i', $documentId)) {
                return false;
            }
            $doc = $this->documentsCollection->findOne(['_id' => new ObjectId($documentId)]);
            if (!$doc) {
                return false;
            }
            // Delete the associated file from the filesystem
            $filePath = UPLOAD_DIR . $doc['file_name'];
            if (file_exists($filePath)) {
                unlink($filePath);
            }
            // Permanently delete from the documents collection
            $result = $this->documentsCollection->deleteOne(['_id' => new ObjectId($documentId)]);
            return $result->getDeletedCount() === 1;
        } catch (\Exception $e) {
            error_log("Reject error: " . $e->getMessage());
            return false;
        }
    }
    public function restore($documentId)
    {
        try {
            if (!preg_match('/^[a-f\d]{24}$/i', $documentId)) {
                return false;
            }
            $trashDoc = $this->trashCollection->findOne(['_id' => new ObjectId($documentId)]);
            if (!$trashDoc) {
                return false;
            }
            $result = $this->documentsCollection->insertOne([
                'file_name' => $trashDoc['file_name'],
                'original_name' => $trashDoc['original_name'],
                'category' => $trashDoc['category'],
                'metadata' => $trashDoc['metadata'],
                'user_id' => $trashDoc['user_id'],
                'status' => 'approved',
                'uploaded_at' => $trashDoc['uploaded_at'],
                'archived' => $trashDoc['archived']
            ]);
            if ($result->getInsertedCount() === 1) {
                $this->trashCollection->deleteOne(['_id' => new ObjectId($documentId)]);
                return true;
            }
            return false;
        } catch (\Exception $e) {
            error_log("Restore error: " . $e->getMessage());
            return false;
        }
    }

    public function search($keyword, $category, $metadata, $dateRange, $sort = ['uploaded_at' => -1], $limit = 10)
    {
        try {
            $query = ['status' => 'approved', 'archived' => false]; // Only approved, non-archived documents
            if (isset($_SESSION['user_id']) && !$this->isAdmin()) {
                $query['user_id'] = $_SESSION['user_id'];
            }
            if ($keyword) {
                $keyword = filter_var($keyword, FILTER_SANITIZE_STRING);
                $query['$or'] = [
                    ['original_name' => ['$regex' => $keyword, '$options' => 'i']],
                    ['category' => ['$regex' => $keyword, '$options' => 'i']]
                ];
            }
            if ($category) {
                $category = filter_var($category, FILTER_SANITIZE_STRING);
                $query['category'] = ['$regex' => $category, '$options' => 'i'];
            }
            if ($metadata && !empty($metadata['tags'])) {
                $tags = filter_var($metadata['tags'], FILTER_SANITIZE_STRING);
                $query['metadata.tags'] = ['$regex' => $tags, '$options' => 'i'];
            }
            if ($dateRange && !empty($dateRange['start']) && !empty($dateRange['end'])) {
                $start = filter_var($dateRange['start'], FILTER_SANITIZE_STRING);
                $end = filter_var($dateRange['end'], FILTER_SANITIZE_STRING);
                $query['uploaded_at'] = [
                    '$gte' => new UTCDateTime(strtotime($start) * 1000),
                    '$lte' => new UTCDateTime(strtotime($end) * 1000)
                ];
            }
            return $this->documentsCollection->find($query, ['sort' => $sort, 'limit' => $limit]);
        } catch (\Exception $e) {
            error_log("Search error: " . $e->getMessage());
            return [];
        }
    }

    public function getDocumentsCount($query)
    {
        try {
            return $this->documentsCollection->countDocuments($query);
        } catch (\Exception $e) {
            error_log("Count error: " . $e->getMessage());
            return 0;
        }
    }

    public function getTrashedDocuments($userId)
    {
        try {
            if (!preg_match('/^[a-f\d]{24}$/i', $userId)) {
                return [];
            }
            return iterator_to_array($this->trashCollection->find(['user_id' => $userId]));
        } catch (\Exception $e) {
            error_log("Get trashed documents error: " . $e->getMessage());
            return [];
        }
    }

    public function getArchivedDocuments($userId, $limit = 10, $skip = 0)
    {
        try {
            if (!preg_match('/^[a-f\d]{24}$/i', $userId)) {
                return [];
            }
            return iterator_to_array($this->documentsCollection->find(
                ['user_id' => $userId, 'archived' => true, 'status' => 'approved'],
                ['sort' => ['uploaded_at' => -1], 'limit' => $limit, 'skip' => $skip]
            ));
        } catch (\Exception $e) {
            error_log("Get archived documents error: " . $e->getMessage());
            return [];
        }
    }

    public function getPendingDocuments($limit = 50, $skip = 0)
    {
        try {
            return iterator_to_array(
                $this->documentsCollection->find(
                    ['status' => 'pending'],
                    ['limit' => $limit, 'skip' => $skip, 'sort' => ['uploaded_at' => -1]]
                )
            );
        } catch (\Exception $e) {
            error_log("Get pending documents error: " . $e->getMessage());
            return [];
        }
    }

    private function isAdmin()
    {
        $auth = new \DocuStream\Auth\Auth();
        return $auth->isAdmin();
    }
}