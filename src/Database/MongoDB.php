<?php
namespace DocuStream\Database;

use MongoDB\Client;

class MongoDB
{
    private $client;
    private $database;

    public function __construct()
    {
        try {
            $this->client = new Client('mongodb://localhost:27017');
            $this->database = $this->client->selectDatabase('docustream');
        } catch (\Exception $e) {
            error_log("MongoDB connection error: " . $e->getMessage());
            throw new \Exception("Failed to connect to database.");
        }
    }

    public function getCollection($collectionName)
    {
        return $this->database->selectCollection($collectionName);
    }
}