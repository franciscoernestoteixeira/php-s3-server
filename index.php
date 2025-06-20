<?php
declare(strict_types=1);

require 'helpers.php'; // Load helper functions (environment loader, logging, signature check, etc.)

// Enable error display for debugging
ini_set('display_errors', '1');
error_reporting(E_ALL);

// ===== Load .env with flexible spacing =====
loadEnv(__DIR__ . '/.env'); // Load environment variables from .env file

// ===== Environment variables and paths =====
$debug = envToBool($_ENV['DEBUG'] ?? false); // Enable debug mode if DEBUG=true
$accessKey = $_ENV['ACCESS_KEY'] ?? '';       // AWS-like access key for authentication
$secretKey = $_ENV['SECRET_KEY'] ?? '';       // AWS-like secret key for signature verification
$storageRoot = __DIR__ . '/' . ($_ENV['STORAGE_ROOT'] ?? '../data'); // Storage root path for file storage
$logFile = __DIR__ . '/' . ($_ENV['LOG_FILE'] ?? 'activities.log');  // Log file location

// ===== Fatal Error Logging =====
set_exception_handler(function ($e) {
    global $logFile;

    // Log the unhandled exception
    file_put_contents($logFile, "[EXCEPTION] " . $e->getMessage() . PHP_EOL, FILE_APPEND);

    // Respond with 500 Internal Error in AWS S3 XML error format
    http_response_code(500);
    header('Content-Type: application/xml');
    echo "<Error><Code>InternalError</Code><Message>Unhandled Exception</Message></Error>";
    exit;
});

// ===== Request Start Logging =====
logMessage("======== NEW REQUEST ========");
logMessage($_SERVER['REQUEST_METHOD'] . ' ' . $_SERVER['REQUEST_URI']);

// Log all request headers
foreach (getallheaders() as $name => $value) {
    logMessage("Header: $name: $value");
}

// ===== Signature Verification =====
checkSignature(); // Validate AWS Signature V4 authorization header

// ===== Parse Bucket and Key from URL path =====
$path = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH); // Extract request path
$uri = trim($path, '/');                                  // Remove leading and trailing slashes
$parts = explode('/', $uri, 2);                           // Split into bucket and key parts
$bucket = $parts[0] ?? '';                                // Bucket name
$key = $parts[1] ?? '';                                   // Object key inside the bucket
$bucketDir = "$storageRoot/$bucket";                      // Local filesystem path for the bucket

logMessage("Parsed bucket: '$bucket' | key: '$key' | dir: '$bucketDir'");

// ===== Route by HTTP Method =====
$method = $_SERVER['REQUEST_METHOD'];

switch ($method) {
    case 'PUT':
        processMethodPut($bucket, $key, $bucketDir);    // Handle bucket creation or object upload
        break;

    case 'HEAD':
        processMethodHead($key, $bucketDir, $bucket);   // Handle HEAD request for object metadata
        break;

    case 'GET':
        processMethodGet($key, $bucketDir, $bucket);    // Handle GET for download or list bucket
        break;

    case 'DELETE':
        processMethodDelete($bucket, $key, $bucketDir); // Handle object or bucket deletion
        break;

    default:
        unknownMethod($method);                         // Respond with 405 for unsupported HTTP methods
}
