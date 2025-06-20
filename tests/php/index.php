<?php
require 'vendor/autoload.php';

use Aws\Exception\AwsException;
use Aws\S3\S3Client;

// Disable SSL verification (use only in testing/self-signed environments)
$s3Config = [
    'version' => 'latest',
    'region' => 'us-east-1',
    'endpoint' => 'http://localhost',
    'credentials' => [
        'key' => 'FAKEACCESS',
        'secret' => 'FAKESECRET',
    ],
    'use_path_style_endpoint' => true,
    'http' => [
        'verify' => false,
    ],
];

$s3 = new S3Client($s3Config);

$bucket = 'mybucket';

// Create Bucket
try {
    $s3->createBucket(['Bucket' => $bucket]);
    echo "Bucket '{$bucket}' created.\n";
} catch (AwsException $e) {
    if ($e->getAwsErrorCode() === 'BucketAlreadyExists') {
        echo "Bucket '{$bucket}' already exists.\n";
    } else {
        echo "CreateBucket error: " . $e->getAwsErrorMessage() . "\n";
    }
}

// Upload hello.txt
$timestamp = time();
$textKey = "{$timestamp}_hello.txt";
$body = 'Hello World from PHP';

try {
    $s3->putObject([
        'Bucket' => $bucket,
        'Key' => $textKey,
        'Body' => $body,
        'ContentLength' => strlen($body),
    ]);
    echo "Uploaded: {$textKey}\n";
} catch (AwsException $e) {
    echo "PutObject error: " . $e->getAwsErrorMessage() . "\n";
}

// Upload sample.png and sample.jpg
function uploadFile($s3, $bucket, $filePath, $key)
{
    try {
        $s3->putObject([
            'Bucket' => $bucket,
            'Key' => $key,
            'Body' => fopen($filePath, 'rb'),
            'ContentLength' => filesize($filePath),
        ]);
        echo "Uploaded: {$key}\n";
    } catch (AwsException $e) {
        echo "Upload error for {$key}: " . $e->getAwsErrorMessage() . "\n";
    }
}

foreach (['sample.png', 'sample.jpg'] as $fileName) {
    if (file_exists($fileName)) {
        $randomKey = "{$timestamp}_{$fileName}";
        uploadFile($s3, $bucket, $fileName, $randomKey);
    } else {
        echo "Warning: File '{$fileName}' not found. Skipping upload.\n";
    }
}

// List Objects
try {
    $result = $s3->listObjects(['Bucket' => $bucket]);
    $contents = $result['Contents'] ?? [];
    echo "Objects in bucket:\n";
    foreach ($contents as $obj) {
        echo "- {$obj['Key']}\n";
    }
} catch (AwsException $e) {
    echo "ListObjects error: " . $e->getAwsErrorMessage() . "\n";
}

// Download all objects
foreach ($contents as $obj) {
    $key = $obj['Key'];
    $destPath = "downloaded_" . basename($key);
    try {
        $result = $s3->getObject([
            'Bucket' => $bucket,
            'Key' => $key,
        ]);
        file_put_contents($destPath, $result['Body']);
        echo "Downloaded: {$destPath}\n";
    } catch (AwsException $e) {
        echo "Download error for {$key}: " . $e->getAwsErrorMessage() . "\n";
    }
}

// Delete all objects
foreach ($contents as $obj) {
    $key = $obj['Key'];
    try {
        $s3->deleteObject([
            'Bucket' => $bucket,
            'Key' => $key,
        ]);
        echo "Deleted: {$key}\n";
    } catch (AwsException $e) {
        echo "DeleteObject error for {$key}: " . $e->getAwsErrorMessage() . "\n";
    }
}

// Delete bucket
try {
    $s3->deleteBucket(['Bucket' => $bucket]);
    echo "Bucket '{$bucket}' deleted.\n";
} catch (AwsException $e) {
    echo "DeleteBucket error: " . $e->getAwsErrorMessage() . "\n";
}
