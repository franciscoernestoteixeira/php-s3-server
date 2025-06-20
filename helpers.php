<?php

/**
 * Load environment variables from a .env file with flexible spacing
 *
 * @param string $envPath Full path to the .env file
 * @return void
 */
function loadEnv(string $envPath): void
{
    if (!file_exists($envPath)) {
        return;
    }

    $lines = file($envPath, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);

    foreach ($lines as $line) {
        if (str_starts_with(trim($line), '#') || !str_contains($line, '=')) {
            continue; // Skip comment or invalid lines
        }

        [$key, $value] = preg_split('/\s*=\s*/', $line, 2);

        if ($key !== null && $value !== null) {
            $_ENV[trim($key)] = trim($value);
        }
    }
}

/**
 * Convert .env string values to boolean
 *
 * @param string $value String value from .env (e.g., "true", "false", "1", "0")
 * @return bool
 */
function envToBool(string $value): bool
{
    return filter_var($value, FILTER_VALIDATE_BOOLEAN, FILTER_NULL_ON_FAILURE) ?? false;
}

/**
 * Log a message to the log file if debug mode is enabled
 *
 * @param string $message Text to log
 * @return void
 */
function logMessage(string $message): void
{
    global $debug, $logFile;

    if ($debug) {
        file_put_contents($logFile, "[" . date('Y-m-d H:i:s') . "] " . $message . PHP_EOL, FILE_APPEND);
    }
}

/**
 * Generate a simple XML element with escaped content
 *
 * @param string $tag XML tag name
 * @param string $content Content inside the tag
 * @return string
 */
function xmlElement(string $tag, string $content): string
{
    return "<{$tag}>" . htmlspecialchars($content, ENT_XML1) . "</{$tag}>";
}

/**
 * Parse AWS Signature V4 Authorization header into its components
 *
 * @param string $header The full Authorization header
 * @return array Parsed values: access key, date, region, signed headers, signature
 */
function parseAuthorization(string $header): array
{
    preg_match('/Credential=([^\/]+)\/([\d]{8})\/([^\/]+)\/s3\/aws4_request/', $header, $c);
    preg_match('/SignedHeaders=([^,]+)/', $header, $s);
    preg_match('/Signature=([0-9a-f]+)/', $header, $sig);

    return [
        'AK' => $c[1] ?? '',
        'Date' => $c[2] ?? '',
        'SHA' => $c[3] ?? '',
        'Signed' => $s[1] ?? '',
        'Sig' => $sig[1] ?? ''
    ];
}

/**
 * Generate the AWS V4 signing key
 *
 * @param string $date The signing date (yyyymmdd)
 * @param string $region AWS region (e.g., "us-east-1")
 * @param string $service AWS service (e.g., "s3")
 * @return string Binary signing key
 */
function getSigningKey(string $date, string $region, string $service): string
{
    global $secretKey;

    $kDate = hash_hmac('sha256', $date, "AWS4{$secretKey}", true);
    $kRegion = hash_hmac('sha256', $region, $kDate, true);
    $kService = hash_hmac('sha256', $service, $kRegion, true);

    return hash_hmac('sha256', 'aws4_request', $kService, true);
}

/**
 * Validate AWS Signature V4 authorization for the incoming request
 *
 * @return void
 */
function checkSignature(): void
{
    $hdr = $_SERVER['HTTP_AUTHORIZATION'] ?? '';
    logMessage("Authorization Header: $hdr");

    $auth = parseAuthorization($hdr);
    logMessage("Parsed Auth: " . json_encode($auth));

    // Validate access key
    if ($auth['AK'] !== $GLOBALS['accessKey']) {
        http_response_code(403);
        header('Content-Type: application/xml');
        logMessage("Access Key mismatch");
        echo "<Error><Code>AccessDenied</Code><Message>Invalid Access Key</Message></Error>";
        exit;
    }

    $method = $_SERVER['REQUEST_METHOD'];
    $path = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
    $qs = $_SERVER['QUERY_STRING'] ?? '';

    // Generate canonical query string
    $canonicalQueryString = '';
    if ($qs) {
        parse_str($qs, $queryParts);
        ksort($queryParts);
        $canonicalQueryString = http_build_query($queryParts, '', '&', PHP_QUERY_RFC3986);
    }

    // Canonical headers block
    $signedHeaders = explode(';', $auth['Signed']);
    $canonicalHeaders = '';

    foreach ($signedHeaders as $h) {
        $headerName = strtolower($h);
        switch ($headerName) {
            case 'host':
                $val = $_SERVER['HTTP_HOST'] ?? $_SERVER['SERVER_NAME'];
                break;
            case 'content-type':
                $val = $_SERVER['CONTENT_TYPE'] ?? '';
                break;
            case 'x-amz-date':
                $val = $_SERVER['HTTP_X_AMZ_DATE'] ?? '';
                break;
            case 'x-amz-content-sha256':
                $val = $_SERVER['HTTP_X_AMZ_CONTENT_SHA256'] ?? '';
                break;
            default:
                $key = 'HTTP_' . strtoupper(str_replace('-', '_', $headerName));
                $val = $_SERVER[$key] ?? '';
        }
        $canonicalHeaders .= $headerName . ':' . trim($val) . "\n";
    }

    // Calculate payload hash
    $hashedPayload = $_SERVER['HTTP_X_AMZ_CONTENT_SHA256'] ?? '';
    if (!$hashedPayload) {
        $payload = file_get_contents('php://input');
        $hashedPayload = hash('sha256', $payload);
    }

    // Build canonical request string
    $canonicalRequest = $method . "\n" .
        $path . "\n" .
        $canonicalQueryString . "\n" .
        $canonicalHeaders . "\n" .
        $auth['Signed'] . "\n" .
        $hashedPayload;

    logMessage("CanonicalRequest:\n" . $canonicalRequest);

    $amzDate = $_SERVER['HTTP_X_AMZ_DATE'] ?? '';
    if (!$amzDate) {
        http_response_code(403);
        header('Content-Type: application/xml');
        logMessage("Missing x-amz-date header");
        echo "<Error><Code>MissingDate</Code><Message>x-amz-date header missing</Message></Error>";
        exit;
    }

    // Build string to sign
    $stringToSign = "AWS4-HMAC-SHA256\n" .
        $amzDate . "\n" .
        $auth['Date'] . "/us-east-1/s3/aws4_request\n" .
        hash('sha256', $canonicalRequest);

    logMessage("StringToSign:\n" . $stringToSign);

    $signingKey = getSigningKey($auth['Date'], 'us-east-1', 's3');
    $calcSig = hash_hmac('sha256', $stringToSign, $signingKey);

    logMessage("Calculated Signature: $calcSig");

    // Compare calculated and provided signature
    if (!hash_equals($calcSig, $auth['Sig'])) {
        http_response_code(403);
        header('Content-Type: application/xml');
        logMessage("Signature mismatch");
        echo "<Error><Code>SignatureDoesNotMatch</Code><Message>Calculated: $calcSig | Received: {$auth['Sig']}</Message></Error>";
        exit;
    }

    logMessage("Signature OK");
}

/**
 * Handle PUT requests (either bucket creation or object upload)
 *
 * @param string $bucket Name of the bucket from URL
 * @param string $key Object key inside the bucket (optional)
 * @param string $bucketDir Filesystem path for the bucket
 * @return void
 */
function processMethodPut(string $bucket, string $key, string $bucketDir): void
{
    if (!empty($bucket) && empty($key)) {
        createBucket($bucketDir, $bucket);
    } else {
        uploadObject($bucketDir, $key, $bucket);
    }
}

/**
 * Create a new bucket (directory) on the local filesystem
 *
 * @param string $bucketDir Target directory path for the bucket
 * @param string $bucket Bucket name (for XML response)
 * @return void
 */
function createBucket(string $bucketDir, string $bucket): void
{
    if (!is_dir($bucketDir)) {
        if (!mkdir($bucketDir, 0777, true)) {
            http_response_code(500);
            header('Content-Type: application/xml');
            logMessage("Failed to create bucket: $bucketDir");
            echo "<Error><Code>InternalError</Code><Message>Could not create bucket directory</Message></Error>";
            exit;
        }

        http_response_code(200);
        header('Content-Type: application/xml');
        echo "<CreateBucketResult><Location>/$bucket</Location></CreateBucketResult>";
        logMessage("Bucket created: $bucket");
    } else {
        http_response_code(409);
        header('Content-Type: application/xml');
        echo "<Error><Code>BucketAlreadyExists</Code><Message>Bucket already exists</Message></Error>";
        logMessage("Bucket already exists: $bucket");
    }
}

/**
 * Upload an object (file) to the target bucket
 * Supports both regular and AWS chunked payload modes
 *
 * @param string $bucketDir Filesystem bucket directory
 * @param string $key Object key (relative path inside bucket)
 * @param string $bucket Bucket name (for logging)
 * @return void
 */
function uploadObject(string $bucketDir, string $key, string $bucket): void
{
    $fullPath = "$bucketDir/$key";
    $dirPath = dirname($fullPath);

    if (!is_dir($dirPath)) {
        mkdir($dirPath, 0777, true);
    }

    $out = fopen($fullPath, 'w');
    $in = fopen('php://input', 'r');

    $isChunked = ($_SERVER['HTTP_X_AMZ_CONTENT_SHA256'] ?? '') === 'STREAMING-UNSIGNED-PAYLOAD-TRAILER';
    logMessage("Upload mode: " . ($isChunked ? 'aws-chunked' : 'normal'));

    if ($isChunked) {
        // AWS chunked payload streaming mode
        while (true) {
            $chunkHeader = fgets($in);
            if ($chunkHeader === false) break;

            $chunkHeader = trim($chunkHeader);
            if ($chunkHeader === '') continue;

            $semiPos = strpos($chunkHeader, ';');
            $sizeHex = $semiPos !== false ? substr($chunkHeader, 0, $semiPos) : $chunkHeader;

            if (!ctype_xdigit($sizeHex)) {
                logMessage("Invalid chunk size header: '$chunkHeader'");
                break;
            }

            $chunkSize = hexdec($sizeHex);
            if ($chunkSize === 0) {
                // Final chunk with size=0, read trailer headers
                while (($line = fgets($in)) !== false) {
                    if (trim($line) === '') break;
                }
                logMessage("Reached final chunk (size=0)");
                break;
            }

            $remaining = $chunkSize;
            while ($remaining > 0) {
                $buffer = fread($in, min(8192, $remaining));
                if ($buffer === false || strlen($buffer) === 0) {
                    logMessage("EOF or error while reading chunk data");
                    break 2;
                }
                fwrite($out, $buffer);
                $remaining -= strlen($buffer);
            }

            fgets($in); // Consume trailing CRLF
        }
    } else {
        // Normal upload (non-chunked)
        while (!feof($in)) {
            $buffer = fread($in, 8192);
            if ($buffer !== false) fwrite($out, $buffer);
        }
    }

    fclose($in);
    fclose($out);
    logMessage("Object saved ($bucket/$key)");

    http_response_code(200);
    header('Content-Type: application/xml');
    echo "<PutObjectResult/>";
}

/**
 * Handle HEAD requests to check object existence
 *
 * @param string $key Object key to check
 * @param string $bucketDir Path to the bucket directory
 * @param string $bucket Bucket name (for logging)
 * @return void
 */
function processMethodHead(string $key, string $bucketDir, string $bucket): void
{
    if (!empty($key)) {
        keyExistenceVerifier($bucketDir, $key);
    } else {
        keyIsMissing($bucket, $key);
    }
}

/**
 * Verify if the given key (object) exists in the bucket
 *
 * @param string $bucketDir Bucket directory
 * @param string $key Object key
 * @return void
 */
function keyExistenceVerifier(string $bucketDir, string $key): void
{
    $f = "$bucketDir/$key";
    $realPath = realpath($f);

    logMessage("HEAD request for key='$key' | Full path='$f' | Realpath='$realPath'");

    if ($realPath !== false && is_file($realPath)) {
        header('Content-Type: application/octet-stream');
        http_response_code(200);
        logMessage("HEAD 200 OK: $realPath");
    } else {
        http_response_code(404);
        header('Content-Type: application/xml');
        echo "<Error><Code>NoSuchKey</Code><Message>Object not found</Message></Error>";
        logMessage("HEAD 404 Not Found: $f");
    }
}

/**
 * Respond to invalid HEAD requests missing the key
 *
 * @param string $bucket Bucket name
 * @param string $key Object key (empty)
 * @return void
 */
function keyIsMissing(string $bucket, string $key): void
{
    http_response_code(400);
    header('Content-Type: application/xml');
    echo "<Error><Code>InvalidRequest</Code><Message>HEAD request without key</Message></Error>";
    logMessage("HEAD 400 Invalid: bucket='$bucket' key='$key'");
}

/**
 * Handle GET requests (object download or bucket list)
 *
 * @param string $key Object key (optional, empty means list bucket)
 * @param string $bucketDir Filesystem bucket path
 * @param string $bucket Bucket name
 * @return void
 */
function processMethodGet(string $key, string $bucketDir, string $bucket): void
{
    if (!empty($key)) {
        downloadObject($bucketDir, $key, $bucket);
    } else {
        listAllObjectsInTheBucket($bucketDir, $bucket);
    }
}

/**
 * Download the requested object as binary stream
 *
 * @param string $bucketDir Bucket directory
 * @param string $key Object key (file path inside bucket)
 * @param string $bucket Bucket name
 * @return void
 */
function downloadObject(string $bucketDir, string $key, string $bucket): void
{
    $f = "$bucketDir/$key";

    if (is_file($f)) {
        header('Content-Type: application/octet-stream');
        readfile($f);
        logMessage("Object read: $bucket/$key");
    } elseif (is_dir($f)) {
        http_response_code(404);
        header('Content-Type: application/xml');
        echo "<Error><Code>NoSuchKey</Code><Message>Expected a file but found a directory</Message></Error>";
        logMessage("GET attempted on a directory (invalid): $bucket/$key");
    } else {
        http_response_code(404);
        header('Content-Type: application/xml');
        echo "<Error><Code>NoSuchKey</Code><Message>Object not found</Message></Error>";
        logMessage("Object not found: $bucket/$key");
    }
}

/**
 * List all objects inside the given bucket
 *
 * @param string $bucketDir Filesystem bucket path
 * @param string $bucket Bucket name
 * @return void
 */
function listAllObjectsInTheBucket(string $bucketDir, string $bucket): void
{
    logMessage("Checking bucket directory: $bucketDir");

    if (!is_dir($bucketDir)) {
        http_response_code(404);
        header('Content-Type: application/xml');
        echo "<Error><Code>NoSuchBucket</Code><Message>Bucket not found</Message></Error>";
        logMessage("Bucket not found: $bucketDir");
        exit;
    }

    $objects = listObjectsRecursively($bucketDir);
    header('Content-Type: application/xml');
    echo "<ListBucketResult>" . xmlElement('Name', $bucket);

    foreach ($objects as $o) {
        echo "<Contents>" . xmlElement('Key', $o) . "</Contents>";
    }

    echo "</ListBucketResult>";
    logMessage("ListBucket: $bucket");
}

/**
 * Recursively list all files and folders inside a directory
 *
 * @param string $dir Directory to scan
 * @param string $prefix Path prefix for returned keys
 * @return array List of object keys (relative paths)
 */
function listObjectsRecursively(string $dir, string $prefix = ''): array
{
    $result = [];
    $items = array_diff(scandir($dir), ['.', '..']);

    foreach ($items as $item) {
        $path = "$dir/$item";
        $key = $prefix . $item;
        if (is_dir($path)) {
            $result = array_merge($result, listObjectsRecursively($path, $key . '/'));
        } else {
            $result[] = $key;
        }
    }

    return $result;
}

/**
 * Handle DELETE requests (object delete or bucket delete)
 *
 * @param string $bucket Bucket name
 * @param string $key Object key (optional)
 * @param string $bucketDir Filesystem path for the bucket
 * @return void
 */
function processMethodDelete(string $bucket, string $key, string $bucketDir): void
{
    if (!empty($bucket) && empty($key)) {
        deleteBucket($bucketDir, $bucket);
    } elseif (!empty($key)) {
        deleteKey($bucketDir, $key, $bucket);
    } else {
        invalidDeleteRequest($bucket, $key);
    }
}

/**
 * Recursively delete a bucket (all files and subfolders)
 *
 * @param string $bucketDir Full path of the bucket
 * @param string $bucket Bucket name
 * @return void
 */
function deleteBucket(string $bucketDir, string $bucket): void
{
    if (!is_dir($bucketDir)) {
        http_response_code(404);
        header('Content-Type: application/xml');
        echo "<Error><Code>NoSuchBucket</Code><Message>Bucket not found</Message></Error>";
        logMessage("Bucket not found for deletion: $bucketDir");
        exit;
    }

    /**
     * Recursive helper for deleting a directory tree
     *
     * @param string $dir Directory path
     * @return bool True on success
     */
    function deleteDirectory(string $dir): bool
    {
        $items = array_diff(scandir($dir), ['.', '..']);
        foreach ($items as $item) {
            $path = "$dir/$item";
            if (is_dir($path)) {
                deleteDirectory($path);
            } else {
                unlink($path);
            }
        }
        return rmdir($dir);
    }

    if (deleteDirectory($bucketDir)) {
        http_response_code(204);
        logMessage("Bucket deleted recursively: $bucket");
    } else {
        http_response_code(500);
        header('Content-Type: application/xml');
        echo "<Error><Code>InternalError</Code><Message>Failed to delete bucket directory</Message></Error>";
        logMessage("Failed to delete bucket directory: $bucketDir");
    }
}

/**
 * Delete a single object (file) inside a bucket
 *
 * @param string $bucketDir Bucket directory path
 * @param string $key Object key
 * @param string $bucket Bucket name
 * @return void
 */
function deleteKey(string $bucketDir, string $key, string $bucket): void
{
    $f = "$bucketDir/$key";

    if (is_file($f)) {
        unlink($f);
        http_response_code(204);
        logMessage("Object deleted: $bucket/$key");
    } else {
        http_response_code(404);
        header('Content-Type: application/xml');
        echo "<Error><Code>NoSuchKey</Code><Message>Object not found</Message></Error>";
        logMessage("Delete failed, not found: $bucket/$key");
    }
}

/**
 * Return a 400 error for invalid DELETE requests (neither bucket nor key specified)
 *
 * @param string $bucket Bucket name
 * @param string $key Object key
 * @return void
 */
function invalidDeleteRequest(string $bucket, string $key): void
{
    http_response_code(400);
    header('Content-Type: application/xml');
    echo "<Error><Code>InvalidRequest</Code><Message>Invalid DELETE request</Message></Error>";
    logMessage("Invalid DELETE request: bucket='$bucket' key='$key'");
}

/**
 * Return a 405 Method Not Allowed for unsupported HTTP verbs
 *
 * @param mixed $method The received HTTP method
 * @return void
 */
function unknownMethod(mixed $method): void
{
    http_response_code(405);
    header('Content-Type: application/xml');
    echo "<Error><Code>MethodNotAllowed</Code><Message>Invalid method</Message></Error>";
    logMessage("Method not allowed: $method");
}
