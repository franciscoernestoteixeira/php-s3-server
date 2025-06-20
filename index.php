<?php
declare(strict_types=1);

ini_set('display_errors', '1');
error_reporting(E_ALL);

// ===== Load .env with flexible spacing =====
function loadEnv(string $envPath): void
{
    if (!file_exists($envPath)) return;
    $lines = file($envPath, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    foreach ($lines as $line) {
        if (str_starts_with(trim($line), '#') || strpos($line, '=') === false) continue;
        [$key, $value] = preg_split('/\s*=\s*/', $line, 2);
        if ($key !== null && $value !== null) {
            $_ENV[trim($key)] = trim($value);
        }
    }
}

loadEnv(__DIR__ . '/.env');

$storageRoot = __DIR__ . '/' . ($_ENV['STORAGE_ROOT'] ?? '../data');
$logFile = __DIR__ . '/' . ($_ENV['LOG_FILE'] ?? 'activities.log');
$accessKey = $_ENV['ACCESS_KEY'] ?? '';
$secretKey = $_ENV['SECRET_KEY'] ?? '';
$canLog = true;

// ===== Fatal Error Logging =====
set_exception_handler(function ($e) {
    global $logFile;
    file_put_contents($logFile, "[EXCEPTION] " . $e->getMessage() . PHP_EOL, FILE_APPEND);
    http_response_code(500);
    header('Content-Type: application/xml');
    echo "<Error><Code>InternalError</Code><Message>Unhandled Exception</Message></Error>";
    exit;
});

// ===== Logging Helper =====
function logMessage(string $message): void
{
    global $canLog, $logFile;
    if ($canLog) {
        file_put_contents($logFile, "[" . date('Y-m-d H:i:s') . "] " . $message . PHP_EOL, FILE_APPEND);
    }
}

// ===== XML Element Helper =====
function xmlElement(string $tag, string $content): string
{
    return "<{$tag}>" . htmlspecialchars($content, ENT_XML1) . "</{$tag}>";
}

// ===== Parse AWS Signature V4 Authorization Header =====
function parseAuthorization(string $header): array
{
    preg_match('/Credential=([^\/]+)\/([\d]{8})\/([^\/]+)\/s3\/aws4_request/', $header, $c);
    preg_match('/SignedHeaders=([^,]+)/', $header, $s);
    preg_match('/Signature=([0-9a-f]+)/', $header, $sig);
    return ['AK' => $c[1] ?? '', 'Date' => $c[2] ?? '', 'SHA' => $c[3] ?? '', 'Signed' => $s[1] ?? '', 'Sig' => $sig[1] ?? ''];
}

// ===== Generate AWS Signing Key =====
function getSigningKey(string $date, string $region, string $service): string
{
    global $secretKey;
    $kDate = hash_hmac('sha256', $date, "AWS4{$secretKey}", true);
    $kRegion = hash_hmac('sha256', $region, $kDate, true);
    $kService = hash_hmac('sha256', $service, $kRegion, true);
    return hash_hmac('sha256', 'aws4_request', $kService, true);
}

// ===== Signature Verification =====
function checkSignature(): void
{
    $hdr = $_SERVER['HTTP_AUTHORIZATION'] ?? '';
    logMessage("Authorization Header: $hdr");

    $auth = parseAuthorization($hdr);
    logMessage("Parsed Auth: " . json_encode($auth));

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

    $canonicalQueryString = '';
    if ($qs) {
        parse_str($qs, $queryParts);
        ksort($queryParts);
        $canonicalQueryString = http_build_query($queryParts, '', '&', PHP_QUERY_RFC3986);
    }

    $signedHeaders = explode(';', $auth['Signed']);
    $canonicalHeaders = '';

    foreach ($signedHeaders as $h) {
        $headerName = strtolower($h);
        if ($headerName === 'host') {
            $val = $_SERVER['HTTP_HOST'] ?? $_SERVER['SERVER_NAME'];
        } elseif ($headerName === 'content-type') {
            $val = $_SERVER['CONTENT_TYPE'] ?? '';
        } elseif ($headerName === 'x-amz-date') {
            $val = $_SERVER['HTTP_X_AMZ_DATE'] ?? '';
        } elseif ($headerName === 'x-amz-content-sha256') {
            $val = $_SERVER['HTTP_X_AMZ_CONTENT_SHA256'] ?? '';
        } else {
            $key = 'HTTP_' . strtoupper(str_replace('-', '_', $headerName));
            $val = $_SERVER[$key] ?? '';
        }
        $canonicalHeaders .= $headerName . ':' . trim($val) . "\n";
    }

    $hashedPayload = $_SERVER['HTTP_X_AMZ_CONTENT_SHA256'] ?? '';
    if (!$hashedPayload) {
        $payload = file_get_contents('php://input');
        $hashedPayload = hash('sha256', $payload);
    }

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

    $stringToSign = "AWS4-HMAC-SHA256\n" .
        $amzDate . "\n" .
        $auth['Date'] . "/us-east-1/s3/aws4_request\n" .
        hash('sha256', $canonicalRequest);

    logMessage("StringToSign:\n" . $stringToSign);

    $signingKey = getSigningKey($auth['Date'], 'us-east-1', 's3');
    $calcSig = hash_hmac('sha256', $stringToSign, $signingKey);

    logMessage("Calculated Signature: $calcSig");

    if (!hash_equals($calcSig, $auth['Sig'])) {
        http_response_code(403);
        header('Content-Type: application/xml');
        logMessage("Signature mismatch");
        echo "<Error><Code>SignatureDoesNotMatch</Code><Message>Calculated: $calcSig | Received: {$auth['Sig']}</Message></Error>";
        exit;
    }

    logMessage("Signature OK");
}

// ===== Request Start =====
logMessage("======== NEW REQUEST ========");
logMessage($_SERVER['REQUEST_METHOD'] . ' ' . $_SERVER['REQUEST_URI']);
foreach (getallheaders() as $name => $value) {
    logMessage("Header: $name: $value");
}

checkSignature();

// ===== Parse Bucket and Key =====
$path = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
$uri = trim($path, '/');
$parts = explode('/', $uri, 2);
$bucket = $parts[0] ?? '';
$key = $parts[1] ?? '';
$bucketDir = "$storageRoot/$bucket";
logMessage("Parsed bucket: '$bucket' | key: '$key' | dir: '$bucketDir'");

$method = $_SERVER['REQUEST_METHOD'];

switch ($method) {
    case 'PUT':
        if ($bucket !== '' && $key === '') {
            // Create Bucket
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
        } else {
            // PutObject
            if (!is_dir($bucketDir)) mkdir($bucketDir, 0777, true);
            if (($_SERVER['HTTP_X_AMZ_CONTENT_SHA256'] ?? '') === 'STREAMING-UNSIGNED-PAYLOAD-TRAILER') {
                $in = fopen('php://input', 'r');
                $out = fopen("$bucketDir/$key", 'w');
                while (!feof($in)) {
                    $chunkSizeHex = trim(fgets($in));
                    if ($chunkSizeHex === '' || $chunkSizeHex === '0') break;
                    $chunkSize = hexdec($chunkSizeHex);
                    if ($chunkSize > 0) {
                        $data = fread($in, $chunkSize);
                        fwrite($out, $data);
                    }
                    fgets($in);
                }
                fclose($in);
                fclose($out);
                logMessage("Object saved (chunked): $bucket/$key");
            } else {
                $payload = file_get_contents('php://input');
                if (file_put_contents("$bucketDir/$key", $payload) === false) {
                    http_response_code(500);
                    header('Content-Type: application/xml');
                    logMessage("Failed to save object: $bucket/$key");
                    echo "<Error><Code>InternalError</Code><Message>Could not write object</Message></Error>";
                    exit;
                }
                logMessage("Object saved (non-chunked): $bucket/$key");
            }
            http_response_code(200);
            header('Content-Type: application/xml');
            echo "<PutObjectResult/>";
        }
        break;

    case 'GET':
        if ($key !== '') {
            // GetObject
            $f = "$bucketDir/$key";
            if (is_file($f)) {
                header('Content-Type: application/octet-stream');
                readfile($f);
                logMessage("Object read: $bucket/$key");
            } else {
                http_response_code(404);
                header('Content-Type: application/xml');
                echo "<Error><Code>NoSuchKey</Code><Message>Object not found</Message></Error>";
                logMessage("Object not found: $bucket/$key");
            }
        } else {
            // ListObjects
            logMessage("Checking bucket directory: $bucketDir");
            if (!is_dir($bucketDir)) {
                http_response_code(404);
                header('Content-Type: application/xml');
                echo "<Error><Code>NoSuchBucket</Code><Message>Bucket not found</Message></Error>";
                logMessage("Bucket not found: $bucketDir");
                exit;
            }
            $objs = array_diff(scandir($bucketDir), ['.', '..']);
            header('Content-Type: application/xml');
            echo "<ListBucketResult>" . xmlElement('Name', $bucket);
            foreach ($objs as $o) {
                echo "<Contents>" . xmlElement('Key', $o) . "</Contents>";
            }
            echo "</ListBucketResult>";
            logMessage("ListBucket: $bucket");
        }
        break;

    case 'DELETE':
        if ($bucket !== '' && $key === '') {
            // DeleteBucket (recursive)
            if (!is_dir($bucketDir)) {
                http_response_code(404);
                header('Content-Type: application/xml');
                echo "<Error><Code>NoSuchBucket</Code><Message>Bucket not found</Message></Error>";
                logMessage("Bucket not found for deletion: $bucketDir");
                exit;
            }

            // Recursive delete helper
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
        } elseif ($key !== '') {
            // DeleteObject
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
        } else {
            http_response_code(400);
            header('Content-Type: application/xml');
            echo "<Error><Code>InvalidRequest</Code><Message>Invalid DELETE request</Message></Error>";
            logMessage("Invalid DELETE request: bucket='$bucket' key='$key'");
        }
        break;

    default:
        http_response_code(405);
        header('Content-Type: application/xml');
        echo "<Error><Code>MethodNotAllowed</Code><Message>Invalid method</Message></Error>";
        logMessage("Method not allowed: $method");
}
