<?php

namespace App\Console\Commands;

use Illuminate\Console\Command;
use Illuminate\Support\Facades\Storage;

class S3LaravelStorageCommand extends Command
{
    /**
     * The name and signature of the console command.
     *
     * @var string
     */
    protected $signature = 'app:s3-laravel-storage-command';

    /**
     * The console command description.
     *
     * @var string
     */
    protected $description = 'Command using custom S3 endpoint';

    /**
     * Execute the console command.
     */
    public function handle(): void
    {
        $disk = Storage::disk('s3');
        $localDisk = Storage::disk('local'); // This is storage/app
        $bucket = config('filesystems.disks.s3.bucket');
        $timestamp = time();

        // 1. Upload a sample text file (created in storage/app)
        $localTextPath = "uploads/{$timestamp}_hello.txt";
        $localDisk->put($localTextPath, 'Hello World from Laravel Storage');
        $disk->put(basename($localTextPath), $localDisk->get($localTextPath));
        $this->info("Uploaded: " . basename($localTextPath));

        // 2. Upload sample.png and sample.jpg from storage/app/uploads/
        foreach (['sample.png', 'sample.jpg'] as $fileName) {
            $localFilePath = "uploads/{$fileName}";
            if ($localDisk->exists($localFilePath)) {
                $key = "{$timestamp}_{$fileName}";
                $disk->put($key, $localDisk->get($localFilePath));
                $this->info("Uploaded: {$key}");
            } else {
                $this->warn("File not found in storage/app/private/uploads/: {$fileName}");
            }
        }

        // 3. List all objects in the bucket
        $this->info("Objects in bucket '{$bucket}':");
        $files = $disk->allFiles();
        foreach ($files as $file) {
            $this->line("- {$file}");
        }

        // 4. Download each file into storage/app/downloads/
        foreach ($files as $file) {
            $localDownloadPath = "downloads/{$file}";
            $localDisk->put($localDownloadPath, $disk->get($file));
            $this->info("Downloaded to storage/app/{$localDownloadPath}");
        }

        // 5. Delete each object from S3
        foreach ($files as $file) {
            $disk->delete($file);
            $this->info("Deleted from S3: {$file}");
        }

        $this->info("Finished S3 Laravel Storage demo. Local files are inside storage/app/uploads/ and storage/app/downloads/");
    }
}
