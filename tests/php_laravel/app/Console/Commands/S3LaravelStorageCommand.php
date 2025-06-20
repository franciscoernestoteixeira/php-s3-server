<?php

namespace App\Console\Commands;

use Illuminate\Console\Command;
use Illuminate\Support\Facades\Storage;
use Symfony\Component\Console\Command\Command as CommandAlias;

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
    public function handle(): int
    {
        $disk = Storage::disk('s3');
        $localDisk = Storage::disk('local');
        $bucket = config('filesystems.disks.s3.bucket');
        $timestamp = time();

        // Upload simple text file
        $textKey = "{$timestamp}_hello.txt";
        $disk->put($textKey, 'Hello World from Laravel');
        $this->info("Uploaded: {$textKey}");

        // Upload sample files if they exist
        foreach (['sample.png', 'sample.jpg'] as $fileName) {
            $localFilePath = "uploads/{$fileName}";

            if ($localDisk->exists($localFilePath)) {
                $key = "{$timestamp}_{$fileName}";
                $disk->put($key, $localDisk->get($localFilePath));
                $this->info("Uploaded to S3: {$key}");
            } else {
                $this->warn("File not found in storage/app/uploads/: {$fileName}");
            }
        }

        // List all objects
        $this->info("Listing objects in bucket '{$bucket}':");
        $objects = $disk->allFiles('');
        foreach ($objects as $object) {
            $this->line("- {$object}");
        }

        // Download all objects back to local storage (inside storage/app/downloaded/)
        foreach ($objects as $object) {
            $localDownloadPath = "downloads/{$object}";
            $localDisk->put($localDownloadPath, $disk->get($object));
            $this->info("Downloaded: {$localDownloadPath}");
        }

        // Delete all objects
        foreach ($objects as $object) {
            $disk->delete($object);
            $this->info("Deleted: {$object}");
        }

        $this->info('S3 Laravel Storage command completed successfully.');

        return CommandAlias::SUCCESS;
    }
}
