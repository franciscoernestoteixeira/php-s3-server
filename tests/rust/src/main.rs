use aws_sdk_s3::{Client, config::Region};
use aws_sdk_s3::primitives::ByteStream;
use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let bucket = "mybucket";
    let endpoint = "http://localhost";
    let access_key = "FAKEACCESS";
    let secret_key = "FAKESECRET";

    let shared_config = aws_config::defaults(aws_config::BehaviorVersion::latest())
        .endpoint_url(endpoint)
        .credentials_provider(aws_sdk_s3::config::Credentials::new(
            access_key,
            secret_key,
            None,
            None,
            "local",
        ))
        .region(Region::new("us-east-1"))
        .load()
        .await;

    let client = Client::new(&shared_config);

    // Create bucket
    if let Err(e) = client.create_bucket().bucket(bucket).send().await {
        println!("Bucket create error: {:?}", e);
    } else {
        println!("Bucket '{}' created.", bucket);
    }

    // Upload hello.txt
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        .to_string();

    let text_key = format!("{}_hello.txt", timestamp);
    client
        .put_object()
        .bucket(bucket)
        .key(&text_key)
        .body(ByteStream::from_static(b"Hello World from Rust"))
        .send()
        .await?;
    println!("Uploaded: {}", text_key);

    // Upload sample.png and sample.jpg
    for file_name in ["sample.png", "sample.jpg"] {
        if Path::new(file_name).exists() {
            let key = format!("{}_{}", timestamp, file_name);
            let mut file = File::open(file_name)?;
            let mut data = Vec::new();
            file.read_to_end(&mut data)?;
            client
                .put_object()
                .bucket(bucket)
                .key(&key)
                .body(ByteStream::from(data))
                .send()
                .await?;
            println!("Uploaded: {}", key);
        } else {
            println!("Warning: File '{}' not found. Skipping upload.", file_name);
        }
    }

    // List objects
    let resp = client.list_objects_v2().bucket(bucket).send().await?;
    println!("Objects in bucket:");
    if let Some(contents) = resp.contents.as_ref() {
        for obj in contents {
            if let Some(key) = obj.key() {
                println!("- {}", key);
            }
        }

        // Download each file
        for obj in contents {
            if let Some(key) = obj.key() {
                let resp = client.get_object().bucket(bucket).key(key).send().await?;
                let data = resp.body.collect().await?.into_bytes();

                let local_file_name = format!("downloaded_{}", Path::new(key).file_name().unwrap().to_str().unwrap());
                let mut out_file = File::create(&local_file_name)?;
                out_file.write_all(&data)?;
                println!("Downloaded: {}", local_file_name);
            }
        }

        // Delete all objects
        for obj in contents {
            if let Some(key) = obj.key() {
                client.delete_object().bucket(bucket).key(key).send().await?;
                println!("Deleted: {}", key);
            }
        }
    }

    // Delete bucket
    if let Err(e) = client.delete_bucket().bucket(bucket).send().await {
        println!("DeleteBucket error: {:?}", e);
    } else {
        println!("Bucket '{}' deleted.", bucket);
    }

    Ok(())
}
