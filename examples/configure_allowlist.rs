//! Example script to configure service call allowlist
//!
//! Usage:
//!   cargo run --example configure_allowlist -- --service worker_service --endpoint "/api/settlement/*" --allow

use clap::Parser;
use std::sync::Arc;
use Bitmesh_backend::cache::{init_cache_pool, CacheConfig, RedisCache};
use Bitmesh_backend::database::init_pool;
use Bitmesh_backend::service_auth::ServiceAllowlist;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Calling service name
    #[arg(short, long)]
    service: String,

    /// Target endpoint pattern
    #[arg(short, long)]
    endpoint: String,

    /// Allow access (default: true)
    #[arg(long, default_value = "true")]
    allow: bool,

    /// Database URL
    #[arg(long, env = "DATABASE_URL")]
    database_url: String,

    /// Redis URL
    #[arg(long, env = "REDIS_URL", default_value = "redis://127.0.0.1:6379")]
    redis_url: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    println!("Configuring allowlist:");
    println!("  Service:  {}", args.service);
    println!("  Endpoint: {}", args.endpoint);
    println!("  Action:   {}", if args.allow { "ALLOW" } else { "DENY" });

    // Connect to database
    let pool = Arc::new(init_pool(&args.database_url, None).await?);

    // Connect to Redis
    let cache_config = CacheConfig {
        redis_url: args.redis_url,
        ..Default::default()
    };
    let cache_pool = init_cache_pool(cache_config).await?;
    let cache = Arc::new(RedisCache::new(cache_pool));

    // Create allowlist
    let allowlist = ServiceAllowlist::new(pool, cache);

    // Set permission
    allowlist
        .set_permission(&args.service, &args.endpoint, args.allow)
        .await?;

    println!("\n✅ Allowlist updated successfully!");

    // List current permissions for the service
    println!("\nCurrent permissions for {}:", args.service);
    let permissions = allowlist.list_permissions(&args.service).await?;
    
    if permissions.is_empty() {
        println!("  (none)");
    } else {
        for perm in permissions {
            let status = if perm.allowed { "✓ ALLOW" } else { "✗ DENY" };
            println!("  {} {}", status, perm.target_endpoint);
        }
    }

    Ok(())
}
