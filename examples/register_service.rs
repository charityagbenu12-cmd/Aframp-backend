//! Example script to register a new service identity
//!
//! Usage:
//!   cargo run --example register_service -- --name worker_service --scopes "worker:execute" --targets "/api/settlement/*"

use clap::Parser;
use std::sync::Arc;
use Bitmesh_backend::database::init_pool;
use Bitmesh_backend::service_auth::{ServiceRegistry, ServiceRegistration};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Service name
    #[arg(short, long)]
    name: String,

    /// Allowed scopes (comma-separated)
    #[arg(short, long, value_delimiter = ',')]
    scopes: Vec<String>,

    /// Allowed target endpoints (comma-separated)
    #[arg(short, long, value_delimiter = ',')]
    targets: Vec<String>,

    /// Database URL
    #[arg(long, env = "DATABASE_URL")]
    database_url: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    println!("Registering service: {}", args.name);
    println!("Scopes: {:?}", args.scopes);
    println!("Targets: {:?}", args.targets);

    // Connect to database
    let pool = Arc::new(init_pool(&args.database_url, None).await?);
    let registry = ServiceRegistry::new(pool);

    // Register service
    let registration = ServiceRegistration {
        service_name: args.name.clone(),
        allowed_scopes: args.scopes,
        allowed_targets: args.targets,
    };

    let identity = registry.register_service(registration).await?;

    println!("\n✅ Service registered successfully!");
    println!("\nService Details:");
    println!("  Name:          {}", identity.service_name);
    println!("  Client ID:     {}", identity.client_id);
    println!("  Client Secret: {}", identity.client_secret);
    println!("  Scopes:        {:?}", identity.allowed_scopes);
    println!("\n⚠️  IMPORTANT: Store the client secret securely. It will not be shown again.");
    println!("\nEnvironment variables for your service:");
    println!("  SERVICE_NAME={}", identity.service_name);
    println!("  SERVICE_CLIENT_ID={}", identity.client_id);
    println!("  SERVICE_CLIENT_SECRET={}", identity.client_secret);

    Ok(())
}
