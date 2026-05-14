mod common;
mod dns_over_tls;
mod resolver;
mod server;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    tokio::spawn(async {
        if let Err(e) = server::run_dns_server().await {
            eprintln!("DNS server error: {}", e);
        }
    });

    tokio::spawn(async {
        if let Err(e) = dns_over_tls::run_dot_server().await {
            eprintln!("DNS-over-TLS server error: {}", e);
        }
    });

    println!("DNS servers started. Press Ctrl+C to exit.");
    tokio::signal::ctrl_c().await?;
    println!("Shutting down...");
    Ok(())
}
