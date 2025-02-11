mod common;
mod server;
mod dns_over_tls;
mod resolver;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tokio::spawn(async {
        if let Err(e) = server::run_dns_server().await {
            eprintln!("Error en el servidor DNS básico: {}", e);
        }
    });

    tokio::spawn(async {
        if let Err(e) = dns_over_tls::run_dot_server().await {
            eprintln!("Error en el servidor DNS-over-TLS: {}", e);
        }
    });

    println!("Servidores DNS iniciados. Presiona Ctrl+C para salir.");
    tokio::signal::ctrl_c().await?;
    println!("Apagando servidores...");
    Ok(())
}
