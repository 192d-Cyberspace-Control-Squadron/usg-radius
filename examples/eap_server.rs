//! EAP-TLS RADIUS Server Example
//!
//! This example demonstrates how to set up a RADIUS server with EAP-TLS authentication.
//!
//! # Prerequisites
//!
//! You need TLS certificates to run this example. Generate them with:
//!
//! ```bash
//! # Generate CA certificate
//! openssl req -new -x509 -days 365 -nodes \
//!     -out ca.pem \
//!     -keyout ca-key.pem \
//!     -subj "/C=US/ST=State/L=City/O=Organization/CN=Test CA"
//!
//! # Generate server certificate
//! openssl req -new -nodes \
//!     -out server-req.pem \
//!     -keyout server-key.pem \
//!     -subj "/C=US/ST=State/L=City/O=Organization/CN=radius.example.com"
//!
//! # Sign server certificate with CA
//! openssl x509 -req -days 365 -in server-req.pem \
//!     -CA ca.pem -CAkey ca-key.pem -CAcreateserial \
//!     -out server.pem
//!
//! # Generate client certificate (for mutual TLS)
//! openssl req -new -nodes \
//!     -out client-req.pem \
//!     -keyout client-key.pem \
//!     -subj "/C=US/ST=State/L=City/O=Organization/CN=alice"
//!
//! # Sign client certificate with CA
//! openssl x509 -req -days 365 -in client-req.pem \
//!     -CA ca.pem -CAkey ca-key.pem -CAcreateserial \
//!     -out client.pem
//! ```
//!
//! # Running
//!
//! ```bash
//! cargo run --example eap_server --features tls
//! ```
//!
//! # Certificate Revocation Checking (Optional)
//!
//! This example shows how to enable OCSP (Online Certificate Status Protocol)
//! for real-time certificate revocation checking:
//!
//! ```rust
//! use radius_proto::revocation::{
//!     RevocationConfig, OcspConfig, CrlConfig,
//!     RevocationCheckMode, FallbackBehavior
//! };
//!
//! // Option 1: OCSP only (recommended for real-time checking)
//! let revocation_config = RevocationConfig::ocsp_only(
//!     OcspConfig::http_fetch(5, 3600, 100),
//!     FallbackBehavior::FailClosed,
//! );
//!
//! // Option 2: Prefer OCSP with CRL fallback (most robust)
//! let revocation_config = RevocationConfig {
//!     check_mode: RevocationCheckMode::PreferOcsp,
//!     fallback_behavior: FallbackBehavior::FailClosed,
//!     ocsp_config: OcspConfig::http_fetch(5, 3600, 100),
//!     crl_config: CrlConfig::http_fetch(5, 3600, 100),
//! };
//!
//! // Apply to TLS configuration
//! let cert_config = TlsCertificateConfig::new(...)
//!     .with_revocation_checking(revocation_config);
//! ```
//!
//! # Testing
//!
//! You can test with `eapol_test` (from wpa_supplicant):
//!
//! ```bash
//! eapol_test -c eap-tls.conf -s testing123
//! ```
//!
//! Where `eap-tls.conf` contains:
//!
//! ```text
//! network={
//!     ssid="test"
//!     key_mgmt=WPA-EAP
//!     eap=TLS
//!     identity="alice"
//!     client_cert="client.pem"
//!     private_key="client-key.pem"
//! }
//! ```

#[cfg(feature = "tls")]
use radius_proto::eap::eap_tls::TlsCertificateConfig;
#[cfg(feature = "tls")]
use radius_proto::revocation::{
    CrlConfig, FallbackBehavior, OcspConfig, RevocationCheckMode, RevocationConfig,
};
use radius_server::{EapAuthHandler, RadiusServer, ServerConfig, SimpleAuthHandler};
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .init();

    println!("Starting EAP-TLS RADIUS Server...");
    println!("Listening on: 0.0.0.0:1812");
    println!("Shared secret: testing123");
    println!();

    #[cfg(not(feature = "tls"))]
    {
        eprintln!("ERROR: This example requires the 'tls' feature!");
        eprintln!("Run with: cargo run --example eap_server --features tls");
        std::process::exit(1);
    }

    #[cfg(feature = "tls")]
    {
        // Create inner authentication handler (for fallback PAP/CHAP)
        let mut inner_handler = SimpleAuthHandler::new();
        inner_handler.add_user("testuser", "testpass");

        // Create EAP authentication handler
        let mut eap_handler = EapAuthHandler::new(Arc::new(inner_handler));

        // Configure TLS certificates
        // In production, you would load these from secure storage
        let mut cert_config = TlsCertificateConfig::new(
            "server.pem".to_string(),
            "server-key.pem".to_string(),
            Some("ca.pem".to_string()), // CA for verifying client certificates
            true,                       // Require client certificate (mutual TLS)
        );

        // Optional: Enable certificate revocation checking
        // Uncomment one of these to enable OCSP/CRL checking:

        // Option 1: OCSP only (fastest, real-time checking)
        // let revocation_config = RevocationConfig::ocsp_only(
        //     OcspConfig::http_fetch(
        //         5,      // 5 second HTTP timeout
        //         3600,   // 1 hour cache TTL
        //         100,    // Cache up to 100 responses
        //     ),
        //     FallbackBehavior::FailClosed, // Reject if OCSP check fails
        // );
        // cert_config = cert_config.with_revocation_checking(revocation_config);

        // Option 2: Prefer OCSP with CRL fallback (recommended for production)
        // let revocation_config = RevocationConfig {
        //     check_mode: RevocationCheckMode::PreferOcsp,
        //     fallback_behavior: FallbackBehavior::FailClosed,
        //     ocsp_config: OcspConfig::http_fetch(5, 3600, 100),
        //     crl_config: CrlConfig::http_fetch(5, 3600, 100),
        // };
        // cert_config = cert_config.with_revocation_checking(revocation_config);

        // Option 3: CRL only (works offline with static CRL files)
        // let revocation_config = RevocationConfig::static_files(
        //     vec!["ca-crl.pem".to_string()],
        //     FallbackBehavior::FailClosed,
        // );
        // cert_config = cert_config.with_revocation_checking(revocation_config);

        // Configure EAP-TLS for default realm
        match eap_handler.configure_tls("", cert_config) {
            Ok(_) => {
                println!("✓ TLS certificates configured successfully");
                println!("  Server cert: server.pem");
                println!("  Server key:  server-key.pem");
                println!("  Client CA:   ca.pem");
                println!();
            }
            Err(e) => {
                eprintln!("ERROR: Failed to configure TLS certificates: {}", e);
                eprintln!();
                eprintln!("Make sure you have generated the certificates.");
                eprintln!("See the example documentation for instructions.");
                std::process::exit(1);
            }
        }

        // Create server configuration
        let config = ServerConfig::new(
            "0.0.0.0:1812".parse()?,
            b"testing123",
            Arc::new(eap_handler),
        );

        println!("Server Configuration:");
        println!("  Authentication: EAP-TLS with mutual TLS");
        println!("  Fallback:      PAP/CHAP (user: testuser/testpass)");
        println!();

        // Create and run server
        let server = RadiusServer::new(config).await?;

        println!("Server is running. Press Ctrl+C to stop.");
        println!();
        println!("Supported EAP methods:");
        println!("  - EAP-TLS (Type 13) - Certificate-based authentication");
        println!();
        println!("Test with eapol_test:");
        println!("  eapol_test -c eap-tls.conf -s testing123");
        println!();

        server.run().await?;
    }

    Ok(())
}
