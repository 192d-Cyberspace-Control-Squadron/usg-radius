use radius_proto::{
    auth::{encrypt_user_password, generate_request_authenticator},
    Attribute, AttributeType, Code, Packet,
};
use std::net::UdpSocket;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 4 {
        eprintln!("Usage: {} <username> <password> <secret> [server_addr]", args[0]);
        eprintln!("Example: {} admin admin123 testing123 127.0.0.1:1812", args[0]);
        std::process::exit(1);
    }

    let username = &args[1];
    let password = &args[2];
    let secret = args[3].as_bytes();
    let server_addr = args.get(4).map(|s| s.as_str()).unwrap_or("127.0.0.1:1812");

    println!("RADIUS Client Test");
    println!("==================");
    println!("Server: {}", server_addr);
    println!("Username: {}", username);
    println!("Secret: {}", std::str::from_utf8(secret).unwrap_or("<binary>"));
    println!();

    // Create UDP socket
    let socket = UdpSocket::bind("0.0.0.0:0")?;
    socket.connect(server_addr)?;

    // Generate request authenticator
    let request_auth = generate_request_authenticator();

    // Create Access-Request packet
    let mut packet = Packet::new(Code::AccessRequest, 1, request_auth);

    // Add User-Name attribute
    packet.add_attribute(Attribute::string(AttributeType::UserName as u8, username)?);

    // Add User-Password attribute (encrypted)
    let encrypted_password = encrypt_user_password(password, secret, &request_auth);
    packet.add_attribute(Attribute::new(AttributeType::UserPassword as u8, encrypted_password)?);

    // Add NAS-IP-Address (optional)
    packet.add_attribute(Attribute::ipv4(
        AttributeType::NasIpAddress as u8,
        [127, 0, 0, 1],
    )?);

    // Encode and send packet
    let request_data = packet.encode()?;
    println!("Sending Access-Request ({} bytes)...", request_data.len());
    socket.send(&request_data)?;

    // Receive response
    let mut buffer = vec![0u8; 4096];
    socket.set_read_timeout(Some(std::time::Duration::from_secs(5)))?;

    match socket.recv(&mut buffer) {
        Ok(len) => {
            println!("Received response ({} bytes)", len);

            // Decode response
            let response = Packet::decode(&buffer[..len])?;

            match response.code {
                Code::AccessAccept => {
                    println!("\n✓ Authentication SUCCESSFUL!");
                    println!("  Response: Access-Accept");

                    // Show any Reply-Message attributes
                    for attr in response.find_all_attributes(AttributeType::ReplyMessage as u8) {
                        if let Ok(msg) = attr.as_string() {
                            println!("  Message: {}", msg);
                        }
                    }
                }
                Code::AccessReject => {
                    println!("\n✗ Authentication FAILED!");
                    println!("  Response: Access-Reject");

                    // Show any Reply-Message attributes
                    for attr in response.find_all_attributes(AttributeType::ReplyMessage as u8) {
                        if let Ok(msg) = attr.as_string() {
                            println!("  Message: {}", msg);
                        }
                    }
                }
                Code::AccessChallenge => {
                    println!("\n→ Authentication CHALLENGE!");
                    println!("  Response: Access-Challenge");

                    // Show any Reply-Message or State attributes
                    for attr in response.find_all_attributes(AttributeType::ReplyMessage as u8) {
                        if let Ok(msg) = attr.as_string() {
                            println!("  Message: {}", msg);
                        }
                    }
                }
                _ => {
                    println!("\n? Unexpected response: {:?}", response.code);
                }
            }

            println!("\nResponse Details:");
            println!("  Identifier: {}", response.identifier);
            println!("  Attributes: {}", response.attributes.len());

            Ok(())
        }
        Err(e) => {
            eprintln!("\n✗ No response from server: {}", e);
            eprintln!("  Make sure the RADIUS server is running on {}", server_addr);
            Err(e.into())
        }
    }
}
