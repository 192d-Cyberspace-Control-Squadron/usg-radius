use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use radius_proto::{Attribute, AttributeType, Code, Packet};
use radius_proto::auth::{encrypt_user_password, decrypt_user_password, generate_request_authenticator};

fn create_test_packet(num_attributes: usize) -> Packet {
    let req_auth = generate_request_authenticator();
    let mut packet = Packet::new(Code::AccessRequest, 1, req_auth);

    // Add username
    packet.add_attribute(
        Attribute::string(AttributeType::UserName as u8, "testuser")
            .expect("Failed to create User-Name attribute"),
    );

    // Add encrypted password
    let encrypted_pwd = encrypt_user_password("testpassword", b"testing123", &req_auth);
    packet.add_attribute(
        Attribute::new(AttributeType::UserPassword as u8, encrypted_pwd)
            .expect("Failed to create User-Password attribute"),
    );

    // Add additional attributes to test scaling
    for i in 0..num_attributes {
        let attr_value = format!("attribute_{}", i);
        if let Ok(attr) = Attribute::string(AttributeType::ReplyMessage as u8, &attr_value) {
            packet.add_attribute(attr);
        }
    }

    packet
}

fn bench_packet_encode(c: &mut Criterion) {
    let mut group = c.benchmark_group("packet_encode");

    for num_attrs in [0, 5, 10, 20].iter() {
        group.bench_with_input(
            BenchmarkId::from_parameter(num_attrs),
            num_attrs,
            |b, &num_attrs| {
                let packet = create_test_packet(num_attrs);
                b.iter(|| {
                    packet.encode().expect("Failed to encode packet")
                });
            },
        );
    }

    group.finish();
}

fn bench_packet_decode(c: &mut Criterion) {
    let mut group = c.benchmark_group("packet_decode");

    for num_attrs in [0, 5, 10, 20].iter() {
        group.bench_with_input(
            BenchmarkId::from_parameter(num_attrs),
            num_attrs,
            |b, &num_attrs| {
                let packet = create_test_packet(num_attrs);
                let encoded = packet.encode().expect("Failed to encode");
                b.iter(|| {
                    Packet::decode(black_box(&encoded)).expect("Failed to decode packet")
                });
            },
        );
    }

    group.finish();
}

fn bench_password_encryption(c: &mut Criterion) {
    let mut group = c.benchmark_group("password_encryption");

    let passwords = vec![
        ("short", "test"),
        ("medium", "testpassword123"),
        ("long", "this_is_a_very_long_password_to_test_performance"),
    ];

    for (name, password) in passwords.iter() {
        group.bench_with_input(
            BenchmarkId::from_parameter(name),
            password,
            |b, &password| {
                let secret = b"testing123";
                let req_auth = generate_request_authenticator();
                b.iter(|| {
                    encrypt_user_password(black_box(password), black_box(secret), black_box(&req_auth))
                });
            },
        );
    }

    group.finish();
}

fn bench_password_decryption(c: &mut Criterion) {
    let mut group = c.benchmark_group("password_decryption");

    let passwords = vec![
        ("short", "test"),
        ("medium", "testpassword123"),
        ("long", "this_is_a_very_long_password_to_test_performance"),
    ];

    for (name, password) in passwords.iter() {
        group.bench_with_input(
            BenchmarkId::from_parameter(name),
            password,
            |b, &password| {
                let secret = b"testing123";
                let req_auth = generate_request_authenticator();
                let encrypted = encrypt_user_password(password, secret, &req_auth);
                b.iter(|| {
                    decrypt_user_password(black_box(&encrypted), black_box(secret), black_box(&req_auth))
                        .expect("Failed to decrypt password")
                });
            },
        );
    }

    group.finish();
}

fn bench_attribute_creation(c: &mut Criterion) {
    let mut group = c.benchmark_group("attribute_creation");

    group.bench_function("string_attribute", |b| {
        b.iter(|| {
            Attribute::string(
                black_box(AttributeType::UserName as u8),
                black_box("testuser"),
            )
            .expect("Failed to create attribute")
        });
    });

    group.bench_function("ipv4_attribute", |b| {
        b.iter(|| {
            let ip_bytes = [192, 168, 1, 1];
            Attribute::new(
                black_box(AttributeType::NasIpAddress as u8),
                black_box(ip_bytes.to_vec()),
            )
            .expect("Failed to create attribute")
        });
    });

    group.finish();
}

fn bench_full_request_cycle(c: &mut Criterion) {
    c.bench_function("full_request_encode_decode", |b| {
        b.iter(|| {
            // Create packet
            let req_auth = generate_request_authenticator();
            let mut packet = Packet::new(Code::AccessRequest, 1, req_auth);

            // Add attributes
            packet.add_attribute(
                Attribute::string(AttributeType::UserName as u8, "testuser")
                    .expect("Failed to create User-Name"),
            );

            let encrypted_pwd = encrypt_user_password("testpassword", b"testing123", &req_auth);
            packet.add_attribute(
                Attribute::new(AttributeType::UserPassword as u8, encrypted_pwd)
                    .expect("Failed to create User-Password"),
            );

            // Encode
            let encoded = packet.encode().expect("Failed to encode");

            // Decode
            let decoded = Packet::decode(&encoded).expect("Failed to decode");

            black_box(decoded)
        });
    });
}

criterion_group!(
    benches,
    bench_packet_encode,
    bench_packet_decode,
    bench_password_encryption,
    bench_password_decryption,
    bench_attribute_creation,
    bench_full_request_cycle
);
criterion_main!(benches);
