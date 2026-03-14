use criterion::{black_box, criterion_group, criterion_main, Criterion};
use rshc::rc4::Rc4;

fn bench_rc4_encrypt(c: &mut Criterion) {
    let mut group = c.benchmark_group("rc4");

    let key = vec![0x42u8; 256];
    let data_sizes = [64, 1024, 16384, 65536];

    for &size in &data_sizes {
        group.bench_function(format!("encrypt_{}b", size), |b| {
            b.iter(|| {
                let mut rc4 = Rc4::new();
                rc4.reset();
                rc4.key(black_box(&key));
                let mut data = vec![0xABu8; size];
                rc4.arc4(black_box(&mut data));
                data
            });
        });
    }

    group.finish();
}

fn bench_aes_encrypt(c: &mut Criterion) {
    let mut group = c.benchmark_group("aes256gcm");

    let key = [0x42u8; 32];
    let data_sizes = [64, 1024, 16384, 65536];

    for &size in &data_sizes {
        let data = vec![0xABu8; size];

        group.bench_function(format!("encrypt_{}b", size), |b| {
            b.iter(|| rshc::aes::aes_encrypt(black_box(&data), black_box(&key)).unwrap());
        });

        let (ciphertext, nonce) = rshc::aes::aes_encrypt(&data, &key).unwrap();

        group.bench_function(format!("decrypt_{}b", size), |b| {
            b.iter(|| {
                rshc::aes::aes_decrypt(black_box(&ciphertext), black_box(&key), black_box(&nonce))
                    .unwrap()
            });
        });
    }

    group.finish();
}

fn bench_argon2id(c: &mut Criterion) {
    let mut group = c.benchmark_group("argon2id");
    group.sample_size(10); // Argon2 is intentionally slow

    let salt = [0x11u8; 32];

    group.bench_function("hash_password", |b| {
        b.iter(|| {
            rshc::security::hash_password(black_box(b"my_secure_password"), black_box(&salt))
        });
    });

    group.finish();
}

fn bench_sha256(c: &mut Criterion) {
    let mut group = c.benchmark_group("sha256");

    let data_sizes = [64, 1024, 16384, 65536];

    for &size in &data_sizes {
        let data = vec![0xABu8; size];
        group.bench_function(format!("hash_{}b", size), |b| {
            b.iter(|| rshc::security::sha256(black_box(&data)));
        });
    }

    group.finish();
}

fn bench_compression(c: &mut Criterion) {
    use flate2::write::DeflateEncoder;
    use flate2::Compression;
    use std::io::Write;

    let mut group = c.benchmark_group("deflate");

    // Typical shell script content (repetitive, compresses well)
    let script =
        "#!/bin/bash\necho \"Hello World\"\nfor i in $(seq 1 100); do\n  echo \"Line $i\"\ndone\n";
    let data = script.repeat(100); // ~5KB

    group.bench_function(format!("compress_{}b", data.len()), |b| {
        b.iter(|| {
            let mut encoder = DeflateEncoder::new(Vec::new(), Compression::best());
            encoder.write_all(black_box(data.as_bytes())).unwrap();
            encoder.finish().unwrap()
        });
    });

    let mut encoder = DeflateEncoder::new(Vec::new(), Compression::best());
    encoder.write_all(data.as_bytes()).unwrap();
    let compressed = encoder.finish().unwrap();

    group.bench_function(format!("decompress_{}b", compressed.len()), |b| {
        use flate2::read::DeflateDecoder;
        use std::io::Read;
        b.iter(|| {
            let mut decoder = DeflateDecoder::new(black_box(&compressed[..]));
            let mut out = Vec::new();
            decoder.read_to_end(&mut out).unwrap();
            out
        });
    });

    group.finish();
}

fn bench_payload_roundtrip(c: &mut Criterion) {
    use rshc::payload::{Payload, FLAG_TRACEABLE};

    let mut group = c.benchmark_group("payload");

    let mut payload = Payload::default();
    payload.flags = FLAG_TRACEABLE;
    payload.arrays[0] = vec![0xAB; 256]; // pswd
    payload.arrays[12] = vec![0x42; 4096]; // text (typical script)

    let mut buf = Vec::new();
    payload.serialize(&mut buf).unwrap();

    group.bench_function("serialize", |b| {
        b.iter(|| {
            let mut out = Vec::new();
            payload.serialize(black_box(&mut out)).unwrap();
            out
        });
    });

    group.bench_function("deserialize", |b| {
        b.iter(|| {
            let mut cursor = std::io::Cursor::new(black_box(&buf));
            Payload::deserialize(&mut cursor).unwrap()
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_rc4_encrypt,
    bench_aes_encrypt,
    bench_argon2id,
    bench_sha256,
    bench_compression,
    bench_payload_roundtrip,
);
criterion_main!(benches);
