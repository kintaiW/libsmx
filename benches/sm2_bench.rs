use criterion::{criterion_group, criterion_main, Criterion};
use libsmx::sm2::{decrypt, encrypt, generate_keypair, get_e, get_z, sign, verify};
use rand::rngs::OsRng;

fn bench_sm2_keygen(c: &mut Criterion) {
    c.bench_function("SM2/keygen", |b| {
        b.iter(|| generate_keypair(&mut OsRng))
    });
}

fn bench_sm2_sign(c: &mut Criterion) {
    let (pri_key, pub_key) = generate_keypair(&mut OsRng);
    let id = b"benchuser";
    let msg = b"benchmark message for SM2 sign";
    let z = get_z(id, &pub_key);
    let e = get_e(&z, msg);

    c.bench_function("SM2/sign", |b| {
        b.iter(|| sign(&e, &pri_key, &mut OsRng))
    });
}

fn bench_sm2_verify(c: &mut Criterion) {
    let (pri_key, pub_key) = generate_keypair(&mut OsRng);
    let id = b"benchuser";
    let msg = b"benchmark message for SM2 verify";
    let z = get_z(id, &pub_key);
    let e = get_e(&z, msg);
    let sig = sign(&e, &pri_key, &mut OsRng);

    c.bench_function("SM2/verify", |b| {
        b.iter(|| verify(&e, &pub_key, &sig))
    });
}

fn bench_sm2_encrypt(c: &mut Criterion) {
    let (_pri_key, pub_key) = generate_keypair(&mut OsRng);
    let msg = b"SM2 encryption benchmark plaintext";

    c.bench_function("SM2/encrypt", |b| {
        b.iter(|| encrypt(&pub_key, msg, &mut OsRng))
    });
}

fn bench_sm2_decrypt(c: &mut Criterion) {
    let (pri_key, pub_key) = generate_keypair(&mut OsRng);
    let msg = b"SM2 decryption benchmark plaintext";
    let ct = encrypt(&pub_key, msg, &mut OsRng).unwrap();

    c.bench_function("SM2/decrypt", |b| {
        b.iter(|| decrypt(&pri_key, &ct))
    });
}

criterion_group!(
    benches,
    bench_sm2_keygen,
    bench_sm2_sign,
    bench_sm2_verify,
    bench_sm2_encrypt,
    bench_sm2_decrypt
);
criterion_main!(benches);
