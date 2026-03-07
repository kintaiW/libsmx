use criterion::{criterion_group, criterion_main, Criterion};
use libsmx::sm9::{
    generate_enc_master_keypair, generate_enc_user_key, generate_sign_master_keypair,
    generate_sign_user_key, sm9_decrypt, sm9_encrypt, sm9_sign, sm9_verify, Sm9EncPubKey,
    Sm9SignPubKey,
};
use rand::rngs::OsRng;

fn bench_sm9_sign_keygen(c: &mut Criterion) {
    c.bench_function("SM9/sign_master_keygen", |b| {
        b.iter(|| generate_sign_master_keypair(&mut OsRng))
    });
}

fn bench_sm9_user_sign_keygen(c: &mut Criterion) {
    let (master_priv, _) = generate_sign_master_keypair(&mut OsRng);
    let id = b"benchuser";
    c.bench_function("SM9/sign_user_keygen", |b| {
        b.iter(|| generate_sign_user_key(&master_priv, id))
    });
}

fn bench_sm9_sign(c: &mut Criterion) {
    let (master_priv, sign_pub) = generate_sign_master_keypair(&mut OsRng);
    let pub_key = Sm9SignPubKey::from_bytes(sign_pub.as_bytes()).unwrap();
    let id = b"benchuser";
    let da = generate_sign_user_key(&master_priv, id).unwrap();
    let msg = b"SM9 signature benchmark message";

    c.bench_function("SM9/sign", |b| {
        b.iter(|| sm9_sign(msg, &da, &pub_key, &mut OsRng))
    });
}

fn bench_sm9_verify(c: &mut Criterion) {
    let (master_priv, sign_pub) = generate_sign_master_keypair(&mut OsRng);
    let pub_key = Sm9SignPubKey::from_bytes(sign_pub.as_bytes()).unwrap();
    let id = b"benchuser";
    let da = generate_sign_user_key(&master_priv, id).unwrap();
    let msg = b"SM9 verify benchmark message";
    let (h, s) = sm9_sign(msg, &da, &pub_key, &mut OsRng).unwrap();

    c.bench_function("SM9/verify", |b| {
        b.iter(|| sm9_verify(msg, &h, &s, id, &pub_key))
    });
}

fn bench_sm9_encrypt(c: &mut Criterion) {
    let (_master_priv, enc_pub) = generate_enc_master_keypair(&mut OsRng);
    let pub_key = Sm9EncPubKey::from_bytes(enc_pub.as_bytes()).unwrap();
    let id = b"benchuser";
    let msg = b"SM9 encryption benchmark plaintext";

    c.bench_function("SM9/encrypt", |b| {
        b.iter(|| sm9_encrypt(id, msg, &pub_key, &mut OsRng))
    });
}

fn bench_sm9_decrypt(c: &mut Criterion) {
    let (master_priv, enc_pub) = generate_enc_master_keypair(&mut OsRng);
    let pub_key = Sm9EncPubKey::from_bytes(enc_pub.as_bytes()).unwrap();
    let id = b"benchuser";
    let de = generate_enc_user_key(&master_priv, id).unwrap();
    let msg = b"SM9 decryption benchmark plaintext";
    let ct = sm9_encrypt(id, msg, &pub_key, &mut OsRng).unwrap();

    c.bench_function("SM9/decrypt", |b| {
        b.iter(|| sm9_decrypt(id, &ct, &de))
    });
}

criterion_group!(
    benches,
    bench_sm9_sign_keygen,
    bench_sm9_user_sign_keygen,
    bench_sm9_sign,
    bench_sm9_verify,
    bench_sm9_encrypt,
    bench_sm9_decrypt,
);
criterion_main!(benches);
