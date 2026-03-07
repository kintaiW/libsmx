use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use libsmx::sm4::{sm4_encrypt_ecb, Sm4Key};

fn bench_sm4_ecb(c: &mut Criterion) {
    let mut group = c.benchmark_group("SM4-ECB");
    let key = [0u8; 16];
    for size in [16usize, 1024, 65536] {
        let data = vec![0u8; size];
        group.bench_with_input(BenchmarkId::new("encrypt", size), &data, |b, d| {
            b.iter(|| sm4_encrypt_ecb(&key, d));
        });
    }
    group.finish();
}

fn bench_sm4_key_new(c: &mut Criterion) {
    let key = [0u8; 16];
    c.bench_function("SM4/key_expand", |b| {
        b.iter(|| Sm4Key::new(&key));
    });
}

criterion_group!(benches, bench_sm4_ecb, bench_sm4_key_new);
criterion_main!(benches);
