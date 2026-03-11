use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use libsmx::sm4::Sm4Key;

fn bench_sm4_block_encrypt(c: &mut Criterion) {
    let mut group = c.benchmark_group("SM4-block");
    let key = [0u8; 16];
    let sm4 = Sm4Key::new(&key);
    group.bench_function("encrypt_block", |b| {
        let mut block = [0u8; 16];
        b.iter(|| sm4.encrypt_block(&mut block));
    });
    group.finish();
}

fn bench_sm4_key_new(c: &mut Criterion) {
    let key = [0u8; 16];
    c.bench_function("SM4/key_expand", |b| {
        b.iter(|| Sm4Key::new(&key));
    });
}

fn bench_sm4_throughput(c: &mut Criterion) {
    let mut group = c.benchmark_group("SM4-throughput");
    let key = [0u8; 16];
    let sm4 = Sm4Key::new(&key);
    for size in [16usize, 1024, 65536] {
        let mut data = vec![0u8; size];
        group.bench_with_input(BenchmarkId::new("encrypt", size), &size, |b, _| {
            b.iter(|| {
                for chunk in data.chunks_exact_mut(16) {
                    sm4.encrypt_block(chunk.try_into().unwrap());
                }
            });
        });
    }
    group.finish();
}

criterion_group!(benches, bench_sm4_block_encrypt, bench_sm4_key_new, bench_sm4_throughput);
criterion_main!(benches);
