use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use libsmx::sm3::Sm3Hasher;

fn bench_sm3_digest(c: &mut Criterion) {
    let mut group = c.benchmark_group("SM3");
    for size in [64usize, 1024, 65536] {
        let data = vec![0x42u8; size];
        group.bench_with_input(BenchmarkId::new("digest", size), &data, |b, d| {
            b.iter(|| Sm3Hasher::digest(d));
        });
    }
    group.finish();
}

criterion_group!(benches, bench_sm3_digest);
criterion_main!(benches);
