use ares::checkers::athena::Athena;
use ares::checkers::checker_type::{Check, Checker};
use ares::checkers::CheckerTypes;
use ares::config::Config;
use ares::decoders::base64_decoder::Base64Decoder;
use ares::decoders::interface::{Crack, Decoder};
use criterion::{criterion_group, criterion_main, Criterion};
use std::hint::black_box;

pub fn criterion_benchmark(c: &mut Criterion) {
    let decode_base64 = Decoder::<Base64Decoder>::new();
    let athena_checker = Checker::<Athena>::new();
    let checker = CheckerTypes::CheckAthena(athena_checker);
    let config = Config::default();

    c.bench_function("base64 successful decoding", |b| {
        b.iter(|| decode_base64.crack(black_box("aGVsbG8gd29ybGQ="), &checker, &config))
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
