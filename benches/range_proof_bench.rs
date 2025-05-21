// benches/range_proof_benchmarks.rs

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use halo2_proofs::{
    circuit::Value,
    pasta::{EqAffine, Fp},
    plonk::{Circuit, SingleVerifier, create_proof, keygen_pk, keygen_vk, verify_proof},
    poly::commitment::Params,
    transcript::{Blake2bRead, Blake2bWrite, Challenge255},
};
use halo2_range_proof::range_circuit::RangeProofCircuit;

use rand::Rng;

const NUM_BITS_TO_CHECK_FOR_BENCH: usize = 64; // 각 입력의 비트 수

fn calculate_k_value(trace_rows: usize, lookup_table_size: usize) -> u32 {
    let mut k_trace = 0;
    let required_min_trace_rows = trace_rows + 10;
    while (1 << k_trace) < required_min_trace_rows {
        k_trace += 1;
        if k_trace > 30 {
            panic!("k_trace too large");
        }
    }

    let mut k_table = 0;
    while (1 << k_table) <= lookup_table_size {
        // 2^k > table_size 조건
        k_table += 1;
        if k_table > 30 {
            panic!("k_table too large");
        }
    }
    k_trace.max(k_table).max(5) // 최소 k는 5로 가정 (더 작은 k는 halo2에서 문제 발생 가능)
}

// 벤치마크 함수 정의
fn benchmark_range_proof(c: &mut Criterion) {
    let input_sizes_to_iterate: [usize; 10] =
        [4, 16, 64, 256, 1024, 4096, 16384, 65536, 262144, 1048576];

    const LOOKUP_BITS_ASSUMED: usize = 8;
    let lookup_table_size_for_k_calc = 1 << LOOKUP_BITS_ASSUMED;

    for &current_num_inputs in input_sizes_to_iterate.iter() {
        let approx_rows_per_input = (NUM_BITS_TO_CHECK_FOR_BENCH / LOOKUP_BITS_ASSUMED).max(1);
        let estimated_trace_rows = current_num_inputs * approx_rows_per_input;
        let k_val = calculate_k_value(estimated_trace_rows, lookup_table_size_for_k_calc);

        if k_val > 24 {
            println!(
                "Skipping benchmark for {} inputs: calculated k={} is too large (max set to 24).",
                current_num_inputs, k_val
            );
            continue;
        }

        println!(
            "Benchmarking for {} inputs with k = {}",
            current_num_inputs, k_val
        );

        let params = Params::<EqAffine>::new(k_val);

        let mut rng = rand::rng();
        let mut values_for_circuit: Vec<Value<Fp>> = Vec::with_capacity(current_num_inputs);
        for _ in 0..current_num_inputs {
            let random_val_u64 = if NUM_BITS_TO_CHECK_FOR_BENCH >= 64 {
                rng.random::<u64>()
            } else {
                let upper_bound = 1u64 << NUM_BITS_TO_CHECK_FOR_BENCH;
                rng.random_range(0..upper_bound)
            };
            values_for_circuit.push(Value::known(<Fp>::from(random_val_u64)));
        }

        let circuit = RangeProofCircuit::<Fp> {
            // 사용자 회로 이름 사용
            inputs: values_for_circuit,
            num_bits_to_check: NUM_BITS_TO_CHECK_FOR_BENCH,
        };

        let empty_circuit = circuit.without_witnesses();
        let vk = keygen_vk(&params, &empty_circuit).expect("keygen_vk should not fail");
        let pk = keygen_pk(&params, vk.clone(), &empty_circuit).expect("keygen_pk should not fail");

        let public_inputs: Vec<Vec<Fp>> = vec![vec![]];
        let proof_public_inputs_slice: &[&[Fp]] =
            if public_inputs.first().is_none_or(|v| v.is_empty()) {
                &[&[]]
            } else {
                unreachable!();
            };
        let final_instances_arg: &[&[&[Fp]]] = &[proof_public_inputs_slice];

        // 1. create_proof 벤치마크
        let mut group_creation = c.benchmark_group("Range Proof Creation");
        group_creation.throughput(Throughput::Elements(current_num_inputs as u64)); // 처리량 설정

        group_creation.bench_function(
            BenchmarkId::new(
                "create_proof",
                format!("{} inputs (k={})", current_num_inputs, k_val),
            ),
            |b| {
                b.iter(|| {
                    let mut transcript_prove =
                        Blake2bWrite::<_, EqAffine, Challenge255<_>>::init(Vec::new());
                    // circuit.clone()을 위해 RangeProofCircuit에 Clone 트레잇 필요
                    let _ = create_proof(
                        &params,
                        &pk,
                        &[circuit.clone()],
                        final_instances_arg,
                        rand_core::OsRng,
                        &mut transcript_prove,
                    );
                    transcript_prove.finalize();
                });
            },
        );
        group_creation.finish();

        let mut transcript_for_one_proof =
            Blake2bWrite::<_, EqAffine, Challenge255<_>>::init(Vec::new());
        let _ = create_proof(
            &params,
            &pk,
            &[circuit.clone()],
            final_instances_arg,
            rand_core::OsRng,
            &mut transcript_for_one_proof,
        );
        let proof_for_verification = transcript_for_one_proof.finalize();

        let mut group_verification = c.benchmark_group("Range Proof Verification");
        group_verification.throughput(Throughput::Elements(current_num_inputs as u64));

        group_verification.bench_function(
            BenchmarkId::new(
                "verify_proof",
                format!("{} inputs (k={})", current_num_inputs, k_val),
            ),
            |b| {
                b.iter(|| {
                    let strategy = SingleVerifier::new(&params);
                    let mut transcript_verify = Blake2bRead::<_, EqAffine, Challenge255<_>>::init(
                        &proof_for_verification[..],
                    );
                    verify_proof(
                        &params,
                        &vk,
                        strategy,
                        final_instances_arg,
                        &mut transcript_verify,
                    )
                    .unwrap();
                });
            },
        );
        group_verification.finish();
        println!(
            "Finished benchmark for {} inputs with k={}",
            current_num_inputs, k_val
        );
    }
}

criterion_group!(
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = benchmark_range_proof
);
criterion_main!(benches);
