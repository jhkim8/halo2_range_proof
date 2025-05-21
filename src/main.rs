use halo2_proofs::{
    circuit::Value,
    dev::MockProver,
    pasta::{EqAffine, Fp},
    plonk::{Circuit, SingleVerifier, create_proof, keygen_pk, keygen_vk, verify_proof},
    poly::commitment::Params,
    transcript::{Blake2bRead, Blake2bWrite, Challenge255},
};
use halo2_range_proof::range_circuit::RangeProofCircuit;
use rand::Rng;
use std::time::Instant;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut rng = rand::rng();
    let num_bits_to_check_for_circuit = 64;
    let num_generated_inputs: usize = 256;

    let mut values_for_circuit: Vec<Value<Fp>> = Vec::with_capacity(num_generated_inputs);

    for i in 0..num_generated_inputs {
        let random_val_u64 = if num_bits_to_check_for_circuit >= 64 {
            // num_bits_to_check_for_circuit가 64 이상이면 u64 전체 범위에서 랜덤 생성
            // (실제로는 Fp가 u64보다 큰 값을 표현할 수 있지만, from_u64는 u64를 받습니다)
            rng.random::<u64>()
        } else {
            // num_bits_to_check_for_circuit가 64 미만이면 해당 비트 범위 내에서 랜덤 생성
            let upper_bound = 1u64 << num_bits_to_check_for_circuit;
            rng.random_range(0..upper_bound)
        };

        println!("Input [{}]: {}", i, random_val_u64);
        values_for_circuit.push(Value::known(<Fp>::from(random_val_u64)));
    }

    let circuit = RangeProofCircuit::<Fp> {
        inputs: values_for_circuit,
        num_bits_to_check: num_bits_to_check_for_circuit,
    };

    let public_inputs: Vec<Vec<Fp>> = vec![vec![]]; // 예: 공개 입력 없음
    // let public_inputs = vec![circuit.inputs.iter().map(|v| v.unwrap_or_default()).collect::<Vec<Fp>>()]; // 만약 inputs가 공개라면

    let k = 12;
    let prover = MockProver::run(k, &circuit, public_inputs.clone())?; // public_inputs는 Vec<Vec<Fp>> 여야 함

    // assert_satisfied()는 모든 제약조건이 만족되었는지 확인합니다.
    // 만족되지 않으면 panic이 발생하며 오류를 출력합니다.
    prover.assert_satisfied();
    println!("MockProver test passed!");

    println!("Generating params (SRS)...");
    let params = Params::<EqAffine>::new(k);
    println!("Params generated.");

    let empty_circuit = circuit.without_witnesses();

    let vk = keygen_vk(&params, &empty_circuit)?;
    let pk = keygen_pk(&params, vk.clone(), &empty_circuit)?;

    println!("Creating proof...");
    let mut transcript_prove = Blake2bWrite::<_, EqAffine, Challenge255<_>>::init(Vec::new());

    let proof_public_inputs: &[&[Fp]] = if public_inputs[0].is_empty() {
        &[&[]]
    } else {
        &[&public_inputs[0]]
    };

    let proof_creation_start_time = Instant::now();
    create_proof(
        &params,
        &pk,
        &[circuit],
        &[proof_public_inputs],
        rand_core::OsRng,
        &mut transcript_prove,
    )?;
    let proof_creation_duration = proof_creation_start_time.elapsed();

    let proof = transcript_prove.finalize();
    println!("Proof created (size: {} bytes).", proof.len());
    println!("Proof creation time: {:?}", proof_creation_duration);

    println!("Verifying proof...");
    let strategy = SingleVerifier::new(&params);
    let mut transcript_verify = Blake2bRead::<_, EqAffine, Challenge255<_>>::init(&proof[..]);

    let proof_verification_start_time = Instant::now();
    verify_proof(
        &params,
        &vk,
        strategy,
        &[proof_public_inputs],
        &mut transcript_verify,
    )?;
    let proof_verification_duration = proof_verification_start_time.elapsed();

    println!("Proof verified successfully!");
    println!("Proof verification time: {:?}", proof_verification_duration);

    Ok(())
}
