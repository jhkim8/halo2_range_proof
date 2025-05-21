use ff::PrimeField;
use halo2_proofs::{
    circuit::{AssignedCell, Layouter, SimpleFloorPlanner, Value},
    plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Expression, Instance, Selector},
    poly::Rotation,
};

use crate::range_chip::{LOOKUP_BITS, RangeTableChip, RangeTableConfig};

#[derive(Default)]
pub struct RangeProofCircuit<F: PrimeField> {
    pub inputs: Vec<Value<F>>,
    pub num_bits_to_check: usize,
}

#[derive(Clone, Debug)]
pub struct RangeProofCircuitConfig {
    instance: Column<Instance>,
    original_input_advice: Column<Advice>, // 추가: 원본 입력값을 할당할 컬럼
    value_chunks_advice: Column<Advice>,   // 기존: 청크들을 할당할 컬럼
    range_table_config: RangeTableConfig,
    q_decompose: Selector,
}

impl<F: PrimeField> Circuit<F> for RangeProofCircuit<F> {
    type Config = RangeProofCircuitConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let instance_col = meta.instance_column();
        let original_input_col = meta.advice_column();
        let chunks_advice_col = meta.advice_column();
        let range_config = RangeTableChip::<F>::configure(meta, chunks_advice_col);

        let q_decompose_selector = meta.selector();

        meta.create_gate("decomposition_check", |virtual_cells| {
            let q_dec = virtual_cells.query_selector(q_decompose_selector);
            let original_input_expr =
                virtual_cells.query_advice(original_input_col, Rotation::cur());

            let mut reconstructed_value = Expression::Constant(F::ZERO);
            let mut power_of_two_lookup_bits = Expression::Constant(F::ONE);
            let num_chunks_to_reconstruct = 64_usize.div_ceil(LOOKUP_BITS);

            for i in 0..num_chunks_to_reconstruct {
                let chunk_expr = virtual_cells.query_advice(chunks_advice_col, Rotation(i as i32));
                reconstructed_value =
                    reconstructed_value + chunk_expr.clone() * power_of_two_lookup_bits.clone();
                for _ in 0..LOOKUP_BITS {
                    power_of_two_lookup_bits =
                        power_of_two_lookup_bits * Expression::Constant(F::from(2));
                }
            }
            vec![q_dec * (reconstructed_value - original_input_expr)]
        });

        RangeProofCircuitConfig {
            instance: instance_col,
            original_input_advice: original_input_col,
            value_chunks_advice: chunks_advice_col,
            range_table_config: range_config,
            q_decompose: q_decompose_selector,
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let range_chip = RangeTableChip::construct(config.range_table_config.clone());
        let _ = range_chip.load_table(&mut layouter.namespace(|| "load entire range table"));

        let mut current_offset = 0;

        for (input_idx, original_value) in self.inputs.iter().enumerate() {
            let (_, _) =
                layouter.assign_region(
                    || format!("input_{}", input_idx), // 각 입력 처리에 대한 region 이름
                    |mut region| {
                        // 2.1. 원본 입력값 할당
                        //      original_input_advice 컬럼의 현재 오프셋에 원본 값을 할당합니다.
                        let input_cell = region.assign_advice(
                            || format!("original_input_{}", input_idx),
                            config.original_input_advice,
                            0, // 이 region 내에서의 상대적 오프셋
                            || *original_value,
                        )?;

                        // 2.2. 입력값을 LOOKUP_BITS 크기의 청크들로 분해
                        let num_chunks = self.num_bits_to_check.div_ceil(LOOKUP_BITS);
                        let mut decomposed_chunks: Vec<Value<F>> = Vec::with_capacity(num_chunks);

                        original_value.map(|val_f| {
                            let mut val_temp_u64 = 0u64; // 임시 변수
                            val_f.to_repr().as_ref().iter().enumerate().for_each(
                                |(idx, byte_val)| {
                                    if idx < 8 {
                                        val_temp_u64 += (*byte_val as u64) << (idx * 8);
                                    }
                                },
                            );

                            for i in 0..num_chunks {
                                let chunk = (val_temp_u64 >> (i * LOOKUP_BITS))
                                    & ((1u64 << LOOKUP_BITS) - 1);
                                decomposed_chunks.push(Value::known(F::from(chunk)));
                            }
                        });

                        // 2.3. 분해된 청크들을 value_chunks_advice 컬럼에 순차적으로 할당
                        //      각 청크는 range_chip에 의해 룩업 테이블에 있는지 자동으로 검사됩니다.
                        let mut chunk_cells: Vec<AssignedCell<F, F>> =
                            Vec::with_capacity(num_chunks);
                        for i in 0..num_chunks {
                            let cell = region.assign_advice(
                                || format!("chunk_{}_of_input_{}", i, input_idx),
                                config.value_chunks_advice,
                                i, // original_input_advice와 같은 행에서 시작하여, 청크마다 다음 행으로 (또는 같은 행의 다른 컬럼)
                                // 여기서는 각 청크를 value_chunks_advice의 i번째 행(region 내부 상대 오프셋)에 할당합니다.
                                // configure의 decomposition_gate가 이를 올바르게 참조하도록 Rotation을 사용해야 합니다.
                                // 만약 decomposition_gate가 Rotation::cur()만 쓴다면 모든 청크와 원본값이 한 행의 다른 컬럼에 있어야 합니다.
                                // 지금은 각 청크를 다음 행에 할당한다고 가정하고, decomposition_gate는 이를 감안해야 합니다.
                                // 가장 간단한 방법은 decomposition_gate가 적용될 행에 필요한 모든 값을 모아두는 것입니다.
                                // 여기서는 original_input_advice와 첫번째 chunk가 row 0에, 다음 chunk가 row 1에 ... 할당된다고 가정해봅니다.
                                // 이 경우 config.original_input_advice는 0번째 행, config.value_chunks_advice는 0, 1, ..., num_chunks-1 행에 할당됩니다.
                                || decomposed_chunks[i],
                            )?;
                            chunk_cells.push(cell);
                        }

                        // 2.4. 청크 분해/재조합 검증 게이트(q_decompose) 활성화
                        //      이 게이트는 청크들이 올바르게 원본 값을 구성하는지 확인합니다.
                        //      보통 모든 청크가 할당된 후, 특정 행(예: 마지막 청크가 할당된 행 또는 원본값이 할당된 행)에서 활성화합니다.
                        //      configure에서 정의한 게이트의 구조에 따라 정확한 위치에 활성화해야 합니다.
                        //      여기서는 원본 입력이 할당된 행(region 내부 offset 0)에서 활성화한다고 가정합니다.
                        //      이때, create_gate의 Rotation 설정이 이 가정과 맞아야 합니다.
                        //      (예: create_gate가 Rotation::cur()에서 original_input, Rotation::cur(), Rotation::next() ... 에서 chunks를 본다면)
                        config.q_decompose.enable(&mut region, 0)?; // region 내부 offset 0에서 활성화

                        current_offset += num_chunks; // 대략적인 다음 시작 오프셋 (실제로는 region 높이에 따라 조절)
                        Ok((input_cell, chunk_cells))
                    },
                )?;
        }
        Ok(())
    }
}
