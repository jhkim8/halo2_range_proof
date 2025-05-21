use std::marker::PhantomData;

use ff::PrimeField;
use halo2_proofs::{
    circuit::{Layouter, Value},
    plonk::{Advice, Column, ConstraintSystem, Error, TableColumn},
    poly::Rotation,
};

pub const LOOKUP_BITS: usize = 8; // 예시로 8비트 테이블

#[derive(Clone, Debug)]
pub struct RangeTableConfig {
    value: Column<Advice>,
    table: TableColumn,
}

pub struct RangeTableChip<F: PrimeField> {
    config: RangeTableConfig,
    _marker: PhantomData<F>,
}

impl<F: PrimeField> RangeTableChip<F> {
    pub fn construct(config: RangeTableConfig) -> Self {
        Self {
            config,
            _marker: PhantomData,
        }
    }

    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        advice_col_for_lookup: Column<Advice>,
    ) -> RangeTableConfig {
        let table_col = meta.lookup_table_column();

        meta.lookup(|virtual_cells| {
            let value_expr = virtual_cells.query_advice(advice_col_for_lookup, Rotation::cur());
            vec![(value_expr, table_col)]
        });

        RangeTableConfig {
            value: advice_col_for_lookup,
            table: table_col,
        }
    }

    pub fn load_table(&self, layouter: &mut impl Layouter<F>) -> Result<(), Error> {
        layouter.assign_table(
            || "load range-check table",
            |mut table_region| {
                for i in 0..(1 << LOOKUP_BITS) {
                    table_region.assign_cell(
                        || format!("table_val_{}", i),
                        self.config.table,
                        i,
                        || Value::known(F::from(i as u64)),
                    )?;
                }
                Ok(())
            },
        )
    }
}
