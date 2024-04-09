use super::*;
use crate::tests::eip4844_test_circuit;
use crate::witness;
use crate::witness::individual_circuits::data_hasher_and_merklizer::compute_linear_keccak256;
use crate::zkevm_circuits::eip_4844::input::*;
use circuit_definitions::circuit_definitions::base_layer::linear_hasher::LinearHasherCircuit;
use circuit_definitions::encodings::LogQueueSimulator;
use circuit_definitions::zk_evm::aux_structures::Timestamp;
use circuit_definitions::zkevm_circuits::base_structures::log_query::{
    LogQueryWitness, LOG_QUERY_PACKED_WIDTH,
};
use circuit_definitions::zkevm_circuits::base_structures::vm_state::QUEUE_STATE_WIDTH;
use circuit_definitions::zkevm_circuits::linear_hasher::input::{
    LinearHasherCircuitInstanceWitness, LinearHasherInputData, LinearHasherInputDataWitness,
    LinearHasherInputOutputWitness, LinearHasherOutputData, LinearHasherOutputDataWitness,
};
use crossbeam::atomic::AtomicCell;
use snark_wrapper::boojum::field::U64RawRepresentable;
use snark_wrapper::boojum::gadgets::num::Num;
use snark_wrapper::boojum::gadgets::queue::{
    CircuitQueueRawWitness, QueueStateWitness, QueueTailStateWitness,
};
use snark_wrapper::boojum::gadgets::traits::allocatable::{CSAllocatable, CSPlaceholder};
use snark_wrapper::boojum::gadgets::u8::UInt8;
use std::collections::VecDeque;
use std::sync::Arc;

// This test can be passed, however it take long time to run as the DATA_ARRAY_LEN is very large.
#[test]
fn test_linear_hasher() {
    let queue_witness = {
        let log_query = LogQuery {
            timestamp: Timestamp(1712648728u32),
            tx_number_in_block: 1234u16,
            aux_byte: 0u8,
            shard_id: 0u8,
            address: H160::zero(),
            key: U256::one(),
            read_value: U256::zero(),
            written_value: U256::zero(),
            rw_flag: true,
            rollback: true,
            is_service: true,
        };
        let witness = (
            [GoldilocksField::from_raw_u64_unchecked(0); 20],
            [GoldilocksField::from_raw_u64_unchecked(0); 4],
            log_query,
        );
        let mut witnesses = VecDeque::new();
        witnesses.push_back(witness);
        witnesses
    };

    let log_queue_simulator = LogQueueSimulator {
        head: [GoldilocksField::from_raw_u64_unchecked(0); 4],
        tail: [GoldilocksField::from_raw_u64_unchecked(1); 4],
        num_items: queue_witness.len() as u32,
        witness: queue_witness,
    };

    let mut witnesses = compute_linear_keccak256(&log_queue_simulator, 0, &Poseidon2Goldilocks);
    let witness = witnesses.remove(0);

    let circuit = LinearHasherCircuit {
        witness: AtomicCell::new(Some(witness)),
        config: Arc::new(10),
        round_function: ZkSyncDefaultRoundFunction::default().into(),
        expected_public_input: None,
    };

    let circuit = linear_hasher_test_circuit(circuit);
}
