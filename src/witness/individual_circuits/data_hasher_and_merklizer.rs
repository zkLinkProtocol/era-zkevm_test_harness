use super::*;
use crate::sha3::*;
use crate::zkevm_circuits::base_structures::log_query::*;
use crate::zkevm_circuits::linear_hasher::input::*;
use circuit_definitions::encodings::*;
use derivative::*;
use nmt_rs::{CelestiaNmt, NamespaceId, NamespaceMerkleHasher, NamespacedSha2Hasher};
use sha2::{Digest, Sha256};

const NAMESPACE_ID_LEN: usize = 28;
const NAMESPACE_VERSION_LEN: usize = 1;
const NAMESPACE_LEN: usize = NAMESPACE_ID_LEN + NAMESPACE_VERSION_LEN;
const DATA_ARRAY_LEN: usize = 1139;
const L2_TO_L1_MESSAGE_BYTE_LENGTH: usize = 88;
const DATA_BYTES_LEN: usize = DATA_ARRAY_LEN * L2_TO_L1_MESSAGE_BYTE_LENGTH;

const NAMESPACE_VERSION: u8 = 0;
const NAMESPACE_ID: [u8; NAMESPACE_ID_LEN] = [0; NAMESPACE_ID_LEN];
const SHARE_VERSION: u8 = 0;

const NS_SIZE: usize = 29;
const SHARE_BYTE_LEN: usize = 512;

pub fn compute_linear_keccak256<
    F: SmallField,
    R: BuildableCircuitRoundFunction<F, 8, 12, 4> + AlgebraicRoundFunction<F, 8, 12, 4>,
>(
    simulator: &LogQueueSimulator<F>,
    capacity: usize,
    _round_function: &R,
) -> Vec<LinearHasherCircuitInstanceWitness<F>> {
    // dbg!(&simulator.num_items);
    assert!(capacity <= u32::MAX as usize);
    let mut full_bytestring = Vec::with_capacity(DATA_ARRAY_LEN * L2_TO_L1_MESSAGE_BYTE_LENGTH);

    // only append meaningful items
    for (_, _, el) in simulator.witness.iter() {
        let serialized = el.serialize();
        assert_eq!(serialized.len(), L2_TO_L1_MESSAGE_BYTE_LENGTH);
        full_bytestring.extend(serialized);
    }

    // data should have fixed length of 1139 * 88 (L2_TO_L1_MESSAGE_BYTE_LENGTH) byte.
    for _ in 0..(DATA_ARRAY_LEN as u32 - simulator.num_items) {
        full_bytestring.extend(vec![0u8; L2_TO_L1_MESSAGE_BYTE_LENGTH]);
    }
    let pubdata_hash = create_celestis_commitment(
        NAMESPACE_VERSION,
        &NAMESPACE_ID,
        full_bytestring,
        SHARE_VERSION,
    );

    // in general we have everything ready, just form the witness

    let mut input_passthrough_data = LinearHasherInputData::placeholder_witness();
    // we only need the state of demuxed rollup storage queue
    input_passthrough_data.queue_state = take_queue_state_from_simulator(&simulator);

    let mut output_passthrough_data = LinearHasherOutputData::placeholder_witness();
    output_passthrough_data.keccak256_hash = pubdata_hash;

    let input_queue_witness: VecDeque<_> = simulator
        .witness
        .iter()
        .map(|(_encoding, old_tail, element)| {
            let circuit_witness = element.reflect();

            (circuit_witness, *old_tail)
        })
        .collect();

    let witness = LinearHasherCircuitInstanceWitness {
        closed_form_input: ClosedFormInputWitness {
            start_flag: true,
            completion_flag: true,
            observable_input: input_passthrough_data,
            observable_output: output_passthrough_data,
            hidden_fsm_input: (),
            hidden_fsm_output: (),
        },

        queue_witness: CircuitQueueRawWitness {
            elements: input_queue_witness,
        },
    };

    vec![witness]
}

// Implementation of celestia blob commitment computation.
// Official Golang implementation: https://github.com/celestiaorg/celestia-app/blob/915847191e80d836f862eea2664949d9a240abea/x/blob/types/payforblob.go#L219
fn create_celestis_commitment(
    namespace_version: u8,
    namespace_id: &[u8],
    data: Vec<u8>,
    share_version: u8,
) -> [u8; 32] {
    let shares = create_celestis_shares(namespace_version, namespace_id, data, share_version);
    create_celestis_commitment_from_shares(shares)
}

fn create_celestis_shares(
    namespace_version: u8,
    namespace_id: &[u8],
    mut data: Vec<u8>,
    share_version: u8,
) -> Vec<[u8; SHARE_BYTE_LEN]> {
    // assert_eq!(namespace_id.len(), NAMESPACE_ID_LEN);
    // assert_eq!(data.len(), DATA_BYTES_LEN);

    let mut normalized_data = vec![];
    normalized_data.extend((data.len() as u32).to_be_bytes());
    normalized_data.append(&mut data);

    let mut shares = vec![];
    let data_size = 512 - 1 - 28 - 1;
    for (i, data) in normalized_data.chunks(data_size).enumerate() {
        // Build share
        // first share: namespace_version (1-byte) || namespace_id (28-byte) || info_byte (1-byte) || sequence_len (4-byte) || data || padding with 0s until 512 bytes
        // remaining shares: namespace_version (1-byte) || namespace_id (28-byte) || info_byte (1-byte) || data || padding with 0s until 512 bytes
        let mut share = vec![];
        share.push(namespace_version);
        share.extend(namespace_id);
        share.push(new_info_byte(share_version, i == 0));
        share.extend(data);
        share.resize(SHARE_BYTE_LEN, 0);
        shares.push(share.try_into().unwrap());
    }
    shares
}

fn new_info_byte(version: u8, is_first_share: bool) -> u8 {
    let prefix = version << 1;
    if is_first_share {
        prefix + 1
    } else {
        prefix
    }
}

fn create_celestis_commitment_from_shares(shares: Vec<[u8; 512]>) -> [u8; 32] {
    const SUBTREE_ROOT_THRESHOLD: usize = 64;
    let shares_len = shares.len();
    let subtree_width = subtree_width(shares_len, SUBTREE_ROOT_THRESHOLD);
    let tree_sizes = merkle_mountain_range_sizes(shares_len, subtree_width);

    let mut leaf_sets = vec![];
    let mut cursor = 0;
    for tree_size in tree_sizes.iter() {
        let mut leaf_set = vec![];
        (cursor..cursor + tree_size).for_each(|j| leaf_set.push(shares[j]));
        leaf_sets.push(leaf_set);
        cursor += tree_size;
    }

    let mut subtree_roots = vec![];
    for set in leaf_sets.iter() {
        let mut nmt = CelestiaNmt::with_hasher(NamespacedSha2Hasher::with_ignore_max_ns(true));
        for leaf in set.iter() {
            let namespace_id = leaf[..NS_SIZE].try_into().unwrap();
            nmt.push_leaf(leaf, namespace_id).unwrap();
        }
        let nmt_root = nmt.root();
        let subtree_root = [
            nmt_root.min_namespace().as_ref(),
            nmt_root.max_namespace().as_ref(),
            nmt_root.hash().as_ref(),
        ]
        .concat();
        subtree_roots.push(subtree_root);
    }

    let mut subtree_roots_slice = vec![];
    for root in subtree_roots.iter() {
        subtree_roots_slice.push(root.as_slice());
    }
    hash_from_byte_slice(&subtree_roots_slice)
}

fn subtree_width(share_count: usize, subtree_root_threshold: usize) -> usize {
    let mut s = share_count / subtree_root_threshold;

    if share_count % subtree_root_threshold != 0 {
        s += 1;
    }

    let x = s.next_power_of_two();
    let y = ((share_count as f64).sqrt().ceil() as usize).next_power_of_two();

    std::cmp::min(x, y)
}

fn merkle_mountain_range_sizes(total_size: usize, max_tree_size: usize) -> Vec<usize> {
    let mut tree_sizes = vec![];
    let mut total_size = total_size;
    while total_size != 0 {
        let tree_size = if total_size >= max_tree_size {
            max_tree_size
        } else {
            total_size.next_power_of_two()
        };
        tree_sizes.push(tree_size);
        total_size -= tree_size;
    }
    tree_sizes
}

// computes a Merkle tree where the leaves are the byte slice,
// in the provided order. It follows RFC-6962.
fn hash_from_byte_slice(items: &[&[u8]]) -> [u8; 32] {
    let len = items.len();
    match len {
        0 => empty_hash(),
        1 => leaf_hash(items[0]),
        _ => {
            let k = get_split_point(len);
            let left = hash_from_byte_slice(&items[..k]);
            let right = hash_from_byte_slice(&items[k..]);
            inner_hash(&left, &right)
        }
    }
}

// returns the largest power of 2 less than length
fn get_split_point(len: usize) -> usize {
    let bitlen = if len == 0 {
        0
    } else {
        32 - (len as u32).leading_zeros()
    };
    let mut k = 1 << (bitlen - 1);
    if k == len {
        k >>= 1
    }
    k
}

const LEAF_PREFIX: u8 = 0;
const INNER_PREFIX: u8 = 1;
// returns tmhash(0x01 || left || right)
fn inner_hash(left: &[u8], right: &[u8]) -> [u8; 32] {
    let mut bytes = vec![];
    bytes.push(INNER_PREFIX);
    bytes.extend(left);
    bytes.extend(right);
    let digest = Sha256::digest(bytes);
    digest.into()
}

// returns tmhash(0x00 || leaf)
fn leaf_hash(leaf: &[u8]) -> [u8; 32] {
    let mut bytes = vec![];
    bytes.push(LEAF_PREFIX);
    bytes.extend(leaf);
    let digest = Sha256::digest(bytes);
    digest.into()
}

// returns tmhash(<empty>)
fn empty_hash() -> [u8; 32] {
    let bytes = vec![];
    let digest = Sha256::digest(bytes);
    digest.into()
}

#[cfg(test)]
mod tests {
    use super::{create_celestis_commitment, hash_from_byte_slice};

    #[test]
    fn test_hash_from_byte_slice() {
        // let items = &[&[1u8, 2, 3][..]][..];
        let test_suites = vec![
            (
                vec![],
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            ),
            (
                vec![&[1, 2, 3][..]],
                "054edec1d0211f624fed0cbca9d4f9400b0e491c43742af2c5b0abebf0c990d8",
            ),
            (
                vec![&[][..]],
                "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
            ),
            (
                vec![&[1, 2, 3][..], &[4, 5, 6][..]],
                "82e6cfce00453804379b53962939eaa7906b39904be0813fcadd31b100773c4b",
            ),
            (
                vec![
                    &[1, 2][..],
                    &[3, 4][..],
                    &[5, 6][..],
                    &[7, 8][..],
                    &[9, 10][..],
                ],
                "f326493eceab4f2d9ffbc78c59432a0a005d6ea98392045c74df5d14a113be18",
            ),
        ];
        for (items, hex_str) in test_suites.into_iter() {
            let hash = hash_from_byte_slice(&items);
            assert_eq!(hash, hex::decode(hex_str).unwrap().as_slice());
        }
    }

    #[test]
    fn test_celestia_create_commitment() {
        fn test(
            blob: Vec<u8>,
            share_version: u8,
            namespace_id: &str,
            namespace_version: u8,
            expected_commitment: &str,
        ) {
            let namespace_id = hex::decode(namespace_id).unwrap();
            let commitment =
                create_celestis_commitment(namespace_version, &namespace_id, blob, share_version);
            assert_eq!(hex::encode(commitment), expected_commitment);
        }
        test(
            vec![0xff; 3 * 512],
            0,
            "00000000000000000000000000000000000001010101010101010101",
            0,
            "3b9e78b6648ec1a241925b31da2ecb50bfc6f4ad552d3279928ca13ebeba8c2b",
        );
    }
}
