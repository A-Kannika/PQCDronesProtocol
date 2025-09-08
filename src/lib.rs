use pyo3::prelude::*;
use pyo3::types::PyBytes;
use sha2::{Digest, Sha256};

// --- From-Scratch HMAC Implementation (Unchanged) ---
const SHA256_BLOCK_SIZE: usize = 64;

fn hmac_sha256_logic(key: &[u8], message: &[u8]) -> [u8; 32] {
    let mut sized_key = [0u8; SHA256_BLOCK_SIZE];
    if key.len() > SHA256_BLOCK_SIZE {
        let hashed_key = Sha256::digest(key);
        sized_key[..hashed_key.len()].copy_from_slice(&hashed_key);
    } else {
        sized_key[..key.len()].copy_from_slice(key);
    }

    let mut o_key_pad = [0u8; SHA256_BLOCK_SIZE];
    let mut i_key_pad = [0u8; SHA256_BLOCK_SIZE];

    for i in 0..SHA256_BLOCK_SIZE {
        o_key_pad[i] = sized_key[i] ^ 0x5c;
        i_key_pad[i] = sized_key[i] ^ 0x36;
    }

    let mut inner_hasher = Sha256::new();
    inner_hasher.update(&i_key_pad);
    inner_hasher.update(message);
    let inner_hash = inner_hasher.finalize();

    let mut outer_hasher = Sha256::new();
    outer_hasher.update(&o_key_pad);
    outer_hasher.update(&inner_hash);
    
    outer_hasher.finalize().into()
}

// --- Optimized From-Scratch Ascon-MAC (Correct PRF128 Mode) ---

const ASCON_KEY_LEN: usize = 16;
const ASCON_TAG_LEN: usize = 16;
const ASCON_RATE: usize = 32;
const ASCON_STATE_SIZE: usize = 5;

const IV: [u64; ASCON_STATE_SIZE] = [
    0x80400c0600000000, // IV encoding: k=128, r=128, a=12 (standard)
    0, 0, 0, 0
];

const ROUND_CONSTANTS: [u64; 12] = [
    0xf0, 0xe1, 0xd2, 0xc3, 0xb4, 0xa5,
    0x96, 0x87, 0x78, 0x69, 0x5a, 0x4b
];

fn ascon_permutation(state: &mut [u64; ASCON_STATE_SIZE]) {
    for &rc in &ROUND_CONSTANTS {
        state[2] ^= rc;

        state[0] ^= state[4];
        state[4] ^= state[3];
        state[2] ^= state[1];

        let t0 = (state[0] & !state[1]) ^ state[2];
        let t1 = (state[1] & !state[2]) ^ state[3];
        let t2 = (state[2] & !state[3]) ^ state[4];
        let t3 = (state[3] & !state[4]) ^ state[0];
        let t4 = (state[4] & !state[0]) ^ state[1];

        state[0] = t0;
        state[1] = t1;
        state[2] = !t2;
        state[3] = t3;
        state[4] = t4;

        state[0] ^= state[0].rotate_right(19) ^ state[0].rotate_right(28);
        state[1] ^= state[1].rotate_right(61) ^ state[1].rotate_right(39);
        state[2] ^= state[2].rotate_right(1) ^ state[2].rotate_right(6);
        state[3] ^= state[3].rotate_right(10) ^ state[3].rotate_right(17);
        state[4] ^= state[4].rotate_right(7) ^ state[4].rotate_right(41);
    }
}

fn ascon_mac_logic(key: &[u8; ASCON_KEY_LEN], message: &[u8]) -> [u8; ASCON_TAG_LEN] {
    let mut state = IV;
    state[1] = u64::from_be_bytes(key[0..8].try_into().unwrap());
    state[2] = u64::from_be_bytes(key[8..16].try_into().unwrap());
    ascon_permutation(&mut state);

    let mut msg_chunks = message.chunks_exact(ASCON_RATE);
    for chunk in &mut msg_chunks {
        for i in 0..4 {
            let word = u64::from_be_bytes(chunk[i*8..(i+1)*8].try_into().unwrap());
            state[i] ^= word;
        }
        ascon_permutation(&mut state);
    }

    let last_chunk = msg_chunks.remainder();
    if !last_chunk.is_empty() {
        let mut padded = [0u8; ASCON_RATE];
        padded[..last_chunk.len()].copy_from_slice(last_chunk);
        padded[last_chunk.len()] = 0x80;

        for i in 0..4 {
            let word = u64::from_be_bytes(padded[i*8..(i+1)*8].try_into().unwrap());
            state[i] ^= word;
        }
    } else {
        // 0-length final block (still pad and permute)
        state[0] ^= 0x8000000000000000;
    }

    ascon_permutation(&mut state);

    let mut tag = [0u8; ASCON_TAG_LEN];
    tag[..8].copy_from_slice(&state[0].to_be_bytes());
    tag[8..].copy_from_slice(&state[1].to_be_bytes());
    tag
}

// --- PyO3 Wrapper Functions (Unchanged) ---

#[pyfunction]
fn hmac_sha256(py: Python, key: &[u8], message: &[u8]) -> PyResult<Py<PyBytes>> {
    let result = hmac_sha256_logic(key, message);
    Ok(PyBytes::new_bound(py, &result).into())
}

#[pyfunction]
fn ascon_mac(py: Python, key: &[u8], message: &[u8]) -> PyResult<Py<PyBytes>> {
    if key.len() != ASCON_KEY_LEN {
        return Err(pyo3::exceptions::PyValueError::new_err(
            format!("Ascon key must be {} bytes", ASCON_KEY_LEN)
        ));
    }
    let key_array: [u8; ASCON_KEY_LEN] = key.try_into().unwrap();
    let result = ascon_mac_logic(&key_array, message);
    Ok(PyBytes::new_bound(py, &result).into())
}

#[pymodule]
fn rust_macs(_py: Python, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(hmac_sha256, m)?)?;
    m.add_function(wrap_pyfunction!(ascon_mac, m)?)?;
    Ok(())
}