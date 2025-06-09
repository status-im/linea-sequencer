use jni::JNIEnv;
use jni::objects::{JClass, JObjectArray, JString, JByteArray};
use jni::sys::{jboolean, jbyteArray, JNI_TRUE, JNI_FALSE};

use ark_bn254::{Bn254, Fr};
use ark_groth16::{Proof, VerifyingKey};
use ark_serialize::CanonicalDeserialize;
use ark_std::vec::Vec;
use ark_ff::PrimeField;

use rln::protocol::{verify_proof, RLNProofValues};
use std::io::Cursor;
use std::panic;

// Helper function to convert hex string to Field Element (Fr)
fn fr_from_hex(hex_str: &str) -> Result<Fr, String> {
    let hex_str = hex_str.trim_start_matches("0x");
    let mut bytes = hex::decode(hex_str).map_err(|e| format!("Hex decode error: {}", e))?;

    // Ensure the byte vector is 32 bytes long for Fr::from_be_bytes_mod_order
    // Pad with leading zeros if shorter, truncate if longer (from left, to keep least significant bytes)
    if bytes.len() < 32 {
        let mut padded_bytes = vec![0u8; 32 - bytes.len()];
        padded_bytes.extend_from_slice(&bytes);
        bytes = padded_bytes;
    } else if bytes.len() > 32 {
        // Take the last 32 bytes if the hex string represents a number larger than the field modulus
        bytes = bytes[bytes.len()-32..].to_vec();
    }

    Ok(Fr::from_be_bytes_mod_order(&bytes))
}

// Helper function to convert Java byte array to Rust Vec<u8>
fn java_byte_array_to_vec<'local>(env: &JNIEnv<'local>, array: jbyteArray) -> Result<Vec<u8>, jni::errors::Error> {
    env.convert_byte_array(unsafe { JByteArray::from_raw(array) })
}

// Helper to throw a Java RuntimeException from Rust
fn throw_exception(env: &mut JNIEnv, message: &str) {
    let _ = env.throw_new("java/lang/RuntimeException", message);
}

// JNI function, name updated to match the new Java class and package
#[no_mangle]
pub extern "system" fn Java_net_consensys_linea_rln_jni_RlnBridge_verifyRlnProof<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>, // Represents the RlnBridge class
    verifying_key_jbytes: jbyteArray,
    proof_jbytes: jbyteArray,
    public_inputs_jarray: JObjectArray<'local>,
) -> jboolean {
    // Perform JNI operations before catch_unwind
    let vk_bytes: Vec<u8>;
    match java_byte_array_to_vec(&env, verifying_key_jbytes) {
        Ok(b) => vk_bytes = b,
        Err(e) => {
            throw_exception(&mut env, &format!("Failed to convert verifying key bytes: {}", e));
            return JNI_FALSE;
        }
    }

    let proof_bytes: Vec<u8>;
    match java_byte_array_to_vec(&env, proof_jbytes) {
        Ok(b) => proof_bytes = b,
        Err(e) => {
            throw_exception(&mut env, &format!("Failed to convert proof bytes: {}", e));
            return JNI_FALSE;
        }
    }

    let num_public_inputs = match env.get_array_length(&public_inputs_jarray) {
        Ok(len) => len,
        Err(e) => {
            throw_exception(&mut env, &format!("Failed to get public inputs array length: {}", e));
            return JNI_FALSE;
        }
    };

    if num_public_inputs != 5 {
        throw_exception(&mut env, &format!("Expected 5 public inputs, got {}", num_public_inputs));
        return JNI_FALSE;
    }

    let mut public_input_strs: Vec<String> = Vec::with_capacity(num_public_inputs as usize);
    for i in 0..num_public_inputs {
        let j_object = match env.get_object_array_element(&public_inputs_jarray, i) {
            Ok(obj) => obj,
            Err(e) => {
                throw_exception(&mut env, &format!("Failed to get public input element {}: {}", i, e));
                return JNI_FALSE;
            }
        };
        let j_string = JString::from(j_object);
        let rust_string: String = match env.get_string(&j_string) {
            Ok(s) => s.into(),
            Err(e) => {
                throw_exception(&mut env, &format!("Failed to convert JString to Rust string for input {}: {}", i, e));
                return JNI_FALSE;
            }
        };
        public_input_strs.push(rust_string);
    }

    // Now, the part that can panic, using only Rust types
    let result = panic::catch_unwind(|| -> Result<bool, String> {
        let vk = VerifyingKey::<Bn254>::deserialize_compressed(&mut Cursor::new(vk_bytes))
            .map_err(|e| format!("Failed to deserialize VK: {}", e))?;

        let proof = Proof::<Bn254>::deserialize_compressed(&mut Cursor::new(proof_bytes))
            .map_err(|e| format!("Failed to deserialize Proof: {}", e))?;

        let share_x = fr_from_hex(&public_input_strs[0])?;
        let share_y = fr_from_hex(&public_input_strs[1])?;
        let epoch = fr_from_hex(&public_input_strs[2])?;
        let root = fr_from_hex(&public_input_strs[3])?;
        let nullifier = fr_from_hex(&public_input_strs[4])?;

        let rln_proof_values = RLNProofValues {
            x: share_x,
            y: share_y,
            external_nullifier: epoch,
            root,
            nullifier,
        };

        match verify_proof(&vk, &proof, &rln_proof_values) {
            Ok(verified) => Ok(verified),
            Err(e) => {
                // Log the error on the Rust side for more detailed debugging if needed
                eprintln!("RLN proof verification failed internally: {:?}", e);
                Ok(false) // Indicate verification failure rather than an operational error
            }
        }
    });

    match result {
        Ok(Ok(true)) => JNI_TRUE,
        Ok(Ok(false)) => JNI_FALSE,
        Ok(Err(e_str)) => {
            throw_exception(&mut env, &e_str);
            JNI_FALSE
        }
        Err(panic_info) => {
            let panic_msg = if let Some(s) = panic_info.downcast_ref::<&str>() {
                *s
            } else if let Some(s) = panic_info.downcast_ref::<String>() {
                s.as_str()
            } else {
                "Unknown panic occurred in Rust JNI function"
            };
            throw_exception(&mut env, &format!("Rust panic: {}", panic_msg));
            JNI_FALSE
        }
    }
} 