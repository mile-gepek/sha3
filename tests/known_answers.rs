//! Known-answer tests against the NIST byte-oriented SHA-3/SHAKE vectors.
//!
//! Each suite loads one derived vector file and checks every case in it.
//! The Monte Carlo tests run one 100,000 hash chain per file.

use std::fs;
use std::path::{Path, PathBuf};

use sha3::{Digest, Sha3_224, Sha3_256, Sha3_384, Sha3_512, Shake128, Shake256, Xof, XofRead};

#[derive(Clone, Copy)]
enum Algorithm {
    Sha3_224,
    Sha3_256,
    Sha3_384,
    Sha3_512,
    Shake128,
    Shake256,
}

impl Algorithm {
    fn hash(self, message: &[u8], output_len: usize) -> Vec<u8> {
        match self {
            Algorithm::Sha3_224 => Sha3_224::digest(message).to_vec(),
            Algorithm::Sha3_256 => Sha3_256::digest(message).to_vec(),
            Algorithm::Sha3_384 => Sha3_384::digest(message).to_vec(),
            Algorithm::Sha3_512 => Sha3_512::digest(message).to_vec(),
            Algorithm::Shake128 => {
                let mut hasher = Shake128::default();
                hasher.update(message);
                hasher.squeeze().read_boxed(output_len).to_vec()
            }
            Algorithm::Shake256 => {
                let mut hasher = Shake256::default();
                hasher.update(message);
                hasher.squeeze().read_boxed(output_len).to_vec()
            }
        }
    }
}

struct TestCase {
    message: Vec<u8>,
    expected: Vec<u8>,
}

/// Remove prefix and suffix double quotes from the string.
fn unquote(value: &str) -> &str {
    value
        .strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
        .expect("Test case values should be wrapped in double quotes")
}

/// Utility function to convert a hex string to a Vec of bytes.
fn hex_string_to_bytes(string: &str) -> Vec<u8> {
    assert_eq!(
        string.len() % 2,
        0,
        "A hex string should have an even number of digits: {string}"
    );
    (0..string.len() / 2)
        .map(|i| {
            u8::from_str_radix(&string[2 * i..2 * i + 2], 16)
                .expect("2 hex digits always fit into 8 bits")
        })
        .collect()
}

/// Utility function to load the .txt file with test cases.
fn load_vectors(path: &Path) -> Vec<TestCase> {
    let file = fs::read_to_string(path).expect("Opening vector file should not fail");
    let mut test_cases = Vec::new();
    let mut message = None;

    for line in file.lines() {
        let line = line.trim();
        // Skip the header comment and the blank line between test cases.
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        if let Some(value) = line.strip_prefix("Message = ") {
            message = Some(unquote(value).to_owned());
        } else if let Some(value) = line.strip_prefix("Expected = ") {
            let message = message
                .take()
                .expect("Every Expected line should be preceded by a Message line");
            let test_case = TestCase {
                message: hex_string_to_bytes(&message),
                expected: hex_string_to_bytes(unquote(value)),
            };
            test_cases.push(test_case)
        } else {
            panic!("Unexpected line in the vector file: {line}");
        }
    }
    assert!(
        !test_cases.is_empty(),
        "The vector file {path:?} contained no test cases"
    );
    test_cases
}

fn vector_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/vectors")
}

/// Number of hashes between each checkpoint in monte carlo tests.
/// A checkpoint is just an iteration where the result is compared.
const MONTE_HASHES_PER_CHECKPOINT: usize = 1000;

struct MonteVectors {
    seed: Vec<u8>,
    checkpoints: Vec<Vec<u8>>,
    /// Output length bounds in bytes, only present in the SHAKE files.
    output_bounds: Option<(usize, usize)>,
}

/// Utility function to load the .txt file with Monte Carlo test cases.
///
/// The seed is 'Seed', and each iteration's checkpoint digest is 'MD'.
fn load_monte_vectors(path: &Path) -> MonteVectors {
    let file = fs::read_to_string(path).expect("Opening Monte Carlo vector file should not fail");
    let mut seed = None;
    let mut checkpoints = Vec::new();
    let mut min_output = None;
    let mut max_output = None;

    for line in file.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        if let Some(value) = line.strip_prefix("Seed = ") {
            seed = Some(hex_string_to_bytes(unquote(value)));
        } else if let Some(value) = line.strip_prefix("MD = ") {
            checkpoints.push(hex_string_to_bytes(unquote(value)));
        } else if let Some(value) = line.strip_prefix("MinOutputBytes = ") {
            min_output = Some(value.parse().expect("Output bounds should be numbers"));
        } else if let Some(value) = line.strip_prefix("MaxOutputBytes = ") {
            max_output = Some(value.parse().expect("Output bounds should be numbers"));
        } else if line.starts_with("ITERATION = ") {
            let iteration: usize = line
                .strip_prefix("ITERATION = ")
                .unwrap()
                .parse()
                .expect("Iteration values should be numbers");
            assert_eq!(
                iteration,
                checkpoints.len(),
                "Iterations in {path:?} should be consecutive and start at zero"
            );
        } else {
            panic!("Unexpected line in the Monte Carlo vector file: {line}");
        }
    }

    let seed = seed.expect("A Monte Carlo vector file should contain a seed");
    assert!(
        !checkpoints.is_empty(),
        "The Monte Carlo vector file {path:?} contained no checkpoints"
    );
    let output_bounds = match (min_output, max_output) {
        (Some(min), Some(max)) => Some((min, max)),
        (None, None) => None,
        _ => panic!("{path:?} should specify both MinOutputBytes and MaxOutputBytes"),
    };
    MonteVectors {
        seed,
        checkpoints,
        output_bounds,
    }
}

fn sha3_monte<D: Digest>(vectors: &MonteVectors, file: &str) {
    let mut digest = vectors.seed.clone();

    for (iteration, expected) in vectors.checkpoints.iter().enumerate() {
        for _ in 0..MONTE_HASHES_PER_CHECKPOINT {
            let mut hasher = D::default();
            hasher.update(&digest);
            digest = hasher.finalize().as_ref().to_vec();
        }
        assert_eq!(digest, *expected, "{file}, iteration {iteration}");
    }
}

fn shake_monte<X: Xof>(vectors: &MonteVectors, file: &str, min_output: usize, max_output: usize) {
    let output_range = max_output - min_output + 1;
    let mut output = vectors.seed.clone();
    let mut output_len = max_output;

    for (iteration, expected) in vectors.checkpoints.iter().enumerate() {
        for _ in 0..MONTE_HASHES_PER_CHECKPOINT {
            let mut message = [0u8; 16];
            let take = output.len().min(message.len());
            message[..take].copy_from_slice(&output[..take]);

            output = X::digest_xof(&message, output_len).into_vec();

            let last = output.len() - 2;
            let rightmost = u16::from_be_bytes([output[last], output[last + 1]]);
            output_len = min_output + (usize::from(rightmost) % output_range);
        }
        assert_eq!(output, *expected, "{file}, iteration {iteration}");
    }
}

impl MonteVectors {
    fn shake_output_bounds(&self) -> (usize, usize) {
        self.output_bounds
            .expect("SHAKE Monte Carlo vector files must specify MinOutputBytes and MaxOutputBytes")
    }
}

enum MonteAlgorithm {
    Sha3_224,
    Sha3_256,
    Sha3_384,
    Sha3_512,
    Shake128,
    Shake256,
}

impl MonteAlgorithm {
    fn run(self, vectors: &MonteVectors, file: &str) {
        match self {
            MonteAlgorithm::Sha3_224 => sha3_monte::<Sha3_224>(vectors, file),
            MonteAlgorithm::Sha3_256 => sha3_monte::<Sha3_256>(vectors, file),
            MonteAlgorithm::Sha3_384 => sha3_monte::<Sha3_384>(vectors, file),
            MonteAlgorithm::Sha3_512 => sha3_monte::<Sha3_512>(vectors, file),
            MonteAlgorithm::Shake128 => {
                let (min_output, max_output) = vectors.shake_output_bounds();
                shake_monte::<Shake128>(vectors, file, min_output, max_output)
            }
            MonteAlgorithm::Shake256 => {
                let (min_output, max_output) = vectors.shake_output_bounds();
                shake_monte::<Shake256>(vectors, file, min_output, max_output)
            }
        }
    }
}

/// Declares one test per vector file, each checks every case of its file.
///
/// NOTE: This is probably slow since each file contains hundreds (maybe even thousands) of tests.
/// It might be faster to find a way to create the tests with a proc macro, so the default test runner
/// can run all of them in parallel. **BUT** I don't care.
macro_rules! known_answer_tests {
    ($($name:ident: $algorithm:ident, $file:literal;)*) => {
        $(
            #[test]
            fn $name() {
                let cases = load_vectors(&vector_dir().join($file));
                for (index, case) in cases.iter().enumerate() {
                    let digest = Algorithm::$algorithm.hash(&case.message, case.expected.len());
                    assert_eq!(
                        digest, case.expected,
                        "{}, case {index} ({} byte message)",
                        $file,
                        case.message.len()
                    );
                }
            }
        )*
    };
}

known_answer_tests! {
    sha3_224_short: Sha3_224, "sha3-224-short.txt";
    sha3_224_long: Sha3_224, "sha3-224-long.txt";
    sha3_256_short: Sha3_256, "sha3-256-short.txt";
    sha3_256_long: Sha3_256, "sha3-256-long.txt";
    sha3_384_short: Sha3_384, "sha3-384-short.txt";
    sha3_384_long: Sha3_384, "sha3-384-long.txt";
    sha3_512_short: Sha3_512, "sha3-512-short.txt";
    sha3_512_long: Sha3_512, "sha3-512-long.txt";
    shake128_short: Shake128, "shake128-short.txt";
    shake128_long: Shake128, "shake128-long.txt";
    shake128_variable_out: Shake128, "shake128-variable-out.txt";
    shake256_short: Shake256, "shake256-short.txt";
    shake256_long: Shake256, "shake256-long.txt";
    shake256_variable_out: Shake256, "shake256-variable-out.txt";
}

/// Declares one test per Monte Carlo vector file.
///
/// NOTE: Every test sequentially computing 100,000 hashes.
/// This is slow, really slow.
macro_rules! known_answer_tests_monte {
    ($($name:ident: $algorithm:ident, $file:literal;)*) => {
        $(
            #[test]
            fn $name() {
                let vectors = load_monte_vectors(&vector_dir().join($file));
                MonteAlgorithm::$algorithm.run(&vectors, $file);
            }
        )*
    };
}

known_answer_tests_monte! {
    sha3_224_monte: Sha3_224, "sha3-224-monte.txt";
    sha3_256_monte: Sha3_256, "sha3-256-monte.txt";
    sha3_384_monte: Sha3_384, "sha3-384-monte.txt";
    sha3_512_monte: Sha3_512, "sha3-512-monte.txt";
    shake128_monte: Shake128, "shake128-monte.txt";
    shake256_monte: Shake256, "shake256-monte.txt";
}
