extern crate bellman_ce;
extern crate bellman_vk_codegen;
extern crate clap;
extern crate plonkit;

use clap::Clap;
use std::fs::File;
use std::path::Path;
use std::{str, fmt};
use bellman_ce::pairing::bn256::Bn256;
use bellman_ce::pairing::bls12_381::Bls12;
use plonkit::circom_circuit::CircomCircuit;
use plonkit::{plonk, bls_demo_proof};
use plonkit::reader;
use std::str::FromStr;
use std::fmt::{Display, Formatter};
use ff::PrimeField;


#[cfg(feature = "server")]
mod server;

//static TEMPLATE_PATH: &str = "./contrib/template.sol";

/// A zkSNARK toolkit to work with circom zkSNARKs DSL in plonk proof system
#[derive(Clap)]
#[clap(version = "0.0.4")]
struct Opts {
    #[clap(subcommand)]
    command: SubCommand,
}
enum ContractType {
    SOLIDITY,
    PLATONCPP,
}

// Implement the trait
impl FromStr for ContractType {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "solidity" => Ok(ContractType::SOLIDITY),
            "platon-cpp" => Ok(ContractType::PLATONCPP),
            _ => Err("no match"),
        }
    }
}
impl Display for ContractType {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        // We need to remove "-" from the number output.
        match self {
            ContractType::SOLIDITY=>{
                formatter.write_str("solidity")
            },
            ContractType::PLATONCPP=>{
                formatter.write_str("platon-cpp")
            },
        }
    }
}

enum Curve {
    BN256,
    BLS12381,
}

// Implement the trait
impl FromStr for Curve {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "bn256" => Ok(Curve::BN256),
            "bls12381" => Ok(Curve::BLS12381),
            _ => Err("no match"),
        }
    }
}
impl Display for Curve {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        // We need to remove "-" from the number output.
        match self {
            Curve::BN256=>{
                formatter.write_str("BN256")
            },
            Curve::BLS12381=>{
              formatter.write_str("BLS12-381")  
            },
        }
    }
}
#[derive(Clap)]
enum SubCommand {
    /// Analyse the circuit and output some stats
    Analyse(AnalyseOpts),
    /// Trusted locally set up Plonk universal srs in monomial form
    Setup(SetupOpts),
    /// Dump "SRS in lagrange form" from a "SRS in monomial form"
    DumpLagrange(DumpLagrangeOpts),
    /// Serve for SNARK proof
    Serve(ServerOpts),
    /// Generate a SNARK proof
    Prove(ProveOpts),
    /// Generate a SNARK proof bls12381 demo
    ProveDemo(ProveDemoOpts),
    /// Verify a SNARK proof
    Verify(VerifyOpts),
    /// Generate verifier smart contract
    GenerateVerifier(GenerateVerifierOpts),
    /// Export verifying key
    ExportVerificationKey(ExportVerificationKeyOpts),
    // /// Export verifier snarkjs formt smart contract
    // ExportSnarkJsContract(ExportSnarkJsContractOpts),
}

/// A subcommand for analysing the circuit and outputting some stats
#[derive(Clap)]
struct AnalyseOpts {
    /// Circuit R1CS or JSON file [default: circuit.r1cs|circuit.json]
    #[clap(short = "c", long = "circuit")]
    circuit: Option<String>,
    /// Output file
    #[clap(short = "o", long = "output", default_value = "analyse.json")]
    output: String,
}

/// A subcommand for locally trusted setting up Plonk universal srs in monomial form
#[derive(Clap)]
struct SetupOpts {
    /// Power_of_two exponent
    #[clap(short = "p", long = "power")]
    power: u32,
    /// curve type bn256, bls12381
    #[clap(short = "u", long = "curve", default_value = "bls12381")]
    curve: Curve,
    
    /// Output file for Plonk universal setup srs in monomial form
    #[clap(short = "m", long = "srs_monomial_form")]
    srs_monomial_form: String,
}

/// A subcommand for dumping SRS in lagrange form
#[derive(Clap)]
struct DumpLagrangeOpts {
    /// Source file for Plonk universal setup srs in monomial form
    #[clap(short = "m", long = "srs_monomial_form")]
    srs_monomial_form: String,
    /// Output file for Plonk universal setup srs in lagrange form
    #[clap(short = "l", long = "srs_lagrange_form")]
    srs_lagrange_form: String,
    /// Circuit R1CS or JSON file [default: circuit.r1cs|circuit.json]
    #[clap(short = "c", long = "circuit")]
    circuit: Option<String>,
}

/// A subcommand for running a server and do SNARK proving
#[derive(Clap)]
struct ServerOpts {
    /// Server address
    #[clap(long = "address")]
    srv_addr: Option<String>,
    /// Source file for Plonk universal setup srs in monomial form
    #[clap(short = "m", long = "srs_monomial_form")]
    srs_monomial_form: String,
    /// Source file for Plonk universal setup srs in lagrange form
    #[clap(short = "l", long = "srs_lagrange_form")]
    srs_lagrange_form: Option<String>,
    /// Circuit R1CS or JSON file [default: circuit.r1cs|circuit.json]
    #[clap(short = "c", long = "circuit")]
    circuit: Option<String>,
}

/// A subcommand for generating a SNARK proof
#[derive(Clap)]
struct ProveOpts {
    /// Source file for Plonk universal setup srs in monomial form
    #[clap(short = "m", long = "srs_monomial_form", default_value ="/home/yangzhou/thirdparty/plonkit/platon_test/bls_setup/12.key")]
    srs_monomial_form: String,
    /// Source file for Plonk universal setup srs in lagrange form
    #[clap(short = "l", long = "srs_lagrange_form")]
    srs_lagrange_form: Option<String>,
    /// Circuit R1CS or JSON file [default: circuit.r1cs|circuit.json]
    #[clap(short = "c", long = "circuit", default_value = "/home/yangzhou/thirdparty/plonkit/platon_test/circuit/circuit.r1cs")]
    circuit: String,
    /// Witness JSON file
    #[clap(short = "w", long = "witness", default_value = "/home/yangzhou/thirdparty/plonkit/platon_test/circuit/witness.wtns")]
    witness: String,
    /// Output file for proof BIN
    #[clap(short = "p", long = "proof", default_value = "/home/yangzhou/thirdparty/plonkit/platon_test/circuit/proof.bin")]
    proof: String,
    /// Output file for proof json
    #[clap(short = "j", long = "proofjson", default_value = "/home/yangzhou/thirdparty/plonkit/platon_test/circuit/proof.json")]
    proofjson: String,
    /// Output file for public input json
    #[clap(short = "i", long = "publicjson", default_value = "public.json")]
    publicjson: String,
    /// curve type bn256, bls12381
    #[clap(short = "u", long = "curve", default_value = "bls12381")]
    curve: Curve,
}

/// A subcommand for generating a SNARK proof bls12381 demo
#[derive(Clap)]
struct ProveDemoOpts {
    /// Output verifying key file
    #[clap(short = "v", long = "vk", default_value = "vk.bin")]
    vk: String,
    /// Output file for proof BIN
    #[clap(short = "p", long = "proof", default_value = "proof.bin")]
    proof: String,
    /// Output file for proof json
    #[clap(short = "j", long = "proofjson", default_value = "proof.json")]
    proofjson: String,
    /// Output file for public input json
    #[clap(short = "i", long = "publicjson", default_value = "public.json")]
    publicjson: String,
    /// curve type bn256, bls12381
    #[clap(short = "u", long = "curve", default_value = "bls12381")]
    curve: Curve,
}
/// A subcommand for verifying a SNARK proof
#[derive(Clap)]
struct VerifyOpts {
    /// Proof BIN file
    #[clap(short = "p", long = "proof", default_value = "/home/yangzhou/thirdparty/plonkit/target/debug/proof.bin")]
    proof: String,
    
    /// Verification key file
    #[clap(short = "v", long = "verification_key", default_value = "/home/yangzhou/thirdparty/plonkit/target/debug/vk.bin")]
    vk: String,

    /// curve type bn256, bls12381
    #[clap(short = "u", long = "curve", default_value = "bls12381")]
    curve: Curve,
}

/// A subcommand for generating a Solidity verifier smart contract
#[derive(Clap)]
struct GenerateVerifierOpts {
    /// Verification key file
    #[clap(short = "v", long = "verification_key", default_value = "/home/yangzhou/thirdparty/plonkit/target/debug/vk.bin")]
    vk: String,
    /// Output contract file
    #[clap(short = "o", long = "output", default_value = "/home/yangzhou/thirdparty/plonkit/target/debug/verifier_bls2.hpp")]
    output: String,
    /// curve type bn256, bls12381
    #[clap(short = "u", long = "curve", default_value = "bls12381")]
    curve: Curve,
    
    /// Output contract type, support:[solidity, platon-cpp]
    #[clap(short = "l", long = "lang", default_value = "platon-cpp")]
    lang: ContractType,
}

/// A subcommand for exporting verifying keys
#[derive(Clap)]
struct ExportVerificationKeyOpts {
    /// Source file for Plonk universal setup srs in monomial form
    #[clap(short = "m", long = "srs_monomial_form")]
    srs_monomial_form: String,
    /// Circuit R1CS or JSON file [default: circuit.r1cs|circuit.json]
    #[clap(short = "c", long = "circuit")]
    circuit: Option<String>,
    /// curve type bn256, bls12381
    #[clap(short = "u", long = "curve", default_value = "bls12381")]
    curve: Curve,
    /// Output verifying key file
    #[clap(short = "v", long = "vk", default_value = "vk.bin")]
    vk: String,
}

/// A subcommand for exporting verifying keys
#[derive(Clap)]
struct ExportSnarkJsContractOpts {
    /// Output contract type, support:[solidity, platon-cpp]
    #[clap(short = "l", long = "lang", default_value = "platon-cpp")]
    lang: ContractType,
    /// Snarkjs format proof file
    #[clap(short = "p", long = "proof", default_value = "proof.json")]
    proof: String,
    /// Snarkjs format verifying key file
    #[clap(short = "v", long = "vk", default_value = "verification_key.json")]
    vk: String,
    /// Output contract file
    #[clap(short = "o", long = "output", default_value = "verifier.hpp")]
    output: String,
    /// ProofOutput contract file
    #[clap(short = "pt", long = "proofoutput", default_value = "proof.cpp")]
    proof_output: String,
}

fn main() {
    // Always print backtrace on panic.
    ::std::env::set_var("RUST_BACKTRACE", "1");
    match ::std::env::var("RUST_LOG") {
        Ok(value) => {
            if value.is_empty() {
                ::std::env::set_var("RUST_LOG", "info");
            }
        }
        Err(_) => ::std::env::set_var("RUST_LOG", "info"),
    }
    env_logger::init();

    let opts: Opts = Opts::parse();
    match opts.command {
        SubCommand::Analyse(o) => {
            analyse(o);
        }
        SubCommand::Setup(o) => {
            setup(o);
        }
        SubCommand::DumpLagrange(o) => {
            dump_lagrange(o);
        }
        SubCommand::Serve(o) => {
            prove_server(o);
        }
        SubCommand::Prove(o) => {
            prove(o);
        }
        SubCommand::ProveDemo(o) => {
            prove_demo(o);
        }
        SubCommand::Verify(o) => {
            verify(o);
        }
        SubCommand::GenerateVerifier(o) => {
            generate_verifier(o);
        }
        SubCommand::ExportVerificationKey(o) => {
            export_vk(o);
        }
        // SubCommand::ExportSnarkJsContract(o) =>{
        //     export_snarkjs_contract(o);
        // }
    }
}

fn analyse(opts: AnalyseOpts) {
    let circuit_file = resolve_circuit_file(opts.circuit);
    log::info!("Loading circuit from {}...", circuit_file);
    let circuit = CircomCircuit {
        r1cs: reader::load_r1cs::<Bn256>(&circuit_file),
        witness: None,
        wire_mapping: None,
        aux_offset: plonk::AUX_OFFSET,
    };
    let mut stats = plonk::analyse(circuit).expect("analyse failed");
    let writer = File::create(&opts.output).unwrap();
    serde_json::to_writer_pretty(writer, &stats).expect("write failed");
    stats.constraint_stats.clear();
    log::info!(
        "analyse result: {}",
        serde_json::to_string_pretty(&stats).unwrap_or_else(|_| "<failed>".to_owned())
    );
    log::info!("output to {}", opts.output);
}

fn setup(opts: SetupOpts) {
    match opts.curve {
        Curve::BN256 => {
            let srs = plonk::gen_key_monomial_form::<Bn256>(opts.power).unwrap();
            let writer = File::create(&opts.srs_monomial_form).unwrap();
            srs.write(writer).unwrap();
        },
        Curve::BLS12381 => {
            let srs = plonk::gen_key_monomial_form::<Bls12>(opts.power).unwrap();
            let writer = File::create(&opts.srs_monomial_form).unwrap();
            srs.write(writer).unwrap();
        }
    }
    
    log::info!("curve {} srs_monomial_form saved to {}", opts.curve, opts.srs_monomial_form);
}

fn resolve_circuit_file(filename: Option<String>) -> String {
    match filename {
        Some(s) => s,
        None => {
            if Path::new("circuit.r1cs").exists() || !Path::new("circuit.json").exists() {
                "circuit.r1cs".to_string()
            } else {
                "circuit.json".to_string()
            }
        }
    }
}

fn dump_lagrange(opts: DumpLagrangeOpts) {
    let circuit_file = resolve_circuit_file(opts.circuit);
    log::info!("Loading circuit from {}...", circuit_file);
    let circuit = CircomCircuit {
        r1cs: reader::load_r1cs::<Bn256>(&circuit_file),
        witness: None,
        wire_mapping: None,
        aux_offset: plonk::AUX_OFFSET,
    };

    let setup = plonk::SetupForProver::prepare_setup_for_prover(circuit, reader::load_key_monomial_form(&opts.srs_monomial_form), None)
        .expect("prepare err");

    let key_lagrange_form = setup.get_srs_lagrange_form_from_monomial_form();
    let writer = File::create(&opts.srs_lagrange_form).unwrap();
    key_lagrange_form.write(writer).unwrap();
    log::info!("srs_lagrange_form saved to {}", opts.srs_lagrange_form);
}

#[cfg(feature = "server")]
fn prove_server(opts: ServerOpts) {
    let circuit_file = resolve_circuit_file(opts.circuit);
    log::info!("Loading circuit from {}...", circuit_file);
    let circuit_base = CircomCircuit {
        r1cs: reader::load_r1cs::<BN256>(&circuit_file),
        witness: None,
        wire_mapping: None,
        aux_offset: plonk::AUX_OFFSET,
    };

    let srs_monomial_form = opts.srs_monomial_form;
    let srs_lagrange_form = opts.srs_lagrange_form;

    let builder = move || -> server::ProveCore {
        let setup = plonk::SetupForProver::prepare_setup_for_prover(
            circuit_base.clone(),
            reader::load_key_monomial_form(&srs_monomial_form),
            reader::maybe_load_key_lagrange_form(srs_lagrange_form),
        )
        .expect("prepare err");

        Box::new(move |witness: Vec<u8>, validate_only: bool| -> server::CoreResult {
            let mut circut = circuit_base.clone();
            match reader::load_witness_from_array::<Bn256>(witness) {
                Ok(witness) => circut.witness = Some(witness),
                err => return server::CoreResult::any_prove_error(err, validate_only),
            }

            if validate_only {
                match setup.validate_witness(circut) {
                    Ok(_) => server::CoreResult::success(validate_only),
                    err => server::CoreResult::any_prove_error(err, validate_only),
                }
            } else {
                let start = std::time::Instant::now();
                match setup.prove(circut) {
                    Ok(proof) => {
                        let elapsed = start.elapsed().as_secs_f64();

                        let ret = server::CoreResult::success(validate_only);
                        let mut mut_resp = ret.into_prove();

                        let (inputs, serialized_proof) = bellman_vk_codegen::serialize_proof(&proof);
                        mut_resp.proof = serialized_proof.iter().map(ToString::to_string).collect();
                        mut_resp.inputs = inputs.iter().map(ToString::to_string).collect();
                        mut_resp.time_cost_secs = elapsed;

                        server::CoreResult::Prove(mut_resp)
                    }

                    err => server::CoreResult::any_prove_error(err, validate_only),
                }
            }
        })
    };

    log::info!("Starting server ... use CTRL+C to exit");
    server::run(server::ServerOptions {
        server_addr: opts.srv_addr,
        build_prove_core: Box::new(builder),
    });
}

#[cfg(not(feature = "server"))]
fn prove_server(opts: ServerOpts) {
    log::info!(
        "Binary is not built with server feature: {:?}, {:?}, {:?}, {}",
        opts.srv_addr,
        opts.circuit,
        opts.srs_lagrange_form,
        opts.srs_monomial_form
    );
}

fn prove(opts: ProveOpts) {
    let circuit_file = resolve_circuit_file(Option::from(opts.circuit));
    log::info!("Loading circuit from {}...", circuit_file);
    
    match opts.curve {
        Curve::BN256=> {
            let circuit = CircomCircuit {
                r1cs: reader::load_r1cs::<Bn256>(&circuit_file),
                witness: Some(reader::load_witness_from_file::<Bn256>(&opts.witness)),
                wire_mapping: None,
                aux_offset: plonk::AUX_OFFSET,
            };

            let setup = plonk::SetupForProver::prepare_setup_for_prover(
                circuit.clone(),
                reader::load_key_monomial_form(&opts.srs_monomial_form),
                reader::maybe_load_key_lagrange_form(opts.srs_lagrange_form),
            )
                .expect("prepare err");

            log::info!("Proving bn256...");
            let proof = setup.prove(circuit).unwrap();
            let writer = File::create(&opts.proof).unwrap();
            proof.write(writer).unwrap();
            log::info!("Proof saved to {}", opts.proof);

            cfg_if::cfg_if! {
        if #[cfg(feature = "solidity")] {
            let (inputs, serialized_proof) = bellman_vk_codegen::serialize_proof(&proof);
            let ser_proof_str = serde_json::to_string_pretty(&serialized_proof).unwrap();
            let ser_inputs_str = serde_json::to_string_pretty(&inputs).unwrap();
            std::fs::write(&opts.proofjson, ser_proof_str.as_bytes()).expect("save proofjson err");
            log::info!("Proof json saved to {}", opts.proofjson);
            std::fs::write(&opts.publicjson, ser_inputs_str.as_bytes()).expect("save publicjson err");
            log::info!("Public input json saved to {}", opts.publicjson);
        }
    }
        },
        Curve::BLS12381=>{
            let circuit = CircomCircuit::<Bls12> {
                r1cs: reader::load_r1cs::<Bls12>(&circuit_file),
                witness: Some(reader::load_witness_from_file::<Bls12>(&opts.witness)),
                wire_mapping: None,
                aux_offset: plonk::AUX_OFFSET,
            };

            let setup = plonk::SetupForProver::prepare_setup_for_prover(
                circuit.clone(),
                reader::load_key_monomial_form(&opts.srs_monomial_form),
                reader::maybe_load_key_lagrange_form(opts.srs_lagrange_form),
            )
                .expect("prepare err");

            log::info!("Proving bls12381...");
            let proof = setup.prove(circuit).unwrap();
            let writer = File::create(&opts.proof).unwrap();
            proof.write(writer).unwrap();
            log::info!("Proof saved to {}", opts.proof);

            cfg_if::cfg_if! {
        if #[cfg(feature = "solidity")] {
            let (inputs, serialized_proof) = plonkit::platon_cpp_code_gen::serialize_proof_bls12(&proof);
            let ser_proof_str = serde_json::to_string_pretty(&serialized_proof).unwrap();
            let ser_inputs_str = serde_json::to_string_pretty(&inputs).unwrap();
            std::fs::write(&opts.proofjson, ser_proof_str.as_bytes()).expect("save proofjson err");
            log::info!("Proof json saved to {}", opts.proofjson);
            std::fs::write(&opts.publicjson, ser_inputs_str.as_bytes()).expect("save publicjson err");
            log::info!("Public input json saved to {}", opts.publicjson);
        }
    }
        }
    }

}

fn prove_demo(opts: ProveDemoOpts) {
    match opts.curve {
        Curve::BN256 =>{
            let (proof, verification_key)  = plonkit::bls_demo_proof::transpile_xor_and_prove_with_no_precomputations::<Bn256>();
            let mut key_writer = std::io::BufWriter::with_capacity(
                1<<24,
                std::fs::File::create(&opts.vk).unwrap()
            );
            verification_key.write(&mut key_writer).unwrap();
            log::info!("Verification key saved to {}", opts.vk);

            let mut proof_writer = std::io::BufWriter::with_capacity(
                1<<24,
                std::fs::File::create(opts.proof).unwrap()
            );
            log::info!("Proof bin saved to {}", opts.vk);

            proof.write(&mut proof_writer).unwrap();
            let (inputs, serialized_proof) = plonkit::platon_cpp_code_gen::serialize_proof(&proof);
            let ser_proof_str = serde_json::to_string_pretty(&serialized_proof).unwrap();
            let ser_inputs_str = serde_json::to_string_pretty(&inputs).unwrap();
            std::fs::write(&opts.proofjson, ser_proof_str.as_bytes()).expect("save proofjson err");
            log::info!("Proof json saved to {}", opts.proofjson);
            std::fs::write(&opts.publicjson, ser_inputs_str.as_bytes()).expect("save publicjson err");
            log::info!("Public input json saved to {}", opts.publicjson);
        }
        Curve::BLS12381=>{
            let (proof, verification_key)  = plonkit::bls_demo_proof::transpile_xor_and_prove_with_no_precomputations::<Bls12>();
            let mut key_writer = std::io::BufWriter::with_capacity(
                1<<24,
                std::fs::File::create(&opts.vk).unwrap()
            );
            verification_key.write(&mut key_writer).unwrap();
            log::info!("Verification key saved to {}", opts.vk);

            let mut proof_writer = std::io::BufWriter::with_capacity(
                1<<24,
                std::fs::File::create(opts.proof).unwrap()
            );
            log::info!("Proof bin saved to {}", opts.vk);

            proof.write(&mut proof_writer).unwrap();
            let (inputs, serialized_proof) = plonkit::platon_cpp_code_gen::serialize_proof_bls12(&proof);
            let ser_proof_str = serde_json::to_string_pretty(&serialized_proof).unwrap();
            let ser_inputs_str = serde_json::to_string_pretty(&inputs).unwrap();
            std::fs::write(&opts.proofjson, ser_proof_str.as_bytes()).expect("save proofjson err");
            log::info!("Proof json saved to {}", opts.proofjson);
            std::fs::write(&opts.publicjson, ser_inputs_str.as_bytes()).expect("save publicjson err");
            log::info!("Public input json saved to {}", opts.publicjson);
        }
    }

}

fn verify(opts: VerifyOpts) {
    match opts.curve {
        Curve::BN256=>{
            let vk = reader::load_verification_key::<Bn256>(&opts.vk);
            let proof = reader::load_proof::<Bn256>(&opts.proof);
            let correct = plonk::verify(&vk, &proof).unwrap();
            if correct {
                log::info!("Proof is valid.");
            } else {
                log::info!("Proof is invalid!");
                std::process::exit(400);
            }
        },
        Curve::BLS12381=>{
            let vk = reader::load_verification_key::<Bls12>(&opts.vk);
            let proof = reader::load_proof::<Bls12>(&opts.proof);
            let (_, serialized_proof) = plonkit::platon_cpp_code_gen::serialize_proof_bls12(&proof);
            let ser_proof_str = serde_json::to_string_pretty(&serialized_proof).unwrap();
            println!("{}", ser_proof_str);
            let correct = plonk::verify(&vk, &proof).unwrap();
            if correct {
                log::info!("Proof is valid.");
            } else {
                log::info!("Proof is invalid!");
                std::process::exit(400);
            }
        }
    }

}

fn generate_verifier(opts: GenerateVerifierOpts) {
    match opts.lang {
        ContractType::PLATONCPP => {
            match opts.curve {
                Curve::BN256=>{
                    let vk = reader::load_verification_key::<Bn256>(&opts.vk);
                    plonkit::platon_cpp_code_gen::render_verification_key_from_default_template::<Bn256, Bn256>(&vk, &opts.output)

                },
                Curve::BLS12381=>{
                    let vk = reader::load_verification_key::<Bls12>(&opts.vk);
                    plonkit::platon_cpp_code_gen::render_verification_key_from_default_template::<Bls12,Bls12>(&vk, &opts.output)

                }
            }
        },
        ContractType::SOLIDITY => {
            let vk = reader::load_verification_key::<Bn256>(&opts.vk);
            bellman_vk_codegen::render_verification_key_from_default_template(&vk, &opts.output);
        }
    }

    log::info!("Contract saved to {}", opts.output);

}

fn export_vk(opts: ExportVerificationKeyOpts) {
    let circuit_file = resolve_circuit_file(opts.circuit);
    log::info!("Loading circuit from {}...", circuit_file);
    
    match opts.curve {
        Curve::BN256=>{
            let circuit = CircomCircuit {
                r1cs: reader::load_r1cs::<Bn256>(&circuit_file),
                witness: None,
                wire_mapping: None,
                aux_offset: plonk::AUX_OFFSET,
            };

            let setup = plonk::SetupForProver::prepare_setup_for_prover(circuit, reader::load_key_monomial_form(&opts.srs_monomial_form), None)
                .expect("prepare err");
            let vk = setup.make_verification_key().unwrap();

            //let path = Path::new(&opts.vk);
            //assert!(!path.exists(), "path for saving verification key exists: {}", path.display());
            let writer = File::create(&opts.vk).unwrap();
            vk.write(writer).unwrap();
        },
        Curve::BLS12381=>{
            let circuit = CircomCircuit {
                r1cs: reader::load_r1cs::<Bls12>(&circuit_file),
                witness: None,
                wire_mapping: None,
                aux_offset: plonk::AUX_OFFSET,
            };

            let setup = plonk::SetupForProver::prepare_setup_for_prover(circuit, reader::load_key_monomial_form(&opts.srs_monomial_form), None)
                .expect("prepare err");
            let vk = setup.make_verification_key().unwrap();

            //let path = Path::new(&opts.vk);
            //assert!(!path.exists(), "path for saving verification key exists: {}", path.display());
            let writer = File::create(&opts.vk).unwrap();
            vk.write(writer).unwrap();
        }
    } 

    log::info!("Verification key saved to {}", opts.vk);
}

// fn export_snarkjs_contract(opts : ExportSnarkJsContractOpts) {
//     match opts.lang {
//         ContractType::PLATONCPP => {
//             match opts.curve {
//                 Curve::BN256=>{
//                     let vk = reader::load_verification_key::<Bn256>(&opts.vk);
//                     plonkit::platon_cpp_code_gen::render_verification_key_from_default_template::<Bn256, Bn256>(&vk, &opts.output)
// 
//                 },
//                 Curve::BLS12381=>{
//                     let vk = reader::load_verification_key::<Bls12>(&opts.vk);
//                     plonkit::platon_cpp_code_gen::render_verification_key_from_default_template::<Bls12,Bls12>(&vk, &opts.output)
// 
//                 }
//             }
//         },
//         ContractType::SOLIDITY => {
//             let vk = reader::load_verification_key::<Bn256>(&opts.vk);
//             bellman_vk_codegen::render_verification_key_from_default_template(&vk, &opts.output);
//         }
//     }
// 
//     log::info!("Contract saved to {}", opts.output);
// }