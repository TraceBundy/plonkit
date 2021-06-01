use bellman_ce::pairing::ff::{PrimeField, PrimeFieldRepr, ScalarEngine};
use bellman_ce::pairing::{Engine, CurveAffine};
use bellman_ce::plonk::better_cs::keys::{VerificationKey, Proof};
use bellman_ce::pairing::bn256::{Bn256, Fr};
use bellman_ce::pairing::bls12_381::{Bls12};
use bellman_ce::plonk::better_cs::cs::PlonkCsWidth4WithNextStepParams;
use handlebars::*;

use serde_json::value::{Map};

use primitive_types::U256;
use primitive_types::U512;
use ff::from_hex;
use crate::{platon_cpp_bls_template, platon_cpp_bn256_template};

pub fn render_verification_key(vk: &VerificationKey<Bn256, PlonkCsWidth4WithNextStepParams>, template_file: &str, render_to_path: &str) {
    println!("{}", template_file);
    let template = std::fs::read_to_string(template_file).expect("must read the template");
    render_verification_key_from_template::<Bn256, Bn256>(vk, &template, render_to_path);
}

pub fn render_verification_key_from_default_template<T : Engine + PlatonCppTemplate, E:RenderG1AffineToHex<T> + RenderG2AffineToHex<T> + Engine>(vk: &VerificationKey<T, PlonkCsWidth4WithNextStepParams>, render_to_path: &str) {
    // let template = include_str!("../template.sol");
    let template = T::template();
    render_verification_key_from_template::<T, E>(vk, template.as_str(), render_to_path);
}

pub fn render_verification_key_from_template<T : Engine, E:RenderG1AffineToHex<T>+RenderG2AffineToHex<T>+Engine>(vk: &VerificationKey<T, PlonkCsWidth4WithNextStepParams>, template: &str, render_to_path: &str) {
    let mut map = Map::new();

    let domain_size = vk.n.next_power_of_two().to_string();
    map.insert("domain_size".to_owned(), to_json(domain_size));

    let num_inputs = vk.num_inputs.to_string();
    map.insert("num_inputs".to_owned(), to_json(num_inputs));



    let domain = bellman_ce::plonk::domains::Domain::<T::Fr>::new_for_size(vk.n as u64 + 1).unwrap();
    let omega = domain.generator;
    println!("omega:{:?}", omega);
    map.insert("omega".to_owned(), to_json(render_scalar_to_u256(&omega)));

    for (i, c) in vk.selector_commitments.iter().enumerate() {
        let rendered = E::render_g1_affine_to_hex(c);

        for j in 0..2 {
            map.insert(format!("selector_commitment_{}_{}", i, j), to_json(&rendered[j]));
        }
    }

    for (i, c) in vk.next_step_selector_commitments.iter().enumerate() {
        let rendered = E::render_g1_affine_to_hex(c);

        for j in 0..2 {
            map.insert(format!("next_step_selector_commitment_{}_{}", i, j), to_json(&rendered[j]));
        }
    }

    for (i, c) in vk.permutation_commitments.iter().enumerate() {
        let rendered = E::render_g1_affine_to_hex(c);

        for j in 0..2 {
            map.insert(format!("permutation_commitment_{}_{}", i, j), to_json(&rendered[j]));
        }
    }

    for (i, c) in vk.non_residues.iter().enumerate() {
        let rendered = render_scalar_to_u256::<T::Fr>(&c);

        map.insert(format!("permutation_non_residue_{}", i), to_json(&rendered));
    }

    let rendered = E::render_g2_affine_to_hex(&vk.g2_elements[1]);

    map.insert("g2_x_x_c0".to_owned(), to_json(&rendered[0]));
    map.insert("g2_x_x_c1".to_owned(), to_json(&rendered[1]));
    map.insert("g2_x_y_c0".to_owned(), to_json(&rendered[2]));
    map.insert("g2_x_y_c1".to_owned(), to_json(&rendered[3]));

    let mut handlebars = Handlebars::new();

    // register template and assign a name to it
    handlebars.register_template_string("contract", template).expect("must register the template");

    // make data and render it
    // println!("{}", handlebars.render("contract", &map).unwrap());

    let mut writer = std::io::BufWriter::with_capacity(1<<24,
                                                       std::fs::File::create(render_to_path).unwrap()
    );

    let rendered = handlebars.render("contract", &map).unwrap();

    use std::io::Write;
    writer.write(rendered.as_bytes()).expect("must write to file");
}

fn render_scalar_to_u256<F: PrimeField>(el: &F) -> String {
    let mut buff = vec![];
    let repr = el.into_repr();
    repr.write_be(&mut buff).unwrap();
    let num = U512::from_big_endian(buff.as_slice());
    format!("{}", num.to_string())
}

fn render_scalar_to_u512<F: PrimeField>(el: &F) -> String {
    let mut buff = vec![];
    let repr = el.into_repr();
    repr.write_be(&mut buff).unwrap();
    let num = U512::from_big_endian(buff.as_slice());
    format!("{}", num.to_string())
}

pub trait RenderG1AffineToHex<T:Engine>{
    fn render_g1_affine_to_hex(_: &T::G1Affine)->[String; 2];
}

impl RenderG1AffineToHex<Bn256> for Bn256 {
    fn render_g1_affine_to_hex(point : &<Bn256 as Engine>::G1Affine) ->[String; 2] {
        if point.is_zero() {
            return ["0".to_string(), "0".to_string()];
        }

        let (x, y) = point.into_xy_unchecked();
        [render_scalar_to_u256(&x), render_scalar_to_u256(&y)]
    }
}

impl RenderG1AffineToHex<Bls12> for Bls12 {
    fn render_g1_affine_to_hex(point : &<Bls12  as Engine>::G1Affine)->[String; 2] {
        if point.is_zero() {
            return ["0".to_string(), "0".to_string()];
        }

        let (x, y) = point.into_xy_unchecked();
        [render_scalar_to_u512(&x), render_scalar_to_u512(&y)]
    }
}


pub trait RenderG2AffineToHex<T:Engine> {
    fn render_g2_affine_to_hex(_: &T::G2Affine)->[String;4];
}

impl RenderG2AffineToHex<Bn256> for Bn256 {
    fn render_g2_affine_to_hex(point : &<Bn256  as Engine>::G2Affine)->[String;4] {
        if point.is_zero() {
            return ["0".to_string(), "0".to_string(), "0".to_string(), "0".to_string()];
        }

        let (x, y) = point.into_xy_unchecked();

        [
            render_scalar_to_u256(&x.c0),
            render_scalar_to_u256(&x.c1),
            render_scalar_to_u256(&y.c0),
            render_scalar_to_u256(&y.c1)
        ]
    }
}

impl RenderG2AffineToHex<Bls12> for Bls12 {
    fn render_g2_affine_to_hex(point : &<Bls12   as Engine>::G2Affine) -> [String; 4] {
        if point.is_zero() {
            return ["0".to_string(), "0".to_string(), "0".to_string(), "0".to_string()];
        }

        let (x, y) = point.into_xy_unchecked();

        [
            render_scalar_to_u512(&x.c0),
            render_scalar_to_u512(&x.c1),
            render_scalar_to_u512(&y.c0),
            render_scalar_to_u512(&y.c1)
        ]
    }

}


fn serialize_g1_for_ethereum(
    point: &<Bn256 as Engine>::G1Affine
) -> (U256, U256) {
    if point.is_zero() {
        return (U256::zero(), U256::zero());
    }
    let uncompressed = point.into_uncompressed();

    let uncompressed_slice = uncompressed.as_ref();

    // bellman serializes points as big endian and in the form x, y
    // ethereum expects the same order in memory
    let x = U256::from_big_endian(&uncompressed_slice[0..32]);
    let y = U256::from_big_endian(&uncompressed_slice[32..64]);

    (x, y)
}

fn serialize_g1_for_ethereum_bls(
    point: &<Bls12 as Engine>::G1Affine
) -> (U512, U512) {
    if point.is_zero() {
        return (U512::zero(), U512::zero());
    }
    let uncompressed = point.into_uncompressed();

    let uncompressed_slice = uncompressed.as_ref();
    
    // println!("hex:{}",  hex::encode(uncompressed_slice));
    // bellman serializes points as big endian and in the form x, y
    // ethereum expects the same order in memory
    let x = U512::from_big_endian(&uncompressed_slice[0..48]);

    let y = U512::from_big_endian(&uncompressed_slice[48..96]);

    (x, y)
}

fn serialize_fe_for_ethereum(field_element: &Fr) -> U256 {
    let mut be_bytes = [0u8; 32];
    field_element
        .into_repr()
        .write_be(&mut be_bytes[..])
        .expect("get new root BE bytes");
    U256::from_big_endian(&be_bytes[..])
}

fn serialize_fe_for_ethereum_bls(field_element: &<Bls12 as ScalarEngine>::Fr) -> U512 {
    let mut be_bytes = [0u8; 32];
    field_element
        .into_repr()
        .write_be(&mut be_bytes[..])
        .expect("get new root BE bytes");
    // println!("hex fr:{}", hex::encode(be_bytes));
    U512::from_big_endian(&be_bytes[..])
}

pub fn serialize_proof(proof: &Proof<Bn256, PlonkCsWidth4WithNextStepParams>) -> (Vec<U256>, Vec<U256>) {
    let mut inputs = vec![];
    for input in proof.input_values.iter() {
        inputs.push(serialize_fe_for_ethereum(&input));
    }
    let mut serialized_proof = vec![];

    for c in proof.wire_commitments.iter() {
        let (x, y) = serialize_g1_for_ethereum(&c);
        serialized_proof.push(x);
        serialized_proof.push(y);
    }

    let (x, y) = serialize_g1_for_ethereum(&proof.grand_product_commitment);
    serialized_proof.push(x);
    serialized_proof.push(y);

    for c in proof.quotient_poly_commitments.iter() {
        let (x, y) = serialize_g1_for_ethereum(&c);
        serialized_proof.push(x);
        serialized_proof.push(y);
    }

    for c in proof.wire_values_at_z.iter() {
        serialized_proof.push(serialize_fe_for_ethereum(&c));
    }

    for c in proof.wire_values_at_z_omega.iter() {
        serialized_proof.push(serialize_fe_for_ethereum(&c));
    }

    serialized_proof.push(serialize_fe_for_ethereum(&proof.grand_product_at_z_omega));
    serialized_proof.push(serialize_fe_for_ethereum(&proof.quotient_polynomial_at_z));
    serialized_proof.push(serialize_fe_for_ethereum(&proof.linearization_polynomial_at_z));

    for c in proof.permutation_polynomials_at_z.iter() {
        serialized_proof.push(serialize_fe_for_ethereum(&c));
    }

    let (x, y) = serialize_g1_for_ethereum(&proof.opening_at_z_proof);
    serialized_proof.push(x);
    serialized_proof.push(y);

    let (x, y) = serialize_g1_for_ethereum(&proof.opening_at_z_omega_proof);
    serialized_proof.push(x);
    serialized_proof.push(y);

    (inputs, serialized_proof)
}

pub fn serialize_proof_bls12(proof: &Proof<Bls12, PlonkCsWidth4WithNextStepParams>) -> (Vec<U512>, Vec<U512>) {
    let mut inputs = vec![];
    for input in proof.input_values.iter() {
        inputs.push(serialize_fe_for_ethereum_bls(&input));
    }
    let mut serialized_proof = vec![];

    for c in proof.wire_commitments.iter() {
        let (x, y) = serialize_g1_for_ethereum_bls(&c);
        serialized_proof.push(x);
        serialized_proof.push(y);
    }

    let (x, y) = serialize_g1_for_ethereum_bls(&proof.grand_product_commitment);
    serialized_proof.push(x);
    serialized_proof.push(y);

    for c in proof.quotient_poly_commitments.iter() {
        let (x, y) = serialize_g1_for_ethereum_bls(&c);
        serialized_proof.push(x);
        serialized_proof.push(y);
    }

    for c in proof.wire_values_at_z.iter() {
        serialized_proof.push(serialize_fe_for_ethereum_bls(&c));
    }

    for c in proof.wire_values_at_z_omega.iter() {
        serialized_proof.push(serialize_fe_for_ethereum_bls(&c));
    }

    serialized_proof.push(serialize_fe_for_ethereum_bls(&proof.grand_product_at_z_omega));
    serialized_proof.push(serialize_fe_for_ethereum_bls(&proof.quotient_polynomial_at_z));
    serialized_proof.push(serialize_fe_for_ethereum_bls(&proof.linearization_polynomial_at_z));

    for c in proof.permutation_polynomials_at_z.iter() {
        serialized_proof.push(serialize_fe_for_ethereum_bls(&c));
    }

    let (x, y) = serialize_g1_for_ethereum_bls(&proof.opening_at_z_proof);
    serialized_proof.push(x);
    serialized_proof.push(y);

    let (x, y) = serialize_g1_for_ethereum_bls(&proof.opening_at_z_omega_proof);
    serialized_proof.push(x);
    serialized_proof.push(y);

    (inputs, serialized_proof)
}

pub trait PlatonCppTemplate{
    fn template() -> String;
}

impl PlatonCppTemplate for Bn256 {
    fn template() -> String {
        platon_cpp_bn256_template::PLATON_CPP_BN256_CONTRACT_TEMPLATE.to_string()
    }
}
impl PlatonCppTemplate for Bls12 {
    fn template() -> String {
        platon_cpp_bls_template::PLATON_CPP_BLS_CONTRACT_TEMPLATE.to_string()
    }
}

