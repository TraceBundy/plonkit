use bellman_ce::pairing::ff::{PrimeField, PrimeFieldRepr};
use bellman_ce::pairing::{Engine, CurveAffine};
use bellman_ce::plonk::better_cs::keys::{VerificationKey, Proof};
use bellman_ce::pairing::bn256::{Bn256, Fr};
use bellman_ce::plonk::better_cs::cs::PlonkCsWidth4WithNextStepParams;

use handlebars::*;

use serde_json::value::{Map};

use web3::types::U256;

pub fn render_verification_key(vk: &VerificationKey<Bn256, PlonkCsWidth4WithNextStepParams>, template_file: &str, render_to_path: &str) {
    println!("{}", template_file);
    let template = std::fs::read_to_string(template_file).expect("must read the template");
    render_verification_key_from_template(vk, &template, render_to_path);
}

pub fn render_verification_key_from_default_template(vk: &VerificationKey<Bn256, PlonkCsWidth4WithNextStepParams>, render_to_path: &str) {
    // let template = include_str!("../template.sol");
    let template = PLATON_CPP_CONTRACT_TEMPLATE;
    render_verification_key_from_template(vk, template, render_to_path);
}

pub fn render_verification_key_from_template(vk: &VerificationKey<Bn256, PlonkCsWidth4WithNextStepParams>, template: &str, render_to_path: &str) {
    let mut map = Map::new();

    let domain_size = vk.n.next_power_of_two().to_string();
    map.insert("domain_size".to_owned(), to_json(domain_size));

    let num_inputs = vk.num_inputs.to_string();
    map.insert("num_inputs".to_owned(), to_json(num_inputs));

    let domain = bellman_ce::plonk::domains::Domain::<Fr>::new_for_size(vk.n.next_power_of_two() as u64).unwrap();
    let omega = domain.generator;
    map.insert("omega".to_owned(), to_json(render_scalar_to_u256(&omega)));

    for (i, c) in vk.selector_commitments.iter().enumerate() {
        let rendered = render_g1_affine_to_hex::<Bn256>(&c);

        for j in 0..2 {
            map.insert(format!("selector_commitment_{}_{}", i, j), to_json(&rendered[j]));
        }
    }

    for (i, c) in vk.next_step_selector_commitments.iter().enumerate() {
        let rendered = render_g1_affine_to_hex::<Bn256>(&c);

        for j in 0..2 {
            map.insert(format!("next_step_selector_commitment_{}_{}", i, j), to_json(&rendered[j]));
        }
    }

    for (i, c) in vk.permutation_commitments.iter().enumerate() {
        let rendered = render_g1_affine_to_hex::<Bn256>(&c);

        for j in 0..2 {
            map.insert(format!("permutation_commitment_{}_{}", i, j), to_json(&rendered[j]));
        }
    }

    for (i, c) in vk.non_residues.iter().enumerate() {
        let rendered = render_scalar_to_u256::<Fr>(&c);

        map.insert(format!("permutation_non_residue_{}", i), to_json(&rendered));
    }

    let rendered = render_g2_affine_to_hex(&vk.g2_elements[1]);

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
    let num = U256::from_big_endian(buff.as_slice());
    format!("{}", num.to_string())
}

fn render_g1_affine_to_hex<E: Engine>(point: &E::G1Affine) -> [String; 2] {
    if point.is_zero() {
        return ["0".to_string(), "0".to_string()];
    }

    let (x, y) = point.into_xy_unchecked();
    [render_scalar_to_u256(&x), render_scalar_to_u256(&y)]
}

fn render_g2_affine_to_hex(point: &<Bn256 as Engine>::G2Affine) -> [String; 4] {
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

fn serialize_fe_for_ethereum(field_element: &Fr) -> U256 {
    let mut be_bytes = [0u8; 32];
    field_element
        .into_repr()
        .write_be(&mut be_bytes[..])
        .expect("get new root BE bytes");
    U256::from_big_endian(&be_bytes[..])
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

const  PLATON_CPP_CONTRACT_TEMPLATE : &str = r#"#pragma once

#include "platon/crypto/bn256/bn256.hpp"

namespace platon {
namespace crypto {
namespace bn256 {
namespace plonk {
typedef std::array<uint8_t, 32> bytes32;
typedef std::array<uint8_t, 4> bytes4;
typedef std::uint256_t Fr;

Fr ExpMod(const Fr &base, const Fr &exp) { return Exp(base, exp, Order); }

Fr Inverse(const Fr &fr) { return ExpMod(fr, Order - 2); }

void AddAssign(Fr &self, const Fr &other) { self = AddMod(self, other, Order); }

void SubAssign(Fr &self, const Fr &other) {
  self = AddMod(self, Order - other, Order);
}

void MulAssign(Fr &self, const Fr &other) { self = MulMod(self, other, Order); }
bool PairingProd2(const G1 &a1, const G2 &a2, const G1 &b1, const G2 &b2) {
  std::array<G1, 2> g1{a1, b1};
  std::array<G2, 2> g2{a2, b2};
  return bn256::pairing(g1, g2) == 0;
}
struct Transcript {
 public:
  Transcript() {
    state_0 = {0};
    state_1 = {0};
    challenge_counter = 0;
  }

  void update_with_u256(const std::uint256_t &value) {
    bytes32 old_state_0 = state_0;
    encodeKeccak256(DST_0, old_state_0, state_1, value, state_0.data());
    encodeKeccak256(DST_1, old_state_0, state_1, value, state_1.data());
  }

  void update_with_fr(const Fr &value) { update_with_u256(value); }

  void update_with_g1(const G1 &p) {
    update_with_u256(p.X());
    update_with_u256(p.Y());
  }

  Fr get_challenge() {
    Fr query;
    encodeKeccak256(DST_CHALLENGE, state_0, state_1, challenge_counter,
                    query.Values());
    challenge_counter += 1;
    Fr challenge = query & FR_MASK;
    return challenge;
  }

 private:
  template <size_t N>
  void encodeKeccak256(const bytes4 &dst, const bytes32 &s0, const bytes32 &s1,
                       const std::WideUint<N> &value, uint8_t *res) {
    std::array<uint8_t, 68 + N/8> input;
    copy(input.data(), dst.data(), dst.size());
    copy(input.data() + 4, s0.data(), s0.size());
    copy(input.data() + 36, s1.data(), s1.size());
    copy(input.data() + 68, value.Values(), value.arr_size);
    platon_sha3(input.data(), input.size(), res, 32);
  }

  void copy(uint8_t *dest, const uint8_t* src, size_t size){
    uint8_t zero = 0;
    bigint_binary_operator(src, false, size, &zero, \
                         false, 1, dest,  \
                         size, ADD);
  }
  // flip 0xe000000000000000000000000000000000000000000000000000000000000000;
  static constexpr std::uint256_t FR_MASK = std::uint256_t(
      "0x1fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");

  static constexpr bytes4 DST_0 = {0, 0, 0, 0};
  static constexpr bytes4 DST_1 = {0, 0, 0, 1};
  static constexpr bytes4 DST_CHALLENGE = {0, 0, 0, 2};

  bytes32 state_0;
  bytes32 state_1;
  std::WideUint<32> challenge_counter;
};

struct Plonk4VerifierWithAccessToDNext {
  static constexpr size_t STATE_WIDTH = 4;
  static constexpr size_t ACCESSIBLE_STATE_POLYS_ON_NEXT_STEP = 1;

  struct VerificationKey {
    std::uint256_t domain_size;
    size_t num_inputs;
    Fr omega;
    std::array<G1, STATE_WIDTH + 2> selector_commitments;  // STATE_WIDTH for witness +
    // multiplication + constant
    std::array<G1, ACCESSIBLE_STATE_POLYS_ON_NEXT_STEP> next_step_selector_commitments;
    std::array<G1, STATE_WIDTH> permutation_commitments;
    std::array<Fr, STATE_WIDTH - 1> permutation_non_residues;
    G2 g2_x;
  };

  struct Proof {
    std::vector<std::uint256_t> input_values;
    std::array<G1, STATE_WIDTH> wire_commitments;
    G1 grand_product_commitment;
    std::array<G1, STATE_WIDTH> quotient_poly_commitments;
    std::array<Fr, STATE_WIDTH> wire_values_at_z;
    std::array<Fr, ACCESSIBLE_STATE_POLYS_ON_NEXT_STEP> wire_values_at_z_omega;
    Fr grand_product_at_z_omega;
    Fr quotient_polynomial_at_z;
    Fr linearization_polynomial_at_z;
    std::array<Fr, STATE_WIDTH - 1> permutation_polynomials_at_z;

    G1 opening_at_z_proof;
    G1 opening_at_z_omega_proof;
  };

  struct PartialVerifierState {
    Fr alpha;
    Fr beta;
    Fr gamma;
    Fr v;
    Fr u;
    Fr z;
    std::vector<Fr> cached_lagrange_evals;
  };

  Fr evaluate_lagrange_poly_out_of_domain(const std::uint256_t &poly_num,
                                          const std::uint256_t &domain_size,
                                          const Fr &omega, const Fr &at) {
    platon_assert(poly_num < domain_size);
    Fr res;
    Fr one = 1;
    Fr omega_power = ExpMod(omega, poly_num);
    res = ExpMod(at, domain_size);
    SubAssign(res, one);
    platon_assert(res != 0);  // Vanishing polynomial can not be zero at point `at`
    MulAssign(res, omega_power);

    Fr den = at;
    SubAssign(den, omega_power);
    MulAssign(den, domain_size);

    den = Inverse(den);

    MulAssign(res, den);
    return res;
  }

  std::vector<Fr> batch_evaluate_lagrange_poly_out_of_domain(
      const std::vector<std::uint256_t> &poly_nums,
      const std::uint256_t &domain_size, const Fr &omega, const Fr &at) {
    std::vector<Fr> res;
    Fr one = 1;
    Fr tmp_1 = 0;
    Fr tmp_2 = domain_size;
    Fr vanishing_at_z = ExpMod(at, domain_size);
    SubAssign(vanishing_at_z, one);
    // we can not have random point z be in domain
    platon_assert(vanishing_at_z != 0);
    std::vector<Fr> nums;
    nums.resize(poly_nums.size());
    std::vector<Fr> dens;
    dens.resize(poly_nums.size());
    // numerators in a form omega^i * (z^n - 1)
    // denoms in a form (z - omega^i) * N
    for (size_t i = 0; i < poly_nums.size(); i++) {
      tmp_1 = ExpMod(omega, poly_nums[i]);  // power of omega
      nums[i] = vanishing_at_z;
      MulAssign(nums[i], tmp_1);

      dens[i] = at;  // (X - omega^i) * N
      SubAssign(dens[i], tmp_1);
      MulAssign(dens[i], tmp_2);  // mul by domain size
    }

    std::vector<Fr> partial_products;
    partial_products.resize(poly_nums.size());
    partial_products[0] = 1;
    for (size_t i = 1; i < dens.size(); i++) {
      partial_products[i] = dens[i - 1];
      MulAssign(partial_products[i], partial_products[i - 1]);
    }

    tmp_2 = partial_products[partial_products.size() - 1];
    MulAssign(tmp_2, dens[dens.size() - 1]);
    tmp_2 = Inverse(tmp_2);  // tmp_2 contains a^-1 * b^-1 (with! the last one)

    
    for (int i = dens.size() - 1; i >= 0; i--) {

      
      tmp_1 = tmp_2;                          // all inversed
      MulAssign(tmp_1, partial_products[i]);  // clear lowest terms
      MulAssign(tmp_2, dens[i]);
      dens[i] = tmp_1;
    }

    for (size_t i = 0; i < nums.size(); i++) {
      MulAssign(nums[i], dens[i]);
    }

    return nums;
  }

  Fr evaluate_vanishing(const std::uint256_t &domain_size, const Fr &at) {
    Fr res = ExpMod(at, domain_size);
    SubAssign(res, 1);
    return res;
  }

  bool verify_at_z(const PartialVerifierState &state, const Proof &proof,
                   const VerificationKey &vk) {
    Fr lhs = evaluate_vanishing(vk.domain_size, state.z);
    platon_assert(lhs != 0);  // we can not check a polynomial relationship if point
    // `z` is in the domain
    MulAssign(lhs, proof.quotient_polynomial_at_z);

    Fr quotient_challenge = 1;
    Fr rhs = proof.linearization_polynomial_at_z;

    // public inputs
    Fr tmp = 0;
    for (size_t i = 0; i < proof.input_values.size(); i++) {
      tmp = state.cached_lagrange_evals[i];
      MulAssign(tmp, proof.input_values[i]);
      AddAssign(rhs, tmp);
    }

    MulAssign(quotient_challenge, state.alpha);

    Fr z_part = proof.grand_product_at_z_omega;
    for (size_t i = 0; i < proof.permutation_polynomials_at_z.size(); i++) {
      tmp = proof.permutation_polynomials_at_z[i];
      MulAssign(tmp, state.beta);
      AddAssign(tmp, state.gamma);
      AddAssign(tmp, proof.wire_values_at_z[i]);
      MulAssign(z_part, tmp);
    }

    tmp = state.gamma;
    // we need a wire value of the last polynomial in enumeration
    AddAssign(tmp, proof.wire_values_at_z[STATE_WIDTH - 1]);

    MulAssign(z_part, tmp);
    MulAssign(z_part, quotient_challenge);

    SubAssign(rhs, z_part);

    MulAssign(quotient_challenge, state.alpha);

    tmp = state.cached_lagrange_evals[0];
    MulAssign(tmp, quotient_challenge);

    SubAssign(rhs, tmp);

    return lhs == rhs;
  }

  G1 reconstruct_d(const PartialVerifierState &state, const Proof &proof,
                   const VerificationKey &vk) {
    // we compute what power of v is used as a delinearization factor in batch
    // opening of commitments. Let's label W(x) = 1 / (x - z) *
    // [
    // t_0(x) + z^n * t_1(x) + z^2n * t_2(x) + z^3n * t_3(x) - t(z)
    // + v (r(x) - r(z))
    // + v^{2..5} * (witness(x) - witness(z))
    // + v^(6..8) * (permutation(x) - permutation(z))
    // ]
    // W'(x) = 1 / (x - z*omega) *
    // [
    // + v^9 (z(x) - z(z*omega)) <- we need this power
    // + v^10 * (d(x) - d(z*omega))
    // ]
    //
    // we pay a little for a few arithmetic operations to not introduce another
    // constant
    std::uint256_t power_for_z_omega_opening = 1 + 1 + STATE_WIDTH + STATE_WIDTH - 1;
    G1 res = vk.selector_commitments[STATE_WIDTH + 1];

    G1 tmp_g1 = G1::Base();
    Fr tmp_fr = 0;

    // addition gates
    for (size_t i = 0; i < STATE_WIDTH; i++) {
      tmp_g1 = ScalarMul(vk.selector_commitments[i], proof.wire_values_at_z[i]);
      res.Add(tmp_g1);
    }

    // multiplication gate
    tmp_fr = proof.wire_values_at_z[0];
    MulAssign(tmp_fr, proof.wire_values_at_z[1]);
    tmp_g1 = ScalarMul(vk.selector_commitments[STATE_WIDTH], tmp_fr);
    res.Add(tmp_g1);

    // d_next
    tmp_g1 = ScalarMul(vk.next_step_selector_commitments[0],
                       proof.wire_values_at_z_omega[0]);
    res.Add(tmp_g1);

    // z * non_res * beta + gamma + a
    Fr grand_product_part_at_z = state.z;
    MulAssign(grand_product_part_at_z, state.beta);
    AddAssign(grand_product_part_at_z, proof.wire_values_at_z[0]);
    AddAssign(grand_product_part_at_z, state.gamma);
    for (size_t i = 0; i < vk.permutation_non_residues.size(); i++) {
      tmp_fr = state.z;
      MulAssign(tmp_fr, vk.permutation_non_residues[i]);
      MulAssign(tmp_fr, state.beta);
      AddAssign(tmp_fr, state.gamma);
      AddAssign(tmp_fr, proof.wire_values_at_z[i + 1]);

      MulAssign(grand_product_part_at_z, tmp_fr);
    }

    MulAssign(grand_product_part_at_z, state.alpha);

    tmp_fr = state.cached_lagrange_evals[0];
    MulAssign(tmp_fr, state.alpha);
    MulAssign(tmp_fr, state.alpha);

    AddAssign(grand_product_part_at_z, tmp_fr);

    Fr grand_product_part_at_z_omega =
        ExpMod(state.v, power_for_z_omega_opening);
    MulAssign(grand_product_part_at_z_omega, state.u);

    Fr last_permutation_part_at_z = 1;
    for (size_t i = 0; i < proof.permutation_polynomials_at_z.size(); i++) {
      tmp_fr = state.beta;
      MulAssign(tmp_fr, proof.permutation_polynomials_at_z[i]);
      AddAssign(tmp_fr, state.gamma);
      AddAssign(tmp_fr, proof.wire_values_at_z[i]);

      MulAssign(last_permutation_part_at_z, tmp_fr);
    }

    MulAssign(last_permutation_part_at_z, state.beta);
    MulAssign(last_permutation_part_at_z, proof.grand_product_at_z_omega);
    MulAssign(last_permutation_part_at_z, state.alpha);

    // add to the linearization
    tmp_g1 = ScalarMul(proof.grand_product_commitment, grand_product_part_at_z);
    tmp_g1.Add(Neg(ScalarMul(vk.permutation_commitments[STATE_WIDTH - 1],
                             last_permutation_part_at_z)));

    res.Add(tmp_g1);
    res.ScalarMul(state.v);

    res.Add(ScalarMul(proof.grand_product_commitment,
                      grand_product_part_at_z_omega));
    return res;
  }

  bool verify_commitments(const PartialVerifierState &state, const Proof &proof,
                          const VerificationKey &vk) {
    G1 d = reconstruct_d(state, proof, vk);

    Fr z_in_domain_size = ExpMod(state.z, vk.domain_size);

    G1 tmp_g1 = G1::Base();

    Fr aggregation_challenge = 1;

    G1 commitment_aggregation = proof.quotient_poly_commitments[0];
    Fr tmp_fr = 1;
    for (size_t i = 1; i < proof.quotient_poly_commitments.size(); i++) {
      MulAssign(tmp_fr, z_in_domain_size);
      tmp_g1 = ScalarMul(proof.quotient_poly_commitments[i], tmp_fr);
      commitment_aggregation.Add(tmp_g1);
    }

    MulAssign(aggregation_challenge, state.v);
    commitment_aggregation.Add(d);

    for (size_t i = 0; i < proof.wire_commitments.size(); i++) {
      MulAssign(aggregation_challenge, state.v);
      tmp_g1 = ScalarMul(proof.wire_commitments[i], aggregation_challenge);
      commitment_aggregation.Add(tmp_g1);
    }

    for (size_t i = 0; i < vk.permutation_commitments.size() - 1; i++) {
      MulAssign(aggregation_challenge, state.v);
      tmp_g1 = ScalarMul(vk.permutation_commitments[i], aggregation_challenge);
      commitment_aggregation.Add(tmp_g1);
    }

    MulAssign(aggregation_challenge, state.v);

    MulAssign(aggregation_challenge, state.v);

    tmp_fr = aggregation_challenge;
    MulAssign(tmp_fr, state.u);
    tmp_g1 = ScalarMul(proof.wire_commitments[STATE_WIDTH - 1], tmp_fr);
    commitment_aggregation.Add(tmp_g1);

    // collect opening values
    aggregation_challenge = 1;

    Fr aggregated_value = proof.quotient_polynomial_at_z;

    MulAssign(aggregation_challenge, state.v);

    tmp_fr = proof.linearization_polynomial_at_z;
    MulAssign(tmp_fr, aggregation_challenge);
    AddAssign(aggregated_value, tmp_fr);

    for (size_t i = 0; i < proof.wire_values_at_z.size(); i++) {
      MulAssign(aggregation_challenge, state.v);

      tmp_fr = proof.wire_values_at_z[i];
      MulAssign(tmp_fr, aggregation_challenge);
      AddAssign(aggregated_value, tmp_fr);
    }

    for (size_t i = 0; i < proof.permutation_polynomials_at_z.size(); i++) {
      MulAssign(aggregation_challenge, state.v);

      tmp_fr = proof.permutation_polynomials_at_z[i];
      MulAssign(tmp_fr, aggregation_challenge);
      AddAssign(aggregated_value, tmp_fr);
    }

    MulAssign(aggregation_challenge, state.v);

    tmp_fr = proof.grand_product_at_z_omega;
    MulAssign(tmp_fr, aggregation_challenge);
    MulAssign(tmp_fr, state.u);
    AddAssign(aggregated_value, tmp_fr);

    MulAssign(aggregation_challenge, state.v);

    tmp_fr = proof.wire_values_at_z_omega[0];
    MulAssign(tmp_fr, aggregation_challenge);
    MulAssign(tmp_fr, state.u);
    AddAssign(aggregated_value, tmp_fr);

    commitment_aggregation.Add(Neg(G1::ScalarBaseMul(aggregated_value)));

    G1 pair_with_generator = commitment_aggregation;
    pair_with_generator.Add(ScalarMul(proof.opening_at_z_proof, state.z));

    tmp_fr = state.z;
    MulAssign(tmp_fr, vk.omega);
    MulAssign(tmp_fr, state.u);
    pair_with_generator.Add(ScalarMul(proof.opening_at_z_omega_proof, tmp_fr));

    G1 pair_with_x = ScalarMul(proof.opening_at_z_omega_proof, state.u);
    pair_with_x.Add(proof.opening_at_z_proof);
    pair_with_x.Neg();

    return PairingProd2(pair_with_generator, G2::Base(), pair_with_x, vk.g2_x);
  }

  bool verify_initial(PartialVerifierState &state, const Proof &proof,
                      const VerificationKey &vk) {
    platon_assert(proof.input_values.size() == vk.num_inputs);
    platon_assert(vk.num_inputs >= 1);
    Transcript transcript;
    for (size_t i = 0; i < vk.num_inputs; i++) {
      transcript.update_with_u256(proof.input_values[i]);
    }

    for (size_t i = 0; i < proof.wire_commitments.size(); i++) {
      transcript.update_with_g1(proof.wire_commitments[i]);
    }

    state.beta = transcript.get_challenge();
    state.gamma = transcript.get_challenge();

    transcript.update_with_g1(proof.grand_product_commitment);
    state.alpha = transcript.get_challenge();

    for (size_t i = 0; i < proof.quotient_poly_commitments.size(); i++) {
      transcript.update_with_g1(proof.quotient_poly_commitments[i]);
    }

    state.z = transcript.get_challenge();

    std::vector<std::uint256_t> lagrange_poly_numbers;
    lagrange_poly_numbers.resize(vk.num_inputs);
    for (size_t i = 0; i < lagrange_poly_numbers.size(); i++) {
      lagrange_poly_numbers[i] = i;
    }

    state.cached_lagrange_evals = batch_evaluate_lagrange_poly_out_of_domain(
        lagrange_poly_numbers, vk.domain_size, vk.omega, state.z);

    bool valid = verify_at_z(state, proof, vk);

    if (!valid) {
      return false;
    }

    for (size_t i = 0; i < proof.wire_values_at_z.size(); i++) {
      transcript.update_with_fr(proof.wire_values_at_z[i]);
    }

    for (size_t i = 0; i < proof.wire_values_at_z_omega.size(); i++) {
      transcript.update_with_fr(proof.wire_values_at_z_omega[i]);
    }

    for (size_t i = 0; i < proof.permutation_polynomials_at_z.size(); i++) {
      transcript.update_with_fr(proof.permutation_polynomials_at_z[i]);
    }

    transcript.update_with_fr(proof.quotient_polynomial_at_z);
    transcript.update_with_fr(proof.linearization_polynomial_at_z);
    transcript.update_with_fr(proof.grand_product_at_z_omega);

    state.v = transcript.get_challenge();
    transcript.update_with_g1(proof.opening_at_z_proof);
    transcript.update_with_g1(proof.opening_at_z_omega_proof);
    state.u = transcript.get_challenge();

    return true;
  }

  // This verifier is for a PLONK with a state width 4
  // and main gate equation
  // q_a(X) * a(X) +
  // q_b(X) * b(X) +
  // q_c(X) * c(X) +
  // q_d(X) * d(X) +
  // q_m(X) * a(X) * b(X) +
  // q_constants(X)+
  // q_d_next(X) * d(X*omega)
  // where q_{}(X) are selectors a, b, c, d - state (witness) polynomials
  // q_d_next(X) "peeks" into the next row of the trace, so it takes
  // the same d(X) polynomial, but shifted

  bool verify(const Proof &proof, const VerificationKey &vk) {
    PartialVerifierState state;

    bool valid = verify_initial(state, proof, vk);

    if (!valid) {
      return false;
    }

    valid = verify_commitments(state, proof, vk);

    return valid;
  }
};

struct KeyedVerifier : public Plonk4VerifierWithAccessToDNext {
  static constexpr size_t SERIALIZED_PROOF_LENGTH = 33;

  VerificationKey get_verification_key() {
    VerificationKey vk = {
        {{domain_size}},
        {{num_inputs}},
        "{{omega}}"_uint256,
        {
            G1{ "{{selector_commitment_0_0}}"_uint256,
                "{{selector_commitment_0_1}}"_uint256 },
            G1{ "{{selector_commitment_1_0}}"_uint256,
                "{{selector_commitment_1_1}}"_uint256 },
            G1{ "{{selector_commitment_2_0}}"_uint256,
                "{{selector_commitment_2_1}}"_uint256 },
            G1{ "{{selector_commitment_3_0}}"_uint256,
                "{{selector_commitment_3_1}}"_uint256 },
            G1{ "{{selector_commitment_4_0}}"_uint256,
                "{{selector_commitment_4_1}}"_uint256 },
            G1{ "{{selector_commitment_5_0}}"_uint256,
                "{{selector_commitment_5_1}}"_uint256 }
        },
        {
            G1{
                "{{next_step_selector_commitment_0_0}}"_uint256,
                "{{next_step_selector_commitment_0_1}}"_uint256 }
        },
        {
            G1{ "{{permutation_commitment_0_0}}"_uint256,
                "{{permutation_commitment_0_1}}"_uint256 },
            G1{ "{{permutation_commitment_1_0}}"_uint256,
                "{{permutation_commitment_1_1}}"_uint256 },
            G1{ "{{permutation_commitment_2_0}}"_uint256,
                "{{permutation_commitment_2_1}}"_uint256 },
            G1{ "{{permutation_commitment_3_0}}"_uint256,
                "{{permutation_commitment_3_1}}"_uint256 }
        },
        {
            "{{permutation_non_residue_0}}"_uint256,
            "{{permutation_non_residue_1}}"_uint256,
            "{{permutation_non_residue_2}}"_uint256
        },

        // we only have access to value of the d(x) witness polynomial on the next
        // trace step, so we only need one element here and deal with it in other
        // places by having this in mind
        G2{ "{{g2_x_x_c1}}"_uint256, "{{g2_x_x_c0}}"_uint256, "{{g2_x_y_c1}}"_uint256, "{{g2_x_y_c0}}"_uint256 }
    };


    

    return vk;
  }

  Proof deserialize_proof(const std::vector<std::uint256_t> &public_inputs,
                          const std::vector<std::uint256_t> &serialized_proof) {
    Proof proof;
    platon_assert(serialized_proof.size() == SERIALIZED_PROOF_LENGTH);
    proof.input_values.resize(public_inputs.size());
    for (size_t i = 0; i < public_inputs.size(); i++) {
      proof.input_values[i] = public_inputs[i];
    }

    size_t j = 0;
    for (size_t i = 0; i < STATE_WIDTH; i++) {
      proof.wire_commitments[i] = {serialized_proof[j],
                                   serialized_proof[j + 1]};

      j += 2;
    }

    proof.grand_product_commitment = {serialized_proof[j],
                                      serialized_proof[j + 1]};
    j += 2;

    for (size_t i = 0; i < STATE_WIDTH; i++) {
      proof.quotient_poly_commitments[i] = {serialized_proof[j],
                                            serialized_proof[j + 1]};

      j += 2;
    }

    for (size_t i = 0; i < STATE_WIDTH; i++) {
      proof.wire_values_at_z[i] = serialized_proof[j];

      j += 1;
    }

    for (size_t i = 0; i < proof.wire_values_at_z_omega.size(); i++) {
      proof.wire_values_at_z_omega[i] = serialized_proof[j];

      j += 1;
    }

    proof.grand_product_at_z_omega = serialized_proof[j];

    j += 1;

    proof.quotient_polynomial_at_z = serialized_proof[j];

    j += 1;

    proof.linearization_polynomial_at_z = serialized_proof[j];

    j += 1;

    for (size_t i = 0; i < proof.permutation_polynomials_at_z.size(); i++) {
      proof.permutation_polynomials_at_z[i] = serialized_proof[j];

      j += 1;
    }

    proof.opening_at_z_proof = {serialized_proof[j], serialized_proof[j + 1]};
    j += 2;

    proof.opening_at_z_omega_proof = {serialized_proof[j],
                                      serialized_proof[j + 1]};
    return proof;
  }

  bool verify_serialized_proof(
      const std::vector<std::uint256_t> &public_inputs,
      const std::vector<std::uint256_t> &serialized_proof) {
    VerificationKey vk = get_verification_key();
    platon_assert(vk.num_inputs == public_inputs.size());

    Proof proof = deserialize_proof(public_inputs, serialized_proof);

    bool valid = verify(proof, vk);

    return valid;
  }
};

}  // namespace plonk
}  // namespace bn256
}  // namespace crypto
}  // namespace platon

"#;