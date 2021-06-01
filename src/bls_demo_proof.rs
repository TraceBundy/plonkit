use std::marker::PhantomData;
use bellman_ce::worker::Worker;

use bellman_ce::plonk::better_cs::cs::{PlonkCsWidth4WithNextStepParams, Circuit};
use bellman_ce::plonk::better_cs::test_assembly::TestAssembly;
use bellman_ce::plonk::better_cs::generator::GeneratorAssembly4WithNextStep;
use bellman_ce::kate_commitment::{CrsForMonomialForm, Crs};
use bellman_ce::pairing::bls12_381::{Bls12, Fr};
use bellman_ce::plonk::commitments::transcript::keccak_transcript::RollingKeccakTranscript;
use bellman_ce::plonk::better_cs::verifier::verify;
use bellman_ce::plonk::{VerificationKey, prove_by_steps, AdaptorCircuit, Transpiler, Proof};
use bellman_ce::{Circuit as Ci, SynthesisError, ConstraintSystem};
use bellman_ce::pairing::Engine;
use crate::bellman_ce::Field;

#[derive(Clone)]
pub(crate) struct XORDemo<E: Engine> {
    pub(crate) a: Option<bool>,
    pub(crate) b: Option<bool>,
    pub(crate) _marker: PhantomData<E>,
}

impl<E:Engine> Ci<E> for XORDemo<E> {
    fn synthesize<CS: ConstraintSystem<E>>(
        self,
        cs: &mut CS
    ) -> Result<(), SynthesisError>
    {
        let a_var = cs.alloc(|| "a", || {
            if self.a.is_some() {
                if self.a.unwrap() {
                    Ok(E::Fr::one())
                } else {
                    Ok(E::Fr::zero())
                }
            } else {
                Err(SynthesisError::AssignmentMissing)
            }
        })?;
        
        cs.enforce(
            || "a_boolean_constraint",
            |lc| lc + CS::one() - a_var,
            |lc| lc + a_var,
            |lc| lc
        );
        
        let b_var = cs.alloc(|| "b", || {
            if self.b.is_some() {
                if self.b.unwrap() {
                    Ok(E::Fr::one())
                } else {
                    Ok(E::Fr::zero())
                }
            } else {
                Err(SynthesisError::AssignmentMissing)
            }
        })?;
        
        cs.enforce(
            || "b_boolean_constraint",
            |lc| lc + CS::one() - b_var,
            |lc| lc + b_var,
            |lc| lc
        );
        
        let c_var = cs.alloc_input(|| "c", || {
            if self.a.is_some() && self.b.is_some() {
                if self.a.unwrap() ^ self.b.unwrap() {
                    Ok(E::Fr::one())
                } else {
                    Ok(E::Fr::zero())
                }
            } else {
                Err(SynthesisError::AssignmentMissing)
            }
        })?;
        
        cs.enforce(
            || "c_xor_constraint",
            |lc| lc + a_var + a_var,
            |lc| lc + b_var,
            |lc| lc + a_var + b_var - c_var
        );

        Ok(())
    }
}



pub fn transpile_xor_and_prove_with_no_precomputations () -> (Proof<Bls12, PlonkCsWidth4WithNextStepParams>, VerificationKey<Bls12, PlonkCsWidth4WithNextStepParams>) {
    
    let c = XORDemo::<Bls12> {
        a: None,
        b: None,
        _marker: PhantomData
    };

    let mut transpiler = Transpiler::<Bls12, PlonkCsWidth4WithNextStepParams>::new();

    c.synthesize(&mut transpiler).expect("sythesize into traspilation must succeed");

    let hints = transpiler.into_hints();

    for (constraint_id, hint) in hints.iter() {
        println!("Constraint {} into {:?}", constraint_id, hint);
    }

    // let c = XORDemo::<Bn256> {
    //     a: None,
    //     b: None,
    //     _marker: PhantomData
    // };

    let c = XORDemo::<Bls12> {
        a: Some(true),
        b: Some(false),
        _marker: PhantomData
    };

    let adapted_curcuit = AdaptorCircuit::<Bls12, PlonkCsWidth4WithNextStepParams, _>::new(c.clone(), &hints);

    let mut assembly = TestAssembly::<Bls12, PlonkCsWidth4WithNextStepParams>::new();
    adapted_curcuit.synthesize(&mut assembly).expect("sythesize of transpiled into CS must succeed");
    let num_gates = assembly.num_gates();
    println!("Transpiled into {} gates", num_gates);

    let adapted_curcuit = AdaptorCircuit::<Bls12, _, _>::new(c.clone(), &hints);
    let mut assembly = GeneratorAssembly4WithNextStep::<Bls12>::new();
    adapted_curcuit.synthesize(&mut assembly).expect("sythesize of transpiled into CS must succeed");
    assembly.finalize();

    let worker = Worker::new();

    let setup = assembly.setup(&worker).unwrap();

    let crs_mons = Crs::<Bls12, CrsForMonomialForm>::crs_42(setup.permutation_polynomials[0].size(), &worker);

    let verification_key = VerificationKey::from_setup(
        &setup,
        &worker,
        &crs_mons
    ).unwrap();

    // let size = setup.permutation_polynomials[0].size();

    // let domain = Domain::<Fr>::new_for_size(size as u64).unwrap();
    // let non_residues = make_non_residues::<Bls12::Fr>(3);
    // println!("Non residues = {:?}", non_residues);

    type Transcr = RollingKeccakTranscript<Fr>;

    let proof = prove_by_steps::<Bls12, _, Transcr>(
        c,
        &hints,
        &setup,
        None,
        &crs_mons,
        None
    ).unwrap();

    let is_valid = verify::<Bls12, PlonkCsWidth4WithNextStepParams, Transcr>(&proof, &verification_key, None).unwrap();

    assert!(is_valid);
    return (proof, verification_key);
    // println!("Verification key = {:?}", verification_key);
    // println!("Proof = {:?}", proof);

    
}

#[test]
fn test_bls() {
    transpile_xor_and_prove_with_no_precomputations();
}