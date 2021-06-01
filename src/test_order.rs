use bellman_ce::{Engine, CurveAffine, CurveProjective, EncodedPoint};
use bellman_ce::bls12_381::Bls12;
use bellman_ce::pairing::bls12_381::Fq2;
use ff::from_hex;
use std::io::{Cursor, Read};
use bellman_ce::pairing::bn256::Bn256;


fn concat_hex_str<'a>(s0 :&'a str, s1 : &'a str) ->String{
    let s1 = if s1.starts_with("0x") { &s1[2..] } else { s1 };
    format!("{}{}", s0, s1)
}
fn decode_fr<E:Engine>(value : &str) ->E::Fr {
    from_hex::<E::Fr>(value).expect("")
}

pub fn decode_fq<E: Engine>(value: &str) -> E::Fq {
    from_hex::<E::Fq>(value).expect("")
}

// pub fn decode_fq2<E: Engine>(x0: &str, x1: &str, y0: &str, y1: &str) -> E::G2Affine {
//     let x = Fq2{
//         c0:decode_fq::<E>(x0),
//         c1:decode_fq::<E>(x1)
//     };
//     let y = Fq2{
//         c0:decode_fq::<E>(y0),
//         c1:decode_fq::<E>(y1)
//     };
//     let g = E::G2Affine::from_xy_unchecked(x, y);
//     g
// }

pub fn decode_g2<E: Engine>(x0: &str, x1: &str, y0: &str, y1: &str) ->std::io::Result<E::G2Affine> {
    let mut value = concat_hex_str(x0, x1);
    value = concat_hex_str(value.as_str(), y0);
    value = concat_hex_str(value.as_str(), y1);
    println!("{}", value);
    let mut buf = hex::decode(&value).expect("");

    let mut reader=  Cursor::new(buf);
    let mut repr = <E::G2Affine as CurveAffine>::Uncompressed::empty();
    reader.read(repr.as_mut())?;

    let e = repr
    .into_affine()
    .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
    .and_then(|e| {
    if e.is_zero() {
    Err(std::io::Error::new(
    std::io::ErrorKind::InvalidData,
    "point at infinity",
    ))?
    } else {
    Ok(e)
}
});

e
}

pub fn decode_g1<E:Engine>(x : &str, y : &str) -> E::G1Affine {
    let g =<E::G1Affine as CurveAffine>::from_xy_unchecked(
        decode_fq::<E>(x),
        decode_fq::<E>(y)
    );
    g
}

// pub fn decode_g2<E:Engine>(x : &str, y : &str) -> E::G2Affine {
//     let g =E::G2Affine::fr
//         decode_fq(x),
//         decode_fq(y)
//     );
//     g
// }

#[test]
fn test_g1() {
    use crate::bellman_ce::CurveProjective;
    let mut repr = <<Bls12 as Engine>::G1Affine as CurveAffine>::from_xy_unchecked(
        decode_fq::<Bls12>("17f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb"),
        decode_fq::<Bls12>("08b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1")
    );

    let f  = decode_fr::<Bls12>("0000000000000000000000000000000000000000000000000000000000000011");
    println!("{:?}", f);
    let mut p = repr.into_projective();
    p.mul_assign(f);
    println!("{:?}", p.into_affine());
}


#[test]
fn test_bls_pairing() {
    use crate::bellman_ce::CurveProjective;
    //bls
    // 
    //       "024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8",
    //       "13e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e",
    //       "0ce5d527727d6e118cc9cdc6da2e351aadfd9baa8cbdd3a76d429a695160d12c923ac9cc3baca289e193548608b82801",
    //       "0606c4a02ea734cc32acd2b02bc28b99cb3e287e85a763af267492ab572e99ab3f370d275cec1da1aaa9075ff05f79be",
    let g2 = decode_g2::<Bls12>(
        "13e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e",
                                "024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8",

        "0606c4a02ea734cc32acd2b02bc28b99cb3e287e85a763af267492ab572e99ab3f370d275cec1da1aaa9075ff05f79be",
                                "0ce5d527727d6e118cc9cdc6da2e351aadfd9baa8cbdd3a76d429a695160d12c923ac9cc3baca289e193548608b82801",
    );
    println!("{:?}", g2);
}

#[test]
fn test_bn256_pairing() {
    //bn256
    //       "216718d0743c44eecacadd90004f9c3d5ede9b3c74ab5da005c79d597fff3055",
    //       "0fab56dbc6e16d5b6608b81950b2f0cc6f9cba6bca9eca81e3bffa8c46fb9a18",
    //       "0065cb19b517e8ffe3b757bf2922392823cacc6c62e77a79e6f5bd3d74fc2947",
    //       "1a416e9be8b25a015e2f1a2feef271b2d8a219c21afb9e2463d67dc624f56f37",
    use crate::bellman_ce::CurveProjective;
    let g2 = decode_g2::<Bn256>(
        "216718d0743c44eecacadd90004f9c3d5ede9b3c74ab5da005c79d597fff3055",
        "0fab56dbc6e16d5b6608b81950b2f0cc6f9cba6bca9eca81e3bffa8c46fb9a18",
        "0065cb19b517e8ffe3b757bf2922392823cacc6c62e77a79e6f5bd3d74fc2947",
        "1a416e9be8b25a015e2f1a2feef271b2d8a219c21afb9e2463d67dc624f56f37",
    );
    println!("{:?}", g2);
}