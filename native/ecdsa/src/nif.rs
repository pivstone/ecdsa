#[macro_use] extern crate rustler;
#[macro_use] extern crate lazy_static;
extern crate ring;
extern crate untrusted;
use ring::{signature,test};
use rustler::{ NifEnv, NifTerm, NifResult, NifEncoder};

mod atoms {
    rustler_atoms! {
        atom ok;
    }
}

rustler_export_nifs!(
    "Elixir.Ecdsa",
    [("add", 2, add),
    ("verify", 3, verify)],
    None
);

fn add<'a>(env: NifEnv<'a>, args: &[NifTerm<'a>]) -> NifResult<NifTerm<'a>> {
    let num1: i64 = try!(args[0].decode());
    let num2: i64 = try!(args[1].decode());

    Ok((atoms::ok(), num1 + num2).encode(env))
}

fn verify<'a>(env: NifEnv<'a>, args: &[NifTerm<'a>]) -> NifResult<NifTerm<'a>> {
    let key: &str = args[0].decode()?;
    let msg: &str = args[1].decode()?;
    let sig: &str = args[2].decode()?;
    let key_data = test::from_hex(key).unwrap();
    let sig_data = test::from_hex(sig).unwrap();
    let msg_data = test::from_hex(msg).unwrap();
    let mut alg = &signature::ECDSA_P256_SHA256_FIXED;
    if sig_data.len() > 64 {
        alg = &signature::ECDSA_P256_SHA256_ASN1
    }
    let key_ref = untrusted::Input::from(&key_data);
    let msg_ref = untrusted::Input::from(&msg_data);
    let sig_ref = untrusted::Input::from(&sig_data);
    let result = signature::verify(alg, key_ref, msg_ref, sig_ref);
    Ok(result.is_ok().encode(env))

}
