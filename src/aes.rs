extern crate aes;
extern crate block_modes;

use std::num::Wrapping;
use std::mem::MaybeUninit;

use aes::Aes128;
use block_modes::{BlockMode, Ecb};
use block_modes::block_padding::ZeroPadding;
use aes::block_cipher_trait::BlockCipher;
use std::convert::TryInto;
use self::aes::block_cipher_trait::generic_array::GenericArray;

pub struct AESContext {
    ecb: Ecb<Aes128, ZeroPadding>,
    aes128: Aes128,
}

pub fn aes_init(key: &[u8]) -> AESContext {
    let cypher = Aes128::new_varkey(key).unwrap();
    return AESContext {
        aes128: cypher.clone(),
        ecb: Ecb::new(cypher, &GenericArray::<u8, _>::default()),
    };
}

fn aes_clone(context: &AESContext) -> Ecb<Aes128, ZeroPadding> {
    let aes128 = context.aes128.clone();
    return Ecb::new(aes128, &GenericArray::<u8, _>::default());
}

pub fn aes_encrypt(context: &AESContext, ctr: &mut [u8]) -> [u8; 16] {
    let context = aes_clone(context);
    return context
        .encrypt(ctr, ctr.len())
        .unwrap()
        .try_into()
        .expect("Expected 16 byte AES payload");
}

fn init_nonce_counter(inp_nonce: &[u8; 16]) -> [u8; 16] {
    return [
        1, inp_nonce[0], inp_nonce[1], inp_nonce[2],
        inp_nonce[3], inp_nonce[4], inp_nonce[5], inp_nonce[6],
        inp_nonce[7], inp_nonce[8], inp_nonce[9], inp_nonce[10],
        inp_nonce[11], inp_nonce[12], 0, 0
    ];
}

fn inc_ctr(ctr: &mut [u8; 16]) {
    ctr[15] = (Wrapping(ctr[15]) + Wrapping(1)).0;
    if ctr[15] == 0 {
        ctr[14] = (Wrapping(ctr[14]) + Wrapping(1)).0;
    }
}

pub fn aes_ctr(context: &AESContext, nonce: &[u8; 16], data: &[u8]) -> Vec<u8> {
    let count = data.len();
    let mut output: Vec<u8> = Vec::with_capacity(count);

    let mut ctr = init_nonce_counter(nonce);
    let blocks = count / 16;

    for i in 0..blocks {
        inc_ctr(&mut ctr);
        let copy = array_mut_ref![ctr, 0, 16];
        let ectr = &mut aes_encrypt(context, copy);

        for j in 0..16 {
            output[j + i * 16] = ectr[j] ^ data[j + i * 16];
        }
    }

    return output;
}


fn init_nonce_hash(inp_nonce: &[u8; 16], data_len: usize) -> [u8; 16] {
    return [
        57, inp_nonce[0], inp_nonce[1], inp_nonce[2],
        inp_nonce[3], inp_nonce[4], inp_nonce[5], inp_nonce[6],
        inp_nonce[7], inp_nonce[8], inp_nonce[9], inp_nonce[10],
        inp_nonce[11], inp_nonce[12], ((data_len >> 8) & 0xFF) as u8, (data_len & 0xFF) as u8
    ];
}

pub fn aes_hash(context: &AESContext, nonce: &[u8; 16], data: &[u8]) -> [u8; 16] {
    let count = data.len();
    let nonce_hash: [u8; 16] = init_nonce_hash(nonce, count);

    let mut output: [u8; 16] = *array_ref![nonce_hash, 0, 16];
    output = aes_encrypt(context,&mut output);

    let blocks = count / 16;
    for i in 0..blocks {
        for j in 0..16 {
            output[j] ^= data[j + i * 16]
        }
        output = aes_encrypt(context, &mut output);
    }
    return output;
}


pub fn encrypt_block(context: &AESContext, nonce_iv: &[u8; 16], nonce: &[u8; 16]) -> [u8; 16] {
    let mut output: MaybeUninit<[u8; 16]> = MaybeUninit::uninit();
    let mut nonce_ctr: [u8; 16] = init_nonce_counter(nonce);
    let tmp = aes_encrypt(context, &mut nonce_ctr);

    for i in 0..16 {
        unsafe {
            let output = output.as_mut_ptr() as *mut u8;
            output.add(i).write(tmp[i] ^ nonce_iv[i]);
        };
    }

    return unsafe { output.assume_init() };
}
