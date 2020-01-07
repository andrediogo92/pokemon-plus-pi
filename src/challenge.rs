extern crate rand;

use rand::random;
use crate::aes::{AESContext, aes_ctr, aes_init, aes_hash, aes_encrypt, encrypt_block};
use crate::secrets::Secrets;
use std::convert::TryFrom;
use std::convert::From;
use std::mem::MaybeUninit;


const FLASH_DATA: [u8; 10] = [
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00
];

#[derive(Clone)]
struct MainChallengeData {
    bt_addr: [u8; 6],
    key: [u8; 16],
    nonce: [u8; 16],
    encrypted_challenge: [u8; 16],
    encrypted_hash: [u8; 16],
    flash_data: [u8; 10],
}

#[derive(Clone)]
struct ChallengeData {
    state: [u8; 4],
    nonce: [u8; 16],
    encrypted_main_challenge: [u8; 80],
    encrypted_hash: [u8; 16],
    bt_addr: [u8; 6],
    blob: [u8; 256],
}

#[derive(Clone)]
struct NextChallenge {
    state: [u8; 4],
    nonce: [u8; 16],
    encrypted_challenge: [u8; 16],
    encrypted_hash: [u8; 16],
}

fn write_by_param(offset: usize, slice: &[u8], buf: *mut u8) -> usize {
    for i in 0..slice.len() {
        unsafe {
            buf.add(offset + i).write(slice[i])
        }
    }
    return offset + slice.len();
}

impl From<MainChallengeData> for [u8; 80] {
    fn from(m: MainChallengeData) -> Self {
        let mut buf: MaybeUninit<[u8; 80]> = MaybeUninit::uninit();
        unsafe {
            let u_buf = buf.as_mut_ptr() as *mut u8;
            let mut offset = 0;
            offset = write_by_param(offset, &m.bt_addr, u_buf);
            offset = write_by_param(offset, &m.key, u_buf);
            offset = write_by_param(offset, &m.nonce, u_buf);
            offset = write_by_param(offset, &m.encrypted_challenge, u_buf);
            offset = write_by_param(offset, &m.encrypted_hash, u_buf);
            write_by_param(offset, &m.flash_data, u_buf);
            return buf.assume_init();
        }
    }
}

impl From<NextChallenge> for [u8; 52] {
    fn from(n: NextChallenge) -> Self {
        let mut buf: MaybeUninit<[u8; 52]> = MaybeUninit::uninit();
        unsafe {
            let u_buf = buf.as_mut_ptr() as *mut u8;
            let mut offset = 0;
            offset = write_by_param(offset, &n.state, u_buf);
            offset = write_by_param(offset, &n.nonce, u_buf);
            offset = write_by_param(offset, &n.encrypted_challenge, u_buf);
            write_by_param(offset, &n.encrypted_hash, u_buf);
            return buf.assume_init();
        }
    }
}

impl From<NextChallenge> for [u8; 48] {
    fn from(n: NextChallenge) -> Self {
        let mut buf: MaybeUninit<[u8; 48]> = MaybeUninit::uninit();
        unsafe {
            let u_buf = buf.as_mut_ptr() as *mut u8;
            let mut offset = 0;
            offset = write_by_param(offset, &n.nonce, u_buf);
            offset = write_by_param(offset, &n.encrypted_challenge, u_buf);
            write_by_param(offset, &n.encrypted_hash, u_buf);
            return buf.assume_init();
        }
    }
}

impl From<[u8; 80]> for MainChallengeData {
    fn from(b: [u8; 80]) -> Self {
        let (
            bt_addr, key, nonce,
            encrypted_challenge,
            encrypted_hash, flash_data
        ) = array_refs![
            &b, 6, 16, 16, 16, 16, 10
        ];
        MainChallengeData {
            bt_addr: *bt_addr,
            key: *key,
            nonce: *nonce,
            encrypted_challenge: *encrypted_challenge,
            encrypted_hash: *encrypted_hash,
            flash_data: *flash_data,
        }
    }
}

impl From<[u8; 52]> for NextChallenge {
    fn from(b: [u8; 52]) -> Self {
        let (
            state, nonce,
            encrypted_challenge,
            encrypted_hash
        ) = array_refs![
            &b, 4, 16, 16, 16
        ];
        NextChallenge {
            state: *state,
            nonce: *nonce,
            encrypted_challenge: *encrypted_challenge,
            encrypted_hash: *encrypted_hash,
        }
    }
}


trait Convert<A> {
    fn convert(x: A) -> Self;
}

impl Convert<&[u8]> for [u8; 80] {
    fn convert(n: &[u8]) -> Self {
        *array_ref![n, 0, 80]
    }
}

impl Convert<&[u8]> for [u8; 52] {
    fn convert(n: &[u8]) -> Self {
        *array_ref![n, 0, 52]
    }
}


fn generate_nonce() -> [u8; 16] {
    return [random::<u8>() & 0xff; 16];
}

fn generate_chal_0(
    secrets: Secrets, mac: &[u8; 6],
    the_challenge: &[u8], main_nonce: &[u8; 16],
    main_key: &[u8; 16], outer_nonce: [u8; 16],
) -> ChallengeData {
    let revmac: [u8; 6] = [
        mac[5], mac[4], mac[3],
        mac[2], mac[1], mac[0]
    ];
    let mcd: MainChallengeData;

    {
        let context: AESContext = aes_init(main_key);

        let tmp_hash = aes_hash(&context, main_nonce, the_challenge);
        let slice = aes_ctr(&context, main_nonce, the_challenge);
        let encrypted_challenge: [u8; 16] = <[u8; 16]>::try_from(slice.as_ref())
            .expect(
                format!(
                    "Encrypted Challenge should be same size as challenge: {}",
                    the_challenge.len()
                ).as_str()
            );

        let encrypted_hash = encrypt_block(&context, &tmp_hash, main_nonce);

        mcd = MainChallengeData {
            bt_addr: revmac,
            key: *main_key,
            nonce: *main_nonce,
            encrypted_challenge,
            encrypted_hash,
            flash_data: FLASH_DATA,
        };
    }

    {
        let context: AESContext = aes_init(&secrets.device_key);
        let main_data = <[u8; 80]>::try_from(mcd)
            .expect("Main challenge data should also be a packed 80-byte array, but is size");

        let tmp_hash = aes_hash(&context, &outer_nonce, &main_data);
        let slice = aes_ctr(&context, &outer_nonce, &main_data);
        let encrypted_main_challenge = <[u8; 80]>::convert(slice.as_ref());

        let encrypted_hash = encrypt_block(&context, &tmp_hash, &outer_nonce);
        return ChallengeData {
            bt_addr: revmac,
            blob: secrets.blob,
            encrypted_main_challenge,
            encrypted_hash,
            nonce: outer_nonce,
            state: [0, 0, 0, 0],
        };
    }
}

fn generate_next_chal(data: Option<&[u8]>, key: &[u8], nonce: &[u8; 16]) -> NextChallenge {
    let context: AESContext = aes_init(key);
    let data: [u8; 16] = match data {
        Some(t) => <[u8; 16]>::try_from(t).unwrap(),
        None => [
            0xaa, 0, 0, 0,
            0, 0, 0, 0,
            0, 0, 0, 0,
            0, 0, 0, 0,
        ]
    };

    let slice = aes_ctr(&context, nonce, &data);
    let encrypted_challenge = <[u8; 16]>::try_from(slice.as_ref()).unwrap();

    let inter_hash = aes_hash(&context, nonce, &data);
    let encrypted_hash = encrypt_block(&context, &inter_hash, nonce);

    return NextChallenge {
        encrypted_challenge,
        encrypted_hash,
        nonce: *nonce,
        state: [0, 0, 0, 0],
    };
}

fn decrypt_next(key: &[u8], challenge: &NextChallenge) -> (bool, [u8; 16]) {
    let context: AESContext = aes_init(key);
    let slice = aes_ctr(&context, &challenge.nonce, &challenge.encrypted_challenge);
    let output = <[u8; 16]>::try_from(slice.as_ref()).unwrap();
    let enc_nonce = encrypt_block(&context, &challenge.encrypted_hash, &challenge.nonce);
    let hash = aes_hash(&context, &challenge.nonce, &output);
    return (hash == enc_nonce, output);
}

fn generate_reconnect_response(key: &[u8], challenge: &NextChallenge) -> [u8; 16] {
    let context: AESContext = aes_init(key);
    let mut output = aes_encrypt(&context, &mut <[u8; 48]>::try_from(challenge.clone()).unwrap());
    for i in 0..16 {
        output[i] ^= challenge.nonce[i];
    }
    return output;
}