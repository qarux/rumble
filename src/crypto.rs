use std::cmp::Ordering;

use aes::cipher::generic_array::GenericArray;
use aes::{Aes128, BlockDecrypt, BlockEncrypt, NewBlockCipher};

const AES_BLOCK_SIZE: usize = 16;
const SHIFT_BITS: u8 = 7;

type Key = [u8; 16];
type Nonce = [u8; 16];
type Tag = [u8; 16];

enum Error {
    Fail,
}

struct CryptState {
    cipher: Aes128,
    encrypt_iv: Nonce,
    decrypt_iv: Nonce,
    decrypt_history: [u8; 256],
    good: u32,
    late: u32,
    lost: u32,
}

// Based on the official Mumble project CryptState implementation
// TODO refactor this mess
impl CryptState {
    pub fn new(key: Key, encrypt_iv: Nonce, decrypt_iv: Nonce) -> CryptState {
        CryptState {
            cipher: Aes128::new(&GenericArray::from(key)),
            encrypt_iv,
            decrypt_iv,
            decrypt_history: [0; 256],
            good: 0,
            late: 0,
            lost: 0,
        }
    }

    pub fn encrypt(&mut self, plain: &[u8]) -> Result<Vec<u8>, Error> {
        let mut tag = [0; AES_BLOCK_SIZE];

        for i in 0..AES_BLOCK_SIZE {
            let (sum, _) = self.encrypt_iv[i].overflowing_add(1);
            self.encrypt_iv[i] = sum;
            if self.encrypt_iv[i] != 0 {
                break;
            }
        }

        let mut result = vec![0; plain.len() + 4];
        if !self.ocb_encrypt(&plain, &mut result[4..], self.encrypt_iv, &mut tag, true) {
            return Err(Error::Fail);
        }

        result[0] = self.encrypt_iv[0];
        result[1] = tag[0];
        result[2] = tag[1];
        result[3] = tag[2];
        Ok(result)
    }

    pub fn decrypt(&mut self, cipher: &[u8]) -> Result<Vec<u8>, Error> {
        if cipher.len() < 4 {
            return Ok(vec![]);
        }

        let mut save_iv = [0; AES_BLOCK_SIZE];
        let iv_byte = cipher[0];
        let mut restore = false;

        save_iv.copy_from_slice(&self.decrypt_iv);

        let (sum, _) = self.decrypt_iv[0].overflowing_add(1);
        if sum == iv_byte {
            // In order as expected.
            match iv_byte.cmp(&self.decrypt_iv[0]) {
                Ordering::Greater => {
                    self.decrypt_iv[0] = iv_byte;
                }
                Ordering::Less => {
                    self.decrypt_iv[0] = iv_byte;
                    for i in 1..AES_BLOCK_SIZE {
                        let (sum, _) = self.decrypt_iv[i].overflowing_add(1);
                        self.decrypt_iv[i] = sum;
                        if self.decrypt_iv[i] != 0 {
                            break;
                        }
                    }
                }
                Ordering::Equal => return Err(Error::Fail),
            }
        } else {
            // This is either out of order or a repeat.
            let (diff, _) = iv_byte.overflowing_sub(self.decrypt_iv[0]);
            let mut diff = diff as i16;
            if diff > 128 {
                diff -= 256;
            } else if diff < -128 {
                diff += 256;
            }

            if (iv_byte < self.decrypt_iv[0]) && (diff > -30) && (diff < 0) {
                // Late packet, but no wraparound.
                self.late += 1;
                self.lost -= 1;
                self.decrypt_iv[0] = iv_byte;
                restore = true;
            } else if (iv_byte > self.decrypt_iv[0]) && (diff > -30) && (diff < 0) {
                // Last was 0x02, here comes 0xff from last round
                self.late += 1;
                self.lost -= 1;
                self.decrypt_iv[0] = iv_byte;
                for i in 1..AES_BLOCK_SIZE {
                    let (sub, _) = self.decrypt_iv[i].overflowing_sub(1);
                    let old_value = self.decrypt_iv[i];
                    self.decrypt_iv[i] = sub;
                    if old_value != 0 {
                        break;
                    }
                }
                restore = true;
            } else if (iv_byte > self.decrypt_iv[0]) && (diff > 0) {
                // Lost a few packets, but beyond that we're good
                self.lost += (iv_byte - self.decrypt_iv[0] - 1) as u32;
                self.decrypt_iv[0] = iv_byte;
            } else if (iv_byte < self.decrypt_iv[0]) && (diff > 0) {
                // Lost a few packets, and wrapped around
                self.lost += (255 - self.decrypt_iv[0] + iv_byte) as u32;
                self.decrypt_iv[0] = iv_byte;
                for i in 1..AES_BLOCK_SIZE {
                    let (sum, _) = self.decrypt_iv[i].overflowing_add(1);
                    self.decrypt_iv[i] = sum;
                    if self.decrypt_iv[i] != 0 {
                        break;
                    }
                }
            } else {
                return Err(Error::Fail);
            }

            if self.decrypt_history[self.decrypt_iv[0] as usize] == self.decrypt_iv[1] {
                self.decrypt_iv.copy_from_slice(&save_iv);
                return Err(Error::Fail);
            }
        }

        let mut result = vec![0; cipher.len() - 4];
        let mut tag = [0; AES_BLOCK_SIZE];
        let ocb_success = self.ocb_decrypt(&cipher[4..], &mut result, self.decrypt_iv, &mut tag);

        if !ocb_success
            || (&tag[..3])
                .iter()
                .zip(&cipher[1..4])
                .any(|(first, second)| first != second)
        {
            self.decrypt_iv.copy_from_slice(&save_iv);
            return Err(Error::Fail);
        }

        self.decrypt_history[self.decrypt_iv[0] as usize] = self.decrypt_iv[1];

        if restore {
            self.decrypt_iv.copy_from_slice(&save_iv);
        }

        self.good += 1;

        Ok(result)
    }

    fn ocb_encrypt(
        &self,
        mut plain: &[u8],
        mut encrypted: &mut [u8],
        nonce: Nonce,
        tag: &mut Tag,
        modify_plain_on_xex_star_attack: bool,
    ) -> bool {
        let mut checksum = [0; AES_BLOCK_SIZE];
        let mut delta = nonce;
        let mut tmp = [0; AES_BLOCK_SIZE];
        let mut pad = [0; AES_BLOCK_SIZE];
        let mut success = true;

        self.cipher
            .encrypt_block(GenericArray::from_mut_slice(&mut delta));

        while plain.len() > AES_BLOCK_SIZE {
            // Counter-cryptanalysis described in section 9 of https://eprint.iacr.org/2019/311
            // For an attack, the second to last block (i.e. the last iteration of this loop)
            // must be all 0 except for the last byte (which may be 0 - 128).
            let mut flip_a_bit = false;
            if (plain.len() - AES_BLOCK_SIZE) <= AES_BLOCK_SIZE {
                let sum = plain
                    .iter()
                    .take(AES_BLOCK_SIZE - 1)
                    .fold(0, |acc, el| acc | el);
                if sum == 0 {
                    if modify_plain_on_xex_star_attack {
                        flip_a_bit = true;
                    } else {
                        success = false;
                    }
                }
            }

            s2(&mut delta);
            xor(&mut tmp, &delta, &plain);
            if flip_a_bit {
                tmp[0] ^= 1;
            }
            self.cipher
                .encrypt_block(GenericArray::from_mut_slice(&mut tmp));
            xor(encrypted, &delta, &tmp);
            xor_a(&mut checksum, &plain);
            if flip_a_bit {
                checksum[0] ^= 1;
            }

            plain = &plain[AES_BLOCK_SIZE..];
            encrypted = &mut encrypted[AES_BLOCK_SIZE..];
        }

        s2(&mut delta);
        zero(&mut tmp);
        tmp[AES_BLOCK_SIZE - 1] = swapped((plain.len() * 8) as u8);
        xor_a(&mut tmp, &delta);
        pad.copy_from_slice(&tmp);
        self.cipher
            .encrypt_block(GenericArray::from_mut_slice(&mut pad));
        (&mut tmp[..plain.len()]).copy_from_slice(plain);
        (&mut tmp[plain.len()..]).copy_from_slice(&pad[plain.len()..]);
        xor_a(&mut checksum, &tmp);
        xor_a(&mut tmp, &pad);
        encrypted.copy_from_slice(&tmp[..encrypted.len()]);

        s3(&mut delta);
        xor(&mut tmp, &delta, &checksum);
        tag.copy_from_slice(&tmp);
        self.cipher.encrypt_block(GenericArray::from_mut_slice(tag));

        success
    }

    fn ocb_decrypt(
        &self,
        mut encrypted: &[u8],
        mut plain: &mut [u8],
        nonce: Nonce,
        tag: &mut Tag,
    ) -> bool {
        let mut checksum = [0; AES_BLOCK_SIZE];
        let mut delta = nonce;
        let mut tmp = [0; AES_BLOCK_SIZE];
        let mut pad = [0; AES_BLOCK_SIZE];
        let mut success = true;

        self.cipher
            .encrypt_block(GenericArray::from_mut_slice(&mut delta));

        while encrypted.len() > AES_BLOCK_SIZE {
            s2(&mut delta);
            xor(&mut tmp, &delta, encrypted);
            self.cipher
                .decrypt_block(GenericArray::from_mut_slice(&mut tmp));
            xor(plain, &delta, &tmp);
            xor_a(&mut checksum, &plain);

            encrypted = &encrypted[AES_BLOCK_SIZE..];
            plain = &mut plain[AES_BLOCK_SIZE..];
        }

        s2(&mut delta);
        zero(&mut tmp);
        tmp[AES_BLOCK_SIZE - 1] = swapped((encrypted.len() * 8) as u8);
        xor_a(&mut tmp, &delta);
        pad.copy_from_slice(&tmp);
        self.cipher
            .encrypt_block(GenericArray::from_mut_slice(&mut pad));
        zero(&mut tmp);
        (&mut tmp[..encrypted.len()]).copy_from_slice(encrypted);
        xor_a(&mut tmp, &pad);
        xor_a(&mut checksum, &tmp);
        plain.copy_from_slice(&tmp[..plain.len()]);

        // Counter-cryptanalysis described in section 9 of https://eprint.iacr.org/2019/311
        if tmp[..(AES_BLOCK_SIZE - 1)] == delta[..(AES_BLOCK_SIZE - 1)] {
            success = false;
        }

        s3(&mut delta);
        xor(&mut tmp, &delta, &checksum);
        tag.copy_from_slice(&tmp);
        self.cipher.encrypt_block(GenericArray::from_mut_slice(tag));

        success
    }
}

#[inline]
fn xor_a(destination: &mut [u8], b: &[u8]) {
    for i in 0..AES_BLOCK_SIZE {
        destination[i] ^= b[i];
    }
}

#[inline]
fn xor(destination: &mut [u8], a: &[u8], b: &[u8]) {
    for i in 0..AES_BLOCK_SIZE {
        destination[i] = a[i] ^ b[i];
    }
}

#[inline]
fn s2(block: &mut [u8]) {
    let carry = swapped(block[0]) >> SHIFT_BITS;
    for i in 0..(AES_BLOCK_SIZE - 1) {
        block[i] = swapped((swapped(block[i]) << 1) | (swapped(block[i + 1]) >> SHIFT_BITS));
    }
    block[AES_BLOCK_SIZE - 1] = swapped((swapped(block[AES_BLOCK_SIZE - 1]) << 1) ^ (carry * 0x87));
}

#[inline]
fn s3(block: &mut [u8]) {
    let carry = swapped(block[0]) >> SHIFT_BITS;
    for i in 0..(AES_BLOCK_SIZE - 1) {
        block[i] ^= swapped((swapped(block[i]) << 1) | (swapped(block[i + 1]) >> SHIFT_BITS));
    }
    block[AES_BLOCK_SIZE - 1] ^=
        swapped((swapped(block[AES_BLOCK_SIZE - 1]) << 1) ^ (carry * 0x87));
}

#[inline]
fn zero(block: &mut [u8]) {
    block.fill(0);
}

#[inline]
fn swapped(value: u8) -> u8 {
    value.swap_bytes()
}

#[cfg(test)]
mod tests {
    use crate::crypto::{CryptState, AES_BLOCK_SIZE};

    #[test]
    fn test_reverse_recovery() {
        let key = [
            0xa0, 0x01, 0x02, 0xd3, 0x04, 0x05, 0x06, 0x07, 0xf8, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f,
        ];
        let encrypt_iv = [0x55; AES_BLOCK_SIZE];
        let decrypt_iv = [
            0x9d, 0xb0, 0xcd, 0xf8, 0x80, 0xf7, 0x3e, 0x3e, 0x10, 0xd4, 0xeb, 0x32, 0x17, 0x76,
            0x66, 0x88,
        ];
        let mut encryption = CryptState::new(key, encrypt_iv, decrypt_iv);
        let mut decryption = CryptState::new(key, decrypt_iv, encrypt_iv);
        let secret = b"MyVerySecret".to_vec();
        let mut encrypted = vec![vec![]; 512];

        for i in 0..128 {
            encrypted[i] = encryption.encrypt(&secret).ok().unwrap();
        }
        for i in 0..30 {
            assert!(decryption.decrypt(&encrypted[127 - i]).is_ok());
        }
        for i in 30..128 {
            assert!(decryption.decrypt(&encrypted[127 - i]).is_err());
        }
        for i in 0..30 {
            assert!(decryption.decrypt(&encrypted[127 - i]).is_err());
        }

        for i in 0..512 {
            encrypted[i] = encryption.encrypt(&secret).ok().unwrap();
        }
        for el in encrypted.iter() {
            assert!(decryption.decrypt(el).is_ok());
        }
        for el in encrypted.iter() {
            assert!(decryption.decrypt(el).is_err());
        }
    }

    #[test]
    fn test_iv_recovery() {
        let key = [
            0xa0, 0x01, 0x02, 0xd3, 0x04, 0x05, 0x06, 0x07, 0xf8, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f,
        ];
        let encrypt_iv = [0x55; AES_BLOCK_SIZE];
        let decrypt_iv = [
            0x9d, 0xb0, 0xcd, 0xf8, 0x80, 0xf7, 0x3e, 0x3e, 0x10, 0xd4, 0xeb, 0x32, 0x17, 0x76,
            0x66, 0x88,
        ];
        let mut encryption = CryptState::new(key, encrypt_iv, decrypt_iv);
        let mut decryption = CryptState::new(key, decrypt_iv, encrypt_iv);
        let secret = b"MyVerySecret".to_vec();

        let mut encrypted = encryption.encrypt(&secret).ok().unwrap();
        assert!(decryption.decrypt(&encrypted).is_ok());
        assert!(decryption.decrypt(&encrypted).is_err());

        for _ in 0..16 {
            encrypted = encryption.encrypt(&secret).ok().unwrap();
        }
        assert!(decryption.decrypt(&encrypted).is_ok());

        for _ in 0..128 {
            decryption.lost = 0;
            for _ in 0..15 {
                encrypted = encryption.encrypt(&secret).ok().unwrap();
            }
            assert!(decryption.decrypt(&encrypted).is_ok());
            assert_eq!(decryption.lost, 14);
        }

        assert_eq!(encryption.encrypt_iv, decryption.decrypt_iv);

        for _ in 0..257 {
            encrypted = encryption.encrypt(&secret).ok().unwrap();
        }
        assert!(decryption.decrypt(&encrypted).is_err());

        decryption.decrypt_iv = encryption.encrypt_iv;
        encrypted = encryption.encrypt(&secret).ok().unwrap();
        assert!(decryption.decrypt(&encrypted).is_ok());
    }

    #[test]
    fn test_testvectors() {
        let source = [0; 0];
        let mut destination = [0; 0];
        let key = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f,
        ];
        let mut tag = [0; 16];
        let crypt_state = CryptState::new(key, [0; 16], [0; 16]);

        assert!(crypt_state.ocb_encrypt(&source, &mut destination, key, &mut tag, true));

        let blank_tag = [
            0xbf, 0x31, 0x08, 0x13, 0x07, 0x73, 0xad, 0x5e, 0xc7, 0x0e, 0xc6, 0x9e, 0x78, 0x75,
            0xa7, 0xb0,
        ];
        assert_eq!(tag, blank_tag);

        let mut source = [0; 40];
        let mut destination = [0; 40];
        for (index, el) in source.iter_mut().enumerate() {
            *el = index as u8;
        }
        assert!(crypt_state.ocb_encrypt(&source, &mut destination, key, &mut tag, true));
        let long_tag = [
            0x9d, 0xb0, 0xcd, 0xf8, 0x80, 0xf7, 0x3e, 0x3e, 0x10, 0xd4, 0xeb, 0x32, 0x17, 0x76,
            0x66, 0x88,
        ];
        let encrypted = [
            0xf7, 0x5d, 0x6b, 0xc8, 0xb4, 0xdc, 0x8d, 0x66, 0xb8, 0x36, 0xa2, 0xb0, 0x8b, 0x32,
            0xa6, 0x36, 0x9f, 0x1c, 0xd3, 0xc5, 0x22, 0x8d, 0x79, 0xfd, 0x6c, 0x26, 0x7f, 0x5f,
            0x6a, 0xa7, 0xb2, 0x31, 0xc7, 0xdf, 0xb9, 0xd5, 0x99, 0x51, 0xae, 0x9c,
        ];

        assert_eq!(tag, long_tag);
        assert_eq!(destination, encrypted);
    }

    #[test]
    fn test_auth_crypt() {
        let key = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f,
        ];
        let nonce = [
            0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22,
            0x11, 0x00,
        ];
        let crypt_state = CryptState::new(key, [0; 16], [0; 16]);

        for len in 0..128 {
            let mut src = Vec::with_capacity(len);
            for i in 0..len {
                src.push((i + 1) as u8);
            }

            let mut encrypted_tag = [0; 16];
            let mut decrypted_tag = [0; 16];
            let mut encrypted = vec![0; len];
            let mut decrypted = vec![0; len];
            assert!(crypt_state.ocb_encrypt(&src, &mut encrypted, nonce, &mut encrypted_tag, true));
            assert!(crypt_state.ocb_decrypt(&encrypted, &mut decrypted, nonce, &mut decrypted_tag));
            assert_eq!(encrypted_tag, decrypted_tag);
            assert_eq!(src, decrypted);
        }

        let source = b"MyVerySecretMyVerySecret";
        let nonce = [
            0xd3, 0xc5, 0x22, 0x8d, 0x79, 0xfd, 0x6c, 0x26, 0x7f, 0x5f, 0x6a, 0xa7, 0xb2, 0x31,
            0x00, 0xfd,
        ];
        let mut encrypted = [0; 24];
        let mut decrypted = [0; 24];
        let mut tag = [0; 16];
        crypt_state.ocb_encrypt(source, &mut encrypted, nonce, &mut tag, true);
        crypt_state.ocb_decrypt(&encrypted, &mut decrypted, nonce, &mut tag);
        assert_eq!(source, &decrypted);
    }

    #[test]
    fn test_xexstar_attack() {
        let key = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f,
        ];
        let nonce = [
            0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22,
            0x11, 0x00,
        ];
        let crypt = CryptState::new(key, nonce, nonce);
        let mut src = [0; AES_BLOCK_SIZE * 2];
        src[AES_BLOCK_SIZE - 1] = (AES_BLOCK_SIZE * 8) as u8;
        src.split_at_mut(AES_BLOCK_SIZE).1.fill(42);
        let mut enc_tag = [0; AES_BLOCK_SIZE];
        let mut dec_tag = [0; AES_BLOCK_SIZE];
        let mut encrypted = [0; AES_BLOCK_SIZE * 2];
        let mut decrypted = [0; AES_BLOCK_SIZE * 2];

        let failed_encrypt = !crypt.ocb_encrypt(&src, &mut encrypted, nonce, &mut enc_tag, false);

        encrypted[AES_BLOCK_SIZE - 1] ^= (AES_BLOCK_SIZE * 8) as u8;
        for i in 0..AES_BLOCK_SIZE {
            enc_tag[i] = src[AES_BLOCK_SIZE + i] ^ encrypted[AES_BLOCK_SIZE + i];
        }

        let failed_decrypt = !crypt.ocb_decrypt(&encrypted, &mut decrypted, nonce, &mut dec_tag);

        assert_eq!(enc_tag, dec_tag);
        assert!(failed_encrypt);
        assert!(failed_decrypt);

        assert!(crypt.ocb_encrypt(&src, &mut encrypted, nonce, &mut enc_tag, true));
        assert!(crypt.ocb_decrypt(&encrypted, &mut decrypted, nonce, &mut dec_tag));
        assert_eq!(enc_tag, dec_tag);
        assert_eq!(src[0], 0);
        assert_eq!(decrypted[0], 1);
    }

    #[test]
    fn test_tamper() {
        let key = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f,
        ];
        let nonce = [
            0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22,
            0x11, 0x00,
        ];
        let mut crypt = CryptState::new(key, nonce, nonce);
        let message = b"It was a funky funky town!";
        let mut encrypted = crypt.encrypt(message).ok().unwrap();

        for i in 0..(message.len() * 8) {
            encrypted[i / 8] ^= 1 << (i % 8);
            assert!(crypt.decrypt(&encrypted).is_err());
            encrypted[i / 8] ^= 1 << (i % 8);
        }
        assert!(crypt.decrypt(&encrypted).is_ok())
    }
}
