// Licensed under the Apache-2.0 license

use caliptra_common::{crypto::Ecc384KeyPair, keyids::KEY_ID_TMP};
use caliptra_drivers::{
    hmac384_kdf, Array4x12, Ecc384PrivKeyOut, Ecc384PubKey, Hmac384Data, Hmac384Key, Hmac384Tag,
    KeyId, KeyReadArgs, KeyUsage, KeyWriteArgs,
};
use caliptra_error::CaliptraResult;
use zerocopy::AsBytes;
use zeroize::Zeroize;

use crate::Drivers;

// Generate an ECC keypair
fn ecc384_key_gen(
    drivers: &mut Drivers,
    input: KeyId,
    label: &[u8],
    priv_key: KeyId,
) -> CaliptraResult<Ecc384KeyPair> {
    hmac384_kdf(
        &mut drivers.hmac384,
        KeyReadArgs::new(input).into(),
        label,
        None,
        &mut drivers.trng,
        KeyWriteArgs::new(
            KEY_ID_TMP,
            KeyUsage::default()
                .set_hmac_key_en()
                .set_ecc_key_gen_seed_en(),
        )
        .into(),
    )?;

    let pub_key = drivers.ecc384.key_pair(
        &KeyReadArgs::new(KEY_ID_TMP).into(),
        &Array4x12::default(),
        &mut drivers.trng,
        KeyWriteArgs::new(priv_key, KeyUsage::default().set_ecc_private_key_en()).into(),
    );

    if KEY_ID_TMP != priv_key {
        drivers.key_vault.erase_key(KEY_ID_TMP)?;
    }

    Ok(Ecc384KeyPair {
        priv_key,
        pub_key: pub_key?,
    })
}

pub enum Hmac {}

impl Hmac {
    // "Hash" the data in the provided KV slot by HMACing it with an empty slice.
    // This mechanism is necessary because the hardware does not directly support
    // hashing data in KV slots.
    pub fn hmac384_hash(drivers: &mut Drivers, input: KeyId, output: KeyId) -> CaliptraResult<()> {
        drivers.hmac384.hmac(
            &KeyReadArgs::new(input).into(),
            &Hmac384Data::Slice(&[]),
            &mut drivers.trng,
            KeyWriteArgs::new(
                output,
                KeyUsage::default()
                    .set_hmac_key_en()
                    .set_ecc_key_gen_seed_en(),
            )
            .into(),
        )
    }

    // Perform an "HMAC" with a key from KV by first using it to derive an
    // ECC keypair, then hashing the public key coordinates into an HMAC key.
    // This roundabout mechanism is necessary because the hardware does not
    // directly support exposing an HMAC computed with key material from KV.
    // Note that the derived public key is considered secret.
    //
    // `label` is used to diversify the key material before it is used to
    // compute an ECC keypair.
    pub fn ecc384_hmac(
        drivers: &mut Drivers,
        input: KeyId,
        label: &[u8],
        data: &[u8],
    ) -> CaliptraResult<Array4x12> {
        let mut keypair = ecc384_key_gen(drivers, input, label, KEY_ID_TMP)?;

        let mut pubkey_digest = Array4x12::default();

        // Done in a closure to ensure state is always cleaned up.
        let hmac_result = || -> CaliptraResult<Array4x12> {
            let mut hasher = drivers.sha384.digest_init()?;

            hasher.update(keypair.pub_key.x.as_bytes())?;
            hasher.update(keypair.pub_key.y.as_bytes())?;
            hasher.finalize(&mut pubkey_digest)?;

            let mut hmac_output = Array4x12::default();
            drivers.hmac384.hmac(
                &Hmac384Key::Array4x12(&pubkey_digest),
                &Hmac384Data::Slice(data),
                &mut drivers.trng,
                Hmac384Tag::Array4x12(&mut hmac_output),
            )?;

            Ok(hmac_output)
        }();

        // Clean up state.
        unsafe { caliptra_drivers::Sha384::zeroize() }
        pubkey_digest.zeroize();
        keypair.pub_key.zeroize();
        drivers.key_vault.erase_key(keypair.priv_key)?;

        hmac_result
    }
}
