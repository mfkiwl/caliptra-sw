// Licensed under the Apache-2.0 license

use crate::Drivers;
use caliptra_common::mailbox_api::MailboxResp;
use caliptra_drivers::{
    hmac384_kdf, Array4x12, CaliptraError, CaliptraResult, Ecc384Seed, Hmac384Key, KeyReadArgs,
    KeyUsage, KeyWriteArgs,
};
use dpe::U8Bool;

pub struct DisableAttestationCmd;
impl DisableAttestationCmd {
    pub(crate) fn execute(drivers: &mut Drivers) -> CaliptraResult<MailboxResp> {
        let key_id_rt_cdi = Drivers::get_key_id_rt_cdi(drivers)?;
        let key_id_rt_priv_key = Drivers::get_key_id_rt_priv_key(drivers)?;
        drivers.key_vault.erase_key(key_id_rt_cdi)?;
        drivers.key_vault.erase_key(key_id_rt_priv_key)?;

        Self::zero_rt_cdi(drivers)?;
        Self::generate_dice_key(drivers)?;
        drivers.persistent_data.get_mut().attestation_disabled = U8Bool::new(true);
        Ok(MailboxResp::default())
    }

    // Set CDI key vault slot to a KDF of a buffer of 0s.
    fn zero_rt_cdi(drivers: &mut Drivers) -> CaliptraResult<()> {
        let key_id_rt_cdi = Drivers::get_key_id_rt_cdi(drivers)?;
        hmac384_kdf(
            &mut drivers.hmac384,
            Hmac384Key::Array4x12(&Array4x12::default()),
            b"zero_rt_cdi",
            None,
            &mut drivers.trng,
            KeyWriteArgs::new(
                key_id_rt_cdi,
                KeyUsage::default()
                    .set_hmac_key_en()
                    .set_ecc_key_gen_seed_en(),
            )
            .into(),
        )?;

        Ok(())
    }

    // Dice key is derived from an empty CDI slot so it will not match the key that was certified in the rt_alias cert.
    fn generate_dice_key(drivers: &mut Drivers) -> CaliptraResult<()> {
        let key_id_rt_cdi = Drivers::get_key_id_rt_cdi(drivers)?;
        let key_id_rt_priv_key = Drivers::get_key_id_rt_priv_key(drivers)?;
        let pub_key = drivers.ecc384.key_pair(
            &Ecc384Seed::Key(KeyReadArgs::new(key_id_rt_cdi)),
            &Array4x12::default(),
            &mut drivers.trng,
            KeyWriteArgs::new(
                key_id_rt_priv_key,
                KeyUsage::default().set_ecc_private_key_en(),
            )
            .into(),
        )?;
        drivers.persistent_data.get_mut().fht.rt_dice_pub_key = pub_key;

        Ok(())
    }
}
