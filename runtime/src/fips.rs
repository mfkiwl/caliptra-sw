// Licensed under the Apache-2.0 license

use caliptra_common::cprintln;
use caliptra_common::{FMC_ORG, RUNTIME_ORG};
use caliptra_drivers::CaliptraError;
use caliptra_drivers::CaliptraResult;
use caliptra_drivers::Ecc384;
use caliptra_drivers::Hmac384;
use caliptra_drivers::KeyVault;
use caliptra_drivers::Sha256;
use caliptra_drivers::Sha384;
use caliptra_drivers::Sha384Acc;
use caliptra_kat::{Ecc384Kat, Hmac384Kat, Sha256Kat, Sha384AccKat, Sha384Kat};
use caliptra_registers::mbox::enums::MboxStatusE;

use crate::MemoryRegions;
use crate::{Drivers, FipsVersionResp, MailboxResp, MailboxRespHeader};
use zerocopy::AsBytes;

pub struct FipsModule;

/// Fips command handler.
impl FipsModule {
    /// Clear data structures in DCCM.
    fn zeroize(env: &mut Drivers) {
        unsafe {
            // Zeroize the crypto blocks.
            Ecc384::zeroize();
            Hmac384::zeroize();
            Sha256::zeroize();
            Sha384::zeroize();
            Sha384Acc::zeroize();

            // Zeroize the key vault.
            KeyVault::zeroize();

            // Lock the SHA Accelerator.
            Sha384Acc::lock();
        }

        env.regions.zeroize();
    }

    /// Execute KAT for cryptographic algorithms implemented in H/W.
    fn execute_kats(env: &mut Drivers) -> CaliptraResult<()> {
        cprintln!("[kat] Executing SHA2-256 Engine KAT");
        Sha256Kat::default().execute(&mut env.sha256)?;

        cprintln!("[kat] Executing SHA2-384 Engine KAT");
        Sha384Kat::default().execute(&mut env.sha384)?;

        cprintln!("[kat] Executing SHA2-384 Accelerator KAT");
        Sha384AccKat::default().execute(&mut env.sha384_acc)?;

        cprintln!("[kat] Executing ECC-384 Engine KAT");
        Ecc384Kat::default().execute(&mut env.ecc384, &mut env.trng)?;

        cprintln!("[kat] Executing HMAC-384 Engine KAT");
        Hmac384Kat::default().execute(&mut env.hmac384, &mut env.trng)?;

        Ok(())
    }
}

pub struct FipsVersionCmd;
impl FipsVersionCmd {
    pub const NAME: [u8; 12] = *b"Caliptra RTM";
    pub const MODE: u32 = 0x46495053;

    pub(crate) fn execute(_env: &mut Drivers) -> CaliptraResult<MailboxResp> {
        cprintln!("[rt] FIPS Version");

        let resp = FipsVersionResp {
            hdr: MailboxRespHeader::default(),
            mode: Self::MODE,
            // Just return all zeroes for now.
            fips_rev: [1, 0, 0],
            name: Self::NAME,
        };

        Ok(MailboxResp::FipsVersion(resp))
    }
}

pub struct FipsSelfTestCmd;
impl FipsSelfTestCmd {
    pub(crate) fn execute(env: &mut Drivers) -> CaliptraResult<MailboxResp> {
        cprintln!("[rt] FIPS self test");
        Self::trigger_update_reset();
        loop {}
    }
    fn trigger_update_reset() {
        const STDOUT: *mut u32 = 0x3003_0624 as *mut u32;
        unsafe {
            core::ptr::write_volatile(STDOUT, 1_u32);
        }
    }
    fn copy_image_to_mbox(env: &mut Drivers) {
        let mbox_ptr = MBOX_ORG as *mut u8;
        let man1_ptr = MAN1_ORG as *const u8;

        let fmc_org = FMC_ORG as *mut u8;
        let rt_org = RUNTIME_ORG as *const u8;

        unsafe {
            let mut offset = 0;
            MemoryRegions::copy_bytes(
                man1_ptr,
                mbox_ptr.add(offset),
                env.manifest.as_bytes().len(),
            );
            offset += env.manifest.as_bytes().len();
            MemoryRegions::copy_bytes(
                fmc_org,
                mbox_ptr.add(offset),
                env.manifest.fmc.size as usize,
            );
            offset += env.manifest.fmc.size as usize;
            MemoryRegions::copy_bytes(
                rt_org,
                mbox_ptr.add(offset),
                env.manifest.runtime.size as usize,
            );
        }
    }
}

pub struct FipsShutdownCmd;
impl FipsShutdownCmd {
    pub(crate) fn execute(env: &mut Drivers) -> CaliptraResult<MailboxResp> {
        FipsModule::zeroize(env);
        env.mbox.set_status(MboxStatusE::CmdComplete);

        Err(CaliptraError::RUNTIME_SHUTDOWN)
    }
}
