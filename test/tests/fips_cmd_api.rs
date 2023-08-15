// Licensed under the Apache-2.0 license

use caliptra_builder::{ImageOptions, APP_WITH_UART, FMC_WITH_UART, ROM_WITH_UART};
use caliptra_hw_model::{BootParams, HwModel, InitParams};
use caliptra_runtime::{CommandId, MailboxReqHeader, MailboxRespHeader};
use zerocopy::{AsBytes, FromBytes};

#[test]
fn test_fips_cmd_api() {
    let image = caliptra_builder::build_and_sign_image(
        &FMC_WITH_UART,
        &APP_WITH_UART,
        ImageOptions::default(),
    )
    .unwrap();

    let rom = caliptra_builder::build_firmware_rom(&ROM_WITH_UART).unwrap();
    let mut hw = caliptra_hw_model::new(BootParams {
        init_params: InitParams {
            rom: &rom,
            ..Default::default()
        },
        fw_image: Some(&image.to_bytes().unwrap()),
        ..Default::default()
    })
    .unwrap();

    hw.step_until(|m| m.ready_for_fw());

    // SELF_TEST
    let payload = MailboxReqHeader {
        chksum: caliptra_common::checksum::calc_checksum(u32::from(CommandId::SELF_TEST), &[]),
    };

    let resp = hw
        .mailbox_execute(u32::from(CommandId::SELF_TEST), payload.as_bytes())
        .unwrap()
        .unwrap();

    let resp = MailboxRespHeader::read_from(resp.as_slice()).unwrap();
    // Verify checksum and FIPS status
    assert!(caliptra_common::checksum::verify_checksum(
        resp.chksum,
        0x0,
        &resp.as_bytes()[core::mem::size_of_val(&resp.chksum)..],
    ));
    assert_eq!(resp.fips_status, MailboxRespHeader::FIPS_STATUS_APPROVED);
}
