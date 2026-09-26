const COMMANDS: &[&str] = &[
    // page-facing WebUSB surface
    "get_devices",
    "request_device",
    "open",
    "close",
    "forget",
    "select_configuration",
    "claim_interface",
    "release_interface",
    "select_alternate_interface",
    "reset_device",
    "clear_halt",
    "control_transfer_in",
    "control_transfer_out",
    "transfer_in",
    "transfer_out",
    "isochronous_transfer_in",
    "isochronous_transfer_out",
    // chooser-window-only (gated by window label at runtime — see chooser.rs)
    "chooser_list_candidates",
    "chooser_select",
    "chooser_cancel",
    // trusted management surface
    "list_granted_origins",
    "revoke_origin_grant",
    "revoke_all_for_origin",
    "list_known_devices",
    "forget_known_device",
    "forget_all_known_devices",
];

fn main() {
    tauri_plugin::Builder::new(COMMANDS).build();
}
