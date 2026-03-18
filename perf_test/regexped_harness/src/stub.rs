// Static stub — the WASM compiler always exports the match function as
// "pattern_match" from import module "pattern".

#[link(wasm_import_module = "pattern")]
unsafe extern "C" {
    #[link_name = "pattern_match"]
    fn ffi_pattern_match(ptr: *const u8, len: usize) -> i32;
}

pub fn pattern_match(input: &[u8]) -> Option<usize> {
    match unsafe { ffi_pattern_match(input.as_ptr(), input.len()) } {
        n if n >= 0 => Some(n as usize),
        _ => None,
    }
}
