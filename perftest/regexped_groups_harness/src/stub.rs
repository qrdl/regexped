// Static stub for OnePass groups function.
// The WASM module exports "groups" from import module "pattern".
// 7 groups: 0=full match, 1=scheme, 2=host, 3=port,
//            4=path, 5=query, 6=fragment

#[link(wasm_import_module = "pattern")]
unsafe extern "C" {
    fn groups(ptr: *const u8, len: usize, out: *mut i32) -> i32;
}

pub fn pattern_groups(input: &[u8]) -> Option<Vec<Option<(usize, usize)>>> {
    let mut slots = [-1i32; 14]; // 7 groups × 2 slots
    if unsafe { groups(input.as_ptr(), input.len(), slots.as_mut_ptr()) } < 0 {
        return None;
    }
    let mut result = Vec::with_capacity(7);
    for i in 0..7 {
        let s = slots[i * 2];
        let e = slots[i * 2 + 1];
        result.push(if s < 0 { None } else { Some((s as usize, e as usize)) });
    }
    Some(result)
}
