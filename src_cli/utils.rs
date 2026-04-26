pub trait TotalMem {
    fn total_mem(&self) -> usize;
}

#[inline]
pub fn bit_test(bitmap: u8, idx: u8) -> bool {
    (bitmap & (0x01 << idx)) != 0
}

#[inline]
pub fn bit_set(bitmap: &mut u8, idx: u8) {
    *bitmap |= 0x01 << idx;
}

#[inline]
pub fn bit_clear(bitmap: &mut u8, idx: u8) {
    *bitmap &= !(0x01 << idx);
}
