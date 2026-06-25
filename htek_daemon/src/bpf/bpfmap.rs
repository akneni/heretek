use std::ffi::{CStr, CString};
use std::mem;
use std::mem::size_of;
use std::ptr::NonNull;
use std::slice;

use anyhow::{Result, bail};

use crate::build_params::{self, NUM_CORES};

const fn asserts_enabled() -> usize {
    if build_params::ASSERTS { 1 } else { 0 }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct CEvent {
    pub event: u32,
    pub pid: i32,
    pub ktime: u64,
    pub fpath1: [libc::c_char; 256],
    pub fpath2: [libc::c_char; 256],
    pub spare: [u8; 8],
    pub magic_num: [u64; asserts_enabled()],
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct CEventMetadata {
    canary: Canary,
    tail: u32,
    head: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct CEventSlot {
    bytes: [u8; size_of::<CEvent>()],
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct Canary {
    cpu_id: u32,
    magic_num: u32,
}

impl CEvent {
    pub fn fpath_str(&self, x: usize) -> Result<String> {
        let fp_ref = match x {
            1 => &self.fpath1,
            2 => &self.fpath2,
            _ => bail!("Bad argument"),
        };
        let idx = fp_ref.iter().position(|&i| i == 0).unwrap_or(256);
        let sl = unsafe { slice::from_raw_parts(fp_ref.as_ptr() as *const u8, idx) };
        Ok(String::from_utf8(sl.to_vec())?)
    }

    pub fn get_spare<T: Sized + Copy>(&self, idx: usize) -> T {
        if build_params::ASSERTS && (idx + 1) * mem::size_of::<T>() > mem::size_of_val(&self.spare)
        {
            tracing::error!("CEvent::get_spare indexed pased the end of the array");
        }

        unsafe {
            let space_ptr: *const u8 = &self.spare as *const u8;
            let mut space_ptr: *const T = space_ptr as *const T;
            space_ptr = space_ptr.add(idx);
            *space_ptr
        }
    }

    fn check_sanity_asso(&self) {
        if !build_params::ASSERTS {
            return;
        }

        if self.pid == 0 || self.ktime == 0 || self.event == 0 {
            tracing::error!("Found invalid CEvent!");
        }

        if self.check_magic_num().is_err() {
            tracing::error!("Cevent doesn't have magic number");
        }
    }

    fn check_magic_num(&self) -> Result<()> {
        if build_params::ASSERTS {
            unsafe {
                let magic_num_ptr = &self.magic_num as *const u64;
                let magic_num = *magic_num_ptr;
                if magic_num == build_params::CANARY as u64 + 1 {
                    Ok(())
                } else {
                    bail!("magic number error");
                }
            }
        } else {
            Ok(())
        }
    }
}

pub struct RingBuf<'a> {
    event_array: &'a mut [CEvent],
    metadata: &'a mut CEventMetadata,
}

pub struct BpfEventArrayReader {
    fd: i32,
    bpf_map: NonNull<CEventSlot>,
}

impl BpfEventArrayReader {
    pub fn from_pinned_path(map_path: &str) -> Result<Self> {
        let map_len = const { map_len_bytes() };

        let (fd, bpf_map) = unsafe {
            let cmap_path = CString::new(map_path)?;
            let fd = cbpfmap::open_htekmap(cmap_path.as_bytes().as_ptr() as *const libc::c_char);
            if fd < 0 {
                bail!("Failed to open bpf map, errcode: {fd}");
            }

            let mut errstr = [0 as libc::c_char; 256];
            let ptr = cbpfmap::mmap_bfpmap(fd, map_len, errstr.as_mut_ptr(), errstr.len());
            if ptr.is_null() {
                let errstr = CStr::from_ptr(errstr.as_ptr()).to_string_lossy();
                libc::close(fd);
                bail!("Failed to mmap eBPF map into memory: {errstr}");
            }

            let s = slice::from_raw_parts_mut(
                ptr as *mut CEventSlot,
                map_len / mem::size_of::<CEventSlot>(),
            );

            let bpf_map = NonNull::from_mut(&mut s[0]);
            (fd, bpf_map)
        };

        Ok(Self { fd, bpf_map })
    }

    fn ring_buf<'a>(&'a mut self, cpu_id: usize) -> RingBuf<'a> {
        let event_array = unsafe {
            let events_ptr = self.bpf_map.add(cpu_id * ring_buf_numslots());
            slice::from_raw_parts_mut(events_ptr.as_ptr() as *mut CEvent, ring_buf_numslots())
        };

        let metadata = unsafe {
            let md_ptr = self.bpf_map.add(NUM_CORES * ring_buf_numslots() + cpu_id);
            (md_ptr.as_ptr() as *mut CEventMetadata)
                .as_mut()
                .unwrap_unchecked()
        };

        RingBuf {
            event_array,
            metadata,
        }
    }

    pub fn poll(&mut self, events: &mut Vec<CEvent>) -> Result<()> {
        for i in 0..NUM_CORES {
            let rbuf = self.ring_buf(i);
            let initial_head = rbuf.metadata.head;
            let mut i = rbuf.metadata.tail;

            while i != initial_head {
                let evt = &rbuf.event_array[i as usize];
                evt.check_sanity_asso();
                events.push(*evt);
                i = (i + 1) % ring_buf_numslots() as u32;
            }

            rbuf.metadata.tail = initial_head;
        }

        Ok(())
    }
}

impl Drop for BpfEventArrayReader {
    fn drop(&mut self) {
        unsafe {
            libc::munmap(self.bpf_map.as_ptr() as *mut libc::c_void, map_len_bytes());
            libc::close(self.fd);
        }
    }
}

/// Returns the number of slots in each logical per core ring buffer
const fn ring_buf_numslots() -> usize {
    (1 << build_params::RING_BUF_SIZE_LOG2) / NUM_CORES
}

/// Returns the length of the entire eBPF map (all cores, event buffer, metadata slots, and
/// parameter block) in terms of bytes
const fn map_len_bytes() -> usize {
    map_len_slots() * mem::size_of::<CEventSlot>()
}

/// Returns the length of the entire eBPF map (all cores, event buffer, metadata slots, and
/// parameter block) in terms of slots
const fn map_len_slots() -> usize {
    (1 << build_params::RING_BUF_SIZE_LOG2) + build_params::NUM_CORES + 1
}

pub mod cbpfmap {
    #[link(name = "cbpfmap", kind = "static")]
    unsafe extern "C" {
        pub unsafe fn open_htekmap(map_path: *const libc::c_char) -> i32;
        pub unsafe fn mmap_bfpmap(
            fd: i32,
            length: usize,
            errstr: *mut libc::c_char,
            errstr_len: usize,
        ) -> *mut libc::c_void;
    }
}
