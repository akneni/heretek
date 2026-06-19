use std::mem::size_of;
use std::path::Path;
use std::{error::Error, slice};
use std::{io, mem};

use anyhow::{Result, anyhow, bail};
use aya::{
    Pod,
    maps::{Map, MapData, PerCpuArray, PerCpuValues},
};

use crate::build_params;

const EVENT_BUFFER_SLOTS: u64 = 1 << build_params::RING_BUF_SIZE_LOG2;
const EVENT_METADATA_SLOT: u32 = EVENT_BUFFER_SLOTS as u32;

#[allow(unused)]
const EVENT_PARAM_SLOT: u32 = EVENT_BUFFER_SLOTS as u32 + 1;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct CEvent {
    pub event: u32,
    pub pid: i32,
    pub ktime: u64,
    pub fpath1: [libc::c_char; 256],
    pub fpath2: [libc::c_char; 256],
    pub spare: [u8; 8],
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct CEventMetadata {
    canary: u32,
    length: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct CEventSlot {
    bytes: [u8; size_of::<CEvent>()],
}

unsafe impl Pod for CEventSlot {}

impl CEvent {
    unsafe fn from_bytes(bytes: &[u8]) -> Result<&Self> {
        let sptr = bytes.as_ptr() as *const Self;
        Ok(unsafe { sptr.as_ref().ok_or(anyhow!("bad pointer"))? })
    }

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
        // Bounds check
        assert!((idx + 1) * mem::size_of::<T>() <= mem::size_of_val(&self.spare));

        unsafe {
            let space_ptr: *const u8 = &self.spare as *const u8;
            let mut space_ptr: *const T = space_ptr as *const T;
            space_ptr = space_ptr.add(idx);
            *space_ptr
        }
    }
}

pub struct BpfEventArrayReader {
    map: PerCpuArray<MapData, CEventSlot>,
}

impl BpfEventArrayReader {
    pub fn from_pinned_path<P>(map_path: P) -> Result<Self, Box<dyn Error>>
    where
        P: AsRef<Path>,
    {
        let map_data = MapData::from_pin(map_path)?;
        let map = Map::PerCpuArray(map_data);
        let map = PerCpuArray::try_from(map)?;
        Ok(Self { map })
    }

    pub fn poll(&mut self, events: &mut Vec<CEvent>) -> Result<(), Box<dyn Error>> {
        let metadata = self.read_metadata()?;

        for (cpu, md) in metadata.iter().enumerate() {
            check_evtmd_canary_asso(md.canary);

            let length = if md.length as u64 > EVENT_BUFFER_SLOTS {
                let dropped = md.length as u64 - EVENT_BUFFER_SLOTS;
                tracing::warn!("dropped {dropped} event(s) on CPU {cpu}");
                EVENT_BUFFER_SLOTS as u32
            } else {
                md.length
            };

            for slot_idx in 0..length {
                let cpu_slots = self.map.get(&slot_idx, 0)?;
                let c_event = match unsafe { CEvent::from_bytes(&cpu_slots[cpu].bytes) } {
                    Ok(r) => r,
                    Err(e) => {
                        tracing::error!("Failed to build CEvent from eBPF buffer: {e}");
                        continue;
                    }
                };

                events.push(*c_event);
            }
        }

        self.reset_lengths(&metadata)?;

        Ok(())
    }

    fn read_metadata(&self) -> Result<Vec<CEventMetadata>, Box<dyn Error>> {
        let cpu_values = self.map.get(&EVENT_METADATA_SLOT, 0)?;
        cpu_values
            .iter()
            .map(parse_metadata)
            .collect::<Result<Vec<_>, _>>()
    }

    fn reset_lengths(&mut self, metadata: &[CEventMetadata]) -> Result<(), Box<dyn Error>> {
        let mut cpu_values = self
            .map
            .get(&EVENT_METADATA_SLOT, 0)?
            .iter()
            .copied()
            .collect::<Vec<_>>();

        for (cpu, slot) in cpu_values.iter_mut().enumerate() {
            if !metadata.get(cpu).is_some_and(|md| md.length > 0) {
                continue;
            }

            let canary = build_params::EVTMD_CANARY as u32;
            write_metadata(slot, canary, 0)?;
        }

        self.map
            .set(EVENT_METADATA_SLOT, PerCpuValues::try_from(cpu_values)?, 0)?;
        Ok(())
    }
}

fn check_evtmd_canary_asso(canary: u32) {
    if !build_params::ASSERTS {
        return;
    }

    if canary != build_params::EVTMD_CANARY as u32 && canary != 0 {
        tracing::error!(
            "event metadata canary mismatch: expected {}, got {}",
            build_params::EVTMD_CANARY,
            canary
        );
    }
}

fn parse_metadata(slot: &CEventSlot) -> Result<CEventMetadata, Box<dyn Error>> {
    let canary_bytes: [u8; size_of::<u32>()] = slot
        .bytes
        .get(..size_of::<u32>())
        .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "metadata slot too small"))?
        .try_into()?;
    let length_bytes: [u8; size_of::<u32>()] = slot
        .bytes
        .get(size_of::<u32>()..size_of::<u32>() * 2)
        .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "metadata slot too small"))?
        .try_into()?;

    Ok(CEventMetadata {
        canary: u32::from_ne_bytes(canary_bytes),
        length: u32::from_ne_bytes(length_bytes),
    })
}

fn write_metadata(slot: &mut CEventSlot, canary: u32, length: u32) -> Result<(), Box<dyn Error>> {
    slot.bytes
        .get_mut(..size_of::<u32>())
        .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "metadata slot too small"))?
        .copy_from_slice(&canary.to_ne_bytes());
    slot.bytes
        .get_mut(size_of::<u32>()..size_of::<u32>() * 2)
        .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "metadata slot too small"))?
        .copy_from_slice(&length.to_ne_bytes());
    Ok(())
}
