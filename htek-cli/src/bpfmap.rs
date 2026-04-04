use std::{error::Error, slice};
use std::io;
use std::mem::size_of;
use std::path::Path;

use anyhow::{Result, bail};
use aya::{
    Pod,
    maps::{Map, MapData, PerCpuArray},
};

use crate::actor::Event;

const EVENT_BUFFER_SLOTS: u64 = 64;
const EVENT_METADATA_SLOT: u32 = EVENT_BUFFER_SLOTS as u32;
const SYSCALL_OPENAT: u32 = 257;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct CEvent {
    pub event: u32,
    pub pid: i32,
    pub fpath1: [libc::c_char; 256],
    pub fpath2: [libc::c_char; 256],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct EventSlot {
    bytes: [u8; size_of::<CEvent>()],
}

unsafe impl Pod for EventSlot {}

impl CEvent {
    unsafe fn from_bytes(bytes: &[u8]) -> &Self {
        let sptr = bytes.as_ptr() as *const Self;
        unsafe {
            sptr.as_ref().unwrap()
        }
    }
    
    pub fn fpath_str(&self, x: usize) -> Result<String> {
        let fp_ref = match x {
            1 => &self.fpath1,
            2 => &self.fpath2,
            _ => bail!("Bad argument"),
        };
        let idx = fp_ref.iter().position(|&i| i == 0).unwrap_or(256);
        let sl = unsafe {
            slice::from_raw_parts(fp_ref.as_ptr() as *const u8, idx)
        };
        Ok(String::from_utf8(sl.to_vec())?)
    }
}


pub struct BpfEventArrayReader {
    map: PerCpuArray<MapData, EventSlot>,
    tails: Vec<u64>,
}

impl BpfEventArrayReader {
    pub fn from_pinned_path<P>(map_path: P) -> Result<Self, Box<dyn Error>>
    where
        P: AsRef<Path>,
    {
        let map_data = MapData::from_pin(map_path)?;
        let map = Map::PerCpuArray(map_data);
        let map = PerCpuArray::try_from(map)?;
        let mut reader = Self {
            map,
            tails: Vec::new(),
        };

        reader.sync_tails_to_head()?;
        Ok(reader)
    }

    pub fn poll(&mut self, events: &mut Vec<(i32, Event)>) -> Result<(), Box<dyn Error>> {
        let heads = self.read_heads()?;

        if self.tails.len() != heads.len() {
            self.tails.resize(heads.len(), 0);
        }

        for (cpu, head) in heads.into_iter().enumerate() {
            if head.saturating_sub(self.tails[cpu]) > EVENT_BUFFER_SLOTS {
                let dropped = head - self.tails[cpu] - EVENT_BUFFER_SLOTS;
                eprintln!("dropped {dropped} event(s) on CPU {cpu}");
                self.tails[cpu] = head - EVENT_BUFFER_SLOTS;
            }

            while self.tails[cpu] < head {
                let slot_idx = (self.tails[cpu] % EVENT_BUFFER_SLOTS) as u32;
                let cpu_slots = self.map.get(&slot_idx, 0)?;
                let c_event = unsafe {
                    CEvent::from_bytes(&cpu_slots[cpu].bytes)
                };

                match Event::from(c_event) {
                    Ok(r) => events.push((c_event.pid, r)),
                    Err(e) => eprintln!("Error parsing CEvent: {}", e),
                };

                self.tails[cpu] += 1;
            }
        }

        Ok(())
    }

    fn sync_tails_to_head(&mut self) -> Result<(), Box<dyn Error>> {
        self.tails = self.read_heads()?;
        Ok(())
    }

    fn read_heads(&self) -> Result<Vec<u64>, Box<dyn Error>> {
        let cpu_values = self.map.get(&EVENT_METADATA_SLOT, 0)?;
        cpu_values
            .iter()
            .map(parse_head)
            .collect::<Result<Vec<_>, _>>()
    }
}

fn parse_head(slot: &EventSlot) -> Result<u64, Box<dyn Error>> {
    let bytes: [u8; size_of::<u64>()] = slot
        .bytes
        .get(..size_of::<u64>())
        .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "metadata slot too small"))?
        .try_into()?;
    Ok(u64::from_ne_bytes(bytes))
}
