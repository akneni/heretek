use std::time::{Duration, Instant};

/// This file and the code in it is likely temporary and only here for performance testing

#[derive(Debug)]
pub struct PerfTracker {
    pub total_time_elapsed: u64,
    pub total_iterations: u64,
    pub total_events: u64,
    pub max_time_elapsed: u64,
    pub max_events: u64,
    pub timer: Instant,
}

impl PerfTracker {
    pub fn new() -> Self {
        Self {
            total_time_elapsed: 0,
            total_iterations: 0,
            total_events: 0,
            max_time_elapsed: 0,
            max_events: 0,
            timer: Instant::now(),
        }
    }

    pub fn start_iter(&mut self) {
        self.timer = Instant::now();
    }

    pub fn record_num_events(&mut self, num_events: u64) {
        self.total_events += num_events;
        self.max_events = self.max_events.max(num_events);
    }

    pub fn end_iter(&mut self) {
        let te = self.timer.elapsed().as_micros() as u64;
        self.total_iterations += 1;
        self.total_time_elapsed += te;
        self.max_time_elapsed = self.max_time_elapsed.max(te);
    }

    #[allow(unused)]
    pub fn display_stats(&self) {
        println!(
            "(Avg Time {:?}) (Max Time = {:?}) (Avg Events {}) (Max Events {})",
            Duration::from_micros(self.total_time_elapsed / self.total_iterations),
            Duration::from_micros(self.max_time_elapsed),
            self.total_events / self.total_iterations,
            self.max_events,
        );
    }
}
