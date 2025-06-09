//! Run tasks in parallel while keeping the original order.

use std::{num::NonZero, panic, thread};

use crossbeam_channel as mpmc;

#[derive(Debug)]
pub struct OrderedParallel<R> {
    injector: Option<mpmc::Sender<Task<R>>>,
    collector: mpmc::Receiver<TaskResult<R>>,
    next_to_send: usize,
    next_to_recv: usize,
    ring_buf: Box<[Option<R>]>,

    threads: Box<[thread::JoinHandle<()>]>,
}

type Task<R> = (usize, Box<dyn FnOnce() -> R + Send>);
type TaskResult<R> = (usize, thread::Result<R>);

impl<R> Drop for OrderedParallel<R> {
    fn drop(&mut self) {
        self.injector = None;
        let worker_panicked = std::mem::take(&mut self.threads)
            .into_iter()
            .fold(false, |panicked, j| panicked | j.join().is_err());
        if worker_panicked && !thread::panicking() {
            panic!("worker panicked");
        }
    }
}

impl<R: Send + 'static> OrderedParallel<R> {
    pub fn new(thread_name: &str, thread_cnt: NonZero<usize>) -> std::io::Result<Self> {
        // Random picked: 1.5x.
        let max_inflights = thread_cnt.saturating_add(thread_cnt.get().div_ceil(2));

        let (injector, injector_rx) = mpmc::bounded(max_inflights.get());
        let (collector_tx, collector) = mpmc::bounded(max_inflights.get());

        let threads = (0..thread_cnt.get())
            .map(|idx| {
                let injector_rx = injector_rx.clone();
                let collector_tx = collector_tx.clone();
                std::thread::Builder::new()
                    .name(format!("{thread_name}-{idx}"))
                    .spawn(|| Self::worker(injector_rx, collector_tx))
            })
            .collect::<std::io::Result<Box<[_]>>>()?;

        let ring_buf = std::iter::repeat_with(|| None)
            .take(max_inflights.get())
            .collect();

        Ok(Self {
            next_to_send: 0,
            next_to_recv: 0,

            ring_buf,

            injector: Some(injector),
            threads,
            collector,
        })
    }

    fn worker(injector: mpmc::Receiver<Task<R>>, collector: mpmc::Sender<TaskResult<R>>) {
        while let Ok((index, task)) = injector.recv() {
            let ret = panic::catch_unwind(panic::AssertUnwindSafe(task));
            if collector.send((index, ret)).is_err() {
                break;
            }
        }
    }

    /// Spawn a new task and retrieve some completed tasks.
    ///
    /// You should always drain the returning iterator, or the behavior is unspecified.
    #[must_use = "iterator must be drained"]
    pub fn submit_and_get<F>(&mut self, task: F) -> impl Iterator<Item = R>
    where
        F: FnOnce() -> R + Send + 'static,
    {
        let index = self.next_to_send;
        self.next_to_send += 1;
        if self.next_to_send == self.ring_buf.len() {
            self.next_to_send = 0;
        }
        self.send_and_recv_inner((index, Box::new(task)))
    }

    fn send_and_recv_inner(&mut self, task: Task<R>) -> impl Iterator<Item = R> {
        let injector = self.injector.as_ref().expect("channel closed");
        // Blocking wait for the bottleneck-ed task if the next send would overflow.
        // Note that we ensures `ring_buf.len() >= 2` so the first send always does no wait.
        if self.next_to_send == self.next_to_recv {
            while self.ring_buf[self.next_to_recv].is_none() {
                Self::process_ret(
                    self.collector.recv().expect("channel closed"),
                    &mut self.ring_buf,
                );
            }
        }

        injector.try_send(task).expect("channel is not full");
        while let Ok(ret) = self.collector.try_recv() {
            Self::process_ret(ret, &mut self.ring_buf);
        }

        Self::received_iter(&mut self.next_to_recv, &mut self.ring_buf)
    }

    fn process_ret((idx, ret): TaskResult<R>, ring_buf: &mut [Option<R>]) {
        let v = match ret {
            Ok(v) => v,
            Err(_err) => panic!("task panicked"),
        };
        assert!(ring_buf[idx].is_none(), "completion buffer overflowed");
        ring_buf[idx] = Some(v);
    }

    fn received_iter(
        next_to_recv: &mut usize,
        ring_buf: &mut [Option<R>],
    ) -> impl Iterator<Item = R> {
        std::iter::from_fn(|| {
            let elem = ring_buf[*next_to_recv].take()?;
            *next_to_recv += 1;
            if *next_to_recv == ring_buf.len() {
                *next_to_recv = 0;
            }
            Some(elem)
        })
    }

    /// Blocking receive some completed results.
    ///
    /// Return `None` if the channel is closed and all results are drained.
    pub fn wait_and_get(&mut self) -> Option<impl Iterator<Item = R>> {
        while self.ring_buf[self.next_to_recv].is_none() {
            let ret = self.collector.recv().ok()?;
            Self::process_ret(ret, &mut self.ring_buf);
        }
        Some(Self::received_iter(
            &mut self.next_to_recv,
            &mut self.ring_buf,
        ))
    }

    /// Signal the end of tasks. Stop all workers.
    pub fn stop(&mut self) {
        self.injector = None;
    }
}
