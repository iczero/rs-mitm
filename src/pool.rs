//! Stack-structured connection pools

// approximate idea
// one pool per host (probably IP address)
// http/2 connections work as usual
// a http/1 "entry" is actually "up to n" (where n is probably 10) connections
// in a trenchcoat
// timeouts or something

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use async_channel::{Receiver, Sender};
use parking_lot::RwLock;
use tokio::sync::{Notify, oneshot};
use tokio::task::{self, JoinHandle, JoinSet};

pub struct RequestObjectPlaceholder;

pub struct Pool {
    request_queue_send: Sender<RequestObjectPlaceholder>,
    request_queue_recv: Receiver<RequestObjectPlaceholder>,
    manager_control_send: Sender<PoolManagerControl>,
    manager_events_recv: Receiver<PoolManagerEvent>,
    shared: Arc<PoolSharedState>,
    /// Whether the worker manager has budget to spawn another worker
    can_spawn_worker: Arc<AtomicBool>,
    /// Asks worker manager to spawn another worker if queues are full
    complain_button: Arc<Notify>,
    worker_manager: JoinHandle<()>,
}

impl Pool {
    pub fn queue_full(&self) {
        if self.can_spawn_worker.load(Ordering::Relaxed) {
            self.complain_button.notify_one();
        }
    }
}

pub struct PoolSharedState {
    /// Total number of in-progress requests (including queued and active)
    pub outstanding_requests: AtomicUsize,
    /// Current active workers count (not necessarily up to date)
    pub workers_count: AtomicUsize,
    /// Total number of requests received
    pub requests_received: AtomicUsize,
    /// Total number of requests completed
    pub requests_completed: AtomicUsize,
}

pub struct PoolWorkerHandle {
    pub join_handle: JoinHandle<()>,
    pub control_send: Sender<PoolWorkerControl>,
}

// TODO:
pub enum PoolManagerControl {
    Drain(oneshot::Receiver<()>),
    Exit { graceful: bool },
}

pub enum PoolManagerEvent {
    /// All workers exited
    PoolEmpty,
    /// Pool manager worker is about to exit
    Exiting,
}

pub struct PoolWorkerManager {
    workers: JoinSet<()>,
    max_workers: usize,
    request_queue_send: Sender<RequestObjectPlaceholder>,
    request_queue_recv: Receiver<RequestObjectPlaceholder>,
    shared: Arc<PoolSharedState>,
    manager_events_send: Sender<PoolManagerEvent>,
    control_recv: Receiver<PoolManagerControl>,
    /// Wakes worker manager to check if it needs to spawn another worker
    complaint_notifier: Arc<Notify>,
    /// Controls whether queue full notifications will be sent to the manager
    can_spawn_worker: Arc<AtomicBool>,
    /// Worker stack
    worker_stack: Vec<PoolWorkerHandle>,
    /// Receiver for worker exit requests (due to inactivity timeout)
    worker_exit_request_recv: Receiver<task::Id>,
    // worker exit: worker requests exit (inactivity timeout), manager sends exit request,
    // worker either accepts, in which case manager joins it and pops it off
    // the stack if it's the last (it should almost always be the last except in
    // exceptional cases like panics) and notifies the next worker that its
    // successor exited. if the worker does not accept, the manager continues.
    //
    // if there are no more workers, the pool may still hang around; in that
    // case, the manager should listen on the request queue and spawn a
    // worker and then re-queue the request
}

pub enum WorkerExitConfirmation {
    /// The worker will exit immediately and the manager should join on it
    WillExit,
    /// The worker will not exit because it is busy
    WillNotExit,
}

/// Control messages sent to pool workers
pub enum PoolWorkerControl {
    /// Request that this worker exit
    RequestExit {
        confirm: oneshot::Receiver<WorkerExitConfirmation>,
        /// Instruct worker to cancel all pending jobs and exit immediately.
        /// If this is set, WillNotExit should not be returned.
        force: bool,
    },
    /// Next worker exited and this worker is now at the top of the stack
    NextWorkerExited,
    /// Next worker added, this worker is no longer at the top of the stack
    NextWorkerCreated,
}

/// Task for
pub struct PoolWorker {
    // prev: notify
}
