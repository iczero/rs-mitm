//! Connection pools

use std::sync::Weak;
use std::sync::atomic::AtomicUsize;

use async_channel::{Receiver, Sender};

pub trait PoolRequest {}

pub enum PoolManagerMessage<T: PoolRequest> {
    WorkerAvailable(Weak<PoolWorkerShared<T>>),
    WorkerShutdown(Weak<PoolWorkerShared<T>>),
}

pub enum PoolWorkerMessage<T: PoolRequest> {
    Request(T),
    NotifyOnAvailable(Sender<PoolManagerMessage<T>>),
}

pub struct PoolWorkerShared<T: PoolRequest> {
    pub send: Sender<PoolWorkerMessage<T>>,
    pub remaining_capacity: AtomicUsize,
}

pub struct PoolWorker<T: PoolRequest> {
    shared: Weak<PoolWorkerShared<T>>,
    recv: Receiver<PoolWorkerMessage<T>>,
    available_notify: Vec<Sender<PoolManagerMessage<T>>>,
    shutdown_notify: Vec<Sender<PoolManagerMessage<T>>>,
}
