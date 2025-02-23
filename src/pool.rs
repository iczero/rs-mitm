//! Connection pool

use std::sync::atomic::AtomicUsize;
use std::sync::{Arc, Weak};

use async_channel::Sender;
use intrusive_collections::{
    KeyAdapter, LinkedList, LinkedListAtomicLink, RBTree, RBTreeAtomicLink, UnsafeRef,
    intrusive_adapter,
};

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
    shared: Arc<PoolWorkerShared<T>>,
    available_notify: Vec<Sender<PoolManagerMessage<T>>>,
    shutdown_notify: Vec<Sender<PoolManagerMessage<T>>>,
}

pub struct WorkerEntry<T: PoolRequest> {
    worker_shared: Arc<PoolWorkerShared<T>>,
    list_link: LinkedListAtomicLink,
    tree_link: RBTreeAtomicLink,
}

impl<T: PoolRequest> WorkerEntry<T> {
    pub fn new(shared: Arc<PoolWorkerShared<T>>) -> Self {
        Self {
            worker_shared: shared,
            list_link: LinkedListAtomicLink::new(),
            tree_link: RBTreeAtomicLink::new(),
        }
    }
}

intrusive_adapter! {
    WorkerEntryListAdapter<T> = UnsafeRef<WorkerEntry<T>>:
        WorkerEntry<T> { list_link: LinkedListAtomicLink }
    where T: PoolRequest
}

intrusive_adapter! {
    WorkerEntryTreeAdapter<T> = UnsafeRef<WorkerEntry<T>>:
        WorkerEntry<T> { list_link: RBTreeAtomicLink }
    where T: PoolRequest
}

impl<'a, T: PoolRequest> KeyAdapter<'a> for WorkerEntryTreeAdapter<T> {
    type Key = *const PoolWorkerShared<T>;

    fn get_key(
        &self,
        value: &'a <Self::PointerOps as intrusive_collections::PointerOps>::Value,
    ) -> Self::Key {
        Arc::as_ptr(&value.worker_shared)
    }
}

pub trait ArcIntoPtr<T> {
    fn into_ptr(this: &Self) -> *const T;
}

impl<T> ArcIntoPtr<T> for Arc<T> {
    fn into_ptr(this: &Self) -> *const T {
        Arc::as_ptr(this)
    }
}

impl<T> ArcIntoPtr<T> for Weak<T> {
    fn into_ptr(this: &Self) -> *const T {
        Weak::as_ptr(this)
    }
}

// "front" is considered the "top" of the stack
pub struct AvailabilityList<T: PoolRequest> {
    list: LinkedList<WorkerEntryListAdapter<T>>,
    tree: RBTree<WorkerEntryTreeAdapter<T>>,
}

unsafe fn hybrid_remove_entry_by_list_cursor<T: PoolRequest>(
    cursor: &mut intrusive_collections::linked_list::CursorMut<'_, WorkerEntryListAdapter<T>>,
    tree: &mut RBTree<WorkerEntryTreeAdapter<T>>,
) -> Option<Arc<PoolWorkerShared<T>>> {
    let ptr = cursor.remove()?;
    // safety: elements must reside in both structures
    debug_assert!(ptr.tree_link.is_linked());
    let mut cursor = unsafe { tree.cursor_mut_from_ptr(ptr.as_ref()) };
    cursor.remove().expect("invalid state");
    // safety: there must only be two of these and we already dropped the second one
    let shared = unsafe { UnsafeRef::into_box(ptr).worker_shared };
    Some(shared)
}

unsafe fn hybrid_remove_entry_by_tree_cursor<T: PoolRequest>(
    cursor: &mut intrusive_collections::rbtree::CursorMut<'_, WorkerEntryTreeAdapter<T>>,
    list: &mut LinkedList<WorkerEntryListAdapter<T>>,
) -> Option<Arc<PoolWorkerShared<T>>> {
    let ptr = cursor.remove()?;
    // safety: elements must reside in both structures
    debug_assert!(ptr.tree_link.is_linked());
    let mut cursor = unsafe { list.cursor_mut_from_ptr(ptr.as_ref()) };
    cursor.remove().expect("invalid state");
    // safety: there must only be two of these and we already dropped the second one
    let shared = unsafe { UnsafeRef::into_box(ptr).worker_shared };
    Some(shared)
}

impl<T: PoolRequest> AvailabilityList<T> {
    pub fn push_front(&mut self, shared: Arc<PoolWorkerShared<T>>) {
        let entry = Box::new(WorkerEntry::new(shared));
        let ptr = UnsafeRef::from_box(entry);
        self.tree.insert(ptr.clone());
        self.list.push_front(ptr);
    }

    pub fn push_back(&mut self, shared: Arc<PoolWorkerShared<T>>) {
        let entry = Box::new(WorkerEntry::new(shared));
        let ptr = UnsafeRef::from_box(entry);
        self.tree.insert(ptr.clone());
        self.list.push_back(ptr);
    }

    pub fn pop_front(&mut self) -> Option<Arc<PoolWorkerShared<T>>> {
        let mut cursor = self.list.front_mut();
        unsafe { hybrid_remove_entry_by_list_cursor(&mut cursor, &mut self.tree) }
    }

    pub fn pop_back(&mut self) -> Option<Arc<PoolWorkerShared<T>>> {
        let mut cursor = self.list.back_mut();
        unsafe { hybrid_remove_entry_by_list_cursor(&mut cursor, &mut self.tree) }
    }

    pub fn remove_by_key(
        &mut self,
        what: impl ArcIntoPtr<PoolWorkerShared<T>>,
    ) -> Option<Arc<PoolWorkerShared<T>>> {
        let mut cursor = self.tree.find_mut(&ArcIntoPtr::into_ptr(&what));
        unsafe { hybrid_remove_entry_by_tree_cursor(&mut cursor, &mut self.list) }
    }

    pub fn very_limited_cursor_front(&mut self) -> VeryLimitedCursor<'_, T> {
        VeryLimitedCursor {
            list_cursor: self.list.front_mut(),
            tree: &mut self.tree,
        }
    }
}

pub struct VeryLimitedCursor<'a, T: PoolRequest> {
    list_cursor: intrusive_collections::linked_list::CursorMut<'a, WorkerEntryListAdapter<T>>,
    tree: &'a mut RBTree<WorkerEntryTreeAdapter<T>>,
}

impl<T: PoolRequest> VeryLimitedCursor<'_, T> {
    pub fn get(&mut self) -> Option<&PoolWorkerShared<T>> {
        self.list_cursor.get().map(|v| v.worker_shared.as_ref())
    }

    /// removes the current element, then moves the cursor to the next element
    pub fn remove(&mut self) -> Option<Arc<PoolWorkerShared<T>>> {
        unsafe { hybrid_remove_entry_by_list_cursor(&mut self.list_cursor, self.tree) }
    }

    pub fn next(&mut self) {
        self.list_cursor.move_next();
    }

    pub fn is_null(&self) -> bool {
        self.list_cursor.is_null()
    }
}

#[cfg(test)]
mod test {
    // TODO:
}
