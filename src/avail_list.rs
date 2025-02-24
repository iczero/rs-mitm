//! Availability list

use std::sync::{Arc, Weak};

use intrusive_collections::{
    KeyAdapter, LinkedList, LinkedListAtomicLink, RBTree, RBTreeAtomicLink, UnsafeRef,
    intrusive_adapter,
};

pub struct Entry<T> {
    shared: Arc<T>,
    list_link: LinkedListAtomicLink,
    tree_link: RBTreeAtomicLink,
}

impl<T> Entry<T> {
    pub fn new_box(shared: Arc<T>) -> Box<Self> {
        Box::new(Self {
            shared,
            list_link: LinkedListAtomicLink::new(),
            tree_link: RBTreeAtomicLink::new(),
        })
    }
}

intrusive_adapter! {
    EntryListAdapter<T> = UnsafeRef<Entry<T>>:
        Entry<T> { list_link: LinkedListAtomicLink }
}

intrusive_adapter! {
    EntryTreeAdapter<T> = UnsafeRef<Entry<T>>:
        Entry<T> { tree_link: RBTreeAtomicLink }
}

impl<'a, T> KeyAdapter<'a> for EntryTreeAdapter<T> {
    type Key = *const T;

    fn get_key(
        &self,
        value: &'a <Self::PointerOps as intrusive_collections::PointerOps>::Value,
    ) -> Self::Key {
        Arc::as_ptr(&value.shared)
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

/// hybrid rbtree/linked list for worker availability tracking
///
/// - "front" is considered the "top" of the stack
/// - invariant: any element in the list must also be in the tree, but elements
///   may exist in the tree without existing in the list
pub struct AvailabilityList<T> {
    list: LinkedList<EntryListAdapter<T>>,
    tree: RBTree<EntryTreeAdapter<T>>,
}

unsafe fn hybrid_remove_entry_by_list_cursor<T>(
    cursor: &mut intrusive_collections::linked_list::CursorMut<'_, EntryListAdapter<T>>,
    tree: &mut RBTree<EntryTreeAdapter<T>>,
) -> Option<Arc<T>> {
    let ptr = cursor.remove()?;
    // safety: elements in the list must also be in the tree, and elements are
    // not shared with other structures
    debug_assert!(ptr.tree_link.is_linked());
    let mut cursor = unsafe { tree.cursor_mut_from_ptr(ptr.as_ref()) };
    cursor.remove().expect("invalid state");
    // safety: there must only be two of these and we already dropped the second one
    let shared = unsafe { UnsafeRef::into_box(ptr).shared };
    Some(shared)
}

unsafe fn hybrid_remove_entry_by_tree_cursor<T>(
    cursor: &mut intrusive_collections::rbtree::CursorMut<'_, EntryTreeAdapter<T>>,
    list: &mut LinkedList<EntryListAdapter<T>>,
) -> Option<Arc<T>> {
    let ptr = cursor.remove()?;
    // safety: elements are not shared with other structures
    if ptr.tree_link.is_linked() {
        let mut cursor = unsafe { list.cursor_mut_from_ptr(ptr.as_ref()) };
        cursor.remove().expect("invalid state");
    }
    // safety: all references removed from the structure
    let shared = unsafe { UnsafeRef::into_box(ptr).shared };
    Some(shared)
}

pub enum CursorAtKeyResult<'a, T> {
    Ok(VeryLimitedCursor<'a, T>),
    NotInList,
    NoMatch,
}

pub enum InsertExistingResult {
    Ok,
    NoMatch,
    AlreadyInList,
}

impl<T> AvailabilityList<T> {
    pub fn new() -> Self {
        Self {
            list: LinkedList::new(EntryListAdapter::new()),
            tree: RBTree::new(EntryTreeAdapter::new()),
        }
    }

    pub fn push_front_new(&mut self, shared: Arc<T>) {
        let ptr = UnsafeRef::from_box(Entry::new_box(shared));
        self.tree.insert(ptr.clone());
        self.list.push_front(ptr);
    }

    pub fn push_back_new(&mut self, shared: Arc<T>) {
        let ptr = UnsafeRef::from_box(Entry::new_box(shared));
        self.tree.insert(ptr.clone());
        self.list.push_back(ptr);
    }

    pub fn push_front_existing(&mut self, what: &impl ArcIntoPtr<T>) -> InsertExistingResult {
        let cursor = self.tree.find_mut(&ArcIntoPtr::into_ptr(what));
        let Some(entry) = cursor.get() else {
            return InsertExistingResult::NoMatch;
        };
        if entry.list_link.is_linked() {
            InsertExistingResult::AlreadyInList
        } else {
            let ptr = unsafe { UnsafeRef::from_raw(entry) };
            self.list.push_front(ptr);
            InsertExistingResult::Ok
        }
    }

    pub fn push_back_existing(&mut self, what: &impl ArcIntoPtr<T>) -> InsertExistingResult {
        let cursor = self.tree.find_mut(&ArcIntoPtr::into_ptr(what));
        let Some(entry) = cursor.get() else {
            return InsertExistingResult::NoMatch;
        };
        if entry.list_link.is_linked() {
            InsertExistingResult::AlreadyInList
        } else {
            let ptr = unsafe { UnsafeRef::from_raw(entry) };
            self.list.push_back(ptr);
            InsertExistingResult::Ok
        }
    }

    pub fn pop_front_full(&mut self) -> Option<Arc<T>> {
        let mut cursor = self.list.front_mut();
        unsafe { hybrid_remove_entry_by_list_cursor(&mut cursor, &mut self.tree) }
    }

    pub fn pop_back_full(&mut self) -> Option<Arc<T>> {
        let mut cursor = self.list.back_mut();
        unsafe { hybrid_remove_entry_by_list_cursor(&mut cursor, &mut self.tree) }
    }

    pub fn remove_by_key(&mut self, what: &impl ArcIntoPtr<T>) -> Option<Arc<T>> {
        let mut cursor = self.tree.find_mut(&ArcIntoPtr::into_ptr(what));
        unsafe { hybrid_remove_entry_by_tree_cursor(&mut cursor, &mut self.list) }
    }

    pub fn cursor_front(&mut self) -> VeryLimitedCursor<'_, T> {
        VeryLimitedCursor {
            list_cursor: self.list.front_mut(),
            tree: &mut self.tree,
        }
    }

    pub fn cursor_back(&mut self) -> VeryLimitedCursor<'_, T> {
        VeryLimitedCursor {
            list_cursor: self.list.back_mut(),
            tree: &mut self.tree,
        }
    }

    pub fn cursor_at_key(&mut self, what: &impl ArcIntoPtr<T>) -> CursorAtKeyResult<'_, T> {
        let tree_cursor = self.tree.find_mut(&ArcIntoPtr::into_ptr(what));
        let Some(entry) = tree_cursor.get() else {
            return CursorAtKeyResult::NoMatch;
        };
        if !entry.list_link.is_linked() {
            CursorAtKeyResult::NotInList
        } else {
            CursorAtKeyResult::Ok(VeryLimitedCursor {
                list_cursor: unsafe { self.list.cursor_mut_from_ptr(entry) },
                tree: &mut self.tree,
            })
        }
    }
}

impl<T> Default for AvailabilityList<T> {
    fn default() -> Self {
        Self::new()
    }
}

pub struct VeryLimitedCursor<'a, T> {
    list_cursor: intrusive_collections::linked_list::CursorMut<'a, EntryListAdapter<T>>,
    tree: &'a mut RBTree<EntryTreeAdapter<T>>,
}

impl<T> VeryLimitedCursor<'_, T> {
    pub fn get(&mut self) -> Option<&Arc<T>> {
        self.list_cursor.get().map(|v| &v.shared)
    }

    /// removes the current element completely, then moves the cursor to the next element
    pub fn remove_full(&mut self) -> Option<Arc<T>> {
        unsafe { hybrid_remove_entry_by_list_cursor(&mut self.list_cursor, self.tree) }
    }

    /// removes the current element from the list, then moves the cursor to the next element
    ///
    /// returns true if removed, false if the cursor is pointing to the null object
    pub fn remove_list(&mut self) -> bool {
        self.list_cursor.remove().is_some()
    }

    pub fn move_prev(&mut self) {
        self.list_cursor.move_prev();
    }

    pub fn move_next(&mut self) {
        self.list_cursor.move_next();
    }

    pub fn is_null(&self) -> bool {
        self.list_cursor.is_null()
    }
}

#[cfg(test)]
mod test {
    use std::collections::HashMap;
    use std::ops::Deref;
    use std::sync::Arc;

    use super::AvailabilityList;

    #[test]
    fn derp() {
        let mut list: AvailabilityList<u64> = AvailabilityList::new();
        let mut map: HashMap<u64, Arc<u64>> = HashMap::new();

        for i in 0u64..64 {
            let arc = Arc::new(i);
            list.push_back_new(Arc::clone(&arc));
            map.insert(i, arc);
        }

        let mut cursor = list.cursor_front();
        assert_eq!(cursor.get().unwrap().deref(), &0);
        cursor.move_next();
        assert_eq!(cursor.get().unwrap().deref(), &1);
        assert_eq!(
            Arc::as_ptr(cursor.get().unwrap()),
            Arc::as_ptr(map.get(&1).unwrap())
        );
    }
    // TODO:
}
