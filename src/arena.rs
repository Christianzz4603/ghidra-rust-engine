use std::fmt;
use std::marker::PhantomData;
use std::ops::{Index, IndexMut};

pub trait ArenaId: Copy + Ord + fmt::Debug {
    fn from_index(index: usize) -> Self;
    fn index(self) -> usize;
}

#[macro_export]
macro_rules! define_id {
    ($name:ident) => {
        #[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(pub u32);

        impl $crate::arena::ArenaId for $name {
            fn from_index(index: usize) -> $name {
                $name(u32::try_from(index).expect("arena index exceeds u32 range"))
            }

            fn index(self) -> usize {
                self.0 as usize
            }
        }
    };
}

pub struct Arena<Id, T> {
    slots: Vec<Option<T>>,
    /// Ids below `base` were handed out before the last `clear`. Their slots are gone (so a
    /// cleared arena holds no memory) but the ids are never reused, so a stale id still panics.
    base: usize,
    live: usize,
    marker: PhantomData<Id>,
}

impl<Id: ArenaId, T> Default for Arena<Id, T> {
    fn default() -> Arena<Id, T> {
        Arena::new()
    }
}

impl<Id: ArenaId, T: Clone> Clone for Arena<Id, T> {
    fn clone(&self) -> Arena<Id, T> {
        Arena {
            slots: self.slots.clone(),
            base: self.base,
            live: self.live,
            marker: PhantomData,
        }
    }
}

impl<Id: ArenaId, T: fmt::Debug> fmt::Debug for Arena<Id, T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_map().entries(self.iter()).finish()
    }
}

impl<Id: ArenaId, T> Arena<Id, T> {
    pub fn new() -> Arena<Id, T> {
        Arena {
            slots: Vec::new(),
            base: 0,
            live: 0,
            marker: PhantomData,
        }
    }

    fn slot_index(&self, id: Id) -> Option<usize> {
        id.index().checked_sub(self.base)
    }

    pub fn alloc(&mut self, value: T) -> Id {
        let id = Id::from_index(self.base + self.slots.len());
        self.slots.push(Some(value));
        self.live += 1;
        id
    }

    pub fn alloc_with(&mut self, build: impl FnOnce(Id) -> T) -> Id {
        let id = Id::from_index(self.base + self.slots.len());
        let value = build(id);
        self.slots.push(Some(value));
        self.live += 1;
        id
    }

    pub fn next_id(&self) -> Id {
        Id::from_index(self.base + self.slots.len())
    }

    pub fn contains(&self, id: Id) -> bool {
        self.try_get(id).is_some()
    }

    pub fn get(&self, id: Id) -> &T {
        match self.try_get(id) {
            Some(value) => value,
            None => panic!("stale or invalid arena id {:?}", id),
        }
    }

    pub fn get_mut(&mut self, id: Id) -> &mut T {
        match self.try_get_mut(id) {
            Some(value) => value,
            None => panic!("stale or invalid arena id {:?}", id),
        }
    }

    pub fn try_get(&self, id: Id) -> Option<&T> {
        let index = self.slot_index(id)?;
        self.slots.get(index).and_then(|slot| slot.as_ref())
    }

    pub fn try_get_mut(&mut self, id: Id) -> Option<&mut T> {
        let index = self.slot_index(id)?;
        self.slots.get_mut(index).and_then(|slot| slot.as_mut())
    }

    pub fn get2_mut(&mut self, first: Id, second: Id) -> (&mut T, &mut T) {
        assert!(
            first.index() != second.index(),
            "get2_mut with identical ids {:?}",
            first
        );
        let (low_id, high_id, swapped) = if first.index() < second.index() {
            (first, second, false)
        } else {
            (second, first, true)
        };
        let (Some(low), Some(high)) = (self.slot_index(low_id), self.slot_index(high_id)) else {
            panic!("stale or invalid arena id {:?} or {:?}", low_id, high_id);
        };
        let (head, tail) = self.slots.split_at_mut(high);
        let low_value = head[low]
            .as_mut()
            .unwrap_or_else(|| panic!("stale or invalid arena id {:?}", low_id));
        let high_value = tail[0]
            .as_mut()
            .unwrap_or_else(|| panic!("stale or invalid arena id {:?}", high_id));
        if swapped {
            (high_value, low_value)
        } else {
            (low_value, high_value)
        }
    }

    pub fn remove(&mut self, id: Id) -> T {
        let value = self
            .slot_index(id)
            .and_then(|index| self.slots.get_mut(index))
            .and_then(|slot| slot.take())
            .unwrap_or_else(|| panic!("stale or invalid arena id {:?}", id));
        self.live -= 1;
        value
    }

    /// Removes every element and frees the storage. Ids already issued stay invalid.
    pub fn clear(&mut self) {
        self.base += self.slots.len();
        self.slots = Vec::new();
        self.live = 0;
    }

    pub fn len(&self) -> usize {
        self.live
    }

    pub fn is_empty(&self) -> bool {
        self.live == 0
    }

    pub fn capacity_ids(&self) -> usize {
        self.base + self.slots.len()
    }

    pub fn iter(&self) -> impl DoubleEndedIterator<Item = (Id, &T)> {
        let base = self.base;
        self.slots
            .iter()
            .enumerate()
            .filter_map(move |(index, slot)| slot.as_ref().map(|value| (Id::from_index(base + index), value)))
    }

    pub fn iter_mut(&mut self) -> impl DoubleEndedIterator<Item = (Id, &mut T)> {
        let base = self.base;
        self.slots
            .iter_mut()
            .enumerate()
            .filter_map(move |(index, slot)| slot.as_mut().map(|value| (Id::from_index(base + index), value)))
    }

    pub fn ids(&self) -> Vec<Id> {
        self.iter().map(|(id, _)| id).collect()
    }
}

impl<Id: ArenaId, T> Index<Id> for Arena<Id, T> {
    type Output = T;

    fn index(&self, id: Id) -> &T {
        self.get(id)
    }
}

impl<Id: ArenaId, T> IndexMut<Id> for Arena<Id, T> {
    fn index_mut(&mut self, id: Id) -> &mut T {
        self.get_mut(id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    define_id!(TestId);

    #[test]
    fn alloc_and_access() {
        let mut arena: Arena<TestId, String> = Arena::new();
        let first = arena.alloc("first".to_string());
        let second = arena.alloc_with(|id| format!("id{}", id.0));
        assert_eq!(first, TestId(0));
        assert_eq!(second, TestId(1));
        assert_eq!(arena[first], "first");
        assert_eq!(arena.get(second), "id1");
        arena[first].push('!');
        assert_eq!(arena[first], "first!");
        assert_eq!(arena.len(), 2);
        assert_eq!(arena.next_id(), TestId(2));
        assert!(first < second);
    }

    #[test]
    fn removal_never_reuses_slots() {
        let mut arena: Arena<TestId, i32> = Arena::new();
        let first = arena.alloc(10);
        let second = arena.alloc(20);
        assert_eq!(arena.remove(first), 10);
        assert!(!arena.contains(first));
        assert!(arena.try_get(first).is_none());
        let third = arena.alloc(30);
        assert_eq!(third, TestId(2));
        assert_eq!(arena.len(), 2);
        let live: Vec<(TestId, i32)> = arena.iter().map(|(id, value)| (id, *value)).collect();
        assert_eq!(live, vec![(second, 20), (third, 30)]);
        assert_eq!(arena.ids(), vec![second, third]);
        arena.clear();
        assert!(arena.is_empty());
        assert_eq!(arena.alloc(40), TestId(3));
        assert_eq!(arena.capacity_ids(), 4);
    }

    #[test]
    fn clear_frees_storage_but_ids_stay_stale() {
        let mut arena: Arena<TestId, i32> = Arena::new();
        let old = arena.alloc(1);
        arena.clear();
        assert!(!arena.contains(old));
        let fresh = arena.alloc(2);
        assert_eq!(fresh, TestId(1));
        assert_eq!(arena[fresh], 2);
        assert!(arena.try_get(old).is_none());
        assert_eq!(arena.capacity_ids(), 2);
    }

    #[test]
    #[should_panic(expected = "stale or invalid arena id")]
    fn stale_id_panics() {
        let mut arena: Arena<TestId, i32> = Arena::new();
        let first = arena.alloc(1);
        arena.remove(first);
        let _value = arena.get(first);
    }

    #[test]
    fn two_mutable_borrows() {
        let mut arena: Arena<TestId, i32> = Arena::new();
        let first = arena.alloc(1);
        let second = arena.alloc(2);
        {
            let (high, low) = arena.get2_mut(second, first);
            *high += 10;
            *low += 100;
        }
        assert_eq!(arena[first], 101);
        assert_eq!(arena[second], 12);
        for (_, value) in arena.iter_mut() {
            *value *= 2;
        }
        assert_eq!(arena[first], 202);
    }
}
