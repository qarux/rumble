use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Mutex;

pub type SessionId = u32;

pub struct SessionPool {
    next_session_id: AtomicU32,
    released: Mutex<Vec<SessionId>>,
}

impl SessionPool {
    pub fn new() -> Self {
        SessionPool {
            // 0 is reserved for SuperUser
            next_session_id: AtomicU32::new(1),
            released: Mutex::new(vec![]),
        }
    }

    pub fn pop(&self) -> SessionId {
        let mut released = self.released.lock().unwrap();
        if released.is_empty() {
            self.next_session_id.fetch_add(1, Ordering::SeqCst)
        } else {
            let index = released.len() - 1;
            released.remove(index)
        }
    }

    pub fn push(&self, id: SessionId) {
        let mut released = self.released.lock().unwrap();
        released.push(id);
    }
}
