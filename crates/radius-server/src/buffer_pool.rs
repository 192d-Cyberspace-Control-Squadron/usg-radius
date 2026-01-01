//! Buffer Pool for Memory Optimization
//!
//! This module provides a thread-safe buffer pool to reduce allocations
//! in hot paths like packet receiving and processing.

use std::sync::Arc;
use tokio::sync::Mutex;

/// A reusable buffer with automatic return to pool
pub struct PooledBuffer {
    buffer: Vec<u8>,
    pool: Arc<BufferPool>,
}

impl PooledBuffer {
    /// Get a mutable reference to the buffer
    pub fn as_mut(&mut self) -> &mut Vec<u8> {
        &mut self.buffer
    }

    /// Get an immutable reference to the buffer
    pub fn as_ref(&self) -> &[u8] {
        &self.buffer
    }

    /// Get the buffer length
    pub fn len(&self) -> usize {
        self.buffer.len()
    }

    /// Check if buffer is empty
    pub fn is_empty(&self) -> bool {
        self.buffer.is_empty()
    }

    /// Get the buffer capacity
    pub fn capacity(&self) -> usize {
        self.buffer.capacity()
    }

    /// Clear the buffer (reset length to 0)
    pub fn clear(&mut self) {
        self.buffer.clear();
    }
}

impl Drop for PooledBuffer {
    fn drop(&mut self) {
        // Return buffer to pool when dropped
        let buffer = std::mem::take(&mut self.buffer);
        let pool = Arc::clone(&self.pool);

        // Return buffer synchronously using blocking_lock
        // This is safe because we're just pushing to a Vec, which is fast
        if let Ok(mut buffers) = pool.buffers.try_lock() {
            // Clear the buffer
            let mut buffer = buffer;
            buffer.clear();

            // Only return to pool if we haven't exceeded max size
            if buffers.len() < pool.max_pool_size {
                // Ensure buffer has the right capacity
                if buffer.capacity() < pool.buffer_size {
                    buffer.reserve(pool.buffer_size - buffer.capacity());
                } else if buffer.capacity() > pool.buffer_size * 2 {
                    // Shrink if buffer grew too large
                    buffer.shrink_to(pool.buffer_size);
                }
                buffers.push(buffer);
            }
            // Otherwise, drop the buffer (let it be freed)
        }
        // If we couldn't get the lock, just drop the buffer
    }
}

impl AsRef<[u8]> for PooledBuffer {
    fn as_ref(&self) -> &[u8] {
        &self.buffer
    }
}

impl AsMut<Vec<u8>> for PooledBuffer {
    fn as_mut(&mut self) -> &mut Vec<u8> {
        &mut self.buffer
    }
}

/// Buffer pool for reusing allocations
pub struct BufferPool {
    buffers: Mutex<Vec<Vec<u8>>>,
    buffer_size: usize,
    max_pool_size: usize,
}

impl BufferPool {
    /// Create a new buffer pool
    ///
    /// # Arguments
    /// * `buffer_size` - Size of each buffer (typically 4096 for RADIUS)
    /// * `max_pool_size` - Maximum number of buffers to keep in the pool
    pub fn new(buffer_size: usize, max_pool_size: usize) -> Arc<Self> {
        Arc::new(BufferPool {
            buffers: Mutex::new(Vec::with_capacity(max_pool_size)),
            buffer_size,
            max_pool_size,
        })
    }

    /// Acquire a buffer from the pool
    ///
    /// If the pool is empty, allocates a new buffer.
    pub async fn acquire(self: &Arc<Self>) -> PooledBuffer {
        let mut pool = self.buffers.lock().await;
        let buffer = pool.pop().unwrap_or_else(|| {
            // Allocate new buffer if pool is empty
            Vec::with_capacity(self.buffer_size)
        });

        PooledBuffer {
            buffer,
            pool: Arc::clone(self),
        }
    }

    /// Get current pool size (for monitoring)
    pub async fn size(&self) -> usize {
        self.buffers.lock().await.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_buffer_pool_acquire_and_return() {
        let pool = BufferPool::new(4096, 10);

        // Acquire buffer
        let mut buffer = pool.acquire().await;
        assert_eq!(buffer.len(), 0);
        assert!(buffer.capacity() >= 4096);

        // Use buffer
        buffer.as_mut().extend_from_slice(b"test data");
        assert_eq!(buffer.len(), 9);

        // Drop buffer (returns to pool synchronously)
        drop(buffer);

        // Verify buffer was returned
        assert_eq!(pool.size().await, 1);

        // Acquire again - should reuse
        let buffer2 = pool.acquire().await;
        assert_eq!(buffer2.len(), 0); // Should be cleared
        assert_eq!(pool.size().await, 0); // Pool should be empty
    }

    #[tokio::test]
    async fn test_buffer_pool_max_size() {
        let pool = BufferPool::new(1024, 2);

        // Acquire 3 buffers
        let b1 = pool.acquire().await;
        let b2 = pool.acquire().await;
        let b3 = pool.acquire().await;

        assert_eq!(pool.size().await, 0);

        // Return all 3 (synchronously)
        drop(b1);
        drop(b2);
        drop(b3);

        // Only 2 should be kept (max_pool_size)
        assert_eq!(pool.size().await, 2);
    }

    #[tokio::test]
    async fn test_buffer_pool_concurrent() {
        let pool = BufferPool::new(4096, 100);

        // Spawn multiple tasks that acquire and release buffers
        let mut handles = vec![];
        for _ in 0..50 {
            let p = Arc::clone(&pool);
            let handle = tokio::spawn(async move {
                for _ in 0..10 {
                    let mut buf = p.acquire().await;
                    buf.as_mut().extend_from_slice(b"test");
                    tokio::time::sleep(tokio::time::Duration::from_micros(1)).await;
                    // Buffer is returned synchronously when dropped
                }
            });
            handles.push(handle);
        }

        // Wait for all tasks
        for handle in handles {
            handle.await.unwrap();
        }

        // Pool should have some buffers available (returns are synchronous now)
        let size = pool.size().await;
        assert!(size > 0 && size <= 100);
    }
}
