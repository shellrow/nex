//! Runtime-independent bridge from the blocking winptap receiver to a Stream.

use super::{CancellationToken, Config, Error, Packet, open};
use futures_core::{Stream, stream::FusedStream};
use nex_core::interface::Interface;
use std::{
    io,
    pin::Pin,
    sync::{Arc, Condvar, Mutex},
    task::{Context, Poll, Waker},
    thread::{self, JoinHandle},
};

#[derive(Default)]
struct State {
    packet: Option<Packet>,
    terminal: Option<Result<(), Error>>,
    waker: Option<Waker>,
}

#[derive(Default)]
struct Shared {
    state: Mutex<State>,
    consumed: Condvar,
}

impl Shared {
    fn finish(&self, result: Result<(), Error>) {
        let waker = {
            let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
            if state.terminal.is_none() {
                if result.is_err() {
                    state.packet = None;
                }
                state.terminal = Some(result);
            }
            state.waker.take()
        };
        self.consumed.notify_all();
        if let Some(waker) = waker {
            waker.wake();
        }
    }

    fn receive(&self, cx: &mut Context<'_>) -> Poll<Option<io::Result<Vec<u8>>>> {
        let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(packet) = state.packet.take() {
            drop(state);
            self.consumed.notify_one();
            // AsyncRawReceiver requires an owned Vec. winptap 0.2 exposes only
            // borrowed packet bytes, so one copy is required at this boundary.
            return Poll::Ready(Some(Ok(packet.data().to_vec())));
        }
        if let Some(result) = &state.terminal {
            return Poll::Ready(match result {
                Ok(()) => None,
                Err(error) => Some(Err(error.clone().into())),
            });
        }
        // The same lock protects publication and registration: no lost wakeup
        // between observing an empty slot and returning Pending.
        if state
            .waker
            .as_ref()
            .is_none_or(|w| !w.will_wake(cx.waker()))
        {
            state.waker = Some(cx.waker().clone());
        }
        Poll::Pending
    }
}

fn drive(shared: &Shared, mut receive: impl FnMut() -> ::winptap::Result<Option<Packet>>) {
    loop {
        let mut state = shared.state.lock().unwrap_or_else(|p| p.into_inner());
        while state.packet.is_some() && state.terminal.is_none() {
            state = shared
                .consumed
                .wait(state)
                .unwrap_or_else(|p| p.into_inner());
        }
        if state.terminal.is_some() {
            return;
        }
        drop(state);
        match receive() {
            Ok(Some(packet)) => {
                let waker = {
                    let mut state = shared.state.lock().unwrap_or_else(|p| p.into_inner());
                    if state.terminal.is_some() {
                        return;
                    }
                    state.packet = Some(packet);
                    state.waker.take()
                };
                if let Some(waker) = waker {
                    waker.wake();
                }
            }
            result => {
                shared.finish(result.map(|_| ()));
                return;
            }
        }
    }
}

/// Cancel both the asynchronous handoff and the underlying capture.
///
/// Clones may be used on other threads. Cancellation discards pending delivery,
/// wakes the stream, and produces one `Interrupted` error followed by stream end.
#[derive(Clone)]
pub struct AsyncCancellationToken {
    inner: CancellationToken,
    shared: Arc<Shared>,
}

impl AsyncCancellationToken {
    /// Request cancellation without joining either worker thread.
    pub fn cancel(&self) {
        self.inner.cancel();
        self.shared.finish(Err(Error::Cancelled));
    }
}

/// A receive-only `Stream<Item = io::Result<Vec<u8>>>` implementing
/// [`crate::async_io::AsyncRawReceiver`], independent of the async runtime.
///
/// One bridge thread waits for packets in addition to winptap's session owner.
/// The handoff holds at most one packet; the configured capture queue remains
/// bounded. Each delivered Vec requires one copy. Polling never waits for packet
/// arrival or thread shutdown. Drop cancels and joins both workers and may block
/// during driver cleanup. Use [`Self::close`] to observe shutdown failures.
pub struct AsyncReceiver {
    shared: Arc<Shared>,
    cancellation: AsyncCancellationToken,
    worker: Option<JoinHandle<io::Result<()>>>,
    terminated: bool,
}

impl AsyncReceiver {
    /// Obtain a token for cancellation from another task or thread.
    pub fn cancellation_token(&self) -> AsyncCancellationToken {
        self.cancellation.clone()
    }

    /// Cancel delivery and synchronously join the workers. This discards pending
    /// frames, unlike the synchronous receiver's draining `stop` operation.
    /// The stream yields one `Interrupted` error then ends unless already ended.
    pub fn close(&mut self) -> io::Result<()> {
        self.cancellation.cancel();
        match self.worker.take() {
            Some(worker) => worker
                .join()
                .map_err(|_| io::Error::other("winptap receive worker panicked"))?,
            None => Ok(()),
        }
    }
}

impl Drop for AsyncReceiver {
    fn drop(&mut self) {
        let _ = self.close();
    }
}

impl Stream for AsyncReceiver {
    type Item = io::Result<Vec<u8>>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        if this.terminated {
            return Poll::Ready(None);
        }
        let result = this.shared.receive(cx);
        if matches!(result, Poll::Ready(None | Some(Err(_)))) {
            this.terminated = true;
        }
        result
    }
}

impl FusedStream for AsyncReceiver {
    fn is_terminated(&self) -> bool {
        self.terminated
    }
}

/// Open and start a runtime-independent asynchronous Ethernet receiver.
///
/// Requires both `winptap` and `async` features. Opening itself performs blocking
/// device initialization, like the existing async channel constructors. There is
/// no sender or implicit Npcap fallback. `read_timeout` must be `None`: use the
/// executor's timeout/select facility around stream reads. Dropping a pending
/// read future does not consume a packet or stop capture.
pub fn open_async(interface: &Interface, config: Config) -> io::Result<AsyncReceiver> {
    if config.read_timeout.is_some() {
        return Err(Error::InvalidConfig(
            "async reception requires read_timeout = None; use an executor deadline",
        )
        .into());
    }
    let mut receiver = open(interface, config)?.inner;
    let shared = Arc::new(Shared::default());
    let cancellation = AsyncCancellationToken {
        inner: receiver.cancellation_token(),
        shared: shared.clone(),
    };
    let producer = shared.clone();
    let worker = thread::Builder::new()
        .name("nex-winptap-receive".into())
        .spawn(move || {
            drive(&producer, || receiver.next_packet());
            receiver.stop().map_err(Into::into)
        })?;
    Ok(AsyncReceiver {
        shared,
        cancellation,
        worker: Some(worker),
        terminated: false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::{
        StreamExt,
        executor::block_on,
        task::{ArcWake, waker},
    };
    use std::sync::atomic::{AtomicUsize, Ordering};
    use winptap_core::{Backend, OverflowPolicy, PacketQueue, wire::decode_stream};

    fn packet(value: u8) -> Packet {
        let mut record = [0; 54];
        record[40..].fill(value);
        decode_stream(&record, 0, 40, 14, 9000, Backend::Pktmon).unwrap()
    }

    fn fake() -> (AsyncReceiver, Arc<PacketQueue>) {
        let queue = PacketQueue::new(2, OverflowPolicy::DropNewest);
        let shared = Arc::new(Shared::default());
        let cancellation = AsyncCancellationToken {
            inner: CancellationToken(queue.clone()),
            shared: shared.clone(),
        };
        let producer = shared.clone();
        let source = queue.clone();
        let worker = thread::spawn(move || {
            drive(&producer, || source.receive(None));
            Ok(())
        });
        (
            AsyncReceiver {
                shared,
                cancellation,
                worker: Some(worker),
                terminated: false,
            },
            queue,
        )
    }

    #[derive(Default)]
    struct WakeCount(AtomicUsize);
    impl ArcWake for WakeCount {
        fn wake_by_ref(arc_self: &Arc<Self>) {
            arc_self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    fn wait_for_handoff(receiver: &AsyncReceiver) {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        while receiver.shared.state.lock().unwrap().packet.is_none() {
            assert!(
                std::time::Instant::now() < deadline,
                "worker failed to publish packet"
            );
            thread::yield_now();
        }
    }

    #[test]
    fn runtime_independent_trait_stream_drains_and_fuses() {
        fn contract<T: crate::async_io::AsyncRawReceiver + FusedStream>() {}
        contract::<AsyncReceiver>();
        let (mut receiver, queue) = fake();
        queue.push(packet(1));
        queue.push(packet(2));
        queue.close(Ok(()));
        block_on(async {
            let raw: &mut dyn crate::async_io::AsyncRawReceiver = &mut receiver;
            assert_eq!(raw.next().await.unwrap().unwrap(), vec![1; 14]);
            assert_eq!(raw.next().await.unwrap().unwrap(), vec![2; 14]);
            assert!(raw.next().await.is_none());
        });
        assert!(receiver.is_terminated());
        assert!(block_on(receiver.next()).is_none());
        receiver.close().unwrap();
    }

    #[test]
    fn latest_waker_is_notified_without_consuming_a_pending_read() {
        let shared = Shared::default();
        let first = Arc::new(WakeCount::default());
        let second = Arc::new(WakeCount::default());
        let first_waker = waker(first.clone());
        let second_waker = waker(second.clone());
        assert!(
            shared
                .receive(&mut Context::from_waker(&first_waker))
                .is_pending()
        );
        assert!(
            shared
                .receive(&mut Context::from_waker(&second_waker))
                .is_pending()
        );
        shared.finish(Err(Error::Cancelled));
        assert_eq!(first.0.load(Ordering::SeqCst), 0);
        assert_eq!(second.0.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn cancellation_wakes_pending_read_and_is_reported_once() {
        let (mut receiver, _queue) = fake();
        let token = receiver.cancellation_token();
        let cancel = thread::spawn(move || token.cancel());
        let error = block_on(receiver.next()).unwrap().unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Interrupted);
        assert_eq!(
            error.get_ref().unwrap().downcast_ref::<Error>(),
            Some(&Error::Cancelled)
        );
        assert!(block_on(receiver.next()).is_none());
        cancel.join().unwrap();
        receiver.close().unwrap();
    }

    #[test]
    fn full_handoff_bounds_prefetch_and_close_does_not_deadlock() {
        let (mut receiver, queue) = fake();
        queue.push(packet(1));
        wait_for_handoff(&receiver);
        queue.push(packet(2));
        queue.push(packet(3));
        queue.push(packet(4));
        assert_eq!(queue.stats().delivered, 1);
        assert_eq!(queue.stats().queue_overflow, 1);
        receiver.close().unwrap();
        assert_eq!(
            block_on(receiver.next()).unwrap().unwrap_err().kind(),
            io::ErrorKind::Interrupted
        );
        assert!(block_on(receiver.next()).is_none());
        receiver.close().unwrap();
    }

    #[test]
    fn terminal_failure_is_preserved_and_drop_wakes_idle_worker() {
        let (mut receiver, queue) = fake();
        queue.close(Err(Error::StreamFailed(17)));
        let error = block_on(receiver.next()).unwrap().unwrap_err();
        assert_eq!(
            error.get_ref().unwrap().downcast_ref::<Error>(),
            Some(&Error::StreamFailed(17))
        );
        assert!(block_on(receiver.next()).is_none());
        drop(receiver);
        let (receiver, queue) = fake();
        drop(receiver);
        assert!(queue.is_closed());
    }

    #[test]
    fn dropped_read_future_leaves_packet_available() {
        let (mut receiver, queue) = fake();
        {
            let mut future = receiver.next();
            let mut cx = Context::from_waker(futures::task::noop_waker_ref());
            assert!(std::future::Future::poll(Pin::new(&mut future), &mut cx).is_pending());
        }
        queue.push(packet(9));
        assert_eq!(block_on(receiver.next()).unwrap().unwrap(), vec![9; 14]);
    }

    #[test]
    fn sync_timeout_is_rejected_before_device_access() {
        let config = Config {
            read_timeout: Some(std::time::Duration::ZERO),
            ..Config::default()
        };
        let error = open_async(&Interface::dummy(), config).err().unwrap();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    }
}
