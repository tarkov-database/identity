pub(crate) mod crypto;

use tokio::{
    signal::unix::{signal, SignalKind},
    sync::broadcast::{self, Sender},
};

pub fn shutdown_signal(rx_count: usize) -> Sender<()> {
    let (tx, _) = broadcast::channel(rx_count);

    let tx2 = tx.clone();

    tokio::spawn(async move {
        let mut sig_int = signal(SignalKind::interrupt()).unwrap();
        let mut sig_term = signal(SignalKind::terminate()).unwrap();

        tokio::select! {
            _ = sig_int.recv() => {},
            _ = sig_term.recv() => {},
        };

        tx.send(()).unwrap();
    });

    tx2
}
