use nanokvm_rust_server::update::raw_transport::{ImageReceiver, TransferContext};
use std::{
    fs::File,
    io::{Read, Seek, SeekFrom},
    os::fd::{AsFd, AsRawFd},
    process::ExitCode,
};

fn probe() -> Result<(), Box<dyn std::error::Error>> {
    let stdin = std::io::stdin();
    let socket = rustix::io::fcntl_dupfd_cloexec(stdin.as_fd(), 3)?;
    // No unsafe ownership conversion for fd0. Retain one owned duplicate and
    // remove the original stdio alias in this disposable single-threaded child.
    let null = File::open("/dev/null")?;
    nix::unistd::dup2(null.as_raw_fd(), 0)?;
    let receiver = ImageReceiver::adopt(socket, nix::unistd::getppid().as_raw() as u32)?;
    let context = TransferContext::new([42; 16], "0.3.0-raw.fixture", [1025, 65537])?;
    let images = receiver.receive(&context)?;
    for (mut image, (size, value)) in images.into_iter().zip([(1025, 0x35), (65537, 0x77)]) {
        assert_eq!(image.seek(SeekFrom::End(0))?, size as u64);
        image.rewind()?;
        let mut actual = Vec::new();
        image.read_to_end(&mut actual)?;
        assert_eq!(actual.len(), size);
        assert!(actual.iter().all(|byte| *byte == value));
    }
    Ok(())
}

fn main() -> ExitCode {
    // Fixed synthetic inputs only. This is NOT an isolated production writer.
    if probe().is_ok() {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    }
}
