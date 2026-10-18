use std::fs::OpenOptions;
use std::io::{self, Read};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

pub const STATE_PATH: &str = "/data/misc/keystore/omk/data/soter_beta.conf";

/// The service process the Soter Beta hook specializes. Restarting it is enough for a
/// changed flag to take effect, because the companion value is read per specialization.
pub const TARGET_PACKAGE: &str = "com.tencent.soter.soterserver";

pub fn canonical_bytes(enabled: bool) -> &'static [u8] {
    if enabled {
        b"1"
    } else {
        b"0"
    }
}

pub fn parse(contents: &[u8]) -> io::Result<bool> {
    match contents {
        b"0" => Ok(false),
        b"1" => Ok(true),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Soter Beta state must contain exactly 0 or 1",
        )),
    }
}

pub fn read() -> io::Result<bool> {
    read_from(Path::new(STATE_PATH))
}

pub fn read_from(path: &Path) -> io::Result<bool> {
    // Open nonblocking before checking the descriptor so a FIFO cannot stall
    // the privileged helper or the Zygisk companion.
    let file = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error),
    };
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() != 1 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Soter Beta state must be a one-byte regular file",
        ));
    }

    let mut contents = Vec::with_capacity(2);
    file.take(2).read_to_end(&mut contents)?;
    parse(&contents)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;
    use std::fs;
    use std::os::unix::{ffi::OsStrExt, fs::symlink};

    #[test]
    fn state_accepts_only_canonical_boolean_bytes() {
        for enabled in [false, true] {
            assert_eq!(parse(canonical_bytes(enabled)).unwrap(), enabled);
        }
        for invalid in [b"".as_slice(), b"true", b"2", b" 1", b"1\n", b"0\0"] {
            assert_eq!(
                parse(invalid).unwrap_err().kind(),
                io::ErrorKind::InvalidData
            );
        }
    }

    #[test]
    fn missing_state_is_disabled_without_creating_a_file() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("state");
        assert!(!read_from(&path).unwrap());
        assert!(!path.exists());
    }

    #[test]
    fn reads_enabled_and_disabled_states() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("state");
        for enabled in [false, true, false] {
            fs::write(&path, canonical_bytes(enabled)).unwrap();
            assert_eq!(read_from(&path).unwrap(), enabled);
        }
    }

    #[test]
    fn rejects_invalid_oversized_and_non_regular_states() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("state");
        for contents in [b"".as_slice(), b"2", b"1\n", &[b'1'; 4096]] {
            fs::write(&path, contents).unwrap();
            assert!(read_from(&path).is_err());
        }
        fs::remove_file(&path).unwrap();
        fs::create_dir(&path).unwrap();
        assert!(read_from(&path).is_err());
    }

    #[test]
    fn rejects_symlink_even_when_target_is_missing() {
        let directory = tempfile::tempdir().unwrap();
        let target = directory.path().join("target");
        let path = directory.path().join("state");
        symlink(&target, &path).unwrap();
        assert!(read_from(&path).is_err());
        fs::write(&target, b"1").unwrap();
        assert!(read_from(&path).is_err());
    }

    #[test]
    fn rejects_fifo_without_waiting_for_a_writer() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("state");
        let c_path = CString::new(path.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) }, 0);
        assert!(read_from(&path).is_err());
    }
}
