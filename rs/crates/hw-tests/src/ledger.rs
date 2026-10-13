//! Transport open/exchange with status-word check, the counterpart of
//! `js/lib/ledger.js`.
//!
//! Two backends:
//!
//! - the host simulator in `sim/`, spawned as a child process. It compiles
//!   the real dispatcher and handlers against the SDK shim, so the suite
//!   exercises the firmware's own code with no emulator, no container and no
//!   device. This is the default, and `SIM_BIN` overrides the binary.
//! - a physical Ledger over USB HID, behind the `hid` feature — the
//!   counterpart of the optional `@ledgerhq/hw-transport-node-hid`
//!   dependency on the JavaScript side. `HW_DEVICE=1` puts it first, which
//!   is what `run-rs-device-tests.sh` sets.
//!
//! The simulator's protocol is one hex APDU per line on stdin, one hex
//! response (data followed by the two status bytes) per line on stdout. Its
//! own environment variables pass straight through to the child: `SIM_SEED`,
//! `SIM_REJECT`, `SIM_VERBOSE`, `SIM_RNG_SEED`.

use std::fmt;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

use crate::hex::{buf2hex, hex2buf};

/// A non-9000 status word, or a transport failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApduError {
    /// Label passed to [`exchange`], as in the JavaScript `[label] SW=...`.
    pub label: String,
    /// The four hex digits of the status word, or `"????"` on a transport error.
    pub sw: String,
    /// Full message.
    pub message: String,
}

impl fmt::Display for ApduError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for ApduError {}

/// An open connection to the device.
pub enum Transport {
    /// The `sim/` binary, driven over stdin/stdout.
    Sim(SimTransport),
    /// A physical Ledger over USB HID.
    #[cfg(feature = "hid")]
    Hid(hid::HidTransport),
}

impl Transport {
    /// Sends one APDU and returns the raw response, status word included.
    pub fn exchange_raw(&mut self, apdu: &[u8]) -> std::io::Result<Vec<u8>> {
        match self {
            Transport::Sim(s) => s.exchange(apdu),
            #[cfg(feature = "hid")]
            Transport::Hid(h) => h.exchange(apdu),
        }
    }
}

/// The simulator child process and its pipes.
pub struct SimTransport {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
    /// Path of the binary, for error messages.
    pub binary: PathBuf,
}

impl SimTransport {
    /// Sends one APDU and reads the reply line.
    pub fn exchange(&mut self, apdu: &[u8]) -> std::io::Result<Vec<u8>> {
        writeln!(self.stdin, "{}", buf2hex(apdu))?;
        self.stdin.flush()?;
        let mut line = String::new();
        let n = self.stdout.read_line(&mut line)?;
        if n == 0 {
            return Err(std::io::Error::other(format!(
                "{} closed its output",
                self.binary.display()
            )));
        }
        let line = line.trim();
        if line.len() % 2 != 0 || !line.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(std::io::Error::other(format!(
                "{} answered something that is not hex: {line:?}",
                self.binary.display()
            )));
        }
        Ok(hex2buf(line))
    }
}

impl Drop for SimTransport {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Spawns a simulator binary.
pub fn spawn_sim(binary: impl AsRef<Path>) -> Result<Transport, String> {
    spawn_sim_with_env(binary, &[])
}

/// Spawns a simulator binary with extra environment variables, for the
/// settings it only reads at startup — `SIM_REJECT`, `SIM_SEED`,
/// `SIM_RNG_SEED`.
pub fn spawn_sim_with_env(
    binary: impl AsRef<Path>,
    env: &[(&str, &str)],
) -> Result<Transport, String> {
    let binary = binary.as_ref().to_path_buf();
    let mut command = Command::new(&binary);
    for (k, v) in env {
        command.env(k, v);
    }
    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(|e| format!("{}: {e}", binary.display()))?;
    let stdin = child.stdin.take().expect("piped stdin");
    let stdout = BufReader::new(child.stdout.take().expect("piped stdout"));
    Ok(Transport::Sim(SimTransport {
        child,
        stdin,
        stdout,
        binary,
    }))
}

/// Where the simulator lands when built with `make MODE=debug` in `sim/`.
///
/// `MODE=debug` is what the suite needs: it compiles `BLIND_SIGN_NO_DISPLAY`
/// (0x02) and `SIGN_WITH_PRIVKEY` (0x50), and the FROST gate brings in the
/// DKG and FROST handlers.
pub fn default_sim_binary() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../sim/build/debug/apdu_sim")
}

/// True when `HW_DEVICE` asks for the physical device rather than the
/// simulator.
pub fn hw_device_requested() -> bool {
    std::env::var("HW_DEVICE").is_ok_and(|v| !v.is_empty() && v != "0")
}

/// Opens the physical Ledger, whatever else is available.
pub fn open_hid() -> Result<Transport, String> {
    #[cfg(feature = "hid")]
    {
        hid::open().map(Transport::Hid)
    }
    #[cfg(not(feature = "hid"))]
    Err("the `hid` feature is off; rebuild with --features hid".to_string())
}

/// `openTransport`.
pub fn open_transport() -> Result<Transport, String> {
    if hw_device_requested() {
        return open_hid();
    }
    if let Ok(path) = std::env::var("SIM_BIN") {
        return spawn_sim(path);
    }
    let default = default_sim_binary();
    if default.exists() {
        return spawn_sim(default);
    }
    #[cfg(feature = "hid")]
    {
        return hid::open().map(Transport::Hid);
    }
    #[cfg(not(feature = "hid"))]
    Err(format!(
        "no simulator at {} (build it with `cd sim && make MODE=debug`), \
         SIM_BIN unset, and the `hid` feature is off",
        default.display()
    ))
}

/// `exchange` — sends the APDU and fails on any status word other than 9000.
pub fn exchange(t: &mut Transport, apdu: &[u8], label: &str) -> Result<Vec<u8>, ApduError> {
    match t.exchange_raw(apdu) {
        Ok(resp) if resp.len() >= 2 => {
            let sw = buf2hex(&resp[resp.len() - 2..]);
            if sw != crate::apdu::SW_OK {
                return Err(ApduError {
                    label: label.to_string(),
                    message: format!("[{label}] SW={sw}"),
                    sw,
                });
            }
            Ok(resp[..resp.len() - 2].to_vec())
        }
        Ok(_) => Err(ApduError {
            label: label.to_string(),
            sw: "????".into(),
            message: format!("[{label}] short response"),
        }),
        Err(e) => Err(ApduError {
            label: label.to_string(),
            sw: "????".into(),
            message: format!("[{label}] transport error: {e}"),
        }),
    }
}

/// The `tryExchange` of `frost-hw.test.js`: the status word instead of a throw.
pub fn try_exchange(t: &mut Transport, apdu: &[u8], label: &str) -> Result<Vec<u8>, String> {
    exchange(t, apdu, label).map_err(|e| e.sw)
}

#[cfg(feature = "hid")]
pub mod hid {
    //! Ledger's HID framing: 64-byte packets of
    //! `channel(2 BE) || 0x05 || seq(2 BE) || [len(2 BE) on seq 0] || payload`.

    const CHANNEL: u16 = 0x0101;
    const TAG: u8 = 0x05;
    const PACKET: usize = 64;
    const LEDGER_VID: u16 = 0x2c97;

    /// An open USB HID connection.
    pub struct HidTransport {
        device: hidapi::HidDevice,
    }

    /// Opens the first Ledger found.
    pub fn open() -> Result<HidTransport, String> {
        let api = hidapi::HidApi::new().map_err(|e| format!("hidapi: {e}"))?;
        let info = api
            .device_list()
            .find(|d| d.vendor_id() == LEDGER_VID && d.usage_page() == 0xffa0)
            .or_else(|| api.device_list().find(|d| d.vendor_id() == LEDGER_VID))
            .ok_or_else(|| "No Ledger device found".to_string())?;
        let device = info
            .open_device(&api)
            .map_err(|e| format!("hidapi open: {e}"))?;
        Ok(HidTransport { device })
    }

    impl HidTransport {
        /// Sends one APDU and reads the reply.
        pub fn exchange(&mut self, apdu: &[u8]) -> std::io::Result<Vec<u8>> {
            let mut payload = (apdu.len() as u16).to_be_bytes().to_vec();
            payload.extend_from_slice(apdu);
            for (seq, chunk) in payload
                .chunks(PACKET - 5)
                .enumerate()
                .map(|(i, c)| (i as u16, c))
            {
                let mut pkt = Vec::with_capacity(PACKET + 1);
                pkt.push(0x00); // hidapi report id
                pkt.extend_from_slice(&CHANNEL.to_be_bytes());
                pkt.push(TAG);
                pkt.extend_from_slice(&seq.to_be_bytes());
                pkt.extend_from_slice(chunk);
                pkt.resize(PACKET + 1, 0);
                self.device
                    .write(&pkt)
                    .map_err(|e| std::io::Error::other(e.to_string()))?;
            }

            let mut out: Vec<u8> = Vec::new();
            let mut expected = 0usize;
            let mut seq = 0u16;
            loop {
                let mut buf = [0u8; PACKET];
                let n = self
                    .device
                    .read_timeout(&mut buf, 60_000)
                    .map_err(|e| std::io::Error::other(e.to_string()))?;
                if n == 0 {
                    return Err(std::io::Error::other("HID read timed out"));
                }
                if buf[0..2] != CHANNEL.to_be_bytes() || buf[2] != TAG {
                    continue;
                }
                let got_seq = u16::from_be_bytes([buf[3], buf[4]]);
                if got_seq != seq {
                    return Err(std::io::Error::other("HID sequence out of order"));
                }
                let body = if seq == 0 {
                    expected = u16::from_be_bytes([buf[5], buf[6]]) as usize;
                    &buf[7..n]
                } else {
                    &buf[5..n]
                };
                out.extend_from_slice(body);
                if out.len() >= expected {
                    out.truncate(expected);
                    return Ok(out);
                }
                seq += 1;
            }
        }
    }
}
