use std::env;
use std::num::NonZeroU32;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};

use tempfile::TempDir;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct UpIntervalSecs(pub NonZeroU32);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DownIntervalSecs(pub NonZeroU32);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct BackingMegabytes(pub u32);

const fn nz(n: u32) -> NonZeroU32 {
    match NonZeroU32::new(n) {
        Some(v) => v,
        None => panic!("zero interval not permitted"),
    }
}

#[derive(Debug, Clone, Copy)]
pub struct FlakyConfig {
    pub up_interval: UpIntervalSecs,
    pub down_interval: DownIntervalSecs,
    pub backing_mb: BackingMegabytes,
}

impl FlakyConfig {
    pub const fn default_stress() -> Self {
        Self {
            up_interval: UpIntervalSecs(nz(8)),
            down_interval: DownIntervalSecs(nz(2)),
            backing_mb: BackingMegabytes(256),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum FlakyError {
    #[error("not running as root, EUID != 0")]
    NotRoot,
    #[error("tool missing: {0}")]
    ToolMissing(&'static str),
    #[error("kernel target dm-flakey unavailable: {0}")]
    DmFlakeyMissing(String),
    #[error("{tool} failed: status={status}, stderr={stderr}")]
    CommandFailed {
        tool: &'static str,
        status: String,
        stderr: String,
    },
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

impl FlakyError {
    pub const fn is_env_absent(&self) -> bool {
        matches!(
            self,
            Self::NotRoot | Self::ToolMissing(_) | Self::DmFlakeyMissing(_)
        )
    }
}

static MOUNT_COUNTER: AtomicU64 = AtomicU64::new(0);

pub struct FlakyMount {
    mount_point: TempDir,
    mapper_name: String,
    mapper_path: PathBuf,
    loop_device: PathBuf,
    backing_file: PathBuf,
    _backing_tempdir: TempDir,
}

impl FlakyMount {
    pub fn try_new(cfg: &FlakyConfig) -> Result<Self, FlakyError> {
        ensure_root()?;
        ["losetup", "dmsetup", "mkfs.ext4", "mount", "umount"]
            .iter()
            .copied()
            .try_for_each(ensure_tool)?;
        probe_dm_flakey()?;
        let _ = reap_stale_mounts();

        let backing_dir = TempDir::new()?;
        let backing_file = backing_dir.path().join("backing.img");
        allocate_backing(&backing_file, cfg.backing_mb)?;

        let loop_device = attach_loop(&backing_file)?;
        let sectors = sector_count(&loop_device)?;

        if let Err(e) = mkfs_ext4(&loop_device) {
            let _ = detach_loop(&loop_device);
            return Err(e);
        }

        let mapper_name = format!(
            "tranquil-flaky-{}-{}",
            std::process::id(),
            MOUNT_COUNTER.fetch_add(1, Ordering::Relaxed),
        );
        match dm_create(
            &mapper_name,
            &loop_device,
            sectors,
            cfg.up_interval,
            cfg.down_interval,
        ) {
            Ok(()) => {}
            Err(e) => {
                let _ = detach_loop(&loop_device);
                return Err(e);
            }
        }
        let mapper_path = PathBuf::from(format!("/dev/mapper/{mapper_name}"));

        let mount_point = TempDir::new()?;
        if let Err(e) = mount_ext4(&mapper_path, mount_point.path()) {
            let _ = dm_remove(&mapper_name);
            let _ = detach_loop(&loop_device);
            return Err(e);
        }

        Ok(Self {
            mount_point,
            mapper_name,
            mapper_path,
            loop_device,
            backing_file,
            _backing_tempdir: backing_dir,
        })
    }

    pub fn path(&self) -> &Path {
        self.mount_point.path()
    }

    pub fn mapper_name(&self) -> &str {
        &self.mapper_name
    }

    pub fn mapper_path(&self) -> &Path {
        &self.mapper_path
    }

    pub fn loop_device(&self) -> &Path {
        &self.loop_device
    }

    pub fn backing_file(&self) -> &Path {
        &self.backing_file
    }
}

impl Drop for FlakyMount {
    fn drop(&mut self) {
        if let Err(e) = umount(self.mount_point.path()) {
            tracing::warn!(
                mount = %self.mount_point.path().display(),
                error = %e,
                "flaky umount failed, trying lazy unmount",
            );
            if let Err(e2) = umount_lazy(self.mount_point.path()) {
                tracing::warn!(
                    mount = %self.mount_point.path().display(),
                    error = %e2,
                    "flaky lazy unmount also failed, device may leak",
                );
            }
        }
        if let Err(e) = dm_remove(&self.mapper_name) {
            tracing::warn!(
                name = %self.mapper_name,
                error = %e,
                "flaky dm remove failed, mapper device may leak",
            );
        }
        if let Err(e) = detach_loop(&self.loop_device) {
            tracing::warn!(
                device = %self.loop_device.display(),
                error = %e,
                "flaky loop detach failed, loop device may leak",
            );
        }
    }
}

#[cfg(unix)]
fn ensure_root() -> Result<(), FlakyError> {
    if unsafe { libc::geteuid() } == 0 {
        Ok(())
    } else {
        Err(FlakyError::NotRoot)
    }
}

#[cfg(not(unix))]
fn ensure_root() -> Result<(), FlakyError> {
    Err(FlakyError::NotRoot)
}

fn ensure_tool(tool: &'static str) -> Result<(), FlakyError> {
    match find_in_path(tool) {
        Some(_) => Ok(()),
        None => Err(FlakyError::ToolMissing(tool)),
    }
}

fn find_in_path(tool: &str) -> Option<PathBuf> {
    let path = env::var_os("PATH")?;
    env::split_paths(&path).find_map(|dir| {
        let candidate = dir.join(tool);
        is_executable_file(&candidate).then_some(candidate)
    })
}

#[cfg(unix)]
fn is_executable_file(p: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(p)
        .map(|m| m.is_file() && (m.permissions().mode() & 0o111) != 0)
        .unwrap_or(false)
}

#[cfg(not(unix))]
fn is_executable_file(p: &Path) -> bool {
    p.is_file()
}

fn probe_dm_flakey() -> Result<(), FlakyError> {
    let out = Command::new("dmsetup").arg("targets").output()?;
    if !out.status.success() {
        return Err(FlakyError::DmFlakeyMissing(stringify_output(&out)));
    }
    let stdout = String::from_utf8_lossy(&out.stdout);
    if !stdout.lines().any(|l| l.starts_with("flakey")) {
        return Err(FlakyError::DmFlakeyMissing(stdout.into_owned()));
    }
    Ok(())
}

fn reap_stale_mounts() -> Result<(), FlakyError> {
    let out = Command::new("dmsetup")
        .arg("ls")
        .arg("--target")
        .arg("flakey")
        .output()?;
    if !out.status.success() {
        return Ok(());
    }
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter_map(parse_flaky_entry)
        .filter(|(_, pid)| !pid_alive(*pid))
        .for_each(|(name, _)| {
            let loop_device = mapper_backing_loop(&name);
            if let Err(e) = dm_remove(&name) {
                tracing::warn!(name, error = %e, "reap: dm_remove stale mapper failed");
                return;
            }
            if let Some(loop_dev) = loop_device
                && let Err(e) = detach_loop(&loop_dev)
            {
                tracing::warn!(
                    device = %loop_dev.display(),
                    error = %e,
                    "reap: detach_loop stale device failed",
                );
            }
        });
    Ok(())
}

fn parse_flaky_entry(line: &str) -> Option<(String, u32)> {
    let name = line.split_whitespace().next()?;
    let suffix = name.strip_prefix("tranquil-flaky-")?;
    let pid_str = suffix.split('-').next()?;
    let pid = pid_str.parse::<u32>().ok()?;
    Some((name.to_string(), pid))
}

fn pid_alive(pid: u32) -> bool {
    Path::new(&format!("/proc/{pid}")).exists()
}

fn mapper_backing_loop(name: &str) -> Option<PathBuf> {
    let out = Command::new("dmsetup")
        .arg("deps")
        .arg("-o")
        .arg("devname")
        .arg(name)
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&out.stdout);
    let inner = text.split('(').nth(1)?;
    let dev = inner.split(')').next()?.trim();
    if dev.is_empty() {
        None
    } else {
        Some(PathBuf::from(format!("/dev/{dev}")))
    }
}

fn allocate_backing(path: &Path, size: BackingMegabytes) -> Result<(), FlakyError> {
    let out = Command::new("truncate")
        .arg("-s")
        .arg(format!("{}M", size.0))
        .arg(path)
        .output()?;
    check_status("truncate", &out)
}

fn attach_loop(backing: &Path) -> Result<PathBuf, FlakyError> {
    let out = Command::new("losetup")
        .arg("--find")
        .arg("--show")
        .arg(backing)
        .output()?;
    check_status("losetup", &out)?;
    let raw = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if raw.is_empty() {
        return Err(FlakyError::CommandFailed {
            tool: "losetup",
            status: "exit 0".to_string(),
            stderr: "no device path on stdout".to_string(),
        });
    }
    Ok(PathBuf::from(raw))
}

fn detach_loop(device: &Path) -> Result<(), FlakyError> {
    let out = Command::new("losetup").arg("-d").arg(device).output()?;
    check_status("losetup -d", &out)
}

fn sector_count(device: &Path) -> Result<u64, FlakyError> {
    let out = Command::new("blockdev")
        .arg("--getsz")
        .arg(device)
        .output()?;
    check_status("blockdev", &out)?;
    let raw = String::from_utf8_lossy(&out.stdout).trim().to_string();
    raw.parse::<u64>().map_err(|_| FlakyError::CommandFailed {
        tool: "blockdev",
        status: "exit 0".to_string(),
        stderr: format!("could not parse sector count: {raw:?}"),
    })
}

fn dm_create(
    name: &str,
    loop_device: &Path,
    sectors: u64,
    up: UpIntervalSecs,
    down: DownIntervalSecs,
) -> Result<(), FlakyError> {
    let table = format!(
        "0 {sectors} flakey {} 0 {} {}",
        loop_device.display(),
        up.0.get(),
        down.0.get(),
    );
    let mut child = Command::new("dmsetup")
        .arg("create")
        .arg(name)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()?;
    if let Some(stdin) = child.stdin.as_mut() {
        use std::io::Write;
        stdin.write_all(table.as_bytes())?;
    }
    let out = child.wait_with_output()?;
    check_status("dmsetup create", &out)
}

fn dm_remove(name: &str) -> Result<(), FlakyError> {
    let out = Command::new("dmsetup")
        .arg("remove")
        .arg("--retry")
        .arg(name)
        .output()?;
    check_status("dmsetup remove", &out)
}

fn mkfs_ext4(device: &Path) -> Result<(), FlakyError> {
    let out = Command::new("mkfs.ext4")
        .arg("-q")
        .arg("-F")
        .arg(device)
        .output()?;
    check_status("mkfs.ext4", &out)
}

fn mount_ext4(device: &Path, target: &Path) -> Result<(), FlakyError> {
    let out = Command::new("mount")
        .arg("-t")
        .arg("ext4")
        .arg(device)
        .arg(target)
        .output()?;
    check_status("mount", &out)
}

fn umount(target: &Path) -> Result<(), FlakyError> {
    let out = Command::new("umount").arg(target).output()?;
    check_status("umount", &out)
}

fn umount_lazy(target: &Path) -> Result<(), FlakyError> {
    let out = Command::new("umount").arg("-l").arg(target).output()?;
    check_status("umount -l", &out)
}

fn check_status(tool: &'static str, out: &Output) -> Result<(), FlakyError> {
    if out.status.success() {
        Ok(())
    } else {
        Err(FlakyError::CommandFailed {
            tool,
            status: format!("{}", out.status),
            stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        })
    }
}

fn stringify_output(out: &Output) -> String {
    let mut s = String::new();
    if !out.stdout.is_empty() {
        s.push_str(&String::from_utf8_lossy(&out.stdout));
    }
    if !out.stderr.is_empty() {
        if !s.is_empty() {
            s.push('\n');
        }
        s.push_str(&String::from_utf8_lossy(&out.stderr));
    }
    s
}
