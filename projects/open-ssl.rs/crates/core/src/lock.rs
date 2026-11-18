//! 项目级签发锁：同一 `projectRoot` 在同一时刻只允许一个签发流程。
//!
//! 锁文件位于 `state_dir()/issue.lock`，用 `create_new` 独占创建，内容记录持有者 pid 与取得时间。
//! 进程异常退出会留下锁文件，此时 [`holder`] 仍可读出持有者信息，由上层决定是否人工清理；
//! 本模块**不自动**删除无法确认已失效的锁。

use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

use crate::{
    dns::credentials::ProjectRoot,
    errors::{Error, ErrorCode, Result},
};

/// 锁文件里记录的持有者信息。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LockHolder {
    /// 取得锁的进程 id。
    pub pid: u32,
    /// 取得锁的 Unix 秒时间戳。
    pub acquired_unix: u64,
}

/// 一次持有的项目锁。离开作用域时尽力删除锁文件。
#[derive(Debug)]
pub struct ProjectLock {
    path: PathBuf,
    released: bool,
}

impl ProjectLock {
    /// 取得项目锁；已被占用时返回 [`ErrorCode::Denied`]。
    pub fn acquire(project: &ProjectRoot) -> Result<Self> {
        let path = lock_path(project);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .map_err(|error| Error::new(ErrorCode::Io, format!("无法创建状态目录 `{}`: {error}", parent.display())))?;
        }
        let mut file = match OpenOptions::new().write(true).create_new(true).open(&path) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                let detail = match holder(project)? {
                    Some(holder) => format!("项目锁已被 pid {} 于 {} 取得", holder.pid, holder.acquired_unix),
                    None => "项目锁已被占用，但锁文件内容无法解析".to_owned(),
                };
                return Err(Error::new(ErrorCode::Denied, detail));
            }
            Err(error) => return Err(Error::new(ErrorCode::Io, format!("无法创建锁文件 `{}`: {error}", path.display()))),
        };
        let acquired_unix = now_unix();
        let payload = format!("pid={}\nacquired_unix={acquired_unix}\n", std::process::id());
        file.write_all(payload.as_bytes())
            .map_err(|error| Error::new(ErrorCode::Io, format!("无法写入锁文件 `{}`: {error}", path.display())))?;
        file.sync_all().map_err(|error| Error::new(ErrorCode::Io, format!("无法落盘锁文件 `{}`: {error}", path.display())))?;
        drop(file);
        Ok(Self { path, released: false })
    }

    /// 显式释放锁；之后的 `Drop` 不会重复删除。
    pub fn release(mut self) -> Result<()> {
        self.remove()
    }

    /// 锁文件路径，供诊断使用。
    pub fn path(&self) -> &std::path::Path {
        &self.path
    }

    fn remove(&mut self) -> Result<()> {
        if self.released {
            return Ok(());
        }
        match fs::remove_file(&self.path) {
            Ok(()) => {
                self.released = true;
                Ok(())
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                self.released = true;
                Ok(())
            }
            Err(error) => Err(Error::new(ErrorCode::Io, format!("无法删除锁文件 `{}`: {error}", self.path.display()))),
        }
    }
}

impl Drop for ProjectLock {
    fn drop(&mut self) {
        let _ = self.remove();
    }
}

/// 读取当前锁的持有者信息；未加锁返回 `Ok(None)`，锁文件存在但内容损坏时返回 `None` 之外由调用方判断。
///
/// 内容无法解析时不猜测持有者，直接返回 `Ok(None)`，避免把损坏文件误报成活跃锁。
pub fn holder(project: &ProjectRoot) -> Result<Option<LockHolder>> {
    let path = lock_path(project);
    let text = match fs::read_to_string(&path) {
        Ok(text) => text,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(Error::new(ErrorCode::Io, format!("无法读取锁文件 `{}`: {error}", path.display()))),
    };
    let mut pid = None;
    let mut acquired_unix = None;
    for line in text.lines() {
        if let Some(value) = line.strip_prefix("pid=") {
            pid = value.trim().parse::<u32>().ok();
        }
        else if let Some(value) = line.strip_prefix("acquired_unix=") {
            acquired_unix = value.trim().parse::<u64>().ok();
        }
    }
    Ok(match (pid, acquired_unix) {
        (Some(pid), Some(acquired_unix)) => Some(LockHolder { pid, acquired_unix }),
        _ => None,
    })
}

fn lock_path(project: &ProjectRoot) -> PathBuf {
    project.state_dir().join("issue.lock")
}

fn now_unix() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|elapsed| elapsed.as_secs()).unwrap_or_default()
}
