//! 运行期记录：签发热路径的高频耗时与卡点事件常开聚合。
//!
//! 机制核心来自 `boost-harness` 的 `hotspot`——与 `database-harness` 建模的
//! `runtime` 同一底座：默认开启，单次埋点只付一次时钟差值加一次短锁持有，
//! 键数与事件数有界，产品行为与输出完全不变。
//!
//! 键词表有界：`acme.http.directory`、`acme.http.nonce`、`acme.http.post`、
//! `acme.jws.sign`、`acme.order.poll`、`acme.order.wait`、`acme.issue`、
//! `dns.cloudflare`、`delivery.stage`、`delivery.commit`。卡点事件登记明确
//! 原因（`badNonce`、`poll-timeout`）。
//!
//! 工程师调优时设置环境变量 `OPEN_SSL_PERF=1` 再运行 `open-ssl acme-issue`，
//! 流程收尾会向 stderr 打印热点表与卡点事件；未设置时记录仍然发生，但没有任何
//! 输出，产品默认运行路径不因本模块产生任何可见变化。

use std::{sync::LazyLock, time::Instant};

use boost_harness::hotspot::Hotspot;

/// 进程级记录器，常开。
pub static SPOTS: LazyLock<Hotspot> = LazyLock::new(Hotspot::new);

/// 在 `key` 下记录 `started` 至今的墙钟耗时。
pub fn record(key: &str, started: Instant) {
    SPOTS.record(key, started.elapsed());
}

/// 执行 `body` 并把墙钟耗时记在 `key` 下。
pub fn time<T>(key: &str, body: impl FnOnce() -> T) -> T {
    SPOTS.time(key, body)
}

/// 登记一条卡点事件（`cause` 来自有界词表）。
pub fn stall(key: &str, cause: &str, detail: impl Into<String>) {
    SPOTS.stall(key, cause, detail);
}

/// `OPEN_SSL_PERF=1` 时把当前快照渲染成调优表打到 stderr。
///
/// 只在签发流程收尾处调用；记录本身常开，输出由环境变量门控。
pub fn maybe_report_stderr() {
    if std::env::var("OPEN_SSL_PERF").map(|value| value != "1").unwrap_or(true) {
        return;
    }
    use std::io::Write;
    let snapshot = SPOTS.snapshot();
    let mut out: Vec<u8> = Vec::new();
    let _ = writeln!(out, "open-ssl runtime profile (uptime {} ms)", snapshot.uptime_ms);
    let _ = writeln!(out, "{:<22}{:>7}{:>10}{:>9}{:>9}{:>9}", "key", "hits", "totalMs", "avgMs", "p95Ms", "maxMs");
    for row in &snapshot.rows {
        let _ = writeln!(out, "{:<22}{:>7}{:>10.1}{:>9.1}{:>9.1}{:>9.1}", row.key, row.hits, ms(row.total_ns), ms(row.avg_ns), ms(row.p95_ns), ms(row.max_ns));
    }
    if !snapshot.stalls.is_empty() {
        let _ = writeln!(out, "stalls:");
        for event in &snapshot.stalls {
            let _ = writeln!(out, "  #{} {} {} — {} ({} ms)", event.seq, event.key, event.cause, event.detail, ms(event.elapsed_ns.unwrap_or(0)));
        }
    }
    if snapshot.dropped_stalls > 0 {
        let _ = writeln!(out, "  (dropped {} older stall events)", snapshot.dropped_stalls);
    }
    let _ = std::io::stderr().write_all(&out);
}

fn ms(ns: u64) -> f64 {
    ns as f64 / 1_000_000.0
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn issuance_hot_path_keys_aggregate() {
        time("test.acme.http.post", || std::thread::sleep(Duration::from_millis(2)));
        record("test.acme.http.post", Instant::now());
        stall("test.acme.http.post", "badNonce", "retried with a fresh nonce");
        let snapshot = SPOTS.snapshot();
        let row = snapshot.rows.iter().find(|row| row.key == "test.acme.http.post").expect("row");
        assert_eq!(row.hits, 2);
        assert!(row.total_ns >= 2_000_000, "一次真实 sleep 加一次近零记录: {row:?}");
        assert!(snapshot.stalls.iter().any(|event| event.cause == "badNonce"));
    }
}
