#[cfg(target_os = "linux")]
pub mod linux;

#[cfg(any(target_os = "freebsd", target_os = "openbsd", target_os = "netbsd"))]
pub mod bsd;

#[cfg(windows)]
pub mod windows;

/// Portable process information struct used across scan layers.
#[derive(Debug, Clone)]
pub struct ProcessInfo {
    /// Process ID.
    pub pid: u32,
    /// Process name (basename of executable, from /proc/PID/comm).
    pub name: String,
    /// Full path to the executable, if available.
    pub exe_path: Option<String>,
    /// True if the executable has been deleted from disk since the process started.
    pub deleted_exe: bool,
    /// Thread count from /proc/PID/status Threads: field.
    pub thread_count: u32,
}

/// A parsed TCP connection from /proc/net/tcp.
#[derive(Debug, Clone)]
pub struct TcpConnection {
    pub local_addr: std::net::Ipv4Addr,
    pub local_port: u16,
    pub remote_addr: std::net::Ipv4Addr,
    pub remote_port: u16,
    /// TCP state as hex string (e.g. "01" = ESTABLISHED).
    pub state: String,
    pub inode: u64,
}
