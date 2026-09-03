// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

use std::{
    collections::{BTreeMap, VecDeque},
    ffi::{OsStr, OsString},
    io::{BufRead, BufReader, Read, Write},
    net::{Shutdown, TcpListener, TcpStream},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{
        atomic::{AtomicBool, AtomicI64, Ordering},
        Arc, Mutex, MutexGuard,
    },
    thread,
    time::{Duration, Instant},
};

use chrono::{TimeZone, Utc};
use tempfile::TempDir;

use crate::gateway::clock::Clock;

pub(crate) struct CliHarness {
    home: TempDir,
    config: PathBuf,
    cache: PathBuf,
    data: PathBuf,
    work: PathBuf,
    credential_paths: Mutex<Vec<PathBuf>>,
}

pub(crate) struct CliOutput {
    pub status: i32,
    pub stdout: String,
    pub stderr: String,
}

struct TrackedChild(Option<Child>);

impl TrackedChild {
    fn wait_with_output(mut self) -> std::io::Result<std::process::Output> {
        self.0.take().expect("tracked child").wait_with_output()
    }
}

pub(crate) struct CliChild(Option<Child>);

impl CliChild {
    pub fn terminate(mut self) -> CliOutput {
        let mut child = self.0.take().expect("tracked CLI child");
        child.kill().expect("terminate CLI child");
        let output = child.wait_with_output().expect("wait for CLI child");
        CliOutput {
            status: output.status.code().unwrap_or(128),
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        }
    }

    #[cfg(unix)]
    pub fn interrupt(mut self) -> CliOutput {
        let child = self.0.as_mut().expect("tracked CLI child");
        let pid = child.id();
        #[allow(unsafe_code)]
        let result = unsafe { libc::kill(pid as i32, libc::SIGINT) };
        assert_eq!(result, 0, "interrupt CLI child");
        let output = self
            .0
            .take()
            .expect("tracked CLI child")
            .wait_with_output()
            .expect("wait for interrupted CLI child");
        CliOutput {
            status: output.status.code().unwrap_or(128),
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        }
    }
}

impl Drop for CliChild {
    fn drop(&mut self) {
        if let Some(mut child) = self.0.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

impl Drop for TrackedChild {
    fn drop(&mut self) {
        if let Some(mut child) = self.0.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

impl CliHarness {
    pub fn isolated() -> Self {
        let home = tempfile::tempdir().expect("isolated CLI home");
        let config = home.path().join("config");
        let cache = home.path().join("cache");
        let data = home.path().join("data");
        let work = home.path().join("work");
        for directory in [&config, &cache, &data, &work] {
            std::fs::create_dir_all(directory).expect("create isolated CLI directory");
        }
        Self {
            home,
            config,
            cache,
            data,
            work,
            credential_paths: Mutex::new(Vec::new()),
        }
    }

    pub fn root(&self) -> &Path {
        self.home.path()
    }

    pub fn config_dir(&self) -> &Path {
        &self.config
    }

    pub fn cache_dir(&self) -> &Path {
        &self.cache
    }

    pub fn data_dir(&self) -> &Path {
        &self.data
    }

    pub fn work_dir(&self) -> &Path {
        &self.work
    }

    pub fn track_temporary_credential(&self, path: impl Into<PathBuf>) {
        self.credential_paths
            .lock()
            .expect("credential tracker")
            .push(path.into());
    }

    pub fn assert_clean(&self) {
        let leaked = self
            .credential_paths
            .lock()
            .expect("credential tracker")
            .iter()
            .filter(|path| path.exists())
            .cloned()
            .collect::<Vec<_>>();
        assert!(
            leaked.is_empty(),
            "temporary credentials remain: {leaked:?}"
        );
    }

    pub fn run<I, S>(&self, binary: &Path, args: I) -> CliOutput
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        self.run_with_stdin_and_env(binary, args, &[], std::iter::empty::<(&str, &str)>())
    }

    pub fn run_with_env<I, S, E, K, V>(&self, binary: &Path, args: I, env: E) -> CliOutput
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
        E: IntoIterator<Item = (K, V)>,
        K: AsRef<OsStr>,
        V: AsRef<OsStr>,
    {
        self.run_with_stdin_and_env(binary, args, &[], env)
    }

    pub fn run_with_stdin_and_env<I, S, E, K, V>(
        &self,
        binary: &Path,
        args: I,
        stdin: &[u8],
        env: E,
    ) -> CliOutput
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
        E: IntoIterator<Item = (K, V)>,
        K: AsRef<OsStr>,
        V: AsRef<OsStr>,
    {
        let mut child = Command::new(binary)
            .args(args)
            .current_dir(&self.work)
            .env_clear()
            .env("HOME", self.home.path())
            .env("XDG_CONFIG_HOME", &self.config)
            .env("XDG_CACHE_HOME", &self.cache)
            .env("XDG_DATA_HOME", &self.data)
            .env("LANG", "C.UTF-8")
            .env("TZ", "UTC")
            .env("NO_COLOR", "1")
            .env("VERDICTAN_TELEMETRY_DISABLED", "true")
            .envs(env)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("run isolated Verdictan CLI");
        child
            .stdin
            .take()
            .expect("child standard input")
            .write_all(stdin)
            .expect("write child standard input");
        let output = TrackedChild(Some(child))
            .wait_with_output()
            .expect("wait for isolated Verdictan CLI");
        CliOutput {
            status: output.status.code().unwrap_or(128),
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        }
    }

    pub fn spawn_with_env<I, S, E, K, V>(&self, binary: &Path, args: I, env: E) -> CliChild
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
        E: IntoIterator<Item = (K, V)>,
        K: AsRef<OsStr>,
        V: AsRef<OsStr>,
    {
        let child = Command::new(binary)
            .args(args)
            .current_dir(&self.work)
            .env_clear()
            .env("HOME", self.home.path())
            .env("XDG_CONFIG_HOME", &self.config)
            .env("XDG_CACHE_HOME", &self.cache)
            .env("XDG_DATA_HOME", &self.data)
            .env("LANG", "C.UTF-8")
            .env("TZ", "UTC")
            .env("NO_COLOR", "1")
            .env("VERDICTAN_TELEMETRY_DISABLED", "true")
            .envs(env)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn isolated Verdictan CLI");
        CliChild(Some(child))
    }

    pub fn assert_secret_absent(&self, output: &CliOutput, secret: &str) {
        assert!(
            !output.stdout.contains(secret),
            "secret leaked to standard output"
        );
        assert!(
            !output.stderr.contains(secret),
            "secret leaked to standard error"
        );
    }

    #[cfg(unix)]
    pub fn write_executable(&self, name: &str, body: &str) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;

        let bin_dir = self.work.join("bin");
        std::fs::create_dir_all(&bin_dir).expect("create isolated executable directory");
        let path = bin_dir.join(name);
        std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).expect("write isolated executable");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))
            .expect("make isolated executable runnable");
        path
    }
}

pub(crate) fn reserve_loopback_addr() -> std::net::SocketAddr {
    TcpListener::bind("127.0.0.1:0")
        .expect("reserve loopback address")
        .local_addr()
        .expect("reserved loopback address")
}

pub(crate) fn wait_for_listener(addr: std::net::SocketAddr, timeout: Duration) {
    let deadline = Instant::now() + timeout;
    loop {
        if TcpStream::connect(addr).is_ok() {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "listener {addr} did not become ready"
        );
        thread::sleep(Duration::from_millis(10));
    }
}

pub(crate) struct ScopedEnv {
    key: OsString,
    original: Option<OsString>,
    _lock: MutexGuard<'static, ()>,
}

impl ScopedEnv {
    pub fn set(key: impl Into<OsString>, value: impl AsRef<OsStr>) -> Self {
        let key = key.into();
        let lock = crate::test_support::env_lock()
            .lock()
            .expect("environment lock");
        let original = std::env::var_os(&key);
        std::env::set_var(&key, value);
        Self {
            key,
            original,
            _lock: lock,
        }
    }
}

impl Drop for ScopedEnv {
    fn drop(&mut self) {
        match &self.original {
            Some(value) => std::env::set_var(&self.key, value),
            None => std::env::remove_var(&self.key),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RecordedRequest {
    pub method: String,
    pub path_and_query: String,
    pub headers: BTreeMap<String, String>,
    pub body: Vec<u8>,
}

#[derive(Debug, Clone)]
pub(crate) enum ScriptedResponse {
    Reply {
        status: u16,
        content_type: &'static str,
        headers: Vec<(String, String)>,
        body: Vec<u8>,
    },
    Disconnect,
    Hold(Duration),
}

impl ScriptedResponse {
    pub fn json(status: u16, body: impl Into<Vec<u8>>) -> Self {
        Self::Reply {
            status,
            content_type: "application/json",
            headers: Vec::new(),
            body: body.into(),
        }
    }

    pub fn with_content_type(
        status: u16,
        content_type: &'static str,
        body: impl Into<Vec<u8>>,
    ) -> Self {
        Self::Reply {
            status,
            content_type,
            headers: Vec::new(),
            body: body.into(),
        }
    }

    pub fn with_header(mut self, name: &str, value: impl Into<String>) -> Self {
        if let Self::Reply { headers, .. } = &mut self {
            headers.push((name.to_owned(), value.into()));
        }
        self
    }
}

pub(crate) struct MockControlPlane {
    addr: std::net::SocketAddr,
    requests: Arc<Mutex<Vec<RecordedRequest>>>,
    stopping: Arc<AtomicBool>,
    thread: Option<thread::JoinHandle<()>>,
}

impl MockControlPlane {
    pub fn start(script: impl IntoIterator<Item = ScriptedResponse>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock control plane");
        let addr = listener.local_addr().expect("mock control-plane address");
        let requests = Arc::new(Mutex::new(Vec::new()));
        let stopping = Arc::new(AtomicBool::new(false));
        let thread_requests = Arc::clone(&requests);
        let thread_stopping = Arc::clone(&stopping);
        let mut script = script.into_iter().collect::<VecDeque<_>>();
        let thread = thread::Builder::new()
            .name("cli-e2e-control-plane".to_owned())
            .spawn(move || loop {
                let Ok((stream, _)) = listener.accept() else {
                    break;
                };
                if thread_stopping.load(Ordering::SeqCst) {
                    break;
                }
                let request = read_request(&stream).expect("read mock HTTP request");
                thread_requests
                    .lock()
                    .expect("request recorder")
                    .push(request);
                let Some(response) = script.pop_front() else {
                    let _ = stream.shutdown(Shutdown::Both);
                    continue;
                };
                write_response(stream, response).expect("write mock HTTP response");
            })
            .expect("start mock control-plane thread");
        Self {
            addr,
            requests,
            stopping,
            thread: Some(thread),
        }
    }

    pub fn start_handler<F>(handler: F) -> Self
    where
        F: Fn(&RecordedRequest) -> ScriptedResponse + Send + 'static,
    {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock control plane");
        let addr = listener.local_addr().expect("mock control-plane address");
        let requests = Arc::new(Mutex::new(Vec::new()));
        let stopping = Arc::new(AtomicBool::new(false));
        let thread_requests = Arc::clone(&requests);
        let thread_stopping = Arc::clone(&stopping);
        let thread = thread::Builder::new()
            .name("cli-e2e-control-plane-handler".to_owned())
            .spawn(move || loop {
                let Ok((stream, _)) = listener.accept() else {
                    break;
                };
                if thread_stopping.load(Ordering::SeqCst) {
                    break;
                }
                let request = read_request(&stream).expect("read mock HTTP request");
                let response = handler(&request);
                thread_requests
                    .lock()
                    .expect("request recorder")
                    .push(request);
                let _ = write_response(stream, response);
            })
            .expect("start mock control-plane handler thread");
        Self {
            addr,
            requests,
            stopping,
            thread: Some(thread),
        }
    }

    pub fn url(&self) -> String {
        format!("http://{}", self.addr)
    }

    pub fn requests(&self) -> Vec<RecordedRequest> {
        self.requests.lock().expect("request recorder").clone()
    }
}

impl Drop for MockControlPlane {
    fn drop(&mut self) {
        self.stopping.store(true, Ordering::SeqCst);
        let _ = TcpStream::connect(self.addr);
        if let Some(thread) = self.thread.take() {
            thread.join().expect("stop mock control-plane thread");
        }
    }
}

fn read_request(stream: &TcpStream) -> std::io::Result<RecordedRequest> {
    let mut reader = BufReader::new(stream);
    let mut request_line = String::new();
    reader.read_line(&mut request_line)?;
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or_default().to_owned();
    let path_and_query = parts.next().unwrap_or_default().to_owned();
    let mut headers = BTreeMap::new();
    loop {
        let mut line = String::new();
        reader.read_line(&mut line)?;
        if line == "\r\n" || line.is_empty() {
            break;
        }
        if let Some((name, value)) = line.split_once(':') {
            headers.insert(name.to_ascii_lowercase(), value.trim().to_owned());
        }
    }
    let content_length = headers
        .get("content-length")
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(0);
    let mut body = vec![0; content_length];
    reader.read_exact(&mut body)?;
    Ok(RecordedRequest {
        method,
        path_and_query,
        headers,
        body,
    })
}

fn write_response(mut stream: TcpStream, response: ScriptedResponse) -> std::io::Result<()> {
    match response {
        ScriptedResponse::Reply {
            status,
            content_type,
            headers,
            body,
        } => {
            let reason = match status {
                200 => "OK",
                302 => "Found",
                400 => "Bad Request",
                401 => "Unauthorized",
                403 => "Forbidden",
                404 => "Not Found",
                409 => "Conflict",
                422 => "Unprocessable Entity",
                429 => "Too Many Requests",
                _ => "Internal Server Error",
            };
            write!(
                stream,
                "HTTP/1.1 {status} {reason}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n",
                body.len()
            )?;
            for (name, value) in headers {
                write!(stream, "{name}: {value}\r\n")?;
            }
            write!(stream, "\r\n")?;
            stream.write_all(&body)?;
            stream.flush()
        }
        ScriptedResponse::Disconnect => shutdown_after_client(&stream),
        ScriptedResponse::Hold(duration) => {
            thread::sleep(duration);
            shutdown_after_client(&stream)
        }
    }
}

fn shutdown_after_client(stream: &TcpStream) -> std::io::Result<()> {
    match stream.shutdown(Shutdown::Both) {
        Ok(()) => Ok(()),
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::NotConnected
                    | std::io::ErrorKind::BrokenPipe
                    | std::io::ErrorKind::ConnectionAborted
                    | std::io::ErrorKind::ConnectionReset
            ) =>
        {
            Ok(())
        }
        Err(error) => Err(error),
    }
}

#[derive(Debug)]
pub(crate) struct InjectedClock(AtomicI64);

impl InjectedClock {
    pub fn at_unix_seconds(value: i64) -> Self {
        Self(AtomicI64::new(value))
    }

    pub fn advance_seconds(&self, seconds: i64) {
        self.0.fetch_add(seconds, Ordering::SeqCst);
    }
}

impl Clock for InjectedClock {
    fn now(&self) -> chrono::DateTime<Utc> {
        Utc.timestamp_opt(self.0.load(Ordering::SeqCst), 0)
            .single()
            .expect("injected timestamp")
    }
}

pub(crate) fn parse_json_output(output: &str) -> serde_json::Value {
    serde_json::from_str(output).expect("valid JSON CLI output")
}

pub(crate) fn parse_table_output(output: &str) -> Vec<Vec<String>> {
    output
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| line.split_whitespace().map(str::to_owned).collect())
        .collect()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PlatformCapability {
    Linux,
    MacOs,
    Windows,
    Other,
}

pub(crate) fn platform_capability() -> PlatformCapability {
    if cfg!(target_os = "linux") {
        PlatformCapability::Linux
    } else if cfg!(target_os = "macos") {
        PlatformCapability::MacOs
    } else if cfg!(target_os = "windows") {
        PlatformCapability::Windows
    } else {
        PlatformCapability::Other
    }
}
