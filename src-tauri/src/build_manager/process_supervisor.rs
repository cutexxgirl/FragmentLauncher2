use std::{
    ffi::OsString,
    io::Read,
    path::Path,
    time::{Duration, Instant},
};

const CLEANUP_POLL: Duration = Duration::from_millis(10);

pub(super) struct ProcessSpec<'a> {
    pub(super) executable: &'a Path,
    pub(super) arguments: &'a [OsString],
    pub(super) cwd: &'a Path,
    pub(super) environment: &'a [(OsString, OsString)],
}

pub(super) struct ProcessPipes {
    pub(super) stdout: Box<dyn Read + Send>,
    pub(super) stderr: Box<dyn Read + Send>,
}

#[cfg(windows)]
mod platform {
    use super::*;
    use std::{
        ffi::{c_void, OsStr},
        fs::File,
        mem::{size_of, size_of_val},
        os::windows::{
            ffi::OsStrExt,
            io::{AsRawHandle, FromRawHandle, OwnedHandle},
        },
    };
    use windows::{
        core::{BOOL, PCWSTR, PWSTR},
        Win32::{
            Foundation::{
                SetHandleInformation, HANDLE, HANDLE_FLAGS, HANDLE_FLAG_INHERIT, WAIT_OBJECT_0,
                WAIT_TIMEOUT,
            },
            Security::SECURITY_ATTRIBUTES,
            System::{
                JobObjects::{
                    CreateJobObjectW, IsProcessInJob, JobObjectBasicAccountingInformation,
                    JobObjectExtendedLimitInformation, QueryInformationJobObject,
                    SetInformationJobObject, TerminateJobObject,
                    JOBOBJECT_BASIC_ACCOUNTING_INFORMATION, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
                    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
                },
                Pipes::CreatePipe,
                Threading::{
                    CreateProcessW, DeleteProcThreadAttributeList, GetExitCodeProcess,
                    InitializeProcThreadAttributeList, ResumeThread, TerminateProcess,
                    UpdateProcThreadAttribute, WaitForSingleObject, CREATE_NO_WINDOW,
                    CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT, EXTENDED_STARTUPINFO_PRESENT,
                    LPPROC_THREAD_ATTRIBUTE_LIST, PROCESS_INFORMATION,
                    PROC_THREAD_ATTRIBUTE_HANDLE_LIST, PROC_THREAD_ATTRIBUTE_JOB_LIST,
                    STARTF_USESTDHANDLES, STARTUPINFOEXW, STARTUPINFOW,
                },
            },
        },
    };

    struct Job {
        handle: OwnedHandle,
    }

    impl Job {
        fn new() -> Result<Self, String> {
            let raw = unsafe { CreateJobObjectW(None, PCWSTR::null()) }
                .map_err(|error| format!("Cannot create processor job: {error}"))?;
            let job = Self {
                handle: owned_handle(raw)?,
            };
            let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
            limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            unsafe {
                SetInformationJobObject(
                    job.raw(),
                    JobObjectExtendedLimitInformation,
                    (&limits as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast::<c_void>(),
                    size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
                )
            }
            .map_err(|error| format!("Cannot configure processor job: {error}"))?;
            Ok(job)
        }

        fn raw(&self) -> HANDLE {
            raw_handle(&self.handle)
        }

        fn terminate(&self) -> Result<(), String> {
            unsafe { TerminateJobObject(self.raw(), 1) }
                .map_err(|error| format!("Cannot terminate processor job: {error}"))
        }

        fn active_processes(&self) -> Result<u32, String> {
            let mut accounting = JOBOBJECT_BASIC_ACCOUNTING_INFORMATION::default();
            unsafe {
                QueryInformationJobObject(
                    Some(self.raw()),
                    JobObjectBasicAccountingInformation,
                    (&mut accounting as *mut JOBOBJECT_BASIC_ACCOUNTING_INFORMATION)
                        .cast::<c_void>(),
                    size_of::<JOBOBJECT_BASIC_ACCOUNTING_INFORMATION>() as u32,
                    None,
                )
            }
            .map_err(|error| format!("Cannot query processor job state: {error}"))?;
            Ok(accounting.ActiveProcesses)
        }
    }

    struct AttributeList {
        _storage: Vec<usize>,
        raw: LPPROC_THREAD_ATTRIBUTE_LIST,
    }

    impl AttributeList {
        fn new(count: u32) -> Result<Self, String> {
            let mut bytes = 0_usize;
            let _ = unsafe { InitializeProcThreadAttributeList(None, count, None, &mut bytes) };
            if bytes == 0 {
                return Err("Windows did not report a processor attribute-list size".into());
            }
            let words = bytes
                .checked_add(size_of::<usize>() - 1)
                .ok_or_else(|| "Processor attribute-list size overflow".to_string())?
                / size_of::<usize>();
            let mut storage = vec![0_usize; words];
            let raw = LPPROC_THREAD_ATTRIBUTE_LIST(storage.as_mut_ptr().cast::<c_void>());
            unsafe { InitializeProcThreadAttributeList(Some(raw), count, None, &mut bytes) }
                .map_err(|error| format!("Cannot initialize processor attributes: {error}"))?;
            Ok(Self {
                _storage: storage,
                raw,
            })
        }

        fn add_handles(&mut self, attribute: u32, handles: &[HANDLE]) -> Result<(), String> {
            unsafe {
                UpdateProcThreadAttribute(
                    self.raw,
                    0,
                    attribute as usize,
                    Some(handles.as_ptr().cast::<c_void>()),
                    size_of_val(handles),
                    None,
                    None,
                )
            }
            .map_err(|error| format!("Cannot set processor creation attribute: {error}"))
        }
    }

    impl Drop for AttributeList {
        fn drop(&mut self) {
            unsafe { DeleteProcThreadAttributeList(self.raw) };
        }
    }

    pub(crate) struct ContainedProcess {
        job: Job,
        process: OwnedHandle,
        exit_code: Option<i32>,
    }

    struct SpawnGuard {
        job: Option<Job>,
        process: Option<OwnedHandle>,
        primary_thread: Option<OwnedHandle>,
        contained: bool,
    }

    impl SpawnGuard {
        fn process_raw(&self) -> HANDLE {
            raw_handle(
                self.process
                    .as_ref()
                    .expect("a live spawn guard always owns its process"),
            )
        }

        fn thread_raw(&self) -> HANDLE {
            raw_handle(
                self.primary_thread
                    .as_ref()
                    .expect("a live spawn guard always owns its primary thread"),
            )
        }

        fn into_child(mut self) -> ContainedProcess {
            drop(self.primary_thread.take());
            ContainedProcess {
                job: self
                    .job
                    .take()
                    .expect("a verified spawn guard owns its job"),
                process: self
                    .process
                    .take()
                    .expect("a verified spawn guard owns its process"),
                exit_code: None,
            }
        }
    }

    impl Drop for SpawnGuard {
        fn drop(&mut self) {
            let Some(process) = self.process.as_ref() else {
                return;
            };
            if self.contained {
                if let Some(job) = self.job.as_ref() {
                    let _ = job.terminate();
                }
            } else {
                let _ = unsafe { TerminateProcess(raw_handle(process), 1) };
            }
            let _ = unsafe { WaitForSingleObject(raw_handle(process), 5000) };
        }
    }

    impl ContainedProcess {
        pub(crate) fn try_wait(&mut self) -> Result<Option<i32>, String> {
            if let Some(code) = self.exit_code {
                return Ok(Some(code));
            }
            match unsafe { WaitForSingleObject(raw_handle(&self.process), 0) } {
                WAIT_TIMEOUT => Ok(None),
                WAIT_OBJECT_0 => {
                    let mut code = 0_u32;
                    unsafe { GetExitCodeProcess(raw_handle(&self.process), &mut code) }
                        .map_err(|error| format!("Cannot read processor exit code: {error}"))?;
                    let code = code as i32;
                    self.exit_code = Some(code);
                    Ok(Some(code))
                }
                other => Err(format!(
                    "Cannot poll processor handle: wait result {}",
                    other.0
                )),
            }
        }

        pub(crate) fn terminate_and_reap(&mut self, timeout: Duration) -> Result<(), String> {
            let mut errors = Vec::new();
            if let Err(error) = self.job.terminate() {
                errors.push(error);
            }
            let deadline = Instant::now() + timeout;
            let mut root_reaped = false;
            let mut job_empty = false;
            loop {
                if !root_reaped {
                    match self.try_wait() {
                        Ok(Some(_)) => root_reaped = true,
                        Ok(None) => {}
                        Err(error) => {
                            errors.push(error);
                            root_reaped = true;
                        }
                    }
                }
                if !job_empty {
                    match self.job.active_processes() {
                        Ok(0) => job_empty = true,
                        Ok(_) => {}
                        Err(error) => {
                            // A query failure is not equivalent to ACTIVE_PROCESS_ZERO. Record it
                            // and stop polling this signal so cleanup cannot claim containment was
                            // drained successfully.
                            errors.push(error);
                            job_empty = true;
                        }
                    }
                }
                if root_reaped && job_empty {
                    break;
                }
                if Instant::now() >= deadline {
                    if !root_reaped {
                        errors.push(
                            "processor root was not reaped before the cleanup deadline".into(),
                        );
                    }
                    if !job_empty {
                        errors.push(
                            "processor job still had active processes at the cleanup deadline"
                                .into(),
                        );
                    }
                    break;
                }
                std::thread::sleep(CLEANUP_POLL);
            }
            if errors.is_empty() {
                Ok(())
            } else {
                Err(errors.join("; "))
            }
        }
    }

    impl Drop for ContainedProcess {
        fn drop(&mut self) {
            let _ = self.job.terminate();
            let deadline = Instant::now() + Duration::from_secs(1);
            loop {
                match self.job.active_processes() {
                    Ok(0) => break,
                    Ok(_) if Instant::now() < deadline => std::thread::sleep(CLEANUP_POLL),
                    Ok(_) | Err(_) => break,
                }
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            let wait_millis = remaining.as_millis().min(u32::MAX as u128) as u32;
            if wait_millis > 0 {
                let _ = unsafe { WaitForSingleObject(raw_handle(&self.process), wait_millis) };
            }
        }
    }

    pub(crate) fn spawn(spec: ProcessSpec<'_>) -> Result<(ContainedProcess, ProcessPipes), String> {
        let application = nul_terminated(spec.executable.as_os_str(), "processor executable")?;
        let cwd = nul_terminated(spec.cwd.as_os_str(), "processor cwd")?;
        let mut command_line = command_line(spec.executable.as_os_str(), spec.arguments)?;
        let environment = environment_block(spec.environment)?;

        let job = Job::new()?;
        let (stdout_read, stdout_write) = inherited_pipe(PipeEnd::Read)?;
        let (stderr_read, stderr_write) = inherited_pipe(PipeEnd::Read)?;
        let (stdin_write, stdin_read) = inherited_pipe(PipeEnd::Write)?;
        drop(stdin_write);

        let child_handles = [
            raw_handle(&stdin_read),
            raw_handle(&stdout_write),
            raw_handle(&stderr_write),
        ];
        let job_handles = [job.raw()];
        let mut attributes = AttributeList::new(2)?;
        attributes.add_handles(PROC_THREAD_ATTRIBUTE_HANDLE_LIST, &child_handles)?;
        attributes.add_handles(PROC_THREAD_ATTRIBUTE_JOB_LIST, &job_handles)?;

        let mut startup = STARTUPINFOEXW::default();
        startup.StartupInfo.cb = size_of::<STARTUPINFOEXW>() as u32;
        startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
        startup.StartupInfo.hStdInput = raw_handle(&stdin_read);
        startup.StartupInfo.hStdOutput = raw_handle(&stdout_write);
        startup.StartupInfo.hStdError = raw_handle(&stderr_write);
        startup.lpAttributeList = attributes.raw;
        let mut info = PROCESS_INFORMATION::default();
        let flags = CREATE_SUSPENDED
            | CREATE_NO_WINDOW
            | CREATE_UNICODE_ENVIRONMENT
            | EXTENDED_STARTUPINFO_PRESENT;
        unsafe {
            CreateProcessW(
                PCWSTR(application.as_ptr()),
                Some(PWSTR(command_line.as_mut_ptr())),
                None,
                None,
                true,
                flags,
                Some(environment.as_ptr().cast::<c_void>()),
                PCWSTR(cwd.as_ptr()),
                (&startup as *const STARTUPINFOEXW).cast::<STARTUPINFOW>(),
                &mut info,
            )
        }
        .map_err(|error| format!("Cannot create contained processor: {error}"))?;

        // A successful CreateProcessW contractually returns both handles. Arm cleanup immediately:
        // before containment is proven, only TerminateProcess can guarantee the suspended root is
        // stopped; after containment, the whole Job is authoritative.
        let mut guard = SpawnGuard {
            job: Some(job),
            process: Some(unsafe { OwnedHandle::from_raw_handle(info.hProcess.0) }),
            primary_thread: Some(unsafe { OwnedHandle::from_raw_handle(info.hThread.0) }),
            contained: false,
        };
        drop(stdin_read);
        drop(stdout_write);
        drop(stderr_write);

        let mut in_job = BOOL::from(false);
        unsafe {
            IsProcessInJob(
                guard.process_raw(),
                Some(guard.job.as_ref().expect("spawn guard owns its job").raw()),
                &mut in_job,
            )
        }
        .map_err(|error| format!("Cannot verify processor job containment: {error}"))?;
        if !in_job.as_bool() {
            return Err("Processor was created outside its mandatory job".into());
        }
        guard.contained = true;
        let previous = unsafe { ResumeThread(guard.thread_raw()) };
        if previous != 1 {
            return Err(format!(
                "Processor primary thread resume count is invalid: {previous}"
            ));
        }
        let child = guard.into_child();

        Ok((
            child,
            ProcessPipes {
                stdout: Box::new(File::from(stdout_read)),
                stderr: Box::new(File::from(stderr_read)),
            },
        ))
    }

    #[derive(Clone, Copy)]
    enum PipeEnd {
        Read,
        Write,
    }

    fn inherited_pipe(parent_end: PipeEnd) -> Result<(OwnedHandle, OwnedHandle), String> {
        let security = SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            bInheritHandle: true.into(),
            ..SECURITY_ATTRIBUTES::default()
        };
        let mut read = HANDLE::default();
        let mut write = HANDLE::default();
        unsafe { CreatePipe(&mut read, &mut write, Some(&security), 0) }
            .map_err(|error| format!("Cannot create processor pipe: {error}"))?;
        let read = owned_handle(read)?;
        let write = owned_handle(write)?;
        let parent = match parent_end {
            PipeEnd::Read => &read,
            PipeEnd::Write => &write,
        };
        unsafe { SetHandleInformation(raw_handle(parent), HANDLE_FLAG_INHERIT.0, HANDLE_FLAGS(0)) }
            .map_err(|error| format!("Cannot protect processor parent pipe: {error}"))?;
        Ok(match parent_end {
            PipeEnd::Read => (read, write),
            PipeEnd::Write => (write, read),
        })
    }

    fn raw_handle(handle: &OwnedHandle) -> HANDLE {
        HANDLE(handle.as_raw_handle())
    }

    fn owned_handle(handle: HANDLE) -> Result<OwnedHandle, String> {
        if handle.is_invalid() {
            return Err("Windows returned an invalid processor handle".into());
        }
        Ok(unsafe { OwnedHandle::from_raw_handle(handle.0) })
    }

    fn nul_terminated(value: &OsStr, label: &str) -> Result<Vec<u16>, String> {
        let mut encoded = value.encode_wide().collect::<Vec<_>>();
        if encoded.is_empty() || encoded.contains(&0) || encoded.len() >= 32_767 {
            return Err(format!("{label} is not a valid Windows process string"));
        }
        encoded.push(0);
        Ok(encoded)
    }

    fn command_line(executable: &OsStr, arguments: &[OsString]) -> Result<Vec<u16>, String> {
        let mut command = Vec::new();
        append_quoted_argument(&mut command, executable)?;
        for argument in arguments {
            command.push(b' ' as u16);
            append_quoted_argument(&mut command, argument)?;
        }
        if command.len() >= 32_767 {
            return Err("Processor command line exceeds the Windows limit".into());
        }
        command.push(0);
        Ok(command)
    }

    fn append_quoted_argument(command: &mut Vec<u16>, argument: &OsStr) -> Result<(), String> {
        let encoded = argument.encode_wide().collect::<Vec<_>>();
        if encoded.contains(&0) {
            return Err("Processor argument contains NUL".into());
        }
        command.push(b'"' as u16);
        let mut backslashes = 0_usize;
        for value in encoded {
            if value == b'\\' as u16 {
                backslashes += 1;
                continue;
            }
            if value == b'"' as u16 {
                command.extend(std::iter::repeat_n(b'\\' as u16, backslashes * 2 + 1));
                command.push(value);
            } else {
                command.extend(std::iter::repeat_n(b'\\' as u16, backslashes));
                command.push(value);
            }
            backslashes = 0;
        }
        command.extend(std::iter::repeat_n(b'\\' as u16, backslashes * 2));
        command.push(b'"' as u16);
        Ok(())
    }

    fn environment_block(environment: &[(OsString, OsString)]) -> Result<Vec<u16>, String> {
        let mut entries = environment.iter().collect::<Vec<_>>();
        entries.sort_by(|(left, _), (right, _)| {
            left.to_string_lossy()
                .to_ascii_uppercase()
                .cmp(&right.to_string_lossy().to_ascii_uppercase())
        });
        let mut block = Vec::new();
        for (key, value) in entries {
            let key = key.encode_wide().collect::<Vec<_>>();
            let value = value.encode_wide().collect::<Vec<_>>();
            if key.is_empty()
                || key.contains(&0)
                || key.contains(&(b'=' as u16))
                || value.contains(&0)
            {
                return Err("Processor environment contains an invalid entry".into());
            }
            block.extend(key);
            block.push(b'=' as u16);
            block.extend(value);
            block.push(0);
        }
        block.push(0);
        if block.len() > 32_767 {
            return Err("Processor environment exceeds the Windows limit".into());
        }
        if block.len() == 1 {
            block.push(0);
        }
        Ok(block)
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::{
            fs,
            io::Read,
            process::Command,
            time::{SystemTime, UNIX_EPOCH},
        };

        struct TempDirectory(std::path::PathBuf);

        impl Drop for TempDirectory {
            fn drop(&mut self) {
                let _ = fs::remove_dir_all(&self.0);
            }
        }

        fn encoded_argument(argument: &OsStr) -> String {
            let units = argument.encode_wide().collect::<Vec<_>>();
            let hex = units
                .iter()
                .map(|unit| format!("{unit:04x}"))
                .collect::<String>();
            format!("{}:{hex}", units.len())
        }

        #[test]
        fn windows_quoting_escapes_quotes_and_trailing_backslashes() {
            let command = command_line(
                OsStr::new(r"C:\Program Files\Java\java.exe"),
                &[
                    OsString::from(r#"plain"#),
                    OsString::from(r#"a b"#),
                    OsString::from(r#"quote\"inside"#),
                    OsString::from(r"trailing\"),
                ],
            )
            .unwrap();
            assert_eq!(*command.last().unwrap(), 0);
            assert!(command.len() < 32_767);
        }

        #[test]
        fn environment_block_is_double_nul_terminated() {
            let block = environment_block(&[(OsString::from("B"), OsString::from("2"))]).unwrap();
            assert_eq!(&block[block.len() - 2..], &[0, 0]);
        }

        #[test]
        fn create_process_round_trips_exact_windows_arguments() {
            let nonce = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let directory = std::env::temp_dir().join(format!(
                "fragment supervisor argv probe {} {nonce}",
                std::process::id()
            ));
            fs::create_dir(&directory).unwrap();
            let directory = TempDirectory(directory);
            let source = directory.0.join("argv probe.rs");
            let executable = directory.0.join("argv probe.exe");
            fs::write(
                &source,
                r#"
use std::os::windows::ffi::OsStrExt;

fn main() {
    for argument in std::env::args_os().skip(1) {
        let units = argument.encode_wide().collect::<Vec<_>>();
        let hex = units
            .iter()
            .map(|unit| format!("{unit:04x}"))
            .collect::<String>();
        println!("{}:{hex}", units.len());
    }
}
"#,
            )
            .unwrap();
            let rustc = std::env::var_os("RUSTC").unwrap_or_else(|| OsString::from("rustc"));
            let compilation = Command::new(rustc)
                .arg("--edition=2021")
                .args(["--crate-name", "fragment_argv_probe"])
                .arg(&source)
                .arg("-o")
                .arg(&executable)
                .output()
                .unwrap();
            assert!(
                compilation.status.success(),
                "argv probe compilation failed: {}",
                String::from_utf8_lossy(&compilation.stderr)
            );

            let arguments = vec![
                OsString::from(""),
                OsString::from("plain"),
                OsString::from("with spaces"),
                OsString::from("quote\"inside"),
                OsString::from(r#"slashes\\before\"quote"#),
                OsString::from("single trailing\\"),
                OsString::from(r"trailing\\"),
                OsString::from("Фрагмент ✨"),
            ];
            let expected = arguments
                .iter()
                .map(|argument| encoded_argument(argument))
                .collect::<Vec<_>>()
                .join("\n")
                + "\n";
            let (mut child, mut pipes) = spawn(ProcessSpec {
                executable: &executable,
                arguments: &arguments,
                cwd: &directory.0,
                environment: &[],
            })
            .unwrap();
            let mut stdout = String::new();
            pipes.stdout.read_to_string(&mut stdout).unwrap();
            let mut stderr = String::new();
            pipes.stderr.read_to_string(&mut stderr).unwrap();
            child.terminate_and_reap(Duration::from_secs(5)).unwrap();
            assert!(stderr.is_empty(), "argv probe stderr: {stderr}");
            assert_eq!(stdout, expected);
        }
    }
}

#[cfg(not(windows))]
mod platform {
    use super::*;
    use std::process::{Child, Command, Stdio};

    pub(crate) struct ContainedProcess {
        child: Child,
        exit_code: Option<i32>,
    }

    impl ContainedProcess {
        pub(crate) fn try_wait(&mut self) -> Result<Option<i32>, String> {
            if let Some(code) = self.exit_code {
                return Ok(Some(code));
            }
            match self
                .child
                .try_wait()
                .map_err(|error| format!("Cannot poll processor: {error}"))?
            {
                Some(status) => {
                    let code = status
                        .code()
                        .ok_or_else(|| "Processor exited without a numeric code".to_string())?;
                    self.exit_code = Some(code);
                    Ok(Some(code))
                }
                None => Ok(None),
            }
        }

        pub(crate) fn terminate_and_reap(&mut self, timeout: Duration) -> Result<(), String> {
            let mut errors = Vec::new();
            if self.try_wait()?.is_none() {
                if let Err(error) = self.child.kill() {
                    errors.push(format!("Cannot kill processor: {error}"));
                }
            }
            let deadline = Instant::now() + timeout;
            loop {
                match self.try_wait() {
                    Ok(Some(_)) => break,
                    Ok(None) if Instant::now() < deadline => std::thread::sleep(CLEANUP_POLL),
                    Ok(None) => {
                        errors.push("processor was not reaped before the cleanup deadline".into());
                        break;
                    }
                    Err(error) => {
                        errors.push(error);
                        break;
                    }
                }
            }
            if errors.is_empty() {
                Ok(())
            } else {
                Err(errors.join("; "))
            }
        }
    }

    pub(crate) fn spawn(spec: ProcessSpec<'_>) -> Result<(ContainedProcess, ProcessPipes), String> {
        let mut child = Command::new(spec.executable)
            .args(spec.arguments)
            .current_dir(spec.cwd)
            .env_clear()
            .envs(spec.environment.iter().cloned())
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|error| format!("Cannot start processor: {error}"))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| "Processor stdout pipe is missing".to_string())?;
        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| "Processor stderr pipe is missing".to_string())?;
        Ok((
            ContainedProcess {
                child,
                exit_code: None,
            },
            ProcessPipes {
                stdout: Box::new(stdout),
                stderr: Box::new(stderr),
            },
        ))
    }
}

pub(super) use platform::spawn;
