#![deny(clippy::all)]

//! Native module for VS Code that provides access to Windows app container tokens.
//! This module enables access to Windows app container process information
//! and named pipe paths for communication with sandboxed applications.

#[macro_use]
extern crate napi_derive;

use napi::{Error, Result, Status};
use std::ffi::OsString;
use std::mem::size_of;
use std::os::windows::prelude::*;
use windows::Wdk::System::Threading::{NtQueryInformationProcess, ProcessBasicInformation};
use windows::Win32::Foundation::FILETIME;
use windows::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE};
use windows::Win32::Security::Isolation::GetAppContainerNamedObjectPath;
use windows::Win32::Security::{
	GetTokenInformation, TokenIsAppContainer, TokenSessionId, TOKEN_QUERY,
};
use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
use windows::Win32::System::Diagnostics::ToolHelp::{
	CreateToolhelp32Snapshot, Process32First, Process32Next, PROCESSENTRY32, TH32CS_SNAPPROCESS,
};
use windows::Win32::System::Memory::{
	VirtualQueryEx, MEMORY_BASIC_INFORMATION, MEM_COMMIT, PAGE_PROTECTION_FLAGS, PAGE_READWRITE,
};
use windows::Win32::System::Threading::{
	GetProcessTimes, OpenProcess, OpenProcessToken, PEB, PROCESS_BASIC_INFORMATION,
	PROCESS_QUERY_INFORMATION, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_VM_READ,
	RTL_USER_PROCESS_PARAMETERS,
};

// Constants
/// Maximum command line buffer size to read (8KB)
const MAX_CMD_LINE_SIZE: usize = 8192;
/// Maximum object path buffer size
const MAX_OBJECT_PATH_SIZE: usize = 1024;
/// Conversion factor from Windows FILETIME to seconds (100-nanosecond intervals)
const FILETIME_TO_SECONDS: u64 = 10_000_000;
/// Seconds between Windows epoch (1601-01-01) and Unix epoch (1970-01-01)
const WINDOWS_TO_UNIX_EPOCH: u64 = 11644473600; // seconds between 1601 and 1970

// RAII wrapper for Windows handles
struct HandleWrapper(HANDLE);

impl HandleWrapper {
	fn new(handle: HANDLE) -> Self {
		Self(handle)
	}

	fn get(&self) -> HANDLE {
		self.0
	}

	fn is_invalid(&self) -> bool {
		self.0.is_invalid()
	}
}

impl Drop for HandleWrapper {
	fn drop(&mut self) {
		if !self.0.is_invalid() {
			unsafe {
				_ = CloseHandle(self.0);
			}
		}
	}
}

/// Retrieves the named pipe path for an app container process
///
/// This function extracts the app container path from a process token
/// and formats it as a named pipe path that can be used for communication.
///
/// # Arguments
/// * `h_token` - A valid process token handle with TOKEN_QUERY access
///
/// # Returns
/// * `Some(String)` - The formatted named pipe path if successful
/// * `None` - If any part of the extraction fails
fn add_app_container_process_name(h_token: HANDLE) -> Option<String> {
	// Get session ID from token
	let mut ul_session_id: u32 = 0;
	let mut ul_return_length: u32 = 0;

	let token_session_id_result = unsafe {
		GetTokenInformation(
			h_token,
			TokenSessionId,
			Some(&mut ul_session_id as *mut _ as *mut _),
			size_of::<u32>() as u32,
			&mut ul_return_length,
		)
		.is_ok()
	};

	if !token_session_id_result {
		return None;
	}

	// Create pipe path string with reasonable capacity
	let mut pipe_name = String::with_capacity(MAX_OBJECT_PATH_SIZE);
	pipe_name.push_str("\\\\.\\pipe\\Sessions\\");
	pipe_name.push_str(&ul_session_id.to_string());
	pipe_name.push('\\');

	// Get app container path
	let mut object_path = vec![0u16; MAX_OBJECT_PATH_SIZE];
	let mut path_length: u32 = MAX_OBJECT_PATH_SIZE as u32;

	let container_path_result = unsafe {
		GetAppContainerNamedObjectPath(
			Some(h_token),
			None,
			Some(&mut object_path),
			&mut path_length,
		)
		.is_ok()
	};

	if !container_path_result {
		return None;
	}

	// Find null terminator and convert to string
	let object_path_str = object_path
		.iter()
		.position(|&c| c == 0)
		.map(|pos| String::from_utf16_lossy(&object_path[0..pos]))?;

	// Combine paths
	pipe_name.push_str(&object_path_str);
	Some(pipe_name)
}

enum WinError {
	NtQueryFailed,
	MemoryProtectionFailed,
	PebReadFailed,
	ProcessParametersMemoryProtectionFailed,
	CommandLineReadFailed,
	EmptyCommandLine,
}

impl std::fmt::Display for WinError {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self {
			WinError::NtQueryFailed => write!(f, "Failed to query process information"),
			WinError::MemoryProtectionFailed => write!(f, "Memory protection check failed for process PEB"),
			WinError::PebReadFailed => write!(f, "Failed to read process PEB"),
			WinError::ProcessParametersMemoryProtectionFailed => write!(f, "Memory protection check failed for process parameters"),
			WinError::CommandLineReadFailed => write!(f, "Failed to read command line from process memory"),
			WinError::EmptyCommandLine => write!(f, "Command line is empty"),
		}
	}
}

impl std::fmt::Debug for WinError {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		std::fmt::Display::fmt(self, f)
	}
}

/// Gets the full command line for a process using NtQueryInformationProcess
///
/// This function safely retrieves the command line string from another process's memory
/// by using the Windows process information API and proper memory protection checks.
///
/// # Arguments
/// * `process_handle` - A valid process handle with PROCESS_QUERY_INFORMATION and PROCESS_VM_READ access
///
/// # Returns
/// * `Ok(String)` - The process command line if successfully retrieved
/// * `Err(WinError)` - The specific error that occurred during retrieval
fn get_process_command_line(process_handle: HANDLE) -> std::result::Result<String, WinError> {
	unsafe {
		// First, get the process basic information to access the PEB
		let mut process_info = PROCESS_BASIC_INFORMATION::default();

		let status = NtQueryInformationProcess(
			process_handle,
			ProcessBasicInformation,
			&mut process_info as *mut _ as *mut _,
			std::mem::size_of::<PROCESS_BASIC_INFORMATION>() as u32,
			std::ptr::null_mut(),
		);

		if !status.is_ok() || process_info.PebBaseAddress.is_null() {
			return Err(WinError::NtQueryFailed);
		}

		// Check memory protection and accessibility with VirtualQueryEx before reading
		let mut mem_info = MEMORY_BASIC_INFORMATION::default();
		let virtual_query_result = VirtualQueryEx(
			process_handle,
			Some(process_info.PebBaseAddress as *const _),
			&mut mem_info,
			std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
		);

		if virtual_query_result == 0
			|| mem_info.State != MEM_COMMIT
			|| (mem_info.Protect & PAGE_READWRITE) == PAGE_PROTECTION_FLAGS(0)
		{
			return Err(WinError::MemoryProtectionFailed);
		}

		// Read the PEB from the process memory
		let mut peb = PEB::default();

		let mut bytes_read = 0;
		let peb_read_success = ReadProcessMemory(
			process_handle,
			process_info.PebBaseAddress as *const _,
			&mut peb as *mut _ as *mut _,
			std::mem::size_of::<PEB>(),
			Some(&mut bytes_read),
		);

		if peb_read_success.is_err() || peb.ProcessParameters.is_null() || bytes_read == 0 {
			return Err(WinError::PebReadFailed);
		}

		// Check memory protection for the process parameters
		let virtual_query_params_result = VirtualQueryEx(
			process_handle,
			Some(peb.ProcessParameters as *const _),
			&mut mem_info,
			std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
		);

		if virtual_query_params_result == 0
			|| mem_info.State != MEM_COMMIT
			|| (mem_info.Protect & PAGE_READWRITE) == PAGE_PROTECTION_FLAGS(0)
		{
			return Err(WinError::ProcessParametersMemoryProtectionFailed);
		}

		// Read the process parameters from the process memory
		let mut process_params = RTL_USER_PROCESS_PARAMETERS::default();
		let params_read_success = ReadProcessMemory(
			process_handle,
			peb.ProcessParameters as *const _,
			&mut process_params as *mut _ as *mut _,
			std::mem::size_of::<RTL_USER_PROCESS_PARAMETERS>(),
			Some(&mut bytes_read),
		);

		if params_read_success.is_err()
			|| process_params.CommandLine.Buffer.is_null()
			|| process_params.CommandLine.Length == 0
		{
			return Err(WinError::EmptyCommandLine);
		}

		// Calculate the buffer size needed (make sure we don't exceed reasonable limits)
		let buffer_size = std::cmp::min(
			process_params.CommandLine.Length as usize,
			MAX_CMD_LINE_SIZE,
		);

		// Read the command line string from the process memory
		let mut buffer = vec![0u16; buffer_size / 2 + 1]; // +1 for null terminator

		let cmd_read_success = ReadProcessMemory(
			process_handle,
			process_params.CommandLine.Buffer.as_ptr() as _,
			buffer.as_mut_ptr() as *mut _,
			buffer_size,
			Some(&mut bytes_read),
		);

		if cmd_read_success.is_err() {
			return Err(WinError::CommandLineReadFailed);
		}

		// Convert to Rust string
		// Find null terminator if any
		let len = buffer.iter().position(|&c| c == 0).unwrap_or(buffer.len());

		if len > 0 {
			Ok(OsString::from_wide(&buffer[0..len])
				.to_string_lossy()
				.into_owned())
		} else {
			Err(WinError::EmptyCommandLine)
		}
	}
}

#[napi(object)]
/// Process information including ID, parent, creation time, and command line
pub struct ProcessInfo {
	/// Process ID
	pub process_id: u32,
	/// Parent process ID
	pub parent_process_id: u32,
	/// Creation date as Unix timestamp (seconds since epoch)
	pub creation_date: i64,
	/// Full command line of the process
	pub command_line: String,
}

/// Helper function to convert Windows FILETIME to Unix timestamp (seconds since epoch)
fn filetime_to_unix_timestamp(ft: FILETIME) -> i64 {
	let filetime_u64 = ((ft.dwHighDateTime as u64) << 32) | (ft.dwLowDateTime as u64);
	((filetime_u64 / FILETIME_TO_SECONDS) - WINDOWS_TO_UNIX_EPOCH) as i64
}

#[napi]
/// Gets information about all accessible processes in the system
///
/// Returns a list of ProcessInfo objects containing:
/// - Process ID
/// - Parent process ID
/// - Creation date as Unix timestamp
/// - Command line
pub fn get_process_info() -> Result<Vec<ProcessInfo>> {
	let mut process_info_list = Vec::with_capacity(128); // Pre-allocate for typical system process count

	// Take a snapshot of all processes in the system
	let h_process_snap =
		unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) }.unwrap_or(INVALID_HANDLE_VALUE);

	if h_process_snap == INVALID_HANDLE_VALUE {
		return Err(Error::new(
			Status::GenericFailure,
			"Failed to create process snapshot".to_string(),
		));
	}

	let process_snap = HandleWrapper::new(h_process_snap);

	// Set the size of the structure before using it
	let mut pe32 = PROCESSENTRY32 {
		dwSize: size_of::<PROCESSENTRY32>() as u32,
		..Default::default()
	};

	// Retrieve information about the first process
	let first_process_result = unsafe { Process32First(process_snap.get(), &mut pe32) };

	if first_process_result.is_err() {
		return Err(Error::new(
			Status::GenericFailure,
			"Failed to get first process in snapshot".to_string(),
		));
	}

	// Walk the snapshot of processes
	loop {
		let h_process_result = unsafe {
			OpenProcess(
				PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ,
				false,
				pe32.th32ProcessID,
			)
		};

		if let Ok(h_process) = h_process_result {
			let process = HandleWrapper::new(h_process);

			if !process.is_invalid() {
				// Get the process creation time
				let mut creation_time = FILETIME::default();
				let mut exit_time = FILETIME::default();
				let mut kernel_time = FILETIME::default();
				let mut user_time = FILETIME::default();

				let times_result = unsafe {
					GetProcessTimes(
						process.get(),
						&mut creation_time,
						&mut exit_time,
						&mut kernel_time,
						&mut user_time,
					)
				};

				let creation_date = if times_result.is_ok() {
					filetime_to_unix_timestamp(creation_time)
				} else {
					0
				};

				// Get command line
				let command_line = get_process_command_line(process.get())
					.unwrap_or_else(|e| format!("Failed to get command line: {}", e));

				process_info_list.push(ProcessInfo {
					process_id: pe32.th32ProcessID,
					parent_process_id: pe32.th32ParentProcessID,
					creation_date,
					command_line,
				});
			}
		}

		if unsafe { Process32Next(process_snap.get(), &mut pe32) }.is_err() {
			break;
		}
	}

	Ok(process_info_list)
}

#[napi]
pub fn get_app_container_process_tokens() -> Result<Vec<String>> {
	let mut tokens = Vec::new();

	// Take a snapshot of all processes in the system
	let h_process_snap =
		unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) }.unwrap_or(INVALID_HANDLE_VALUE);

	if h_process_snap == INVALID_HANDLE_VALUE {
		return Err(Error::new(
			Status::GenericFailure,
			"CreateToolhelp32Snapshot failed".to_string(),
		));
	}

	let process_snap = HandleWrapper::new(h_process_snap);

	// Set the size of the structure before using it
	let mut pe32 = PROCESSENTRY32 {
		dwSize: size_of::<PROCESSENTRY32>() as u32,
		..Default::default()
	};

	// Retrieve information about the first process
	let first_process_result = unsafe { Process32First(process_snap.get(), &mut pe32) };

	if first_process_result.is_err() {
		return Err(Error::new(
			Status::GenericFailure,
			"Process32First failed".to_string(),
		));
	}

	// Walk the snapshot of processes
	loop {
		let h_process_result =
			unsafe { OpenProcess(PROCESS_QUERY_INFORMATION, false, pe32.th32ProcessID) };

		if let Ok(h_process) = h_process_result {
			let process = HandleWrapper::new(h_process);

			if process.is_invalid() {
				// Skip processes we can't open
				if unsafe { Process32Next(process_snap.get(), &mut pe32) }.is_err() {
					break;
				}
				continue;
			}

			let mut h_process_token = HANDLE::default();

			// Open the process token
			let token_open_result =
				unsafe { OpenProcessToken(process.get(), TOKEN_QUERY, &mut h_process_token) };

			if token_open_result.is_ok() {
				let process_token = HandleWrapper::new(h_process_token);

				// Check if the process is running in an app container
				let mut ul_is_app_container: u32 = 0;
				let mut dw_return_length: u32 = 0;

				let token_info_result = unsafe {
					GetTokenInformation(
						process_token.get(),
						TokenIsAppContainer,
						Some(&mut ul_is_app_container as *mut _ as *mut _),
						size_of::<u32>() as u32,
						&mut dw_return_length,
					)
				};

				if token_info_result.is_ok() && ul_is_app_container != 0 {
					// Add the app container process token
					if let Some(token_name) = add_app_container_process_name(process_token.get()) {
						tokens.push(token_name);
					}
				}
			}
		}

		if unsafe { Process32Next(process_snap.get(), &mut pe32) }.is_err() {
			break;
		}
	}

	Ok(tokens)
}
