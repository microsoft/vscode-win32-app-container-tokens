#![deny(clippy::all)]

#[macro_use]
extern crate napi_derive;

use napi::{Error, Result, Status};
use std::mem::size_of;
use windows::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE};
use windows::Win32::Security::Isolation::GetAppContainerNamedObjectPath;
use windows::Win32::Security::{
	GetTokenInformation, TokenIsAppContainer, TokenSessionId, TOKEN_QUERY,
};
use windows::Win32::System::Diagnostics::ToolHelp::{
	CreateToolhelp32Snapshot, Process32First, Process32Next, PROCESSENTRY32, TH32CS_SNAPPROCESS,
};
use windows::Win32::System::Threading::{OpenProcess, OpenProcessToken, PROCESS_QUERY_INFORMATION};

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
				CloseHandle(self.0);
			}
		}
	}
}

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
		.as_bool()
	};

	if !token_session_id_result {
		return None;
	}

	// Create pipe path string
	let mut pipe_name = String::from("\\\\.\\pipe\\Sessions\\");
	pipe_name.push_str(&ul_session_id.to_string());
	pipe_name.push('\\');

	// Get app container path
	let mut object_path = [0u16; 1024];

	let container_path_result = unsafe {
		GetAppContainerNamedObjectPath(h_token, None, Some(&mut object_path), &mut ul_return_length)
			.as_bool()
	};

	if !container_path_result {
		return None;
	}

	// Find null terminator and convert to string
	let object_path_str = match object_path
		.iter()
		.position(|&c| c == 0)
		.map(|pos| String::from_utf16_lossy(&object_path[0..pos]))
	{
		Some(s) => s,
		None => return None,
	};

	// Combine paths
	pipe_name.push_str(&object_path_str);
	Some(pipe_name)
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

	if !first_process_result.as_bool() {
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
				if !unsafe { Process32Next(process_snap.get(), &mut pe32) }.as_bool() {
					break;
				}
				continue;
			}

			let mut h_process_token = HANDLE::default();

			// Open the process token
			let token_open_result =
				unsafe { OpenProcessToken(process.get(), TOKEN_QUERY, &mut h_process_token) };

			if token_open_result.as_bool() {
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

				if token_info_result.as_bool() && ul_is_app_container != 0 {
					// Add the app container process token
					if let Some(token_name) = add_app_container_process_name(process_token.get()) {
						tokens.push(token_name);
					}
				}
			}
		}

		if !unsafe { Process32Next(process_snap.get(), &mut pe32) }.as_bool() {
			break;
		}
	}

	Ok(tokens)
}
