#include <windows.h>
#include <TlHelp32.h>
#include <string>
#include <sstream>
#include <napi.h>

/**
 * Schedules a JS error to be thrown via NAPI. Note that this doesn't actually
 * throw a C++ exception. Code should usually return after calling this.
 */
void ThrowJsError(Napi::Env env, const char *msg) {

  auto errMsg = std::string(msg);

  const int sysMsgLen = 256;
  char sysMsg[sysMsgLen] = "";
  FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                NULL, GetLastError(),
                MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), // Default language
                sysMsg, sysMsgLen, NULL);

  errMsg += ": ";
  errMsg += sysMsg;

  Napi::Error::New(env, errMsg).ThrowAsJavaScriptException();
}

BOOL addAppContainerProcessName(Napi::Env env, Napi::Array tokens,
                                HANDLE hToken) {
  ULONG ulSessionId;
  ULONG ulReturnLength;
  WCHAR ObjectPath[1024] = L"";
  std::wstringstream stringStream;
  std::wstring strPipeName;

  if (!GetTokenInformation(hToken, TokenSessionId, &ulSessionId,
                           sizeof(ulSessionId), &ulReturnLength)) {
    return false;
  }

  stringStream.str(L"");
  stringStream << ulSessionId;

  strPipeName = L"\\\\.\\pipe\\Sessions\\";
  strPipeName += stringStream.str();
  strPipeName += L"\\";

  if (!GetAppContainerNamedObjectPath(hToken, NULL,
                                      sizeof(ObjectPath) / sizeof(WCHAR),
                                      ObjectPath, &ulReturnLength)) {
    return false; // just ignore any errors that happen here
  }

  strPipeName += ObjectPath;
  auto pipeNameU16 = std::u16string(strPipeName.begin(), strPipeName.end());
  tokens[tokens.Length()] = Napi::String::New(env, pipeNameU16.c_str());
  return true;
}

Napi::Value getAppContainerProcessTokens(const Napi::CallbackInfo &info) {
  Napi::Env env = info.Env();

  // Take a snapshot of all processes in the system.
  auto hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if (hProcessSnap == INVALID_HANDLE_VALUE) {
    ThrowJsError(env, "CreateToolhelp32Snapshot: ");
    return env.Null();
  }

  // Set the size of the structure before using it.
  PROCESSENTRY32 pe32;
  pe32.dwSize = sizeof(PROCESSENTRY32);

  // Retrieve information about the first process,
  // and exit if unsuccessful
  if (!Process32First(hProcessSnap, &pe32)) {
    CloseHandle(hProcessSnap);
    ThrowJsError(env, "Process32First: ");
    return env.Null();
  }

  auto tokens = Napi::Array::New(env);

  // Now walk the snapshot of processes, and gather process tokens
  do {
    auto hProcess =
        OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pe32.th32ProcessID);
    if (hProcess == NULL) {
      continue;
    }

    HANDLE hProcessToken;
    ULONG ulIsAppContainer;
    DWORD dwReturnLength;

    if (OpenProcessToken(hProcess, TOKEN_QUERY, &hProcessToken)) {
      if (GetTokenInformation(hProcessToken, TokenIsAppContainer,
                              &ulIsAppContainer, sizeof(ulIsAppContainer),
                              &dwReturnLength)) {
        if (ulIsAppContainer) {
          addAppContainerProcessName(env, tokens, hProcessToken);
        }
        CloseHandle(hProcessToken);
      }

      CloseHandle(hProcess);
    }
  } while (Process32Next(hProcessSnap, &pe32));

  CloseHandle(hProcessSnap);

  return tokens;
}

Napi::Object Init(Napi::Env env, Napi::Object exports) {
  exports.Set(Napi::String::New(env, "getAppContainerProcessTokens"),
              Napi::Function::New(env, getAppContainerProcessTokens));
  return exports;
}

NODE_API_MODULE(w32appcontainertokens, Init)
