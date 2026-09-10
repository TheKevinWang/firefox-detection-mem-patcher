/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "livepatch/core.h"

#include <bcrypt.h>
#include <psapi.h>
#include <tlhelp32.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <map>
#include <set>
#include <sstream>
#include <stdexcept>
#include <thread>

namespace livepatch {
namespace {

std::atomic_bool g_stop = false;

std::string Trim(std::string value) {
  const auto first = value.find_first_not_of(" \t\r\n");
  if (first == std::string::npos)
    return {};
  const auto last = value.find_last_not_of(" \t\r\n");
  return value.substr(first, last - first + 1);
}

std::string Upper(std::string value) {
  std::transform(
      value.begin(), value.end(), value.begin(),
      [](unsigned char c) { return static_cast<char>(std::toupper(c)); });
  return value;
}

std::wstring Lower(std::wstring value) {
  std::transform(value.begin(), value.end(), value.begin(), towlower);
  return value;
}

std::uint64_t ParseInteger(const std::string &value, const char *field) {
  std::size_t used = 0;
  try {
    const auto result = std::stoull(value, &used, 0);
    if (used != value.size())
      throw std::invalid_argument("trailing data");
    return result;
  } catch (const std::exception &) {
    throw std::runtime_error(std::string("invalid ") + field + ": " + value);
  }
}

std::vector<std::uint8_t> ParseBytes(std::string value) {
  value.erase(
      std::remove_if(value.begin(), value.end(),
                     [](unsigned char c) { return std::isspace(c) != 0; }),
      value.end());
  if (value.empty() || value.size() % 2 != 0) {
    throw std::runtime_error(
        "byte string must contain complete hexadecimal bytes");
  }
  std::vector<std::uint8_t> result;
  result.reserve(value.size() / 2);
  for (std::size_t i = 0; i < value.size(); i += 2) {
    const auto part = value.substr(i, 2);
    std::size_t used = 0;
    unsigned long byte = 0;
    try {
      byte = std::stoul(part, &used, 16);
    } catch (const std::exception &) {
      throw std::runtime_error("invalid hexadecimal byte: " + part);
    }
    if (used != 2 || byte > 0xff) {
      throw std::runtime_error("invalid hexadecimal byte: " + part);
    }
    result.push_back(static_cast<std::uint8_t>(byte));
  }
  return result;
}

std::vector<std::string> Split(const std::string &value, char delimiter) {
  std::vector<std::string> parts;
  std::stringstream stream(value);
  std::string part;
  while (std::getline(stream, part, delimiter))
    parts.push_back(Trim(part));
  return parts;
}

std::string WinError(DWORD code) {
  wchar_t *message = nullptr;
  const DWORD length = FormatMessageW(
      FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
          FORMAT_MESSAGE_IGNORE_INSERTS,
      nullptr, code, 0, reinterpret_cast<wchar_t *>(&message), 0, nullptr);
  std::wstring text =
      length && message ? std::wstring(message, length) : L"unknown error";
  if (message)
    LocalFree(message);
  return Narrow(text) + " (" + std::to_string(code) + ")";
}

class Handle {
public:
  explicit Handle(HANDLE handle = nullptr) : handle_(handle) {}
  ~Handle() {
    if (handle_ && handle_ != INVALID_HANDLE_VALUE)
      CloseHandle(handle_);
  }
  Handle(const Handle &) = delete;
  Handle &operator=(const Handle &) = delete;
  Handle(Handle &&other) noexcept : handle_(other.handle_) {
    other.handle_ = nullptr;
  }
  Handle &operator=(Handle &&other) noexcept {
    if (this != &other) {
      if (handle_ && handle_ != INVALID_HANDLE_VALUE)
        CloseHandle(handle_);
      handle_ = other.handle_;
      other.handle_ = nullptr;
    }
    return *this;
  }
  HANDLE get() const { return handle_; }
  explicit operator bool() const {
    return handle_ && handle_ != INVALID_HANDLE_VALUE;
  }
  HANDLE release() {
    HANDLE result = handle_;
    handle_ = nullptr;
    return result;
  }

private:
  HANDLE handle_;
};

class SuspendedThreads {
public:
  explicit SuspendedThreads(DWORD pid) {
    try {
      std::set<DWORD> seen;
      for (int pass = 0; pass < 4; ++pass) {
        bool found_new = false;
        Handle snapshot(CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0));
        if (!snapshot) {
          throw std::runtime_error("thread snapshot failed: " +
                                   WinError(GetLastError()));
        }
        THREADENTRY32 entry{};
        entry.dwSize = sizeof(entry);
        if (!Thread32First(snapshot.get(), &entry))
          break;
        do {
          if (entry.th32OwnerProcessID != pid || seen.count(entry.th32ThreadID))
            continue;
          Handle thread(OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT,
                                   FALSE, entry.th32ThreadID));
          if (!thread) {
            throw std::runtime_error("cannot open target thread " +
                                     std::to_string(entry.th32ThreadID) + ": " +
                                     WinError(GetLastError()));
          }
          if (SuspendThread(thread.get()) == static_cast<DWORD>(-1)) {
            throw std::runtime_error("cannot suspend target thread " +
                                     std::to_string(entry.th32ThreadID) + ": " +
                                     WinError(GetLastError()));
          }
          seen.insert(entry.th32ThreadID);
          threads_.push_back(std::move(thread));
          found_new = true;
        } while (Thread32Next(snapshot.get(), &entry));
        if (!found_new)
          return;
      }
      throw std::runtime_error(
          "target kept creating threads while suspension was attempted");
    } catch (...) {
      ResumeAll();
      throw;
    }
  }

  ~SuspendedThreads() { ResumeAll(); }

  bool InstructionPointerInside(std::uintptr_t begin,
                                std::uintptr_t end) const {
    for (const auto &thread : threads_) {
      CONTEXT context{};
      context.ContextFlags = CONTEXT_CONTROL;
      if (!GetThreadContext(thread.get(), &context)) {
        throw std::runtime_error("cannot read a suspended thread context: " +
                                 WinError(GetLastError()));
      }
#if defined(_M_X64)
      const auto instruction = static_cast<std::uintptr_t>(context.Rip);
#else
#error The live-patch MVP supports x64 only.
#endif
      if (instruction >= begin && instruction < end)
        return true;
    }
    return false;
  }

private:
  void ResumeAll() {
    for (auto &thread : threads_)
      ResumeThread(thread.get());
    threads_.clear();
  }

  std::vector<Handle> threads_;
};

std::string Sha256(const std::filesystem::path &path) {
  BCRYPT_ALG_HANDLE algorithm = nullptr;
  BCRYPT_HASH_HANDLE hash = nullptr;
  DWORD object_size = 0;
  DWORD hash_size = 0;
  DWORD result_size = 0;
  std::vector<std::uint8_t> object;
  std::vector<std::uint8_t> digest;
  Handle file(
      CreateFileW(path.c_str(), GENERIC_READ,
                  FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                  nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr));
  if (!file)
    throw std::runtime_error("cannot open module for hashing: " +
                             WinError(GetLastError()));
  auto cleanup = [&] {
    if (hash)
      BCryptDestroyHash(hash);
    if (algorithm)
      BCryptCloseAlgorithmProvider(algorithm, 0);
  };
  if (BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr,
                                  0) < 0 ||
      BCryptGetProperty(algorithm, BCRYPT_OBJECT_LENGTH,
                        reinterpret_cast<PUCHAR>(&object_size),
                        sizeof(object_size), &result_size, 0) < 0 ||
      BCryptGetProperty(algorithm, BCRYPT_HASH_LENGTH,
                        reinterpret_cast<PUCHAR>(&hash_size), sizeof(hash_size),
                        &result_size, 0) < 0) {
    cleanup();
    throw std::runtime_error("cannot initialize SHA-256");
  }
  object.resize(object_size);
  digest.resize(hash_size);
  if (BCryptCreateHash(algorithm, &hash, object.data(), object_size, nullptr, 0,
                       0) < 0) {
    cleanup();
    throw std::runtime_error("cannot create SHA-256 hash");
  }
  std::vector<std::uint8_t> buffer(1024 * 1024);
  while (true) {
    DWORD read = 0;
    if (!ReadFile(file.get(), buffer.data(), static_cast<DWORD>(buffer.size()),
                  &read, nullptr)) {
      cleanup();
      throw std::runtime_error("cannot read module for hashing: " +
                               WinError(GetLastError()));
    }
    if (read == 0)
      break;
    if (BCryptHashData(hash, buffer.data(), read, 0) < 0) {
      cleanup();
      throw std::runtime_error("cannot update SHA-256 hash");
    }
  }
  if (BCryptFinishHash(hash, digest.data(), hash_size, 0) < 0) {
    cleanup();
    throw std::runtime_error("cannot finish SHA-256 hash");
  }
  cleanup();
  return Hex(digest);
}

bool SamePath(const std::filesystem::path &left,
              const std::filesystem::path &right) {
  std::error_code error;
  const auto canonical_left = std::filesystem::weakly_canonical(left, error);
  if (error)
    return Lower(left.wstring()) == Lower(right.wstring());
  const auto canonical_right = std::filesystem::weakly_canonical(right, error);
  if (error)
    return Lower(left.wstring()) == Lower(right.wstring());
  return Lower(canonical_left.wstring()) == Lower(canonical_right.wstring());
}

std::wstring QuoteArgument(const std::wstring &argument) {
  if (argument.empty())
    return L"\"\"";
  if (argument.find_first_of(L" \t\"") == std::wstring::npos)
    return argument;
  std::wstring result = L"\"";
  std::size_t slashes = 0;
  for (wchar_t character : argument) {
    if (character == L'\\') {
      ++slashes;
    } else if (character == L'\"') {
      result.append(slashes * 2 + 1, L'\\');
      result.push_back(L'\"');
      slashes = 0;
    } else {
      result.append(slashes, L'\\');
      slashes = 0;
      result.push_back(character);
    }
  }
  result.append(slashes * 2, L'\\');
  result.push_back(L'\"');
  return result;
}

std::optional<std::filesystem::path> PathFromHandle(HANDLE file) {
  if (!file || file == INVALID_HANDLE_VALUE)
    return std::nullopt;
  std::vector<wchar_t> buffer(32768);
  const DWORD length = GetFinalPathNameByHandleW(
      file, buffer.data(), static_cast<DWORD>(buffer.size()),
      FILE_NAME_NORMALIZED);
  if (!length || length >= buffer.size())
    return std::nullopt;
  std::wstring value(buffer.data(), length);
  if (value.rfind(L"\\\\?\\", 0) == 0)
    value.erase(0, 4);
  return std::filesystem::path(value);
}

std::optional<std::filesystem::path> PathFromModule(HANDLE process,
                                                    const void *base) {
  if (!process || !base)
    return std::nullopt;
  std::vector<wchar_t> buffer(32768);
  const DWORD length = GetModuleFileNameExW(
      process, static_cast<HMODULE>(const_cast<void *>(base)), buffer.data(),
      static_cast<DWORD>(buffer.size()));
  if (!length || length >= buffer.size())
    return std::nullopt;
  return std::filesystem::path(std::wstring(buffer.data(), length));
}

} // namespace

Manifest ParseManifestText(const std::string &text) {
  Manifest manifest;
  std::set<std::string> fields;
  std::stringstream input(text);
  std::string line;
  std::size_t line_number = 0;
  while (std::getline(input, line)) {
    ++line_number;
    line = Trim(line);
    if (line.empty() || line[0] == '#')
      continue;
    const auto equals = line.find('=');
    if (equals == std::string::npos) {
      throw std::runtime_error("manifest line " + std::to_string(line_number) +
                               " has no '='");
    }
    const std::string key = Trim(line.substr(0, equals));
    const std::string value = Trim(line.substr(equals + 1));
    if (key == "patch") {
      const auto parts = Split(value, '|');
      if (parts.size() != 4) {
        throw std::runtime_error(
            "patch line must be name|rva|expected|replacement");
      }
      PatchDefinition patch;
      patch.name = parts[0];
      patch.rva = ParseInteger(parts[1], "patch RVA");
      patch.expected = ParseBytes(parts[2]);
      patch.replacement = ParseBytes(parts[3]);
      if (patch.name.empty() || patch.rva == 0 || patch.expected.empty() ||
          patch.expected.size() != patch.replacement.size()) {
        throw std::runtime_error("patch requires a name, nonzero RVA, and "
                                 "equal nonempty byte sequences");
      }
      if (std::any_of(manifest.patches.begin(), manifest.patches.end(),
                      [&](const PatchDefinition &existing) {
                        return existing.name == patch.name;
                      })) {
        throw std::runtime_error("duplicate patch name: " + patch.name);
      }
      manifest.patches.push_back(std::move(patch));
      continue;
    }
    if (!fields.insert(key).second)
      throw std::runtime_error("duplicate manifest field: " + key);
    if (key == "format")
      manifest.format = value;
    else if (key == "module")
      manifest.module = value;
    else if (key == "architecture")
      manifest.architecture = value;
    else if (key == "file_size")
      manifest.file_size = ParseInteger(value, "file_size");
    else if (key == "image_size")
      manifest.image_size = ParseInteger(value, "image_size");
    else if (key == "timestamp")
      manifest.timestamp =
          static_cast<std::uint32_t>(ParseInteger(value, "timestamp"));
    else if (key == "sha256")
      manifest.sha256 = Upper(value);
    else
      throw std::runtime_error("unknown manifest field: " + key);
  }
  if (manifest.format != "1" || manifest.module.empty() ||
      manifest.architecture != "x64" || !manifest.file_size ||
      !manifest.image_size || !fields.count("timestamp") ||
      manifest.sha256.size() != 64 || manifest.patches.empty()) {
    throw std::runtime_error("manifest is incomplete or unsupported");
  }
  return manifest;
}

Manifest LoadManifest(const std::filesystem::path &path) {
  std::ifstream input(path, std::ios::binary);
  if (!input)
    throw std::runtime_error("cannot open manifest: " + path.string());
  std::ostringstream text;
  text << input.rdbuf();
  return ParseManifestText(text.str());
}

ModuleIdentity InspectModuleFile(const std::filesystem::path &path) {
  Handle file(
      CreateFileW(path.c_str(), GENERIC_READ,
                  FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                  nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr));
  if (!file)
    throw std::runtime_error("cannot open module: " + WinError(GetLastError()));
  LARGE_INTEGER size{};
  if (!GetFileSizeEx(file.get(), &size))
    throw std::runtime_error("cannot read module size");
  Handle mapping(
      CreateFileMappingW(file.get(), nullptr, PAGE_READONLY, 0, 0, nullptr));
  if (!mapping)
    throw std::runtime_error("cannot map module: " + WinError(GetLastError()));
  const auto *base = static_cast<const std::uint8_t *>(
      MapViewOfFile(mapping.get(), FILE_MAP_READ, 0, 0, 0));
  if (!base)
    throw std::runtime_error("cannot view module: " + WinError(GetLastError()));
  ModuleIdentity identity;
  try {
    const auto *dos = reinterpret_cast<const IMAGE_DOS_HEADER *>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew <= 0 ||
        static_cast<std::uint64_t>(dos->e_lfanew) + sizeof(IMAGE_NT_HEADERS64) >
            static_cast<std::uint64_t>(size.QuadPart)) {
      throw std::runtime_error("module has an invalid DOS header");
    }
    const auto *nt =
        reinterpret_cast<const IMAGE_NT_HEADERS64 *>(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE ||
        nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
      throw std::runtime_error("module is not a 64-bit PE image");
    }
    identity.architecture = nt->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64
                                ? "x64"
                                : "unsupported";
    identity.file_size = static_cast<std::uint64_t>(size.QuadPart);
    identity.image_size = nt->OptionalHeader.SizeOfImage;
    identity.timestamp = nt->FileHeader.TimeDateStamp;
  } catch (...) {
    UnmapViewOfFile(base);
    throw;
  }
  UnmapViewOfFile(base);
  identity.sha256 = Sha256(path);
  return identity;
}

bool IdentityMatches(const Manifest &manifest, const ModuleIdentity &identity) {
  return manifest.architecture == identity.architecture &&
         manifest.file_size == identity.file_size &&
         manifest.image_size == identity.image_size &&
         manifest.timestamp == identity.timestamp &&
         Upper(manifest.sha256) == Upper(identity.sha256);
}

SiteState ClassifySite(const std::vector<std::uint8_t> &current,
                       const PatchDefinition &patch) {
  if (current == patch.expected)
    return SiteState::NeedsPatch;
  if (current == patch.replacement)
    return SiteState::AlreadyPatched;
  return SiteState::Mismatch;
}

std::string Hex(const std::vector<std::uint8_t> &bytes) {
  std::ostringstream output;
  output << std::hex << std::uppercase << std::setfill('0');
  for (const auto byte : bytes)
    output << std::setw(2) << static_cast<unsigned>(byte);
  return output.str();
}

std::string Hex(std::uint64_t value) {
  std::ostringstream output;
  output << "0x" << std::hex << std::uppercase << value;
  return output.str();
}

std::wstring Widen(const std::string &value) {
  if (value.empty())
    return {};
  const int length =
      MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value.data(),
                          static_cast<int>(value.size()), nullptr, 0);
  if (!length)
    throw std::runtime_error("invalid UTF-8 text");
  std::wstring result(length, L'\0');
  MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value.data(),
                      static_cast<int>(value.size()), result.data(), length);
  return result;
}

std::string Narrow(const std::wstring &value) {
  if (value.empty())
    return {};
  const int length = WideCharToMultiByte(
      CP_UTF8, WC_ERR_INVALID_CHARS, value.data(),
      static_cast<int>(value.size()), nullptr, 0, nullptr, nullptr);
  if (!length)
    return "<invalid path>";
  std::string result(length, '\0');
  WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value.data(),
                      static_cast<int>(value.size()), result.data(), length,
                      nullptr, nullptr);
  return result;
}

std::optional<std::filesystem::path> ProcessExecutable(DWORD pid) {
  Handle process(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid));
  if (!process)
    return std::nullopt;
  std::vector<wchar_t> buffer(32768);
  DWORD size = static_cast<DWORD>(buffer.size());
  if (!QueryFullProcessImageNameW(process.get(), 0, buffer.data(), &size))
    return std::nullopt;
  return std::filesystem::path(std::wstring(buffer.data(), size));
}

std::vector<ProcessInfo> EnumerateProcessTree(DWORD root_pid) {
  Handle snapshot(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
  if (!snapshot)
    throw std::runtime_error("process snapshot failed: " +
                             WinError(GetLastError()));
  std::map<DWORD, DWORD> parents;
  PROCESSENTRY32W entry{};
  entry.dwSize = sizeof(entry);
  if (Process32FirstW(snapshot.get(), &entry)) {
    do {
      parents[entry.th32ProcessID] = entry.th32ParentProcessID;
    } while (Process32NextW(snapshot.get(), &entry));
  }
  std::vector<ProcessInfo> result;
  for (const auto &item : parents) {
    DWORD current = item.first;
    std::set<DWORD> visited;
    bool descendant = current == root_pid;
    while (!descendant && current && visited.insert(current).second) {
      const auto parent = parents.find(current);
      if (parent == parents.end())
        break;
      current = parent->second;
      descendant = current == root_pid;
    }
    if (!descendant)
      continue;
    const auto executable = ProcessExecutable(item.first);
    if (executable)
      result.push_back({item.first, item.second, *executable});
  }
  return result;
}

std::vector<DWORD>
SelectAttachRoots(const std::vector<ProcessInfo> &processes,
                  const std::vector<DWORD> &module_processes,
                  const std::filesystem::path &firefox) {
  const std::set<DWORD> modules(module_processes.begin(),
                                module_processes.end());
  std::map<DWORD, const ProcessInfo *> by_pid;
  for (const auto &process : processes)
    by_pid[process.pid] = &process;

  std::vector<DWORD> roots;
  for (const auto &process : processes) {
    if (!modules.count(process.pid) ||
        !SamePath(process.executable, firefox))
      continue;
    const auto parent = by_pid.find(process.parent_pid);
    const bool parent_is_browser =
        parent != by_pid.end() && modules.count(parent->first) &&
        SamePath(parent->second->executable, firefox);
    if (!parent_is_browser)
      roots.push_back(process.pid);
  }
  std::sort(roots.begin(), roots.end());
  return roots;
}

std::vector<DWORD> FindAttachRoots(const std::filesystem::path &firefox,
                                   const std::wstring &module_name) {
  Handle snapshot(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
  if (!snapshot)
    throw std::runtime_error("process snapshot failed: " +
                             WinError(GetLastError()));
  std::vector<ProcessInfo> processes;
  PROCESSENTRY32W entry{};
  entry.dwSize = sizeof(entry);
  if (Process32FirstW(snapshot.get(), &entry)) {
    do {
      const auto executable = ProcessExecutable(entry.th32ProcessID);
      if (executable) {
        processes.push_back(
            {entry.th32ProcessID, entry.th32ParentProcessID, *executable});
      }
    } while (Process32NextW(snapshot.get(), &entry));
  }

  std::vector<DWORD> module_processes;
  for (const auto &process : processes) {
    if (SamePath(process.executable, firefox) &&
        FindModule(process.pid, module_name)) {
      module_processes.push_back(process.pid);
    }
  }
  return SelectAttachRoots(processes, module_processes, firefox);
}

std::optional<ModuleInfo> FindModule(DWORD pid,
                                     const std::wstring &module_name) {
  Handle snapshot(
      CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid));
  if (!snapshot)
    return std::nullopt;
  MODULEENTRY32W entry{};
  entry.dwSize = sizeof(entry);
  if (!Module32FirstW(snapshot.get(), &entry))
    return std::nullopt;
  const std::wstring wanted = Lower(module_name);
  do {
    if (Lower(entry.szModule) == wanted) {
      return ModuleInfo{reinterpret_cast<std::uintptr_t>(entry.modBaseAddr),
                        entry.szExePath};
    }
  } while (Module32NextW(snapshot.get(), &entry));
  return std::nullopt;
}

bool PatchProcess(DWORD pid, std::uintptr_t module_base,
                  const Manifest &manifest, bool dry_run, bool suspend_threads,
                  std::string &error) {
  error.clear();
  Handle process(OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ |
                                 PROCESS_VM_WRITE | PROCESS_VM_OPERATION,
                             FALSE, pid));
  if (!process) {
    error = "OpenProcess failed: " + WinError(GetLastError());
    return false;
  }
  std::optional<SuspendedThreads> suspended;
  try {
    if (suspend_threads && !dry_run)
      suspended.emplace(pid);
    struct Site {
      const PatchDefinition *patch;
      std::uintptr_t address;
      SiteState state;
    };
    std::vector<Site> sites;
    for (const auto &patch : manifest.patches) {
      std::vector<std::uint8_t> current(patch.expected.size());
      SIZE_T read = 0;
      const auto address = module_base + static_cast<std::uintptr_t>(patch.rva);
      if (!ReadProcessMemory(process.get(),
                             reinterpret_cast<const void *>(address),
                             current.data(), current.size(), &read) ||
          read != current.size()) {
        error = patch.name +
                ": ReadProcessMemory failed: " + WinError(GetLastError());
        return false;
      }
      const auto state = ClassifySite(current, patch);
      if (state == SiteState::Mismatch) {
        error = patch.name + ": expected " + Hex(patch.expected) + " at " +
                Hex(address) + ", observed " + Hex(current);
        return false;
      }
      sites.push_back({&patch, address, state});
    }
    if (suspended) {
      for (const auto &site : sites) {
        if (suspended->InstructionPointerInside(
                site.address, site.address + site.patch->expected.size())) {
          error =
              site.patch->name +
              ": a target thread is executing inside the patch region; retry";
          return false;
        }
      }
    }
    struct AppliedSite {
      const Site *site;
      DWORD original_protection;
    };
    std::vector<AppliedSite> written;
    for (const auto &site : sites) {
      if (site.state == SiteState::AlreadyPatched) {
        std::cout << "ALREADY_APPLIED pid=" << pid
                  << " patch=" << site.patch->name
                  << " address=" << Hex(site.address) << '\n';
        continue;
      }
      if (dry_run) {
        std::cout << "WOULD_APPLY pid=" << pid << " patch=" << site.patch->name
                  << " address=" << Hex(site.address) << '\n';
        continue;
      }
      DWORD old_protection = 0;
      if (!VirtualProtectEx(process.get(),
                            reinterpret_cast<void *>(site.address),
                            site.patch->replacement.size(),
                            PAGE_EXECUTE_READWRITE, &old_protection)) {
        error = site.patch->name +
                ": VirtualProtectEx failed: " + WinError(GetLastError());
        break;
      }
      written.push_back({&site, old_protection});
      SIZE_T written_size = 0;
      const bool write_ok =
          WriteProcessMemory(process.get(),
                             reinterpret_cast<void *>(site.address),
                             site.patch->replacement.data(),
                             site.patch->replacement.size(), &written_size) &&
          written_size == site.patch->replacement.size();
      DWORD ignored = 0;
      const bool protect_ok =
          VirtualProtectEx(process.get(),
                           reinterpret_cast<void *>(site.address),
                           site.patch->replacement.size(), old_protection,
                           &ignored) != FALSE;
      if (!write_ok || !protect_ok) {
        error = site.patch->name +
                ": memory write or protection restore failed: " +
                WinError(GetLastError());
        break;
      }
      if (!FlushInstructionCache(process.get(),
                                 reinterpret_cast<const void *>(site.address),
                                 site.patch->replacement.size())) {
        error = site.patch->name +
                ": FlushInstructionCache failed: " + WinError(GetLastError());
        break;
      }
      std::cout << "APPLIED pid=" << pid << " patch=" << site.patch->name
                << " address=" << Hex(site.address) << '\n';
    }
    if (!error.empty()) {
      for (auto iterator = written.rbegin(); iterator != written.rend();
           ++iterator) {
        const Site &site = *iterator->site;
        DWORD temporary_protection = 0;
        if (VirtualProtectEx(process.get(),
                             reinterpret_cast<void *>(site.address),
                             site.patch->expected.size(),
                             PAGE_EXECUTE_READWRITE, &temporary_protection)) {
          SIZE_T restored = 0;
          WriteProcessMemory(process.get(),
                             reinterpret_cast<void *>(site.address),
                             site.patch->expected.data(),
                             site.patch->expected.size(), &restored);
          DWORD ignored = 0;
          VirtualProtectEx(process.get(),
                           reinterpret_cast<void *>(site.address),
                           site.patch->expected.size(),
                           iterator->original_protection, &ignored);
          FlushInstructionCache(process.get(),
                                reinterpret_cast<const void *>(site.address),
                                site.patch->expected.size());
        }
      }
      return false;
    }
    return true;
  } catch (const std::exception &exception) {
    error = exception.what();
    return false;
  }
}

int RunAttach(DWORD root_pid, const Manifest &manifest, bool dry_run,
              bool once) {
  const auto root_executable = ProcessExecutable(root_pid);
  if (!root_executable)
    throw std::runtime_error("cannot resolve the root process executable");
  std::map<DWORD, std::filesystem::path> handled;
  std::map<std::wstring, ModuleIdentity> identities;
  bool initial_scan = true;
  do {
    bool root_seen = false;
    for (const auto &process : EnumerateProcessTree(root_pid)) {
      if (process.pid == root_pid)
        root_seen = true;
      if (!SamePath(process.executable, *root_executable) ||
          handled.count(process.pid))
        continue;
      const auto module = FindModule(process.pid, Widen(manifest.module));
      if (!module)
        continue;
      const auto identity_key = Lower(module->path.wstring());
      auto identity = identities.find(identity_key);
      if (identity == identities.end()) {
        identity =
            identities.emplace(identity_key, InspectModuleFile(module->path))
                .first;
      }
      if (!IdentityMatches(manifest, identity->second)) {
        std::cerr << "REFUSED pid=" << process.pid
                  << " module=" << module->path.string()
                  << " sha256=" << identity->second.sha256 << '\n';
        handled[process.pid] = module->path;
        continue;
      }
      std::string error;
      if (!PatchProcess(process.pid, module->base, manifest, dry_run, true,
                        error)) {
        std::cerr << "REFUSED pid=" << process.pid << " reason=" << error
                  << '\n';
      }
      handled[process.pid] = module->path;
    }
    if (initial_scan) {
      std::cout << "INITIAL_SCAN_COMPLETE root=" << root_pid
                << " processes=" << handled.size() << '\n';
      initial_scan = false;
    }
    if (once)
      break;
    if (!root_seen || g_stop.load())
      break;
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
  } while (!g_stop.load());
  return 0;
}

int RunLaunch(const std::filesystem::path &firefox,
              const std::vector<std::wstring> &arguments,
              const Manifest &manifest, bool dry_run) {
  const auto installed_module = firefox.parent_path() / Widen(manifest.module);
  const auto installed_identity = InspectModuleFile(installed_module);
  if (!IdentityMatches(manifest, installed_identity)) {
    throw std::runtime_error("manifest does not match " +
                             installed_module.string() + " (observed SHA-256 " +
                             installed_identity.sha256 + ")");
  }
  std::wstring command = QuoteArgument(firefox.wstring());
  for (const auto &argument : arguments)
    command += L" " + QuoteArgument(argument);
  std::vector<wchar_t> mutable_command(command.begin(), command.end());
  mutable_command.push_back(L'\0');
  STARTUPINFOW startup{};
  startup.cb = sizeof(startup);
  PROCESS_INFORMATION created{};
  if (!CreateProcessW(firefox.c_str(), mutable_command.data(), nullptr, nullptr,
                      FALSE, DEBUG_PROCESS | CREATE_UNICODE_ENVIRONMENT,
                      nullptr, firefox.parent_path().c_str(), &startup,
                      &created)) {
    throw std::runtime_error("CreateProcess failed: " +
                             WinError(GetLastError()));
  }
  CloseHandle(created.hProcess);
  CloseHandle(created.hThread);
  DebugSetProcessKillOnExit(FALSE);
  std::map<DWORD, HANDLE> processes;
  std::set<DWORD> live_processes;
  std::map<std::wstring, ModuleIdentity> identities;
  while (!g_stop.load()) {
    DEBUG_EVENT event{};
    if (!WaitForDebugEvent(&event, 100)) {
      if (GetLastError() == ERROR_SEM_TIMEOUT)
        continue;
      throw std::runtime_error("WaitForDebugEvent failed: " +
                               WinError(GetLastError()));
    }
    DWORD disposition = DBG_CONTINUE;
    if (event.dwDebugEventCode == CREATE_PROCESS_DEBUG_EVENT) {
      live_processes.insert(event.dwProcessId);
      processes[event.dwProcessId] = event.u.CreateProcessInfo.hProcess;
      std::cout << "PROCESS_STARTED pid=" << event.dwProcessId << " parent="
                << (event.dwProcessId == created.dwProcessId
                        ? 0
                        : created.dwProcessId)
                << '\n';
      if (event.u.CreateProcessInfo.hFile)
        CloseHandle(event.u.CreateProcessInfo.hFile);
    } else if (event.dwDebugEventCode == LOAD_DLL_DEBUG_EVENT) {
      try {
        auto path = PathFromHandle(event.u.LoadDll.hFile);
        const auto process = processes.find(event.dwProcessId);
        if (!path && process != processes.end()) {
          path = PathFromModule(process->second, event.u.LoadDll.lpBaseOfDll);
        }
        if (path && Lower(path->filename().wstring()) ==
                        Lower(Widen(manifest.module))) {
          const auto identity_key = Lower(path->wstring());
          auto identity = identities.find(identity_key);
          if (identity == identities.end()) {
            identity =
                identities.emplace(identity_key, InspectModuleFile(*path))
                    .first;
          }
          if (!IdentityMatches(manifest, identity->second)) {
            std::cerr << "REFUSED pid=" << event.dwProcessId
                      << " module=" << path->string()
                      << " sha256=" << identity->second.sha256 << '\n';
          } else {
            std::string error;
            if (!PatchProcess(event.dwProcessId,
                              reinterpret_cast<std::uintptr_t>(
                                  event.u.LoadDll.lpBaseOfDll),
                              manifest, dry_run, false, error)) {
              std::cerr << "REFUSED pid=" << event.dwProcessId
                        << " reason=" << error << '\n';
            }
          }
        }
      } catch (const std::exception &exception) {
        std::cerr << "REFUSED pid=" << event.dwProcessId
                  << " reason=" << exception.what() << '\n';
      }
      if (event.u.LoadDll.hFile)
        CloseHandle(event.u.LoadDll.hFile);
    } else if (event.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT) {
      live_processes.erase(event.dwProcessId);
      const auto process = processes.find(event.dwProcessId);
      if (process != processes.end())
        CloseHandle(process->second);
      processes.erase(event.dwProcessId);
    } else if (event.dwDebugEventCode == EXCEPTION_DEBUG_EVENT) {
      const DWORD code = event.u.Exception.ExceptionRecord.ExceptionCode;
      if (code != EXCEPTION_BREAKPOINT && code != EXCEPTION_SINGLE_STEP) {
        disposition = DBG_EXCEPTION_NOT_HANDLED;
      }
    }
    ContinueDebugEvent(event.dwProcessId, event.dwThreadId, disposition);
    if (live_processes.empty())
      break;
  }
  for (const auto &process : live_processes)
    DebugActiveProcessStop(process);
  for (const auto &process : processes)
    CloseHandle(process.second);
  return 0;
}

void RequestStop() { g_stop.store(true); }

} // namespace livepatch
