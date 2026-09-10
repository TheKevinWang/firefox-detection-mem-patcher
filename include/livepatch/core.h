/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#pragma once

#include <windows.h>

#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <vector>

namespace livepatch {

struct PatchDefinition {
  std::string name;
  std::uint64_t rva = 0;
  std::vector<std::uint8_t> expected;
  std::vector<std::uint8_t> replacement;
};

struct Manifest {
  std::string format;
  std::string module;
  std::string architecture;
  std::uint64_t file_size = 0;
  std::uint64_t image_size = 0;
  std::uint32_t timestamp = 0;
  std::string sha256;
  std::vector<PatchDefinition> patches;
};

struct ModuleIdentity {
  std::string architecture;
  std::uint64_t file_size = 0;
  std::uint64_t image_size = 0;
  std::uint32_t timestamp = 0;
  std::string sha256;
};

enum class SiteState {
  NeedsPatch,
  AlreadyPatched,
  Mismatch,
};

struct ProcessInfo {
  DWORD pid = 0;
  DWORD parent_pid = 0;
  std::filesystem::path executable;
};

struct ModuleInfo {
  std::uintptr_t base = 0;
  std::filesystem::path path;
};

Manifest ParseManifestText(const std::string &text);
Manifest LoadManifest(const std::filesystem::path &path);
ModuleIdentity InspectModuleFile(const std::filesystem::path &path);
bool IdentityMatches(const Manifest &manifest, const ModuleIdentity &identity);
SiteState ClassifySite(const std::vector<std::uint8_t> &current,
                       const PatchDefinition &patch);
std::string Hex(const std::vector<std::uint8_t> &bytes);
std::string Hex(std::uint64_t value);
std::wstring Widen(const std::string &value);
std::string Narrow(const std::wstring &value);

std::vector<ProcessInfo> EnumerateProcessTree(DWORD root_pid);
std::vector<DWORD>
SelectAttachRoots(const std::vector<ProcessInfo> &processes,
                  const std::vector<DWORD> &module_processes,
                  const std::filesystem::path &firefox);
std::vector<DWORD> FindAttachRoots(const std::filesystem::path &firefox,
                                   const std::wstring &module_name);
std::optional<ModuleInfo> FindModule(DWORD pid,
                                     const std::wstring &module_name);
std::optional<std::filesystem::path> ProcessExecutable(DWORD pid);
bool PatchProcess(DWORD pid, std::uintptr_t module_base,
                  const Manifest &manifest, bool dry_run, bool suspend_threads,
                  std::string &error);

int RunAttach(DWORD root_pid, const Manifest &manifest, bool dry_run,
              bool once);
int RunLaunch(const std::filesystem::path &firefox,
              const std::vector<std::wstring> &arguments,
              const Manifest &manifest, bool dry_run);

void RequestStop();

} // namespace livepatch
