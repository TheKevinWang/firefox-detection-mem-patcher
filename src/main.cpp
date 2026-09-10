/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "livepatch/core.h"

#include <windows.h>

#include <filesystem>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

BOOL WINAPI ConsoleHandler(DWORD signal) {
  if (signal == CTRL_C_EVENT || signal == CTRL_BREAK_EVENT ||
      signal == CTRL_CLOSE_EVENT) {
    livepatch::RequestStop();
    return TRUE;
  }
  return FALSE;
}

void Usage(std::ostream &output) {
  output
      << "Usage:\n"
      << "  firefox-detection-mem-patcher inspect --firefox <path> --manifest "
         "<path>\n"
      << "  firefox-detection-mem-patcher attach (--pid <pid> | --firefox "
         "<path>) "
         "--manifest <path> [--dry-run] [--once]\n"
      << "  firefox-detection-mem-patcher launch --firefox <path> --manifest "
         "<path> [--dry-run] [-- <args...>]\n";
}

struct Options {
  std::wstring command;
  std::filesystem::path firefox;
  std::filesystem::path manifest;
  DWORD pid = 0;
  bool dry_run = false;
  bool once = false;
  std::vector<std::wstring> arguments;
};

Options ParseOptions(int argc, wchar_t **argv) {
  if (argc < 2)
    throw std::runtime_error("missing command");
  Options options;
  options.command = argv[1];
  bool passthrough = false;
  for (int i = 2; i < argc; ++i) {
    std::wstring argument = argv[i];
    if (passthrough) {
      options.arguments.push_back(argument);
    } else if (argument == L"--") {
      passthrough = true;
    } else if (argument == L"--firefox" && i + 1 < argc) {
      options.firefox = argv[++i];
    } else if (argument == L"--manifest" && i + 1 < argc) {
      options.manifest = argv[++i];
    } else if (argument == L"--pid" && i + 1 < argc) {
      const auto value = std::stoull(argv[++i]);
      if (value == 0 || value > MAXDWORD)
        throw std::runtime_error("invalid PID");
      options.pid = static_cast<DWORD>(value);
    } else if (argument == L"--dry-run") {
      options.dry_run = true;
    } else if (argument == L"--once") {
      options.once = true;
    } else {
      throw std::runtime_error("unknown or incomplete option: " +
                               livepatch::Narrow(argument));
    }
  }
  if (options.manifest.empty())
    throw std::runtime_error("--manifest is required");
  if ((options.command == L"inspect" || options.command == L"launch") &&
      options.firefox.empty()) {
    throw std::runtime_error("--firefox is required");
  }
  if (options.command == L"attach" &&
      ((!options.pid && options.firefox.empty()) ||
       (options.pid && !options.firefox.empty()))) {
    throw std::runtime_error(
        "attach requires exactly one of --pid or --firefox");
  }
  if (options.command != L"inspect" && options.command != L"attach" &&
      options.command != L"launch") {
    throw std::runtime_error("unknown command");
  }
  return options;
}

} // namespace

int wmain(int argc, wchar_t **argv) {
  try {
    std::cout.setf(std::ios::unitbuf);
    std::cerr.setf(std::ios::unitbuf);
    if (argc == 2 && (std::wstring(argv[1]) == L"--help" ||
                      std::wstring(argv[1]) == L"-h")) {
      Usage(std::cout);
      return 0;
    }
    if (argc == 2 && std::wstring(argv[1]) == L"--version") {
      std::cout << "firefox-detection-mem-patcher "
                << FIREFOX_DETECTION_MEM_PATCHER_VERSION << '\n';
      return 0;
    }
    SetConsoleCtrlHandler(ConsoleHandler, TRUE);
    const auto options = ParseOptions(argc, argv);
    const auto manifest = livepatch::LoadManifest(options.manifest);
    if (options.command == L"inspect") {
      const auto xul =
          options.firefox.parent_path() / livepatch::Widen(manifest.module);
      const auto identity = livepatch::InspectModuleFile(xul);
      if (!livepatch::IdentityMatches(manifest, identity)) {
        std::cerr << "REFUSED module=" << xul.string()
                  << " arch=" << identity.architecture
                  << " file_size=" << identity.file_size
                  << " image_size=" << livepatch::Hex(identity.image_size)
                  << " timestamp=" << livepatch::Hex(identity.timestamp)
                  << " sha256=" << identity.sha256 << '\n';
        return 2;
      }
      std::cout << "MATCH module=" << manifest.module
                << " arch=" << identity.architecture
                << " sha256=" << identity.sha256
                << " patches=" << manifest.patches.size() << '\n';
      return 0;
    }
    if (options.command == L"attach") {
      DWORD root_pid = options.pid;
      if (!root_pid) {
        const auto roots = livepatch::FindAttachRoots(
            options.firefox, livepatch::Widen(manifest.module));
        if (roots.empty()) {
          throw std::runtime_error(
              "no running browser with the supplied executable path and "
              "module was found");
        }
        if (roots.size() != 1) {
          std::ostringstream message;
          message << "multiple running browser roots match --firefox; use "
                     "--pid with one of:";
          for (const auto pid : roots)
            message << ' ' << pid;
          throw std::runtime_error(message.str());
        }
        root_pid = roots.front();
        std::cout << "ATTACH_ROOT pid=" << root_pid
                  << " firefox=" << options.firefox.string() << '\n';
      }
      return livepatch::RunAttach(root_pid, manifest, options.dry_run,
                                  options.once);
    }
    return livepatch::RunLaunch(options.firefox, options.arguments, manifest,
                                options.dry_run);
  } catch (const std::exception &exception) {
    std::cerr << "ERROR " << exception.what() << '\n';
    Usage(std::cerr);
    return 1;
  }
}
