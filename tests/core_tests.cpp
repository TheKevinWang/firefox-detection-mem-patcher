/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "livepatch/core.h"

#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

void Require(bool condition, const char *message) {
  if (!condition)
    throw std::runtime_error(message);
}

template <typename Function>
void RequireThrows(Function function, const char *message) {
  try {
    function();
  } catch (const std::exception &) {
    return;
  }
  throw std::runtime_error(message);
}

std::string ValidManifest() {
  return "format=1\n"
         "module=xul.dll\n"
         "architecture=x64\n"
         "file_size=100\n"
         "image_size=0x200\n"
         "timestamp=0x1234\n"
         "sha256="
         "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n"
         "patch=navigator.webdriver|0x10|56575553|31C0C390\n";
}

} // namespace

int main() {
  try {
    const auto manifest = livepatch::ParseManifestText(ValidManifest());
    Require(manifest.patches.size() == 1, "valid manifest patch count");
    Require(manifest.patches[0].rva == 0x10, "valid manifest RVA");
    Require(
        manifest.sha256 ==
            "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF",
        "SHA-256 normalization");
    Require(livepatch::ClassifySite({0x56, 0x57, 0x55, 0x53},
                                    manifest.patches[0]) ==
                livepatch::SiteState::NeedsPatch,
            "expected bytes classification");
    Require(livepatch::ClassifySite({0x31, 0xC0, 0xC3, 0x90},
                                    manifest.patches[0]) ==
                livepatch::SiteState::AlreadyPatched,
            "replacement bytes classification");
    Require(livepatch::ClassifySite({0, 0, 0, 0}, manifest.patches[0]) ==
                livepatch::SiteState::Mismatch,
            "mismatch classification");
    livepatch::ModuleIdentity identity{
        "x64", 100, 0x200, 0x1234,
        "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF"};
    Require(livepatch::IdentityMatches(manifest, identity),
            "matching module identity");
    identity.timestamp++;
    Require(!livepatch::IdentityMatches(manifest, identity),
            "mismatched module identity");
    auto zero_timestamp_text = ValidManifest();
    zero_timestamp_text.replace(zero_timestamp_text.find("timestamp=0x1234"),
                                16, "timestamp=0");
    const auto zero_timestamp_manifest =
        livepatch::ParseManifestText(zero_timestamp_text);
    identity.timestamp = 0;
    Require(zero_timestamp_manifest.timestamp == 0,
            "zero timestamp manifest parsing");
    Require(livepatch::IdentityMatches(zero_timestamp_manifest, identity),
            "zero timestamp module identity");
    RequireThrows(
        [] {
          auto text = ValidManifest();
          text.erase(text.find("timestamp=0x1234\n"), 17);
          livepatch::ParseManifestText(text);
        },
        "missing timestamp rejection");
    RequireThrows(
        [] {
          livepatch::ParseManifestText(ValidManifest() + "module=again.dll\n");
        },
        "duplicate field rejection");
    RequireThrows(
        [] {
          auto text = ValidManifest();
          text.replace(text.find("56575553"), 8, "5657");
          livepatch::ParseManifestText(text);
        },
        "unequal patch length rejection");
    RequireThrows(
        [] {
          auto text = ValidManifest();
          text.replace(text.find("56575553"), 8, "GG575553");
          livepatch::ParseManifestText(text);
        },
        "invalid hex rejection");
    const std::filesystem::path firefox = L"C:\\Browser\\firefox.exe";
    const std::filesystem::path other = L"C:\\Other\\firefox.exe";
    const std::vector<livepatch::ProcessInfo> processes{
        {5, 1, firefox},   {10, 5, firefox}, {20, 10, firefox},
        {30, 10, firefox}, {40, 10, other},  {100, 1, firefox},
        {110, 100, firefox}};
    auto roots = livepatch::SelectAttachRoots(
        processes, {10, 20, 30, 40, 100, 110}, firefox);
    Require(roots == std::vector<DWORD>({10, 100}),
            "attach root selection and ambiguity");
    roots = livepatch::SelectAttachRoots(processes, {5, 10, 20, 30}, firefox);
    Require(roots == std::vector<DWORD>({5}),
            "topmost module-loaded attach root selection");
    std::cout << "all livepatch core tests passed\n";
    return 0;
  } catch (const std::exception &exception) {
    std::cerr << exception.what() << '\n';
    return 1;
  }
}
