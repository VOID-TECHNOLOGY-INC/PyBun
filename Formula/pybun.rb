# This file is auto-generated. Do not edit by hand.
class Pybun < Formula
  desc "Rust-based single-binary Python toolchain."
  homepage "https://github.com/VOID-TECHNOLOGY-INC/PyBun"
  version "0.1.23"
  license "MIT"

  if ENV["HOMEBREW_PYBUN_TEST_TARBALL"]
    url ENV["HOMEBREW_PYBUN_TEST_TARBALL"]
    sha256 ENV["HOMEBREW_PYBUN_TEST_SHA256"]
  else
    on_macos do
      if Hardware::CPU.arm?
        url "https://github.com/VOID-TECHNOLOGY-INC/PyBun/releases/download/v0.1.23/pybun-aarch64-apple-darwin.tar.gz"
        sha256 "ae996215d940b535912c55447969a78531eb1a1851f1511169363dc6f40940cf"
      else
        url "https://github.com/VOID-TECHNOLOGY-INC/PyBun/releases/download/v0.1.23/pybun-x86_64-apple-darwin.tar.gz"
        sha256 "53ccce7e840a6a1496997da294262c6b35735b0358a1d9da7a5563e737d8d377"
      end
    end

    on_linux do
      if Hardware::CPU.arm?
        url "https://github.com/VOID-TECHNOLOGY-INC/PyBun/releases/download/v0.1.23/pybun-aarch64-unknown-linux-gnu.tar.gz"
        sha256 "7d9d3791273e3c3731c7976de72088630b4e44145389af2addc1852f52477814"
      else
        url "https://github.com/VOID-TECHNOLOGY-INC/PyBun/releases/download/v0.1.23/pybun-x86_64-unknown-linux-gnu.tar.gz"
        sha256 "c689b673a741ccd5d7f8a387819d3d111ebc98b294682464edac99692229d216"
      end
    end
  end

  def install
    if File.exist?("pybun")
      bin.install "pybun"
    else
      bin.install Dir["pybun-*/pybun"]
    end
    bin.install_symlink "pybun" => "pybun-cli"
  end

  test do
    system "#{bin}/pybun", "--version"
  end
end
