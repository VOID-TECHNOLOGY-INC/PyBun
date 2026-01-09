# This file is auto-generated. Do not edit by hand.
class Pybun < Formula
  desc "Rust-based single-binary Python toolchain."
  homepage "https://github.com/VOID-TECHNOLOGY-INC/PyBun"
  version "0.1.6"
  license "MIT"

  if ENV["HOMEBREW_PYBUN_TEST_TARBALL"]
    url ENV["HOMEBREW_PYBUN_TEST_TARBALL"]
    sha256 ENV["HOMEBREW_PYBUN_TEST_SHA256"]
  else
    on_macos do
      if Hardware::CPU.arm?
        url "https://github.com/VOID-TECHNOLOGY-INC/PyBun/releases/download/v0.1.6/pybun-aarch64-apple-darwin.tar.gz"
        sha256 "71d1af54a5c0dd2919a393f39c8d3cc2325646dffef7f7b25571e505fa5bb4e0"
      else
        url "https://github.com/VOID-TECHNOLOGY-INC/PyBun/releases/download/v0.1.6/pybun-x86_64-apple-darwin.tar.gz"
        sha256 "cd0a4931cda38b3212461174bc0b59f4c611de60c69ab1a3ba31dedd614cf0e8"
      end
    end

    on_linux do
      if Hardware::CPU.arm?
        url "https://github.com/VOID-TECHNOLOGY-INC/PyBun/releases/download/v0.1.6/pybun-aarch64-unknown-linux-gnu.tar.gz"
        sha256 "84f0c955f2e7d8bc7dd67368f7767848895966a846d03b64d110168e98d014f0"
      else
        url "https://github.com/VOID-TECHNOLOGY-INC/PyBun/releases/download/v0.1.6/pybun-x86_64-unknown-linux-gnu.tar.gz"
        sha256 "8bf660572724eacca80ae8ddf38c61290d1f20cb0f58452d80612704bb2a27db"
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
