# This file is auto-generated. Do not edit by hand.
class Pybun < Formula
  desc "Rust-based single-binary Python toolchain."
  homepage "https://github.com/VOID-TECHNOLOGY-INC/PyBun"
  version "0.1.17"
  license "MIT"

  if ENV["HOMEBREW_PYBUN_TEST_TARBALL"]
    url ENV["HOMEBREW_PYBUN_TEST_TARBALL"]
    sha256 ENV["HOMEBREW_PYBUN_TEST_SHA256"]
  else
    on_macos do
      if Hardware::CPU.arm?
        url "https://github.com/VOID-TECHNOLOGY-INC/PyBun/releases/download/v0.1.17/pybun-aarch64-apple-darwin.tar.gz"
        sha256 "72979bab9c40b1a8a8ee001ce5d63c36fedd8a5c5310c5e13a5011f233a312f6"
      else
        url "https://github.com/VOID-TECHNOLOGY-INC/PyBun/releases/download/v0.1.17/pybun-x86_64-apple-darwin.tar.gz"
        sha256 "1efdf061e00d8d7fa30150fa3d942b696572e6c0ceeacc1e7b1b6b0ea167a4aa"
      end
    end

    on_linux do
      if Hardware::CPU.arm?
        url "https://github.com/VOID-TECHNOLOGY-INC/PyBun/releases/download/v0.1.17/pybun-aarch64-unknown-linux-gnu.tar.gz"
        sha256 "bc00b7b7b3993ea259579450bb9386a6a113863324b39f99cc81714c7f62aba4"
      else
        url "https://github.com/VOID-TECHNOLOGY-INC/PyBun/releases/download/v0.1.17/pybun-x86_64-unknown-linux-gnu.tar.gz"
        sha256 "870fa2b52619c99575aa7fc1efd97e706c4260eb2f2aa8858275a30a45bae9cb"
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
