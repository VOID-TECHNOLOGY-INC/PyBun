# This file is auto-generated. Do not edit by hand.
class Pybun < Formula
  desc "Rust-based single-binary Python toolchain."
  homepage "https://github.com/VOID-TECHNOLOGY-INC/PyBun"
  version "0.1.25"
  license "MIT"

  if ENV["HOMEBREW_PYBUN_TEST_TARBALL"]
    url ENV["HOMEBREW_PYBUN_TEST_TARBALL"]
    sha256 ENV["HOMEBREW_PYBUN_TEST_SHA256"]
  else
    on_macos do
      if Hardware::CPU.arm?
        url "https://github.com/VOID-TECHNOLOGY-INC/PyBun/releases/download/v0.1.25/pybun-aarch64-apple-darwin.tar.gz"
        sha256 "534881ad0ce9c12d9ebbd2b183abad6617123efe5605c59f275bbb7f40b65a8d"
      else
        url "https://github.com/VOID-TECHNOLOGY-INC/PyBun/releases/download/v0.1.25/pybun-x86_64-apple-darwin.tar.gz"
        sha256 "b7cf6ee61085ea496e27dfbfac5a8b186aba1a317851ec74bff09312db059256"
      end
    end

    on_linux do
      if Hardware::CPU.arm?
        url "https://github.com/VOID-TECHNOLOGY-INC/PyBun/releases/download/v0.1.25/pybun-aarch64-unknown-linux-gnu.tar.gz"
        sha256 "74d53a7951889366c0f7d3cc1c92cd9e630e3fb313c3c82c4f6a79382a0a65ac"
      else
        url "https://github.com/VOID-TECHNOLOGY-INC/PyBun/releases/download/v0.1.25/pybun-x86_64-unknown-linux-gnu.tar.gz"
        sha256 "1f0d0b328a5010e0bbf0a2dbed7ebf34e93d8977372891b92afe7fd5866e1dc7"
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
