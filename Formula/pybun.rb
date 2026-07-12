# This file is auto-generated. Do not edit by hand.
class Pybun < Formula
  desc "Rust-based single-binary Python toolchain."
  homepage "https://github.com/VOID-TECHNOLOGY-INC/PyBun"
  version "0.1.22"
  license "MIT"

  if ENV["HOMEBREW_PYBUN_TEST_TARBALL"]
    url ENV["HOMEBREW_PYBUN_TEST_TARBALL"]
    sha256 ENV["HOMEBREW_PYBUN_TEST_SHA256"]
  else
    on_macos do
      if Hardware::CPU.arm?
        url "https://github.com/VOID-TECHNOLOGY-INC/PyBun/releases/download/v0.1.22/pybun-aarch64-apple-darwin.tar.gz"
        sha256 "b4704e1f7b39b2bef7c2cd93541c6da564278f0fa6681fc775461b6088516be7"
      else
        url "https://github.com/VOID-TECHNOLOGY-INC/PyBun/releases/download/v0.1.22/pybun-x86_64-apple-darwin.tar.gz"
        sha256 "3ad0cefaca83eee10ea552c6cb250090a69cf43b5cfcb693565a6af80d9d3015"
      end
    end

    on_linux do
      if Hardware::CPU.arm?
        url "https://github.com/VOID-TECHNOLOGY-INC/PyBun/releases/download/v0.1.22/pybun-aarch64-unknown-linux-gnu.tar.gz"
        sha256 "6333c5982d4fd2efb233bc8da4b57b07b6f44530ec3fd92b75403173da2cde94"
      else
        url "https://github.com/VOID-TECHNOLOGY-INC/PyBun/releases/download/v0.1.22/pybun-x86_64-unknown-linux-gnu.tar.gz"
        sha256 "0d2e6b53afeae1f9bf147d836b15985a6b7aedee3cf869e66a909ccd1f20efa2"
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
