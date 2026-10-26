# This file is auto-generated. Do not edit by hand.
class Pybun < Formula
  desc "Rust-based single-binary Python toolchain."
  homepage "https://github.com/VOID-TECHNOLOGY-INC/PyBun"
  version "0.2.6"
  license "MIT"

  if ENV["HOMEBREW_PYBUN_TEST_TARBALL"]
    url ENV["HOMEBREW_PYBUN_TEST_TARBALL"]
    sha256 ENV["HOMEBREW_PYBUN_TEST_SHA256"]
  else
    on_macos do
      if Hardware::CPU.arm?
        url "https://github.com/VOID-TECHNOLOGY-INC/PyBun/releases/download/v0.2.6/pybun-aarch64-apple-darwin.tar.gz"
        sha256 "2ef88984d4b1ca8a4fe4b7e8eaafc5dee51a27c304d5bfbd5bb2b04ae182a454"
      else
        url "https://github.com/VOID-TECHNOLOGY-INC/PyBun/releases/download/v0.2.6/pybun-x86_64-apple-darwin.tar.gz"
        sha256 "51a93d14a9cf8cc48d17c62ab6f6608e4a1b6b91145dfc9ece4ff510770b58ab"
      end
    end

    on_linux do
      if Hardware::CPU.arm?
        url "https://github.com/VOID-TECHNOLOGY-INC/PyBun/releases/download/v0.2.6/pybun-aarch64-unknown-linux-gnu.tar.gz"
        sha256 "ab9aeb57ab7cce30bc0219f57d1156ec86102efdc4375dc4ce17b04ef0fe9db7"
      else
        url "https://github.com/VOID-TECHNOLOGY-INC/PyBun/releases/download/v0.2.6/pybun-x86_64-unknown-linux-gnu.tar.gz"
        sha256 "c491db09f7a4565ef84d4d6c843216276232df9ac026caf5e5d2a5fe0b8afbfa"
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
