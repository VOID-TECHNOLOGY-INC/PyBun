# This file is auto-generated. Do not edit by hand.
class Pybun < Formula
  desc "Rust-based single-binary Python toolchain."
  homepage "https://github.com/VOID-TECHNOLOGY-INC/PyBun"
  version "0.1.27"
  license "MIT"

  if ENV["HOMEBREW_PYBUN_TEST_TARBALL"]
    url ENV["HOMEBREW_PYBUN_TEST_TARBALL"]
    sha256 ENV["HOMEBREW_PYBUN_TEST_SHA256"]
  else
    on_macos do
      if Hardware::CPU.arm?
        url "https://github.com/VOID-TECHNOLOGY-INC/PyBun/releases/download/v0.1.27/pybun-aarch64-apple-darwin.tar.gz"
        sha256 "64aa19ae03ca2a7ba3ea69186ad6fe23dfb7f6e9a9c2ee90e881e3285d69d963"
      else
        url "https://github.com/VOID-TECHNOLOGY-INC/PyBun/releases/download/v0.1.27/pybun-x86_64-apple-darwin.tar.gz"
        sha256 "783b228c62289ec522425addb8074a586a9543911e666e7e9869443350ce2db1"
      end
    end

    on_linux do
      if Hardware::CPU.arm?
        url "https://github.com/VOID-TECHNOLOGY-INC/PyBun/releases/download/v0.1.27/pybun-aarch64-unknown-linux-gnu.tar.gz"
        sha256 "b1f626aff33c5496e887cd5ba075f4ae7698a41e8553b5b753c753aeefeb09dc"
      else
        url "https://github.com/VOID-TECHNOLOGY-INC/PyBun/releases/download/v0.1.27/pybun-x86_64-unknown-linux-gnu.tar.gz"
        sha256 "464b6a411c2180167ea5d3b9aa3740d762ad1aa1268d235dc98fee8def272293"
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
