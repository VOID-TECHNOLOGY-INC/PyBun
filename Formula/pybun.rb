# This file is auto-generated. Do not edit by hand.
class Pybun < Formula
  desc "Rust-based single-binary Python toolchain."
  homepage "https://github.com/VOID-TECHNOLOGY-INC/PyBun"
  version "0.2.0"
  license "MIT"

  if ENV["HOMEBREW_PYBUN_TEST_TARBALL"]
    url ENV["HOMEBREW_PYBUN_TEST_TARBALL"]
    sha256 ENV["HOMEBREW_PYBUN_TEST_SHA256"]
  else
    on_macos do
      if Hardware::CPU.arm?
        url "https://github.com/VOID-TECHNOLOGY-INC/PyBun/releases/download/v0.2.0/pybun-aarch64-apple-darwin.tar.gz"
        sha256 "fbc944317e01e62e826673ebbae9673750ba1ce6b9ce4656dd8c7de1f1fcef93"
      else
        url "https://github.com/VOID-TECHNOLOGY-INC/PyBun/releases/download/v0.2.0/pybun-x86_64-apple-darwin.tar.gz"
        sha256 "dd9fdb62695bfa42f09db4054c5e77ad8ecd5a73b68ac7b5869a13dda8aa5b5b"
      end
    end

    on_linux do
      if Hardware::CPU.arm?
        url "https://github.com/VOID-TECHNOLOGY-INC/PyBun/releases/download/v0.2.0/pybun-aarch64-unknown-linux-gnu.tar.gz"
        sha256 "633818564c6be65deb3651fe77e3f073b7b3bdbd8b7fb519cd0429af6fdb45c5"
      else
        url "https://github.com/VOID-TECHNOLOGY-INC/PyBun/releases/download/v0.2.0/pybun-x86_64-unknown-linux-gnu.tar.gz"
        sha256 "330d9551658022306d12a007c8207ac78b6f3c1e28ca785b8e91c01cf7beb2d6"
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
