# This file is auto-generated. Do not edit by hand.
class Pybun < Formula
  desc "Rust-based single-binary Python toolchain."
  homepage "https://github.com/VOID-TECHNOLOGY-INC/PyBun"
  version "0.1.18"
  license "MIT"

  if ENV["HOMEBREW_PYBUN_TEST_TARBALL"]
    url ENV["HOMEBREW_PYBUN_TEST_TARBALL"]
    sha256 ENV["HOMEBREW_PYBUN_TEST_SHA256"]
  else
    on_macos do
      if Hardware::CPU.arm?
        url "https://github.com/VOID-TECHNOLOGY-INC/PyBun/releases/download/v0.1.18/pybun-aarch64-apple-darwin.tar.gz"
        sha256 "131a5f28ebdd5e9e6c535cb22913a4ea11312c3401babf0c984b34bc548c33fa"
      else
        url "https://github.com/VOID-TECHNOLOGY-INC/PyBun/releases/download/v0.1.18/pybun-x86_64-apple-darwin.tar.gz"
        sha256 "560150de196ec0b8673ae76d9ac5a0bc6fb0054b874c1e092fef973e5a9f127d"
      end
    end

    on_linux do
      if Hardware::CPU.arm?
        url "https://github.com/VOID-TECHNOLOGY-INC/PyBun/releases/download/v0.1.18/pybun-aarch64-unknown-linux-gnu.tar.gz"
        sha256 "f0a32b4e86bbd4286925c0c06eb7173f1320b8fbe596a38bfbe3a64e383d14bc"
      else
        url "https://github.com/VOID-TECHNOLOGY-INC/PyBun/releases/download/v0.1.18/pybun-x86_64-unknown-linux-gnu.tar.gz"
        sha256 "910ac179bcb769459b106bb782f02b6bef693760ca4e4923300af8cf041a8827"
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
