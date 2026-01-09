# This file is auto-generated. Do not edit by hand.
class Pybun < Formula
  desc "Rust-based single-binary Python toolchain."
  homepage "https://github.com/VOID-TECHNOLOGY-INC/PyBun"
  version "0.1.7"
  license "MIT"

  if ENV["HOMEBREW_PYBUN_TEST_TARBALL"]
    url ENV["HOMEBREW_PYBUN_TEST_TARBALL"]
    sha256 ENV["HOMEBREW_PYBUN_TEST_SHA256"]
  else
    on_macos do
      if Hardware::CPU.arm?
        url "https://github.com/VOID-TECHNOLOGY-INC/PyBun/releases/download/v0.1.7/pybun-aarch64-apple-darwin.tar.gz"
        sha256 "1b820bddc547e2324edd0217bf8fd8003cd20b7985eb5e19ecf4a6ee09d698b6"
      else
        url "https://github.com/VOID-TECHNOLOGY-INC/PyBun/releases/download/v0.1.7/pybun-x86_64-apple-darwin.tar.gz"
        sha256 "0684b9fbf4ebeada1ca324f0e8eb43fd2bf97dd43153ae19cde25788e32cd410"
      end
    end

    on_linux do
      if Hardware::CPU.arm?
        url "https://github.com/VOID-TECHNOLOGY-INC/PyBun/releases/download/v0.1.7/pybun-aarch64-unknown-linux-gnu.tar.gz"
        sha256 "fdd8abb0d362a6257503cf69f18c8ce550113b87a8180bbbe543d9a56aa8143d"
      else
        url "https://github.com/VOID-TECHNOLOGY-INC/PyBun/releases/download/v0.1.7/pybun-x86_64-unknown-linux-gnu.tar.gz"
        sha256 "bc058365727168bcce87042bc2c96de4293972bf7de2fe28b1fb088c7e7ee126"
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
