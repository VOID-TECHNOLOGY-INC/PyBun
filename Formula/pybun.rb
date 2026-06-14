# This file is auto-generated. Do not edit by hand.
class Pybun < Formula
  desc "Rust-based single-binary Python toolchain."
  homepage "https://github.com/VOID-TECHNOLOGY-INC/PyBun"
  version "0.1.19"
  license "MIT"

  if ENV["HOMEBREW_PYBUN_TEST_TARBALL"]
    url ENV["HOMEBREW_PYBUN_TEST_TARBALL"]
    sha256 ENV["HOMEBREW_PYBUN_TEST_SHA256"]
  else
    on_macos do
      if Hardware::CPU.arm?
        url "https://github.com/VOID-TECHNOLOGY-INC/PyBun/releases/download/v0.1.19/pybun-aarch64-apple-darwin.tar.gz"
        sha256 "85d5e790dd30441b8f075a6e90c2ed729218be500f421c2f44cfe76faa5e75f5"
      else
        url "https://github.com/VOID-TECHNOLOGY-INC/PyBun/releases/download/v0.1.19/pybun-x86_64-apple-darwin.tar.gz"
        sha256 "76881fb6f036477597feeb1b78eadffc1c853d1aaf92eaef0db009ec95262816"
      end
    end

    on_linux do
      if Hardware::CPU.arm?
        url "https://github.com/VOID-TECHNOLOGY-INC/PyBun/releases/download/v0.1.19/pybun-aarch64-unknown-linux-gnu.tar.gz"
        sha256 "02bffcd2ee68bffb4e9dc12f2976ed53cab78ebdd2f0b73cc82d45b7a9498e3c"
      else
        url "https://github.com/VOID-TECHNOLOGY-INC/PyBun/releases/download/v0.1.19/pybun-x86_64-unknown-linux-gnu.tar.gz"
        sha256 "7078f855e278ccb6a540d80734fa3fdb8550ba591cd74ea13e83342275d7322b"
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
