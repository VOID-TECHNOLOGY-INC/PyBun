# This file is auto-generated. Do not edit by hand.
class Pybun < Formula
  desc "Rust-based single-binary Python toolchain."
  homepage "https://github.com/VOID-TECHNOLOGY-INC/PyBun"
  version "0.2.7"
  license "MIT"

  if ENV["HOMEBREW_PYBUN_TEST_TARBALL"]
    url ENV["HOMEBREW_PYBUN_TEST_TARBALL"]
    sha256 ENV["HOMEBREW_PYBUN_TEST_SHA256"]
  else
    on_macos do
      if Hardware::CPU.arm?
        url "https://github.com/VOID-TECHNOLOGY-INC/PyBun/releases/download/v0.2.7/pybun-aarch64-apple-darwin.tar.gz"
        sha256 "e53f149ccae5ac6dd7199ef30073d7fcc4908c02a26a845ca186383ed301bd11"
      else
        url "https://github.com/VOID-TECHNOLOGY-INC/PyBun/releases/download/v0.2.7/pybun-x86_64-apple-darwin.tar.gz"
        sha256 "b848866405e9cef5042a3dd4980cc0ed45ca066b2cdfce7b12d403ecb9dc5f1f"
      end
    end

    on_linux do
      if Hardware::CPU.arm?
        url "https://github.com/VOID-TECHNOLOGY-INC/PyBun/releases/download/v0.2.7/pybun-aarch64-unknown-linux-gnu.tar.gz"
        sha256 "ae00d5ebb230d1238aff1546cbd46655669aa3a223d907aeb6177e91be8c7738"
      else
        url "https://github.com/VOID-TECHNOLOGY-INC/PyBun/releases/download/v0.2.7/pybun-x86_64-unknown-linux-gnu.tar.gz"
        sha256 "142424b4d1865736fadec51854ba8168d75601e4485944dfde60ef69a84c8ff5"
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
