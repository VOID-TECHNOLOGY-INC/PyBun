# This file is auto-generated. Do not edit by hand.
class Pybun < Formula
  desc "Rust-based single-binary Python toolchain."
  homepage "https://github.com/VOID-TECHNOLOGY-INC/PyBun"
  version "0.1.24"
  license "MIT"

  if ENV["HOMEBREW_PYBUN_TEST_TARBALL"]
    url ENV["HOMEBREW_PYBUN_TEST_TARBALL"]
    sha256 ENV["HOMEBREW_PYBUN_TEST_SHA256"]
  else
    on_macos do
      if Hardware::CPU.arm?
        url "https://github.com/VOID-TECHNOLOGY-INC/PyBun/releases/download/v0.1.24/pybun-aarch64-apple-darwin.tar.gz"
        sha256 "0e863d5b6a876ba6d7d6f47e4c47fe35f8e2a5d9643d4ffb5e4a6cba4046e966"
      else
        url "https://github.com/VOID-TECHNOLOGY-INC/PyBun/releases/download/v0.1.24/pybun-x86_64-apple-darwin.tar.gz"
        sha256 "9e5ebc17ba7c1ba9a4dc25a2c3790803c0ee496dd72c25803db48fbffa23c030"
      end
    end

    on_linux do
      if Hardware::CPU.arm?
        url "https://github.com/VOID-TECHNOLOGY-INC/PyBun/releases/download/v0.1.24/pybun-aarch64-unknown-linux-gnu.tar.gz"
        sha256 "78f02b33657e16c6242c1e5decb3c2f405be2dd4b8afb0b13efbedd7b4a6903c"
      else
        url "https://github.com/VOID-TECHNOLOGY-INC/PyBun/releases/download/v0.1.24/pybun-x86_64-unknown-linux-gnu.tar.gz"
        sha256 "855d6126d39fd210fe2b90a4da8d720245d39f0423e5b5cdb61abbc277029690"
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
