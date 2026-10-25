# This file is auto-generated. Do not edit by hand.
class Pybun < Formula
  desc "Rust-based single-binary Python toolchain."
  homepage "https://github.com/VOID-TECHNOLOGY-INC/PyBun"
  version "0.2.5"
  license "MIT"

  if ENV["HOMEBREW_PYBUN_TEST_TARBALL"]
    url ENV["HOMEBREW_PYBUN_TEST_TARBALL"]
    sha256 ENV["HOMEBREW_PYBUN_TEST_SHA256"]
  else
    on_macos do
      if Hardware::CPU.arm?
        url "https://github.com/VOID-TECHNOLOGY-INC/PyBun/releases/download/v0.2.5/pybun-aarch64-apple-darwin.tar.gz"
        sha256 "f8540f96234b8818473956303fcf1e1d58cf6a0d8f6066ad726e3b83d669fe37"
      else
        url "https://github.com/VOID-TECHNOLOGY-INC/PyBun/releases/download/v0.2.5/pybun-x86_64-apple-darwin.tar.gz"
        sha256 "dfaed311b51df3fa9e746ad69382be591b127d5631dd1f9a16b9d78fc7e95f5a"
      end
    end

    on_linux do
      if Hardware::CPU.arm?
        url "https://github.com/VOID-TECHNOLOGY-INC/PyBun/releases/download/v0.2.5/pybun-aarch64-unknown-linux-gnu.tar.gz"
        sha256 "0df2046802f8cc1c3dd84334cca790e4dcd0bbd4df67afb284ea242ad83c4cd7"
      else
        url "https://github.com/VOID-TECHNOLOGY-INC/PyBun/releases/download/v0.2.5/pybun-x86_64-unknown-linux-gnu.tar.gz"
        sha256 "6d9ef9458efb2f8c49e759864d4258acb4a65ab72bbce6a69b8fdf52bde5c978"
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
