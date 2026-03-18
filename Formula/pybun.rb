# This file is auto-generated. Do not edit by hand.
class Pybun < Formula
  desc "Rust-based single-binary Python toolchain."
  homepage "https://github.com/VOID-TECHNOLOGY-INC/PyBun"
  version "0.1.17"
  license "MIT"

  if ENV["HOMEBREW_PYBUN_TEST_TARBALL"]
    url ENV["HOMEBREW_PYBUN_TEST_TARBALL"]
    sha256 ENV["HOMEBREW_PYBUN_TEST_SHA256"]
  else
    on_macos do
      if Hardware::CPU.arm?
        url "https://github.com/VOID-TECHNOLOGY-INC/PyBun/releases/download/v0.1.17/pybun-aarch64-apple-darwin.tar.gz"
        sha256 "ab3f7c49ce2fdda3570ddeaa4cc54f56aa64c1df376a35deb08e027b961ace62"
      else
        url "https://github.com/VOID-TECHNOLOGY-INC/PyBun/releases/download/v0.1.17/pybun-x86_64-apple-darwin.tar.gz"
        sha256 "351aa0f5190df32a894501524d665660b737eed5bc4abf4f1269a65d0554188e"
      end
    end

    on_linux do
      if Hardware::CPU.arm?
        url "https://github.com/VOID-TECHNOLOGY-INC/PyBun/releases/download/v0.1.17/pybun-aarch64-unknown-linux-gnu.tar.gz"
        sha256 "3e8fb48cfe2ae8a3ff3434290c7e9c61ad0ca26e9a4097e06a79fd7f8fe5f297"
      else
        url "https://github.com/VOID-TECHNOLOGY-INC/PyBun/releases/download/v0.1.17/pybun-x86_64-unknown-linux-gnu.tar.gz"
        sha256 "d428d883fc47cdab5700d04baaa48b9eea21dbaf1910730ef3ea0dc264ed6af0"
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
