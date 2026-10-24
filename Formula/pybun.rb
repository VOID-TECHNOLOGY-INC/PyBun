# This file is auto-generated. Do not edit by hand.
class Pybun < Formula
  desc "Rust-based single-binary Python toolchain."
  homepage "https://github.com/VOID-TECHNOLOGY-INC/PyBun"
  version "0.2.4"
  license "MIT"

  if ENV["HOMEBREW_PYBUN_TEST_TARBALL"]
    url ENV["HOMEBREW_PYBUN_TEST_TARBALL"]
    sha256 ENV["HOMEBREW_PYBUN_TEST_SHA256"]
  else
    on_macos do
      if Hardware::CPU.arm?
        url "https://github.com/VOID-TECHNOLOGY-INC/PyBun/releases/download/v0.2.4/pybun-aarch64-apple-darwin.tar.gz"
        sha256 "9006fe497bcc44853ee171bab076d69e4092e00e91908c487394874ed5f07880"
      else
        url "https://github.com/VOID-TECHNOLOGY-INC/PyBun/releases/download/v0.2.4/pybun-x86_64-apple-darwin.tar.gz"
        sha256 "1da35de4fb78b5185901ffc822e748ce678ffdb7aa5af142a46ca7db4cea31ef"
      end
    end

    on_linux do
      if Hardware::CPU.arm?
        url "https://github.com/VOID-TECHNOLOGY-INC/PyBun/releases/download/v0.2.4/pybun-aarch64-unknown-linux-gnu.tar.gz"
        sha256 "a1a2aa9ccb3324b48eb357bbfe7cd8b76c72c2978f3f353bf756b5e5683a960a"
      else
        url "https://github.com/VOID-TECHNOLOGY-INC/PyBun/releases/download/v0.2.4/pybun-x86_64-unknown-linux-gnu.tar.gz"
        sha256 "e4fb6a56b2d811f1c68e6a01d37e3e39fbff77088e586bf52ad8df6bc2a3d1ef"
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
