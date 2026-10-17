# This file is auto-generated. Do not edit by hand.
class Pybun < Formula
  desc "Rust-based single-binary Python toolchain."
  homepage "https://github.com/VOID-TECHNOLOGY-INC/PyBun"
  version "0.2.2"
  license "MIT"

  if ENV["HOMEBREW_PYBUN_TEST_TARBALL"]
    url ENV["HOMEBREW_PYBUN_TEST_TARBALL"]
    sha256 ENV["HOMEBREW_PYBUN_TEST_SHA256"]
  else
    on_macos do
      if Hardware::CPU.arm?
        url "https://github.com/VOID-TECHNOLOGY-INC/PyBun/releases/download/v0.2.2/pybun-aarch64-apple-darwin.tar.gz"
        sha256 "1d5f17128f61d81dc907199987384360228399154f3cbd58f4c668719aafdc5a"
      else
        url "https://github.com/VOID-TECHNOLOGY-INC/PyBun/releases/download/v0.2.2/pybun-x86_64-apple-darwin.tar.gz"
        sha256 "8034d623f0b1ddb5ff7b532398a5084431c0441f81a888d6246aa6ee8079423d"
      end
    end

    on_linux do
      if Hardware::CPU.arm?
        url "https://github.com/VOID-TECHNOLOGY-INC/PyBun/releases/download/v0.2.2/pybun-aarch64-unknown-linux-gnu.tar.gz"
        sha256 "41285bb0b5c547e53435b0b8d7b8ae28cca8969d21990edbe9b8538989888b90"
      else
        url "https://github.com/VOID-TECHNOLOGY-INC/PyBun/releases/download/v0.2.2/pybun-x86_64-unknown-linux-gnu.tar.gz"
        sha256 "b78ed3059bc9b91580612a1a65c92d1c9b9ce574b46a1db41a324ad0297ed639"
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
