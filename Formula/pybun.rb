# This file is auto-generated. Do not edit by hand.
class Pybun < Formula
  desc "Rust-based single-binary Python toolchain."
  homepage "https://github.com/VOID-TECHNOLOGY-INC/PyBun"
  version "0.1.28"
  license "MIT"

  if ENV["HOMEBREW_PYBUN_TEST_TARBALL"]
    url ENV["HOMEBREW_PYBUN_TEST_TARBALL"]
    sha256 ENV["HOMEBREW_PYBUN_TEST_SHA256"]
  else
    on_macos do
      if Hardware::CPU.arm?
        url "https://github.com/VOID-TECHNOLOGY-INC/PyBun/releases/download/v0.1.28/pybun-aarch64-apple-darwin.tar.gz"
        sha256 "49bdd361fddccb7f32d68be8ea2e308e4c1be9ae685e44c7edd7b60734c5a21c"
      else
        url "https://github.com/VOID-TECHNOLOGY-INC/PyBun/releases/download/v0.1.28/pybun-x86_64-apple-darwin.tar.gz"
        sha256 "b17c39bc55bbc51cac15f113b4ae9a7297de52a39e46fc707875161ba5c83d10"
      end
    end

    on_linux do
      if Hardware::CPU.arm?
        url "https://github.com/VOID-TECHNOLOGY-INC/PyBun/releases/download/v0.1.28/pybun-aarch64-unknown-linux-gnu.tar.gz"
        sha256 "4a882ccbb518ecb1e21e4a8183e5697e225d0eaa532b669040c9486a76152d67"
      else
        url "https://github.com/VOID-TECHNOLOGY-INC/PyBun/releases/download/v0.1.28/pybun-x86_64-unknown-linux-gnu.tar.gz"
        sha256 "ef24a5c61891a66e50dd2a117a95fa7b154aa63a29af7eb9344cfe71f1080e2c"
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
