# This file is auto-generated. Do not edit by hand.
class Pybun < Formula
  desc "Rust-based single-binary Python toolchain."
  homepage "https://github.com/VOID-TECHNOLOGY-INC/PyBun"
  version "0.1.26"
  license "MIT"

  if ENV["HOMEBREW_PYBUN_TEST_TARBALL"]
    url ENV["HOMEBREW_PYBUN_TEST_TARBALL"]
    sha256 ENV["HOMEBREW_PYBUN_TEST_SHA256"]
  else
    on_macos do
      if Hardware::CPU.arm?
        url "https://github.com/VOID-TECHNOLOGY-INC/PyBun/releases/download/v0.1.26/pybun-aarch64-apple-darwin.tar.gz"
        sha256 "ede3be560bf2df1845d35c8609e224d2506de988bc658aa837a3474eec7b4de6"
      else
        url "https://github.com/VOID-TECHNOLOGY-INC/PyBun/releases/download/v0.1.26/pybun-x86_64-apple-darwin.tar.gz"
        sha256 "962757888b81f683eb130625ed9e217070e78556343924b7a03eab24fc3736ba"
      end
    end

    on_linux do
      if Hardware::CPU.arm?
        url "https://github.com/VOID-TECHNOLOGY-INC/PyBun/releases/download/v0.1.26/pybun-aarch64-unknown-linux-gnu.tar.gz"
        sha256 "8f4f355c90b66f22dc3a9d8394cbbd6d57bc0626bebb7c540a379dda2ea8f1da"
      else
        url "https://github.com/VOID-TECHNOLOGY-INC/PyBun/releases/download/v0.1.26/pybun-x86_64-unknown-linux-gnu.tar.gz"
        sha256 "a924c3540403df219d1a0e65b9df24735516a8af5d011fdac87a0419608382df"
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
