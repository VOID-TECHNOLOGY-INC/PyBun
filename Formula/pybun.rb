# This file is auto-generated. Do not edit by hand.
class Pybun < Formula
  desc "Rust-based single-binary Python toolchain."
  homepage "https://github.com/VOID-TECHNOLOGY-INC/PyBun"
  version "0.1.5"
  license "MIT"

  if ENV["HOMEBREW_PYBUN_TEST_TARBALL"]
    url ENV["HOMEBREW_PYBUN_TEST_TARBALL"]
    sha256 ENV["HOMEBREW_PYBUN_TEST_SHA256"]
  else
    on_macos do
      if Hardware::CPU.arm?
        url "https://github.com/VOID-TECHNOLOGY-INC/PyBun/releases/download/v0.1.5/pybun-aarch64-apple-darwin.tar.gz"
        sha256 "5e6a2a58c310263f26da4b4a24c551410e4d41156492ebe6748392d486ff4463"
      else
        url "https://github.com/VOID-TECHNOLOGY-INC/PyBun/releases/download/v0.1.5/pybun-x86_64-apple-darwin.tar.gz"
        sha256 "3f6067f64c459ae95127046b52aa8319684e2a2ca8872c5158ebd6e4f6aae2e8"
      end
    end

    on_linux do
      if Hardware::CPU.arm?
        url "https://github.com/VOID-TECHNOLOGY-INC/PyBun/releases/download/v0.1.5/pybun-aarch64-unknown-linux-gnu.tar.gz"
        sha256 "5ddd383fa36da484300ccfa0e16cb185554385ff3c624af525b16b8f00c642e5"
      else
        url "https://github.com/VOID-TECHNOLOGY-INC/PyBun/releases/download/v0.1.5/pybun-x86_64-unknown-linux-gnu.tar.gz"
        sha256 "ea22d255b80a65ac6500a87044450c103ddce800f64e43d2548d6ed644fd573f"
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
