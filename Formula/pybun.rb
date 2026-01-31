# This file is auto-generated. Do not edit by hand.
class Pybun < Formula
  desc "Rust-based single-binary Python toolchain."
  homepage "https://github.com/VOID-TECHNOLOGY-INC/PyBun"
  version "0.1.13"
  license "MIT"

  if ENV["HOMEBREW_PYBUN_TEST_TARBALL"]
    url ENV["HOMEBREW_PYBUN_TEST_TARBALL"]
    sha256 ENV["HOMEBREW_PYBUN_TEST_SHA256"]
  else
    on_macos do
      if Hardware::CPU.arm?
        url "https://github.com/VOID-TECHNOLOGY-INC/PyBun/releases/download/v0.1.13/pybun-aarch64-apple-darwin.tar.gz"
        sha256 "fae2007a578393c4c11017b1af67120b90003c0518f25691bb8683896c56e0cb"
      else
        url "https://github.com/VOID-TECHNOLOGY-INC/PyBun/releases/download/v0.1.13/pybun-x86_64-apple-darwin.tar.gz"
        sha256 "734a750dae77d3ed5a5afca7bfa096a9201f7f9327e73fcf3f8c9da09170326c"
      end
    end

    on_linux do
      if Hardware::CPU.arm?
        url "https://github.com/VOID-TECHNOLOGY-INC/PyBun/releases/download/v0.1.13/pybun-aarch64-unknown-linux-gnu.tar.gz"
        sha256 "3b45c04cd00839113eb5652c7748d2faef1f8bf1ad736bf4959e6d27775f7e0a"
      else
        url "https://github.com/VOID-TECHNOLOGY-INC/PyBun/releases/download/v0.1.13/pybun-x86_64-unknown-linux-gnu.tar.gz"
        sha256 "2a3596c0df656a4f1ad4e4c1dcd4d554177230410004e1dc11f90285ce610ec6"
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
