# This file is auto-generated. Do not edit by hand.
class Pybun < Formula
  desc "Rust-based single-binary Python toolchain."
  homepage "https://github.com/VOID-TECHNOLOGY-INC/PyBun"
  version "0.2.1"
  license "MIT"

  if ENV["HOMEBREW_PYBUN_TEST_TARBALL"]
    url ENV["HOMEBREW_PYBUN_TEST_TARBALL"]
    sha256 ENV["HOMEBREW_PYBUN_TEST_SHA256"]
  else
    on_macos do
      if Hardware::CPU.arm?
        url "https://github.com/VOID-TECHNOLOGY-INC/PyBun/releases/download/v0.2.1/pybun-aarch64-apple-darwin.tar.gz"
        sha256 "4be825f3ed3d3781d3cad05a82a769ae69bff3c4581972ba26bb209b93adab27"
      else
        url "https://github.com/VOID-TECHNOLOGY-INC/PyBun/releases/download/v0.2.1/pybun-x86_64-apple-darwin.tar.gz"
        sha256 "69f9f332e83ef8fdeadcd3dd87f9dc4bda2a0b495351c5ecc041bbe2f89f4e2f"
      end
    end

    on_linux do
      if Hardware::CPU.arm?
        url "https://github.com/VOID-TECHNOLOGY-INC/PyBun/releases/download/v0.2.1/pybun-aarch64-unknown-linux-gnu.tar.gz"
        sha256 "24d0e13d730e1cf3c8556784c12b79262cc8fe22047fd284bf459a248d034300"
      else
        url "https://github.com/VOID-TECHNOLOGY-INC/PyBun/releases/download/v0.2.1/pybun-x86_64-unknown-linux-gnu.tar.gz"
        sha256 "66f3ec26805490c45039f98268c12161fb00f3a7bbc77e16d4ccd2e69a088ae8"
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
