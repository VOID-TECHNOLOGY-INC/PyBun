# This file is auto-generated. Do not edit by hand.
class Pybun < Formula
  desc "Rust-based single-binary Python toolchain."
  homepage "https://github.com/VOID-TECHNOLOGY-INC/PyBun"
  version "0.1.14"
  license "MIT"

  if ENV["HOMEBREW_PYBUN_TEST_TARBALL"]
    url ENV["HOMEBREW_PYBUN_TEST_TARBALL"]
    sha256 ENV["HOMEBREW_PYBUN_TEST_SHA256"]
  else
    on_macos do
      if Hardware::CPU.arm?
        url "https://github.com/VOID-TECHNOLOGY-INC/PyBun/releases/download/v0.1.14/pybun-aarch64-apple-darwin.tar.gz"
        sha256 "0fc21c2516db770c3a1d18f7814d2537e6f258e3c5c7532b2894f9a665e42db0"
      else
        url "https://github.com/VOID-TECHNOLOGY-INC/PyBun/releases/download/v0.1.14/pybun-x86_64-apple-darwin.tar.gz"
        sha256 "fe59bc6a8809db346a517ae3d3b5b48239a49fb389388638763aba34e02b2ca6"
      end
    end

    on_linux do
      if Hardware::CPU.arm?
        url "https://github.com/VOID-TECHNOLOGY-INC/PyBun/releases/download/v0.1.14/pybun-aarch64-unknown-linux-gnu.tar.gz"
        sha256 "536d828d5dc434fc7611fbe4dee2596653eb0d7bef1b5e4fa65c91875a104600"
      else
        url "https://github.com/VOID-TECHNOLOGY-INC/PyBun/releases/download/v0.1.14/pybun-x86_64-unknown-linux-gnu.tar.gz"
        sha256 "9b8959304695ff7c9927b3063101aceb0ae1524cc7662ec06f2431d36f755e1c"
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
