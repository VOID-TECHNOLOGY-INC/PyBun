# This file is auto-generated. Do not edit by hand.
class Pybun < Formula
  desc "Rust-based single-binary Python toolchain."
  homepage "https://github.com/VOID-TECHNOLOGY-INC/PyBun"
  version "0.1.15"
  license "MIT"

  if ENV["HOMEBREW_PYBUN_TEST_TARBALL"]
    url ENV["HOMEBREW_PYBUN_TEST_TARBALL"]
    sha256 ENV["HOMEBREW_PYBUN_TEST_SHA256"]
  else
    on_macos do
      if Hardware::CPU.arm?
        url "https://github.com/VOID-TECHNOLOGY-INC/PyBun/releases/download/v0.1.15/pybun-aarch64-apple-darwin.tar.gz"
        sha256 "e8d345b8bbd9b571d3bb2c59083c611309481381eff3d5911d6cd4f56d3b6a97"
      else
        url "https://github.com/VOID-TECHNOLOGY-INC/PyBun/releases/download/v0.1.15/pybun-x86_64-apple-darwin.tar.gz"
        sha256 "20795b237a2af0fe2b0da5dae6ab2e07d91e2444c1c47f1ed2fe280ec218cc24"
      end
    end

    on_linux do
      if Hardware::CPU.arm?
        url "https://github.com/VOID-TECHNOLOGY-INC/PyBun/releases/download/v0.1.15/pybun-aarch64-unknown-linux-gnu.tar.gz"
        sha256 "33c1339cd2ba49839eae614883a5d06eec7294930a7019184ee5f4c7b2cc01d5"
      else
        url "https://github.com/VOID-TECHNOLOGY-INC/PyBun/releases/download/v0.1.15/pybun-x86_64-unknown-linux-gnu.tar.gz"
        sha256 "20a100645ec5af2b513800556f67238e6854ba81aba532d206ba21239dfdaf43"
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
