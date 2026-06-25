# This file is auto-generated. Do not edit by hand.
class Pybun < Formula
  desc "Rust-based single-binary Python toolchain."
  homepage "https://github.com/VOID-TECHNOLOGY-INC/PyBun"
  version "0.1.21"
  license "MIT"

  if ENV["HOMEBREW_PYBUN_TEST_TARBALL"]
    url ENV["HOMEBREW_PYBUN_TEST_TARBALL"]
    sha256 ENV["HOMEBREW_PYBUN_TEST_SHA256"]
  else
    on_macos do
      if Hardware::CPU.arm?
        url "https://github.com/VOID-TECHNOLOGY-INC/PyBun/releases/download/v0.1.21/pybun-aarch64-apple-darwin.tar.gz"
        sha256 "dc9bb12097732060ea17fd909612b052b1cf2ef1b955a055ab35108e4fc4d59a"
      else
        url "https://github.com/VOID-TECHNOLOGY-INC/PyBun/releases/download/v0.1.21/pybun-x86_64-apple-darwin.tar.gz"
        sha256 "733e41f9a3e61c935b43dd4b1fea09f798ca60f503f5132c4ae180bb9be209ed"
      end
    end

    on_linux do
      if Hardware::CPU.arm?
        url "https://github.com/VOID-TECHNOLOGY-INC/PyBun/releases/download/v0.1.21/pybun-aarch64-unknown-linux-gnu.tar.gz"
        sha256 "e70a2249d3cf3a19ddc5398d75e48629da7261d4a42577f6bb8cdf1df13d62ce"
      else
        url "https://github.com/VOID-TECHNOLOGY-INC/PyBun/releases/download/v0.1.21/pybun-x86_64-unknown-linux-gnu.tar.gz"
        sha256 "a51102fd59541e9c09ab99cd193f049eabe0b4fad081dba6b311b62eb615744a"
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
