# This file is auto-generated. Do not edit by hand.
class Pybun < Formula
  desc "Rust-based single-binary Python toolchain."
  homepage "https://github.com/VOID-TECHNOLOGY-INC/PyBun"
  version "0.2.3"
  license "MIT"

  if ENV["HOMEBREW_PYBUN_TEST_TARBALL"]
    url ENV["HOMEBREW_PYBUN_TEST_TARBALL"]
    sha256 ENV["HOMEBREW_PYBUN_TEST_SHA256"]
  else
    on_macos do
      if Hardware::CPU.arm?
        url "https://github.com/VOID-TECHNOLOGY-INC/PyBun/releases/download/v0.2.3/pybun-aarch64-apple-darwin.tar.gz"
        sha256 "f65c9d012454d435d681fb2c9d285b153c68e54b37eeb1bebbf8d188a55039a5"
      else
        url "https://github.com/VOID-TECHNOLOGY-INC/PyBun/releases/download/v0.2.3/pybun-x86_64-apple-darwin.tar.gz"
        sha256 "dc53d97ebbed98aa7bddf6f1dd47da3c1604b3e62524e688df0fcac89ddb667d"
      end
    end

    on_linux do
      if Hardware::CPU.arm?
        url "https://github.com/VOID-TECHNOLOGY-INC/PyBun/releases/download/v0.2.3/pybun-aarch64-unknown-linux-gnu.tar.gz"
        sha256 "809370b61a917dc88725ba2ef52bda961a4c672be3901828fb91ecd0ec69a434"
      else
        url "https://github.com/VOID-TECHNOLOGY-INC/PyBun/releases/download/v0.2.3/pybun-x86_64-unknown-linux-gnu.tar.gz"
        sha256 "23a77fc44e9ddc63c2e2bebe9cc924992ad5343fa9645194c64db13d843589c1"
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
