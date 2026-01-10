# This file is auto-generated. Do not edit by hand.
class Pybun < Formula
  desc "Rust-based single-binary Python toolchain."
  homepage "https://github.com/VOID-TECHNOLOGY-INC/PyBun"
  version "0.1.9"
  license "MIT"

  if ENV["HOMEBREW_PYBUN_TEST_TARBALL"]
    url ENV["HOMEBREW_PYBUN_TEST_TARBALL"]
    sha256 ENV["HOMEBREW_PYBUN_TEST_SHA256"]
  else
    on_macos do
      if Hardware::CPU.arm?
        url "https://github.com/VOID-TECHNOLOGY-INC/PyBun/releases/download/v0.1.9/pybun-aarch64-apple-darwin.tar.gz"
        sha256 "9fe33111cfe9e0d29a5d82a1947fbfe13807e1d78ce1b4277d31a922975e5c77"
      else
        url "https://github.com/VOID-TECHNOLOGY-INC/PyBun/releases/download/v0.1.9/pybun-x86_64-apple-darwin.tar.gz"
        sha256 "5156138dedefb15659375501f2fa7f7fd1cb69f74824974764149cf4aeb2e62f"
      end
    end

    on_linux do
      if Hardware::CPU.arm?
        url "https://github.com/VOID-TECHNOLOGY-INC/PyBun/releases/download/v0.1.9/pybun-aarch64-unknown-linux-gnu.tar.gz"
        sha256 "50903648a8c95a82e541ff556e5faac1ccb54fb0b4ace1dd38bb32c2388bf87d"
      else
        url "https://github.com/VOID-TECHNOLOGY-INC/PyBun/releases/download/v0.1.9/pybun-x86_64-unknown-linux-gnu.tar.gz"
        sha256 "6c49a8359763c46cbfe03761816a1c3348bc61e438ce07de1ceb29d2a0514344"
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
