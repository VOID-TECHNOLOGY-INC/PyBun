# This file is auto-generated. Do not edit by hand.
class Pybun < Formula
  desc "Rust-based single-binary Python toolchain."
  homepage "https://github.com/VOID-TECHNOLOGY-INC/PyBun"
  version "0.1.12"
  license "MIT"

  if ENV["HOMEBREW_PYBUN_TEST_TARBALL"]
    url ENV["HOMEBREW_PYBUN_TEST_TARBALL"]
    sha256 ENV["HOMEBREW_PYBUN_TEST_SHA256"]
  else
    on_macos do
      if Hardware::CPU.arm?
        url "https://github.com/VOID-TECHNOLOGY-INC/PyBun/releases/download/v0.1.12/pybun-aarch64-apple-darwin.tar.gz"
        sha256 "1688afda94d9f58f853caa22b36ea26a276e60a2691f55dae2b22d6c52bd757b"
      else
        url "https://github.com/VOID-TECHNOLOGY-INC/PyBun/releases/download/v0.1.12/pybun-x86_64-apple-darwin.tar.gz"
        sha256 "8dc9bf8cbb28d38242d63e9096d2d6c3cf3082fb535747bcaaeba50c7437b401"
      end
    end

    on_linux do
      if Hardware::CPU.arm?
        url "https://github.com/VOID-TECHNOLOGY-INC/PyBun/releases/download/v0.1.12/pybun-aarch64-unknown-linux-gnu.tar.gz"
        sha256 "3440240d3db537c18d4ecb5dbdf62b061469c358cc788e059c9b87e9a55584f2"
      else
        url "https://github.com/VOID-TECHNOLOGY-INC/PyBun/releases/download/v0.1.12/pybun-x86_64-unknown-linux-gnu.tar.gz"
        sha256 "759c029f93e174a5b3ad6b51945f71b2162faa9e9316093ae89b030478ac56f2"
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
