# This file is auto-generated. Do not edit by hand.
class Pybun < Formula
  desc "Rust-based single-binary Python toolchain."
  homepage "https://github.com/VOID-TECHNOLOGY-INC/PyBun"
  version "0.1.10"
  license "MIT"

  if ENV["HOMEBREW_PYBUN_TEST_TARBALL"]
    url ENV["HOMEBREW_PYBUN_TEST_TARBALL"]
    sha256 ENV["HOMEBREW_PYBUN_TEST_SHA256"]
  else
    on_macos do
      if Hardware::CPU.arm?
        url "https://github.com/VOID-TECHNOLOGY-INC/PyBun/releases/download/v0.1.10/pybun-aarch64-apple-darwin.tar.gz"
        sha256 "9cb1acc9db5ffdacca0ba079f49401cc7fe0014c3746d5eb2fe36b69117f5bc1"
      else
        url "https://github.com/VOID-TECHNOLOGY-INC/PyBun/releases/download/v0.1.10/pybun-x86_64-apple-darwin.tar.gz"
        sha256 "29b03dcce4316184ff6a3c4ff58a4991d76fcf4ebfc645aebc2430a8d28c0696"
      end
    end

    on_linux do
      if Hardware::CPU.arm?
        url "https://github.com/VOID-TECHNOLOGY-INC/PyBun/releases/download/v0.1.10/pybun-aarch64-unknown-linux-gnu.tar.gz"
        sha256 "9fb68ea74119e9e78064fbe367685684bc863544e7e250185a6479a4c0237618"
      else
        url "https://github.com/VOID-TECHNOLOGY-INC/PyBun/releases/download/v0.1.10/pybun-x86_64-unknown-linux-gnu.tar.gz"
        sha256 "d224e1b76ed111e97dc2a71c81be7292a7a46203c7e7be98c6ec1ba0a3e3ca7c"
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
