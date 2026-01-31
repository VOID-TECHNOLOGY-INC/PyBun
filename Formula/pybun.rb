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
        sha256 "e859fb061a41b2936814266ea3f43351d44b4f8eb839bf1e319cd1619ba0337c"
      else
        url "https://github.com/VOID-TECHNOLOGY-INC/PyBun/releases/download/v0.1.12/pybun-x86_64-apple-darwin.tar.gz"
        sha256 "e7261dbf00a448e6757acd91d6c778eb68a6149af31aa9249d07dfd46512ce7c"
      end
    end

    on_linux do
      if Hardware::CPU.arm?
        url "https://github.com/VOID-TECHNOLOGY-INC/PyBun/releases/download/v0.1.12/pybun-aarch64-unknown-linux-gnu.tar.gz"
        sha256 "ad1310ffce856a73495f1c9a7feadb51c17eb5a6178c8f3fabf18461f2cc3879"
      else
        url "https://github.com/VOID-TECHNOLOGY-INC/PyBun/releases/download/v0.1.12/pybun-x86_64-unknown-linux-gnu.tar.gz"
        sha256 "15f2b899401c11440c37df1ad5c4ace35866322d0760334eaf10018f78d8d516"
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
