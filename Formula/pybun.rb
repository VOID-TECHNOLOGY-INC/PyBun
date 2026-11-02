# This file is auto-generated. Do not edit by hand.
class Pybun < Formula
  desc "Rust-based single-binary Python toolchain."
  homepage "https://github.com/VOID-TECHNOLOGY-INC/PyBun"
  version "0.2.8"
  license "MIT"

  if ENV["HOMEBREW_PYBUN_TEST_TARBALL"]
    url ENV["HOMEBREW_PYBUN_TEST_TARBALL"]
    sha256 ENV["HOMEBREW_PYBUN_TEST_SHA256"]
  else
    on_macos do
      if Hardware::CPU.arm?
        url "https://github.com/VOID-TECHNOLOGY-INC/PyBun/releases/download/v0.2.8/pybun-aarch64-apple-darwin.tar.gz"
        sha256 "8960313f01efd65b3db22af4da3d90db5cee6e22c36d949eef8ca9fb1989b828"
      else
        url "https://github.com/VOID-TECHNOLOGY-INC/PyBun/releases/download/v0.2.8/pybun-x86_64-apple-darwin.tar.gz"
        sha256 "dcab9ada57b8479f379e6d975294d7760b05ed1322d13c7fa0da0ac40874051a"
      end
    end

    on_linux do
      if Hardware::CPU.arm?
        url "https://github.com/VOID-TECHNOLOGY-INC/PyBun/releases/download/v0.2.8/pybun-aarch64-unknown-linux-gnu.tar.gz"
        sha256 "3eec7dcc605c47c0d752310dfe82abcbf620c061916d1a9b63fac296cf674607"
      else
        url "https://github.com/VOID-TECHNOLOGY-INC/PyBun/releases/download/v0.2.8/pybun-x86_64-unknown-linux-gnu.tar.gz"
        sha256 "53a2dc4107fc2d1ac18594af27fcd6174ae6673b1deef531a209ffa9fff9f744"
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
