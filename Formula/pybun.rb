# This file is auto-generated. Do not edit by hand.
class Pybun < Formula
  desc "Rust-based single-binary Python toolchain."
  homepage "https://github.com/VOID-TECHNOLOGY-INC/PyBun"
  version "0.1.20"
  license "MIT"

  if ENV["HOMEBREW_PYBUN_TEST_TARBALL"]
    url ENV["HOMEBREW_PYBUN_TEST_TARBALL"]
    sha256 ENV["HOMEBREW_PYBUN_TEST_SHA256"]
  else
    on_macos do
      if Hardware::CPU.arm?
        url "https://github.com/VOID-TECHNOLOGY-INC/PyBun/releases/download/v0.1.20/pybun-aarch64-apple-darwin.tar.gz"
        sha256 "cc1f40ffc120efc781ca4605eb82fd95dc775e60924ab82e0061d5f855ade9c8"
      else
        url "https://github.com/VOID-TECHNOLOGY-INC/PyBun/releases/download/v0.1.20/pybun-x86_64-apple-darwin.tar.gz"
        sha256 "e6c2efce8e0e643c15633edf74fbd94a9f47b0dbb875464ae1f1665eba8d7dd8"
      end
    end

    on_linux do
      if Hardware::CPU.arm?
        url "https://github.com/VOID-TECHNOLOGY-INC/PyBun/releases/download/v0.1.20/pybun-aarch64-unknown-linux-gnu.tar.gz"
        sha256 "665f5156a85abf24fb22dc7cafa22c4bbe847c34008933c342072309c1efdebb"
      else
        url "https://github.com/VOID-TECHNOLOGY-INC/PyBun/releases/download/v0.1.20/pybun-x86_64-unknown-linux-gnu.tar.gz"
        sha256 "3d8fc572bbd9e148a5ab22eda482cd6a53464b63ad31d01b3a0073fb406e5e57"
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
