class Verdictan < Formula
  desc "Verdictan AI governance gateway"
  homepage "https://verdictan.com"
  version "0.1.1"
  if OS.mac?
    if Hardware::CPU.arm?
      url "https://github.com/verdictan/verdictan/releases/download/v0.1.1/verdictan-aarch64-apple-darwin.tar.gz"
      sha256 "217d8afce7c5ec0235d2cd81e42b79cd53aaf2c5af1d4bd80b4530800df6fcb8"
    end
    if Hardware::CPU.intel?
      url "https://github.com/verdictan/verdictan/releases/download/v0.1.1/verdictan-x86_64-apple-darwin.tar.gz"
      sha256 "8065c94ca43a9380e99a3acbee2ff1dee986b9e96613c01f603ccdbd6d4b259f"
    end
  end
  if OS.linux?
    if Hardware::CPU.arm?
      url "https://github.com/verdictan/verdictan/releases/download/v0.1.1/verdictan-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "032ce8f9f7c587450268f3e4ef2d392cba8c0fa70ccac64fa90d8db67503c3b5"
    end
    if Hardware::CPU.intel?
      url "https://github.com/verdictan/verdictan/releases/download/v0.1.1/verdictan-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "af8c49798ad9b68a4c88b1efe8cb25d3292bcd848c07c89819c095ea5b8180a7"
    end
  end
  license "BUSL-1.1"

  BINARY_ALIASES = {
    "aarch64-apple-darwin": {},
    "aarch64-unknown-linux-gnu": {},
    "x86_64-apple-darwin": {},
    "x86_64-pc-windows-gnu": {},
    "x86_64-unknown-linux-gnu": {}
  }

  def target_triple
    cpu = Hardware::CPU.arm? ? "aarch64" : "x86_64"
    os = OS.mac? ? "apple-darwin" : "unknown-linux-gnu"

    "#{cpu}-#{os}"
  end

  def install_binary_aliases!
    BINARY_ALIASES[target_triple.to_sym].each do |source, dests|
      dests.each do |dest|
        bin.install_symlink bin/source.to_s => dest
      end
    end
  end

  def install
    if OS.mac? && Hardware::CPU.arm?
      bin.install "verdictan", "verdictan-update"
    end
    if OS.mac? && Hardware::CPU.intel?
      bin.install "verdictan", "verdictan-update"
    end
    if OS.linux? && Hardware::CPU.arm?
      bin.install "verdictan", "verdictan-update"
    end
    if OS.linux? && Hardware::CPU.intel?
      bin.install "verdictan", "verdictan-update"
    end

    install_binary_aliases!

    # Homebrew will automatically install these, so we don't need to do that
    doc_files = Dir["README.*", "readme.*", "LICENSE", "LICENSE.*", "CHANGELOG.*"]
    leftover_contents = Dir["*"] - doc_files

    # Install any leftover files in pkgshare; these are probably config or
    # sample files.
    pkgshare.install(*leftover_contents) unless leftover_contents.empty?
  end
end
