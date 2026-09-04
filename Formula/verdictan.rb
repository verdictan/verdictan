class Verdictan < Formula
  desc "Verdictan AI governance gateway"
  homepage "https://verdictan.com"
  version "0.1.1"
  if OS.mac?
    if Hardware::CPU.arm?
      url "https://github.com/verdictan/verdictan/releases/download/v0.1.1/verdictan-aarch64-apple-darwin.tar.gz"
      sha256 "5028f2fbaa5d7cc88a1cd2206f9f5d37d9857d5601418b7317ff0a61ca6902bc"
    end
    if Hardware::CPU.intel?
      url "https://github.com/verdictan/verdictan/releases/download/v0.1.1/verdictan-x86_64-apple-darwin.tar.gz"
      sha256 "2aeae875f10e70b78568e746c3151e5ca65fa922910cb3b2c4ab473464c7d692"
    end
  end
  if OS.linux?
    if Hardware::CPU.arm?
      url "https://github.com/verdictan/verdictan/releases/download/v0.1.1/verdictan-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "e648d41b5020b23adfc0c4209efb66ee4ce77b9158f03d1e735b7f1cfe73170c"
    end
    if Hardware::CPU.intel?
      url "https://github.com/verdictan/verdictan/releases/download/v0.1.1/verdictan-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "530fc7786bbbfb37e8c172830c1d2f5da802cee1ea5a70010ae40feb43c59af0"
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
