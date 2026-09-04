class Verdictan < Formula
  desc "Verdictan AI governance gateway"
  homepage "https://verdictan.com"
  version "0.1.1"
  if OS.mac?
    if Hardware::CPU.arm?
      url "https://github.com/verdictan/verdictan/releases/download/v0.1.1/verdictan-aarch64-apple-darwin.tar.gz"
      sha256 "15b329d00b819bb44870ff8ffb755d712eef2c2e23b2596552f6756eb0ae942a"
    end
    if Hardware::CPU.intel?
      url "https://github.com/verdictan/verdictan/releases/download/v0.1.1/verdictan-x86_64-apple-darwin.tar.gz"
      sha256 "0a993781d0e9639ee30e784be6701143f4e2c953627893acd4ed0fb62651b98d"
    end
  end
  if OS.linux?
    if Hardware::CPU.arm?
      url "https://github.com/verdictan/verdictan/releases/download/v0.1.1/verdictan-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "dc4a9b47007c053f0442914747aa4634b6fcec5bbc51e487ea48e32eb9624f97"
    end
    if Hardware::CPU.intel?
      url "https://github.com/verdictan/verdictan/releases/download/v0.1.1/verdictan-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "7e6169ec64c70598805e5666c581b1dbf402d553636b68ccc6fa2baedc2a89ee"
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
