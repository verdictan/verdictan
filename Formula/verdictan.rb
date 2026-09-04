class Verdictan < Formula
  desc "Verdictan AI governance gateway"
  homepage "https://verdictan.com"
  version "0.1.1"
  if OS.mac?
    if Hardware::CPU.arm?
      url "https://github.com/verdictan/verdictan/releases/download/v0.1.1/verdictan-aarch64-apple-darwin.tar.gz"
      sha256 "6b7874e7f4e31e050287f5b38afc84e9377d4a449c9e52990fca786b77839251"
    end
    if Hardware::CPU.intel?
      url "https://github.com/verdictan/verdictan/releases/download/v0.1.1/verdictan-x86_64-apple-darwin.tar.gz"
      sha256 "e4cd5f4688933b11508ea8109f5e9b1bfd2ba2ffa2874a804c127e76db3e30dd"
    end
  end
  if OS.linux?
    if Hardware::CPU.arm?
      url "https://github.com/verdictan/verdictan/releases/download/v0.1.1/verdictan-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "88404dca88489c82b13fc8471f1ea7b1133cbe9d19149a00d467b0bb3dfd8798"
    end
    if Hardware::CPU.intel?
      url "https://github.com/verdictan/verdictan/releases/download/v0.1.1/verdictan-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "b36e4d72dd4efa8d14875801fd4bf9da24f9545e9c5b8bd1d3cb06357c7dda58"
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
