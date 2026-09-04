class Verdictan < Formula
  desc "Verdictan AI governance gateway"
  homepage "https://verdictan.com"
  version "0.1.1"
  if OS.mac?
    if Hardware::CPU.arm?
      url "https://github.com/verdictan/verdictan/releases/download/v0.1.1/verdictan-aarch64-apple-darwin.tar.gz"
      sha256 "79009888e43e0cd6fe92bd9410acde95750131cc7d8ecc6d671cc090ace65573"
    end
    if Hardware::CPU.intel?
      url "https://github.com/verdictan/verdictan/releases/download/v0.1.1/verdictan-x86_64-apple-darwin.tar.gz"
      sha256 "026ab17628b93d87237aefaf37f168dc6a8c947cdff9dcaa6cbef86244fa473b"
    end
  end
  if OS.linux?
    if Hardware::CPU.arm?
      url "https://github.com/verdictan/verdictan/releases/download/v0.1.1/verdictan-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "13e529b2d6ceee9bf48cf51f83e51048f57b2910b28436635459291be98b968b"
    end
    if Hardware::CPU.intel?
      url "https://github.com/verdictan/verdictan/releases/download/v0.1.1/verdictan-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "9cc4f6432867dbdff9cdb981c739bdef7a2f27922992e960a9ed953fb246f044"
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
