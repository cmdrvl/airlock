class Airlock < Formula
  desc "Prove what crossed the model boundary"
  homepage "https://github.com/cmdrvl/airlock"
  version "__VERSION__"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/cmdrvl/airlock/releases/download/v__VERSION__/airlock-__VERSION__-aarch64-apple-darwin.tar.gz"
      sha256 "__SHA256_AARCH64_APPLE_DARWIN__"
    else
      url "https://github.com/cmdrvl/airlock/releases/download/v__VERSION__/airlock-__VERSION__-x86_64-apple-darwin.tar.gz"
      sha256 "__SHA256_X86_64_APPLE_DARWIN__"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://github.com/cmdrvl/airlock/releases/download/v__VERSION__/airlock-__VERSION__-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "__SHA256_AARCH64_UNKNOWN_LINUX_GNU__"
    else
      url "https://github.com/cmdrvl/airlock/releases/download/v__VERSION__/airlock-__VERSION__-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "__SHA256_X86_64_UNKNOWN_LINUX_GNU__"
    end
  end

  def install
    bin.install "airlock"
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/airlock --version")
  end
end
