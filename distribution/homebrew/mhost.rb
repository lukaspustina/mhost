class Mhost < Formula
  desc "More than host - A modern take on the classic host DNS lookup utility"
  homepage "https://mhost.pustina.de"
  url "https://github.com/lukaspustina/mhost/archive/v0.3.0.tar.gz"
  sha256 "651a8abd334325b3d743e7ff930027e1ffad2ff15885b81bbf65b03284f2091c"
  license any_of: ["MIT", "Apache-2.0"]
  head "https://github.com/lukaspustina/mhost.git"

  depends_on "rust" => :build

  def install
    system "cargo", "install", "--features", "app", *std_cargo_args

    out_dir = Dir["target/release/build/mhost-*/out"].first
    # man1.install "#{out_dir}/man.1"
    bash_completion.install "#{out_dir}/mhost.bash"
    fish_completion.install "#{out_dir}/mhost.fish"
    zsh_completion.install "#{out_dir}/_mhost"
  end

  test do
    system "#{bin}/mhost", "lookup", "mhost.pustina.de"
  end
end
