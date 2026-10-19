---
id: installation
title: Installation
sidebar_label: Installation
slug: /installation
---

## Homebrew (macOS)

```sh
brew install lukaspustina/mhost/mhost
```

## Docker

Try mhost without installing:

```sh
docker run lukaspustina/mhost:latest mhost l example.com
```

## Debian / Ubuntu

Download the `.deb` from the [latest GitHub Release](https://github.com/lukaspustina/mhost/releases):

```sh
dpkg -i mhost.deb
```

## Redhat / Fedora

Download the `.rpm` from the [latest GitHub Release](https://github.com/lukaspustina/mhost/releases):

```sh
rpm -i mhost.rpm
```

## Cargo (Rust developers)

```sh
cargo install --features app mhost       # CLI only
cargo install --features tui mhost       # CLI + interactive TUI (mdive)
```

## From Source

```sh
git clone https://github.com/lukaspustina/mhost
cd mhost
make install                             # CLI only
cargo install --features tui --path .    # CLI + TUI
```
