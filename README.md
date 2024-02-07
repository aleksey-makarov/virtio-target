# Virtio Over Fabrics

> "Virtio Over Fabrics" aims at "reuse virtio device specifications",
> and provides network defined peripheral devices.
> And this protocol also could be used in virtualization environment,
> typically hypervisor (or vhost-user process) handles request from virtio PCI/MMIO/CCW,
> remaps request and forwards to target by fabrics.

## History

Virtio-oF was introduced by Zhenwei Pi <pizhenwei@bytedance.com> in the virtio-comment (https://lists.oasis-open.org/archives/virtio-comment/) mailing list.

V4 was issued on July 2023: https://lists.oasis-open.org/archives/virtio-comment/202306/msg00446.html

Initial post https://lists.oasis-open.org/archives/virtio-comment/202304/msg00442.html refers to some implementation of it:

Kernel: https://github.com/pizhenwei/linux/tree/virtio-of-github

Target: https://github.com/pizhenwei/virtio-target/ It looks like it contains implementations for VIRTIO block,  crypto and random number generator devices.

## NIX

### What is Nix

`Nix` is a package manager that provides reproducible environment.
[`NixOS`](https://nixos.org/) is a Linux distributive that uses `Nix` as package manager.
Flakes is a recent feature of the `Nix` package manager that simplifies configuration of
complex projects.

### Intallation

`Nix` can be installed on virtually any Linux distributive.
Follow [the link](https://nixos.org/download) (single-user installation).
After installation, enable flake support.
To do that, create file `~/.config/nix/nix.conf` or `/etc/nix/nix.conf`
and add this line to it:

    experimental-features = nix-command flakes

For the reference [look here](https://nixos.wiki/wiki/Flakes).

### How to run development environment

Clone the Remote GPU repo from GitHub, enter to the created directory and run `nix` development environment:

    git clone -b work https://github.com/aleksey-makarov/virtio-target.git
    cd virtio-target
    nix develop

The last command will download the most of the required software from the `Nix` caches
and create the environment.
After it completes you will be presented a shell environment where all the required
software is ready to use.
