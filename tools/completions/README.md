# Shell completion for shorewall-nft

Pre-generated bash, zsh, and fish completion scripts for the
`shorewall-nft` CLI. Click's built-in completion engine handles
commands, subcommands, options, and directory arguments.

## Install

### bash

```bash
# Per-user
mkdir -p ~/.local/share/bash-completion/completions
cp tools/completions/shorewall-nft.bash \
   ~/.local/share/bash-completion/completions/shorewall-nft

# System-wide (requires root)
sudo cp tools/completions/shorewall-nft.bash \
        /etc/bash_completion.d/shorewall-nft
```

Restart your shell or `source` the file. Test:

```bash
shorewall-nft <TAB><TAB>        # lists all top-level commands
shorewall-nft start --<TAB>     # lists --config-dir, --netns, etc.
```

### zsh

```bash
# Per-user (with oh-my-zsh or similar)
mkdir -p ~/.zsh/completions
cp tools/completions/shorewall-nft.zsh ~/.zsh/completions/_shorewall-nft

# Ensure it's on fpath (add to ~/.zshrc if not):
fpath=(~/.zsh/completions $fpath)
autoload -U compinit && compinit
```

### fish

```bash
# Per-user
mkdir -p ~/.config/fish/completions
cp tools/completions/shorewall-nft.fish \
   ~/.config/fish/completions/shorewall-nft.fish
```

Fish picks it up automatically on next shell start.

## Regenerating

If you add new commands or options, regenerate the completion files:

```bash
source .venv/bin/activate

_SHOREWALL_NFT_COMPLETE=bash_source shorewall-nft \
    > tools/completions/shorewall-nft.bash

_SHOREWALL_NFT_COMPLETE=zsh_source shorewall-nft \
    > tools/completions/shorewall-nft.zsh

_SHOREWALL_NFT_COMPLETE=fish_source shorewall-nft \
    > tools/completions/shorewall-nft.fish
```

Commit the regenerated files.

## Distro packaging

Packages should install these files to the standard completion paths:

| Shell | Path |
|-------|------|
| bash | `/usr/share/bash-completion/completions/shorewall-nft` |
| zsh | `/usr/share/zsh/site-functions/_shorewall-nft` |
| fish | `/usr/share/fish/vendor_completions.d/shorewall-nft.fish` |
