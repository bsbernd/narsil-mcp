#!/bin/bash
# Setup script for narsil-mcp
set -e

echo "🦀 Setting up narsil-mcp..."

# Check for Rust
if ! command -v cargo &> /dev/null; then
    echo "📦 Installing Rust..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    # shellcheck source=/dev/null
    source "$HOME/.cargo/env"
fi

# Build release binary
echo "🔨 Building release binary..."
cargo build --release

# Create symlink in PATH (optional)
INSTALL_DIR="$HOME/.local/bin"
mkdir -p "$INSTALL_DIR"

if [[ ":$PATH:" != *":$INSTALL_DIR:"* ]]; then
    echo "⚠️  Adding $INSTALL_DIR to PATH in your shell config..."
    # shellcheck disable=SC2016  # Single quotes intentional - we want $HOME to expand at runtime
    echo 'export PATH="$HOME/.local/bin:$PATH"' >> "$HOME/.bashrc"
fi

# delete first to avoid ETXTBSY if narsil-mcp is running
rm -f "$INSTALL_DIR/narsil-mcp" 
cp target/release/narsil-mcp "$INSTALL_DIR/"
echo "✅ Installed to $INSTALL_DIR/narsil-mcp"

# Print usage
echo ""
echo "🎉 Setup complete! Usage:"
echo ""
echo "  # Index a repository"
echo "  narsil-mcp --repos /path/to/your/project"
echo ""
echo "  # Add to Claude Desktop config:"
cat << EOF
  {
    "mcpServers": {
      "narsil-mcp": {
        "command": "${INSTALL_DIR}/narsil-mcp",
        "args": ["--repos", "/path/to/your/projects"]
      }
    }
  }
EOF
