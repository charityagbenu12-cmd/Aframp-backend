#!/bin/bash

# Aframp Backend Setup Script
# This script helps set up the development environment

set -e  # Exit on any error

# Detect operating system
detect_os() {
    case "$(uname -s)" in
        Linux*)     OS="linux";;
        Darwin*)    OS="macos";;
        CYGWIN*)    OS="cygwin";;
        MINGW*)     OS="mingw";;
        MSYS*)      OS="msys";;
        *)          OS="unknown";;
    esac
    echo "$OS"
}

# Detect Linux distribution
detect_distro() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        echo "$ID"
    elif [ -f /etc/arch-release ]; then
        echo "arch"
    elif [ -f /etc/debian_version ]; then
        echo "debian"
    else
        echo "unknown"
    fi
}

OS=$(detect_os)
DISTRO=""

# Validate supported OS and detect distribution
echo "🔍 Detecting operating system..."
case "$OS" in
    linux)
        DISTRO=$(detect_distro)
        echo "✅ Detected OS: Linux ($DISTRO)"
        ;;
    macos)
        echo "✅ Detected OS: macOS"
        ;;
    *)
        echo "❌ Unsupported operating system: $OS"
        echo "This setup script supports Linux and macOS only."
        echo "Please install the required dependencies manually:"
        echo "  - Rust (https://rustup.rs/)"
        echo "  - PostgreSQL (https://www.postgresql.org/download/)"
        echo "  - Redis (https://redis.io/download)"
        exit 1
        ;;
esac

echo "🚀 Setting up Aframp Backend Development Environment"

# Check if Rust is installed
if ! command -v rustc &> /dev/null; then
    echo "🦀 Installing Rust..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
    source ~/.cargo/env
else
    echo "✅ Rust is already installed"
fi

# Check if PostgreSQL is installed
if ! command -v psql &> /dev/null; then
    echo "🐘 Installing PostgreSQL..."
    if [[ "$OS" == "linux" ]]; then
        case "$DISTRO" in
            arch|manjaro|endeavouros|blackarch)
                sudo pacman -Sy --noconfirm postgresql
                ;;
            debian|ubuntu|linuxmint|pop)
                sudo apt update
                sudo apt install -y postgresql postgresql-contrib
                ;;
            fedora|rhel|centos|rocky|almalinux)
                sudo dnf install -y postgresql-server postgresql-contrib
                ;;
            *)
                echo "❌ Unsupported Linux distribution: $DISTRO"
                echo "Please install PostgreSQL manually."
                exit 1
                ;;
        esac
    elif [[ "$OS" == "macos" ]]; then
        brew install postgresql
    else
        echo "❌ Unsupported OS. Please install PostgreSQL manually."
        exit 1
    fi
else
    echo "✅ PostgreSQL is already installed"
fi

# Check if Redis is installed
if ! command -v redis-cli &> /dev/null; then
    echo "🧠 Installing Redis..."
    if [[ "$OS" == "linux" ]]; then
        case "$DISTRO" in
            arch|manjaro|endeavouros|blackarch)
                sudo pacman -Sy --noconfirm redis
                ;;
            debian|ubuntu|linuxmint|pop)
                sudo apt install -y redis-server
                ;;
            fedora|rhel|centos|rocky|almalinux)
                sudo dnf install -y redis
                ;;
            *)
                echo "❌ Unsupported Linux distribution: $DISTRO"
                echo "Please install Redis manually."
                exit 1
                ;;
        esac
    elif [[ "$OS" == "macos" ]]; then
        brew install redis
    else
        echo "❌ Unsupported OS. Please install Redis manually."
        exit 1
    fi
else
    echo "✅ Redis is already installed"
fi

# Start services
echo "🔄 Starting services..."
if [[ "$OS" == "linux" ]]; then
    case "$DISTRO" in
        arch|manjaro|endeavouros|blackarch)
            # Initialize PostgreSQL database if not already done
            if [ ! -d "/var/lib/postgres/data" ]; then
                sudo -u postgres initdb -D /var/lib/postgres/data
            fi
            sudo systemctl start postgresql
            sudo systemctl start redis
            ;;
        debian|ubuntu|linuxmint|pop|fedora|rhel|centos|rocky|almalinux)
            sudo systemctl start postgresql
            sudo systemctl start redis
            ;;
    esac
elif [[ "$OS" == "macos" ]]; then
    brew services start postgresql
    brew services start redis
fi

# Create database
echo "📊 Creating database..."
sudo -u postgres createdb aframp 2>/dev/null || echo "✅ Database already exists"
sudo -u postgres createuser -s $USER 2>/dev/null || echo "✅ User already exists"

# Install sqlx CLI
if ! command -v sqlx &> /dev/null; then
    echo "🔧 Installing sqlx CLI..."
    cargo install --features postgres sqlx-cli --quiet
else
    echo "✅ sqlx CLI is already installed"
fi

# Run migrations
echo "📋 Running database migrations..."
DATABASE_URL=postgresql:///aframp sqlx migrate run

# Create .env file if it doesn't exist
if [ ! -f .env ]; then
    echo "📝 Creating .env file..."
    cp .env.example .env
    echo "✅ Created .env file. Please review and update as needed."
else
    echo "✅ .env file already exists"
fi

# Build the project
echo "🏗️ Building the project..."
cargo build

echo ""
echo "🎉 Setup complete!"
echo ""
echo "Next steps:"
echo "1. Review and update the .env file with your configuration"
echo "2. Run the server: cargo run"
echo "3. For development: cargo watch -x run (install cargo-watch first)"
echo ""
echo "For more information, check the README.md and QUICK_START.md files"