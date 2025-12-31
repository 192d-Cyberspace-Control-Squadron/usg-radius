# USG RADIUS Documentation

This directory contains the complete documentation for the USG RADIUS server, built with Zensical.

## Documentation Structure

```
docs/
├── docs/                          # Documentation content
│   ├── index.md                   # Homepage
│   ├── quick-reference.md         # Quick reference guide
│   ├── getting-started/           # Installation and setup
│   │   └── installation.md
│   ├── protocol/                  # RADIUS protocol details
│   │   ├── overview.md
│   │   └── attributes.md
│   ├── configuration/             # Server configuration
│   │   ├── server.md
│   │   ├── users.md
│   │   └── clients.md
│   ├── api/                       # API reference
│   │   └── overview.md
│   ├── security/                  # Security guidelines
│   │   └── overview.md
│   └── examples/                  # Usage examples
│       └── basic-auth.md
├── zensical.toml                  # Site configuration
└── README.md                      # This file
```

## Building the Documentation

### Prerequisites

Install Zensical (if not already installed):

```bash
pip install zensical
# or
pipx install zensical
```

### Build the Site

```bash
cd docs
zensical build
```

The site will be generated in the `site/` directory.

### Serve Locally

```bash
cd docs
zensical serve
```

Then visit http://127.0.0.1:8000 in your browser.

### Watch Mode

For development, use watch mode to auto-rebuild on changes:

```bash
cd docs
zensical serve --watch
```

## Documentation Sections

### Home (index.md)

Overview of USG RADIUS with quick start guide and feature highlights.

### Quick Reference (quick-reference.md)

Fast reference for common tasks, commands, and configurations.

### Getting Started

- **Installation**: Step-by-step installation and first run

### Protocol

- **Overview**: RADIUS protocol details, packet structure, authentication flow
- **Attributes**: Complete attribute reference with examples

### Configuration

- **Server**: Server settings and configuration
- **Users**: User management and authentication
- **Clients**: Client (NAS) configuration

### API Reference

- **Overview**: Using USG RADIUS as a library, custom authentication handlers

### Security

- **Overview**: Security considerations, best practices, cryptographic details

### Examples

- **Basic Authentication**: Complete working example with code

## Contributing to Documentation

1. Create or edit Markdown files in `docs/docs/`
2. Test locally with `zensical serve`
3. Commit changes
4. Documentation will be built and deployed automatically

## Contact

For documentation issues or suggestions:

- Open an issue on GitHub
- Contact: John Edward Willman V <john.willman.1@us.af.mil>
