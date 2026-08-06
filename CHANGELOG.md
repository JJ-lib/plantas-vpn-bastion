# Changelog

All notable changes to Bastión VPN will be documented here. The project has not published a stable release yet.

## [Unreleased]

- Reworked the repository boundary into a generic public source monorepo; deployment-generated overlays and operational data are external.
- Added canonical operator, architecture, networking, security, and contributor documentation.
- Added repository branding, neutral SVG illustrations, issue forms, and validation workflows.
- Preserved the generated site VPN/proxy implementation and imported Guacamole CLIPRDR customization.

## [0.1.0-dev]

- Initial production-oriented control-plane baseline.
- Docker Compose control plane with panel, reconciler, Caddy, Guacamole, and guacd.
- Generic templates and engine-specific VPN/proxy images.
