## [0.3.0] UNRELEASED
### Added
- Add support for sideloading XDP program by another loader. Now you can use `spale` alongside other XDP programs
- Add support for specifying listening address for ipv4 and ipv6. Defaults to `0.0.0.0` and `[::]`
- Add bpfman bytecode image

### Changed
- Pin maps are now used for persisting state across runs instead of being teardown. These are required if you are using maps from an external loader

## [0.2.0] 2025-10-17
### Added
- Add profile support for client tool
- Add server management cli tooling for querying the system for authorized IPs and manage the runtime

### Changed
- Gate checks now only apply to the host (improved interface handling)
- Code deduplication and modularization

### Fixed
- Use sendto() instead of send() for better network handling

## [0.1.1] - 2025-10-10
- Fix inline comments parsing
- Fix clock issues

## [0.1.0] - 2025-10-08
- Initial public release
