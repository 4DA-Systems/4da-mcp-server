# 0.30.0

 * Split `System` into subtypes: `Components`, `Disks`, `Networks` and `Users`.
 * `brand`, `vendor_id` and `frequency` information is not set anymore on the global CPU.
 * Unix: Fix endless loop in user groups retrieval.
 * Unix/Windows: Fix infinite loop when retrieving various information because of bad usage
   of `Vec::reserve`.
 * Unix: Fix invalid usage of NULL pointer when retrieving user group name.
 * Linux: Fix CPU name retrieval.
 * Linux: Remove cgroup usage from memory computation.
 * Linux: Add `linux-netdevs` feature to allow to retrieve network devices.
 * Linux: Improve system memory information retrieval (using `statm` file instead of `stat`).
 * Linux: Tasks are listed in processes.
 * macOS: Correctly retrieve process root directory.
 * Windows: Add warning that `System::load_average` is not working in documentation.
 * Windows: Fix invalid use of NULL pointer when retrieving users groups.
 * Windows: Correctly retrieve process root directory.
 * Create new `System::cgroup_limits` method.
 * Remove `System::refresh_system` method.
 * `Disk::file_system` and `Disk::name` now return an `Option<&OsStr>`.
 * Implement `Display` trait on `DiskKind`.
 * Move from `winapi` to `windows` crate.
 * Add `System::cpu_arch`.
 * Add `System::refresh_pids` and `System::refresh_pids_specifics`.
 * `System::boot_time`, `System::cpu_arch`, `System::distribution_id`, `System::host_name`,
   `System::kernel_version`, `System::load_average`, `System::long_os_version`, `System::name`,
   `System::os_version` and `System::uptime` are static methods.
 * `ProcessRefreshKind` has a lot more of possibilities for better control over updates.
 * Add new `UpdateKind` enum.
 * Add new `MemoryRefreshKind` struct.
 * Add new `System::refresh_memory_specifics` method.
 * `Process::exe`, `Process::cwd` and `Process::root` return an `Option<&Path>`.
 * `Process::tasks` method is available on all platforms.
 * `Process::tasks` method returns a `HashSet<Pid>`.
 * Move `System::IS_SUPPORTED`, `System::SUPPORTED_SIGNALS` and
   `System::MINIMUM_CPU_UPDATE_INTERVAL` constants out of `System` directly at the crate top-level.
 * Rename `IS_SUPPORTED` into `IS_SUPPORTED_SYSTEM`.
 * Fix `serde` serialization.
 * Add `System::refresh_cpu_frequency` and `System::refresh_cpu_all`.
 * Fix `sysinfo.h` and C wrapper.
 * Add a migration guide.

# 0.29.11

 * macOS: Fix bug when a user group doesn't have a name.
