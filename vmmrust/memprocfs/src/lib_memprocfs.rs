//! # The MemProcFS API Documentation
//!
//! The MemProcFS crate contains a wrapper API around the [MemProcFS physical
//! memory analysis framework](https://github.com/ufrisk/MemProcFS). The native
//! library in the form of `vmm.dll`, `vmm.dylib`, `vmm.so` must be downloaded
//! or compiled in order to make use of the memprocfs crate.
//! 
//! Physical memory analysis may take place on memory dump files for forensic
//! purposes. Analysis may also take place on live memory - either captured by
//! using [PCILeech PCIe DMA devices](https://github.com/ufrisk/pcileech-fpga)
//! or by using a driver - such as WinPMEM, LiveCloudKd, VMware or similar.
//! 
//! The base of the MemProcFS API is the [`Vmm`] struct. Once the native vmm
//! has been initialized it's possible to retrieve processes in the form of
//! the [`VmmProcess`] struct. Using the `Vmm` and `VmmProcess` it's possible
//! to undertake a wide range of actions - such as reading/writing memory or
//! retrieve various information.
//! 
//! The use of the low-level [`LeechCore`] library is also possible. [LeechCore](https://github.com/ufrisk/LeechCore/wiki)
//! is used for low-level tasks such as setting a [memory map](https://github.com/ufrisk/LeechCore/wiki/Device_FPGA_AMD_Thunderbolt),
//! implementing raw PCIe Transaction Layer Packet (TLP), PCIe Base Address
//! Register (BAR) support and more.
//! 
//! 
//! <b>Read and write memory</b> by using the methods
//! [`mem_read()`](VmmProcess::mem_read()),
//! [`mem_read_ex()`](VmmProcess::mem_read_ex()),
//! [`mem_read_as()`](VmmProcess::mem_read_as()) and
//! [`mem_write()`](VmmProcess::mem_write()) /
//! [`mem_write_as()`](VmmProcess::mem_write_as()).
//! Virtual memory is read from [`VmmProcess`] struct.
//! Physical memory is read from the [`Vmm`] struct.
//! 
//! <b>Efficiently read and write memory</b> using the [`VmmScatterMemory`]
//! struct. The scatter struct is retrieved by calling
//! [`mem_scatter()`](VmmProcess::mem_scatter()) on either the base [`Vmm`]
//! struct or the individual [`VmmProcess`] structs.
//! 
//! <b>Access information</b> about loaded modules, memory regions, registry,
//! process handles, kernel pool allocations and much more!
//! 
//! <b>Access the Virtual File System</b> (VFS) using the Rust API to get access
//! to the full range of built-in and external plugins. The VFS is accessed by
//! using the methods
//! [`vfs_list()`](Vmm::vfs_list()), [`vfs_read()`](Vmm::vfs_read()) and
//! [`vfs_write()`](Vmm::vfs_write()) on the [`Vmm`] struct.
//! 
//! The MemProcFS crate and API also supports creation of native MemProcFS
//! plugins in the form of a library `.dll` or `.so`.
//! 
//! 
//! ## Example projects
//! Check out the
//! [Example Project](https://github.com/ufrisk/MemProcFS/blob/master/vmmrust/memprocfs_example/src/main.rs)
//! and the
//! [Example Plugin](https://github.com/ufrisk/MemProcFS/blob/master/vmmrust/m_example_plugin/src/lib.rs).
//! 
//! 
//! ## Project documentation
//! Check out the project documentation for MemProcFS, LeechCore and pcileech-fpga:
//! * [MemProcFS](https://github.com/ufrisk/MemProcFS) - [Documentation](https://github.com/ufrisk/MemProcFS/wiki).
//! * [LeechCore](https://github.com/ufrisk/LeechCore/) - [Documentation](https://github.com/ufrisk/LeechCore/wiki).
//! * [PCILeech](https://github.com/ufrisk/pcileech) - [Documentation](https://github.com/ufrisk/pcileech/wiki).
//! * [PCILeech-FPGA](https://github.com/ufrisk/pcileech-fpga).
//! 
//! 
//! ## Support PCILeech/MemProcFS development:
//! PCILeech and MemProcFS is free and open source!
//! 
//! I put a lot of time and energy into PCILeech and MemProcFS and related
//! research to make this happen. Some aspects of the projects relate to
//! hardware and I put quite some money into my projects and related research.
//! If you think PCILeech and/or MemProcFS are awesome tools and/or if you
//! had a use for them it's now possible to contribute by becoming a sponsor!
//! 
//! If you like what I've created with PCIleech and MemProcFS with regards to
//! DMA, Memory Analysis and Memory Forensics and would like to give something
//! back to support future development please consider becoming a sponsor at:
//! <https://github.com/sponsors/ufrisk>
//! 
//! To all my sponsors, Thank You 💖
//! 
//! 
//! ## Questions and Comments
//! Please feel free to contact me!
//! * Github: <https://github.com/ufrisk/MemProcFS>
//! * Discord Server: <https://discord.gg/pcileech>.
//! * Twitter: <https://twitter.com/UlfFrisk>
//! * Email: pcileech@frizk.net
//! 
//! 
//! ## Get Started!
//! Check out the [`Vmm`] documentation and the
//! [Example Project](https://github.com/ufrisk/MemProcFS/tree/master/vmmrust/memprocfs_example)!
//! 
//! <b>Best wishes with your memory analysis project!</b>

//
// (c) Ulf Frisk, 2023-2024
// Author: Ulf Frisk, pcileech@frizk.net
// https://github.com/ufrisk/LeechCore
//

use std::collections::HashMap;
use std::ffi::{CStr, CString, c_char, c_int};
use std::fmt;
use anyhow::{anyhow, Context};
use serde::{Serialize, Deserialize};



/// Result type for MemProcFS API.
/// 
/// The MemProcFS result type is a wrapper around the anyhow::Result type.
/// It contains a function-defined return type and a String error type.
pub type ResultEx<T> = anyhow::Result<T>;



// MemProcFS memory read/write flags:
/// Do not use internal data cache.
pub const FLAG_NOCACHE                              : u64 = 0x0001;
/// Zero pad failed memory reads and report success.
pub const FLAG_ZEROPAD_ON_FAIL                      : u64 = 0x0002;
/// Force use of data cache - fail non-cached pages.
///
/// Flag is only valid for reads, invalid with VMM_FLAG_NOCACHE/VMM_FLAG_ZEROPAD_ON_FAIL.
pub const FLAG_FORCECACHE_READ                      : u64 = 0x0008;
/// Do not retrieve memory from paged out memory.
/// 
/// Paged out memory may be from pagefile/compressed (even if possible).
/// If slow I/O accesses are the concern the flag `FLAG_NOPAGING_IO` may be a better choice.
pub const FLAG_NOPAGING                             : u64 = 0x0010;
/// Do not retrieve memory from paged out memory***.
/// 
/// ***) If the read would incur additional I/O (even if possible).
pub const FLAG_NOPAGING_IO                          : u64 = 0x0020;
/// Do not populate the data cache on a successful read.
pub const FLAG_NOCACHEPUT                           : u64 = 0x0100;
/// Only fetch from the most recent active cache region when reading.
pub const FLAG_CACHE_RECENT_ONLY                    : u64 = 0x0200;
/// Deprecated/Unused.
pub const FLAG_NO_PREDICTIVE_READ                   : u64 = 0x0400;
/// Disable/override any use of VMM_FLAG_FORCECACHE_READ.
/// 
/// This flag is only recommended for local files. improves forensic artifact order.
pub const FLAG_FORCECACHE_READ_DISABLE              : u64 = 0x0800;
/// Disable clearing of memory supplied to VmmScatterMemory.prepare_ex
pub const FLAG_SCATTER_PREPAREEX_NOMEMZERO          : u64 = 0x1000;
/// Get/Set library console printouts.
pub const CONFIG_OPT_CORE_PRINTF_ENABLE             : u64 = 0x4000000100000000;
/// Get/Set standard verbosity.
pub const CONFIG_OPT_CORE_VERBOSE                   : u64 = 0x4000000200000000;
/// Get/Set extra verbosity.
pub const CONFIG_OPT_CORE_VERBOSE_EXTRA             : u64 = 0x4000000300000000;
/// Get/Set super extra verbosity and PCIe TLP debug.
pub const CONFIG_OPT_CORE_VERBOSE_EXTRA_TLP         : u64 = 0x4000000400000000;
/// Get max native physical memory address.
pub const CONFIG_OPT_CORE_MAX_NATIVE_ADDRESS        : u64 = 0x4000000800000000;
/// Get the LeechCore native handle. (void*) (do not close/free).
pub const CONFIG_OPT_CORE_LEECHCORE_HANDLE          : u64 = 0x4000001000000000;
/// Get the vmmid that may be used with startup option '-create-from-vmmid' to create a thread-safe duplicate VMM instance.
pub const CONFIG_OPT_CORE_VMM_ID                    : u64 = 0x4000002000000000;
/// Get the numeric system type according to VMM C-API.
pub const CONFIG_OPT_CORE_SYSTEM                    : u64 = 0x2000000100000000;
/// Get the numeric memory model type according to the VMM C-API.
pub const CONFIG_OPT_CORE_MEMORYMODEL               : u64 = 0x2000000200000000;
/// Get whether the refresh is enabled or not (1/0).
pub const CONFIG_OPT_CONFIG_IS_REFRESH_ENABLED      : u64 = 0x2000000300000000;
/// Get/Set base tick period in ms.
pub const CONFIG_OPT_CONFIG_TICK_PERIOD             : u64 = 0x2000000400000000;
/// Get/Set memory cache validity period (in ticks).
pub const CONFIG_OPT_CONFIG_READCACHE_TICKS         : u64 = 0x2000000500000000;
/// Get/Set page table (tlb) cache validity period (in ticks).
pub const CONFIG_OPT_CONFIG_TLBCACHE_TICKS          : u64 = 0x2000000600000000;
/// Get/Set process refresh (partial) period (in ticks).
pub const CONFIG_OPT_CONFIG_PROCCACHE_TICKS_PARTIAL : u64 = 0x2000000700000000;
/// Get/Set process refresh (full) period (in ticks).
pub const CONFIG_OPT_CONFIG_PROCCACHE_TICKS_TOTAL   : u64 = 0x2000000800000000;
/// Get MemProcFS major version.
pub const CONFIG_OPT_CONFIG_VMM_VERSION_MAJOR       : u64 = 0x2000000900000000;
/// Get MemProcFS minor version.
pub const CONFIG_OPT_CONFIG_VMM_VERSION_MINOR       : u64 = 0x2000000A00000000;
/// Get MemProcFS revision version.
pub const CONFIG_OPT_CONFIG_VMM_VERSION_REVISION    : u64 = 0x2000000B00000000;
/// Get/Set enable function call statistics (.status/statistics_fncall file).
pub const CONFIG_OPT_CONFIG_STATISTICS_FUNCTIONCALL : u64 = 0x2000000C00000000;
/// Get/Set enable paging support 1/0.
pub const CONFIG_OPT_CONFIG_IS_PAGING_ENABLED       : u64 = 0x2000000D00000000;
/// Set native library internal custom debug.
pub const CONFIG_OPT_CONFIG_DEBUG                   : u64 = 0x2000000E00000000;
/// Get OS version major.
pub const CONFIG_OPT_WIN_VERSION_MAJOR              : u64 = 0x2000010100000000;
/// Get OS version minor.
pub const CONFIG_OPT_WIN_VERSION_MINOR              : u64 = 0x2000010200000000;
/// Get OS version build.
pub const CONFIG_OPT_WIN_VERSION_BUILD              : u64 = 0x2000010300000000;
/// Get MemProcFS unique system id.
pub const CONFIG_OPT_WIN_SYSTEM_UNIQUE_ID           : u64 = 0x2000010400000000;
/// Get/Set enable/retrieve forensic mode type [0-4].
pub const CONFIG_OPT_FORENSIC_MODE                  : u64 = 0x2000020100000000;

// REFRESH OPTIONS:
/// Set - trigger refresh all caches.
pub const CONFIG_OPT_REFRESH_ALL                    : u64 = 0x2001ffff00000000;
/// Set - refresh memory cache (excl. TLB) (fully).
pub const CONFIG_OPT_REFRESH_FREQ_MEM               : u64 = 0x2001100000000000;
/// Set - refresh memory cache (excl. TLB) [partial 33%/call].
pub const CONFIG_OPT_REFRESH_FREQ_MEM_PARTIAL       : u64 = 0x2001000200000000;
/// Set - refresh page table (TLB) cache (fully)
pub const CONFIG_OPT_REFRESH_FREQ_TLB               : u64 = 0x2001080000000000;
/// Set - refresh page table (TLB) cache [partial 33%/call].
pub const CONFIG_OPT_REFRESH_FREQ_TLB_PARTIAL       : u64 = 0x2001000400000000;
/// Set - refresh fast frequency - incl. partial process refresh.
pub const CONFIG_OPT_REFRESH_FREQ_FAST              : u64 = 0x2001040000000000;
/// Set - refresh medium frequency - incl. full process refresh.
pub const CONFIG_OPT_REFRESH_FREQ_MEDIUM            : u64 = 0x2001000100000000;
/// Set - refresh slow frequency.
pub const CONFIG_OPT_REFRESH_FREQ_SLOW              : u64 = 0x2001001000000000;
/// Set custom process directory table base. [LO-DWORD: Process PID].
pub const CONFIG_OPT_PROCESS_DTB                    : u64 = 0x2002000100000000;

// PLUGIN NOTIFICATIONS:
/// Verbosity change. Query new verbosity with: `vmm.get_config()`.
pub const PLUGIN_NOTIFY_VERBOSITYCHANGE             : u32 = 0x01;
/// Fast refresh. Partial process refresh.
pub const PLUGIN_NOTIFY_REFRESH_FAST                : u32 = 0x05;
/// Medium refresh. Full process refresh and other refresh tasks.
pub const PLUGIN_NOTIFY_REFRESH_MEDIUM              : u32 = 0x02;
/// Slow refresh. Total refresh of as much as possible.
pub const PLUGIN_NOTIFY_REFRESH_SLOW                : u32 = 0x04;
/// Forensic mode initialization start.
pub const PLUGIN_NOTIFY_FORENSIC_INIT               : u32 = 0x01000100;
/// Forensic mode processing is completed.
pub const PLUGIN_NOTIFY_FORENSIC_INIT_COMPLETE      : u32 = 0x01000200;
/// A child VM was attached or detached. Query new state with API.
pub const PLUGIN_NOTIFY_VM_ATTACH_DETACH            : u32 = 0x01000400;



/// <b>MemProcFS API Base Struct.</b>
/// 
/// The [`Vmm`] struct is the base of the MemProcFS API. All API accesses
/// takes place from the [`Vmm`] struct and its sub-structs.
/// 
/// The [`Vmm`] struct acts as a wrapper around the native MemProcFS VMM API.
/// 
/// <b>Check out the example project for more detailed API usage and
/// additional examples!</b>
/// 
/// 
/// # Created By
/// - [`Vmm::new()`]
/// - [`Vmm::new_from_leechcore()`]
/// - [`Vmm::new_from_virtual_machine()`]
/// - `plugin sub-system`
/// 
/// The [`Vmm`] is normally created by [`Vmm::new()`] (see example below).
/// 
/// The [`Vmm`] object represents memory analysis of a target system. If the
/// target system contains virtual machines additional child `Vmm` objects
/// representing the individual VMs may be retrieved by calling the
/// function [`Vmm::new_from_virtual_machine()`].
/// 
/// The [`Vmm`] object is also supplied by the plugin API to any plugins created.
/// 
/// 
/// # Examples
/// 
/// ```
/// // Initialize MemProcFS VMM on a Windows system parsing a
/// // memory dump and virtual machines inside it.
/// let args = ["-printf", "-v", "-waitinitialize", "-device", "C:\\Dumps\\mem.dmp"].to_vec();
/// if let Ok(vmm) = Vmm::new("C:\\MemProcFS\\vmm.dll", &args) {
///     ...
///     // The underlying native vmm is automatically closed 
///     // when the vmm object goes out of scope.
/// };
/// ```
/// 
/// ```
/// // Initialize MemProcFS VMM on a Linux system parsing live memory
/// // retrieved from a PCILeech FPGA hardware device.
/// let args = ["-device", "fpga"].to_vec();
/// if let Ok(vmm) = Vmm::new("/home/user/memprocfs/vmm.so", &args) {
///     ...
///     // The underlying native vmm is automatically closed 
///     // when the vmm object goes out of scope.
/// };
/// ```
#[allow(dead_code)]
#[derive(Debug)]
pub struct Vmm<'a> {
    path_lc : String,
    path_vmm : String,
    native : VmmNative,
    parent_vmm : Option<&'a Vmm<'a>>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum VmmLogLevel {
    _1Critical,
    _2Warning,
    _3Info,
    _4Verbose,
    _5Debug,
    _6Trace,
    _7None,
}

/// Info: Network connections.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VmmMapNetEntry {
    pub pid : u32,
    pub state : u32,
    pub address_family : u16,
    pub src_is_valid : bool,
    pub src_port : u16,
    pub src_addr_raw : [u8; 16],
    pub src_str : String,
    pub dst_is_valid : bool,
    pub dst_port : u16,
    pub dst_addr_raw : [u8; 16],
    pub dst_str : String,
    pub va_object : u64,
    pub filetime : u64,
    pub pool_tag : u32,
    pub desc : String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum VmmMapPfnType {
    Zero,
    Free,
    Standby,
    Modified,
    ModifiedNoWrite,
    Bad,
    Active,
    Transition,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum VmmMapPfnTypeExtended {
    Unknown,
    Unused,
    ProcessPrivate,
    PageTable,
    LargePage,
    DriverLocked,
    Shareable,
    File,
}

/// Info: Memory PFN (Page Frame Number).
/// 
/// # Created By
/// - [`vmm.map_pfn()`](Vmm::map_pfn())
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct VmmMapPfnEntry {
    pub pfn : u32,
    pub location : VmmMapPfnType,
    pub is_prototype : bool,
    pub color : u32,
    // extended attributes below - only valid if is_extended == true
    pub is_extended : bool,
    pub tp_ex : VmmMapPfnTypeExtended,
    pub pid : u32,
    pub ptes : [u32; 5],    // 1 = pfn:PTE, .. 4 = pfn:PML4E
    pub va : u64,
    pub va_pte : u64,
    pub pte_original : u64,
}

/// Info: Kernel device entries.
/// 
/// # Created By
/// - [`vmm.map_kdevice()`](Vmm::map_kdevice())
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VmmMapKDeviceEntry {
    /// Virtual address of the device object.
    pub va : u64,
    /// Depth of the device object.
    pub depth : u32,
    /// Device type according to FILE_DEVICE_* in the Windows API.
    pub device_type : u32,
    /// Device type name.
    pub device_type_name : String,
    /// Virtual address of the associated driver object.
    pub va_driver_object : u64,
    /// Virtual address of the attached device object.
    pub va_attached_device : u64,
    /// Virtual address for some device types.
    pub va_file_system_device : u64,
    /// Volume info for some device types.
    pub volume_info : String,
}

/// Info: Kernel driver entries.
/// 
/// # Created By
/// - [`vmm.map_kdriver()`](Vmm::map_kdriver())
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VmmMapKDriverEntry {
    /// Virtual address of the driver object.
    pub va : u64,
    /// Virtual address of the start of the loaded driver in memory (the module PE header).
    pub va_driver_start : u64,
    /// Size of the loaded driver in memory.
    pub cb_driver_size : u64,
    /// Virtual address of the associated device object.
    pub va_device_object : u64,
    /// Device name.
    pub name : String,
    /// Device path.
    pub path : String,
    /// Service key name.
    pub service_key_name : String,
    /// Virtual addresses of the major functions.
    pub major_function : [u64; 28],
}

/// Info: Kernel named object manager entries.
/// 
/// # Created By
/// - [`vmm.map_kobject()`](Vmm::map_kobject())
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VmmMapKObjectEntry {
    /// Virtual address of the object.
    pub va : u64,
    /// Virtual address of the parent of this object, or 0 if top-level object.
    pub va_parent : u64,
    /// Virtual address of the object's children object (in case of a directlry object).
    pub children : Vec<u64>,
    /// Object name.
    pub name : String,
    /// Object type.
    pub object_type : String,
}

/// Info: Kernel pool entries.
/// 
/// # Created By
/// - [`vmm.map_pool()`](Vmm::map_pool())
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct VmmMapPoolEntry {
    pub va : u64,
    pub cb : u32,
    pub tag : u32,
    pub is_alloc : bool,
    pub tp_pool : u8,           // VMMDLL_MAP_POOL_TYPE
    pub tp_subsegment : u8,     // VMMDLL_MAP_POOL_TYPE_SUBSEGMENT
}

/// Info: Physical memory map entries.
/// 
/// # Created By
/// - [`vmm.map_memory()`](Vmm::map_memory())
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct VmmMapMemoryEntry {
    pub pa : u64,
    pub cb : u64
}

/// Info: Services.
/// 
/// # Created By
/// - [`vmm.map_service()`](Vmm::map_service())
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VmmMapServiceEntry {
    pub ordinal : u32,
    pub va_object : u64,
    pub pid : u32,
    pub start_type : u32,
    pub service_type : u32,
    pub current_state : u32,
    pub controls_accepted : u32,
    pub win32_exit_code : u32,
    pub service_specific_exit_code : u32,
    pub check_point : u32,
    pub wait_hint : u32,
    pub name : String,
    pub name_display : String,
    pub path : String,
    pub user_type : String,
    pub user_account : String,
    pub image_path : String,
}

/// Info: Users.
/// 
/// # Created By
/// - [`vmm.map_user()`](Vmm::map_user())
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VmmMapUserEntry {
    pub user : String,
    pub sid : String,
    pub va_reg_hive : u64,
}

/// Info: Virtual Machines (VMs).
/// 
/// # Created By
/// - [`vmm.map_virtual_machine()`](Vmm::map_virtual_machine())
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VmmMapVirtualMachineEntry {
    h_vmm : usize,
    h_vm : usize,
    pub name : String,
    pub gpa_max : u64,
    pub tp_vm : u32,
    pub is_active : bool,
    pub is_readonly : bool,
    pub is_physicalonly : bool,
    pub partition_id : u32,
    pub guest_os_version_build : u32,
    pub guest_tp_system : u32,
    pub parent_mount_id : u32,
    pub vmmem_pid : u32,
}

/// VFS (Virtual File System) entry information - file or directory.
/// 
/// # Created By
/// - [`vmm.vfs_list()`](Vmm::vfs_list())
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VmmVfsEntry {
    /// Name of the file or directory.
    pub name : String,
    /// True if entry is a directory, False if entry is a file.
    pub is_directory : bool,
    /// File size if file.
    pub size : u64,
}

impl Vmm<'_> {
    /// <b>MemProcFS Initialization Function.</b>
    /// 
    /// The [`Vmm`] struct is the base of the MemProcFS API. All API accesses
    /// takes place from the [`Vmm`] struct and its sub-structs.
    /// 
    /// The [`Vmm`] struct acts as a wrapper around the native MemProcFS VMM API.
    /// 
    /// 
    /// # Arguments
    /// * `vmm_lib_path` - Full path to the native vmm library - i.e. `vmm.dll`,  `vmm.so` or `vmm.dylib` depending on platform.
    /// * `args` - MemProcFS command line arguments as a Vec<&str>.
    /// 
    /// MemProcFS command line argument documentation is found on the [MemProcFS wiki](https://github.com/ufrisk/MemProcFS/wiki/_CommandLine).
    /// 
    /// 
    /// # Examples
    /// 
    /// ```
    /// // Initialize MemProcFS VMM on a Windows system parsing a
    /// // memory dump and virtual machines inside it.
    /// let args = ["-printf", "-v", "-waitinitialize", "-device", "C:\\Dumps\\mem.dmp"].to_vec();
    /// if let Ok(vmm) = Vmm::new("C:\\MemProcFS\\vmm.dll", &args) {
    ///     ...
    ///     // The underlying native vmm is automatically closed 
    ///     // when the vmm object goes out of scope.
    /// };
    /// ```
    /// 
    /// ```
    /// // Initialize MemProcFS VMM on a Linux system parsing live memory
    /// // retrieved from a PCILeech FPGA hardware device.
    /// let args = ["-device", "fpga"].to_vec();
    /// if let Ok(vmm) = Vmm::new("/home/user/memprocfs/vmm.so", &args) {
    ///     ...
    ///     // The underlying native vmm is automatically closed 
    ///     // when the vmm object goes out of scope.
    /// };
    /// ```
    pub fn new<'a>(vmm_lib_path : &str, args: &Vec<&str>) -> ResultEx<Vmm<'a>> {
        return crate::impl_new(vmm_lib_path, None, 0, args);
    }

    /// <b>MemProcFS Initialization Function.</b>
    /// 
    /// The [`Vmm`] struct is the base of the MemProcFS API. All API accesses
    /// takes place from the [`Vmm`] struct and its sub-structs.
    /// 
    /// The [`Vmm`] struct acts as a wrapper around the native MemProcFS VMM API.
    /// 
    /// This function initializes a new [`Vmm`] struct from an already existing
    /// LeechCore object. The LeechCore object may be dropped at user discretion
    /// after the [`Vmm`] object has been created without it being affected. The
    /// underlying device will be closed when all internal LeechCore references
    /// have been dropped.
    /// 
    /// 
    /// # Arguments
    /// * `leechcore_existing` - The LeechCore struct to use as underlying device when initializing MemProcFS VMM.
    /// * `args` - MemProcFS command line arguments as a Vec<&str> not including any -device arguments.
    /// 
    /// MemProcFS command line argument documentation is found on the [MemProcFS wiki](https://github.com/ufrisk/MemProcFS/wiki/_CommandLine).
    /// 
    /// 
    /// # Examples
    /// 
    /// ```
    /// // Initialize MemProcFS VMM on a Windows system using an existing
    /// // LeechCore object to parse a memory dump. Note that no '-device'
    /// // argument should be supplied when using Vmm::new_from_leechcore.
    /// let args = ["-printf", "-v", "-waitinitialize"].to_vec();
    /// if let Ok(vmm) = Vmm::new_from_leechcore(&leechcore_existing, &args) {
    ///     ...
    ///     // The underlying native vmm is automatically closed 
    ///     // when the vmm object goes out of scope.
    /// };
    /// ```
    pub fn new_from_leechcore<'a>(leechcore_existing : &LeechCore, args: &Vec<&str>) -> ResultEx<Vmm<'a>> {
        return crate::impl_new_from_leechcore(leechcore_existing, args);
    }

    /// Initialize MemProcFS from a host VMM and a child VM.
    /// 
    /// Initialize a MemProcFS VMM object representing a child virtual machine (VM).
    /// 
    /// # Arguments
    /// * `vmm_parent` - The host (parent) [`Vmm`].
    /// * `vm_entry` - The [`VmmMapVirtualMachineEntry`] to initialize as a [`Vmm`].
    /// 
    /// # Examples
    /// ```
    /// if let Ok(virtualmachine_all) = vmm.map_virtual_machine() {
    ///     for virtualmachine in &*virtualmachine_all {
    ///         println!("{virtualmachine}");
    ///         if virtualmachine.is_active {
    ///             // for active vms it's possible to create a new vmm object for
    ///             // the vm. it's possible to treat this as any other vmm object
    ///             // to read memory, query processes etc.
    ///             let vmm_vm = match Vmm::new_from_virtual_machine(&vmm, &virtualmachine) {
    ///                 Err(_) => continue,
    ///                 Ok(r) => r,
    ///             };
    ///             let max_addr = vmm_vm.get_config(CONFIG_OPT_CORE_MAX_NATIVE_ADDRESS).unwrap_or(0);
    ///             println!("vm max native address: {:#x}", max_addr);
    ///         }
    ///     }
    /// }
    /// ```
    pub fn new_from_virtual_machine<'a>(vmm_parent : &'a Vmm, vm_entry : &VmmMapVirtualMachineEntry) -> ResultEx<Vmm<'a>> {
        return impl_new_from_virtual_machine(vmm_parent, vm_entry);
    }

    /// Retrieve the underlying LeechCore native handle.
    /// 
    /// # Examples
    /// ```
    /// let lc = vmm.get_leechcore()?;
    /// ```
    pub fn get_leechcore(&self) -> ResultEx<LeechCore> {
        return self.impl_get_leechcore();
    }

    /// Retrieve a single process by PID.
    /// 
    /// # Arguments
    /// * `pid` - Process id (PID) of the process to retrieve.
    /// 
    /// # Examples
    /// ```
    /// if let Ok(process) = vmm.process_from_pid(4) {
    ///     println!("{}", process);    
    /// }
    /// ```
    pub fn process_from_pid(&self, pid : u32) -> ResultEx<VmmProcess> {
        return self.impl_process_from_pid(pid);
    }

    /// Retrieve a single process by name.
    /// 
    /// If multiple processes have the same name the first process located by
    /// MemProcFS will be returned. If it is important to fetch the correct
    /// process retrieve the process list from `vmm.list()` and iterate.
    /// 
    /// # Arguments
    /// * `process_name` - Name of the process to retrieve.
    /// 
    /// # Examples
    /// ```
    /// if let Ok(process) = vmm.process_from_name("System") {
    ///     println!("{}", process);    
    /// }
    /// ```
    pub fn process_from_name(&self, process_name : &str) -> ResultEx<VmmProcess> {
        return self.impl_process_from_name(process_name);
    }

    /// Retrieve all processes.
    /// 
    /// # Examples
    /// ```
    /// // Retrieve all processes (as a Vec).
    /// process_all = vmm.process_list()?
    /// for process in &*process_all {
    ///     println!("{process} ");
    /// }
    /// ```
    pub fn process_list(&self) -> ResultEx<Vec<VmmProcess>> {
        return self.impl_process_list();
    }

    /// Retrieve all processes as a map.
    /// 
    /// K: PID,
    /// V: VmmProcess
    /// 
    /// # Examples
    /// ```
    ///  // Retrieve all processes as (a HashMap).
    /// process_all = vmm.process_map()?;
    /// for process in process_all {
    ///     println!("<{},{}> ", process.0, process.1);
    /// }
    /// ```
    pub fn process_map(&self) -> ResultEx<HashMap<u32, VmmProcess>> {
        return Ok(self.impl_process_list()?.into_iter().map(|s| (s.pid, s)).collect());
    }

    /// Get a numeric configuration value.
    /// 
    /// # Arguments
    /// * `config_id` - As specified by a `CONFIG_OPT_*` constant marked as `Get`. (Optionally or'ed | with process pid for select options).
    /// 
    /// # Examples
    /// ```
    /// println!("max addr: {:#x}", vmm.get_config(CONFIG_OPT_CORE_MAX_NATIVE_ADDRESS).unwrap_or(0));
    /// ```
    pub fn get_config(&self, config_id : u64) -> ResultEx<u64> {
        return self.impl_get_config(config_id);
    }

    /// Set a numeric configuration value.
    /// 
    /// # Arguments
    /// * `config_id` - As specified by a `CONFIG_OPT_*` constant marked as `Set`. (Optionally or'ed | with process pid for select options).
    /// * `config_value` - The config value to set.
    /// 
    /// # Examples
    /// ```
    /// // The below force MemProcFS to undertake a full refresh - refresing
    /// // processes, memory and other general data structures completely.
    /// let _r = vmm.set_config(CONFIG_OPT_REFRESH_ALL, 1);
    /// ```
    pub fn set_config(&self, config_id : u64, config_value : u64) -> ResultEx<()> {
        return self.impl_set_config(config_id, config_value);
    }

    /// Retrieve the kernel convenience struct.
    /// 
    /// The kernel struct provides easy access to kernel build number,
    /// the system process (pid 4) and kernel (nt) debug symbols.
    /// 
    /// # Examples
    /// ```
    /// // Retrieve and print the kernel build number.
    /// println!("{}", vmm.kernel().build());
    /// ```
    pub fn kernel(&self) -> VmmKernel {
        return VmmKernel { vmm : &self };
    }

    /// Log a message to the MemProcFS logging system.
    /// 
    /// # Arguments
    /// * `log_level`
    /// * `log_message`
    /// 
    /// # Examples
    /// ```
    /// vmm.log(&VmmLogLevel::_1Critical, "Test Message Critical!");
    /// ```
    pub fn log(&self, log_level : &VmmLogLevel, log_message : &str) {
        self.impl_log(VMMDLL_MID_RUST, log_level, log_message);
    }

    /// Retrieve the physical memory range info map.
    /// 
    /// # Examples
    /// ```
    /// if let Ok(memory_range_all) = vmm.map_memory() {
    ///     for memory_range in &*memory_range_all {
    ///         println!("{memory_range} \t pa={:x} cb={:x}", memory_range.pa, memory_range.cb);
    ///     }
    /// }
    /// ```
    pub fn map_memory(&self) -> ResultEx<Vec<VmmMapMemoryEntry>> {
        return self.impl_map_memory();
    }

    /// Retrieve the network connection info map.
    /// 
    /// # Examples
    /// ```
    /// let net_all vmm.map_net()?;
    /// for net in &*net_all {
    ///     println!("{net}");
    /// }
    /// ```
    pub fn map_net(&self) -> ResultEx<Vec<VmmMapNetEntry>> {
        return self.impl_map_net();
    }

    /// Retrieve the page frame number (PFN) info map.
    /// 
    /// # Arguments
    /// * `pfns` - The PFNs to retrieve.
    /// * `is_extended` - Retrieve extended information (more resource intense).
    /// 
    /// # Examples
    /// ```
    /// let pfns: Vec<u32> = (1..=10).collect();
    /// if let Ok(pfn_all) = vmm.map_pfn(&pfns, true) {
    ///     for pfn in &*pfn_all {
    ///         println!("{pfn} \t location={} tp_ex={} pid={:x} va={:x} color={}",
    ///                  pfn.location, pfn.tp_ex, pfn.pid, pfn.va, pfn.color);
    ///     }
    /// }
    /// ```
    pub fn map_pfn(&self, pfns : &Vec<u32>, is_extended : bool) -> ResultEx<Vec<VmmMapPfnEntry>> {
        return self.impl_map_pfn(pfns, is_extended);
    }

    /// Retrieve the kernel device map.
    /// 
    /// # Examples
    /// ```
    /// if let Ok(kdevices) = vmm.map_kdevice() {
    ///     println!("Number of devices: {}.", kdevices.len());
    ///     for kdevice in &*kdevices {
    ///         println!("{kdevice} ");
    ///     }
    ///     println!("");
    /// }
    /// ```
    pub fn map_kdevice(&self) -> ResultEx<Vec<VmmMapKDeviceEntry>> {
        return self.impl_map_kdevice();
    }

    /// Retrieve the kernel driver map.
    /// 
    /// # Examples
    /// ```
    /// if let Ok(kdrivers) = vmm.map_kdriver() {
    ///     println!("Number of drivers: {}.", kdrivers.len());
    ///     for kdriver in &*kdrivers {
    ///         println!("{kdriver} ");
    ///     }
    ///     println!("");
    /// }
    /// ```
    pub fn map_kdriver(&self) -> ResultEx<Vec<VmmMapKDriverEntry>> {
        return self.impl_map_kdriver();
    }

    /// Retrieve the kernel named objects map.
    /// 
    /// # Examples
    /// ```
    /// if let Ok(kobjects) = vmm.map_kobject() {
    ///     println!("Number of objects: {}.", kobjects.len());
    ///     for kobject in &*kobjects {
    ///         println!("{kobject} ");
    ///     }
    ///     println!("");
    /// }
    /// ```
    pub fn map_kobject(&self) -> ResultEx<Vec<VmmMapKObjectEntry>> {
        return self.impl_map_kobject();
    }

    /// Retrieve the kernel pool allocation info map.
    /// 
    /// # Arguments
    /// * `is_bigpool_only` - Retrieve only entries from the big pool (faster).
    /// 
    /// # Examples
    /// ```
    /// if let Ok(pool_all) = vmm.map_pool(false) {
    ///     println!("Number of pool allocations: {}.", pool_all.len());
    ///     let pool_proc_all : Vec<&VmmMapPoolEntry> =
    ///             pool_all.iter().filter(|e| e.tag == 0x636f7250 /* 'Proc' backwards */).collect();
    ///     println!("Number of pool 'Proc' allocations: {}.", pool_all.len());
    ///     for pool_proc in &*pool_proc_all {
    ///         print!("{pool_proc} ");
    ///     }
    ///     println!("");
    /// }
    /// ```
    pub fn map_pool(&self, is_bigpool_only : bool) -> ResultEx<Vec<VmmMapPoolEntry>> {
        return self.impl_map_pool(is_bigpool_only);
    }

    /// Retrieve the servives info map.
    /// 
    /// # Examples
    /// ```
    /// let service_all = vmm.map_service()?;
    /// for service in &*service_all {
    ///     println!("{service} ");
    /// }
    /// ```
    pub fn map_service(&self) -> ResultEx<Vec<VmmMapServiceEntry>> {
        return self.impl_map_service();
    }

    /// Retrieve the user map.
    /// 
    /// # Examples
    /// ```
    /// let user_all = vmm.map_user()?;
    /// for user in &*user_all {
    ///     println!("{:x}:: {} :: {} :: {user}", user.va_reg_hive, user.sid, user.user);
    /// }
    /// ```
    pub fn map_user(&self) -> ResultEx<Vec<VmmMapUserEntry>> {
        return self.impl_map_user();
    }

    /// Retrieve the virtual machines info map.
    /// 
    /// # Examples
    /// ```
    /// let virtualmachine_all = vmm.map_virtual_machine()?
    /// for virtualmachine in &*virtualmachine_all {
    ///     println!("{virtualmachine}");
    ///     if virtualmachine.is_active {
    ///         // for active vms it's possible to create a new vmm object for
    ///         // the vm. it's possible to treat this as any other vmm object
    ///         // to read memory, query processes etc.
    ///         let vmm_vm = match Vmm::new_from_virtual_machine(&vmm, &virtualmachine) {
    ///             Err(_) => continue,
    ///             Ok(r) => r,
    ///         };
    ///         println!("vm max native address: {:#x} -> {:#x}",
    ///                  CONFIG_OPT_CORE_MAX_NATIVE_ADDRESS,
    ///                  vmm_vm.get_config(CONFIG_OPT_CORE_MAX_NATIVE_ADDRESS).unwrap_or(0));
    ///     }
    /// }
    /// ```
    pub fn map_virtual_machine(&self) -> ResultEx<Vec<VmmMapVirtualMachineEntry>> {
        return self.impl_map_virtual_machine();
    }

    /// Read a contigious physical memory chunk.
    /// 
    /// The physical memory is read without any special flags. The whole chunk
    /// must be read successfully for the method to succeed.
    /// 
    /// If deseriable to provide flags modifying the behavior (such as skipping
    /// the built-in data cache or slower paging access) use the method
    /// `mem_read_ex()` instead.
    /// 
    /// Reading many memory chunks individually may be slow, especially if
    /// reading takes place using hardware FPGA devices. In that case it's
    /// better to use the `mem_scatter()` functionality for better performance.
    /// 
    /// 
    /// # Arguments
    /// * `pa` - Physical address to start reading from.
    /// * `size` - Number of bytes to read.
    /// 
    /// # Examples
    /// ```
    /// // Read 0x100 bytes of data starting at address 0x1000.
    /// // Example assumes: use pretty_hex::*;
    /// if let Ok(data_read) = vmm.mem_read(0x1000, 0x100) {
    ///     println!("{:?}", data_read.hex_dump());
    /// }
    /// ```
    pub fn mem_read(&self, pa : u64, size : usize) -> ResultEx<Vec<u8>> {
        return self.impl_mem_read(u32::MAX, pa, size, 0);
    }

    /// Read a contigious physical memory chunk with flags.
    /// 
    /// Flags are constants named `FLAG_*`
    /// 
    /// Reading many memory chunks individually may be slow, especially if
    /// reading takes place using hardware FPGA devices. In that case it's
    /// better to use the `mem_scatter()` functionality for better performance.
    /// 
    /// 
    /// # Arguments
    /// * `pa` - Physical address to start reading from.
    /// * `size` - Number of bytes to read.
    /// * `flags` - Any combination of `FLAG_*`.
    /// 
    /// # Examples
    /// ```
    /// // Read 0x100 bytes of data starting at address 0x1000.
    /// // Force reading the underlying memory device (skip data cache) and
    /// // Zero-Pad if parts of the memory read fail instead of failing.
    /// // Example assumes: use pretty_hex::*;
    /// if let Ok(data_read) = vmm.mem_read_ex(0x1000, 0x100, FLAG_NOCACHE | FLAG_ZEROPAD_ON_FAIL) {
    ///     println!("{:?}", data_read.hex_dump());
    /// }
    /// ```
    pub fn mem_read_ex(&self, pa : u64, size : usize, flags : u64) -> ResultEx<Vec<u8>> {
        return self.impl_mem_read(u32::MAX, pa, size, flags);
    }

    /// Read a contigious physical memory chunk with flags into a pre-existing buffer.
    /// 
    /// Flags are constants named `FLAG_*`
    /// 
    /// Reading many memory chunks individually may be slow, especially if
    /// reading takes place using hardware FPGA devices. In that case it's
    /// better to use the `mem_scatter()` functionality for better performance.
    /// 
    /// 
    /// # Arguments
    /// * `pa` - Physical address to start reading from.
    /// * `flags` - Any combination of `FLAG_*`.
    /// * `data` - Pre-allocated buffer to read into.
    /// 
    /// # Examples
    /// ```
    /// // Read 0x100 bytes of data starting at address 0x1000.
    /// // Force reading the underlying memory device (skip data cache) and
    /// // Zero-Pad if parts of the memory read fail instead of failing.
    /// // Example assumes: use pretty_hex::*;
    /// let mut data = [0u8; 0x100];
    /// if let Ok(length) = vmm.mem_read_into(0x1000, FLAG_NOCACHE | FLAG_ZEROPAD_ON_FAIL, &mut data) {
    ///     println!("bytes_read: {length}");
    ///     println!("{:?}", data.hex_dump());
    /// }
    /// ```
    pub fn mem_read_into(&self, pa : u64, flags : u64, data : &mut [u8]) -> ResultEx<usize> {
        return self.impl_mem_read_into(u32::MAX, pa, flags, data);
    }

    /// Read a contigious physical memory chunk with flags as a type/struct.
    /// 
    /// Flags are constants named `FLAG_*`
    /// 
    /// Reading many memory chunks individually may be slow, especially if
    /// reading takes place using hardware FPGA devices. In that case it's
    /// better to use the `mem_scatter()` functionality for better performance.
    /// 
    /// 
    /// # Arguments
    /// * `pa` - Physical address to start reading from.
    /// * `flags` - Any combination of `FLAG_*`.
    /// 
    /// # Examples
    /// ```
    /// // Read the C-struct IMAGE_DOS_HEADER from memory.
    /// // Force reading the underlying memory device (skip data cache).
    /// #[repr(C)]
    /// struct IMAGE_DOS_HEADER {
    ///     e_magic : u16,
    /// 	...
    ///     e_lfanew : u32,
    /// }
    /// if let Ok(doshdr) = vmm.mem_read_as::<IMAGE_DOS_HEADER>(pa_kernel32, FLAG_NOCACHE) {
    ///     println!("e_magic:  {:x}", doshdr.e_magic);
    ///     println!("e_lfanew: {:x}", doshdr.e_lfanew);
    /// }
    /// ```
    pub fn mem_read_as<T>(&self, pa : u64, flags : u64) -> ResultEx<T> {
        return self.impl_mem_read_as(u32::MAX, pa, flags);
    }

    /// Create a scatter memory object for efficient physical memory reads.
    /// 
    /// Check out the [`VmmScatterMemory`] struct for more detailed information.
    /// 
    /// # Arguments
    /// * `flags` - Any combination of `FLAG_*`.
    /// 
    /// # Examples
    /// ```
    /// let mem_scatter_physical = vmm.mem_scatter(FLAG_NOCACHE | FLAG_ZEROPAD_ON_FAIL)?;
    /// ```
    pub fn mem_scatter(&self, flags : u64) -> ResultEx<VmmScatterMemory> {
        return self.impl_mem_scatter(u32::MAX, flags);
    }

    /// Write physical memory.
    /// 
    /// The write is a best effort. Even of the write should fail it's not
    /// certain that an error will be returned. To be absolutely certain that
    /// a write has taken place follow up with a read.
    /// 
    /// # Arguments
    /// * `pa` - Physical address to start writing from.
    /// * `data` - Byte data to write.
    /// 
    /// # Examples
    /// ```
    /// let data_to_write = [0x56u8, 0x4d, 0x4d, 0x52, 0x55, 0x53, 0x54].to_vec();
    /// let _r = vmm.mem_write(0x1000, &data_to_write);
    /// ```
    pub fn mem_write(&self, pa : u64, data : &[u8]) -> ResultEx<()> {
        return self.impl_mem_write(u32::MAX, pa, data);
    }

    /// Write a type/struct to physical memory.
    /// 
    /// The write is a best effort. Even of the write should fail it's not
    /// certain that an error will be returned. To be absolutely certain that
    /// a write has taken place follow up with a read.
    /// 
    /// # Arguments
    /// * `pa` - Pnhysical address to start writing from.
    /// * `data` - Data to write. In case of a struct repr(C) is recommended.
    /// 
    /// # Examples
    /// ```
    /// let data_to_write = [0x56, 0x4d, 0x4d, 0x52, 0x55, 0x53, 0x54];
    /// let _r = vmm.mem_write_as(0x1000, &data_to_write);
    /// ```
    pub fn mem_write_as<T>(&self, pa : u64, data : &T) -> ResultEx<()> {
        return self.impl_mem_write_as(u32::MAX, pa, data);
    }

    /// List a VFS (Virtual File System) directory.
    /// 
    /// Returns a result containing the individual directory entries -
    /// which may be files or directories.
    /// 
    /// # Arguments
    /// * `path` - VFS path to list directory contents in. Ex: /sys/
    /// 
    /// # Examples
    /// ```
    /// let vfs_list_path = "/sys/";
    /// if let Ok(vfs_all) = vmm.vfs_list(vfs_list_path) {
    ///     println!("VFS directory listing for directory: {vfs_list_path}");
    ///     println!("Number of file/directory entries: {}.", vfs_all.len());
    ///     for vfs in &*vfs_all {
    ///         println!("{vfs}");
    ///     }
    /// }
    /// ```
    pub fn vfs_list(&self, path : &str) -> ResultEx<Vec<VmmVfsEntry>> {
        return self.impl_vfs_list(path);
    }

    /// Read a VFS (Virtual File System) file.
    /// 
    /// The read contents are returned as a Vec containing the byte results.
    /// If the end of the file is reached the number of read bytes may be
    /// shorter than the requested read size.
    /// 
    /// # Arguments
    /// * `filename` - Full vfs path of the file to read. Ex: /sys/version.txt
    /// * `size` - Number of bytes to read.
    /// * `offset` - File offset.
    /// 
    /// # Examples
    /// ```
    /// if let Ok(vfs_file_data) = vmm.vfs_read("/sys/memory/physmemmap.txt", 0x2000, 0) {
    ///     println!("Bytes read from file '/sys/memory/physmemmap.txt': {}.", vfs_file_data.len());
    ///     println!("{:?}", vfs_file_data.hex_dump());
    /// }
    /// ```
    pub fn vfs_read(&self, filename : &str, size : u32, offset : u64) -> ResultEx<Vec<u8>> {
        return self.impl_vfs_read(filename, size, offset);
    }

    /// Write a VFS (Virtual File System) file.
    /// 
    /// Writes are undertaken on a best-effort basis. Writing to read-only
    /// files will have no meaning. Writing to memory may or may not be
    /// possible depending on various factors. If important, it's recommended
    /// to verify the `vfs_write()` with a `vfs_read()`.
    /// 
    /// # Arguments
    /// * `filename` - Full VFS path of the file to write. Ex: /conf/config_printf_enable.txt
    /// * `data` - Byte data to write.
    /// * `offset` - File offset.
    /// 
    /// # Examples
    /// ```
    /// let vfs_write_data = vec![1u8; 1];
    /// vmm.vfs_write("/conf/config_process_show_terminated.txt", vfs_write_data, 0);
    /// ```
    pub fn vfs_write(&self, filename : &str, data : Vec<u8>, offset : u64) {
        return self.impl_vfs_write(filename, &data, offset);
    }

    /// Retrieve all registry hives.
    /// 
    /// # Examples
    /// ```
    /// let hive_all = vmm.reg_hive_list()?;
    /// for hive in hive_all {
    ///     println!("{hive} size={} path={}", hive.size, hive.path);
    /// }
    /// ```
    pub fn reg_hive_list(&self) -> ResultEx<Vec<VmmRegHive>> {
        return self.impl_reg_hive_list();
    }

    /// Retrieve a registry key by its path.
    /// 
    /// Registry keys may be addressed either by its full path or by hive address
    /// and hive path. Both addressing modes are shown in the examples below.
    /// Registry keys are case sensitive.
    /// 
    /// Check out the [`VmmRegKey`] struct for more detailed information.
    /// 
    /// # Examples
    /// ```
    /// // Retrieve a regkey by full path.
    /// let regkey = vmm.reg_key("HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run")?
    /// println!("{regkey");
    /// ```
    /// 
    /// ```
    /// // Retrieve a regkey by hive path.
    /// // (SOFTWARE hive example address: 0xffffba061a908000).
    /// let regkey = vmm.reg_key("0xffffba061a908000\\ROOT\\Microsoft\\Windows\\CurrentVersion\\Run")?
    /// println!("{regkey");
    /// ```
    pub fn reg_key(&self, path : &str) -> ResultEx<VmmRegKey> {
        return self.impl_reg_key(path);
    }

    /// Retrieve a registry value by its path.
    /// 
    /// Registry values may be addressed either by its full path or by hive
    /// address and hive path. Both addressing modes are shown in the examples
    /// below. Registry keys are case sensitive.
    /// 
    /// Check out the [`VmmRegValue`] struct for more detailed information.
    /// 
    /// # Examples
    /// ```
    /// // Retrieve a regvalue by full path.
    /// let regpath = "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\ProgramFilesDir";
    /// let regvalue = vmm.reg_key(regpath)?
    /// println!("{regkey");
    /// ```
    /// 
    /// ```
    /// // Retrieve a regvalue by hive path.
    /// // (SOFTWARE hive example address: 0xffffba061a908000).
    /// regpath = "0xffffba061a908000\\ROOT\\Microsoft\\Windows\\CurrentVersion\\ProgramFilesDir";
    /// let regvalue = vmm.reg_key(regpath)?
    /// println!("{regkey");
    /// ```
    pub fn reg_value(&self, path : &str) -> ResultEx<VmmRegValue> {
        return self.impl_reg_value(path);
    }

    /// Retrieve a search struct for physical memory.
    /// 
    /// NB! This does not start the actual search yet.
    /// 
    /// Check out the [`VmmSearch`] struct for more detailed information.
    /// 
    /// 
    /// # Arguments
    /// * `addr_min` - Start search at this physical address.
    /// * `addr_max` - End the search at this physical address. 0 is interpreted as u64::MAX.
    /// * `num_results_max` - Max number of search hits to search for. Max allowed value is 0x10000.
    /// * `flags` - Any combination of `FLAG_*`.
    /// 
    /// 
    /// # Examples
    /// ```
    /// // Retrieve a VmmSearch for the entire physical memory.
    /// let mut search = vmm.search(0, 0, 0x10000, 0)?
    /// ```
    /// 
    /// ```
    /// // Retrieve a VmmSearch for physical memory between 4GB and 8GB.
    /// // Also stop at first search hit.
    /// let mut search = vmm.search(0x100000000, 0x200000000, 1, 0)?
    /// ```
    pub fn search(&self, addr_min : u64, addr_max : u64, num_results_max : u32, flags : u64) -> ResultEx<VmmSearch> {
        return VmmSearch::impl_new(&self, u32::MAX, addr_min, addr_max, num_results_max, flags);
    }

    /// Retrieve a yara search struct for physical memory.
    /// 
    /// NB! This does not start the actual search yet. 
    /// 
    /// Check out the [`VmmYara`] struct for more detailed information.
    /// 
    /// 
    /// # Arguments
    /// * `rules` - Yara rules to search for.
    /// * `addr_min` - Start yara search at this physical address.
    /// * `addr_max` - End the yara search at this physical address. 0 is interpreted as u64::MAX.
    /// * `num_results_max` - Max number of search hits to search for. Max allowed value is 0x10000.
    /// * `flags` - Any combination of `FLAG_*`.
    /// 
    /// 
    /// # Examples
    /// ```
    /// // Retrieve a VmmYara for the entire physical memory.
    /// let yara_rule = " rule mz_header { strings: $mz = \"MZ\" condition: $mz at 0 } ";
    /// let yara_rules = vec![yara_rule];
    /// let mut yara = vmm.search_yara(yara_rules, 0, 0, 0x10000, 0)?
    /// ```
    /// 
    /// ```
    /// // Retrieve a VmmYara for physical memory between 4GB and 8GB.
    /// // Also stop at first yara search hit.
    /// let yara_rules = vec!["/tmp/my_yara_rule.yar", "/tmp/my_yara_rule2.yar"];
    /// let mut yara = vmm.search_yara(yara_rules, 0x100000000, 0x200000000, 1, 0)?
    /// ```
    pub fn search_yara(&self, rules : Vec<&str>, addr_min : u64, addr_max : u64, num_results_max : u32, flags : u64) -> ResultEx<VmmYara> {
        return VmmYara::impl_new(&self, rules, u32::MAX, addr_min, addr_max, num_results_max, flags);
    }
}

impl VmmMapPoolEntry {
    /// Retrieve the pool entry tag String.
    pub fn tag_to_string(&self) -> String {
        let tag_chars = [((self.tag >> 0) & 0xff) as u8, ((self.tag >> 8) & 0xff) as u8, ((self.tag >> 16) & 0xff) as u8, ((self.tag >> 24) & 0xff) as u8];
        return String::from_utf8_lossy(&tag_chars).to_string();
    }
}






/// Kernel information.
/// 
/// The kernel struct gives easy access to:
/// * The system process (pid 4).
/// * Kernel build number.
/// * Kernel debug symbols (nt).
/// 
/// 
/// # Created By
/// - [`vmm.kernel()`](Vmm::kernel())
/// 
/// # Examples
/// ```
/// println!("{}", vmm.kernel().process());
/// println!("{}", vmm.kernel().build());
/// let kernel = vmm.kernel();
/// let pdb = kernel.pdb();
/// println!("{pdb}");
/// ```
#[derive(Clone, Copy, Debug)]
pub struct VmmKernel<'a> {
    vmm : &'a Vmm<'a>,
}

impl VmmKernel<'_> {
    /// Get the kernel build numer.
    /// 
    /// # Examples
    /// ```
    /// // Retrieve and print the kernel build number.
    /// println!("{}", vmm.kernel().build());
    /// ```
    pub fn build(&self) -> u32 {
        return self.vmm.get_config(CONFIG_OPT_WIN_VERSION_BUILD).unwrap_or_default().try_into().unwrap_or_default();
    }

    /// Get the System process (pid 4).
    /// 
    /// # Examples
    /// ```
    /// // Retrieve and print the kernel build number.
    /// let systemprocess = vmm.kernel().process();
    /// ```
    pub fn process(&self) -> VmmProcess {
        return VmmProcess { vmm : self.vmm, pid : 4 };
    }

    /// Get kernel debug information (nt).
    /// 
    /// For additional information about debug symbols check out the [`VmmPdb`] struct.
    /// 
    /// # Examples
    /// ```
    /// // Retrieve and print the kernel build number.
    /// let pdb_nt = vmm.kernel().pdb();
    /// ```
    pub fn pdb(&self) -> VmmPdb {
        return VmmPdb { vmm : self.vmm, module : String::from("nt") };
    }
}






/// Debug Symbol API.
/// 
/// The PDB sub-system requires that MemProcFS supporting DLLs/.DYLIBs/.SOs for
/// debugging and symbol server are put alongside `vmm.dll`.
/// Also it's recommended that the file `info.db` is put alongside `vmm.dll`.
/// 
/// 
/// # Created By
/// - [`vmmprocess.pdb_from_module_address()`](VmmProcess::pdb_from_module_address())
/// - [`vmmprocess.pdb_from_module_name()`](VmmProcess::pdb_from_module_name())
/// - [`vmm.kernel().pdb()`](VmmKernel::pdb())
/// 
/// # Examples
/// ```
/// // Retrieve the PDB struct associated with the kernel (nt).
/// let kernel = vmm.kernel();
/// let pdb = kernel.pdb();
/// ```
/// 
/// ```
/// // Retrieve the PDB struct associated with a process module.
/// let pdb = vmmprocess.pdb_from_module_name("ntdll.dll")?;
/// ```
#[derive(Clone, Debug)]
pub struct VmmPdb<'a> {
    vmm : &'a Vmm<'a>,
    pub module : String,
}

impl VmmPdb<'_> {
    /// Retrieve a symbol name and a displacement given a module offset or virtual address.
    /// 
    /// # Arguments
    /// * `va_or_offset` - Virtual address or offset from module base.
    /// 
    /// # Examples
    /// ```
    /// if let Ok(r) = pdb.symbol_name_from_address(va_symbol) {
    ///     println!("va_o: {:x} name: '{}' displacement: {:x}", va_symbol, r.0, r.1);
    /// }
    /// ```
    pub fn symbol_name_from_address(&self, va_or_offset : u64) -> ResultEx<(String, u32)> {
        return self.impl_symbol_name_from_address(va_or_offset);
    }

    /// Lookup a symbol address given its name.
    /// 
    /// # Arguments
    /// * `symbol_name`
    /// 
    /// # Examples
    /// ```
    /// let va = pdb_nt.symbol_address_from_name("MiMapContiguousMemory")?;
    /// ```
    pub fn symbol_address_from_name(&self, symbol_name : &str) -> ResultEx<u64> {
        return self.impl_symbol_address_from_name(symbol_name);
    }

    /// Retrieve the size of a struct/type.
    /// 
    /// # Arguments
    /// * `type_name`
    /// 
    /// # Examples
    /// ```
    /// let size_eprocess = pdb_nt.type_size("_EPROCESS")?;
    /// ```
    pub fn type_size(&self, type_name : &str) -> ResultEx<u32> {
        return self.impl_type_size(type_name);
    }

    /// Retrieve offset of a struct child member.
    /// 
    /// # Arguments
    /// * `type_name`
    /// * `type_child_name`
    /// 
    /// # Examples
    /// ```
    /// let offet_vadroot = pdb_nt.type_child_offset("_EPROCESS", "VadRoot")?
    /// ```
    pub fn type_child_offset(&self, type_name : &str, type_child_name : &str) -> ResultEx<u32> {
        return self.impl_type_child_offset(type_name, type_child_name);
    }
}






/// Efficient Memory Reading API.
/// 
/// The Scatter Memory API allows reading several scattered memory regions at
/// the same time in one pass - greatly improving efficiency over multiple
/// normal memory reads.
/// 
/// The Rust Scatter API may be used in two different ways, both are displayed
/// below in the examples section.
/// 
/// 
/// # Created By
/// - [`vmm.mem_scatter()`](Vmm::mem_scatter())
/// - [`vmmprocess.mem_scatter()`](VmmProcess::mem_scatter())
/// 
/// # Example #1
/// ```
/// // Example: vmmprocess.mem_scatter() #1:
/// // This example will show how it's possible to use VmmScatterMemory to
/// // more efficiently read memory from the underlying device.
/// {
///     // Example: vmmprocess.mem_scatter():
///     // Retrieve a scatter memory read object that may be used to batch
///     // several reads/writes into one efficient call to the memory device.
///     println!("========================================");
///     println!("vmmprocess.mem_scatter() #1:");
///     let mem_scatter = vmmprocess.mem_scatter(FLAG_NOCACHE | FLAG_ZEROPAD_ON_FAIL)?;
///     println!("mem_scatter = {mem_scatter}");
///     // Prepare three memory ranges to read.
///     let _r = mem_scatter.prepare(kernel32.va_base + 0x0000, 0x100);
///     let _r = mem_scatter.prepare(kernel32.va_base + 0x1000, 0x100);
///     let _r = mem_scatter.prepare(kernel32.va_base + 0x2000, 0x100);
///     // Perform the actual read (and writes) by calling the execute() function.
///     let _r = mem_scatter.execute();
///     // Fetch data read. It's possible (but wasteful) to read less data than was prepared.
///     if let Ok(data_read) = mem_scatter.read(kernel32.va_base + 0x0000, 0x80) {
///         println!("memory range: va={:x} cb={:x} cb_read={:x}", kernel32.va_base + 0x0000, 0x80, data_read.len());
///         println!("{:?}", data_read.hex_dump());
///         println!("-----------------------");
///     }
///     if let Ok(data_read) = mem_scatter.read(kernel32.va_base + 0x1000, 0x100) {
///         println!("memory range: va={:x} cb={:x} cb_read={:x}", kernel32.va_base + 0x1000, 0x100, data_read.len());
///         println!("{:?}", data_read.hex_dump());
///         println!("-----------------------");
///     }
///     // It's possible to do a re-read of the ranges by calling execute again!
///     let _r = mem_scatter.execute();
///     if let Ok(data_read) = mem_scatter.read(kernel32.va_base + 0x0000, 0x80) {
///         println!("memory range: va={:x} cb={:x} cb_read={:x}", kernel32.va_base + 0x0000, 0x80, data_read.len());
///         println!("{:?}", data_read.hex_dump());
///         println!("-----------------------");
///     }
///     // It's also possible to clear the VmmScatterMemory to start anew.
///     // Clearing is slightly more efficient than creating a new object.
///     // let _r = mem_scatter.clear();
/// 
///     // NB! the VmmScatterMemory struct will be automatically free'd
///     //     on the native backend when it goes out of scope.
/// }
/// ```
/// 
/// # Example #2
/// ```
/// // Example: vmmprocess.mem_scatter() #2:
/// // This example demo how it's possible to use the prepare_ex function
/// // which will populate the prepared data regions automatically when the
/// // VmmScatterMemory is dropped.
/// // It's not recommended to mix the #1 and #2 syntaxes.
/// {
///     // memory ranges to read are tuples:
///     // .0 = the virtual address to read.
///     // .1 = vector of u8 which memory should be read into.
///     // .2 = u32 receiving the bytes successfully read data.
///     let mut memory_range_1 = (kernel32.va_base + 0x0000, vec![0u8; 0x100], 0u32);
///     let mut memory_range_2 = (kernel32.va_base + 0x1000, vec![0u8; 0x100], 0u32);
///     let mut memory_range_3 = (kernel32.va_base + 0x2000, vec![0u8; 0x100], 0u32);
///     // Feed the ranges into a mutable VmmScatterMemory inside a
///     // separate scope. The actual memory read will take place when
///     // the VmmScatterMemory goes out of scope and are dropped.
///     println!("========================================");
///     println!("vmmprocess.mem_scatter() #2:");
///     if let Ok(mut mem_scatter) = vmmprocess.mem_scatter(FLAG_NOCACHE | FLAG_ZEROPAD_ON_FAIL) {
///         let _r = mem_scatter.prepare_ex(&mut memory_range_1);
///         let _r = mem_scatter.prepare_ex(&mut memory_range_2);
///         let _r = mem_scatter.prepare_ex(&mut memory_range_3);
///     }
///     // Results should now be available in the memory ranges if the read
///     // was successful. Note that there is no guarantee that memory is
///     // read - make sure to check the .2 item - number of bytes read.
///     for memory_range in [memory_range_1, memory_range_2, memory_range_3] {
///         println!("memory range: va={:x} cb={:x} cb_read={:x}", memory_range.0, memory_range.1.len(), memory_range.2);
///         println!("{:?}", memory_range.1.hex_dump());
///         println!("-----------------------");
///     }
/// }
/// ```
#[derive(Debug)]
pub struct VmmScatterMemory<'a> {
    vmm : &'a Vmm<'a>,
    hs : usize,
    pid : u32,
    flags : u32,
    is_scatter_ex : bool,
}

impl <'a> VmmScatterMemory<'a> {
    /// Prepare a memory range for reading according to method #2.
    /// 
    /// Once the `mem_scatter.execute()` call has been made the memory
    /// read should (if successful) be found in the prepared tuple.
    /// 
    /// See the [`VmmScatterMemory`] struct for an example.
    /// 
    /// # Arguments
    /// * `data_to_read` - Tuple with data to prepare as below:
    ///   * `data_to_read.0` - Address to start read from.
    ///   * `data_to_read.1` - Byte Vec with space to fill with read data on success.
    ///   * `data_to_read.2` - Bytes actually read on `mem_scatter.execute()` call. Should be zero at call to `mem_scatter.prepare_ex()`.
    pub fn prepare_ex(&mut self, data_to_read : &'a mut (u64, Vec<u8>, u32)) -> ResultEx<()> {
        return self.impl_prepare_ex(data_to_read);
    }

    /// Prepare a memory range for reading according to method #2.
    /// 
    /// Once the `mem_scatter.execute()` call has been made the memory
    /// read should (if successful) be found in the prepared tuple.
    /// 
    /// See the [`VmmScatterMemory`] struct for an example.
    /// 
    /// # Arguments
    /// * `data_to_read` - Tuple with data to prepare as below:
    ///   * `data_to_read.0` - Address to start read from.
    ///   * `data_to_read.1` - Generic Type/Struct to fill with read data on success.
    ///   * `data_to_read.2` - Bytes actually read on `mem_scatter.execute()` call. Should be zero at call to `mem_scatter.prepare_ex()`.
    pub fn prepare_ex_as<T>(&mut self, data_to_read : &'a mut (u64, T, u32)) -> ResultEx<()> {
        return self.impl_prepare_ex_as(data_to_read);
    }
}

impl VmmScatterMemory<'_> {
    /// Prepare a memory range for reading according to method #1.
    /// 
    /// Once the `mem_scatter.execute()` call has been made it's possible
    /// to read the memory by calling `mem_scatter.read()`.
    /// 
    /// See the [`VmmScatterMemory`] struct for an example.
    /// 
    /// # Arguments
    /// * `va` - Address to prepare to read from.
    /// * `size` - Number of bytes to read.
    pub fn prepare(&self, va : u64, size : usize) -> ResultEx<()> {
        return self.impl_prepare(va, size);
    }

    /// Prepare a memory range for reading according to method #1.
    /// 
    /// Once the `mem_scatter.execute()` call has been made it's possible
    /// to read the memory by calling `mem_scatter.read()`.
    /// 
    /// See the [`VmmScatterMemory`] struct for an example.
    /// 
    /// # Arguments
    /// * `va` - Address to prepare to read from.
    pub fn prepare_as<T>(&self, va : u64) -> ResultEx<()> {
        return self.impl_prepare(va, std::mem::size_of::<T>());
    }

    /// Prepare a memory range for writing.
    /// 
    /// Writing takes place on the call to `mem_scatter.execute()`.
    /// 
    /// # Arguments
    /// * `va` - Address to prepare to write to.
    /// * `data` - Data to write.
    pub fn prepare_write(&self, va : u64, data : &[u8]) -> ResultEx<()> {
        return self.impl_prepare_write(va, data);
    }

    /// Prepare a memory range for writing.
    /// 
    /// Writing takes place on the call to `mem_scatter.execute()`.
    /// 
    /// # Arguments
    /// * `va` - Address to prepare to write to.
    /// * `data` - Data to write. In case of a struct repr(C) is recommended.
    pub fn prepare_write_as<T>(&self, va : u64, data : &T) -> ResultEx<()> {
        return self.impl_prepare_write_as(va, data);
    }

    /// Execute the scatter call to the underlying memory device.
    /// 
    /// This function takes care of all reading and writing. After
    /// this function is called it's possible to read memory, or if
    /// approach #2 is used the memory should already be read into
    /// buffers prepared with the call to `mem_scatter.prepare_ex()`.
    pub fn execute(&self) -> ResultEx<()> {
        return self.impl_execute();
    }

    /// Read memory prepared after the `execute()` call.
    pub fn read(&self, va : u64, size : usize) -> ResultEx<Vec<u8>> {
        return self.impl_read(va, size);
    }

    /// Read memory prepared after the `execute()` call.
    pub fn read_as<T>(&self, va : u64) -> ResultEx<T> {
        return self.impl_read_as(va);
    }

    /// Read memory prepared after the `execute()` call.
    pub fn read_into(&self, va : u64, data : &mut [u8]) -> ResultEx<usize> {
        return self.impl_read_into(va, data);
    }

    /// Clear the scatter memory for additional read/writes.
    pub fn clear(&self) -> ResultEx<()> {
        return self.impl_clear();
    }
}






/// <b>Process API Base Struct.</b>
/// 
/// The [`VmmProcess`] struct is the base of the per-process related
/// functionality of the MemProcFS API. The [`VmmProcess`] struct should
/// be considered a child to the main [`Vmm`] struct.
/// 
/// <b>Check out the example project for more detailed API usage and
/// additional examples!</b>
/// 
/// 
/// # Created By
/// - [`vmm.process_from_pid()`](Vmm::process_from_pid())
/// - [`vmm.process_from_name()`](Vmm::process_from_name())
/// - [`vmm.process_list()`](Vmm::process_list())
/// - [`vmm.kernel().process()`](VmmKernel::process())
/// - `plugin sub-system`
/// 
/// 
/// # Examples
/// 
/// ```
/// // Retrieve all processes:
/// if let Ok(process_all) = vmm.process_list() {
///     for process in &*process_all {
///         print!("{process} ");
///     }
/// }
/// ```
/// 
/// ```
/// // Retrieve a process by its name. If more than one process share the
/// // same name the first found will be returned.
/// let systemprocess = vmm.process_from_name("System")?;
/// println!("{systemprocess}");
/// ```
/// 
/// ```
/// // Retrieve a process by its PID.
/// let systemprocess = vmm.process_from_pid(4)?;
/// println!("{systemprocess}");
/// ```
/// 
/// ```
/// // Process kernel memory and session space:
/// // Mask the process PID with 0x80000000 to retrieve kernel memory.
/// // This may be useful for retrieving kernel session data related to win32k.
/// let mut winlogon = vmm.process_from_name("winlogon.exe")?;
/// winlogon.pid = winlogon.pid | 0x80000000;
/// let va = winlogon.get_proc_address("win32kbase.sys", "gSessionId")?;
/// let sessionid : u32 = winlogon.mem_read_as(va, 0)?;
/// println!("win32kbase.sys!gSessionId -> {:x} : {}", va, sessionid);
/// ```
#[derive(Clone, Copy, Debug)]
pub struct VmmProcess<'a> {
    pub vmm : &'a Vmm<'a>,
    pub pid : u32,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum VmmIntegrityLevelType {
    Unknown,
    Untrusted,
    Low,
    Medium,
    MediumPlus,
    High,
    System,
    Protected,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum VmmMemoryModelType {
    NA,
    X86,
    X86PAE,
    X64,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum VmmSystemType {
    UnknownPhysical,
    UnknownX64,
    WindowsX64,
    UnknownX86,
    WindowsX86,
}

/// Process Information.
/// 
/// # Created By
/// - [`vmmprocess.info()`](VmmProcess::info())
/// 
/// # Examples
/// ```
/// // Retrieve the VmmProcess info struct from a process.
/// // It's better to retrieve this struct once and query its fields rather
/// // than calling `vmmprocess.info()` repetedly since there is a small
/// // native overhead doing so.
/// if let Ok(procinfo) = vmmprocess.info() {
///     println!("struct   -> {procinfo}");
///     println!("pid      -> {}", procinfo.pid);
///     println!("ppid     -> {}", procinfo.pid);
///     println!("peb      -> {:x}", procinfo.va_peb);
///     println!("eprocess -> {:x}", procinfo.va_eprocess);
///     println!("name     -> {}", procinfo.name);
///     println!("longname -> {}", procinfo.name_long);
///     println!("SID      -> {}", procinfo.sid);
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VmmProcessInfo {
    pub pid : u32,
    pub ppid : u32,
    pub name : String,
    pub name_long : String,
    pub tp_system : VmmSystemType,
    pub tp_memorymodel : VmmMemoryModelType,
    pub is_user_mode : bool,
    pub state : u32,
    pub pa_dtb : u64,
    pub pa_dtb_user : u64,
    pub va_eprocess : u64,
    pub va_peb : u64,
    pub is_wow64 : bool,
    pub va_peb32 : u32,
    pub session_id : u32,
    pub luid : u64,
    pub sid : String,
    pub integrity_level : VmmIntegrityLevelType,
}

/// Info: Process Module: PE data directories.
/// 
/// # Created By
/// - [`vmmprocess.map_module_data_directory()`](VmmProcess::map_module_data_directory())
/// 
/// # Examples
/// ```
/// if let Ok(data_directory_all) = vmmprocess.map_module_data_directory("kernel32.dll") {
///     println!("Number of module data directories: {}.", data_directory_all.len());
///     for data_directory in &*data_directory_all {
///         println!("{data_directory}");
///     }
/// }
/// ```
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct VmmProcessMapDirectoryEntry {
    pub pid : u32,
    pub name : &'static str,
    pub virtual_address : u32,
    pub size : u32,
}

/// Info: Process Module: PE exported entries.
/// 
/// # Created By
/// - [`vmmprocess.map_module_eat()`](VmmProcess::map_module_eat()
/// 
/// # Examples
/// ```
/// if let Ok(eat_all) = vmmprocess.map_module_eat("kernel32.dll") {
///     println!("Number of module exported functions: {}.", eat_all.len());
///     for eat in &*eat_all {
///         println!("{eat} :: {}", eat.forwarded_function);
///     }
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VmmProcessMapEatEntry {
    pub pid : u32,
    pub va_function : u64,
    pub ordinal : u32,
    pub function : String,
    pub forwarded_function : String,
}

/// Info: Process: Handles.
/// 
/// # Created By
/// - [`vmmprocess.map_handle()`](VmmProcess::map_handle())
/// 
/// # Examples
/// ```
/// if let Ok(handle_all) = vmmprocess.map_handle() {
///     println!("Number of handle entries: {}.", handle_all.len());
///     for handle in &*handle_all {
///         println!("{handle}");
///     }
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VmmProcessMapHandleEntry {
    pub pid : u32,
    pub va_object : u64,
    pub handle_id : u32,
    pub granted_access : u32,
    pub type_index : u32,
    pub handle_count : u64,
    pub pointer_count : u64,
    pub va_object_create_info : u64,
    pub va_security_descriptor : u64,
    pub handle_pid : u32,
    pub pool_tag : u32,
    pub info : String,
    pub tp : String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum VmmProcessMapHeapType {
    NA,
    NtHeap,
    SegmentHeap,
}

/// Info: Process: Heaps.
/// 
/// # Created By
/// - [`vmmprocess.map_heap()`](VmmProcess::map_heap())
/// 
/// # Examples
/// ```
/// if let Ok(heap_all) = vmmprocess.map_heap() {
///     println!("Number of heap entries: {}.", heap_all.len());
///     for heap in &*heap_all {
///         println!("{heap}");
///     }
/// }
/// ```
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct VmmProcessMapHeapEntry {
    pub pid : u32,
    pub tp : VmmProcessMapHeapType,
    pub is_32 : bool,
    pub index : u32,
    pub number : u32,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum VmmProcessMapHeapAllocType {
    NA,
    NtHeap,
    NtLFH,
    NtLarge,
    NtNA,
    SegVS,
    SegLFH,
    SegLarge,
    SegNA,
}

/// Info: Process: Heap allocations.
/// 
/// # Created By
/// - [`vmmprocess.map_heapalloc()`](VmmProcess::map_heapalloc())
/// 
/// # Examples
/// ```
/// if let Ok(heapalloc_all) = vmmprocess.map_heapalloc(0) {
///     println!("Number of allocated heap entries: {}.", heapalloc_all.len());
///     for heapalloc in &*heapalloc_all {
///         print!("{heapalloc} ");
///     }
///     println!("");
/// }
/// ```
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct VmmProcessMapHeapAllocEntry {
    pub pid : u32,
    pub va : u64,
    pub size : u32,
    pub tp : VmmProcessMapHeapAllocType,
}

/// Info: Process Module: PE imported entries.
/// 
/// # Created By
/// - [`vmmprocess.map_module_iat()`](VmmProcess::map_module_iat())
/// 
/// # Examples
/// ```
/// if let Ok(iat_all) = vmmprocess.map_module_iat("kernel32.dll") {
///     println!("Number of module imported functions: {}.", iat_all.len());
///     for iat in &*iat_all {
///         println!("{iat}");
///     }
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VmmProcessMapIatEntry {
    pub pid : u32,
    pub va_function : u64,
    pub function : String,
    pub module : String,
}

/// Info: Process: Modules (loaded DLLs) debug information.
/// 
/// # Created By
/// - [`vmmprocess.map_module()`](VmmProcess::map_module())
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VmmProcessMapModuleDebugEntry {
    pub pid : u32,
    pub age : u32,
    pub raw_guid : [u8; 16],
    pub guid : String,
    pub pdb_filename : String,
}

/// Info: Process: Modules (loaded DLLs) version information.
/// 
/// # Created By
/// - [`vmmprocess.map_module()`](VmmProcess::map_module())
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VmmProcessMapModuleVersionEntry {
    pub pid : u32,
    pub company_name : String,
    pub file_description : String,
    pub file_version : String,
    pub internal_name : String,
    pub legal_copyright : String,
    pub original_file_name : String,
    pub product_name : String,
    pub product_version : String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum VmmProcessMapModuleType {
    Normal,
    Data,
    NotLinked,
    Injected,
}

/// Info: Process: Modules (loaded DLLs).
/// 
/// # Created By
/// - [`vmmprocess.map_module()`](VmmProcess::map_module())
/// 
/// # Examples
/// ```
/// if let Ok(module_all) = vmmprocess.map_module(true, true) {
///     println!("Number of process modules: {}.", module_all.len());
///     for module in &*module_all {
///         println!("{module}");
///     }
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VmmProcessMapModuleEntry {
    pub pid : u32,
    pub va_base : u64,
    pub va_entry : u64,
    pub image_size : u32,
    pub is_wow64 : bool,
    pub tp : VmmProcessMapModuleType,
    pub name : String,
    pub full_name : String,
    pub file_size_raw : u32,
    pub section_count : u32,
    pub eat_count : u32,
    pub iat_count : u32,
    pub debug_info : Option<VmmProcessMapModuleDebugEntry>,
    pub version_info : Option<VmmProcessMapModuleVersionEntry>,
}

/// Info: Process: PTE memory map entries.
/// 
/// # Created By
/// - [`vmmprocess.map_pte()`](VmmProcess::map_pte())
/// 
/// # Examples
/// ```
/// if let Ok(pte_all) = vmmprocess.map_pte(true) {
///     println!("Number of pte entries: {}.", pte_all.len());
///     for pte in &*pte_all {
///         let s = if pte.is_s { 's' } else { '-' };
///         let r = if pte.is_r { 'r' } else { '-' };
///         let w = if pte.is_w { 'w' } else { '-' };
///         let x = if pte.is_x { 'x' } else { '-' };
///         println!("{pte} :: {s}{r}{w}{x} :: {}", pte.info);
///     }
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VmmProcessMapPteEntry {
    pub pid : u32,
    pub va_base : u64,
    pub page_count : u64,
    pub page_software_count : u32,
    pub is_wow64 : bool,
    pub info : String,
    pub is_r : bool,
    pub is_w : bool,
    pub is_x : bool,
    pub is_s : bool,
}

/// Info: Process Module: PE sections.
/// 
/// # Created By
/// - [`vmmprocess.map_module_section()`](VmmProcess::map_module_section())
/// 
/// # Examples
/// ```
/// if let Ok(section_all) = vmmprocess.map_module_section("kernel32.dll") {
///     println!("Number of module sections: {}.", section_all.len());
///     for section in &*section_all {
///         println!("{section}");
///     }
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VmmProcessSectionEntry {
    pub pid : u32,
    pub index : u32,
    pub name : String,
    pub name_raw : [u8; 8],
    pub misc_virtual_size : u32,
    pub virtual_address : u32,
    pub size_of_raw_data : u32,
    pub pointer_to_raw_data : u32,
    pub pointer_to_relocations : u32,
    pub pointer_to_linenumbers : u32,
    pub number_of_relocations : u16,
    pub number_of_linenumbers : u16,
    pub characteristics : u32,
}

/// Info: Process: Threads.
/// 
/// # Created By
/// - [`vmmprocess.map_thread()`](VmmProcess::map_thread())
/// 
/// # Examples
/// ```
/// if let Ok(thread_all) = vmmprocess.map_thread() {
///     println!("Number of process threads: {}.", thread_all.len());
///     for thread in &*thread_all {
///         println!("{thread}");
///     }
/// }
/// ```
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct VmmProcessMapThreadEntry {
    pub pid : u32,
    pub thread_id : u32,
    pub thread_pid : u32,
    pub exit_status : u32,
    pub state : u8,
    pub running : u8,
    pub priority : u8,
    pub priority_base : u8,
    pub va_ethread : u64,
    pub va_teb : u64,
    pub ft_create_time : u64,
    pub ft_exit_time : u64,
    pub va_start_address : u64,
    pub va_win32_start_address : u64,
    pub va_stack_user_base : u64,
    pub va_stack_user_limit : u64,
    pub va_stack_kernel_base : u64,
    pub va_stack_kernel_limit : u64,
    pub va_trap_frame : u64,
    pub va_impersonation_token : u64,
    pub va_rip : u64,
    pub va_rsp : u64,
    pub affinity : u64,
    pub user_time : u32,
    pub kernel_time : u32,
    pub suspend_count : u8,
    pub wait_reason : u8
}

/// Info: Process: Thread Callstack.
/// 
/// # Created By
/// - [`vmmprocess.map_thread_callstack()`](VmmProcess::map_thread_callstack())
/// - [`vmmprocess.map_thread_callstack_ex()`](VmmProcess::map_thread_callstack_ex())
/// 
/// # Examples
/// ```
/// // in this example the TID (thread id) is 9600.
/// if let Ok(thread_callstack) = vmmprocess.map_thread_callstack(9600) {
///     for cs_entry in &*thread_callstack {
///         println!("{cs_entry}");
///     }
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VmmProcessMapThreadCallstackEntry {
    pub pid : u32,
    pub tid : u32,
    pub i : u32,
    pub is_reg_present : bool,
    pub va_ret_addr : u64,
    pub va_rsp : u64,
    pub va_base_sp : u64,
    pub displacement : i32,
    pub module : String,
    pub function : String,
}

/// Info: Process: Unloaded modules.
/// 
/// # Created By
/// - [`vmmprocess.map_unloaded_module()`](VmmProcess::map_unloaded_module())
/// 
/// # Examples
/// ```
/// if let Ok(unloaded_all) = vmmprocess.map_unloaded_module() {
///     println!("Number of process unloaded modules: {}.", unloaded_all.len());
///     for unloaded in &*unloaded_all {
///         println!("{unloaded}");
///     }
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VmmProcessMapUnloadedModuleEntry {
    pub pid : u32,
    pub va_base : u64,
    pub image_size : u32,
    pub is_wow64 : bool,
    pub name : String,
    pub checksum : u32,         // user-mode only
    pub timedatestamp : u32,    // user-mode only
    pub ft_unload : u64,        // kernel-mode only
}

/// Info: Process: VAD (Virtual Address Descriptor) memory map entries.
/// 
/// # Created By
/// - [`vmmprocess.map_vad()`](VmmProcess::map_vad())
/// 
/// # Examples
/// ```
/// if let Ok(vad_all) = vmmprocess.map_vad(true) {
///     println!("Number of vad entries: {}.", vad_all.len());
///     for vad in &*vad_all {
///         println!("{vad} :: {}", vad.info);
///     }
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VmmProcessMapVadEntry {
    pub pid : u32,
    pub va_start : u64,
    pub va_end : u64,
    pub va_vad : u64,
    pub u0 : u32,
    pub u1 : u32,
    pub u2 : u32,
    pub commit_charge : u32,
    pub is_mem_commit : bool,
    pub cb_prototype_pte : u32,
    pub va_prototype_pte : u64,
    pub va_subsection : u64,
    pub va_file_object : u64,
    pub info : String,
    pub vadex_page_base : u32,
    pub vadex_page_count : u32,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum VmmProcessMapVadExType {
    NA,
    Hardware,
    Transition,
    Prototype,
    DemandZero,
    Compressed,
    Pagefile,
    File,
}

/// Info: Process: Extended VAD memory map entries.
/// 
/// # Created By
/// - [`vmmprocess.map_vadex()`](VmmProcess::map_vadex())
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VmmProcessMapVadExEntry {
    pub pid : u32,
    pub tp : VmmProcessMapVadExType,
    pub i_pml : u8,
    pub va : u64,
    pub pa : u64,
    pub pte : u64,
    pub pte_flags : u8,
    pub proto_tp : VmmProcessMapVadExType,
    pub proto_pa : u64,
    pub proto_pte : u64,
    pub va_vad_base : u64,
}

impl VmmProcess<'_> {
    /// Get the base virtual address for a loaded module.
    /// 
    /// # Arguments
    /// * `module_name`
    /// 
    /// # Examples
    /// ```
    /// if let Ok(module_base_kernel32) = vmmprocess.get_module_base("kernel32.dll") {
    ///     println!("kernel32.dll -> {:x}", module_base_kernel32);
    /// }
    /// ```
    pub fn get_module_base(&self, module_name : &str) -> ResultEx<u64> {
        return self.impl_get_module_base(module_name);
    }

    /// Get the address of an exported function or symbol.
    /// 
    /// This is similar to the Windows function GetProcAddress.
    /// 
    /// # Arguments
    /// * `module_name`
    /// * `function_name`
    /// 
    /// # Examples
    /// ```
    /// if let Ok(procaddress) = vmmprocess.get_proc_address("kernel32.dll", "GetProcAddress") {
    ///     println!("kernel32.dll!GetProcAddress -> {:x}", procaddress);
    /// }
    /// ```
    pub fn get_proc_address(&self, module_name : &str, function_name : &str) -> ResultEx<u64> {
        return self.impl_get_proc_address(module_name, function_name);
    }

    /// Get the process path (retrieved fom kernel mode).
    /// 
    /// # Examples
    /// ```
    /// if let Ok(path) = vmmprocess.get_path_kernel() {
    ///     println!("-> {path}");
    /// }
    /// ```
    pub fn get_path_kernel(&self) -> ResultEx<String> {
        return self.impl_get_information_string(VMMDLL_PROCESS_INFORMATION_OPT_STRING_PATH_KERNEL);
    }

    /// Get the process path (retrieved from user-mode).
    /// 
    /// # Examples
    /// ```
    /// if let Ok(path) = vmmprocess.get_path_user() {
    ///     println!("-> {path}");
    /// }
    /// ```
    pub fn get_path_user(&self) -> ResultEx<String> {
        return self.impl_get_information_string(VMMDLL_PROCESS_INFORMATION_OPT_STRING_PATH_USER_IMAGE);
    }

    /// Get the process command line.
    /// 
    /// # Examples
    /// ```
    /// if let Ok(s_cmdline) = vmmprocess.get_cmdline() {
    ///     println!("-> {s_cmdline}");
    /// }
    /// ```
    pub fn get_cmdline(&self) -> ResultEx<String> {
        return self.impl_get_information_string(VMMDLL_PROCESS_INFORMATION_OPT_STRING_CMDLINE);
    }

    /// Get process information - such as name, ppid, state, etc.
    /// 
    /// If retrieving multiple values from the [`VmmProcessInfo`] struct it's
    /// recommended to retrieve the info object once instead of repetedly
    /// calling the info() method.
    /// 
    /// # Examples
    /// ```
    /// if let Ok(procinfo) = vmmprocess.info() {
    ///     println!("struct   -> {procinfo}");
    ///     println!("pid      -> {}", procinfo.pid);
    ///     println!("ppid     -> {}", procinfo.pid);
    ///     println!("peb      -> {:x}", procinfo.va_peb);
    ///     println!("eprocess -> {:x}", procinfo.va_eprocess);
    ///     println!("name     -> {}", procinfo.name);
    ///     println!("longname -> {}", procinfo.name_long);
    ///     println!("SID      -> {}", procinfo.sid);
    /// }
    /// ```
    pub fn info(&self) -> ResultEx<VmmProcessInfo> {
        return self.impl_info();
    }

    /// Retrieve the handles info map.
    /// 
    /// For additional information see the [`VmmProcessMapHandleEntry`] struct.
    /// 
    /// # Examples
    /// ```
    /// if let Ok(handle_all) = vmmprocess.map_handle() {
    ///     println!("Number of handle entries: {}.", handle_all.len());
    ///     for handle in &*handle_all {
    ///         println!("{handle}");
    ///     }
    /// }
    /// ```
    pub fn map_handle(&self) -> ResultEx<Vec<VmmProcessMapHandleEntry>> {
        return self.impl_map_handle();
    }

    /// Retrieve the heaps info map.
    /// 
    /// For additional information see the [`VmmProcessMapHeapEntry`] struct.
    /// 
    /// # Examples
    /// ```
    /// if let Ok(heap_all) = vmmprocess.map_heap() {
    ///     println!("Number of heap entries: {}.", heap_all.len());
    ///     for heap in &*heap_all {
    ///         println!("{heap}");
    ///     }
    /// }
    /// ```
    pub fn map_heap(&self) -> ResultEx<Vec<VmmProcessMapHeapEntry>> {
        return self.impl_map_heap();
    }

    /// Retrieve the heap allocations info map.
    /// 
    /// For additional information see the [`VmmProcessMapHeapAllocEntry`] struct.
    /// 
    /// # Arguments
    /// * `heap_number_or_address` - Heap number as given by [`VmmProcessMapHeapEntry`] or the heap base address.
    /// 
    /// # Examples
    /// ```
    /// if let Ok(heapalloc_all) = vmmprocess.map_heapalloc(0) {
    ///     println!("Number of allocated heap entries: {}.", heapalloc_all.len());
    ///     for heapalloc in &*heapalloc_all {
    ///         print!("{heapalloc} ");
    ///     }
    ///     println!("");
    /// }
    /// ```
    pub fn map_heapalloc(&self, heap_number_or_address : u64) -> ResultEx<Vec<VmmProcessMapHeapAllocEntry>> {
        return self.impl_map_heapalloc(heap_number_or_address);
    }

    /// Retrieve the loaded modules map.
    /// 
    /// For additional information see the [`VmmProcessMapModuleEntry`] struct.
    /// 
    /// # Arguments
    /// * `is_info_debug` - Also retrieve debug information.
    /// * `is_info_version` - Also version information.
    /// 
    /// # Examples
    /// ```
    /// if let Ok(module_all) = vmmprocess.map_module(true, true) {
    ///     println!("Number of process modules: {}.", module_all.len());
    ///     for module in &*module_all {
    ///         println!("{module}");
    ///     }
    /// }
    /// ```
    pub fn map_module(&self, is_info_debug : bool, is_info_version : bool) -> ResultEx<Vec<VmmProcessMapModuleEntry>> {
        return self.impl_map_module(is_info_debug, is_info_version);
    }

    /// Retrieve PE data directories associated with a module.
    /// 
    /// For additional information see the [`VmmProcessMapDirectoryEntry`] struct.
    /// 
    /// # Arguments
    /// * `module_name`
    /// 
    /// # Examples
    /// ```
    /// if let Ok(data_directory_all) = vmmprocess.map_module_data_directory("kernel32.dll") {
    ///     println!("Number of module data directories: {}.", data_directory_all.len());
    ///     for data_directory in &*data_directory_all {
    ///         println!("{data_directory}");
    ///     }
    /// }
    /// ```
    pub fn map_module_data_directory(&self, module_name : &str) -> ResultEx<Vec<VmmProcessMapDirectoryEntry>> {
        return self.impl_map_module_data_directory(module_name);
    }

    /// Retrieve exported functions and symbols associated with a module.
    /// 
    /// For additional information see the [`VmmProcessMapEatEntry`] struct.
    /// 
    /// # Arguments
    /// * `module_name`
    /// 
    /// # Examples
    /// ```
    /// if let Ok(eat_all) = vmmprocess.map_module_eat("kernel32.dll") {
    ///     println!("Number of module exported functions: {}.", eat_all.len());
    ///     for eat in &*eat_all {
    ///         println!("{eat} :: {}", eat.forwarded_function);
    ///     }
    /// }
    /// ```
    pub fn map_module_eat(&self, module_name : &str) -> ResultEx<Vec<VmmProcessMapEatEntry>> {
        return self.impl_map_module_eat(module_name);
    }

    /// Retrieve imported functions associated with a module.
    /// 
    /// For additional information see the [`VmmProcessMapIatEntry`] struct.
    /// 
    /// # Arguments
    /// * `module_name`
    /// 
    /// # Examples
    /// ```
    /// if let Ok(iat_all) = vmmprocess.map_module_iat("kernel32.dll") {
    ///     println!("Number of module imported functions: {}.", iat_all.len());
    ///     for iat in &*iat_all {
    ///         println!("{iat}");
    ///     }
    /// }
    /// ```
    pub fn map_module_iat(&self, module_name : &str) -> ResultEx<Vec<VmmProcessMapIatEntry>> {
        return self.impl_map_module_iat(module_name);
    }

    /// Retrieve PE sections associated with a module.
    /// 
    /// For additional information see the [`VmmProcessSectionEntry`] struct.
    /// 
    /// # Arguments
    /// * `module_name`
    /// 
    /// # Examples
    /// ```
    /// if let Ok(section_all) = vmmprocess.map_module_section("kernel32.dll") {
    ///     println!("Number of module sections: {}.", section_all.len());
    ///     for section in &*section_all {
    ///         println!("{section}");
    ///     }
    /// }
    /// ```
    pub fn map_module_section(&self, module_name : &str) -> ResultEx<Vec<VmmProcessSectionEntry>> {
        return self.impl_map_module_section(module_name);
    }

    /// Retrieve the PTE memory info map.
    /// 
    /// For additional information see the [`VmmProcessMapPteEntry`] struct.
    /// 
    /// # Examples
    /// ```
    /// if let Ok(pte_all) = vmmprocess.map_pte(true) {
    ///     println!("Number of pte entries: {}.", pte_all.len());
    ///     for pte in &*pte_all {
    ///         let s = if pte.is_s { 's' } else { '-' };
    ///         let r = if pte.is_r { 'r' } else { '-' };
    ///         let w = if pte.is_w { 'w' } else { '-' };
    ///         let x = if pte.is_x { 'x' } else { '-' };
    ///         println!("{pte} :: {s}{r}{w}{x} :: {}", pte.info);
    ///     }
    /// }
    /// ```
    pub fn map_pte(&self, is_identify_modules : bool) -> ResultEx<Vec<VmmProcessMapPteEntry>> {
        return self.impl_map_pte(is_identify_modules);
    }

    /// Retrieve the thread info map.
    /// 
    /// For additional information see the [`VmmProcessMapThreadEntry`] struct.
    /// 
    /// # Examples
    /// ```
    /// if let Ok(thread_all) = vmmprocess.map_thread() {
    ///     println!("Number of process threads: {}.", thread_all.len());
    ///     for thread in &*thread_all {
    ///         println!("{thread}");
    ///     }
    /// }
    /// ```
    pub fn map_thread(&self) -> ResultEx<Vec<VmmProcessMapThreadEntry>> {
        return self.impl_map_thread();
    }

    /// Info: Process: Thread Callstack.
    /// 
    /// For additional information see the [`VmmProcessMapThreadCallstackEntry`] struct.
    /// 
    /// # Examples
    /// ```
    /// // in this example the TID (thread id) is 9600.
    /// if let Ok(thread_callstack) = vmmprocess.map_thread_callstack(9600) {
    ///     for cs_entry in &*thread_callstack {
    ///         println!("{cs_entry}");
    ///     }
    /// }
    /// ```
    pub fn map_thread_callstack(&self, tid : u32) -> ResultEx<Vec<VmmProcessMapThreadCallstackEntry>> {
        return self.impl_map_thread_callstack(tid, 0);
    }

    /// Info: Process: Thread Callstack.
    /// 
    /// For additional information see the [`VmmProcessMapThreadCallstackEntry`] struct.
    /// 
    /// # Examples
    /// ```
    /// // in this example the TID (thread id) is 9600.
    /// if let Ok(thread_callstack) = vmmprocess.map_thread_callstack_ex(9600, 0) {
    ///     for cs_entry in &*thread_callstack {
    ///         println!("{cs_entry}");
    ///     }
    /// }
    /// ```
    pub fn map_thread_callstack_ex(&self, tid : u32, flags : u32) -> ResultEx<Vec<VmmProcessMapThreadCallstackEntry>> {
        return self.impl_map_thread_callstack(tid, flags);
    }

    /// Retrieve the unloaded module info map.
    /// 
    /// For additional information see the [`VmmProcessMapUnloadedModuleEntry`] struct.
    /// 
    /// # Examples
    /// ```
    /// if let Ok(unloaded_all) = vmmprocess.map_unloaded_module() {
    ///     println!("Number of process unloaded modules: {}.", unloaded_all.len());
    ///     for unloaded in &*unloaded_all {
    ///         println!("{unloaded}");
    ///     }
    /// }
    /// ```
    pub fn map_unloaded_module(&self) -> ResultEx<Vec<VmmProcessMapUnloadedModuleEntry>> {
        return self.impl_map_unloaded_module();
    }

    /// Retrieve the VAD (virtual address descriptor) memory info map.
    /// 
    /// For additional information see the [`VmmProcessMapVadEntry`] struct.
    /// 
    /// # Examples
    /// ```
    /// if let Ok(vad_all) = vmmprocess.map_vad(true) {
    ///     println!("Number of vad entries: {}.", vad_all.len());
    ///     for vad in &*vad_all {
    ///         println!("{vad} :: {}", vad.info);
    ///     }
    /// }
    /// ```
    pub fn map_vad(&self, is_identify_modules : bool) -> ResultEx<Vec<VmmProcessMapVadEntry>> {
        return self.impl_map_vad(is_identify_modules);
    }

    /// Retrieve the extended VAD info map.
    /// 
    /// For additional information see the [`VmmProcessMapVadExEntry`] struct.
    pub fn map_vadex(&self, offset_pages : u32, count_pages : u32) -> ResultEx<Vec<VmmProcessMapVadExEntry>> {
        return self.impl_map_vadex(offset_pages, count_pages);
    }

    /// Read a contigious virtual memory chunk.
    /// 
    /// The virtual memory is read without any special flags. The whole chunk
    /// must be read successfully for the method to succeed.
    /// 
    /// If deseriable to provide flags modifying the behavior (such as skipping
    /// the built-in data cache or slower paging access) use the method
    /// `mem_read_ex()` instead.
    /// 
    /// Reading many memory chunks individually may be slow, especially if
    /// reading takes place using hardware FPGA devices. In that case it's
    /// better to use the `mem_scatter()` functionality for better performance.
    /// 
    /// 
    /// # Arguments
    /// * `va` - Virtual address to start reading from.
    /// * `size` - Number of bytes to read.
    /// 
    /// # Examples
    /// ```
    /// // Read 0x100 bytes of data from the base of kernel32.
    /// // Example assumes: use pretty_hex::*;
    /// if let Ok(data_read) = vmmprocess.mem_read(va_kernel32, 0x100) {
    ///     println!("{:?}", data_read.hex_dump());
    /// }
    /// ```
    pub fn mem_read(&self, va : u64, size : usize) -> ResultEx<Vec<u8>> {
        return self.vmm.impl_mem_read(self.pid, va, size, 0);
    }

    /// Read a contigious virtual memory chunk with flags.
    /// 
    /// Flags are constants named `FLAG_*`
    /// 
    /// Reading many memory chunks individually may be slow, especially if
    /// reading takes place using hardware FPGA devices. In that case it's
    /// better to use the `mem_scatter()` functionality for better performance.
    /// 
    /// 
    /// # Arguments
    /// * `va` - Virtual address to start reading from.
    /// * `size` - Number of bytes to read.
    /// * `flags` - Any combination of `FLAG_*`.
    /// 
    /// # Examples
    /// ```
    /// // Read 0x100 bytes of data from the base of kernel32.
    /// // Force reading the underlying memory device (skip data cache) and
    /// // Zero-Pad if parts of the memory read fail instead of failing.
    /// // Example assumes: use pretty_hex::*;
    /// let r = vmmprocess.mem_read_ex(va_kernel32, 0x100, FLAG_NOCACHE | FLAG_ZEROPAD_ON_FAIL);
    /// let Ok(data_read) = r {
    ///     println!("{:?}", data_read.hex_dump());
    /// }
    /// ```
    pub fn mem_read_ex(&self, va : u64, size : usize, flags : u64) -> ResultEx<Vec<u8>> {
        return self.vmm.impl_mem_read(self.pid, va, size, flags);
    }

    /// Read a contigious virtual memory chunk with flags into a pre-existing buffer.
    /// 
    /// Flags are constants named `FLAG_*`
    /// 
    /// Reading many memory chunks individually may be slow, especially if
    /// reading takes place using hardware FPGA devices. In that case it's
    /// better to use the `mem_scatter()` functionality for better performance.
    /// 
    /// 
    /// # Arguments
    /// * `va` - Virtual address to start reading from.
    /// * `flags` - Any combination of `FLAG_*`.
    /// * `data` - Pre-allocated buffer to read into.
    /// 
    /// # Examples
    /// ```
    /// // Read 0x100 bytes of data from the base of kernel32.
    /// // Force reading the underlying memory device (skip data cache) and
    /// // Zero-Pad if parts of the memory read fail instead of failing.
    /// // Example assumes: use pretty_hex::*;
    /// let mut data = [0u8; 0x100];
    /// if let Ok(length) = vmmprocess.mem_read_into(va_kernel32, FLAG_NOCACHE | FLAG_ZEROPAD_ON_FAIL, &mut data) {
    ///     println!("bytes_read: {length}");
    ///     println!("{:?}", data.hex_dump());
    /// }
    /// ```
    pub fn mem_read_into(&self, va : u64, flags : u64, data : &mut [u8]) -> ResultEx<usize> {
        return self.vmm.impl_mem_read_into(self.pid, va, flags, data);
    }

    /// Read a contigious virtual memory chunk with flags as a type/struct.
    /// 
    /// Flags are constants named `FLAG_*`
    /// 
    /// Reading many memory chunks individually may be slow, especially if
    /// reading takes place using hardware FPGA devices. In that case it's
    /// better to use the `mem_scatter()` functionality for better performance.
    /// 
    /// 
    /// # Arguments
    /// * `va` - Virtual address to start reading from.
    /// * `flags` - Any combination of `FLAG_*`.
    /// 
    /// # Examples
    /// ```
    /// // Read the C-struct IMAGE_DOS_HEADER from memory.
    /// // Force reading the underlying memory device (skip data cache).
    /// #[repr(C)]
    /// struct IMAGE_DOS_HEADER {
    ///     e_magic : u16,
    /// 	...
    ///     e_lfanew : u32,
    /// }
    /// if let Ok(doshdr) = vmmprocess.mem_read_as::<IMAGE_DOS_HEADER>(va_kernel32, FLAG_NOCACHE) {
    ///     println!("e_magic:  {:x}", doshdr.e_magic);
    ///     println!("e_lfanew: {:x}", doshdr.e_lfanew);
    /// }
    /// ```
    pub fn mem_read_as<T>(&self, va : u64, flags : u64) -> ResultEx<T> {
        return self.vmm.impl_mem_read_as(self.pid, va, flags);
    }

    /// Create a scatter memory object for efficient virtual memory reads.
    /// 
    /// Check out the [`VmmScatterMemory`] struct for more detailed information.
    /// 
    /// # Arguments
    /// * `flags` - Any combination of `FLAG_*`.
    /// 
    /// # Examples
    /// ```
    /// let mem_scatter = vmmprocess.mem_scatter(FLAG_NOCACHE | FLAG_ZEROPAD_ON_FAIL)?;
    /// ```
    pub fn mem_scatter(&self, flags : u64) -> ResultEx<VmmScatterMemory> {
        return self.vmm.impl_mem_scatter(self.pid, flags);
    }

    /// Translate a virtual address to a physical address.
    /// 
    /// It's not always possible to translate a virtual address to a physical
    /// address. This is the case when memory is "paged out".
    /// 
    /// # Arguments
    /// * `va` - Virtual address to translate.
    /// 
    /// # Examples
    /// ```
    /// let pa_kernel32 = vmmprocess.mem_virt2phys(va_kernel32)?;
    /// ```
    pub fn mem_virt2phys(&self, va : u64) -> ResultEx<u64> {
        return self.vmm.impl_mem_virt2phys(self.pid, va);
    }

    /// Write virtual memory.
    /// 
    /// The write is a best effort. Even of the write should fail it's not
    /// certain that an error will be returned. To be absolutely certain that
    /// a write has taken place follow up with a read.
    /// 
    /// # Arguments
    /// * `va` - Virtual address to start writing from.
    /// * `data` - Byte data to write.
    /// 
    /// # Examples
    /// ```
    /// // Write data starting at the base of kernel32 (in the pe header).
    /// let data_to_write = [0x56u8, 0x4d, 0x4d, 0x52, 0x55, 0x53, 0x54].to_vec();
    /// let _r = vmmprocess.mem_write(va_kernel32, &data_to_write);
    /// ```
    pub fn mem_write(&self, va : u64, data : &[u8]) -> ResultEx<()> {
        return self.vmm.impl_mem_write(self.pid, va, data);
    }

    /// Write a type/struct to virtual memory.
    /// 
    /// The write is a best effort. Even of the write should fail it's not
    /// certain that an error will be returned. To be absolutely certain that
    /// a write has taken place follow up with a read.
    /// 
    /// # Arguments
    /// * `va` - Virtual address to start writing from.
    /// * `data` - Data to write. In case of a struct repr(C) is recommended.
    /// 
    /// # Examples
    /// ```
    /// // Write data starting at the base of kernel32 (in the pe header).
    /// let data_to_write = [0x56, 0x4d, 0x4d, 0x52, 0x55, 0x53, 0x54];
    /// let _r = vmmprocess.mem_write_as(va_kernel32, &data_to_write);
    /// ```
    pub fn mem_write_as<T>(&self, va : u64, data : &T) -> ResultEx<()> {
        return self.vmm.impl_mem_write_as(self.pid, va, data);
    }

    /// Retrieve PDB debugging for the module.
    /// 
    /// PDB debugging most often only work on modules by Microsoft.
    /// See [`VmmPdb`] documentation for additional information.
    /// 
    /// # Arguments
    /// * `va_module_base`
    /// 
    /// # Examples
    /// ```
    /// if let Ok(pdb_kernel32) = vmmprocess.pdb_from_module_address(kernel32.va_base) {
    ///     println!("-> {pdb_kernel32}");
    /// }
    /// ```
    pub fn pdb_from_module_address(&self, va_module_base : u64) -> ResultEx<VmmPdb> {
        return self.impl_pdb_from_module_address(va_module_base);
    }

    /// Retrieve PDB debugging for the module.
    /// 
    /// PDB debugging most often only work on modules by Microsoft.
    /// See [`VmmPdb`] documentation for additional information.
    /// 
    /// # Arguments
    /// * `module_name`
    /// 
    /// # Examples
    /// ```
    /// if let Ok(pdb_kernel32) = vmmprocess.pdb_from_module_name("kernel32.dll") {
    ///     println!("-> {pdb_kernel32}");
    /// }
    /// ```
    pub fn pdb_from_module_name(&self, module_name : &str) -> ResultEx<VmmPdb> {
        return self.impl_pdb_from_module_name(module_name);
    }

    /// Retrieve a search struct for process virtual memory.
    /// 
    /// NB! This does not start the actual search yet.
    /// 
    /// Check out the [`VmmSearch`] struct for more detailed information.
    /// 
    /// 
    /// # Arguments
    /// * `addr_min` - Start search at this virtual address.
    /// * `addr_max` - End the search at this virtual address. 0 is interpreted as u64::MAX.
    /// * `num_results_max` - Max number of search hits to search for. Max allowed value is 0x10000.
    /// * `flags` - Any combination of `FLAG_*`.
    /// 
    /// 
    /// # Examples
    /// ```
    /// // Retrieve a VmmSearch for the entire virtual memory.
    /// let mut search = vmmprocess.search(0, 0, 0x10000, 0)?
    /// ```
    /// 
    /// ```
    /// // Retrieve a VmmSearch for virtual memory. Stop at first hit.
    /// // Also avoid using cached and paged out memory.
    /// let mut search = vmmprocess.search(0, 0, 1, FLAG_NOCACHE | FLAG_NOPAGING)?
    /// ```
    pub fn search(&self, addr_min : u64, addr_max : u64, num_results_max : u32, flags : u64) -> ResultEx<VmmSearch> {
        return VmmSearch::impl_new(self.vmm, self.pid, addr_min, addr_max, num_results_max, flags);
    }

    /// Retrieve a yara search struct for process virtual memory.
    /// 
    /// NB! This does not start the actual search yet.
    /// 
    /// Check out the [`VmmYara`] struct for more detailed information.
    /// 
    /// 
    /// # Arguments
    /// * `rules` - Yara rules to search for.
    /// * `addr_min` - Start yara search at this virtual address.
    /// * `addr_max` - End the yara search at this virtual address. 0 is interpreted as u64::MAX.
    /// * `num_results_max` - Max number of yara search hits to search for. Max allowed value is 0x10000.
    /// * `flags` - Any combination of `FLAG_*`.
    /// 
    /// 
    /// # Examples
    /// # Examples
    /// ```
    /// // Retrieve a VmmYara for the entire physical memory.
    /// let yara_rule = " rule mz_header { strings: $mz = \"MZ\" condition: $mz at 0 } ";
    /// let yara_rules = vec![yara_rule];
    /// let mut yara = vmmprocess.search_yara(yara_rules, 0, 0, 0x10000, 0)?
    /// ```
    /// 
    /// ```
    /// // Retrieve a VmmYara for physical memory between 4GB and 8GB.
    /// // Also stop at first yara search hit.
    /// let yara_rules = vec!["/tmp/my_yara_rule.yar", "/tmp/my_yara_rule2.yar"];
    /// let mut yara = vmmprocess.search_yara(yara_rules, 0x100000000, 0x200000000, 1, 0)?
    /// ```
    pub fn search_yara(&self, rules : Vec<&str>, addr_min : u64, addr_max : u64, num_results_max : u32, flags : u64) -> ResultEx<VmmYara> {
        return VmmYara::impl_new(self.vmm, rules, self.pid, addr_min, addr_max, num_results_max, flags);
    }
}






/// Registry Hive API.
/// 
/// The [`VmmRegHive`] info struct allows for access to the registry hive by
/// exposed fields and various methods.
/// 
/// # Created By
/// - [`vmm.reg_hive_list()`](Vmm::reg_hive_list())
/// 
/// # Examples
/// ```
/// let hive_all = vmm.reg_hive_list()?;
/// for hive in hive_all {
///     println!("{hive} size={} path={}", hive.size, hive.path);
/// }
/// ```
#[derive(Debug, Clone)]
pub struct VmmRegHive<'a> {
    vmm : &'a Vmm<'a>,
    pub va : u64,
    pub va_baseblock : u64,
    pub size : u32,
    pub name : String,
    pub name_short : String,
    pub path : String,
}

impl VmmRegHive<'_> {
    /// Read registry hive data.
    /// 
    /// # Arguments
    /// * `ra` - Registry hive address to start reading from.
    /// * `size` - The number of bytes to read.
    /// * `flags` - Any combination of `FLAG_*`.
    /// 
    /// # Examples
    /// ```
    /// if let Ok(data) = hive.reg_hive_read(0x1000, 0x100, FLAG_NOCACHE | FLAG_ZEROPAD_ON_FAIL) {
    ///     println!("{:?}", data.hex_dump());
    /// }
    /// ```
    pub fn reg_hive_read(&self, ra : u32, size : usize, flags : u64) -> ResultEx<Vec<u8>> {
        return self.impl_reg_hive_read(ra, size, flags);
    }

    /// Write registry hive data.
    /// 
    /// Writing to registry hives is extemely unsafe and may lead to
    /// registry corruption and unusable systems. Use with extreme care!
    /// 
    /// # Arguments
    /// * `ra` - Registry hive address to start writing from.
    /// * `data` - Byte data to write.
    /// 
    /// # Examples
    /// ```
    /// let data_to_write = [0x56u8, 0x4d, 0x4d, 0x52, 0x55, 0x53, 0x54].to_vec();
    /// let _r = hive.reg_hive_write(0x1000, &data_to_write);
    /// ```
    pub fn reg_hive_write(&self, ra : u32, data : &[u8]) -> ResultEx<()> {
        return self.impl_reg_hive_write(ra, data);
    }
}

/// Registry Key API.
/// 
/// The [`VmmRegKey`] info struct represents a registry key and also have
/// additional access methods for retrieving registry keys and values.
/// 
/// Registry keys may be addressed either by its full path or by hive address
/// and hive path. Both addressing modes are shown in the examples below.
/// Registry keys are case sensitive.
/// 
/// # Created By
/// - [`vmm.reg_key()`](Vmm::reg_key())
/// - [`vmmregkey.parent()`](VmmRegKey::parent())
/// - [`vmmregkey.subkeys()`](VmmRegKey::subkeys())
/// - [`vmmregkey.subkeys_map()`](VmmRegKey::subkeys_map())
/// - [`vmmregvalue.parent()`](VmmRegValue::parent())
/// 
/// # Examples
/// ```
/// // Retrieve a regkey by full path.
/// let regkey = vmm.reg_key("HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run")?
/// println!("{regkey");
/// ```
/// 
/// ```
/// // Retrieve a regkey by hive path.
/// // (SOFTWARE hive example address: 0xffffba061a908000).
/// let regkey = vmm.reg_key("0xffffba061a908000\\ROOT\\Microsoft\\Windows\\CurrentVersion\\Run")?
/// println!("{regkey");
/// ```
#[derive(Clone, Debug)]
pub struct VmmRegKey<'a> {
    vmm : &'a Vmm<'a>,
    /// Key name.
    pub name : String,
    /// Path including key name.
    pub path : String,
    /// Last write timestamp in Windows filetime format.
    pub ft_last_write : u64,
}

impl VmmRegKey<'_> {
    /// Retrieve the parent registry key of this registry key.
    /// 
    /// # Examples
    /// ```
    /// let regkey_parent = regkey.parent()?
    /// println!("{regkey_parent");
    /// ```
    pub fn parent(&self) -> ResultEx<VmmRegKey> {
        return self.impl_parent();
    }

    /// Retrieve the registry subkeys of this registry key
    /// 
    /// # Examples
    /// ```
    /// // Retrieve all registry subkeys (as Vec).
    /// let subkeys = regkey.subkeys()?
    /// for key in subkeys {
    ///     println!("{key}")
    /// }
    /// ```
    pub fn subkeys(&self) -> ResultEx<Vec<VmmRegKey>> {
        return self.impl_subkeys();
    }

    /// Retrieve the registry subkeys of this registry key as a map
    /// 
    /// K: String key name,
    /// V: VmmRegKey
    /// 
    /// # Examples
    /// ```
    /// // Retrieve all registry subkeys (as HashMap).
    /// let subkeys = regkey.subkeys_map()?
    /// for e in subkeys {
    ///     println!("{},{}", e.0, e.1)
    /// }
    /// ```
    pub fn subkeys_map(&self) -> ResultEx<HashMap<String, VmmRegKey>> {
        return Ok(self.impl_subkeys()?.into_iter().map(|s| (s.name.clone(), s)).collect());
    }

    /// Retrieve the registry values of this registry key
    /// 
    /// # Examples
    /// ```
    /// // Retrieve all registry values (as Vec).
    /// let values = regkey.values()?
    /// for value in values {
    ///     println!("{value}")
    /// }
    /// ```
    pub fn values(&self) -> ResultEx<Vec<VmmRegValue>> {
        return self.impl_values();
    }

    /// Retrieve the registry values of this registry key as a map
    /// 
    /// K: String value name,
    /// V: VmmRegValue
    /// 
    /// # Examples
    /// ```
    /// // Retrieve all registry values (as HashMap).
    /// let values = regkey.values_map()?
    /// for e in values {
    ///     println!("{},{}", e.0, e.1)
    /// }
    /// ```
    pub fn values_map(&self) -> ResultEx<HashMap<String, VmmRegValue>> {
        return Ok(self.impl_values()?.into_iter().map(|s| (s.name.clone(), s)).collect());
    }

}

#[allow(non_camel_case_types)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum VmmRegValueType {
    REG_NONE,
    REG_SZ(String),
    REG_EXPAND_SZ(String),
    REG_BINARY(Vec<u8>),
    REG_DWORD(u32),
    REG_DWORD_BIG_ENDIAN(u32),
    REG_LINK(String),
    REG_MULTI_SZ(Vec<String>),
    REG_RESOURCE_LIST(Vec<u8>),
    REG_FULL_RESOURCE_DESCRIPTOR(Vec<u8>),
    REG_RESOURCE_REQUIREMENTS_LIST(Vec<u8>),
    REG_QWORD(u64),
}

/// Registry Value API.
/// 
/// The [`VmmRegValue`] info struct represents a registry value and also have
/// additional access methods for parent key and the value itself.
/// 
/// Registry values may be addressed either by its full path or by hive address
/// and hive path. Both addressing modes are shown in the examples below.
/// Registry values are case sensitive.
/// 
/// # Created By
/// - [`vmm.reg_value()`](Vmm::reg_value())
/// - [`vmmregkey.values()`](VmmRegKey::values())
/// - [`vmmregkey.values_map()`](VmmRegKey::values_map())
/// 
/// # Examples
/// ```
/// // Retrieve a REG_SZ (string) reg value by its full path.
/// let regpath = "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\ProgramFilesDir";
/// let regvalue = vmm.reg_key(regpath)?
/// println!("{regvalue}");
/// if let Ok(VmmRegValueType::REG_SZ(s)) = regvalue.value() {
///     println!("REG_SZ: {s}");
/// }
/// ```
/// 
/// ```
/// // Retrieve a REG_DWORD reg value using the hive path.
/// // (SOFTWARE hive example address: 0xffffba061a908000).
/// let regpath = "0xffffba061a908000\\ROOT\\Microsoft\\.NETFramework\\Enable64Bit";
/// let regvalue = vmm.reg_key(regpath)?
/// if let Ok(VmmRegValueType::REG_DWORD(dw)) = regvalue.value() {
///     println!("REG_DWORD: 0x{:08x}", dw);
/// }
/// ```
#[derive(Clone, Debug)]
pub struct VmmRegValue<'a> {
    vmm : &'a Vmm<'a>,
    /// Value name.
    pub name : String,
    /// Path including key name.
    pub path : String,
    /// The raw type as specified by Windows REG_* constants.
    pub raw_type : u32,
    /// The raw data size in bytes.
    pub raw_size : u32,
    raw_value : Option<Vec<u8>>,
}

impl VmmRegValue<'_> {
    /// Retrieve the parent registry key.
    /// 
    /// # Examples
    /// ```
    /// let regkey_parent = regvalue.parent()?
    /// println!("{regkey_parent");
    /// ```
    pub fn parent(&self) -> ResultEx<VmmRegKey> {
        return self.impl_parent();
    }

    /// Retrieve the registry value.
    /// 
    /// The registry value is returned as [`VmmRegValueType`] enum containing
    /// the relevant embedded value.
    /// 
    /// 
    /// # Examples
    /// ```
    /// // Retrieve a REG_SZ (string) reg value.
    /// if let Ok(VmmRegValueType::REG_SZ(s)) = regvalue.value() {
    ///     println!("REG_SZ: {s}");
    /// }
    /// ```
    /// 
    /// ```
    /// // Retrieve a REG_DWORD reg value.
    /// if let Ok(VmmRegValueType::REG_DWORD(dw)) = regvalue.value() {
    ///     println!("REG_DWORD: 0x{:08x}", dw);
    /// }
    /// ```
    pub fn value(&self) -> ResultEx<VmmRegValueType> {
        return self.impl_value();
    }

    /// Retrieve the raw value bytes backing the actual value.
    /// 
    /// # Examples
    /// ```
    /// let raw_value = vmmregvalue.raw_value()?;
    /// println!("{:?}", raw_value.hex_dump());
    /// ```
    pub fn raw_value(&self) -> ResultEx<Vec<u8>> {
        return self.impl_raw_value();
    }
}






/// Search API.
/// 
/// Search for binary keywords in physical or virtual memory.
/// 
/// Each keyword/term may be up to 32 bytes long. Up to 16 search terms may
/// be used in the same search.
/// 
/// The search may optionally take place with a skipmask - i.e. a bitmask in
/// which '1' would equal a wildcard bit.
/// 
/// The [`VmmSearch`] must be used as mut. Also see [`VmmSearchResult`].
/// 
/// The synchronous search workflow:
/// 1) Acquire search object from `vmm.search()` or `vmmprocess.search()`.
/// 2) Add 1-16 different search terms using `vmmsearch.add_search()` and/or
///    `vmmsearch.add_search_ex()`.
/// 3) Start the search and retrieve result (blocking) by calling
///    `vmmsearch.result()`.
/// 
/// The asynchronous search workflow:
/// 1) Acquire search object from `vmm.search()` or `vmmprocess.search()`.
/// 2) Add 1-16 different search terms using `vmmsearch.add_search()` and/or
///    `vmmsearch.add_search_ex()`.
/// 3) Start the search in the background using `vmmsearch.start()`.
/// 4) Optionally abort the search with `vmmsearch.abort()`.
/// 5) Optionally poll status or result (if completed) using `vmmsearch.poll()`.
/// 6) Optionally retrieve result (blocking) by calling `vmmsearch.result()`.
/// 7) Search goes out of scope and is cleaned up. Any on-going searches may
///    take a short while to terminate gracefully.
/// 
/// 
/// # Created By
/// - [`vmm.search()`](Vmm::search())
/// - [`vmmprocess.search()`](VmmProcess::search())
/// 
/// # Examples
/// ```
/// // Fetch search struct for entire process virtual address space.
/// // Max 256 search hits and avoid using the cache in this example.
/// let mut vmmsearch = vmmprocess.search(0, 0, 256, FLAG_NOCACHE);
/// // Search for 'MZ' - i.e. start at PE file at even 0x1000 alignment.
/// let search_term = ['M' as u8, 'Z' as u8];
/// let _search_term_id = vmmsearch.add_search_ex(&search_term, None, 0x1000);
/// // Start search in async mode.
/// vmmsearch.start();
/// // Search is now running - it's possible to do other actions here.
/// // It's possible to poll() to see current progress (or if finished).
/// // It's possible to abort() to stop search.
/// // It's possible to fetch result() which will block until search is finished.
/// let search_result = vmmsearch.result();
/// ```
#[derive(Debug)]
pub struct VmmSearch<'a> {
    vmm : &'a Vmm<'a>,
    pid : u32,
    is_started : bool,
    is_completed : bool,
    is_completed_success : bool,
    native_search : CVMMDLL_MEM_SEARCH_CONTEXT,
    search_terms : Vec<CVMMDLL_MEM_SEARCH_CONTEXT_SEARCHENTRY>,
    thread : Option<std::thread::JoinHandle<bool>>,
    result : Vec<(u64, u32)>,
}

/// Info: Search Progress/Result.
/// 
/// Also see [`VmmSearch`].
/// 
/// # Created By
/// - [`vmmsearch.poll()`](VmmSearch::poll())
/// - [`vmmsearch.result()`](VmmSearch::result())
/// 
/// # Examples
/// ```
/// // Retrieve a search progress/result in a non-blocking call.
/// let searchresult = vmmsearch.poll();
/// ```
/// 
/// ```
/// // Retrieve a search result in a blocking call (until completed search).
/// let searchresult = vmmsearch.result();
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VmmSearchResult {
    /// Indicates that the search has been started. i.e. start() or result() have been called.
    pub is_started : bool,
    /// Indicates that the search has been completed.
    pub is_completed : bool,
    /// Indicates that the search has been completed successfully.
    pub is_completed_success : bool,
    /// Address to start searching from - default 0.
    pub addr_min : u64,
    /// Address to stop searching at - default u64::MAX.
    pub addr_max : u64,
    /// Current address being searched in search thread.
    pub addr_current : u64,
    /// Number of bytes that have been procssed in search.
    pub total_read_bytes : u64,
    /// Number of search results.
    pub total_results : u32,
    /// The actual result. result.0 = address, result.1 = search_term_id.
    pub result : Vec<(u64, u32)>,
}

impl VmmSearch<'_> {
    /// Add a search term.
    /// 
    /// The search will later be performed using the whole search term and
    /// without alignment requirements (align = 1 byte).
    /// 
    /// On success the `search_term_id` will be returned. This is the 2nd
    /// field (`searchresulttuple.1`) in the search result tuple. This may be
    /// useful if multiple searches are undertaken in one single search run.
    /// 
    /// # Arguments
    /// * `search_bytes` - Byte data to search for. Max 32 bytes.
    /// 
    /// # Examples
    /// ```
    /// // add a search term for pointer references to address 0x7ffcec973308.
    /// let search_term = [0x08, 0x33, 0x97, 0xec, 0xfc, 0x7f, 0x00, 0x00];
    /// let search_term_id = vmmsearch.add_search(&search_term)?;
    /// ```
    pub fn add_search(&mut self, search_bytes : &[u8]) -> ResultEx<u32> {
        return self.impl_add_search(search_bytes, None, 1);
    }

    /// Add a search term.
    /// 
    /// The search will later be performed using the search term with the
    /// given alignment (typically 1, 2, 4, 8, 16, .. 0x1000) and an optional
    /// skip bitmask in which bit '1' represents a search wildcard value.
    /// 
    /// On success the `search_term_id` will be returned. This is the 2nd
    /// field (`searchresulttuple.1`) in the search result tuple. This may be
    /// useful if multiple searches are undertaken in one single search run.
    /// 
    /// # Arguments
    /// * `search_bytes` - Byte data to search for. Max 32 bytes.
    /// * `search_skipmask` - Optional skipmask (see above). Max search_bytes.len().
    /// * `byte_align` - Byte alignment (see above).
    /// 
    /// # Examples
    /// ```
    /// // Add a search term for pointer references to address 0x7ffcec973308.
    /// // Pointers are 64-bit/8-byte aligned hence the 8-byte alignment.
    /// let search_term = [0x08, 0x33, 0x97, 0xec, 0xfc, 0x7f, 0x00, 0x00];
    /// let search_term_id = vmmsearch.add_search_ex(&search_term, None, 8)?;
    /// ```
    pub fn add_search_ex(&mut self, search_bytes : &[u8], search_skipmask : Option<&[u8]>, byte_align : u32) -> ResultEx<u32> {
        return self.impl_add_search(search_bytes, search_skipmask, byte_align);
    }

    /// Start a search in asynchronous background thread.
    /// 
    /// This is useful since the search may take some time and other work may
    /// be done while waiting for the result.
    /// 
    /// The search will start immediately and the progress (and result, if
    /// finished) may be polled by calling [`poll()`](VmmSearch::poll()).
    /// 
    /// The result may be retrieved by a call to `poll()` or by a blocking
    /// call to [`result()`](VmmSearch::result()) which will return when the
    /// search is completed.
    /// 
    /// # Examples
    /// ```
    /// vmmsearch.start();
    /// ```
    pub fn start(&mut self) {
        self.impl_start();
    }

    /// Abort an on-going search.
    /// 
    /// # Examples
    /// ```
    /// vmmsearch.abort();
    /// ```
    pub fn abort(&mut self) {
        self.impl_abort();
    }

    /// Poll an on-going search for the status/result.
    /// 
    /// Also see [`VmmSearch`] and [`VmmSearchResult`].
    /// 
    /// # Examples
    /// ```
    /// let search_status_and_result = vmmsearch.poll();
    /// ```
    pub fn poll(&mut self) -> VmmSearchResult {
        return self.impl_poll();
    }

    /// Retrieve the search result.
    /// 
    /// If the search haven't yet been started it will be started.
    /// The function is blocking and will wait for the search to complete
    /// before the search results are returned.
    /// 
    /// Also see [`VmmSearch`] and [`VmmSearchResult`].
    /// 
    /// # Examples
    /// ```
    /// let search_status_and_result = vmmsearch.result();
    /// ```
    pub fn result(&mut self) -> VmmSearchResult {
        return self.impl_result();
    }
}






/// Yara Search API.
/// 
/// Search for yara signatures in physical or virtual memory.
/// 
/// Yara rules may be in either the form of:
/// - one (1) compiled yara rules file.
/// - multiple yara source rules files.
/// - multiple yara source rules strings.
/// 
/// The [`VmmYara`] must be used as mut. Also see [`VmmYaraResult`].
/// 
/// The synchronous search workflow:
/// 1) Acquire search object from `vmm.search_yara()` or `vmmprocess.search_yara()`.
/// 2) Start the search and retrieve result (blocking) by calling `vmmyara.result()`.
/// 
/// The asynchronous search workflow:
/// 1) Acquire search object from `vmm.search_yara()` or `vmmprocess.search_yara()`.
/// 2) Start the search in the background using `vmmyara.start()`.
/// 3) Optionally abort the search with `vmmyara.abort()`.
/// 4) Optionally poll status or result (if completed) using `vmmyara.poll()`.
/// 5) Optionally retrieve result (blocking) by calling `vmmyara.result()`.
/// 6) Yara Search goes out of scope and is cleaned up. Any on-going searches
///    may take a short while to terminate gracefully.
/// 
/// 
/// # Created By
/// - [`vmm.search_yara()`](Vmm::search_yara())
/// - [`vmmprocess.search_yara()`](VmmProcess::search_yara())
/// 
/// # Examples
/// ```
/// // Fetch yara search struct for entire process virtual address space.
/// // Max 256 search hits and avoid using the cache in this example.
/// let yara_rule = " rule mz_header { strings: $mz = \"MZ\" condition: $mz at 0 } ";
/// let yara_rules = vec![yara_rule];
/// let mut vmmyara = vmmprocess.search_yara(yara_rules, 0, 0, 256, FLAG_NOCACHE);
/// // Start search in async mode.
/// vmmyara.start();
/// // Search is now running - it's possible to do other actions here.
/// // It's possible to poll() to see current progress (or if finished).
/// // It's possible to abort() to stop search.
/// // It's possible to fetch result() which will block until search is finished.
/// let yara_result = vmmyara.result();
/// ```
#[derive(Debug)]
pub struct VmmYara<'a> {
    vmm : &'a Vmm<'a>,
    pid : u32,
    is_started : bool,
    is_completed : bool,
    is_completed_success : bool,
    native : CVMMDLL_YARA_CONFIG,
    _native_args_rules : Vec<CString>,
    _native_argv_rules : Vec<*const c_char>,
    thread : Option<std::thread::JoinHandle<bool>>,
    result : Vec<VmmYaraMatch>,
}

/// Info: Yara search Progress/Result.
/// 
/// Also see [`VmmYara`].
/// 
/// 
/// # Created By
/// - [`vmmyara.poll()`](VmmYara::poll())
/// - [`vmmyara.result()`](VmmYara::result())
/// 
/// # Examples
/// ```
/// // Retrieve a search progress/result in a non-blocking call.
/// let yararesult = vmmyara.poll();
/// ```
/// 
/// ```
/// // Retrieve a search result in a blocking call (until completed search).
/// let yararesult = vmmyara.result();
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VmmYaraResult {
    /// Indicates that the yara search has been completed.
    pub is_completed : bool,
    /// If is_completed is true this indicates if the search was completed successfully.
    pub is_completed_success : bool,
    /// Address to start searching from - default 0.
    pub addr_min : u64,
    /// Address to stop searching at - default u64::MAX.
    pub addr_max : u64,
    /// Current address being searched in search thread.
    pub addr_current : u64,
    /// Number of bytes that have been procssed in search.
    pub total_read_bytes : u64,
    /// Number of search results.
    pub total_results : u32,
    /// The actual result containing the yara matches.
    pub result : Vec<VmmYaraMatch>,
}

/// Info: Yara search match string.
/// 
/// Also see [`VmmYara`] and [`VmmYaraResult`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VmmYaraMatchString {
    /// yara match string identifier.
    pub match_string : String,
    /// yara match addresses.
    pub addresses : Vec<u64>,
}

/// Info: Yara search match.
/// 
/// Also see [`VmmYara`] and [`VmmYaraResult`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VmmYaraMatch {
    /// yara match memory region base address.
    pub addr : u64,
    /// yara rule identifier.
    pub rule : String,
    /// yara rule tags.
    pub tags : Vec<String>,
    /// yara rule meta data - key/value pairs.
    pub meta : Vec<(String, String)>,
    /// yara match strings.
    pub match_strings : Vec<VmmYaraMatchString>,
}

impl VmmYara<'_> {
    /// Start a yara search in asynchronous background thread.
    /// 
    /// This is useful since the yara search may take some time and other work
    /// may be done while waiting for the result.
    /// 
    /// The search will start immediately and the progress (and result, if
    /// finished) may be polled by calling [`poll()`](VmmYara::poll()).
    /// 
    /// The result may be retrieved by a call to `poll()` or by a blocking
    /// call to [`result()`](VmmSearch::result()) which will return when the
    /// search is completed.
    /// 
    /// # Examples
    /// ```
    /// vmmyara.start();
    /// ```
    pub fn start(&mut self) {
        self.impl_start();
    }

    /// Abort an on-going yara search.
    /// 
    /// # Examples
    /// ```
    /// vmmyara.abort();
    /// ```
    pub fn abort(&mut self) {
        self.impl_abort();
    }

    /// Poll an on-going yara search for the status/result.
    /// 
    /// Also see [`VmmYara`] and [`VmmYaraResult`].
    /// 
    /// # Examples
    /// ```
    /// let yara_status_and_result = vmmyara.poll();
    /// ```
    pub fn poll(&mut self) -> VmmYaraResult {
        return self.impl_poll();
    }

    /// Retrieve the yara search result.
    /// 
    /// The function is blocking and will wait for the search to complete
    /// before the results are returned.
    /// 
    /// Also see [`VmmYara`] and [`VmmYaraResult`].
    /// 
    /// # Examples
    /// ```
    /// let yara_status_and_result = vmmyara.result();
    /// ```
    pub fn result(&mut self) -> VmmYaraResult {
        return self.impl_result();
    }
}






/// Initialize plugin information and initialization context.
/// 
/// This should usually be the first call in a `InitializeVmmPlugin()` export.
///
/// See the plugin example for additional documentation.
pub fn new_plugin_initialization<T>(native_h : usize, native_reginfo : usize) -> ResultEx<(VmmPluginInitializationInfo, VmmPluginInitializationContext<T>)> {
    return impl_new_plugin_initialization::<T>(native_h, native_reginfo);
}



/// Plugin Context: Supplied by MemProcFS to plugin callback functions.
/// 
/// Contains the `vmm` field which gives access to the general API.
/// 
/// Contains the `ctxlock` field which gives access to the user-defined generic
/// struct set at plugin initialization.
/// 
/// The `ctxlock` field is a `std::sync::RwLock` and the inner user-defined
/// generic struct may be accessed in either multi-threaded read-mode or
/// single-threaded mutable write-mode. Read mode is more efficient.
/// 
/// See the plugin example for additional use cases and documentation.
/// 
/// 
/// # Created By
/// - `plugin sub-system`
/// 
/// 
/// # Examples
/// 
/// ```
/// // Access the `vmm` field to retrieve a process for pid 768.
/// // Some `vmm` calls such as `vmm.process(pid)` may fail. In this case if
/// // the process does not exist. It is recommended to handle these errors
/// // gracefully as per below.
/// if let Ok(systemprocess) = plugin_ctx.vmm.process(768) {
///     // ...
/// }
/// ```
/// 
/// ```
/// // Access the `vmm` field to retrieve a process for pid 768.
/// // Some `vmm` calls such as `vmm.process(pid)` may fail. It is possible to
/// // use error propagation for simplicity. Errors will be handled by upper
/// // plugin layers. If this is preferred error propagation may be simpler.
/// let systemprocess = plugin_ctx.vmm.process(768)?;
/// ```
/// 
/// ```
/// // Access the ctxlock in multi-threaded read-mode:
/// // The lock should always contain a generic so unwrap() should be safe.
/// let user_ctx = plugin_ctx.ctxlock.read().unwrap();
/// ```
/// 
/// ```
/// // Access the ctxlock in single-threaded mutable write-mode:
/// // The lock should always contain a generic so unwrap() should be safe.
/// let mut user_ctx = plugin_ctx.ctxlock.write().unwrap();
/// ```
/// 
/// 
/// See the plugin example about usage of the ctxlock field.
pub struct VmmPluginContext<'a, T> {
    /// Access the general MemProcFS API through the `vmm` field.
    pub vmm     : Vmm<'a>,
    /// Access generic user-set plugin context in a thread-safe way.
    pub ctxlock : std::sync::RwLock<T>,
    fn_list     : Option<fn(ctxp : &VmmPluginContext<T>, process : Option<VmmProcess>, path : &str, file_list : &VmmPluginFileList) -> ResultEx<()>>,
    fn_read     : Option<fn(ctxp : &VmmPluginContext<T>, process : Option<VmmProcess>, file_name : &str, cb : u32, cb_offset : u64) -> ResultEx<Vec<u8>>>,
    fn_write    : Option<fn(ctxp : &VmmPluginContext<T>, process : Option<VmmProcess>, file_name : &str, data : Vec<u8>, cb_offset : u64) -> ResultEx<()>>,
    fn_visible  : Option<fn(ctxp : &VmmPluginContext<T>, process : Option<VmmProcess>) -> ResultEx<bool>>,
    fn_notify   : Option<fn(ctxp : &VmmPluginContext<T>, event_id : u32) -> ResultEx<()>>,
}



/// Plugin File List: Supplied by MemProcFS to plugin list callback function.
/// 
/// The `VmmPluginFileList` struct contains the methods `add_file()` and 
/// `add_directory()` which will allow the plugin list callback function
/// to populate files & directories given the specified path and process.
/// 
/// # Created By
/// - `plugin sub-system`
#[derive(Debug)]
pub struct VmmPluginFileList<'a> {
    vmm : &'a Vmm<'a>,
    h_file_list : usize,
}

impl VmmPluginFileList<'_> {
    /// Add a file to the plugin directory indicated by path and process.
    /// 
    /// For additional information check the `plugin_list_cb()` function in the
    /// plugin example project.
    /// 
    /// # Examples
    /// 
    /// ```
    /// // Add a directory named readme.txt with size 4kB to the plugin path.
    /// file_list.impl_add_file("readme.txt", 4096);
    /// ```
    pub fn add_file(&self, name : &str, size : u64) {
        self.impl_add_file(name, size);
    }

    /// Add a directory to the plugin directory indicated by path and process.
    /// 
    /// For additional information check the `plugin_list_cb()` function in the
    /// plugin example project.
    /// 
    /// # Examples
    /// 
    /// ```
    /// // Add a directory named subdir33 to the plugin path.
    /// file_list.add_directory("subdir33");
    /// ```
    pub fn add_directory(&self, name : &str) {
        self.impl_add_directory(name);
    }
}



/// Plugin Initialization System Information.
/// 
/// The `VmmPluginInitializationInfo` is used in the plugin module entry point
/// (the exported `InitializeVmmPlugin()` function).
/// 
/// The `InitializeVmmPlugin()` function must be fast for the user experience
/// and the initialization function may query this info struct to decide if
/// the current system is supported or not before registering the plugin. 
/// 
/// Contains information about the: system type, memory model and OS version
/// (in the form of build, major and minor).
/// 
/// For additional information check the `InitializeVmmPlugin()` function in
/// the plugin example project.
/// 
/// 
/// # Created By
/// - [`new_plugin_initialization()`]
/// 
/// 
/// # Examples
/// 
/// ```
/// // Retrieve the system_info and plugin_init_ctx in InitializeVmmPlugin()
/// let (system_info, mut plugin_init_ctx) = match new_plugin_initialization::<PluginContext>(native_h, native_reginfo) {
///     Ok(r) => r,
///     Err(_) => return,
/// };
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VmmPluginInitializationInfo {
    /// The system type - i.e. 32-bit or 64-bit Windows.
    pub tp_system : VmmSystemType,
    /// The memory model type - i.e. X86, X86PAE, X64.
    pub tp_memorymodel : VmmMemoryModelType,
    /// The OS major version. Use version_build instead if possible.
    pub version_major : u32,
    /// The OS minor version. Use version_build instead if possible.
    pub version_minor : u32,
    /// The build version number.
    pub version_build : u32,
}



/// Plugin Initialization Context.
/// 
/// The `VmmPluginInitializationContext` is used in the plugin module entry
/// point (the exported `InitializeVmmPlugin()` function).
/// 
/// The context is to be populated by the user with information such as name,
/// callback functions and plugin visibility.
/// 
/// The flow usually follows the below structure:
/// 
/// 1: Call: memprocfs::new_plugin_initialization(native_h, native_reginfo) to
///    create the plugin init context inside the InitializeVmmPlugin() function.
/// 
/// 2: Fill out the required ctx and path_name struct members.
/// 
/// 3: Fill out the module type in the is* struct members.
/// 
/// 4: Fill out the optional pfn* callback functions.
/// 
/// 5: Register the plugin with the VMM by calling the register() method.
/// 
/// For additional information check the `InitializeVmmPlugin()` function in
/// the plugin example project.
/// 
/// 
/// # Created By
/// - [`new_plugin_initialization()`]
/// 
/// 
/// # Examples
/// 
/// ```
/// // Retrieve the system_info and plugin_init_ctx in InitializeVmmPlugin()
/// let (system_info, mut plugin_init_ctx) = match new_plugin_initialization::<PluginContext>(native_h, native_reginfo) {
///     Ok(r) => r,
///     Err(_) => return,
/// };
/// // set plugin name:
/// plugin_init_ctx.path_name = String::from("/rust/example");
/// // Set user-defined generic plugin context:
/// let ctx = PluginContext {
///     ...
/// };
/// plugin_init_ctx.ctx = Some(ctx);
/// // Set visiblity:
/// plugin_init_ctx.is_root_module = true;
/// plugin_init_ctx.is_process_module = true;
/// // Set callback functions:
/// plugin_init_ctx.fn_list = Some(plugin_list_cb);
/// plugin_init_ctx.fn_read = Some(plugin_read_cb);
/// plugin_init_ctx.fn_write = Some(plugin_write_cb);
/// // Register the plugin with the MemProcFS plugin manager:
/// let _r = plugin_init_ctx.register();
/// ```
pub struct VmmPluginInitializationContext<T> {
    h_vmm           : usize,
    h_reginfo       : usize,
    /// user-defined generic plugin context.
    pub ctx         : Option<T>,
    /// Plugin path and name.
    pub path_name   : String,
    /// Plugin shows up in the file system root.
    pub is_root_module : bool,
    /// Plugin is hidden in the file system root.
    pub is_root_module_hidden : bool,
    /// Plugin shows up on a per-process basis.
    pub is_process_module : bool,
    /// Plugin is hidden on a per-process basis.
    pub is_process_module_hidden : bool,
    /// Callback function - VFS list directory. This callback used in most cases.
    pub fn_list    : Option<fn(ctxp : &VmmPluginContext<T>, process : Option<VmmProcess>, path : &str, file_list : &VmmPluginFileList) -> ResultEx<()>>,
    /// Callback function - VFS read file. This callback is used in most cases.
    pub fn_read    : Option<fn(ctxp : &VmmPluginContext<T>, process : Option<VmmProcess>, file_name : &str, cb : u32, cb_offset : u64) -> ResultEx<Vec<u8>>>,
    /// Callback function - VFS write file.
    pub fn_write   : Option<fn(ctxp : &VmmPluginContext<T>, process : Option<VmmProcess>, file_name : &str, data : Vec<u8>, cb_offset : u64) -> ResultEx<()>>,
    /// Callback function - plugin dynamic visiblity. This callback is rarely used, and in special circumstances only.
    pub fn_visible : Option<fn(ctxp : &VmmPluginContext<T>, process : Option<VmmProcess>) -> ResultEx<bool>>,
    /// Callback function - notification on an event defined by: `PLUGIN_NOTIFY_*` constants.
    pub fn_notify  : Option<fn(ctxp : &VmmPluginContext<T>, event_id : u32) -> ResultEx<()>>,
}

impl<T> VmmPluginInitializationContext<T> {
    /// Register the plugin with the MemProcFS plugin sub-system.
    /// 
    /// The initialiation context may not be used after the `register()` call.
    /// 
    /// It is possible to register additional plugins in the same plugin
    /// initialization function if a new `VmmPluginInitializationContext`
    /// is retrieved from the `new_plugin_initialization()` function.
    /// 
    /// # Examples
    /// 
    /// ```
    /// // Register the plugin with MemProcFS. This will consume the context
    /// // which should not be possible to use after this.
    /// let _r = plugin_init_ctx.register();
    /// ```
    /// 
    pub fn register(self) -> ResultEx<()> {
        return self.impl_register();
    }
}












//=============================================================================
// LEECHCORE API:
//=============================================================================

/// <b>LeechCore API Base Struct.</b>
/// 
/// The [`LeechCore`] struct is the base of the low-level physical memory
/// aqusition API used by MemProcFS / [`Vmm`]. Normally it is not required
/// to interact with this low-level library.
/// 
/// One may however wish to use specialized functionality such as sending and
/// receiving raw PCIe TLPs (if the FPGA backend is in use), or to implement a
/// device PCIe BAR.
/// 
/// The [`LeechCore`] struct acts as a wrapper around the native LeechCore API.
/// 
/// <b>Check out the example project for more detailed API usage and
/// additional examples!</b>
/// 
/// 
/// # Created By
/// - [`LeechCore::new()`]
/// - [`LeechCore::new_ex()`]
/// - [`Vmm::get_leechcore()`]
/// 
/// # Examples
/// 
/// ```
/// // Create a new LeechCore instance:
/// let lc = LeechCore::new('C:\\Temp\\MemProcFS\\leechcore.dll', 'fpga://algo=0', LeechCore::LC_CONFIG_PRINTF_ENABLED)?;
/// ```
/// 
/// ```
/// // Fetch an existing LeechCore instance from a Vmm instance:
/// let lc = vmm.get_leechcore()?;
/// ```
#[derive(Debug)]
pub struct LeechCore {
    path_lc : String,
    native : LcNative,
}

/// PCIe BAR info struct.
/// 
/// # Created By
/// - [`LeechCore::get_bars()`]
/// - LeechCore PCIe BAR callback.
/// ```
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct LcBar {
    /// BAR is valid.
    pub is_valid : bool,
    /// BAR is I/O.
    pub is_io : bool,
    /// BAR is 64-bit.
    pub is_64bit : bool,
    /// BAR is prefetchable.
    pub is_prefetchable : bool,
    /// BAR index (0-5).
    pub bar_index : u32,
    /// BAR physical base address.
    pub pa : u64,
    /// BAR size in bytes.
    pub cb : u64,
}

/// PCIe BAR request struct.
/// 
/// # Created By
/// - LeechCore PCIe BAR callback.
/// ```
#[derive(Debug)]
pub struct LcBarRequest {
    native : *mut LC_BAR_REQUEST,
    /// The PCIe BAR which this request is for.
    pub bar : LcBar,
    /// PCIe TLP packet tag.
    pub tag : u8,
    /// first byte-enable.
    pub be_first : u8,
    /// last byte-enable.
    pub be_last : u8,
    /// is a 64-bit request.
    pub is_64bit : bool,
    /// is a read request.
    pub is_read : bool,
    /// is a write request.
    pub is_write : bool,
    /// data size in bytes.
    pub data_size : u32,
    /// data byte offset within the BAR.
    pub data_offset : u64,
    /// data to write (if a write request).
    pub data_write : Option<Vec<u8>>,
}

/// PCIe BAR Context: Supplied by LeechCore to the BAR callback function.
/// 
/// Contains the `lc` field which gives access to the general API.
/// 
/// Contains the `ctxlock` field which gives access to the user-defined generic
/// struct set at plugin initialization.
/// 
/// The `ctxlock` field is a `std::sync::RwLock` and the inner user-defined
/// generic struct may be accessed in either multi-threaded read-mode or
/// single-threaded mutable write-mode. Read mode is more efficient.
/// 
/// See the plugin example for additional use cases and documentation.
/// 
/// Only one BAR callback may be active at a given time for a given native
/// LeechCore instance. Previous instances will become inactive if a new
/// one is started. To inactivate a callback drop the context.
/// 
/// 
/// # Created By
/// - `LeechCore::pcie_bar_callback()`
///
pub struct LcBarContext<'a, T> {
    /// Access the general LeechCore API through the `lc` field.
    pub lc     : &'a LeechCore,
    /// Access generic user-set plugin context in a thread-safe way.
    pub ctxlock : std::sync::RwLock<T>,
    fn_callback : fn(ctx : &LcBarContext<T>, req : &LcBarRequest) -> ResultEx<()>,
    native_ctx : usize,
}

/// PCIe BAR wrapper context - returned to the caller of the BAR enable function.
pub struct LcBarContextWrap<'a, T> {
    /// Access to the underlying context.
    pub ctx     : &'a LcBarContext::<'a, T>,
    native      : *mut LcBarContext::<'a, T>,
}

/// PCIe TLP Context: Supplied by LeechCore to the TLP callback function.
/// 
/// Contains the `lc` field which gives access to the general API.
/// 
/// Contains the `ctxlock` field which gives access to the user-defined generic
/// struct set at plugin initialization.
/// 
/// The `ctxlock` field is a `std::sync::RwLock` and the inner user-defined
/// generic struct may be accessed in either multi-threaded read-mode or
/// single-threaded mutable write-mode. Read mode is more efficient.
/// 
/// See the plugin example for additional use cases and documentation.
/// 
/// Only one TLP callback may be active at a given time for a given native
/// LeechCore instance. Previous instances will become inactive if a new
/// one is started. To inactivate a callback drop the context.
/// 
/// 
/// # Created By
/// - `LeechCore::pcie_tlp_callback()`
///
pub struct LcTlpContext<'a, T> {
    /// Access the general LeechCore API through the `lc` field.
    pub lc     : &'a LeechCore,
    /// Access generic user-set plugin context in a thread-safe way.
    pub ctxlock : std::sync::RwLock<T>,
    fn_callback : fn(ctx : &LcTlpContext<T>, tlp : &[u8], tlp_str : &str) -> ResultEx<()>,
    native_ctx : usize,
}

/// PCIe TLP wrapper context - returned to the caller of the TLP enable function.
pub struct LcTlpContextWrap<'a, T> {
    /// Access to the underlying context.
    pub ctx     : &'a LcTlpContext::<'a, T>,
    native      : *mut LcTlpContext::<'a, T>,
}

impl LeechCore {
    /// LeechCore configuration struct version.
    pub const LC_CONFIG_VERSION                         : u32 = 0xc0fd0002;

    /// No printf verbosity.
    pub const LC_CONFIG_PRINTF_NONE                     : u32 = 0x00000000;
    /// Printf verbosity: standard.
    pub const LC_CONFIG_PRINTF_ENABLED                  : u32 = 0x00000001;
    /// Printf verbosity: verbose.
    pub const LC_CONFIG_PRINTF_V                        : u32 = 0x00000002;
    /// Printf verbosity: extra verbose.
    pub const LC_CONFIG_PRINTF_VV                       : u32 = 0x00000004;
    /// Printf verbosity: extra extra verbose (TLP).
    pub const LC_CONFIG_PRINTF_VVV                      : u32 = 0x00000008;

    
    /// LeechCore initialization function.
    /// 
    /// The [`LeechCore`] is the base of the low-level physical memory
    /// aqusition API used by MemProcFS / [`Vmm`]. Normally it is not required
    /// to interact with this low-level library.
    /// 
    /// One may however wish to use specialized functionality such as sending and
    /// receiving raw PCIe TLPs (if the FPGA backend is in use), or to implement a
    /// device PCIe BAR.
    /// 
    /// # Arguments
    /// * `lc_lib_path` - Full path to the native leechcore library - i.e. `leechcore.dll`, `leechcore.dylib` or `leechcore.so`.
    /// * `device_config` - Leechcore device connection string, i.e. `fpga://algo=0`.
    /// * `lc_config_printf_verbosity` - Leechcore printf verbosity level as a combination of `LeechCore::LC_CONFIG_PRINTF_*` values.
    /// 
    /// Information about supported memory acqusition methods may be found on the [LeechCore wiki](https://github.com/ufrisk/LeechCore/wiki).
    /// 
    /// 
    /// # Examples
    /// 
    /// ```
    /// // Initialize a new LeechCore instance using the FPGA memory acqusition method.
    /// let lc = LeechCore::new('C:\\Temp\\MemProcFS\\leechcore.dll', 'fpga://algo=0', LeechCore::LC_CONFIG_PRINTF_ENABLED)?;
    /// ```
    pub fn new(lc_lib_path : &str, device_config : &str, lc_config_printf_verbosity : u32) -> ResultEx<LeechCore> {
        return LeechCore::impl_new(lc_lib_path, device_config, "", lc_config_printf_verbosity, 0);
    }

    /// LeechCore initialization function.
    /// 
    /// The [`LeechCore`] is the base of the low-level physical memory
    /// aqusition API used by MemProcFS / [`Vmm`]. Normally it is not required
    /// to interact with this low-level library.
    /// 
    /// One may however wish to use specialized functionality such as sending and
    /// receiving raw PCIe TLPs (if the FPGA backend is in use), or to implement a
    /// device PCIe BAR.
    /// 
    /// # Arguments
    /// * `lc_lib_path` - Full path to the native leechcore library - i.e. `leechcore.dll`,  `leechcore.dylib` or `leechcore.so`.
    /// * `device_config` - Leechcore device connection string, i.e. `fpga://algo=0`.
    /// * `lc_config_printf_verbosity` - Leechcore printf verbosity level as a combination of `LeechCore::LC_CONFIG_PRINTF_*` values.
    /// * `remote_config` - Leechcore remote connection string, i.e. blank or ``rpc://...` (Windows only).
    /// * `pa_max` - Max physical address to use for memory acquisition.
    /// 
    /// Information about supported memory acqusition methods may be found on the [LeechCore wiki](https://github.com/ufrisk/LeechCore/wiki).
    /// 
    /// 
    /// # Examples
    /// 
    /// ```
    /// // Initialize a new LeechCore instance using the FPGA memory acqusition method.
    /// let lc = LeechCore::new('C:\\Temp\\MemProcFS\\leechcore.dll', 'fpga://algo=0', LeechCore::LC_CONFIG_PRINTF_ENABLED, '', 0x23fffffff)?;
    /// ```
    pub fn new_ex(lc_lib_path : &str, device_config : &str, lc_config_printf_verbosity : u32, remote_config : &str, pa_max : u64) -> ResultEx<LeechCore> {
        return LeechCore::impl_new(lc_lib_path, device_config, remote_config, lc_config_printf_verbosity, pa_max);
    }

    /// LeechCore printf enable [RW].
    pub const LC_OPT_CORE_PRINTF_ENABLE                 : u64 = 0x4000000100000000;
    /// LeechCore verbose level [RW].
    pub const LC_OPT_CORE_VERBOSE                       : u64 = 0x4000000200000000;
    /// LeechCore extra verbose level [RW].
    pub const LC_OPT_CORE_VERBOSE_EXTRA                 : u64 = 0x4000000300000000;
    /// LeechCore extra extra verbose level (TLP) [RW].
    pub const LC_OPT_CORE_VERBOSE_EXTRA_TLP             : u64 = 0x4000000400000000;
    /// LeechCore major version [R].
    pub const LC_OPT_CORE_VERSION_MAJOR                 : u64 = 0x4000000500000000;
    /// LeechCore minor version [R].
    pub const LC_OPT_CORE_VERSION_MINOR                 : u64 = 0x4000000600000000;
    /// LeechCore revision version [R].
    pub const LC_OPT_CORE_VERSION_REVISION              : u64 = 0x4000000700000000;
    /// LeechCore max physical address [R].
    pub const LC_OPT_CORE_ADDR_MAX                      : u64 = 0x1000000800000000;
    /// LeechCore statistics call count [lo-dword: LC_STATISTICS_ID_*] [R].
    pub const LC_OPT_CORE_STATISTICS_CALL_COUNT         : u64 = 0x4000000900000000;
    /// LeechCore statistics call time [lo-dword: LC_STATISTICS_ID_*] [R].
    pub const LC_OPT_CORE_STATISTICS_CALL_TIME          : u64 = 0x4000000a00000000;
    /// LeechCore is memory volatile [R].
    pub const LC_OPT_CORE_VOLATILE                      : u64 = 0x1000000b00000000;
    /// LeechCore is memory readonly [R].
    pub const LC_OPT_CORE_READONLY                      : u64 = 0x1000000c00000000;

    /// LeechCore memory info: is valid [R]
    pub const LC_OPT_MEMORYINFO_VALID                   : u64 = 0x0200000100000000;
    /// LeechCore memory info: is 32-bit OS [R].
    pub const LC_OPT_MEMORYINFO_FLAG_32BIT              : u64 = 0x0200000300000000;
    /// LeechCore memory info: is 32-bit PAE OS [R].
    pub const LC_OPT_MEMORYINFO_FLAG_PAE                : u64 = 0x0200000400000000;
    /// LeechCore memory info: architecture [R].
    pub const LC_OPT_MEMORYINFO_ARCH                    : u64 = 0x0200001200000000;
    /// LeechCore memory info: OS minor version [R].
    pub const LC_OPT_MEMORYINFO_OS_VERSION_MINOR        : u64 = 0x0200000500000000;
    /// LeechCore memory info: OS major version [R].
    pub const LC_OPT_MEMORYINFO_OS_VERSION_MAJOR        : u64 = 0x0200000600000000;
    /// LeechCore memory info: OS directory table base [R].
    pub const LC_OPT_MEMORYINFO_OS_DTB                  : u64 = 0x0200000700000000;
    /// LeechCore memory info: OS PFN database [R].
    pub const LC_OPT_MEMORYINFO_OS_PFN                  : u64 = 0x0200000800000000;
    /// LeechCore memory info: OS PsLoadedModuleList [R].
    pub const LC_OPT_MEMORYINFO_OS_PSLOADEDMODULELIST   : u64 = 0x0200000900000000;
    /// LeechCore memory info: OS PsActiveProcessHead [R].
    pub const LC_OPT_MEMORYINFO_OS_PSACTIVEPROCESSHEAD  : u64 = 0x0200000a00000000;
    /// LeechCore memory info: OS machine image type [R].
    pub const LC_OPT_MEMORYINFO_OS_MACHINE_IMAGE_TP     : u64 = 0x0200000b00000000;
    /// LeechCore memory info: OS number of processors [R].
    pub const LC_OPT_MEMORYINFO_OS_NUM_PROCESSORS       : u64 = 0x0200000c00000000;
    /// LeechCore memory info: OS system time [R].
    pub const LC_OPT_MEMORYINFO_OS_SYSTEMTIME           : u64 = 0x0200000d00000000;
    /// LeechCore memory info: OS uptime [R].
    pub const LC_OPT_MEMORYINFO_OS_UPTIME               : u64 = 0x0200000e00000000;
    /// LeechCore memory info: OS kernel base [R].
    pub const LC_OPT_MEMORYINFO_OS_KERNELBASE           : u64 = 0x0200000f00000000;
    /// LeechCore memory info: OS kernel hint [R].
    pub const LC_OPT_MEMORYINFO_OS_KERNELHINT           : u64 = 0x0200001000000000;
    /// LeechCore memory info: OS KdDebuggerDataBlock [R].
    pub const LC_OPT_MEMORYINFO_OS_KDDEBUGGERDATABLOCK  : u64 = 0x0200001100000000;

    /// LeechCore fpga: probe maximum number of pages [RW].
    pub const LC_OPT_FPGA_PROBE_MAXPAGES                : u64 = 0x0300000100000000;
    /// LeechCore fpga: max rx size [RW].
    pub const LC_OPT_FPGA_MAX_SIZE_RX                   : u64 = 0x0300000300000000;
    /// LeechCore fpga: max tx size [RW].
    pub const LC_OPT_FPGA_MAX_SIZE_TX                   : u64 = 0x0300000400000000;
    /// LeechCore fpga: time delay probe read in uS (algo: 2,3) [RW].
    pub const LC_OPT_FPGA_DELAY_PROBE_READ              : u64 = 0x0300000500000000;
    /// LeechCore fpga: time delay probe write in uS (algo: 2,3) [RW].
    pub const LC_OPT_FPGA_DELAY_PROBE_WRITE             : u64 = 0x0300000600000000;
    /// LeechCore fpga: time delay write in uS (algo: 2,3) [RW].
    pub const LC_OPT_FPGA_DELAY_WRITE                   : u64 = 0x0300000700000000;
    /// LeechCore fpga: time delay read in uS (algo: 2,3) [RW].
    pub const LC_OPT_FPGA_DELAY_READ                    : u64 = 0x0300000800000000;
    /// LeechCore fpga: retry on error [RW].
    pub const LC_OPT_FPGA_RETRY_ON_ERROR                : u64 = 0x0300000900000000;
    /// LeechCore fpga: PCIe device id - bus:dev:fn (ex: 04:00.0 == : u64 = 0x0400) [RW].
    pub const LC_OPT_FPGA_DEVICE_ID                     : u64 = 0x0300008000000000;
    /// LeechCore fpga: FPGA bistream id [R].
    pub const LC_OPT_FPGA_FPGA_ID                       : u64 = 0x0300008100000000;
    /// LeechCore fpga: version major [R].
    pub const LC_OPT_FPGA_VERSION_MAJOR                 : u64 = 0x0300008200000000;
    /// LeechCore fpga: version minor [R].
    pub const LC_OPT_FPGA_VERSION_MINOR                 : u64 = 0x0300008300000000;
    /// LeechCore fpga: 1/0 use tiny 128-byte/tlp read algorithm. [RW].
    pub const LC_OPT_FPGA_ALGO_TINY                     : u64 = 0x0300008400000000;
    /// LeechCore fpga: 1/0 use synchronous (old) read algorithm. [RW].
    pub const LC_OPT_FPGA_ALGO_SYNCHRONOUS              : u64 = 0x0300008500000000;
    /// LeechCore fpga: [lo-dword: register address in bytes] [bytes: 0-3: data, 4-7: byte_enable(if wr/set); top bit = cfg_mgmt_wr_rw1c_as_rw] [RW].
    pub const LC_OPT_FPGA_CFGSPACE_XILINX               : u64 = 0x0300008600000000;
    /// LeechCore fpga: 1/0 call TLP read callback with additional string info in szInfo [RW].
    pub const LC_OPT_FPGA_TLP_READ_CB_WITHINFO          : u64 = 0x0300009000000000;
    /// LeechCore fpga: 1/0 call TLP read callback with memory read completions from read calls filtered [RW].
    pub const LC_OPT_FPGA_TLP_READ_CB_FILTERCPL         : u64 = 0x0300009100000000;

    /// Get a numeric configuration value.
    /// 
    /// # Arguments
    /// * `config_id` - As specified by a `LeechCore::LC_OPT_*` constant marked as Read [R] or Read/Write [RW]. (Optionally or'ed with other data on select options).
    /// 
    /// # Examples
    /// ```
    /// println!("max addr: {:#x}", lc.get_option(LeechCore::LC_OPT_CORE_ADDR_MAX).unwrap_or(0));
    /// ```
    pub fn get_option(&self, config_id : u64) -> ResultEx<u64> {
        return self.impl_get_option(config_id);
    }

    /// Set a numeric configuration value.
    /// 
    /// # Arguments
    /// * `config_id` - As specified by a `LeechCore::LC_OPT_*` constant marked as Write [W] or Read/Write [RW]. (Optionally or'ed with other data on select options).
    /// * `config_value` - The config value to set.
    /// 
    /// # Examples
    /// ```
    /// // The below enables printf outputs from within the LeechCore library.
    /// let _r = lc.set_option(LeechCore::LC_OPT_CORE_PRINTF_ENABLE, 1);
    /// ```
    pub fn set_option(&self, config_id : u64, config_value : u64) -> ResultEx<()> {
        return self.impl_set_option(config_id, config_value);
    }

    /// LeechCore command: FPGA PCIe Config Space [R].
    pub const LC_CMD_FPGA_PCIECFGSPACE                  : u64 = 0x0000010300000000;
    /// LeechCore command: FPGA PCIe register value [lo-dword: register address] [RW].
    pub const LC_CMD_FPGA_CFGREGPCIE                    : u64 = 0x0000010400000000;
    /// LeechCore command: FPGA register cfg [RW].
    pub const LC_CMD_FPGA_CFGREGCFG                     : u64 = 0x0000010500000000;
    /// LeechCore command: FPGA read/write DRP register space [lo-dword: register address] [RW].
    pub const LC_CMD_FPGA_CFGREGDRP                     : u64 = 0x0000010600000000;
    /// LeechCore command: FPGA write with mask [lo-dword: register address] [bytes: 0-1: data, 2-3: mask] [W].
    pub const LC_CMD_FPGA_CFGREGCFG_MARKWR              : u64 = 0x0000010700000000;
    /// LeechCore command: FPGA write with mask [lo-dword: register address] [bytes: 0-1: data, 2-3: mask] [W].
    pub const LC_CMD_FPGA_CFGREGPCIE_MARKWR             : u64 = 0x0000010800000000;
    /// LeechCore command: FPGA probe [RW].
    pub const LC_CMD_FPGA_PROBE                         : u64 = 0x0000010b00000000;
    /// LeechCore command: FPGA read shadow config space[R]. 
    pub const LC_CMD_FPGA_CFGSPACE_SHADOW_RD            : u64 = 0x0000010c00000000;
    /// LeechCore command: FPGA [lo-dword: config space write base address] [W].
    pub const LC_CMD_FPGA_CFGSPACE_SHADOW_WR            : u64 = 0x0000010d00000000;
    /// LeechCore command: FPGA write single tlp BYTE:s [W].
    pub const LC_CMD_FPGA_TLP_WRITE_SINGLE              : u64 = 0x0000011000000000;
    /// LeechCore command: FPGA write multiple LC_TLP:s [W].
    pub const LC_CMD_FPGA_TLP_WRITE_MULTIPLE            : u64 = 0x0000011100000000;
    /// LeechCore command: FPGA convert single TLP to LPSTR; *pcbDataOut includes NULL terminator [RW].
    pub const LC_CMD_FPGA_TLP_TOSTRING                  : u64 = 0x0000011200000000;
    /// LeechCore command: FPGA set/unset TLP user-defined context to be passed to callback function. [not remote] [W].
    pub const LC_CMD_FPGA_TLP_CONTEXT                   : u64 = 0x2000011400000000;
    /// LeechCore command: FPGA get TLP user-defined context to be passed to callback function. [not remote] [R].
    pub const LC_CMD_FPGA_TLP_CONTEXT_RD                : u64 = 0x2000011b00000000;
    /// LeechCore command: FPGA set/unset TLP callback function [not remote] [W].
    pub const LC_CMD_FPGA_TLP_FUNCTION_CALLBACK         : u64 = 0x2000011500000000;
    /// LeechCore command: FPGA get TLP callback function [not remote] [R].
    pub const LC_CMD_FPGA_TLP_FUNCTION_CALLBACK_RD      : u64 = 0x2000011c00000000;
    /// LeechCore command: FPGA set/unset BAR user-defined context to be passed to callback function. [not remote] [W].
    pub const LC_CMD_FPGA_BAR_CONTEXT                   : u64 = 0x2000012000000000;
    /// LeechCore command: FPGA get BAR user-defined context to be passed to callback function [not remote] [R].
    pub const LC_CMD_FPGA_BAR_CONTEXT_RD                : u64 = 0x2000012100000000;
    /// LeechCore command: FPGA set/unset BAR callback function [not remote] [W].
    pub const LC_CMD_FPGA_BAR_FUNCTION_CALLBACK         : u64 = 0x2000012200000000;
    /// LeechCore command: FPGA get BAR callback function [not remote] [R].
    pub const LC_CMD_FPGA_BAR_FUNCTION_CALLBACK_RD      : u64 = 0x2000012300000000;
    /// LeechCore command: FPGA BAR info. (pbDataOut == LC_BAR_INFO[6]) [R].
    pub const LC_CMD_FPGA_BAR_INFO                      : u64 = 0x0000012400000000;
    /// LeechCore command: Get the dump file header [R].
    pub const LC_CMD_FILE_DUMPHEADER_GET                : u64 = 0x0000020100000000;
    /// LeechCore command: Get statistics [R].
    pub const LC_CMD_STATISTICS_GET                     : u64 = 0x4000010000000000;
    /// LeechCore command: Get memmap as string [R].
    pub const LC_CMD_MEMMAP_GET                         : u64 = 0x4000020000000000;
    /// LeechCore command: Set memmap as string [W].
    pub const LC_CMD_MEMMAP_SET                         : u64 = 0x4000030000000000;
    /// LeechCore command: Get memmap as C-struct [R].
    pub const LC_CMD_MEMMAP_GET_STRUCT                  : u64 = 0x4000040000000000;
    /// LeechCore command: Set memmap as C-struct [W].
    pub const LC_CMD_MEMMAP_SET_STRUCT                  : u64 = 0x4000050000000000;

    /// Execute a command using the LcCommand interface.
    /// 
    /// # Arguments
    /// * `command_id` - The command id to execute.
    /// * `data` - Optional data to send with the command.
    /// 
    /// # Examples
    /// ```
    /// // Get the LeechCore memory map:
    /// let memmap = lc.command(LeechCore::LC_CMD_MEMMAP_GET, None)?.to_string();
    /// ```
    pub fn command(&self, command_id : u64, data : Option<&Vec<u8>>) -> ResultEx<Option<Vec<u8>>> {
        return self.impl_command(command_id, data);
    }

    /// Read a contigious physical memory chunk.
    /// 
    /// The whole chunk must be read successfully for the method to succeed.
    /// 
    /// 
    /// # Arguments
    /// * `pa` - Physical address to start reading from.
    /// * `size` - Number of bytes to read.
    /// 
    /// # Examples
    /// ```
    /// // Read 0x100 bytes of data starting at address 0x1000.
    /// // Example assumes: use pretty_hex::*;
    /// let data_read = lc.mem_read(0x1000, 0x100)?;
    /// println!("{:?}", data_read.hex_dump());
    /// ```
    pub fn mem_read(&self, pa : u64, size : usize) -> ResultEx<Vec<u8>> {
        return self.impl_mem_read(pa, size);
    }

    /// Read a contigious physical memory chunk with flags as a type/struct.
    /// 
    /// 
    /// # Arguments
    /// * `pa` - Physical address to start reading from.
    /// 
    /// # Examples
    /// ```
    /// // Read the C-struct IMAGE_DOS_HEADER from memory.
    /// #[repr(C)]
    /// struct IMAGE_DOS_HEADER {
    ///     e_magic : u16,
    /// 	...
    ///     e_lfanew : u32,
    /// }
    /// if let Ok(doshdr) = lc.mem_read_as::<IMAGE_DOS_HEADER>(pa_module) {
    ///     println!("e_magic:  {:x}", doshdr.e_magic);
    ///     println!("e_lfanew: {:x}", doshdr.e_lfanew);
    /// }
    /// ```
    pub fn mem_read_as<T>(&self, pa : u64) -> ResultEx<T> {
        return self.impl_mem_read_as(pa);
    }

    /// Write physical memory.
    /// 
    /// The write is a best effort. Even of the write should fail it's not
    /// certain that an error will be returned. To be absolutely certain that
    /// a write has taken place follow up with a read.
    /// 
    /// # Arguments
    /// * `pa` - Physical address to start writing from.
    /// * `data` - Byte data to write.
    /// 
    /// # Examples
    /// ```
    /// let data_to_write = [0x56u8, 0x4d, 0x4d, 0x52, 0x55, 0x53, 0x54].to_vec();
    /// let _r = lc.mem_write(0x1000, &data_to_write);
    /// ```
    pub fn mem_write(&self, pa : u64, data : &Vec<u8>) -> ResultEx<()> {
        return self.impl_mem_write(pa, data);
    }

    /// Write a type/struct to physical memory.
    /// 
    /// The write is a best effort. Even of the write should fail it's not
    /// certain that an error will be returned. To be absolutely certain that
    /// a write has taken place follow up with a read.
    /// 
    /// # Arguments
    /// * `pa` - Physical address to start writing from.
    /// * `data` - Data to write. In case of a struct repr(C) is recommended.
    /// 
    /// # Examples
    /// ```
    /// let data_to_write = [0x56, 0x4d, 0x4d, 0x52, 0x55, 0x53, 0x54];
    /// let _r = lc.mem_write_as(0x1000, &data_to_write);
    /// ```
    pub fn mem_write_as<T>(&self, pa : u64, data : &T) -> ResultEx<()> {
        return self.impl_mem_write_as(pa, data);
    }

    /// Retrieve the memory map currently in-use.
    /// 
    /// For more information about memory maps see the [LeechCore wiki](https://github.com/ufrisk/LeechCore/wiki/Device_FPGA_AMD_Thunderbolt).
    /// 
    /// # Examples
    /// ```
    /// let memmap = lc.get_memmap()?;
    /// println!("{}", memmap);
    /// ```
    pub fn get_memmap(&self) -> ResultEx<String> {
        return self.impl_get_memmap();
    }

    /// Set/Update the memory map currently in-use.
    /// 
    /// For more information about memory maps see the [LeechCore wiki](https://github.com/ufrisk/LeechCore/wiki/Device_FPGA_AMD_Thunderbolt).
    /// 
    /// # Arguments
    /// * `str_memmap` - The str containing the new memory map to use.
    /// 
    /// # Examples
    /// ```
    /// let _r = lc.set_memmap(memmap.as_str())?;
    /// ```
    pub fn set_memmap(&self, str_memmap : &str) -> ResultEx<()> {
        return self.impl_set_memmap(str_memmap);
    }

    /// PCIe only function: Get the BARs of the PCIe device.
    /// 
    /// # Examples
    /// ```
    /// let bars = lc.pcie_bar_info()?;
    /// ```
    pub fn pcie_bar_info(&self) -> ResultEx<[LcBar; 6]> {
        return self.impl_pcie_bar_info();
    }

    /// PCIe only function: Start a PCIe BAR callback.
    /// 
    /// # Arguments
    /// * `ctx` - User defined context to be passed to the callback function.
    /// * `fn_bar_callback` - The callback function to call when a BAR is accessed.
    ///
    /// See [`LcBarContext`] for more information.
    /// 
    /// Only one PCIe BAR callback may be active at a time.
    pub fn pcie_bar_callback<T>(&self, ctx : T, fn_bar_callback : fn(ctx : &LcBarContext<T>, req : &LcBarRequest) -> ResultEx<()>) -> ResultEx<LcBarContextWrap<T>> {
        return self.impl_pcie_bar_callback(ctx, fn_bar_callback);
    }

    /// PCIe only function: Start a PCIe TLP callback.
    /// 
    /// # Arguments
    /// * `ctx` - User defined context to be passed to the callback function.
    /// * `fn_tlp_callback` - The callback function to call when a TLP is received.
    /// 
    /// See [`LcTlpContext`] for more information.
    /// 
    /// Only one PCIe TLP callback may be active at a time.
    pub fn pcie_tlp_callback<T>(&self, ctx : T, fn_tlp_callback : fn(ctx : &LcTlpContext<T>, tlp : &[u8], tlp_str : &str) -> ResultEx<()>) -> ResultEx<LcTlpContextWrap<T>> {
        return self.impl_pcie_tlp_callback(ctx, fn_tlp_callback);
    }

    /// PCIe only function: Write a PCIe TLP.
    /// 
    /// # Arguments
    /// * `tlp` - The TLP to write.
    pub fn pcie_tlp_write(&self, tlp : &[u8]) -> ResultEx<()> {
        return self.impl_pcie_tlp_write(tlp);
    }
}

impl LcBarRequest {
    /// Send a valid read reply to the BAR request.
    /// 
    /// The read reply must be of the exact length of the BAR read request.
    /// 
    /// # Arguments
    /// * `data_reply` - The data to send as a reply.
    pub fn read_reply(&self, data_reply : &[u8]) -> ResultEx<()> {
        return self.impl_read_reply(data_reply, false);
    }

    /// Send an invalid read reply to the BAR request indicating that the read
    /// failed. An Unsupported Request TLP will be sent to the host system in
    /// reponse to the failed read.
    /// 
    /// This function should normally not be called.
    pub fn read_reply_fail(&self) -> ResultEx<()> {
        let data = [0u8; 0];
        return self.impl_read_reply(&data, true);
    }
}












//=============================================================================
// INTERNAL: VMM CORE:
//=============================================================================

#[allow(dead_code)]
#[allow(non_snake_case)]
#[derive(Debug)]
struct VmmNative {
    h : usize,
    is_close_h : bool,
    library_lc : Option<libloading::Library>,
    library_vmm : Option<libloading::Library>,
    VMMDLL_Initialize :             extern "C" fn(argc: c_int, argv: *const *const c_char) -> usize,
    VMMDLL_InitializePlugins :      extern "C" fn(hVMM : usize) -> bool,
    VMMDLL_Close :                  extern "C" fn(hVMM : usize),
    VMMDLL_ConfigGet :              extern "C" fn(hVMM : usize, fOption : u64, pqwValue : *mut u64) -> bool,
    VMMDLL_ConfigSet :              extern "C" fn(hVMM : usize, fOption : u64, qwValue : u64) -> bool,
    VMMDLL_MemFree :                extern "C" fn(pvMem : usize),
    
    VMMDLL_Log :                    extern "C" fn(hVMM : usize, MID : u32, dwLogLevel : u32, uszFormat : *const c_char, uszParam : *const c_char),
    VMMDLL_MemSearch :              extern "C" fn(hVMM : usize, pid : u32, ctx : *mut CVMMDLL_MEM_SEARCH_CONTEXT, ppva : *mut u64, pcva : *mut u32) -> bool,
    VMMDLL_YaraSearch :             extern "C" fn(hVMM : usize, pid : u32, ctx : *mut CVMMDLL_YARA_CONFIG, ppva : *mut u64, pcva : *mut u32) -> bool,

    VMMDLL_MemReadEx :              extern "C" fn(hVMM : usize, pid : u32, qwA : u64, pb : *mut u8, cb : u32, pcbReadOpt : *mut u32, flags : u64) -> bool,
    VMMDLL_MemWrite :               extern "C" fn(hVMM : usize, pid : u32, qwA : u64, pb : *const u8, cb : u32) -> bool,
    VMMDLL_MemVirt2Phys :           extern "C" fn(hVMM : usize, pid : u32, qwA : u64, pqwPA : *mut u64) -> bool,

    VMMDLL_Scatter_Initialize :     extern "C" fn(hVMM : usize, pid : u32, flags : u32) -> usize,
    VMMDLL_Scatter_Prepare :        extern "C" fn(hS : usize, va : u64, cb : u32) -> bool,
    VMMDLL_Scatter_PrepareEx :      extern "C" fn(hS : usize, va : u64, cb : u32, pb : *mut u8, pcbRead : *mut u32) -> bool,
    VMMDLL_Scatter_PrepareWrite :   extern "C" fn(hS : usize, va : u64, pb : *const u8, cb : u32) -> bool,
    VMMDLL_Scatter_Execute :        extern "C" fn(hS : usize) -> bool,
    VMMDLL_Scatter_Read :           extern "C" fn(hS : usize, va : u64, cb : u32, pb : *mut u8, pcbRead : *mut u32) -> bool,
    VMMDLL_Scatter_Clear :          extern "C" fn(hS : usize, pid : u32, flags : u32) -> bool,
    VMMDLL_Scatter_CloseHandle :    extern "C" fn(hS : usize),

    VMMDLL_PidGetFromName :         extern "C" fn(hVMM : usize, szProcName : *const c_char, pdwPID : *mut u32) -> bool,
    VMMDLL_PidList :                extern "C" fn(hVMM : usize, pPIDs : *mut u32, pcPIDs : *mut usize) -> bool,

    VMMDLL_WinReg_HiveList :        extern "C" fn(hVMM : usize, pHives : *mut CRegHive, cHives : u32, pcHives : *mut u32) -> bool,
    VMMDLL_WinReg_HiveReadEx :      extern "C" fn(hVMM : usize, vaCMHive : u64, ra : u32, pb : *mut u8, cb : u32, pcbReadOpt : *mut u32, flags : u64) -> bool,
    VMMDLL_WinReg_HiveWrite :       extern "C" fn(hVMM : usize, vaCMHive : u64, ra : u32, pb : *const u8, cb : u32) -> bool,
    VMMDLL_WinReg_EnumKeyExU :      extern "C" fn(hVMM : usize, uszFullPathKey : *const c_char, dwIndex : u32, lpcchName : *mut c_char, lpcchName : *mut u32, lpftLastWriteTime : *mut u64) -> bool,
    VMMDLL_WinReg_EnumValueU :      extern "C" fn(hVMM : usize, uszFullPathKey : *const c_char, dwIndex : u32, lpValueName : *mut c_char, lpcchValueName : *mut u32, lpType : *mut u32, lpcbData : *mut u32) -> bool,
    VMMDLL_WinReg_QueryValueExU :   extern "C" fn(hVMM : usize, uszFullPathKeyValue : *const c_char, lpType : *mut u32, lpData : *mut u8, lpcbData : *mut u32) -> bool,

    VMMDLL_ProcessGetModuleBaseU :  extern "C" fn(hVMM : usize, pid : u32, uszModuleName : *const c_char) -> u64,
    VMMDLL_ProcessGetProcAddressU : extern "C" fn(hVMM : usize, pid : u32, uszModuleName : *const c_char, szFunctionName : *const c_char) -> u64,
    VMMDLL_ProcessGetInformation :  extern "C" fn(hVMM : usize, pid : u32, pProcessInformation : *mut CProcessInformation, pcbProcessInformation : *mut usize) -> bool,
    VMMDLL_ProcessGetInformationString : extern "C" fn(hVMM : usize, pid : u32, fOptionString : u32) -> *const c_char,

    VMMDLL_Map_GetKDeviceU :        extern "C" fn(hVMM : usize, ppPoolMap : *mut *mut CKDeviceMap) -> bool,
    VMMDLL_Map_GetKDriverU :        extern "C" fn(hVMM : usize, ppPoolMap : *mut *mut CKDriverMap) -> bool,
    VMMDLL_Map_GetKObjectU :        extern "C" fn(hVMM : usize, ppPoolMap : *mut *mut CKObjectMap) -> bool,
    VMMDLL_Map_GetNetU :            extern "C" fn(hVMM : usize, ppNetMap : *mut *mut CNetMap) -> bool,
    VMMDLL_Map_GetPfnEx :           extern "C" fn(hVMM : usize, pPfns : *const u32, cPfns : u32, ppPfnMap : *mut *mut CPfnMap, flags : u32) -> bool,
    VMMDLL_Map_GetPhysMem :         extern "C" fn(hVMM : usize, ppPhysMemMap : *mut *mut CMemoryMap) -> bool,
    VMMDLL_Map_GetPool :            extern "C" fn(hVMM : usize, ppPoolMap : *mut *mut CPoolMap, flags : u32) -> bool,
    VMMDLL_Map_GetServicesU :       extern "C" fn(hVMM : usize, ppServiceMap : *mut *mut CServiceMap) -> bool,
    VMMDLL_Map_GetUsersU :          extern "C" fn(hVMM : usize, ppUserMap : *mut *mut CUserMap) -> bool,
    VMMDLL_Map_GetVMU :             extern "C" fn(hVMM : usize, ppVmMap : *mut *mut CVmMap) -> bool,

    VMMDLL_PdbLoad :                extern "C" fn(hVMM : usize, dwPID : u32, vaModuleBase : u64, szModuleName : *mut c_char) -> bool,
    VMMDLL_PdbSymbolName :          extern "C" fn(hVMM : usize, szModule : *const c_char, cbSymbolAddressOrOffset : u64, szSymbolName : *mut c_char, pdwSymbolDisplacement : *mut u32) -> bool,
    VMMDLL_PdbSymbolAddress :       extern "C" fn(hVMM : usize, szModule : *const c_char, szSymbolName : *const c_char, pvaSymbolAddress : *mut u64) -> bool,
    VMMDLL_PdbTypeSize :            extern "C" fn(hVMM : usize, szModule : *const c_char, szTypeName : *const c_char, pcbTypeSize : *mut u32) -> bool,
    VMMDLL_PdbTypeChildOffset :     extern "C" fn(hVMM : usize, szModule : *const c_char, uszTypeName : *const c_char, uszTypeChildName : *const c_char, pcbTypeChildOffset : *mut u32) -> bool,

    VMMDLL_Map_GetEATU :            extern "C" fn(hVMM : usize, pid : u32, uszModuleName : *const c_char, ppEatMap : *mut *mut CEatMap) -> bool,
    VMMDLL_Map_GetHandleU :         extern "C" fn(hVMM : usize, pid : u32, ppHandleMap : *mut *mut CHandleMap) -> bool,
    VMMDLL_Map_GetHeap :            extern "C" fn(hVMM : usize, pid : u32, ppHeapMap : *mut *mut CHeapMap) -> bool,
    VMMDLL_Map_GetHeapAlloc :       extern "C" fn(hVMM : usize, pid : u32, qwHeapNumOrAddress : u64, ppHeapAllocMap : *mut *mut CHeapAllocMap) -> bool,
    VMMDLL_Map_GetIATU :            extern "C" fn(hVMM : usize, pid : u32, uszModuleName : *const c_char, ppIatMap : *mut *mut CIatMap) -> bool,
    VMMDLL_Map_GetModuleU :         extern "C" fn(hVMM : usize, pid : u32, ppModuleMap : *mut *mut CModuleMap, flags : u32) -> bool,
    VMMDLL_Map_GetPteU :            extern "C" fn(hVMM : usize, pid : u32, fIdentifyModules : bool, ppPteMap : *mut *mut CPteMap) -> bool,
    VMMDLL_Map_GetThread :          extern "C" fn(hVMM : usize, pid : u32, ppThreadMap : *mut *mut CThreadMap) -> bool,
    VMMDLL_Map_GetThreadCallstackU: extern "C" fn(hVMM : usize, pid : u32, tid : u32, flags : u32, ppThreadCallstack : *mut *mut CThreadCallstackMap) -> bool,
    VMMDLL_Map_GetUnloadedModuleU : extern "C" fn(hVMM : usize, pid : u32, ppUnloadedModuleMap : *mut *mut CUnloadedModuleMap) -> bool,
    VMMDLL_Map_GetVadU :            extern "C" fn(hVMM : usize, pid : u32, fIdentifyModules : bool, ppVadMap : *mut *mut CVadMap) -> bool,
    VMMDLL_Map_GetVadEx :           extern "C" fn(hVMM : usize, pid : u32, oPage : u32, cPage : u32, ppVadExMap : *mut *mut CVadExMap) -> bool,
    VMMDLL_ProcessGetDirectoriesU : extern "C" fn(hVMM : usize, pid : u32, uszModule : *const c_char, pDataDirectories : *mut CIMAGE_DATA_DIRECTORY) -> bool,
    VMMDLL_ProcessGetSectionsU :    extern "C" fn(hVMM : usize, pid : u32, uszModule : *const c_char, pSections : *mut CIMAGE_SECTION_HEADER, cSections : u32, pcSections : *mut u32) -> bool,

    VMMDLL_VfsListU :               extern "C" fn(hVMM : usize, uszPath : *const c_char, pFileList : *mut CVMMDLL_VFS_FILELIST2) -> bool,
    VMMDLL_VfsReadU :               extern "C" fn(hVMM : usize, uszFileName : *const c_char, pb : *mut u8, cb : u32, pcbRead : *mut u32, cbOffset : u64) -> u32,
    VMMDLL_VfsWriteU :              extern "C" fn(hVMM : usize, uszFileName : *const c_char, pb : *const u8, cb : u32, pcbWrite : *mut u32, cbOffset : u64) -> u32,

    VMMDLL_VmGetVmmHandle :         extern "C" fn(hVMM : usize, hVM : usize) -> usize,

    // Plugin related info below:
    VMMDLL_VfsList_AddFile :        extern "C" fn(pFileList : usize, uszName : *const c_char, cb : u64, pExInfo : usize),
    VMMDLL_VfsList_AddDirectory :   extern "C" fn(pFileList : usize, uszName : *const c_char, pExInfo : usize),
}

#[allow(non_snake_case)]
fn impl_new<'a>(vmm_lib_path : &str, lc_existing_opt : Option<&LeechCore>, h_vmm_existing_opt : usize, args: &Vec<&str>) -> ResultEx<Vmm<'a>> {
    unsafe {
        // load MemProcFS native library (vmm.dll / vmm.so):
        // vmm is however dependant on leechcore which must be loaded first...
        let path_vmm = std::path::Path::new(vmm_lib_path).canonicalize()?;
        let mut path_lc = path_vmm.parent().unwrap().canonicalize()?;
        if cfg!(windows) {
            path_lc = path_lc.join("leechcore.dll");
        } else if cfg!(target_os = "macos") {
            path_lc = path_lc.join("leechcore.dylib");
        } else {
            path_lc = path_lc.join("leechcore.so");
        }
        let str_path_lc = path_lc.to_str().unwrap_or("");
        let str_path_vmm = path_vmm.to_str().unwrap_or("");
        let lib_lc : libloading::Library = libloading::Library::new(str_path_lc)
            .with_context(|| format!("Failed to load leechcore library at: {}", str_path_lc))?;
        let lib : libloading::Library = libloading::Library::new(str_path_vmm)
            .with_context(|| format!("Failed to load vmm library at: {}", str_path_vmm))?;
        // fetch function references:
        let VMMDLL_Initialize : extern "C" fn(argc: c_int, argv: *const *const c_char) -> usize = *lib.get(b"VMMDLL_Initialize")?;
        let VMMDLL_InitializePlugins : extern "C" fn(usize) -> bool = *lib.get(b"VMMDLL_InitializePlugins")?;
        let VMMDLL_Close = *lib.get(b"VMMDLL_Close")?;
        let VMMDLL_ConfigGet = *lib.get(b"VMMDLL_ConfigGet")?;
        let VMMDLL_ConfigSet = *lib.get(b"VMMDLL_ConfigSet")?;
        let VMMDLL_MemFree = *lib.get(b"VMMDLL_MemFree")?;
        let VMMDLL_Log = *lib.get(b"VMMDLL_Log")?;
        let VMMDLL_MemSearch = *lib.get(b"VMMDLL_MemSearch")?;
        let VMMDLL_YaraSearch = *lib.get(b"VMMDLL_YaraSearch")?;
        let VMMDLL_MemReadEx = *lib.get(b"VMMDLL_MemReadEx")?;
        let VMMDLL_MemWrite = *lib.get(b"VMMDLL_MemWrite")?;
        let VMMDLL_MemVirt2Phys = *lib.get(b"VMMDLL_MemVirt2Phys")?;
        let VMMDLL_Scatter_Initialize = *lib.get(b"VMMDLL_Scatter_Initialize")?;
        let VMMDLL_Scatter_Prepare = *lib.get(b"VMMDLL_Scatter_Prepare")?;
        let VMMDLL_Scatter_PrepareEx = *lib.get(b"VMMDLL_Scatter_PrepareEx")?;
        let VMMDLL_Scatter_PrepareWrite = *lib.get(b"VMMDLL_Scatter_PrepareWrite")?;
        let VMMDLL_Scatter_Execute = *lib.get(b"VMMDLL_Scatter_Execute")?;
        let VMMDLL_Scatter_Read = *lib.get(b"VMMDLL_Scatter_Read")?;
        let VMMDLL_Scatter_Clear = *lib.get(b"VMMDLL_Scatter_Clear")?;
        let VMMDLL_Scatter_CloseHandle = *lib.get(b"VMMDLL_Scatter_CloseHandle")?;
        let VMMDLL_PidGetFromName = *lib.get(b"VMMDLL_PidGetFromName")?;
        let VMMDLL_PidList = *lib.get(b"VMMDLL_PidList")?;
        let VMMDLL_WinReg_HiveList = *lib.get(b"VMMDLL_WinReg_HiveList")?;
        let VMMDLL_WinReg_HiveReadEx = *lib.get(b"VMMDLL_WinReg_HiveReadEx")?;
        let VMMDLL_WinReg_HiveWrite = *lib.get(b"VMMDLL_WinReg_HiveWrite")?;
        let VMMDLL_WinReg_EnumKeyExU = *lib.get(b"VMMDLL_WinReg_EnumKeyExU")?;
        let VMMDLL_WinReg_EnumValueU = *lib.get(b"VMMDLL_WinReg_EnumValueU")?;
        let VMMDLL_WinReg_QueryValueExU = *lib.get(b"VMMDLL_WinReg_QueryValueExU")?;
        let VMMDLL_ProcessGetModuleBaseU = *lib.get(b"VMMDLL_ProcessGetModuleBaseU")?;
        let VMMDLL_ProcessGetProcAddressU = *lib.get(b"VMMDLL_ProcessGetProcAddressU")?;
        let VMMDLL_ProcessGetInformation = *lib.get(b"VMMDLL_ProcessGetInformation")?;
        let VMMDLL_ProcessGetInformationString = *lib.get(b"VMMDLL_ProcessGetInformationString")?;
        let VMMDLL_Map_GetKDeviceU = *lib.get(b"VMMDLL_Map_GetKDeviceU")?;
        let VMMDLL_Map_GetKDriverU = *lib.get(b"VMMDLL_Map_GetKDriverU")?;
        let VMMDLL_Map_GetKObjectU = *lib.get(b"VMMDLL_Map_GetKObjectU")?;
        let VMMDLL_Map_GetNetU = *lib.get(b"VMMDLL_Map_GetNetU")?;
        let VMMDLL_Map_GetPfnEx = *lib.get(b"VMMDLL_Map_GetPfnEx")?;
        let VMMDLL_Map_GetPhysMem = *lib.get(b"VMMDLL_Map_GetPhysMem")?;
        let VMMDLL_Map_GetPool = *lib.get(b"VMMDLL_Map_GetPool")?;
        let VMMDLL_Map_GetUsersU = *lib.get(b"VMMDLL_Map_GetUsersU")?;
        let VMMDLL_Map_GetServicesU = *lib.get(b"VMMDLL_Map_GetServicesU")?;
        let VMMDLL_Map_GetVMU = *lib.get(b"VMMDLL_Map_GetVMU")?;
        let VMMDLL_PdbLoad = *lib.get(b"VMMDLL_PdbLoad")?;
        let VMMDLL_PdbSymbolName = *lib.get(b"VMMDLL_PdbSymbolName")?;
        let VMMDLL_PdbSymbolAddress = *lib.get(b"VMMDLL_PdbSymbolAddress")?;
        let VMMDLL_PdbTypeSize = *lib.get(b"VMMDLL_PdbTypeSize")?;
        let VMMDLL_PdbTypeChildOffset = *lib.get(b"VMMDLL_PdbTypeChildOffset")?;
        let VMMDLL_Map_GetEATU = *lib.get(b"VMMDLL_Map_GetEATU")?;
        let VMMDLL_Map_GetHandleU = *lib.get(b"VMMDLL_Map_GetHandleU")?;
        let VMMDLL_Map_GetHeap = *lib.get(b"VMMDLL_Map_GetHeap")?;
        let VMMDLL_Map_GetHeapAlloc = *lib.get(b"VMMDLL_Map_GetHeapAlloc")?;
        let VMMDLL_Map_GetIATU = *lib.get(b"VMMDLL_Map_GetIATU")?;
        let VMMDLL_Map_GetModuleU = *lib.get(b"VMMDLL_Map_GetModuleU")?;
        let VMMDLL_Map_GetPteU = *lib.get(b"VMMDLL_Map_GetPteU")?;
        let VMMDLL_Map_GetThread = *lib.get(b"VMMDLL_Map_GetThread")?;
        let VMMDLL_Map_GetThreadCallstackU = *lib.get(b"VMMDLL_Map_GetThread_CallstackU")?;
        let VMMDLL_Map_GetUnloadedModuleU = *lib.get(b"VMMDLL_Map_GetUnloadedModuleU")?;
        let VMMDLL_Map_GetVadU = *lib.get(b"VMMDLL_Map_GetVadU")?;
        let VMMDLL_Map_GetVadEx = *lib.get(b"VMMDLL_Map_GetVadEx")?;
        let VMMDLL_ProcessGetDirectoriesU = *lib.get(b"VMMDLL_ProcessGetDirectoriesU")?;
        let VMMDLL_ProcessGetSectionsU = *lib.get(b"VMMDLL_ProcessGetSectionsU")?;
        let VMMDLL_VfsListU = *lib.get(b"VMMDLL_VfsListU")?;
        let VMMDLL_VfsReadU = *lib.get(b"VMMDLL_VfsReadU")?;
        let VMMDLL_VfsWriteU = *lib.get(b"VMMDLL_VfsWriteU")?;
        let VMMDLL_VmGetVmmHandle = *lib.get(b"VMMDLL_VmGetVmmHandle")?;
        let VMMDLL_VfsList_AddFile = *lib.get(b"VMMDLL_VfsList_AddFile")?;
        let VMMDLL_VfsList_AddDirectory = *lib.get(b"VMMDLL_VfsList_AddDirectory")?;
        // initialize MemProcFS
        let h;
        if h_vmm_existing_opt != 0 {
            h = h_vmm_existing_opt;
        } else {
            let mut args = args.clone();
            let lc_existing_device : String;
            if let Some(lc_existing) = lc_existing_opt {
                lc_existing_device = format!("existing://0x{:x}", lc_existing.native.h);
                args.push("-device");
                args.push(lc_existing_device.as_str());
            }
            let args = args.iter().map(|arg| CString::new(*arg).unwrap()).collect::<Vec<CString>>();
            let argv: Vec<*const c_char> = args.iter().map(|s| s.as_ptr()).collect();
            let argc: c_int = args.len() as c_int;
            h = (VMMDLL_Initialize)(argc, argv.as_ptr());
            if h == 0 {
                return Err(anyhow!("VMMDLL_Initialize: fail"));
            }
            let r = (VMMDLL_InitializePlugins)(h);
            if !r {
                return Err(anyhow!("VMMDLL_InitializePlugins: fail"));
            }
        }
        // return Vmm struct:
        let native = VmmNative {
            h,
            is_close_h : h_vmm_existing_opt == 0,
            library_lc : Some(lib_lc),
            library_vmm : Some(lib),
            VMMDLL_Initialize,
            VMMDLL_InitializePlugins,
            VMMDLL_Close,
            VMMDLL_ConfigGet,
            VMMDLL_ConfigSet,
            VMMDLL_MemFree,
            VMMDLL_Log,
            VMMDLL_MemSearch,
            VMMDLL_YaraSearch,
            VMMDLL_MemReadEx,
            VMMDLL_MemWrite,
            VMMDLL_MemVirt2Phys,
            VMMDLL_Scatter_Initialize,
            VMMDLL_Scatter_Prepare,
            VMMDLL_Scatter_PrepareEx,
            VMMDLL_Scatter_PrepareWrite,
            VMMDLL_Scatter_Execute,
            VMMDLL_Scatter_Read,
            VMMDLL_Scatter_Clear,
            VMMDLL_Scatter_CloseHandle,
            VMMDLL_PidGetFromName,
            VMMDLL_PidList,
            VMMDLL_WinReg_HiveList,
            VMMDLL_WinReg_HiveReadEx,
            VMMDLL_WinReg_HiveWrite,
            VMMDLL_WinReg_EnumKeyExU,
            VMMDLL_WinReg_EnumValueU,
            VMMDLL_WinReg_QueryValueExU,
            VMMDLL_ProcessGetModuleBaseU,
            VMMDLL_ProcessGetProcAddressU,
            VMMDLL_ProcessGetInformation,
            VMMDLL_ProcessGetInformationString,
            VMMDLL_Map_GetKDeviceU,
            VMMDLL_Map_GetKDriverU,
            VMMDLL_Map_GetKObjectU,
            VMMDLL_Map_GetNetU,
            VMMDLL_Map_GetPfnEx,
            VMMDLL_Map_GetPhysMem,
            VMMDLL_Map_GetPool,
            VMMDLL_Map_GetUsersU,
            VMMDLL_Map_GetServicesU,
            VMMDLL_Map_GetVMU,
            VMMDLL_PdbLoad,
            VMMDLL_PdbSymbolName,
            VMMDLL_PdbSymbolAddress,
            VMMDLL_PdbTypeSize,
            VMMDLL_PdbTypeChildOffset,
            VMMDLL_Map_GetEATU,
            VMMDLL_Map_GetHandleU,
            VMMDLL_Map_GetHeap,
            VMMDLL_Map_GetHeapAlloc,
            VMMDLL_Map_GetIATU,
            VMMDLL_Map_GetModuleU,
            VMMDLL_Map_GetPteU,
            VMMDLL_Map_GetThread,
            VMMDLL_Map_GetThreadCallstackU,
            VMMDLL_Map_GetUnloadedModuleU,
            VMMDLL_Map_GetVadU,
            VMMDLL_Map_GetVadEx,
            VMMDLL_ProcessGetDirectoriesU,
            VMMDLL_ProcessGetSectionsU,
            VMMDLL_VfsListU,
            VMMDLL_VfsReadU,
            VMMDLL_VfsWriteU,
            VMMDLL_VmGetVmmHandle,
            VMMDLL_VfsList_AddFile,
            VMMDLL_VfsList_AddDirectory,
        };
        let vmm = Vmm {
            path_lc : str_path_lc.to_string(),
            path_vmm : str_path_vmm.to_string(),
            native,
            parent_vmm : None,
        };
        return Ok(vmm);
    }
}

fn impl_new_from_leechcore<'a>(leechcore_existing : &LeechCore, args: &Vec<&str>) -> ResultEx<Vmm<'a>> {
    // vmm path is assumed to be the same as leechcore path
    let path_vmm = std::path::Path::new(leechcore_existing.path_lc.as_str()).canonicalize()?;
    let mut path_vmm = path_vmm.parent().unwrap().canonicalize()?;
    if cfg!(windows) {
        path_vmm = path_vmm.join("vmm.dll");
    } else if cfg!(target_os = "macos") {
        path_vmm = path_vmm.join("vmm.dylib");
    } else {
        path_vmm = path_vmm.join("vmm.so");
    }
    let str_path_vmm = path_vmm.to_str().unwrap_or("");
    return crate::impl_new(str_path_vmm, Some(leechcore_existing), 0, args)
}

#[allow(non_snake_case)]
fn impl_new_from_virtual_machine<'a>(vmm_parent : &'a Vmm, vm_entry : &VmmMapVirtualMachineEntry) -> ResultEx<Vmm<'a>> {
    if vmm_parent.native.h != vm_entry.h_vmm {
        return Err(anyhow!("Invalid parent/vm relationship."));
    }
    let h_vmm_vm = (vmm_parent.native.VMMDLL_VmGetVmmHandle)(vmm_parent.native.h, vm_entry.h_vm);
    if h_vmm_vm == 0 {
        return Err(anyhow!("VMMDLL_VmGetVmmHandle: fail."));
    }
    let native = VmmNative {
        h: vmm_parent.native.h,
        library_lc : None,
        library_vmm : None,
        ..vmm_parent.native
    };
    let vmm = Vmm {
        path_lc : vmm_parent.path_lc.clone(),
        path_vmm : vmm_parent.path_vmm.clone(),
        native : native,
        parent_vmm : Some(vmm_parent),
    };
    return Ok(vmm);
}






//=============================================================================
// INTERNAL: VMM:
//=============================================================================

const MAX_PATH                          : usize = 260;
const VMMDLL_MEM_SEARCH_VERSION         : u32 = 0xfe3e0003;
const VMMDLL_YARA_CONFIG_VERSION        : u32 = 0xdec30001;
const VMMYARA_RULE_MATCH_VERSION        : u32 = 0xfedc0005;
const VMMYARA_RULE_MATCH_TAG_MAX        : usize = 27;
const VMMYARA_RULE_MATCH_META_MAX       : usize = 32;
const VMMYARA_RULE_MATCH_STRING_MAX     : usize = 16;
const VMMYARA_RULE_MATCH_OFFSET_MAX     : usize = 24;

const VMMDLL_VFS_FILELIST_VERSION       : u32 = 2;

const VMMDLL_MAP_EAT_VERSION            : u32 = 3;
const VMMDLL_MAP_HANDLE_VERSION         : u32 = 3;
const VMMDLL_MAP_HEAP_VERSION           : u32 = 4;
const VMMDLL_MAP_HEAPALLOC_VERSION      : u32 = 1;
const VMMDLL_MAP_IAT_VERSION            : u32 = 2;
const VMMDLL_MAP_KDEVICE_VERSION        : u32 = 1;
const VMMDLL_MAP_KDRIVER_VERSION        : u32 = 1;
const VMMDLL_MAP_KOBJECT_VERSION        : u32 = 1;
const VMMDLL_MAP_POOL_VERSION           : u32 = 2;
const VMMDLL_MAP_PTE_VERSION            : u32 = 2;
const VMMDLL_MAP_MODULE_VERSION         : u32 = 6;
const VMMDLL_MAP_NET_VERSION            : u32 = 3;
const VMMDLL_MAP_PFN_VERSION            : u32 = 1;
const VMMDLL_MAP_PHYSMEM_VERSION        : u32 = 2;
const VMMDLL_MAP_SERVICE_VERSION        : u32 = 3;
const VMMDLL_MAP_THREAD_VERSION         : u32 = 4;
const VMMDLL_MAP_THREAD_CALLSTACK_VERSION : u32 = 1;
const VMMDLL_MAP_UNLOADEDMODULE_VERSION : u32 = 2;
const VMMDLL_MAP_USER_VERSION           : u32 = 2;
const VMMDLL_MAP_VAD_VERSION            : u32 = 6;
const VMMDLL_MAP_VADEX_VERSION          : u32 = 4;
const VMMDLL_MAP_VM_VERSION             : u32 = 2;

const VMMDLL_MID_RUST                   : u32 = 0x80000004;

const VMMDLL_PLUGIN_CONTEXT_MAGIC       : u64 = 0xc0ffee663df9301c;
const VMMDLL_PLUGIN_CONTEXT_VERSION     : u16 = 5;
const VMMDLL_PLUGIN_REGINFO_MAGIC       : u64 = 0xc0ffee663df9301d;
const VMMDLL_PLUGIN_REGINFO_VERSION     : u16 = 18;
const VMMDLL_STATUS_SUCCESS             : u32 = 0x00000000;
const VMMDLL_STATUS_END_OF_FILE         : u32 = 0xC0000011;
const VMMDLL_STATUS_FILE_INVALID        : u32 = 0xC0000098;

const VMMDLL_PROCESS_INFORMATION_MAGIC          : u64 = 0xc0ffee663df9301e;
const VMMDLL_PROCESS_INFORMATION_VERSION        : u16 = 7;
const VMMDLL_REGISTRY_HIVE_INFORMATION_MAGIC    : u64 = 0xc0ffee653df8d01e;
const VMMDLL_REGISTRY_HIVE_INFORMATION_VERSION  : u16 = 4;

const VMMDLL_PROCESS_INFORMATION_OPT_STRING_PATH_KERNEL     : u32 = 1;
const VMMDLL_PROCESS_INFORMATION_OPT_STRING_PATH_USER_IMAGE : u32 = 2;
const VMMDLL_PROCESS_INFORMATION_OPT_STRING_CMDLINE         : u32 = 3;

const DIRECTORY_NAMES : [&str; 16] = ["EXPORT",  "IMPORT",  "RESOURCE",  "EXCEPTION",  "SECURITY",  "BASERELOC",  "DEBUG",  "ARCHITECTURE",  "GLOBALPTR",  "TLS",  "LOAD_CONFIG",  "BOUND_IMPORT",  "IAT",  "DELAY_IMPORT",  "COM_DESCRIPTOR",  "RESERVED"];

impl Drop for Vmm<'_> {
    fn drop(&mut self) {
        if self.native.is_close_h {
            (self.native.VMMDLL_Close)(self.native.h);
        }
    }
}

impl Clone for Vmm<'_> {
    fn clone(&self) -> Self {
        let vmmid = self.get_config(CONFIG_OPT_CORE_VMM_ID).unwrap();
        let vmmid_str = vmmid.to_string();
        let vmm_clone_args = ["-create-from-vmmid", &vmmid_str].to_vec();
        let vmm_clone = Vmm::new(&self.path_vmm, &vmm_clone_args).unwrap();
        return vmm_clone;
    }
}

impl fmt::Display for Vmm<'_> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Vmm")
    }
}

impl fmt::Display for VmmLogLevel {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let v = match self {
            VmmLogLevel::_1Critical => "Critical(1)",
            VmmLogLevel::_2Warning => "Warning(2)",
            VmmLogLevel::_3Info => "Info(3)",
            VmmLogLevel::_4Verbose => "Verbose(4)",
            VmmLogLevel::_5Debug => "Debug(5)",
            VmmLogLevel::_6Trace => "Trace(6)",
            VmmLogLevel::_7None => "None(7)",
        };
        write!(f, "{v}")
    }
}

impl From<u32> for VmmMemoryModelType {
    fn from(v : u32) -> Self {
        return match v {
            1 => VmmMemoryModelType::X86,
            2 => VmmMemoryModelType::X86PAE,
            3 => VmmMemoryModelType::X64,
            _ => VmmMemoryModelType::NA,
        };
    }
}

impl fmt::Display for VmmMemoryModelType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let v = match self {
            VmmMemoryModelType::NA => "NA",
            VmmMemoryModelType::X86 => "X86",
            VmmMemoryModelType::X86PAE => "X86PAE",
            VmmMemoryModelType::X64 => "X64",
        };
        write!(f, "{v}")
    }
}

impl From<u32> for VmmSystemType {
    fn from(v : u32) -> Self {
        return match v {
            1 => VmmSystemType::UnknownX64,
            2 => VmmSystemType::WindowsX64,
            3 => VmmSystemType::UnknownX86,
            4 => VmmSystemType::WindowsX86,
            _ => VmmSystemType::UnknownPhysical,
        };
    }
}

impl fmt::Display for VmmSystemType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let v = match self {
            VmmSystemType::UnknownPhysical => "UnknownPhysical",
            VmmSystemType::UnknownX64 => "UnknownX64",
            VmmSystemType::WindowsX64 => "WindowsX64",
            VmmSystemType::UnknownX86 => "UnknownX86",
            VmmSystemType::WindowsX86 => "WindowsX86",
        };
        write!(f, "{v}")
    }
}

impl From<u32> for VmmIntegrityLevelType {
    fn from(v : u32) -> Self {
        return match v {
            1 => VmmIntegrityLevelType::Untrusted,
            2 => VmmIntegrityLevelType::Low,
            3 => VmmIntegrityLevelType::Medium,
            4 => VmmIntegrityLevelType::MediumPlus,
            5 => VmmIntegrityLevelType::High,
            6 => VmmIntegrityLevelType::System,
            7 => VmmIntegrityLevelType::Protected,
            _ => VmmIntegrityLevelType::Unknown,
        };
    }
}

impl fmt::Display for VmmIntegrityLevelType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let v = match self {
            VmmIntegrityLevelType::Untrusted => "Untrusted",
            VmmIntegrityLevelType::Low => "Low",
            VmmIntegrityLevelType::Medium => "Medium",
            VmmIntegrityLevelType::MediumPlus => "MediumPlus",
            VmmIntegrityLevelType::High => "High",
            VmmIntegrityLevelType::System => "System",
            VmmIntegrityLevelType::Protected => "Protected",
            VmmIntegrityLevelType::Unknown => "Unknown",
        };
        write!(f, "{v}")
    }
}

impl From<u32> for VmmMapPfnType {
    fn from(v : u32) -> Self {
        return match v {
            0 => VmmMapPfnType::Zero,
            1 => VmmMapPfnType::Free,
            2 => VmmMapPfnType::Standby,
            3 => VmmMapPfnType::Modified,
            4 => VmmMapPfnType::ModifiedNoWrite,
            5 => VmmMapPfnType::Bad,
            6 => VmmMapPfnType::Active,
            _ => VmmMapPfnType::Transition,
        };
    }
}

impl fmt::Display for VmmMapPfnType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let v = match self {
            VmmMapPfnType::Zero => "Zero",
            VmmMapPfnType::Free => "Free",
            VmmMapPfnType::Standby => "Standby",
            VmmMapPfnType::Modified => "Modified",
            VmmMapPfnType::ModifiedNoWrite => "ModifiedNoWrite",
            VmmMapPfnType::Bad => "Bad",
            VmmMapPfnType::Active => "Active",
            VmmMapPfnType::Transition => "Transition",
        };
        write!(f, "{v}")
    }
}

impl From<u32> for VmmMapPfnTypeExtended {
    fn from(v : u32) -> Self {
        return match v {
            1 => VmmMapPfnTypeExtended::Unused,
            2 => VmmMapPfnTypeExtended::ProcessPrivate,
            3 => VmmMapPfnTypeExtended::PageTable,
            4 => VmmMapPfnTypeExtended::LargePage,
            5 => VmmMapPfnTypeExtended::DriverLocked,
            6 => VmmMapPfnTypeExtended::Shareable,
            7 => VmmMapPfnTypeExtended::File,
            _ => VmmMapPfnTypeExtended::Unknown,
        };
    }
}

impl fmt::Display for VmmMapPfnTypeExtended {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let v = match self {
            VmmMapPfnTypeExtended::Unused => "Unused",
            VmmMapPfnTypeExtended::ProcessPrivate => "ProcessPrivate",
            VmmMapPfnTypeExtended::PageTable => "PageTable",
            VmmMapPfnTypeExtended::LargePage => "LargePage",
            VmmMapPfnTypeExtended::DriverLocked => "DriverLocked",
            VmmMapPfnTypeExtended::Shareable => "Shareable",
            VmmMapPfnTypeExtended::File => "File",
            VmmMapPfnTypeExtended::Unknown => "Unknown",
        };
        write!(f, "{v}")
    }
}

#[repr(C)]
#[allow(non_snake_case)]
struct CVmEntry {
    hVM : usize,
    uszName : *const c_char,
    gpaMax : u64,
    tp : u32,
    fActive : bool,
    fReadOnly : bool,
    fPhysicalOnly : bool,
    dwPartitionID : u32,
    dwVersionBuild : u32,
    tpSystem : u32,
    dwParentVmmMountID : u32,
    dwVmMemPID : u32,
}

#[repr(C)]
#[allow(non_snake_case)]
struct CVmMap {
    dwVersion : u32,
    _Reserved1 : [u32; 5],
    pbMultiText : *const c_char,
    cbMultiText : u32,
    cMap : u32,
    pMap : CVmEntry,
}

impl fmt::Display for VmmMapPfnEntry {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "VmmMapPfnEntry:{}", self.pfn)
    }
}

impl fmt::Display for VmmMapMemoryEntry {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "VmmMapMemoryEntry:{:x}->{:x}", self.pa, self.pa + self.cb - 1)
    }
}

impl fmt::Display for VmmMapNetEntry {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "VmmMapNetEntry:'{}'", self.desc)
    }
}

impl PartialEq for VmmMapNetEntry {
    fn eq(&self, other: &Self) -> bool {
        self.va_object == other.va_object
    }
}

impl fmt::Display for VmmMapKDeviceEntry {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "VmmMapKDeviceEntry:{:x}:'{}'", self.va, self.device_type_name)
    }
}

impl PartialEq for VmmMapKDeviceEntry {
    fn eq(&self, other: &Self) -> bool {
        self.va == other.va
    }
}

impl fmt::Display for VmmMapKDriverEntry {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "VmmMapKDriverEntry::{:x}'{}'", self.va, self.name)
    }
}

impl PartialEq for VmmMapKDriverEntry {
    fn eq(&self, other: &Self) -> bool {
        self.va == other.va
    }
}

impl fmt::Display for VmmMapKObjectEntry {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "VmmMapKObjectEntry:{:x}:{}:'{}'", self.va, self.object_type, self.name)
    }
}

impl PartialEq for VmmMapKObjectEntry {
    fn eq(&self, other: &Self) -> bool {
        self.va == other.va
    }
}

impl fmt::Display for VmmMapPoolEntry {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "VmmMapPoolEntry:'{}':{:x}", self.tag_to_string(), self.va)
    }
}

impl PartialEq for VmmMapPoolEntry {
    fn eq(&self, other: &Self) -> bool {
        self.va == other.va
    }
}

impl fmt::Display for VmmMapServiceEntry {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "VmmMapServiceEntry:{}", self.name)
    }
}

impl fmt::Display for VmmMapUserEntry {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "VmmMapUserEntry:[{}]", self.user)
    }
}

impl fmt::Display for VmmMapVirtualMachineEntry {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "VmmMapVirtualMachineEntry:[{}]", self.name)
    }
}

#[repr(C)]
#[allow(non_snake_case)]
struct CPfnEntry {
    dwPfn : u32,
    tpExtended : u32,
    dwPfnPte : [u32; 5],
    va : u64,
    vaPte : u64,
    OriginalPte : u64,
    u3 : u32,
    u4 : u64,
    _FutureUse : [u32; 6],
}

#[repr(C)]
#[allow(non_snake_case)]
struct CPfnMap {
    dwVersion : u32,
    _Reserved1 : [u32; 5],
    cMap : u32,
    pMap : CPfnEntry,
}

#[repr(C)]
#[allow(non_snake_case)]
struct CNetMapEntry {
    dwPID : u32,
    dwState : u32,
    _FutureUse3 : [u16; 3],
    AF : u16,
    src_fValid : bool,
    src__Reserved : u16,
    src_port : u16,
    src_pbAddr : [u8; 16],
    src_uszText : *const c_char,
    dst_fValid : bool,
    dst__Reserved : u16,
    dst_port : u16,
    dst_pbAddr : [u8; 16],
    dst_uszText : *const c_char,
    vaObj : u64,
    ftTime : u64,
    dwPoolTag : u32,
    _FutureUse4 : u32,
    uszText : *const c_char,
    _FutureUse2 : [u32; 4],
}

#[repr(C)]
#[allow(non_snake_case)]
struct CNetMap {
    dwVersion : u32,
    _Reserved1 : u32,
    pbMultiText : *const c_char,
    cbMultiText : u32,
    cMap : u32,
    pMap : CNetMapEntry,
}

#[repr(C)]
struct CMemoryMapEntry {
    pa : u64,
    cb : u64,
}

#[repr(C)]
#[allow(non_snake_case)]
struct CMemoryMap {
    dwVersion : u32,
    _Reserved1 : [u32; 5],
    cMap : u32,
    _Reserved2 : u32,
    pMap : CMemoryMapEntry,
}

#[repr(C)]
#[allow(non_snake_case)]
struct CKDeviceEntry {
    va : u64,
    iDepth : u32,
    dwDeviceType : u32,
    uszDeviceType : *const c_char,
    vaDriverObject : u64,
    vaAttachedDevice : u64,
    vaFileSystemDevice : u64,
    uszVolumeInfo : *const c_char,
}

#[repr(C)]
#[allow(non_snake_case)]
struct CKDeviceMap {
    dwVersion : u32,
    _Reserved1 : [u32; 5],
    pbMultiText : *const c_char,
    cbMultiText : u32,
    cMap : u32,
    pMap : CKDeviceEntry,
}

#[repr(C)]
#[allow(non_snake_case)]
struct CKDriverEntry {
    va : u64,
    vaDriverStart : u64,
    cbDriverSize : u64,
    vaDeviceObject : u64,
    uszName : *const c_char,
    uszPath : *const c_char,
    uszServiceKeyName : *const c_char,
    MajorFunction : [u64; 28],
}

#[repr(C)]
#[allow(non_snake_case)]
struct CKDriverMap {
    dwVersion : u32,
    _Reserved1 : [u32; 5],
    pbMultiText : *const c_char,
    cbMultiText : u32,
    cMap : u32,
    pMap : CKDriverEntry,
}

#[repr(C)]
#[allow(non_snake_case)]
struct CKObjectEntry {
    va : u64,
    vaParent : u64,
    _Filler : u32,
    cvaChild : u32,
    pvaChild : *const u64,
    uszName : *const c_char,
    uszType : *const c_char,
}

#[repr(C)]
#[allow(non_snake_case)]
struct CKObjectMap {
    dwVersion : u32,
    _Reserved1 : [u32; 5],
    pbMultiText : *const c_char,
    cbMultiText : u32,
    cMap : u32,
    pMap : CKObjectEntry,
}

#[repr(C)]
#[allow(non_snake_case)]
struct CPoolEntry {
    va : u64,
    dwTag : u32,
    _ReservedZero : u8,
    fAlloc : u8,
    tpPool : u8,
    tpSS : u8,
    cb : u32,
    _Filler : u32,
}

#[repr(C)]
#[allow(non_snake_case)]
struct CPoolMap {
    dwVersion : u32,
    _Reserved1 : [u32; 6],
    cbTotal : u32,
    piTag2Map : usize,      // ptr
    pTag : usize,           // ptr
    cTag : u32,
    cMap : u32,
    pMap : CPoolEntry,
}

#[repr(C)]
#[allow(non_snake_case)]
struct CServiceEntry {
    vaObj : u64,
    dwOrdinal : u32,
    dwStartType : u32,
    dwServiceType : u32,
    dwCurrentState : u32,
    dwControlsAccepted : u32,
    dwWin32ExitCode : u32,
    dwServiceSpecificExitCode : u32,
    dwCheckPoint : u32,
    wWaitHint : u32,
    uszServiceName : *const c_char,
    uszDisplayName : *const c_char,
    uszPath : *const c_char,
    uszUserTp : *const c_char,
    uszUserAcct : *const c_char,
    uszImagePath : *const c_char,
    dwPID : u32,
    _FutureUse1 : u32,
    _FutureUse2 : u64,
}

#[repr(C)]
#[allow(non_snake_case)]
struct CServiceMap {
    dwVersion : u32,
    _Reserved1 : [u32; 5],
    pbMultiText : *const c_char,
    cbMultiText : u32,
    cMap : u32,
    pMap : CServiceEntry,
}

#[repr(C)]
#[allow(non_snake_case)]
struct CUserEntry {
    _FutureUse1 : [u32; 2],
    uszText : *const c_char,
    vaRegHive : u64,
    uszSID : *const c_char,
    _FutureUse2 : [u32; 2],
}

#[repr(C)]
#[allow(non_snake_case)]
struct CUserMap {
    dwVersion : u32,
    _Reserved1 : [u32; 5],
    pbMultiText : *const c_char,
    cbMultiText : u32,
    cMap : u32,
    pMap : CUserEntry,
}

#[repr(C)]
#[allow(non_snake_case)]
struct CRegHive {
    magic : u64,
    wVersion : u16,
    wSize : u16,
    _FutureReserved1 : [u8; 0x34],
    vaCMHIVE : u64,
    vaHBASE_BLOCK : u64,
    cbLength : u32,
    uszName : [i8; 128],
    uszNameShort : [i8; 32 + 1],
    uszHiveRootPath : [i8; 260],
    _FutureReserved : [u64; 0x10],
}

impl fmt::Display for VmmVfsEntry {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if self.is_directory {
            write!(f, "VmmVfsEntry:D:'{}'", self.name,)
        } else {
            write!(f, "VmmVfsEntry:F:'{}':0x{:x}", self.name, self.size)
        }
    }
}

#[repr(C)]
#[allow(non_snake_case, non_camel_case_types)]
struct CVMMDLL_VFS_FILELIST2 {
    dwVersion : u32,
    pfnAddFile : extern "C" fn(h : &mut Vec<VmmVfsEntry>, uszName : *const c_char, cb : u64, pExInfo : usize),
    pfnAddDirectory : extern "C" fn(h : &mut Vec<VmmVfsEntry>, uszName : *const c_char, pExInfo : usize),
    h : *mut Vec<VmmVfsEntry>,
}

extern "C" fn vfs_list_addfile_cb(h : &mut Vec<VmmVfsEntry>, name : *const c_char, cb : u64, _p_ex_info : usize) {
    unsafe {
        if name.is_null() { return; }
        if let Ok(name) = CStr::from_ptr(name).to_str() {
            let e = VmmVfsEntry {
                name : name.to_string(),
                is_directory : false,
                size : cb,
            };
            h.push(e);
        }
    }
}

extern "C" fn vfs_list_adddirectory_cb(h : &mut Vec<VmmVfsEntry>, name : *const c_char, _p_ex_info : usize) {
    unsafe {
        if name.is_null() { return; }
        if let Ok(name) = CStr::from_ptr(name).to_str() {
            let e = VmmVfsEntry {
                name : name.to_string(),
                is_directory : true,
                size : 0,
            };
            h.push(e);
        }
    }
}

unsafe fn cstr_to_string(sz : *const c_char) -> String {
    return if sz.is_null() {
        String::from("")
    } else {
        String::from(CStr::from_ptr(sz).to_str().unwrap_or(""))
    };
}

unsafe fn cstr_to_string_lossy(sz : *const c_char) -> String {
    return if sz.is_null() {
        String::from("")
    } else {
        String::from_utf8_lossy(CStr::from_ptr(sz).to_bytes()).to_string()
    };
}

#[allow(non_snake_case)]
impl Vmm<'_> {
    fn impl_get_leechcore(&self) -> ResultEx<LeechCore> {
        let lc_handle = self.get_config(CONFIG_OPT_CORE_LEECHCORE_HANDLE)?;
        let lc_lib_path = self.path_lc.as_str();
        let device_config_string = format!("existing://0x{:x}", lc_handle);
        return LeechCore::new(lc_lib_path, device_config_string.as_str(), 0);
    }

    fn impl_log(&self, log_mid : u32, log_level : &VmmLogLevel, log_message : &str) {
        let c_loglevel : u32 = match log_level {
            VmmLogLevel::_1Critical => 1,
            VmmLogLevel::_2Warning => 2,
            VmmLogLevel::_3Info => 3,
            VmmLogLevel::_4Verbose => 4,
            VmmLogLevel::_5Debug => 5,
            VmmLogLevel::_6Trace => 6,
            VmmLogLevel::_7None => 7,
        };
        let sz_log_fmt = CString::new("%s").unwrap();
        let sz_log_message = CString::new(log_message).unwrap();
        let _r = (self.native.VMMDLL_Log)(self.native.h, log_mid, c_loglevel, sz_log_fmt.as_ptr(), sz_log_message.as_ptr());
    }

    fn impl_get_config(&self, config_id : u64) -> ResultEx<u64> {
        let mut v = 0;
        let f = (self.native.VMMDLL_ConfigGet)(self.native.h, config_id, &mut v);
        return if f { Ok(v) } else { Err(anyhow!("VMMDLL_ConfigGet: fail")) };
    }

    fn impl_set_config(&self, config_id : u64, config_value : u64) -> ResultEx<()> {
        let f = (self.native.VMMDLL_ConfigSet)(self.native.h, config_id, config_value);
        return if f { Ok(()) } else { Err(anyhow!("VMMDLL_ConfigSet: fail")) };
    }

    fn impl_process_from_pid(&self, pid : u32) -> ResultEx<VmmProcess> {
        let process_list = self.process_list()?;
        let process = VmmProcess {
            vmm : &self,
            pid : pid,
        };
        if process_list.contains(&process) {
            return Ok(process);
        }
        return Err(anyhow!("VMMDLL_PidGetFromName: fail. PID '{pid}' does not exist."));
    }

    fn impl_process_from_name(&self, process_name : &str) -> ResultEx<VmmProcess> {
        let mut pid = 0;
        let sz_process_name = CString::new(process_name)?;
        let r = (self.native.VMMDLL_PidGetFromName)(self.native.h, sz_process_name.as_ptr(), &mut pid);
        if !r {
            return Err(anyhow!("VMMDLL_PidGetFromName: fail. Process '{process_name}' does not exist."));
        }
        return Ok(VmmProcess {
            vmm : &self,
            pid : pid,
        });
    }

    fn impl_process_list(&self) -> ResultEx<Vec<VmmProcess>> {
        let mut cpids : usize = 0;
        let r = (self.native.VMMDLL_PidList)(self.native.h, std::ptr::null_mut(), &mut cpids);
        if !r || cpids > 0x00100000 {
            return Err(anyhow!("VMMDLL_PidList: fail."));
        }
        let mut pids = vec![0u32; cpids];
        let r = (self.native.VMMDLL_PidList)(self.native.h, pids.as_mut_ptr(), &mut cpids);
        if !r || cpids > 0x00100000 {
            return Err(anyhow!("VMMDLL_PidList: fail."));
        }
        let mut proclist = Vec::new();
        for i in 0..cpids {
            let proc = VmmProcess {
                vmm : self,
                pid : *pids.get(i).unwrap(),
            };
            proclist.push(proc);
        }
        return Ok(proclist);
    }
    fn impl_map_pfn(&self, pfns : &Vec<u32>, is_extended : bool) -> ResultEx<Vec<VmmMapPfnEntry>> {
        unsafe {
            let mut structs = std::ptr::null_mut();
            let flags = if is_extended { 1 } else { 0 };
            let r = (self.native.VMMDLL_Map_GetPfnEx)(self.native.h, pfns.as_ptr(), u32::try_from(pfns.len())?, &mut structs, flags);
            if !r {
                return Err(anyhow!("VMMDLL_Map_GetPfnEx: fail."));
            }
            if (*structs).dwVersion != VMMDLL_MAP_PFN_VERSION {
                (self.native.VMMDLL_MemFree)(structs as usize);
                return Err(anyhow!("VMMDLL_Map_GetPfnEx: bad version [{} != {}].", (*structs).dwVersion, VMMDLL_MAP_PFN_VERSION));
            }
            let mut result = Vec::new();
            if (*structs).cMap == 0 {
                (self.native.VMMDLL_MemFree)(structs as usize);
                return Ok(result);
            }
            let cMap : usize = (*structs).cMap.try_into()?;
            let pMap = std::slice::from_raw_parts(&(*structs).pMap, cMap);
            for i in 0..cMap {
                let ne = &pMap[i];
                let e = VmmMapPfnEntry {
                    pfn : ne.dwPfn,
                    location : VmmMapPfnType::from((ne.u3 >> 16) & 7),
                    is_prototype : if ne.u4 & 0x0200000000000000 > 0 { true } else { false },
                    color : u32::try_from(ne.u4 >> 58)?,
                    is_extended : is_extended,
                    tp_ex : VmmMapPfnTypeExtended::from(ne.tpExtended),
                    pid : ne.dwPfnPte[0],
                    ptes : [0, ne.dwPfnPte[1], ne.dwPfnPte[2], ne.dwPfnPte[3], ne.dwPfnPte[4]],
                    va : ne.va,
                    va_pte : ne.vaPte,
                    pte_original : ne.OriginalPte,
                };
                result.push(e);
            }
            (self.native.VMMDLL_MemFree)(structs as usize);
            return Ok(result);
        }
    }

    fn impl_map_memory(&self) -> ResultEx<Vec<VmmMapMemoryEntry>> {
        unsafe {
            let mut structs  = std::ptr::null_mut();
            let r = (self.native.VMMDLL_Map_GetPhysMem)(self.native.h, &mut structs);
            if !r {
                return Err(anyhow!("VMMDLL_Map_GetPhysMem: fail."));
            }
            if (*structs).dwVersion != VMMDLL_MAP_PHYSMEM_VERSION {
                (self.native.VMMDLL_MemFree)(structs as usize);
                return Err(anyhow!("VMMDLL_Map_GetPhysMem: bad version [{} != {}].", (*structs).dwVersion, VMMDLL_MAP_PHYSMEM_VERSION));
            }
            let mut result = Vec::new();
            if (*structs).cMap == 0 {
                (self.native.VMMDLL_MemFree)(structs as usize);
                return Ok(result);
            }
            let cMap : usize = (*structs).cMap.try_into()?;
            let pMap = std::slice::from_raw_parts(&(*structs).pMap, cMap);
            for i in 0..cMap {
                let ne = &pMap[i];
                let e = VmmMapMemoryEntry {
                    pa : ne.pa,
                    cb : ne.cb,
                };
                result.push(e);
            }
            (self.native.VMMDLL_MemFree)(structs as usize);
            return Ok(result);
        }
    }

    fn impl_map_net(&self) -> ResultEx<Vec<VmmMapNetEntry>> {
        unsafe {
            let mut structs = std::ptr::null_mut();
            let r = (self.native.VMMDLL_Map_GetNetU)(self.native.h, &mut structs);
            if !r {
                return Err(anyhow!("VMMDLL_Map_GetNetU: fail."));
            }
            if (*structs).dwVersion != VMMDLL_MAP_NET_VERSION {
                (self.native.VMMDLL_MemFree)(structs as usize);
                return Err(anyhow!("VMMDLL_Map_GetNetU: bad version [{} != {}].", (*structs).dwVersion, VMMDLL_MAP_NET_VERSION));
            }
            let mut result = Vec::new();
            if (*structs).cMap == 0 {
                (self.native.VMMDLL_MemFree)(structs as usize);
                return Ok(result);
            }
            let cMap : usize = (*structs).cMap.try_into()?;
            let pMap = std::slice::from_raw_parts(&(*structs).pMap, cMap);
            for i in 0..cMap {
                let ne = &pMap[i];
                let e = VmmMapNetEntry {
                    pid : ne.dwPID,
                    state : ne.dwState,
                    address_family : ne.AF,
                    src_is_valid : ne.src_fValid,
                    src_port : ne.src_port,
                    src_addr_raw : ne.src_pbAddr,
                    src_str : cstr_to_string(ne.src_uszText),
                    dst_is_valid : ne.dst_fValid,
                    dst_port : ne.dst_port,
                    dst_addr_raw : ne.dst_pbAddr,
                    dst_str : cstr_to_string(ne.dst_uszText),
                    va_object : ne.vaObj,
                    filetime : ne.ftTime,
                    pool_tag : ne.dwPoolTag,
                    desc : cstr_to_string(ne.uszText),
                };
                result.push(e);
            }
            (self.native.VMMDLL_MemFree)(structs as usize);
            return Ok(result);
        }
    }

    fn impl_map_kdevice(&self) -> ResultEx<Vec<VmmMapKDeviceEntry>> {
        unsafe {
            let mut structs = std::ptr::null_mut();
            let r = (self.native.VMMDLL_Map_GetKDeviceU)(self.native.h, &mut structs);
            if !r {
                return Err(anyhow!("VMMDLL_Map_GetKDeviceU: fail."));
            }
            if (*structs).dwVersion != VMMDLL_MAP_KDEVICE_VERSION {
                (self.native.VMMDLL_MemFree)(structs as usize);
                return Err(anyhow!("VMMDLL_Map_GetKDeviceU: bad version [{} != {}].", (*structs).dwVersion, VMMDLL_MAP_KDEVICE_VERSION));
            }
            let mut result = Vec::new();
            if (*structs).cMap == 0 {
                (self.native.VMMDLL_MemFree)(structs as usize);
                return Ok(result);
            }
            let cMap : usize = (*structs).cMap.try_into()?;
            let pMap = std::slice::from_raw_parts(&(*structs).pMap, cMap);
            for i in 0..cMap {
                let ne = &pMap[i];
                let e = VmmMapKDeviceEntry {
                    va : ne.va,
                    depth : ne.iDepth,
                    device_type : ne.dwDeviceType,
                    device_type_name : cstr_to_string(ne.uszDeviceType),
                    va_driver_object : ne.vaDriverObject,
                    va_attached_device : ne.vaAttachedDevice,
                    va_file_system_device : ne.vaFileSystemDevice,
                    volume_info : cstr_to_string(ne.uszVolumeInfo),
                };
                result.push(e);
            }
            (self.native.VMMDLL_MemFree)(structs as usize);
            return Ok(result);
        }
    }

    fn impl_map_kdriver(&self) -> ResultEx<Vec<VmmMapKDriverEntry>> {
        unsafe {
            let mut structs = std::ptr::null_mut();
            let r = (self.native.VMMDLL_Map_GetKDriverU)(self.native.h, &mut structs);
            if !r {
                return Err(anyhow!("VMMDLL_Map_GetKDriverU: fail."));
            }
            if (*structs).dwVersion != VMMDLL_MAP_KDRIVER_VERSION {
                (self.native.VMMDLL_MemFree)(structs as usize);
                return Err(anyhow!("VMMDLL_Map_GetKDriverU: bad version [{} != {}].", (*structs).dwVersion, VMMDLL_MAP_KDRIVER_VERSION));
            }
            let mut result = Vec::new();
            if (*structs).cMap == 0 {
                (self.native.VMMDLL_MemFree)(structs as usize);
                return Ok(result);
            }
            let cMap : usize = (*structs).cMap.try_into()?;
            let pMap = std::slice::from_raw_parts(&(*structs).pMap, cMap);
            for i in 0..cMap {
                let ne = &pMap[i];
                let e = VmmMapKDriverEntry {
                    va : ne.va,
                    va_driver_start : ne.vaDriverStart,
                    cb_driver_size : ne.cbDriverSize,
                    va_device_object : ne.vaDeviceObject,
                    name : cstr_to_string(ne.uszName),
                    path : cstr_to_string(ne.uszPath),
                    service_key_name : cstr_to_string(ne.uszServiceKeyName),
                    major_function : ne.MajorFunction,
                };
                result.push(e);
            }
            (self.native.VMMDLL_MemFree)(structs as usize);
            return Ok(result);
        }
    }

    fn impl_map_kobject(&self) -> ResultEx<Vec<VmmMapKObjectEntry>> {
        unsafe {
            let mut structs = std::ptr::null_mut();
            let r = (self.native.VMMDLL_Map_GetKObjectU)(self.native.h, &mut structs);
            if !r {
                return Err(anyhow!("VMMDLL_Map_GetKObjectU: fail."));
            }
            if (*structs).dwVersion != VMMDLL_MAP_KOBJECT_VERSION {
                (self.native.VMMDLL_MemFree)(structs as usize);
                return Err(anyhow!("VMMDLL_Map_GetKObjectU: bad version [{} != {}].", (*structs).dwVersion, VMMDLL_MAP_KOBJECT_VERSION));
            }
            let mut result = Vec::new();
            if (*structs).cMap == 0 {
                (self.native.VMMDLL_MemFree)(structs as usize);
                return Ok(result);
            }
            let cMap : usize = (*structs).cMap.try_into()?;
            let pMap = std::slice::from_raw_parts(&(*structs).pMap, cMap);
            for i in 0..cMap {
                let ne = &pMap[i];
                let mut child_vec = Vec::new();
                let child_count = ne.cvaChild as usize;
                let child_ptr = std::slice::from_raw_parts(ne.pvaChild, ne.cvaChild as usize);
                for j in 0..child_count {
                    child_vec.push(child_ptr[j]);
                }
                let e = VmmMapKObjectEntry {
                    va : ne.va,
                    va_parent : ne.vaParent,
                    children : child_vec,
                    name : cstr_to_string(ne.uszName),
                    object_type : cstr_to_string(ne.uszType),
                };
                result.push(e);
            }
            (self.native.VMMDLL_MemFree)(structs as usize);
            return Ok(result);
        }
    }

    fn impl_map_pool(&self, is_bigpool_only : bool) -> ResultEx<Vec<VmmMapPoolEntry>> {
        unsafe {
            let mut structs = std::ptr::null_mut();
            let flags = if is_bigpool_only { 1 } else { 0 };
            let r = (self.native.VMMDLL_Map_GetPool)(self.native.h, &mut structs, flags);
            if !r {
                return Err(anyhow!("VMMDLL_Map_GetPool: fail."));
            }
            if (*structs).dwVersion != VMMDLL_MAP_POOL_VERSION {
                (self.native.VMMDLL_MemFree)(structs as usize);
                return Err(anyhow!("VMMDLL_Map_GetPool: bad version [{} != {}].", (*structs).dwVersion, VMMDLL_MAP_POOL_VERSION));
            }
            let mut result = Vec::new();
            if (*structs).cMap == 0 {
                (self.native.VMMDLL_MemFree)(structs as usize);
                return Ok(result);
            }
            let cMap : usize = (*structs).cMap.try_into()?;
            let pMap = std::slice::from_raw_parts(&(*structs).pMap, cMap);
            for i in 0..cMap {
                let ne = &pMap[i];
                let e = VmmMapPoolEntry {
                    va : ne.va,
                    cb : ne.cb,
                    tag : ne.dwTag,
                    is_alloc : ne.fAlloc != 0,
                    tp_pool : ne.tpPool,
                    tp_subsegment : ne.tpSS,
                };
                result.push(e);
            }
            (self.native.VMMDLL_MemFree)(structs as usize);
            return Ok(result);
        }
    }

    fn impl_map_service(&self) -> ResultEx<Vec<VmmMapServiceEntry>> {
        unsafe {
            let mut structs = std::ptr::null_mut();
            let r = (self.native.VMMDLL_Map_GetServicesU)(self.native.h, &mut structs);
            if !r {
                return Err(anyhow!("VMMDLL_Map_GetServicesU: fail."));
            }
            if (*structs).dwVersion != VMMDLL_MAP_SERVICE_VERSION {
                (self.native.VMMDLL_MemFree)(structs as usize);
                return Err(anyhow!("VMMDLL_Map_GetServicesU: bad version [{} != {}].", (*structs).dwVersion, VMMDLL_MAP_SERVICE_VERSION));
            }
            let mut result = Vec::new();
            if (*structs).cMap == 0 {
                (self.native.VMMDLL_MemFree)(structs as usize);
                return Ok(result);
            }
            let cMap : usize = (*structs).cMap.try_into()?;
            let pMap = std::slice::from_raw_parts(&(*structs).pMap, cMap);
            for i in 0..cMap {
                let ne = &pMap[i];
                let e = VmmMapServiceEntry {
                    ordinal : ne.dwOrdinal,
                    va_object : ne.vaObj,
                    pid : ne.dwPID,
                    start_type : ne.dwStartType,
                    service_type : ne.dwServiceType,
                    current_state : ne.dwCurrentState,
                    controls_accepted : ne.dwControlsAccepted,
                    win32_exit_code : ne.dwWin32ExitCode,
                    service_specific_exit_code : ne.dwServiceSpecificExitCode,
                    check_point : ne.dwCheckPoint,
                    wait_hint : ne.wWaitHint,
                    name : cstr_to_string(ne.uszServiceName),
                    name_display : cstr_to_string(ne.uszDisplayName),
                    path : cstr_to_string(ne.uszPath),
                    user_type : cstr_to_string(ne.uszUserTp),
                    user_account : cstr_to_string(ne.uszUserAcct),
                    image_path : cstr_to_string(ne.uszImagePath),
                };
                result.push(e);
            }
            (self.native.VMMDLL_MemFree)(structs as usize);
            return Ok(result);
        }
    }

    fn impl_map_user(&self) -> ResultEx<Vec<VmmMapUserEntry>> {
        unsafe {
            let mut structs = std::ptr::null_mut();
            let r = (self.native.VMMDLL_Map_GetUsersU)(self.native.h, &mut structs);
            if !r {
                return Err(anyhow!("VMMDLL_Map_GetUsersU: fail."));
            }
            if (*structs).dwVersion != VMMDLL_MAP_USER_VERSION {
                (self.native.VMMDLL_MemFree)(structs as usize);
                return Err(anyhow!("VMMDLL_Map_GetUsersU: bad version [{} != {}].", (*structs).dwVersion, VMMDLL_MAP_USER_VERSION));
            }
            let mut result = Vec::new();
            if (*structs).cMap == 0 {
                (self.native.VMMDLL_MemFree)(structs as usize);
                return Ok(result);
            }
            let cMap : usize = (*structs).cMap.try_into()?;
            let pMap = std::slice::from_raw_parts(&(*structs).pMap, cMap);
            for i in 0..cMap {
                let ne = &pMap[i];
                let e = VmmMapUserEntry {
                    user : cstr_to_string(ne.uszText),
                    sid : cstr_to_string(ne.uszSID),
                    va_reg_hive : ne.vaRegHive,
                };
                result.push(e);
            }
            (self.native.VMMDLL_MemFree)(structs as usize);
            return Ok(result);
        }
    }

    fn impl_map_virtual_machine(&self) -> ResultEx<Vec<VmmMapVirtualMachineEntry>> {
        unsafe {
            let mut structs = std::ptr::null_mut();
            let r = (self.native.VMMDLL_Map_GetVMU)(self.native.h, &mut structs);
            if !r {
                return Err(anyhow!("VMMDLL_Map_GetVMU: fail."));
            }
            if (*structs).dwVersion != VMMDLL_MAP_VM_VERSION {
                (self.native.VMMDLL_MemFree)(structs as usize);
                return Err(anyhow!("VMMDLL_Map_GetVMU: bad version [{} != {}].", (*structs).dwVersion, VMMDLL_MAP_VM_VERSION));
            }
            let mut result = Vec::new();
            if (*structs).cMap == 0 {
                (self.native.VMMDLL_MemFree)(structs as usize);
                return Ok(result);
            }
            let cMap : usize = (*structs).cMap.try_into()?;
            let pMap = std::slice::from_raw_parts(&(*structs).pMap, cMap);
            for i in 0..cMap {
                let ne = &pMap[i];
                let e = VmmMapVirtualMachineEntry {
                    h_vmm : self.native.h,
                    h_vm : ne.hVM,
                    name : cstr_to_string(ne.uszName),
                    gpa_max : ne.gpaMax,
                    tp_vm : ne.tp,
                    is_active : ne.fActive,
                    is_readonly : ne.fReadOnly,
                    is_physicalonly : ne.fPhysicalOnly,
                    partition_id : ne.dwPartitionID,
                    guest_os_version_build : ne.dwVersionBuild,
                    guest_tp_system : ne.tpSystem,
                    parent_mount_id : ne.dwParentVmmMountID,
                    vmmem_pid : ne.dwVmMemPID,
                };
                result.push(e);
            }
            (self.native.VMMDLL_MemFree)(structs as usize);
            return Ok(result);
        }
    }

    fn impl_mem_read(&self, pid : u32, va : u64, size : usize, flags : u64) -> ResultEx<Vec<u8>> {
        let cb = u32::try_from(size)?;
        let mut cb_read = 0;
        let mut pb_result = vec![0u8; size];
        let r = (self.native.VMMDLL_MemReadEx)(self.native.h, pid, va, pb_result.as_mut_ptr(), cb, &mut cb_read, flags);
        if !r {
            return Err(anyhow!("VMMDLL_MemReadEx: fail."));
        }
        return Ok(pb_result);
    }

    fn impl_mem_read_into(&self, pid : u32, va : u64, flags : u64, data : &mut [u8]) -> ResultEx<usize> {
        let cb = u32::try_from(data.len())?;
        let mut cb_read = 0;
        let r = (self.native.VMMDLL_MemReadEx)(self.native.h, pid, va, data.as_mut_ptr(), cb, &mut cb_read, flags);
        if !r {
            return Err(anyhow!("VMMDLL_MemReadEx: fail."));
        }
        return Ok(cb_read as usize);
    }

    fn impl_mem_read_as<T>(&self, pid : u32, va : u64, flags : u64) -> ResultEx<T> {
        unsafe {
            let cb = u32::try_from(std::mem::size_of::<T>())?;
            let mut cb_read = 0;
            let mut result : T = std::mem::zeroed();
            let r = (self.native.VMMDLL_MemReadEx)(self.native.h, pid, va, &mut result as *mut _ as *mut u8, cb, &mut cb_read, flags);
            if !r {
                return Err(anyhow!("VMMDLL_MemReadEx: fail."));
            }
            return Ok(result);
        }
    }

    fn impl_mem_scatter(&self, pid : u32, flags : u64) -> ResultEx<VmmScatterMemory> {
        let flags = u32::try_from(flags)?;
        let r = (self.native.VMMDLL_Scatter_Initialize)(self.native.h, pid, flags);
        if r == 0 {
            return Err(anyhow!("VMMDLL_Scatter_Initialize: fail."));
        }
        return Ok(VmmScatterMemory {
            vmm : &self,
            hs : r,
            pid,
            flags,
            is_scatter_ex : false,
        });
    }

    fn impl_mem_virt2phys(&self, pid : u32, va : u64) -> ResultEx<u64> {
        let mut pa : u64 = 0;
        let r = (self.native.VMMDLL_MemVirt2Phys)(self.native.h, pid, va, &mut pa);
        if !r {
            return Err(anyhow!("VMMDLL_MemVirt2Phys: fail."));
        }
        return Ok(pa);
    }

    fn impl_mem_write(&self, pid : u32, va : u64, data : &[u8]) -> ResultEx<()> {
        let cb = u32::try_from(data.len())?;
        let pb = data.as_ptr();
        let r = (self.native.VMMDLL_MemWrite)(self.native.h, pid, va, pb, cb);
        if !r {
            return Err(anyhow!("VMMDLL_MemWrite: fail."));
        }
        return Ok(());
    }

    fn impl_mem_write_as<T>(&self, pid : u32, va : u64, data : &T) -> ResultEx<()> {
        let cb = u32::try_from(std::mem::size_of::<T>())?;
        let r = (self.native.VMMDLL_MemWrite)(self.native.h, pid, va, data as *const _ as *const u8, cb);
        if !r {
            return Err(anyhow!("VMMDLL_MemWrite: fail."));
        }
        return Ok(());
    }

    fn impl_vfs_list(&self, path : &str) -> ResultEx<Vec<VmmVfsEntry>> {
        let c_path = CString::new(str::replace(path, "/", "\\"))?;
        let mut vec_result : Vec<VmmVfsEntry> = Vec::new();
        let ptr_result : *mut Vec<VmmVfsEntry> = &mut vec_result;
        let mut filelist2 = CVMMDLL_VFS_FILELIST2 {
            dwVersion : VMMDLL_VFS_FILELIST_VERSION,
            pfnAddFile : vfs_list_addfile_cb,
            pfnAddDirectory : vfs_list_adddirectory_cb,
            h : ptr_result,
        };
        let r = (self.native.VMMDLL_VfsListU)(self.native.h, c_path.as_ptr(), &mut filelist2);
        if !r {
            return Err(anyhow!("VMMDLL_VfsListU: fail."));
        }
        return Ok(vec_result);
    }

    fn impl_vfs_read(&self, filename : &str, size : u32, offset : u64) -> ResultEx<Vec<u8>> {
        let c_filename = CString::new(str::replace(filename, "/", "\\"))?;
        let mut cb_read = 0u32;
        let mut data = vec![0u8; size as usize];
        let ntstatus = (self.native.VMMDLL_VfsReadU)(self.native.h, c_filename.as_ptr(), data.as_mut_ptr(), size, &mut cb_read, offset);
        if ntstatus != 0 && ntstatus != 0xC0000011 {
            return Err(anyhow!("VMMDLL_VfsReadU: fail."));
        }
        if cb_read < size {
            data.resize(cb_read as usize, 0);
        }
        return Ok(data);
    }

    fn impl_vfs_write(&self, filename : &str, data : &[u8], offset : u64) {
        if data.len() < u32::MAX as usize {
            let c_filename = CString::new(str::replace(filename, "/", "\\")).unwrap();
            let mut cb_write = 0u32;
            let _ntstatus = (self.native.VMMDLL_VfsWriteU)(self.native.h, c_filename.as_ptr(), data.as_ptr(), data.len() as u32, &mut cb_write, offset);
        }
    }

    fn impl_reg_hive_list(&self) -> ResultEx<Vec<VmmRegHive>> {
        unsafe {
            let mut cHives = 0;
            let r = (self.native.VMMDLL_WinReg_HiveList)(self.native.h, std::ptr::null_mut(), 0, &mut cHives);
            if !r {
                return Err(anyhow!("VMMDLL_WinReg_HiveList: fail."));
            }
            if cHives == 0 {
                return Ok(Vec::new());
            }
            let size = std::mem::size_of::<CRegHive>();
            let mut bytes = vec![0u8; size * cHives as usize];
            let ptr = bytes.as_mut_ptr() as *mut CRegHive;
            let r = (self.native.VMMDLL_WinReg_HiveList)(self.native.h, ptr, cHives, &mut cHives);
            if !r {
                return Err(anyhow!("VMMDLL_WinReg_HiveList: fail."));
            }
            if cHives == 0 {
                return Ok(Vec::new());
            }
            let mut result = Vec::new();
            let pMap = std::slice::from_raw_parts(ptr, cHives as usize);
            for i in 0..cHives as usize {
                let ne = &pMap[i];
                if (ne.magic != VMMDLL_REGISTRY_HIVE_INFORMATION_MAGIC) || (ne.wVersion != VMMDLL_REGISTRY_HIVE_INFORMATION_VERSION) {
                    return Err(anyhow!("Hive Bad Version."));
                }
                let e = VmmRegHive {
                    vmm : &self,
                    va : ne.vaCMHIVE,
                    va_baseblock : ne.vaHBASE_BLOCK,
                    size : ne.cbLength,
                    name : cstr_to_string_lossy(ne.uszName.as_ptr() as *const c_char),
                    name_short : cstr_to_string_lossy(ne.uszNameShort.as_ptr() as *const c_char),
                    path : cstr_to_string_lossy(ne.uszHiveRootPath.as_ptr() as *const c_char),
                };
                result.push(e);
            }
            return Ok(result);
        }
    }

    fn impl_reg_pathsplit(path : &str) -> ResultEx<(&str, &str)> {
        let path = path.trim_end_matches('\\');
        if let Some(split) = path.rsplit_once('\\') {
            if (split.0.len() > 0) && (split.1.len() > 0) {
                return Ok(split);
            }
        }
        return Err(anyhow!("[err]"));
    }

    fn impl_reg_key(&self, path : &str) -> ResultEx<VmmRegKey> {
        let mut ftLastWrite = 0;
        let mut cch = 0;
        let c_path = CString::new(path)?;
        let r = (self.native.VMMDLL_WinReg_EnumKeyExU)(self.native.h, c_path.as_ptr(), u32::MAX, std::ptr::null_mut(), &mut cch, &mut ftLastWrite);
        if !r {
            return Err(anyhow!("VMMDLL_WinReg_EnumKeyExU: fail."));
        }
        let pathname = Vmm::impl_reg_pathsplit(path)?;
        let result = VmmRegKey {
            vmm : &self,
            name : String::from(pathname.1),
            path : String::from(path),
            ft_last_write : ftLastWrite,
        };
        return Ok(result);
    }

    fn impl_reg_value(&self, path : &str) -> ResultEx<VmmRegValue> {
        let mut raw_value = None;
        let mut raw_type = 0;
        let mut v = [0u8; 64];
        let mut raw_size = v.len() as u32;
        let c_path = CString::new(path)?;
        let r = (self.native.VMMDLL_WinReg_QueryValueExU)(self.native.h, c_path.as_ptr(), &mut raw_type, v.as_mut_ptr(), &mut raw_size);
        if !r {
            return Err(anyhow!("VMMDLL_WinReg_QueryValueExU: fail."));
        }
        if raw_size < v.len() as u32 {
            raw_value = Some(v[0..raw_size as usize].to_vec());
        } else {
            let r = (self.native.VMMDLL_WinReg_QueryValueExU)(self.native.h, c_path.as_ptr(), std::ptr::null_mut(), std::ptr::null_mut(), &mut raw_size);
            if !r {
                return Err(anyhow!("VMMDLL_WinReg_QueryValueExU: fail."));
            }
        }
        let pathname = Vmm::impl_reg_pathsplit(path)?;
        let result = VmmRegValue {
            vmm : &self,
            name : String::from(pathname.1),
            path : String::from(path),
            raw_type,
            raw_size,
            raw_value,
        };
        return Ok(result);
    }
}






//=============================================================================
// INTERNAL: VMM.KERNEL:
//=============================================================================

impl fmt::Display for VmmKernel<'_> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "VmmKernel")
    }
}






//=============================================================================
// INTERNAL: VMM.PDB:
//=============================================================================

impl fmt::Display for VmmPdb<'_> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "VmmPdb:{}", self.module)
    }
}

impl VmmPdb<'_> {
    fn impl_symbol_name_from_address(&self, va_or_offset : u64) -> ResultEx<(String, u32)> {
        let c_module = CString::new(self.module.as_str())?;
        let mut c_symbol_name = [0 as c_char; MAX_PATH];
        let mut result_symbol_displacement = 0;
        let r = (self.vmm.native.VMMDLL_PdbSymbolName)(self.vmm.native.h, c_module.as_ptr(), va_or_offset, c_symbol_name.as_mut_ptr(), &mut result_symbol_displacement);
        if !r {
            return Err(anyhow!("VMMDLL_PdbSymbolName: fail."));
        }
        let string_symbol_name = unsafe { cstr_to_string_lossy(c_symbol_name.as_ptr()) };
        return Ok((string_symbol_name, result_symbol_displacement));
    }

    fn impl_symbol_address_from_name(&self, symbol_name : &str) -> ResultEx<u64> {
        let c_module = CString::new(self.module.as_str())?;
        let c_symbol_name = CString::new(symbol_name)?;
        let mut result = 0;
        let r = (self.vmm.native.VMMDLL_PdbSymbolAddress)(self.vmm.native.h, c_module.as_ptr(), c_symbol_name.as_ptr(), &mut result);
        if !r {
            return Err(anyhow!("VMMDLL_PdbSymbolAddress: fail."));
        }
        return Ok(result);
    }

    fn impl_type_size(&self, type_name : &str) -> ResultEx<u32> {
        let c_module = CString::new(self.module.as_str())?;
        let c_type_name = CString::new(type_name)?;
        let mut result = 0;
        let r = (self.vmm.native.VMMDLL_PdbTypeSize)(self.vmm.native.h, c_module.as_ptr(), c_type_name.as_ptr(), &mut result);
        if !r {
            return Err(anyhow!("VMMDLL_PdbTypeSize: fail."));
        }
        return Ok(result);
    }

    fn impl_type_child_offset(&self, type_name : &str, type_child_name : &str) -> ResultEx<u32> {
        let c_module = CString::new(self.module.as_str())?;
        let c_type_name = CString::new(type_name)?;
        let c_type_child_name = CString::new(type_child_name)?;
        let mut result = 0;
        let r = (self.vmm.native.VMMDLL_PdbTypeChildOffset)(self.vmm.native.h, c_module.as_ptr(), c_type_name.as_ptr(), c_type_child_name.as_ptr(), &mut result);
        if !r {
            return Err(anyhow!("VMMDLL_PdbTypeChildOffset: fail."));
        }
        return Ok(result);
    }
}






//=============================================================================
// INTERNAL: VMM.REGISTRY:
//=============================================================================

impl fmt::Display for VmmRegHive<'_> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "VmmRegHive:{:x}", self.va)
    }
}

impl PartialEq for VmmRegHive<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.va == other.va
    }
}

impl fmt::Display for VmmRegKey<'_> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "VmmRegKey:{}", self.name)
    }
}

impl PartialEq for VmmRegKey<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.name.eq(&other.name)
    }
}

impl fmt::Display for VmmRegValueType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let v = match self {
            VmmRegValueType::REG_NONE => "REG_NONE".to_string(),
            VmmRegValueType::REG_SZ(r) => format!("REG_SZ({r})"),
            VmmRegValueType::REG_EXPAND_SZ(_) => "REG_EXPAND_SZ".to_string(),
            VmmRegValueType::REG_BINARY(_) => "REG_BINARY".to_string(),
            VmmRegValueType::REG_DWORD(r) => format!("REG_DWORD(0x{:x})", r),
            VmmRegValueType::REG_DWORD_BIG_ENDIAN(r) => format!("REG_DWORD_BIG_ENDIAN(0x{:x})", r),
            VmmRegValueType::REG_LINK(r) => format!("REG_LINK({r})"),
            VmmRegValueType::REG_MULTI_SZ(_) => "REG_MULTI_SZ".to_string(),
            VmmRegValueType::REG_RESOURCE_LIST(_) => "REG_RESOURCE_LIST".to_string(),
            VmmRegValueType::REG_FULL_RESOURCE_DESCRIPTOR(_) => "REG_FULL_RESOURCE_DESCRIPTOR".to_string(),
            VmmRegValueType::REG_RESOURCE_REQUIREMENTS_LIST(_) => "REG_RESOURCE_REQUIREMENTS_LIST".to_string(),
            VmmRegValueType::REG_QWORD(r) => format!("REG_QWORD(0x{:x})", r),
        };
        write!(f, "{v}")
    }
}

impl fmt::Display for VmmRegValue<'_> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "VmmRegValue:{}", self.name)
    }
}

impl PartialEq for VmmRegValue<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.name.eq(&other.name)
    }
}

impl VmmRegHive<'_> {
    fn impl_reg_hive_read(&self, ra : u32, size : usize, flags : u64) -> ResultEx<Vec<u8>> {
        let cb = u32::try_from(size)?;
        let mut cb_read = 0;
        let mut pb_result = vec![0u8; size];
        let r = (self.vmm.native.VMMDLL_WinReg_HiveReadEx)(self.vmm.native.h, self.va, ra, pb_result.as_mut_ptr(), cb, &mut cb_read, flags);
        if !r {
            return Err(anyhow!("VMMDLL_WinReg_HiveReadEx: fail."));
        }
        return Ok(pb_result);
    }

    fn impl_reg_hive_write(&self, ra : u32, data : &[u8]) -> ResultEx<()> {
        let cb = u32::try_from(data.len())?;
        let pb = data.as_ptr();
        let r = (self.vmm.native.VMMDLL_WinReg_HiveWrite)(self.vmm.native.h, self.va, ra, pb, cb);
        if !r {
            return Err(anyhow!("VMMDLL_WinReg_HiveWrite: fail."));
        }
        return Ok(());
    }
}

impl VmmRegKey<'_> {
    fn impl_parent(&self) -> ResultEx<VmmRegKey> {        
        let pathfile = Vmm::impl_reg_pathsplit(self.path.as_str())?;
        let result = self.vmm.impl_reg_key(pathfile.0)?;
        return Ok(result);
    }

    #[allow(unused_assignments)]
    fn impl_subkeys(&self) -> ResultEx<Vec<VmmRegKey>> {
        unsafe {
            let mut ft_last_write = 0;
            let mut cch = 0;
            let mut i = 0;
            let mut data = [0; MAX_PATH+1];
            let c_path = CString::new(self.path.as_str())?;
            let mut result = Vec::new();
            loop {
                cch = data.len() as u32 - 1;
                let r = (self.vmm.native.VMMDLL_WinReg_EnumKeyExU)(self.vmm.native.h, c_path.as_ptr(), i, data.as_mut_ptr(), &mut cch, &mut ft_last_write);
                if !r {
                    break;
                }
                let name = cstr_to_string_lossy(data.as_ptr());
                let path = format!("{}\\{}", self.path, name);
                let e = VmmRegKey {
                    vmm : self.vmm,
                    name,
                    path,
                    ft_last_write,
                };
                result.push(e);
                i += 1;
            }
            return Ok(result);
        }
    }

    fn impl_values(&self) -> ResultEx<Vec<VmmRegValue>> {
        return Err(anyhow!("Not implemented"));
    }
}

impl VmmRegValue<'_> {
    fn impl_parent(&self) -> ResultEx<VmmRegKey> {        
        let pathfile = Vmm::impl_reg_pathsplit(self.path.as_str())?;
        let result = self.vmm.impl_reg_key(pathfile.0)?;
        return Ok(result);
    }

    fn impl_raw_value(&self) -> ResultEx<Vec<u8>> {
            if self.raw_value.is_some() {
                return Ok(self.raw_value.as_ref().unwrap().clone());
            }
            // size larger than 64 bytes -> not cached in VmmRegValue.
            if self.raw_size > 0x01000000 {
                return Err(anyhow!("VmmRegKey size too large (>16MB)."));
            }
            let mut raw_value = vec![0; self.raw_size as usize];
            let c_path = CString::new(self.path.clone())?;
            let mut raw_size = self.raw_size;
            let r = (self.vmm.native.VMMDLL_WinReg_QueryValueExU)(self.vmm.native.h, c_path.as_ptr(), std::ptr::null_mut(), raw_value.as_mut_ptr(), &mut raw_size);
            if !r {
                return Err(anyhow!("VMMDLL_WinReg_QueryValueExU: fail."));
            }
            return Ok(raw_value);
    }

    fn impl_value(&self) -> ResultEx<VmmRegValueType> {
        const REG_NONE                      : u32 = 0;
        const REG_SZ                        : u32 = 1;
        const REG_EXPAND_SZ                 : u32 = 2;
        const REG_BINARY                    : u32 = 3;
        const REG_DWORD                     : u32 = 4;
        const REG_DWORD_BIG_ENDIAN          : u32 = 5;
        const REG_LINK                      : u32 = 6;
        const REG_MULTI_SZ                  : u32 = 7;
        const REG_RESOURCE_LIST             : u32 = 8;
        const REG_FULL_RESOURCE_DESCRIPTOR  : u32 = 9;
        const REG_RESOURCE_REQUIREMENTS_LIST: u32 = 10;
        const REG_QWORD                     : u32 = 11;
        // Sanity checks and REG_NONE type:
        if self.raw_type == REG_NONE {
            return Ok(VmmRegValueType::REG_NONE);
        }
        if self.raw_type > REG_QWORD {
            return Err(anyhow!("Unknown registry value type."));
        }
        // Get data using method call since data may be larger than cached data.
        let raw_value = self.raw_value()?;
        match self.raw_type {
            REG_BINARY => return Ok(VmmRegValueType::REG_BINARY(raw_value)),
            REG_RESOURCE_LIST => return Ok(VmmRegValueType::REG_RESOURCE_LIST(raw_value)),
            REG_FULL_RESOURCE_DESCRIPTOR => return Ok(VmmRegValueType::REG_FULL_RESOURCE_DESCRIPTOR(raw_value)),
            REG_RESOURCE_REQUIREMENTS_LIST => return Ok(VmmRegValueType::REG_RESOURCE_REQUIREMENTS_LIST(raw_value)),
            _ => (),
        };
        if self.raw_type == REG_DWORD {
            let v : [u8; 4] = raw_value.as_slice().try_into()?;
            return Ok(VmmRegValueType::REG_DWORD(u32::from_le_bytes(v)));
        }
        if self.raw_type == REG_DWORD_BIG_ENDIAN {
            let v : [u8; 4] = raw_value.as_slice().try_into()?;
            return Ok(VmmRegValueType::REG_DWORD_BIG_ENDIAN(u32::from_be_bytes(v)));
        }
        if self.raw_type == REG_QWORD {
            let v : [u8; 8] = raw_value.as_slice().try_into()?;
            return Ok(VmmRegValueType::REG_QWORD(u64::from_le_bytes(v)));
        }
        // UTF16 below
        if raw_value.len() % 2 == 1 {
            return Err(anyhow!("Invalid size"));
        }
        let mut raw_chars = vec![0u16; raw_value.len() / 2];
        unsafe {
            // this will only work on little-endian archs (which should be most)
            std::ptr::copy_nonoverlapping(raw_value.as_ptr(), raw_chars.as_mut_ptr() as *mut u8, raw_value.len());
        }
        if self.raw_type == REG_MULTI_SZ {
            let mut result_vec = Vec::new();
            for raw_string in raw_chars.split(|v| *v == 0) {
                if raw_string.len() > 0 {
                    result_vec.push(String::from_utf16_lossy(raw_string));
                }
            }
            return Ok(VmmRegValueType::REG_MULTI_SZ(result_vec));
        }
        // SZ EXPAND_SZ, LINK
        let mut result_string = "".to_string();
        if let Some(raw_string) = raw_chars.split(|v| *v == 0).next() {
            result_string = String::from_utf16_lossy(raw_string);
        }
        match self.raw_type {
            REG_SZ => return Ok(VmmRegValueType::REG_SZ(result_string)),
            REG_EXPAND_SZ => return Ok(VmmRegValueType::REG_EXPAND_SZ(result_string)),
            REG_LINK => return Ok(VmmRegValueType::REG_LINK(result_string)),
            _ => return Err(anyhow!("[err]")),
        };
    }
}






//=============================================================================
// INTERNAL: VMM.PROCESS:
//=============================================================================

impl fmt::Display for VmmProcess<'_> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "VmmProcess:{}", self.pid & 0x7fffffff)
    }
}

impl PartialEq for VmmProcess<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.pid == other.pid
    }
}

impl fmt::Display for VmmProcessInfo {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "VmmProcessInfo:{}:{}", self.pid & 0x7fffffff, self.name)
    }
}

impl fmt::Display for VmmProcessMapEatEntry {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "VmmProcessMapEatEntry:{:x}:{}", self.va_function, self.function)
    }
}

impl fmt::Display for VmmProcessMapHandleEntry {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "VmmProcessMapHandleEntry:{}:{:x}:{}:[{}]", self.pid & 0x7fffffff, self.handle_id, self.tp, self.info)
    }
}

impl From<u32> for VmmProcessMapHeapType {
    fn from(v : u32) -> Self {
        return match v {
            1 => VmmProcessMapHeapType::NtHeap,
            2 => VmmProcessMapHeapType::SegmentHeap,
            _ => VmmProcessMapHeapType::NA,
        };
    }
}

impl fmt::Display for VmmProcessMapHeapType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let v = match self {
            VmmProcessMapHeapType::NA => "NA",
            VmmProcessMapHeapType::NtHeap => "NtHeap",
            VmmProcessMapHeapType::SegmentHeap => "SegmentHeap",
        };
        write!(f, "{v}")
    }
}

impl fmt::Display for VmmProcessMapHeapEntry {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "VmmProcessMapHeapAllocEntry:{}:{}:{}", self.pid & 0x7fffffff, self.number, self.tp)
    }
}

impl From<u32> for VmmProcessMapHeapAllocType {
    fn from(v : u32) -> Self {
        return match v {
            1 => VmmProcessMapHeapAllocType::NtHeap,
            2 => VmmProcessMapHeapAllocType::NtLFH,
            3 => VmmProcessMapHeapAllocType::NtLarge,
            4 => VmmProcessMapHeapAllocType::NtNA,
            5 => VmmProcessMapHeapAllocType::SegVS,
            6 => VmmProcessMapHeapAllocType::SegLFH,
            7 => VmmProcessMapHeapAllocType::SegLarge,
            8 => VmmProcessMapHeapAllocType::SegNA,
            _ => VmmProcessMapHeapAllocType::NA,
        };
    }
}

impl fmt::Display for VmmProcessMapHeapAllocType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let v = match self {
            VmmProcessMapHeapAllocType::NA => "NA",
            VmmProcessMapHeapAllocType::NtHeap => "NtHeap",
            VmmProcessMapHeapAllocType::NtLFH => "NtLFH",
            VmmProcessMapHeapAllocType::NtLarge => "NtLarge",
            VmmProcessMapHeapAllocType::NtNA => "NtNA",
            VmmProcessMapHeapAllocType::SegVS => "SegVS",
            VmmProcessMapHeapAllocType::SegLFH => "SegLFH",
            VmmProcessMapHeapAllocType::SegLarge => "SegLarge",
            VmmProcessMapHeapAllocType::SegNA => "SegNA",
        };
        write!(f, "{v}")
    }
}

impl fmt::Display for VmmProcessMapHeapAllocEntry {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "VmmProcessMapHeapAllocEntry:{}:{}:{:x}", self.pid & 0x7fffffff, self.tp, self.va)
    }
}

impl fmt::Display for VmmProcessMapIatEntry {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "VmmProcessMapIatEntry:{:x}:{}", self.va_function, self.function)
    }
}

impl fmt::Display for VmmProcessMapPteEntry {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "VmmProcessMapPteEntry:{}:{:x}->{:x}", self.pid & 0x7fffffff, self.va_base, self.va_base + self.page_count * 0x1000 - 1)
    }
}

impl fmt::Display for VmmProcessMapModuleEntry {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "VmmProcessMapModuleEntry:{}:{:x}:[{}]", self.pid & 0x7fffffff, self.va_base, self.name)
    }
}

impl fmt::Display for VmmProcessMapModuleDebugEntry {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "VmmProcessMapModuleDebugEntry:[{}]", self.pdb_filename)
    }
}

impl fmt::Display for VmmProcessMapModuleVersionEntry {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "VmmProcessMapModuleVersionEntry")
    }
}

impl fmt::Display for VmmProcessMapThreadEntry {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "VmmProcessMapThreadEntry:{}:{:x}", self.pid & 0x7fffffff, self.thread_id)
    }
}

impl fmt::Display for VmmProcessMapThreadCallstackEntry {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "VmmProcessMapThreadEntry:{}:{}:{:02x}:{:016x}:{:016x}:[{}!{}+{:x}]", self.pid & 0x7fffffff, self.tid, self.i, self.va_rsp, self.va_ret_addr, self.module, self.function, self.displacement)
    }
}

impl fmt::Display for VmmProcessMapUnloadedModuleEntry {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "VmmProcessMapUnloadedModuleEntry:{}:{:x}:[{}]", self.pid & 0x7fffffff, self.va_base, self.name)
    }
}

impl fmt::Display for VmmProcessMapVadEntry {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "VmmProcessMapVadEntry:{}:{:x}->{}", self.pid & 0x7fffffff, self.va_start, self.va_end)
    }
}

impl From<u32> for VmmProcessMapVadExType {
    fn from(v : u32) -> Self {
        return match v {
            1 => VmmProcessMapVadExType::Hardware,
            2 => VmmProcessMapVadExType::Transition,
            3 => VmmProcessMapVadExType::Prototype,
            4 => VmmProcessMapVadExType::DemandZero,
            5 => VmmProcessMapVadExType::Compressed,
            6 => VmmProcessMapVadExType::Pagefile,
            7 => VmmProcessMapVadExType::File,
            _ => VmmProcessMapVadExType::NA,
        };
    }
}

impl fmt::Display for VmmProcessMapVadExType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let v = match self {
            VmmProcessMapVadExType::NA => "NA",
            VmmProcessMapVadExType::Hardware => "Hardware",
            VmmProcessMapVadExType::Transition => "Transition",
            VmmProcessMapVadExType::Prototype => "Prototype",
            VmmProcessMapVadExType::DemandZero => "DemandZero",
            VmmProcessMapVadExType::Compressed => "Compressed",
            VmmProcessMapVadExType::Pagefile => "Pagefile",
            VmmProcessMapVadExType::File => "File",
        };
        write!(f, "{v}")
    }
}

impl fmt::Display for VmmProcessMapVadExEntry {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "VmmProcessMapVadExEntry:{}:{:x}:{}", self.pid & 0x7fffffff, self.va, self.tp)
    }
}

impl fmt::Display for VmmProcessMapDirectoryEntry {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "VmmProcessMapDirectoryEntry:{}:{}:{:x}:{:x}", self.pid & 0x7fffffff, self.name, self.virtual_address, self.size)
    }
}

impl fmt::Display for VmmProcessSectionEntry {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "VmmProcessSectionEntry:{}:[{}]:{:x}:{:x}", self.pid & 0x7fffffff, self.name, self.virtual_address, self.misc_virtual_size)
    }
}

impl From<u32> for VmmProcessMapModuleType {
    fn from(v : u32) -> Self {
        return match v {
            1 => VmmProcessMapModuleType::Data,
            2 => VmmProcessMapModuleType::NotLinked,
            3 => VmmProcessMapModuleType::Injected,
            _ => VmmProcessMapModuleType::Normal,
        };
    }
}

impl fmt::Display for VmmProcessMapModuleType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let v = match self {
            VmmProcessMapModuleType::Data => "Data",
            VmmProcessMapModuleType::NotLinked => "NotLinked",
            VmmProcessMapModuleType::Injected => "Injected",
            VmmProcessMapModuleType::Normal => "Normal",
        };
        write!(f, "{v}")
    }
}

#[repr(C)]
#[allow(non_snake_case)]
struct CProcessInformation {
    magic : u64,
    wVersion : u16,
    wSize : u16,
    tpMemoryModel : u32,
    tpSystem : u32,
    fUserOnly : bool,
    dwPID : u32,
    dwPPID : u32,
    dwState : u32,
    szName : [c_char; 16],
    szNameLong : [c_char; 64],
    paDTB : u64,
    paDTB_UserOpt : u64,
    vaEPROCESS : u64,
    vaPEB : u64,
    _Reserved1 : u64,
    fWow64 : bool,
    vaPEB32 : u32,
    dwSessionId : u32,
    qwLUID : u64,
    szSID : [c_char; 260],
    IntegrityLevel : u32,
}

#[repr(C)]
#[allow(non_snake_case, non_camel_case_types)]
#[derive(Clone, Default)]
struct CIMAGE_SECTION_HEADER {
    Name : [u8; 8],
    Misc_VirtualAddress : u32,
    VirtualAddress : u32,
    SizeOfRawData : u32,
    PointerToRawData : u32,
    PointerToRelocations : u32,
    PointerToLinenumbers : u32,
    NumberOfRelocations : u16,
    NumberOfLinenumbers : u16,
    Characteristics : u32,
}

#[repr(C)]
#[allow(non_snake_case, non_camel_case_types)]
#[derive(Clone, Default)]
struct CIMAGE_DATA_DIRECTORY {
    VirtualAddress : u32,
    Size : u32,
}

#[repr(C)]
#[allow(non_snake_case)]
struct CEatEntry {
    vaFunction : u64,
    dwOrdinal : u32,
    oFunctionsArray : u32,
    oNamesArray : u32,
    _FutureUse1 : u32,
    uszFunction : *const c_char,
    uszForwardedFunction : *const c_char,
}

#[repr(C)]
#[allow(non_snake_case)]
struct CEatMap {
    dwVersion : u32,
    dwOrdinalBase : u32,
    cNumberOfNames : u32,
    cNumberOfFunctions : u32,
    cNumberOfForwardedFunctions : u32,
    _Reserved1 : [u32; 3],
    vaModuleBase : u64,
    vaAddressOfFunctions : u64,
    vaAddressOfNames : u64,
    pbMultiText : *const c_char,
    cbMultiText : u32,
    cMap : u32,
    pMap : CEatEntry,
}

#[repr(C)]
#[allow(non_snake_case)]
struct CHandleEntry {
    vaObject : u64,
    dwHandle : u32,
    dwGrantedAccess_Tp : u32,
    qwHandleCount : u64,
    qwPointerCount : u64,
    vaObjectCreateInfo : u64,
    vaSecurityDescriptor : u64,
    uszText : *const c_char,
    _FutureUse2 : u32,
    dwPID : u32,
    dwPoolTag : u32,
    _FutureUse : [u32; 7],
    uszType : *const c_char,
}

#[repr(C)]
#[allow(non_snake_case)]
struct CHandleMap {
    dwVersion : u32,
    _Reserved1 : [u32; 5],
    pbMultiText : *const c_char,
    cbMultiText : u32,
    cMap : u32,
    pMap : CHandleEntry,
}

#[repr(C)]
#[allow(non_snake_case)]
struct CHeapEntry {
    va : u64,
    tp : u32,
    f32 : bool,
    iHeap : u32,
    dwHeapNum : u32,
}

#[repr(C)]
#[allow(non_snake_case)]
struct CHeapMap {
    dwVersion : u32,
    _Reserved1 : [u32; 7],
    pSegments : usize,
    cSegments : u32,
    cMap : u32,
    pMap : CHeapEntry,
}

#[repr(C)]
#[allow(non_snake_case)]
struct CHeapAllocEntry {
    va : u64,
    cb : u32,
    tp : u32,
}

#[repr(C)]
#[allow(non_snake_case)]
struct CHeapAllocMap {
    dwVersion : u32,
    _Reserved1 : [u32; 7],
    _Reserved2 : [usize; 2],
    cMap : u32,
    pMap : CHeapAllocEntry,
}

#[repr(C)]
#[allow(non_snake_case)]
struct CIatEntry {
    vaFunction : u64,
    uszFunction : *const c_char,
    _FutureUse1 : u32,
    _FutureUse2 : u32,
    uszModule : *const c_char,
    thunk_f32 : bool,
    thunk_wHint : u16,
    thunk__Reserved1 : u16,
    thunk_rvaFirstThunk : u32,
    thunk_rvaOriginalFirstThunk : u32,
    thunk_rvaNameModule : u32,
    thunk_rvaNameFunction : u32,
}

#[repr(C)]
#[allow(non_snake_case)]
struct CIatMap {
    dwVersion : u32,
    _Reserved1 : [u32; 5],
    vaModuleBase : u64,
    pbMultiText : *const c_char,
    cbMultiText : u32,
    cMap : u32,
    pMap : CIatEntry,
}

#[repr(C)]
#[allow(non_snake_case)]
struct CDebugInfo {
    dwAge : u32,
    _Reserved : u32,
    Guid : [u8; 16],
    uszGuid : *const c_char,
    uszPdbFilename : *const c_char,
}

#[repr(C)]
#[allow(non_snake_case)]
struct CVersionInfo {
    uszCompanyName : *const c_char,
    uszFileDescription : *const c_char,
    uszFileVersion : *const c_char,
    uszInternalName : *const c_char,
    uszLegalCopyright : *const c_char,
    uszOriginalFilename : *const c_char,
    uszProductName : *const c_char,
    uszProductVersion : *const c_char,
}

#[repr(C)]
#[allow(non_snake_case)]
struct CModuleEntry {
    vaBase : u64,
    vaEntry : u64,
    cbImageSize : u32,
    fWoW64 : bool,
    uszText : *const c_char,
    _Reserved3 : u32,
    _Reserved4 : u32,
    uszFullName : *const c_char,
    tp : u32,
    cbFileSizeRaw : u32,
    cSection : u32,
    cEAT : u32,
    cIAT : u32,
    _Reserved2 : u32,
    _Reserved1 : [u64; 3],
    pExDebugInfo : *const CDebugInfo,
    pExVersionInfo : *const CVersionInfo,
}

#[repr(C)]
#[allow(non_snake_case)]
struct CModuleMap {
    dwVersion : u32,
    _Reserved1 : [u32; 5],
    pbMultiText : *const c_char,
    cbMultiText : u32,
    cMap : u32,
    pMap : CModuleEntry,
}

#[repr(C)]
#[allow(non_snake_case)]
struct CPteEntry {
    vaBase : u64,
    cPages : u64,
    fPage : u64,
    fWoW64 : bool,
    _FutureUse1 : u32,
    uszText : *const c_char,
    _Reserved1 : u32,
    cSoftware : u32,
}

#[repr(C)]
#[allow(non_snake_case)]
struct CPteMap {
    dwVersion : u32,
    _Reserved1 : [u32; 5],
    pbMultiText : *const c_char,
    cbMultiText : u32,
    cMap : u32,
    pMap : CPteEntry,
}

#[repr(C)]
#[allow(non_snake_case)]
struct CThreadEntry {
    dwTID : u32,
    dwPID : u32,
    dwExitStatus : u32,
    bState : u8,
    bRunning : u8,
    bPriority : u8,
    bBasePriority : u8,
    vaETHREAD : u64,
    vaTeb : u64,
    ftCreateTime : u64,
    ftExitTime : u64,
    vaStartAddress : u64,
    vaStackBaseUser : u64,
    vaStackLimitUser : u64,
    vaStackBaseKernel : u64,
    vaStackLimitKernel : u64,
    vaTrapFrame : u64,
    vaRIP : u64,
    vaRSP : u64,
    qwAffinity : u64,
    dwUserTime : u32,
    dwKernelTime : u32,
    bSuspendCount : u8,
    bWaitReason : u8,
    _FutureUse1 : [u8; 2],
    _FutureUse2 : [u32; 11],
    vaImpersonationToken : u64,
    vaWin32StartAddress : u64,
}

#[repr(C)]
#[allow(non_snake_case)]
struct CThreadMap {
    dwVersion : u32,
    _Reserved1 : [u32; 8],
    cMap : u32,
    pMap : CThreadEntry,
}

#[repr(C)]
#[allow(non_snake_case)]
struct CThreadCallstackEntry {
    i : u32,
    fRegPresent : bool,
    vaRetAddr : u64,
    vaRSP : u64,
    vaBaseSP : u64,
    _FutureUse1 : u32,
    cbDisplacement : i32,
    uszModule : *const c_char,
    uszFunction : *const c_char,
}

#[repr(C)]
#[allow(non_snake_case)]
struct CThreadCallstackMap {
    dwVersion : u32,
    _Reserved1 : [u32; 6],
    dwPID : u32,
    dwTID : u32,
    cbText : u32,
    uszText : *const c_char,
    pbMultiText : *const c_char,
    cbMultiText : u32,
    cMap : u32,
    pMap : CThreadCallstackEntry,
}

#[repr(C)]
#[allow(non_snake_case)]
struct CUnloadedModuleEntry {
    vaBase : u64,
    cbImageSize : u32,
    fWoW64 : bool,
    uszText : *const c_char,
    _FutureUse1 : u32,
    dwCheckSum : u32,
    dwTimeDateStamp : u32,
    _Reserved1 : u32,
    ftUnload : u64,
}

#[repr(C)]
#[allow(non_snake_case)]
struct CUnloadedModuleMap {
    dwVersion : u32,
    _Reserved1 : [u32; 5],
    pbMultiText : *const c_char,
    cbMultiText : u32,
    cMap : u32,
    pMap : CUnloadedModuleEntry,
}

#[repr(C)]
#[allow(non_snake_case)]
struct CVadEntry {
    vaStart : u64,
    vaEnd : u64,
    vaVad : u64,
    u0 : u32,
    u1 : u32,
    u2 : u32,
    cbPrototypePte : u32,
    vaPrototypePte : u64,
    vaSubsection : u64,
    uszText : *const c_char,
    _FutureUse1 : u32,
    _Reserved1 : u32,
    vaFileObject : u64,
    cVadExPages : u32,
    cVadExPagesBase : u32,
    _Reserved2 : u64,
}

#[repr(C)]
#[allow(non_snake_case)]
struct CVadMap {
    dwVersion : u32,
    _Reserved1 : [u32; 4],
    cPage : u32,
    pbMultiText : *const c_char,
    cbMultiText : u32,
    cMap : u32,
    pMap : CVadEntry,
}

#[repr(C)]
#[allow(non_snake_case)]
struct CVadExEntry {
    tp : u32,
    iPML : u8,
    pteFlags : u8,
    _Reserved2 : u16,
    va : u64,
    pa : u64,
    pte : u64,
    proto__Reserved1 : u32,
    proto_tp : u32,
    proto_pa : u64,
    proto_va : u64,
    vaVadBase : u64,
}

#[repr(C)]
#[allow(non_snake_case)]
struct CVadExMap {
    dwVersion : u32,
    _Reserved1 : [u32; 4],
    cMap : u32,
    pMap : CVadExEntry,
}

#[allow(non_snake_case)]
impl VmmProcess<'_> {
    fn impl_info(&self) -> ResultEx<VmmProcessInfo> {
        let mut cb_pi = std::mem::size_of::<CProcessInformation>();
        let mut pi = CProcessInformation {
            magic : VMMDLL_PROCESS_INFORMATION_MAGIC,
            wVersion : VMMDLL_PROCESS_INFORMATION_VERSION,
            wSize : u16::try_from(cb_pi)?,
            tpMemoryModel : 0,
            tpSystem : 0,
            fUserOnly : false,
            dwPID : 0,
            dwPPID : 0,
            dwState : 0,
            szName : [0; 16],
            szNameLong : [0; 64],
            paDTB : 0,
            paDTB_UserOpt : 0,
            vaEPROCESS : 0,
            vaPEB : 0,
            _Reserved1 : 0,
            fWow64 : false,
            vaPEB32 : 0,
            dwSessionId : 0,
            qwLUID : 0,
            szSID : [0; 260],
            IntegrityLevel : 0,
        };
        let raw_pi = &mut pi as *mut CProcessInformation;
        let r = (self.vmm.native.VMMDLL_ProcessGetInformation)(self.vmm.native.h, self.pid, raw_pi, &mut cb_pi);
        if !r {
            return Err(anyhow!("VMMDLL_ProcessGetInformation: fail."));
        }
        let result = VmmProcessInfo {
            tp_system : VmmSystemType::from(pi.tpSystem),
            tp_memorymodel : VmmMemoryModelType::from(pi.tpMemoryModel),
            is_user_mode : pi.fUserOnly,
            pid : pi.dwPID,
            ppid : pi.dwPPID,
            state : pi.dwState,
            name : unsafe { cstr_to_string_lossy(&pi.szName as *const c_char) },
            name_long : unsafe { cstr_to_string_lossy(&pi.szNameLong as *const c_char) },
            pa_dtb : pi.paDTB,
            pa_dtb_user : pi.paDTB_UserOpt,
            va_eprocess : pi.vaEPROCESS,
            va_peb : pi.vaPEB,
            is_wow64 : pi.fWow64,
            va_peb32 : pi.vaPEB32,
            session_id : pi.dwSessionId,
            luid : pi.qwLUID,
            sid : unsafe { cstr_to_string_lossy(&pi.szSID as *const c_char) },
            integrity_level : VmmIntegrityLevelType::from(pi.IntegrityLevel),
        };
        return Ok(result);
    }

    fn impl_get_information_string(&self, option : u32) -> ResultEx<String> {
        let r = (self.vmm.native.VMMDLL_ProcessGetInformationString)(self.vmm.native.h, self.pid, option);
        if r.is_null() {
            return Err(anyhow!("VMMDLL_ProcessGetInformationString: fail."));
        }
        let result = unsafe { cstr_to_string_lossy(r) };
        (self.vmm.native.VMMDLL_MemFree)(r as usize);
        return Ok(result);
    }
    
    fn impl_get_module_base(&self, module_name : &str) -> ResultEx<u64> {
        let sz_module_name = CString::new(module_name)?;
        let r = (self.vmm.native.VMMDLL_ProcessGetModuleBaseU)(self.vmm.native.h, self.pid, sz_module_name.as_ptr());
        if r == 0 {
            return Err(anyhow!("VMMDLL_ProcessGetModuleBaseU: fail."));
        }
        return Ok(r);
    }

    fn impl_get_proc_address(&self, module_name : &str, function_name : &str) -> ResultEx<u64> {
        let sz_module_name = CString::new(module_name)?;
        let sz_function_name = CString::new(function_name)?;
        let r = (self.vmm.native.VMMDLL_ProcessGetProcAddressU)(self.vmm.native.h, self.pid, sz_module_name.as_ptr(), sz_function_name.as_ptr());
        if r == 0 {
            return Err(anyhow!("VMMDLL_ProcessGetProcAddressU: fail."));
        }
        return Ok(r);
    }

    fn impl_pdb_from_module_name(&self, module_name : &str) -> ResultEx<VmmPdb> {
        let va_module_base = self.get_module_base(module_name)?;
        return self.impl_pdb_from_module_address(va_module_base);
    }

    fn impl_pdb_from_module_address(&self, va_module_base : u64) -> ResultEx<VmmPdb> {
        let mut szModuleName = [0i8; MAX_PATH + 1];
        let r = (self.vmm.native.VMMDLL_PdbLoad)(self.vmm.native.h, self.pid, va_module_base, szModuleName.as_mut_ptr() as *mut c_char);
        if !r {
            return Err(anyhow!("VMMDLL_PdbLoad: fail."));
        }
        let module = unsafe { cstr_to_string_lossy(szModuleName.as_ptr() as *const c_char) };
        let pdb = VmmPdb {
            vmm : self.vmm,
            module,
        };
        return Ok(pdb);
    }

    fn impl_map_handle(&self) -> ResultEx<Vec<VmmProcessMapHandleEntry>> {
        unsafe {
            let mut structs = std::ptr::null_mut();
            let r = (self.vmm.native.VMMDLL_Map_GetHandleU)(self.vmm.native.h, self.pid, &mut structs);
            if !r {
                return Err(anyhow!("VMMDLL_Map_GetHandleU: fail."));
            }
            if (*structs).dwVersion != VMMDLL_MAP_HANDLE_VERSION {
                (self.vmm.native.VMMDLL_MemFree)(structs as usize);
                return Err(anyhow!("VMMDLL_Map_GetHandleU: bad version [{} != {}].", (*structs).dwVersion, VMMDLL_MAP_HANDLE_VERSION));
            }
            let mut result = Vec::new();
            if (*structs).cMap == 0 {
                (self.vmm.native.VMMDLL_MemFree)(structs as usize);
                return Ok(result);
            }
            let cMap : usize = (*structs).cMap.try_into()?;
            let pMap = std::slice::from_raw_parts(&(*structs).pMap, cMap);
            for i in 0..cMap {
                let ne = &pMap[i];
                let e = VmmProcessMapHandleEntry {
                    pid : self.pid,
                    va_object : ne.vaObject,
                    handle_id : ne.dwHandle,
                    granted_access : ne.dwGrantedAccess_Tp & 0x00ffffff,
                    type_index : (ne.dwGrantedAccess_Tp >> 24) & 0xff,
                    handle_count : ne.qwHandleCount,
                    pointer_count : ne.qwPointerCount,
                    va_object_create_info : ne.vaObjectCreateInfo,
                    va_security_descriptor : ne.vaSecurityDescriptor,
                    handle_pid : ne.dwPID,
                    pool_tag : ne.dwPoolTag,
                    info : cstr_to_string(ne.uszText),
                    tp : cstr_to_string(ne.uszType),
                };
                result.push(e);
            }
            (self.vmm.native.VMMDLL_MemFree)(structs as usize);
            return Ok(result);
        }
    }

    fn impl_map_heap(&self) -> ResultEx<Vec<VmmProcessMapHeapEntry>> {
        unsafe {
            let mut structs = std::ptr::null_mut();
            let r = (self.vmm.native.VMMDLL_Map_GetHeap)(self.vmm.native.h, self.pid, &mut structs);
            if !r {
                return Err(anyhow!("VMMDLL_Map_GetHeap: fail."));
            }
            if (*structs).dwVersion != VMMDLL_MAP_HEAP_VERSION {
                (self.vmm.native.VMMDLL_MemFree)(structs as usize);
                return Err(anyhow!("VMMDLL_Map_GetHeap: bad version [{} != {}].", (*structs).dwVersion, VMMDLL_MAP_HEAP_VERSION));
            }
            let mut result = Vec::new();
            if (*structs).cMap == 0 {
                (self.vmm.native.VMMDLL_MemFree)(structs as usize);
                return Ok(result);
            }
            let cMap : usize = (*structs).cMap.try_into()?;
            let pMap = std::slice::from_raw_parts(&(*structs).pMap, cMap);
            for i in 0..cMap {
                let ne = &pMap[i];
                let e = VmmProcessMapHeapEntry {
                    pid : self.pid,
                    tp : VmmProcessMapHeapType::from(ne.tp),
                    is_32 : ne.f32,
                    index : ne.iHeap,
                    number : ne.dwHeapNum,
                };
                result.push(e);
            }
            (self.vmm.native.VMMDLL_MemFree)(structs as usize);
            return Ok(result);
        }
    }

    fn impl_map_heapalloc(&self, heap_number_or_address : u64) -> ResultEx<Vec<VmmProcessMapHeapAllocEntry>> {
        unsafe {
            let mut structs = std::ptr::null_mut();
            let r = (self.vmm.native.VMMDLL_Map_GetHeapAlloc)(self.vmm.native.h, self.pid, heap_number_or_address, &mut structs);
            if !r {
                return Err(anyhow!("VMMDLL_Map_GetHeapAlloc: fail."));
            }
            if (*structs).dwVersion != VMMDLL_MAP_HEAPALLOC_VERSION {
                (self.vmm.native.VMMDLL_MemFree)(structs as usize);
                return Err(anyhow!("VMMDLL_Map_GetHeapAlloc: bad version [{} != {}].", (*structs).dwVersion, VMMDLL_MAP_HEAPALLOC_VERSION));
            }
            let mut result = Vec::new();
            if (*structs).cMap == 0 {
                (self.vmm.native.VMMDLL_MemFree)(structs as usize);
                return Ok(result);
            }
            let cMap : usize = (*structs).cMap.try_into()?;
            let pMap = std::slice::from_raw_parts(&(*structs).pMap, cMap);
            for i in 0..cMap {
                let ne = &pMap[i];
                let e = VmmProcessMapHeapAllocEntry {
                    pid : self.pid,
                    va : ne.va,
                    size : ne.cb,
                    tp : VmmProcessMapHeapAllocType::from(ne.tp),
                };
                result.push(e);
            }
            (self.vmm.native.VMMDLL_MemFree)(structs as usize);
            return Ok(result);
        }
    }

    fn impl_map_module(&self, is_info_debug : bool, is_info_version : bool) -> ResultEx<Vec<VmmProcessMapModuleEntry>> {
        unsafe {
            let mut structs = std::ptr::null_mut();
            let flags = 0 + if is_info_debug { 1 } else { 0 } + if is_info_version { 2 } else { 0 };
            let r = (self.vmm.native.VMMDLL_Map_GetModuleU)(self.vmm.native.h, self.pid, &mut structs, flags);
            if !r {
                return Err(anyhow!("VMMDLL_Map_GetModuleU: fail."));
            }
            if (*structs).dwVersion != VMMDLL_MAP_MODULE_VERSION {
                (self.vmm.native.VMMDLL_MemFree)(structs as usize);
                return Err(anyhow!("VMMDLL_Map_GetModuleU: bad version [{} != {}].", (*structs).dwVersion, VMMDLL_MAP_MODULE_VERSION));
            }
            let mut result = Vec::new();
            if (*structs).cMap == 0 {
                (self.vmm.native.VMMDLL_MemFree)(structs as usize);
                return Ok(result);
            }
            let cMap : usize = (*structs).cMap.try_into()?;
            let pMap = std::slice::from_raw_parts(&(*structs).pMap, cMap);
            for i in 0..cMap {
                let ne = &pMap[i];
                let mut debug_info = None;
                if !ne.pExDebugInfo.is_null() {
                    let nei = &*ne.pExDebugInfo;
                    debug_info = Some(VmmProcessMapModuleDebugEntry {
                        pid : self.pid,
                        age : nei.dwAge,
                        raw_guid : nei.Guid,
                        guid : cstr_to_string(nei.uszGuid),
                        pdb_filename : cstr_to_string(nei.uszPdbFilename),
                    });
                }
                let mut version_info = None;
                if !ne.pExVersionInfo.is_null() {
                    let nei = &*ne.pExVersionInfo;
                    version_info = Some(VmmProcessMapModuleVersionEntry {
                        pid : self.pid,
                        company_name : cstr_to_string(nei.uszCompanyName),
                        file_description : cstr_to_string(nei.uszFileDescription),
                        file_version : cstr_to_string(nei.uszFileVersion),
                        internal_name : cstr_to_string(nei.uszInternalName),
                        legal_copyright : cstr_to_string(nei.uszLegalCopyright),
                        original_file_name : cstr_to_string(nei.uszOriginalFilename),
                        product_name : cstr_to_string(nei.uszProductName),
                        product_version : cstr_to_string(nei.uszProductVersion),
                    });
                }
                let e = VmmProcessMapModuleEntry {
                    pid : self.pid,
                    va_base : ne.vaBase,
                    va_entry : ne.vaEntry,
                    image_size : ne.cbImageSize,
                    is_wow64 : ne.fWoW64,
                    tp : VmmProcessMapModuleType::from(ne.tp),
                    name : cstr_to_string(ne.uszText),
                    full_name : cstr_to_string(ne.uszFullName),
                    file_size_raw : ne.cbFileSizeRaw,
                    section_count : ne.cSection,
                    eat_count : ne.cEAT,
                    iat_count : ne.cIAT,
                    debug_info : debug_info,
                    version_info : version_info,
                };
                result.push(e);
            }
            (self.vmm.native.VMMDLL_MemFree)(structs as usize);
            return Ok(result);
        }
    }

    fn impl_map_module_eat(&self, module_name : &str) -> ResultEx<Vec<VmmProcessMapEatEntry>> {
        unsafe {
            let mut structs = std::ptr::null_mut();
            let sz_module_name = CString::new(module_name)?;
            let r = (self.vmm.native.VMMDLL_Map_GetEATU)(self.vmm.native.h, self.pid, sz_module_name.as_ptr(), &mut structs);
            if !r {
                return Err(anyhow!("VMMDLL_Map_GetEATU: fail."));
            }
            if (*structs).dwVersion != VMMDLL_MAP_EAT_VERSION {
                (self.vmm.native.VMMDLL_MemFree)(structs as usize);
                return Err(anyhow!("VMMDLL_Map_GetEATU: bad version [{} != {}].", (*structs).dwVersion, VMMDLL_MAP_EAT_VERSION));
            }
            let mut result = Vec::new();
            if (*structs).cMap == 0 {
                (self.vmm.native.VMMDLL_MemFree)(structs as usize);
                return Ok(result);
            }
            let cMap : usize = (*structs).cMap.try_into()?;
            let pMap = std::slice::from_raw_parts(&(*structs).pMap, cMap);
            for i in 0..cMap {
                let ne = &pMap[i];
                let e = VmmProcessMapEatEntry {
                    pid : self.pid,
                    va_function : ne.vaFunction,
                    ordinal : ne.dwOrdinal,
                    function : cstr_to_string(ne.uszFunction),
                    forwarded_function : cstr_to_string(ne.uszForwardedFunction),
                };
                result.push(e);
            }
            (self.vmm.native.VMMDLL_MemFree)(structs as usize);
            return Ok(result);
        }
    }

    fn impl_map_module_iat(&self, module_name : &str) -> ResultEx<Vec<VmmProcessMapIatEntry>> {
        unsafe {
            let mut structs = std::ptr::null_mut();
            let sz_module_name = CString::new(module_name)?;
            let r = (self.vmm.native.VMMDLL_Map_GetIATU)(self.vmm.native.h, self.pid, sz_module_name.as_ptr(), &mut structs);
            if !r {
                return Err(anyhow!("VMMDLL_Map_GetIATU: fail."));
            }
            if (*structs).dwVersion != VMMDLL_MAP_IAT_VERSION {
                (self.vmm.native.VMMDLL_MemFree)(structs as usize);
                return Err(anyhow!("VMMDLL_Map_GetIATU: bad version [{} != {}].", (*structs).dwVersion, VMMDLL_MAP_IAT_VERSION));
            }
            let mut result = Vec::new();
            if (*structs).cMap == 0 {
                (self.vmm.native.VMMDLL_MemFree)(structs as usize);
                return Ok(result);
            }
            let cMap : usize = (*structs).cMap.try_into()?;
            let pMap = std::slice::from_raw_parts(&(*structs).pMap, cMap);
            for i in 0..cMap {
                let ne = &pMap[i];
                let e = VmmProcessMapIatEntry {
                    pid : self.pid,
                    va_function : ne.vaFunction,
                    function : cstr_to_string(ne.uszFunction),
                    module : cstr_to_string(ne.uszModule),
                };
                result.push(e);
            }
            (self.vmm.native.VMMDLL_MemFree)(structs as usize);
            return Ok(result);
        }
    }

    fn impl_map_pte(&self, is_identify_modules : bool) -> ResultEx<Vec<VmmProcessMapPteEntry>> {
        unsafe {
            let mut structs = std::ptr::null_mut();
            let r = (self.vmm.native.VMMDLL_Map_GetPteU)(self.vmm.native.h, self.pid, is_identify_modules, &mut structs);
            if !r {
                return Err(anyhow!("VMMDLL_Map_GetPteU: fail."));
            }
            if (*structs).dwVersion != VMMDLL_MAP_PTE_VERSION {
                (self.vmm.native.VMMDLL_MemFree)(structs as usize);
                return Err(anyhow!("VMMDLL_Map_GetPteU: bad version [{} != {}].", (*structs).dwVersion, VMMDLL_MAP_PTE_VERSION));
            }
            let mut result = Vec::new();
            if (*structs).cMap == 0 {
                (self.vmm.native.VMMDLL_MemFree)(structs as usize);
                return Ok(result);
            }
            let cMap : usize = (*structs).cMap.try_into()?;
            let pMap = std::slice::from_raw_parts(&(*structs).pMap, cMap);
            for i in 0..cMap {
                let ne = &pMap[i];
                let e = VmmProcessMapPteEntry {
                    pid : self.pid,
                    va_base : ne.vaBase,
                    page_count : ne.cPages,
                    page_software_count : ne.cSoftware,
                    is_r : true,
                    is_w : (ne.fPage & 0x0000000000000002) != 0,
                    is_x : (ne.fPage & 0x8000000000000000) == 0,
                    is_s : (ne.fPage & 0x0000000000000004) == 0,
                    is_wow64 : ne.fWoW64,
                    info : cstr_to_string(ne.uszText),
                };
                result.push(e);
            }
            (self.vmm.native.VMMDLL_MemFree)(structs as usize);
            return Ok(result);
        }
    }

    fn impl_map_thread(&self) -> ResultEx<Vec<VmmProcessMapThreadEntry>> {
        unsafe {
            let mut structs = std::ptr::null_mut();
            let r = (self.vmm.native.VMMDLL_Map_GetThread)(self.vmm.native.h, self.pid, &mut structs);
            if !r {
                return Err(anyhow!("VMMDLL_Map_GetThread: fail."));
            }
            if (*structs).dwVersion != VMMDLL_MAP_THREAD_VERSION {
                (self.vmm.native.VMMDLL_MemFree)(structs as usize);
                return Err(anyhow!("VMMDLL_Map_GetThread: bad version [{} != {}].", (*structs).dwVersion, VMMDLL_MAP_THREAD_VERSION));
            }
            let mut result = Vec::new();
            if (*structs).cMap == 0 {
                (self.vmm.native.VMMDLL_MemFree)(structs as usize);
                return Ok(result);
            }
            let cMap : usize = (*structs).cMap.try_into()?;
            let pMap = std::slice::from_raw_parts(&(*structs).pMap, cMap);
            for i in 0..cMap {
                let ne = &pMap[i];
                let e = VmmProcessMapThreadEntry {
                    pid : self.pid,
                    thread_id : ne.dwTID,
                    thread_pid : ne.dwPID,
                    exit_status : ne.dwExitStatus,
                    state : ne.bState,
                    running : ne.bRunning,
                    priority : ne.bPriority,
                    priority_base : ne.bBasePriority,
                    va_ethread : ne.vaETHREAD,
                    va_teb : ne.vaTeb,
                    ft_create_time : ne.ftCreateTime,
                    ft_exit_time : ne.ftExitTime,
                    va_start_address : ne.vaStartAddress,
                    va_win32_start_address : ne.vaWin32StartAddress,
                    va_stack_user_base : ne.vaStackBaseUser,
                    va_stack_user_limit : ne.vaStackLimitUser,
                    va_stack_kernel_base : ne.vaStackBaseKernel,
                    va_stack_kernel_limit : ne.vaStackLimitKernel,
                    va_trap_frame : ne.vaTrapFrame,
                    va_impersonation_token : ne.vaImpersonationToken,
                    va_rip : ne.vaRIP,
                    va_rsp : ne.vaRSP,
                    affinity : ne.qwAffinity,
                    user_time : ne.dwUserTime,
                    kernel_time : ne.dwKernelTime,
                    suspend_count : ne.bSuspendCount,
                    wait_reason : ne.bWaitReason
                };
                result.push(e);
            }
            (self.vmm.native.VMMDLL_MemFree)(structs as usize);
            return Ok(result);
        }
    }

    fn impl_map_thread_callstack(&self, tid : u32, flags : u32) -> ResultEx<Vec<VmmProcessMapThreadCallstackEntry>> {
        unsafe {
            let mut structs = std::ptr::null_mut();
            let r = (self.vmm.native.VMMDLL_Map_GetThreadCallstackU)(self.vmm.native.h, self.pid, tid, flags, &mut structs);
            if !r {
                return Err(anyhow!("VMMDLL_Map_GetThreadCallstackU: fail."));
            }
            if (*structs).dwVersion != VMMDLL_MAP_THREAD_CALLSTACK_VERSION {
                (self.vmm.native.VMMDLL_MemFree)(structs as usize);
                return Err(anyhow!("VMMDLL_Map_GetThreadCallstackU: bad version [{} != {}].", (*structs).dwVersion, VMMDLL_MAP_THREAD_CALLSTACK_VERSION));
            }
            let mut result = Vec::new();
            if (*structs).cMap == 0 {
                (self.vmm.native.VMMDLL_MemFree)(structs as usize);
                return Ok(result);
            }
            let cMap : usize = (*structs).cMap.try_into()?;
            let pMap = std::slice::from_raw_parts(&(*structs).pMap, cMap);
            for i in 0..cMap {
                let ne = &pMap[i];
                let e = VmmProcessMapThreadCallstackEntry {
                    pid : self.pid,
                    tid : tid,
                    i : ne.i,
                    is_reg_present : ne.fRegPresent,
                    va_ret_addr : ne.vaRetAddr,
                    va_rsp : ne.vaRSP,
                    va_base_sp : ne.vaBaseSP,
                    displacement : ne.cbDisplacement,
                    module : cstr_to_string(ne.uszModule),
                    function : cstr_to_string(ne.uszFunction),
                };
                result.push(e);
            }
            (self.vmm.native.VMMDLL_MemFree)(structs as usize);
            return Ok(result);
        }
    }

    fn impl_map_unloaded_module(&self) -> ResultEx<Vec<VmmProcessMapUnloadedModuleEntry>> {
        unsafe {
            let mut structs = std::ptr::null_mut();
            let r = (self.vmm.native.VMMDLL_Map_GetUnloadedModuleU)(self.vmm.native.h, self.pid, &mut structs);
            if !r {
                return Err(anyhow!("VMMDLL_Map_GetUnloadedModuleU: fail."));
            }
            if (*structs).dwVersion != VMMDLL_MAP_UNLOADEDMODULE_VERSION {
                (self.vmm.native.VMMDLL_MemFree)(structs as usize);
                return Err(anyhow!("VMMDLL_Map_GetUnloadedModuleU: bad version [{} != {}].", (*structs).dwVersion, VMMDLL_MAP_UNLOADEDMODULE_VERSION));
            }
            let mut result = Vec::new();
            if (*structs).cMap == 0 {
                (self.vmm.native.VMMDLL_MemFree)(structs as usize);
                return Ok(result);
            }
            let cMap : usize = (*structs).cMap.try_into()?;
            let pMap = std::slice::from_raw_parts(&(*structs).pMap, cMap);
            for i in 0..cMap {
                let ne = &pMap[i];
                let e = VmmProcessMapUnloadedModuleEntry {
                    pid : self.pid,
                    va_base : ne.vaBase,
                    image_size : ne.cbImageSize,
                    is_wow64 : ne.fWoW64,
                    name : cstr_to_string(ne.uszText),
                    checksum : ne.dwCheckSum,
                    timedatestamp : ne.dwTimeDateStamp,
                    ft_unload : ne.ftUnload,
                };
                result.push(e);
            }
            (self.vmm.native.VMMDLL_MemFree)(structs as usize);
            return Ok(result);
        }
    }

    fn impl_map_vad(&self, is_identify_modules : bool) -> ResultEx<Vec<VmmProcessMapVadEntry>> {
        unsafe {
            let mut structs = std::ptr::null_mut();
            let r = (self.vmm.native.VMMDLL_Map_GetVadU)(self.vmm.native.h, self.pid, is_identify_modules, &mut structs);
            if !r {
                return Err(anyhow!("VMMDLL_Map_GetVadU: fail."));
            }
            if (*structs).dwVersion != VMMDLL_MAP_VAD_VERSION {
                (self.vmm.native.VMMDLL_MemFree)(structs as usize);
                return Err(anyhow!("VMMDLL_Map_GetVadU: bad version [{} != {}].", (*structs).dwVersion, VMMDLL_MAP_VAD_VERSION));
            }
            let mut result = Vec::new();
            if (*structs).cMap == 0 {
                (self.vmm.native.VMMDLL_MemFree)(structs as usize);
                return Ok(result);
            }
            let cMap : usize = (*structs).cMap.try_into()?;
            let pMap = std::slice::from_raw_parts(&(*structs).pMap, cMap);
            for i in 0..cMap {
                let ne = &pMap[i];
                let e = VmmProcessMapVadEntry {
                    pid : self.pid,
                    va_start : ne.vaStart,
                    va_end : ne.vaEnd,
                    va_vad : ne.vaVad,
                    u0 : ne.u0,
                    u1 : ne.u1,
                    u2 : ne.u2,
                    commit_charge : ne.u1 & 0x7fffffff,
                    is_mem_commit : (ne.u1 & 0x80000000) != 0,
                    cb_prototype_pte : ne.cbPrototypePte,
                    va_prototype_pte : ne.vaPrototypePte,
                    va_subsection : ne.vaSubsection,
                    va_file_object : ne.vaFileObject,
                    info : cstr_to_string(ne.uszText),
                    vadex_page_base : ne.cVadExPagesBase,
                    vadex_page_count : ne.cVadExPages,
                };
                result.push(e);
            }
            (self.vmm.native.VMMDLL_MemFree)(structs as usize);
            return Ok(result);
        }
    }

    fn impl_map_vadex(&self, offset_pages : u32, count_pages : u32) -> ResultEx<Vec<VmmProcessMapVadExEntry>> {
        unsafe {
            let mut structs = std::ptr::null_mut();
            let r = (self.vmm.native.VMMDLL_Map_GetVadEx)(self.vmm.native.h, self.pid, offset_pages, count_pages, &mut structs);
            if !r {
                return Err(anyhow!("VMMDLL_Map_GetVadEx: fail."));
            }
            if (*structs).dwVersion != VMMDLL_MAP_VADEX_VERSION {
                (self.vmm.native.VMMDLL_MemFree)(structs as usize);
                return Err(anyhow!("VMMDLL_Map_GetVadEx: bad version [{} != {}].", (*structs).dwVersion, VMMDLL_MAP_VADEX_VERSION));
            }
            let mut result = Vec::new();
            if (*structs).cMap == 0 {
                (self.vmm.native.VMMDLL_MemFree)(structs as usize);
                return Ok(result);
            }
            let cMap : usize = (*structs).cMap.try_into()?;
            let pMap = std::slice::from_raw_parts(&(*structs).pMap, cMap);
            for i in 0..cMap {
                let ne = &pMap[i];
                let e = VmmProcessMapVadExEntry {
                    pid : self.pid,
                    tp : VmmProcessMapVadExType::from(ne.tp),
                    i_pml : ne.iPML,
                    va : ne.va,
                    pa : ne.pa,
                    pte : ne.pte,
                    pte_flags : ne.pteFlags,
                    proto_tp : VmmProcessMapVadExType::from(ne.proto_tp),
                    proto_pa : ne.proto_pa,
                    proto_pte : ne.proto_va,
                    va_vad_base : ne.vaVadBase,
                };
                result.push(e);
            }
            (self.vmm.native.VMMDLL_MemFree)(structs as usize);
            return Ok(result);
        }
    }

    fn impl_map_module_data_directory(&self, module_name : &str) -> ResultEx<Vec<VmmProcessMapDirectoryEntry>> {
        let sz_module_name = CString::new(module_name)?;
        let mut data_directories = vec![CIMAGE_DATA_DIRECTORY::default(); 16];
        let r = (self.vmm.native.VMMDLL_ProcessGetDirectoriesU)(self.vmm.native.h, self.pid, sz_module_name.as_ptr(), data_directories.as_mut_ptr());
        if !r {
            return Err(anyhow!("VMMDLL_ProcessGetDirectoriesU: fail."));
        }
        let mut result = Vec::new();
        for i in 0..16 {
            let src : &CIMAGE_DATA_DIRECTORY = data_directories.get(i).unwrap();
            let dst = VmmProcessMapDirectoryEntry {
                pid : self.pid,
                name : DIRECTORY_NAMES[i],
                virtual_address : src.VirtualAddress,
                size : src.Size,
            };
            result.push(dst);
        }
        return Ok(result);
    }

    fn impl_map_module_section(&self, module_name : &str) -> ResultEx<Vec<VmmProcessSectionEntry>> {
        let sz_module_name = CString::new(module_name)?;
        let mut section_count = 0u32;
        let r = (self.vmm.native.VMMDLL_ProcessGetSectionsU)(self.vmm.native.h, self.pid, sz_module_name.as_ptr(), std::ptr::null_mut(), 0, &mut section_count);
        if !r {
            return Err(anyhow!("VMMDLL_ProcessGetSectionsU: fail."));
        }
        let mut sections = vec![CIMAGE_SECTION_HEADER::default(); section_count.try_into()?];
        let mut result = Vec::new();
        if section_count == 0 {
            return Ok(result);
        }
        let r = (self.vmm.native.VMMDLL_ProcessGetSectionsU)(self.vmm.native.h, self.pid, sz_module_name.as_ptr(), sections.as_mut_ptr(), section_count, &mut section_count);
        if !r {
            return Err(anyhow!("VMMDLL_ProcessGetSectionsU: fail."));
        }
        for i in 0..(section_count as usize) {
            let src : &CIMAGE_SECTION_HEADER = sections.get(i).unwrap();
            let dst = VmmProcessSectionEntry {
                pid : self.pid,
                index : i as u32,
                name : std::str::from_utf8(&src.Name).unwrap_or_default().to_string(),
                name_raw : src.Name,
                misc_virtual_size : src.Misc_VirtualAddress,
                virtual_address : src.VirtualAddress,
                size_of_raw_data : src.SizeOfRawData,
                pointer_to_raw_data : src.PointerToRawData,
                pointer_to_relocations : src.PointerToRelocations,
                pointer_to_linenumbers : src.PointerToLinenumbers,
                number_of_relocations : src.NumberOfRelocations,
                number_of_linenumbers : src.NumberOfLinenumbers,
                characteristics : src.Characteristics,
            };
            result.push(dst);
        }
        return Ok(result);
    }

}






//=============================================================================
// INTERNAL: VMM.SCATTERMEMORY:
//=============================================================================

impl fmt::Display for VmmScatterMemory<'_> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if self.pid == u32::MAX { write!(f, "VmmScatterMemory:physical") } else { write!(f, "VmmScatterMemory:virtual:{}", self.pid & 0x7fffffff) }
    }
}

impl Drop for VmmScatterMemory<'_> {
    fn drop(&mut self) {
        if self.is_scatter_ex {
            let _r = self.impl_execute();
        }
        (self.vmm.native.VMMDLL_Scatter_CloseHandle)(self.hs);
    }
}

impl <'a> VmmScatterMemory<'a> {
    fn impl_prepare_ex(&mut self, data_to_read : &'a mut (u64, Vec<u8>, u32)) -> ResultEx<()> {
        if data_to_read.2 != 0 {
            return Err(anyhow!("data_to_read.2 not set to zero"));
        }
        let cb = u32::try_from(data_to_read.1.len())?;
        let r = (self.vmm.native.VMMDLL_Scatter_PrepareEx)(self.hs, data_to_read.0, cb, data_to_read.1.as_mut_ptr(), &mut data_to_read.2);
        if !r {
            return Err(anyhow!("VMMDLL_Scatter_PrepareEx: fail."));
        }
        self.is_scatter_ex = true;
        return Ok(());
    }

    fn impl_prepare_ex_as<T>(&mut self, data_to_read : &'a mut (u64, T, u32)) -> ResultEx<()> {
        if data_to_read.2 != 0 {
            return Err(anyhow!("data_to_read.2 not set to zero"));
        }
        let cb = u32::try_from(std::mem::size_of::<T>())?;
        let r = (self.vmm.native.VMMDLL_Scatter_PrepareEx)(self.hs, data_to_read.0, cb, &mut data_to_read.1 as *mut _ as *mut u8, &mut data_to_read.2);
        if !r {
            return Err(anyhow!("VMMDLL_Scatter_PrepareEx: fail."));
        }
        self.is_scatter_ex = true;
        return Ok(());
    }
}

impl VmmScatterMemory<'_> {
    fn impl_prepare(&self, va : u64, size : usize) -> ResultEx<()> {
        let cb = u32::try_from(size)?;
        let r = (self.vmm.native.VMMDLL_Scatter_Prepare)(self.hs, va, cb);
        if !r {
            return Err(anyhow!("VMMDLL_Scatter_Prepare: fail."));
        }
        return Ok(());
    }

    fn impl_prepare_write(&self, va : u64, data : &[u8]) -> ResultEx<()> {
        let cb = u32::try_from(data.len())?;
        let pb = data.as_ptr();
        let r = (self.vmm.native.VMMDLL_Scatter_PrepareWrite)(self.hs, va, pb, cb);
        if !r {
            return Err(anyhow!("VMMDLL_Scatter_PrepareWrite: fail."));
        }
        return Ok(());
    }

    fn impl_prepare_write_as<T>(&self, va : u64, data : &T) -> ResultEx<()> {
        let cb = u32::try_from(std::mem::size_of::<T>())?;
        let r = (self.vmm.native.VMMDLL_Scatter_PrepareWrite)(self.hs, va, data as *const _ as *const u8, cb);
        if !r {
            return Err(anyhow!("VMMDLL_Scatter_PrepareWrite: fail."));
        }
        return Ok(());
    }

    fn impl_execute(&self) -> ResultEx<()> {
        let r = (self.vmm.native.VMMDLL_Scatter_Execute)(self.hs);
        if !r {
            return Err(anyhow!("VMMDLL_Scatter_Execute: fail."));
        }
        return Ok(());
    }

    fn impl_read(&self, va : u64, size : usize) -> ResultEx<Vec<u8>> {
        let cb = u32::try_from(size)?;
        let mut cb_read = 0;
        let mut pb_result = vec![0u8; size];
        let r = (self.vmm.native.VMMDLL_Scatter_Read)(self.hs, va, cb, pb_result.as_mut_ptr(), &mut cb_read);
        if !r {
            return Err(anyhow!("VMMDLL_Scatter_Read: fail."));
        }
        return Ok(pb_result);
    }

    fn impl_read_as<T>(&self, va : u64) -> ResultEx<T> {
        unsafe {
            let cb = u32::try_from(std::mem::size_of::<T>())?;
            let mut cb_read = 0;
            let mut result : T = std::mem::zeroed();
            let r = (self.vmm.native.VMMDLL_Scatter_Read)(self.hs, va, cb, &mut result as *mut _ as *mut u8, &mut cb_read);
            if !r {
                return Err(anyhow!("VMMDLL_Scatter_Read: fail."));
            }
            return Ok(result);
        }
    }

    fn impl_read_into(&self, va : u64, data : &mut [u8]) -> ResultEx<usize> {
        let cb = u32::try_from(data.len())?;
        let mut cb_read = 0;
        let r = (self.vmm.native.VMMDLL_Scatter_Read)(self.hs, va, cb, data.as_mut_ptr(), &mut cb_read);
        if !r {
            return Err(anyhow!("VMMDLL_Scatter_Read: fail."));
        }
        return Ok(cb_read as usize);
    }

    fn impl_clear(&self) -> ResultEx<()> {
        let r = (self.vmm.native.VMMDLL_Scatter_Clear)(self.hs, self.pid, self.flags);
        if !r {
            return Err(anyhow!("VMMDLL_Scatter_Clear: fail."));
        }
        return Ok(());
    }
}






//=============================================================================
// INTERNAL: VMM.SEARCH:
//=============================================================================

impl fmt::Display for VmmSearch<'_> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "VmmSearch")
    }
}

impl fmt::Display for VmmSearchResult {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "VmmSearchResult")
    }
}

/// Maximum number of supported search terms.
const CVMMDLL_MEM_SEARCH_CONTEXT_SEARCHENTRY_MAX : usize = 0x00100000;

#[repr(C)]
#[allow(non_snake_case, non_camel_case_types)]
#[derive(Debug, Default)]
struct CVMMDLL_MEM_SEARCH_CONTEXT_SEARCHENTRY {
    cbAlign : u32,
    cb : u32,
    pb : [u8; 32],
    pbSkipMask : [u8; 32],
}

#[repr(C)]
#[allow(non_snake_case, non_camel_case_types)]
#[derive(Debug, Default)]
pub(crate) struct CVMMDLL_MEM_SEARCH_CONTEXT {
    dwVersion : u32,
    _Filler : [u32; 2],
    fAbortRequested : u32,
    cMaxResult : u32,
    cSearch : u32,
    pSearch : usize,
    vaMin : u64,
    vaMax : u64,
    vaCurrent : u64,
    _Filler2 : u32,
    cResult : u32,
    cbReadTotal : u64,
    pvUserPtrOpt : usize,
    pfnResultOptCB : usize,
    ReadFlags : u64,
    fForcePTE : u32,
    fForceVAD : u32,
    pfnFilterOptCB : usize,
}

impl Drop for VmmSearch<'_> {
    fn drop(&mut self) {
        if self.is_started && !self.is_completed {
            self.impl_abort();
            let _r = self.impl_result();
        }
    }
}

// The below implementation is quite ugly, but it works since all methods are
// serialized since they all require &mut self. Under no conditions should the
// VmmSearch struct be accessed directly or non-mutable.
impl VmmSearch<'_> {
    fn impl_result(&mut self) -> VmmSearchResult {
        if self.is_started == false {
            self.impl_start();
        }
        if self.is_completed == false {
            self.is_completed = true;
            if let Some(thread) = self.thread.take() {
                if let Ok(thread_result) = thread.join() {
                    self.is_completed_success = thread_result;
                }
            }
        }
        return self.impl_poll();
    }

    fn impl_abort(&mut self) {
        if self.is_started && !self.is_completed {
            self.native_search.fAbortRequested = 1;
        }
    }

    fn impl_start(&mut self) {
        if self.is_started == false {
            self.is_started = true;
            // ugly code below - but it works ...
            self.native_search.cSearch = self.search_terms.len() as u32;
            self.native_search.pSearch = self.search_terms.as_ptr() as usize;
            self.native_search.pvUserPtrOpt = std::ptr::addr_of!(self.result) as usize;
            let pid = self.pid;
            let native_h = self.vmm.native.h;
            let pfn = self.vmm.native.VMMDLL_MemSearch;
            let ptr = &mut self.native_search as *mut CVMMDLL_MEM_SEARCH_CONTEXT;
            let ptr_wrap = ptr as usize;
            let thread_handle = std::thread::spawn(move || {
                let ptr = ptr_wrap as *mut CVMMDLL_MEM_SEARCH_CONTEXT;
                (pfn)(native_h, pid, ptr, std::ptr::null_mut(), std::ptr::null_mut())
            });
            self.thread = Some(thread_handle);
        }
    }

    fn impl_poll(&mut self) -> VmmSearchResult {
        if self.is_started && !self.is_completed && self.thread.as_ref().unwrap().is_finished() {
            return self.impl_result();
        }
        let result_vec = if self.is_completed_success { self.result.clone() } else { Vec::new() };
        return VmmSearchResult {
            is_started : self.is_started,
            is_completed : self.is_completed,
            is_completed_success : self.is_completed_success,
            addr_min : self.native_search.vaMin,
            addr_max : self.native_search.vaMax,
            addr_current : self.native_search.vaCurrent,
            total_read_bytes : self.native_search.cbReadTotal,
            total_results : self.native_search.cResult,
            result : result_vec,
        }
    }

    fn impl_new<'a>(vmm : &'a Vmm<'a>, pid : u32, addr_min : u64, addr_max : u64, num_results_max : u32, flags : u64) -> ResultEx<VmmSearch<'a>> {
        let num_results_max = std::cmp::min(0x10000, num_results_max);
        let addr_min = addr_min & 0xfffffffffffff000;
        let addr_max = addr_max & 0xfffffffffffff000;
        if addr_max != 0 && addr_max <= addr_min {
            return Err(anyhow!("search max address must be larger than min address"));
        }
        let result_vec = Vec::new();
        let mut native_search = CVMMDLL_MEM_SEARCH_CONTEXT::default();
        native_search.dwVersion = VMMDLL_MEM_SEARCH_VERSION;
        native_search.vaMin = addr_min;
        native_search.vaMax = addr_max;
        native_search.ReadFlags = flags;
        native_search.cMaxResult = num_results_max;
        native_search.pfnResultOptCB = VmmSearch::impl_search_cb as usize;
        native_search.pvUserPtrOpt = std::ptr::addr_of!(result_vec) as usize;
        return Ok(VmmSearch {
            vmm,
            pid,
            is_started : false,
            is_completed : false,
            is_completed_success : false,
            native_search,
            search_terms : Vec::new(),
            thread : None,
            result : result_vec,
        });
    }

    fn impl_add_search(&mut self, search_bytes : &[u8], search_skipmask : Option<&[u8]>, byte_align : u32) -> ResultEx<u32> {
        if self.is_started || self.is_completed {
            return Err(anyhow!("Search cannot add terms to an already started/completed search."));
        }
        if self.search_terms.len() >= CVMMDLL_MEM_SEARCH_CONTEXT_SEARCHENTRY_MAX {
            return Err(anyhow!("Search max terms ({}) reached.", CVMMDLL_MEM_SEARCH_CONTEXT_SEARCHENTRY_MAX));
        }
        if (search_bytes.len() == 0) || (search_bytes.len() > 32) {
            return Err(anyhow!("Search invalid length: search_bytes."));
        }
        if byte_align > 0 {
            if ((byte_align & (byte_align - 1)) != 0) || (byte_align > 0x1000) {
                return Err(anyhow!("Search bad byte_align."));
            }
        }
        if let Some(search_skipmask) = search_skipmask {
            if search_skipmask.len() > search_bytes.len() {
                return Err(anyhow!("Search invalid length: search_skipmask."));
            }
        }
        let mut term = CVMMDLL_MEM_SEARCH_CONTEXT_SEARCHENTRY::default();
        term.cbAlign = byte_align;
        term.cb = search_bytes.len() as u32;
        term.pb[0..search_bytes.len()].copy_from_slice(search_bytes);
        if let Some(search_skipmask) = search_skipmask {
            term.pbSkipMask[0..search_skipmask.len()].copy_from_slice(search_skipmask);
        }
        let result_index = self.search_terms.len() as u32;
        self.search_terms.push(term);
        return Ok(result_index);
    }

    extern "C" fn impl_search_cb(ctx : usize, va : u64, i_search : u32) -> bool {
        unsafe {
            let ctx = ctx as *const CVMMDLL_MEM_SEARCH_CONTEXT;
            let ptr_result_vec = (*ctx).pvUserPtrOpt as *mut Vec<(u64, u32)>;
            (*ptr_result_vec).push((va, i_search));
            return true;
        }
    }
}






//=============================================================================
// INTERNAL: VMM.YARA:
//=============================================================================

impl fmt::Display for VmmYara<'_> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "VmmYara")
    }
}

impl fmt::Display for VmmYaraResult {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "VmmYaraResult")
    }
}

impl fmt::Display for VmmYaraMatch {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "VmmYaraMatch:[{}]:{}", self.rule, self.match_strings.len())
    }
}

impl fmt::Display for VmmYaraMatchString {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "VmmYaraMatchString:[{}]:{}", self.match_string, self.addresses.len())
    }
}

#[repr(C)]
#[allow(non_snake_case, non_camel_case_types)]
#[derive(Debug)]
struct CVMMDLL_VMMYARA_RULE_MATCH_META {
    szIdentifier : *const c_char,
    szString : *const c_char,
}

#[repr(C)]
#[allow(non_snake_case, non_camel_case_types)]
#[derive(Debug)]
struct CVMMDLL_VMMYARA_RULE_MATCH_STRINGS {
    szString : *const c_char,
    cMatch : u32,
    cbMatchOffset : [usize; VMMYARA_RULE_MATCH_OFFSET_MAX],
}

#[repr(C)]
#[allow(non_snake_case, non_camel_case_types)]
#[derive(Debug)]
struct CVMMDLL_VMMYARA_RULE_MATCH {
    dwVersion : u32,
    flags : u32,
    szRuleIdentifier : *const c_char,
    cTags : u32,
    szTags : [*const c_char; VMMYARA_RULE_MATCH_TAG_MAX],
    cMeta : u32,
    meta : [CVMMDLL_VMMYARA_RULE_MATCH_META; VMMYARA_RULE_MATCH_META_MAX],
    cStrings : u32,
    strings : [CVMMDLL_VMMYARA_RULE_MATCH_STRINGS; VMMYARA_RULE_MATCH_STRING_MAX],
}

#[repr(C)]
#[allow(non_snake_case, non_camel_case_types)]
#[derive(Debug)]
pub(crate) struct CVMMDLL_YARA_CONFIG {
    dwVersion : u32,
    _Filler : [u32; 2],
    fAbortRequested : u32,
    cMaxResult : u32,
    cRules : u32,
    pszRules : *const *const c_char,
    vaMin : u64,
    vaMax : u64,
    vaCurrent : u64,
    _Filler2 : u32,
    cResult : u32,
    cbReadTotal : u64,
    pvUserPtrOpt : usize,
    pfnScanMemoryCB : usize,
    ReadFlags : u64,
    fForcePTE : u32,
    fForceVAD : u32,
    pfnFilterOptCB : usize,
    pvUserPtrOpt2 : usize,
    _Reserved : u64,
}

impl Drop for VmmYara<'_> {
    fn drop(&mut self) {
        if self.is_started && !self.is_completed {
            self.impl_abort();
            let _r = self.impl_result();
        }
    }
}

// The below implementation is quite ugly, but it works since all methods are
// serialized since they all require &mut self. Under no conditions should the
// VmmYara struct be accessed directly or non-mutable.
impl VmmYara<'_> {
    fn impl_result(&mut self) -> VmmYaraResult {
        if self.is_started == false {
            self.impl_start();
        }
        if self.is_completed == false {
            self.is_completed = true;
            if let Some(thread) = self.thread.take() {
                if let Ok(thread_result) = thread.join() {
                    self.is_completed_success = thread_result;
                }
            }
        }
        return self.impl_poll();
    }

    fn impl_abort(&mut self) {
        if self.is_started && !self.is_completed {
            self.native.fAbortRequested = 1;
        }
    }

    fn impl_start(&mut self) {
        if self.is_started == false {
            self.is_started = true;
            // ugly code below - but it works ...
            self.native.pvUserPtrOpt2 = std::ptr::addr_of!(self.result) as usize;
            self.native.pvUserPtrOpt = std::ptr::addr_of!(self.native) as usize;
            let pid = self.pid;
            let native_h = self.vmm.native.h;
            let pfn = self.vmm.native.VMMDLL_YaraSearch;
            let ptr = &mut self.native as *mut CVMMDLL_YARA_CONFIG;
            let ptr_wrap = ptr as usize;
            let thread_handle = std::thread::spawn(move || {
                let ptr = ptr_wrap as *mut CVMMDLL_YARA_CONFIG;
                (pfn)(native_h, pid, ptr, std::ptr::null_mut(), std::ptr::null_mut())
            });
            self.thread = Some(thread_handle);
        }
    }

    fn impl_poll(&mut self) -> VmmYaraResult {
        if self.is_started && !self.is_completed && self.thread.as_ref().unwrap().is_finished() {
            return self.impl_result();
        }
        let result_vec = if self.is_completed_success { self.result.clone() } else { Vec::new() };
        return VmmYaraResult {
            is_completed : self.is_completed,
            is_completed_success : self.is_completed_success,
            addr_min : self.native.vaMin,
            addr_max : self.native.vaMax,
            addr_current : self.native.vaCurrent,
            total_read_bytes : self.native.cbReadTotal,
            total_results : self.result.len() as u32,
            result : result_vec,
        }
    }

    fn impl_new<'a>(vmm : &'a Vmm<'a>, rules : Vec<&str>, pid : u32, addr_min : u64, addr_max : u64, num_results_max : u32, flags : u64) -> ResultEx<VmmYara<'a>> {
        // 1: verify address validity:
        let num_results_max = std::cmp::min(0x10000, num_results_max);
        let addr_min = addr_min & 0xfffffffffffff000;
        let addr_max = addr_max & 0xfffffffffffff000;
        if addr_max != 0 && addr_max <= addr_min {
            return Err(anyhow!("search max address must be larger than min address"));
        }
        // 2: create native object:
        let native_args_rules = rules.iter().map(|arg| CString::new(*arg).unwrap()).collect::<Vec<CString>>();
        let native_argv_rules: Vec<*const c_char> = native_args_rules.iter().map(|s| s.as_ptr()).collect();
        let native = CVMMDLL_YARA_CONFIG {
            dwVersion : VMMDLL_YARA_CONFIG_VERSION,
            _Filler : [0; 2],
            fAbortRequested : 0,
            cMaxResult : num_results_max,
            cRules : native_args_rules.len() as u32,
            pszRules : native_argv_rules.as_ptr(),
            vaMin : addr_min,
            vaMax : addr_max,
            vaCurrent : 0,
            _Filler2 : 0,
            cResult : 0,
            cbReadTotal : 0,
            pvUserPtrOpt : 0,
            pfnScanMemoryCB : VmmYara::impl_yara_cb as usize,
            ReadFlags : flags,
            fForcePTE : 0,
            fForceVAD : 0,
            pfnFilterOptCB : 0,
            pvUserPtrOpt2 : 0,
            _Reserved : 0,
        };
        // 3: create object and return:
        let yara = VmmYara {
            vmm,
            pid,
            is_started : false,
            is_completed : false,
            is_completed_success : false,
            native,
            _native_args_rules : native_args_rules,
            _native_argv_rules : native_argv_rules,
            thread : None,
            result : Vec::new(),
        };
        return Ok(yara);
    }

    extern "C" fn impl_yara_cb(ctx : *const CVMMDLL_YARA_CONFIG, yrm : *const CVMMDLL_VMMYARA_RULE_MATCH, _pb_buffer : *const u8, _cb_buffer : usize) -> bool {
        unsafe {
            if (*ctx).dwVersion != VMMDLL_YARA_CONFIG_VERSION {
                return false;
            }
            if (*yrm).dwVersion != VMMYARA_RULE_MATCH_VERSION {
                return false;
            }
            let addr = (*ctx).vaCurrent;
            // rule:
            let rule = cstr_to_string((*yrm).szRuleIdentifier);
            // tags:
            let mut tags = Vec::new();
            let ctags = std::cmp::min((*yrm).cTags as usize, VMMYARA_RULE_MATCH_TAG_MAX);
            for i in 0..ctags {
                let tag = cstr_to_string((*yrm).szTags[i]);
                tags.push(tag);
            }
            // meta:
            let mut meta = Vec::new();
            let cmeta = std::cmp::min((*yrm).cMeta as usize, VMMYARA_RULE_MATCH_META_MAX);
            for i in 0..cmeta {
                let key = cstr_to_string((*yrm).meta[i].szIdentifier);
                let value = cstr_to_string((*yrm).meta[i].szString);
                meta.push((key, value));
            }
            // match_strings:
            let mut match_strings = Vec::new();
            let cmatch_strings = std::cmp::min((*yrm).cStrings as usize, VMMYARA_RULE_MATCH_STRING_MAX);
            for i in 0..cmatch_strings {
                let match_string = cstr_to_string((*yrm).strings[i].szString);
                let cmatch = std::cmp::min((*yrm).strings[i].cMatch as usize, VMMYARA_RULE_MATCH_OFFSET_MAX);
                let mut addresses = Vec::new();
                for j in 0..cmatch {
                    let offset = (*yrm).strings[i].cbMatchOffset[j] as u64;
                    addresses.push(addr + offset);
                }
                let match_string = VmmYaraMatchString {
                    match_string,
                    addresses,
                };
                match_strings.push(match_string);
            }
            // create result:
            let yara_match = VmmYaraMatch {
                addr,
                rule,
                tags,
                meta,
                match_strings,
            };
            let ptr_result_vec = (*ctx).pvUserPtrOpt2 as *mut Vec<VmmYaraMatch>;
            (*ptr_result_vec).push(yara_match);
            return true;    
        }
    }
}






//=============================================================================
// INTERNAL: VMM.PLUGINS:
//=============================================================================

impl<T> fmt::Display for VmmPluginContext<'_, T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "VmmPluginContext")
    }
}

impl fmt::Display for VmmPluginFileList<'_> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "VmmPluginFileList")
    }
}

impl<T> fmt::Display for VmmPluginInitializationContext<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "VmmPluginInitializationContext")
    }
}

impl fmt::Display for VmmPluginInitializationInfo {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "VmmPluginInitializationInfo")
    }
}

#[repr(C)]
#[allow(non_snake_case, non_camel_case_types)]
struct CVMMDLL_PLUGIN_CONTEXT<'a, T> {
    magic : u64,
    wVersion : u16,
    wSize : u16,
    pid : u32,
    pProcess : usize,
    uszModule : *const c_char,
    uszPath : *const c_char,
    pvReserved1 : usize,
    ctxM : *const VmmPluginContext<'a, T>,
    MID : u32,
}

#[repr(C)]
#[allow(non_snake_case, non_camel_case_types)]
struct CVMMDLL_PLUGIN_REGINFO<T> {
    magic : u64,
    wVersion : u16,
    wSize : u16,
    tpMemoryModel : u32,
    tpSystem : u32,
    hDLL : usize,
    pfnPluginManager_Register : extern "C" fn(H : usize, pPluginRegInfo : *mut CVMMDLL_PLUGIN_REGINFO<T>) -> bool,
    uszPathVmmDLL : *const c_char,
    _Reserved : [u32; 30],
    Py_fPythonStandalone : bool,
    Py__Reserved : u32,
    Py_hReservedDllPython3 : usize,
    Py_hReservedDllPython3X : usize,
    // reg_info:
    reg_info_ctxM : usize,
    reg_info_uszPathName : [u8; 128],
    reg_info_fRootModule : u32,          // bool
    reg_info_fProcessModule : u32,       // bool
    reg_info_fRootModuleHidden : u32,    // bool
    reg_info_fProcessModuleHidden : u32, // bool
    reg_info_sTimelineNameShort : [u8; 6],
    reg_info__Reserved : [u8; 2],
    reg_info_uszTimelineFile : [u8; 32],
    reg_info__Reserved2 : [u8; 32],
    // reg_fn:
    reg_fn_pfnList : extern "C" fn(H : usize, ctxP : *const CVMMDLL_PLUGIN_CONTEXT<T>, pFileList : usize) -> bool,
    reg_fn_pfnRead : extern "C" fn(H : usize, ctxP : *const CVMMDLL_PLUGIN_CONTEXT<T>, pb : *mut u8, cb : u32, pcbRead : *mut u32, cbOffset : u64) -> u32,
    reg_fn_pfnWrite : extern "C" fn(H : usize, ctxP : *const CVMMDLL_PLUGIN_CONTEXT<T>, pb : *const u8, cb : u32, pcbWrite : *mut u32, cbOffset : u64) -> u32,
    reg_fn_pfnNotify : extern "C" fn(H : usize, ctxP : *const CVMMDLL_PLUGIN_CONTEXT<T>, fEvent : u32, pvEvent : usize, cbEvent : usize),
    reg_fn_pfnClose : extern "C" fn(H : usize, ctxP : *const CVMMDLL_PLUGIN_CONTEXT<T>),
    reg_fn_pfnVisibleModule : extern "C" fn(H : usize, ctxP : *const CVMMDLL_PLUGIN_CONTEXT<T>) -> bool,
    reg_fn_pvReserved : [usize; 10],
    // reg_fnfc: // TODO:
    reg_fnfc_pfnInitialize : usize,
    reg_fnfc_pfnFinalize : usize,
    reg_fnfc_pfnTimeline : usize,
    reg_fnfc_pfnIngestPhysmem : usize,
    reg_fnfc_pfnIngestVirtmem : usize,
    reg_fnfc_pfnIngestFinalize : usize,
    reg_fnfc_pfnFindEvil : usize,
    reg_fnfc_pvReserved : [usize; 7],
    reg_fnfc_pfnLogCSV : usize,
    reg_fnfc_pfnLogJSON : usize,
    // sysinfo:
    sysinfo_f32 : u32,
    sysinfo_dwVersionMajor : u32,
    sysinfo_dwVersionMinor : u32,
    sysinfo_dwVersionBuild : u32,
    sysinfo__Reserved : [u32; 32],
}

fn impl_new_plugin_initialization<T>(native_h : usize, native_reginfo : usize) -> ResultEx<(VmmPluginInitializationInfo, VmmPluginInitializationContext<T>)> {
    unsafe {
        let reginfo = native_reginfo as *mut CVMMDLL_PLUGIN_REGINFO<T>;
        if (*reginfo).magic != VMMDLL_PLUGIN_REGINFO_MAGIC || (*reginfo).wVersion != VMMDLL_PLUGIN_REGINFO_VERSION {
            return Err(anyhow!("Bad reginfo magic/version."));
        }
        let info = VmmPluginInitializationInfo {
            tp_system : VmmSystemType::from((*reginfo).tpSystem),
            tp_memorymodel : VmmMemoryModelType::from((*reginfo).tpMemoryModel),
            version_major : (*reginfo).sysinfo_dwVersionMajor,
            version_minor : (*reginfo).sysinfo_dwVersionMinor,
            version_build : (*reginfo).sysinfo_dwVersionBuild,
        };
        let ctx = VmmPluginInitializationContext {
            h_vmm : native_h,
            h_reginfo : native_reginfo,
            ctx : None,
            path_name : String::from(""),
            is_root_module : false,
            is_root_module_hidden : false,
            is_process_module : false,
            is_process_module_hidden : false,
            fn_list : None,
            fn_read : None,
            fn_write : None,
            fn_notify : None,
            fn_visible : None,
        };
        return Ok((info, ctx));
    }
}

impl<T> VmmPluginInitializationContext<T> {
    fn impl_register(self) -> ResultEx<()> {
        unsafe {
            let reginfo = self.h_reginfo as *mut CVMMDLL_PLUGIN_REGINFO<T>;
            if (*reginfo).magic != VMMDLL_PLUGIN_REGINFO_MAGIC || (*reginfo).wVersion != VMMDLL_PLUGIN_REGINFO_VERSION {
                return Err(anyhow!("Bad reginfo magic/version."));
            }
            if self.ctx.is_none() {
                return Err(anyhow!("User context ctx is missing. User context cannot be None."));
            }
            let pathname_str = str::replace(&self.path_name, "/", "\\");
            let pathname_cstring = CString::new(pathname_str)?;
            let pathname_bytes = pathname_cstring.to_bytes_with_nul();
            if pathname_bytes.len() > (*reginfo).reg_info_uszPathName.len() {
                return Err(anyhow!("Plugin path/name too long."));
            }
            let pathname_len = std::cmp::min(pathname_bytes.len(), (*reginfo).reg_info_uszPathName.len());
            // "initialize" rust vmm context from handle and create rust plugin native context:
            let c_path_vmm = CStr::from_ptr((*reginfo).uszPathVmmDLL);
            let vmm = impl_new(c_path_vmm.to_str()?, None, self.h_vmm, &Vec::new())?;
            let ctx_user = self.ctx.unwrap();
            let ctx_rust = VmmPluginContext {
                vmm : vmm,
                ctxlock : std::sync::RwLock::new(ctx_user),
                fn_list : self.fn_list,
                fn_read : self.fn_read,
                fn_write : self.fn_write,
                fn_notify : self.fn_notify,
                fn_visible : self.fn_visible,
            };
            let ctx_rust_box = Box::new(ctx_rust);
            let ctx_native = Box::into_raw(ctx_rust_box);
            // prepare native registration context and register:
            for i in 0..pathname_len {
                (*reginfo).reg_info_uszPathName[i] = pathname_bytes[i];
            }
            (*reginfo).reg_info_ctxM = ctx_native as usize;
            (*reginfo).reg_info_fProcessModule = if self.is_process_module { 1 }  else { 0 };
            (*reginfo).reg_info_fProcessModuleHidden = if self.is_process_module_hidden { 1 }  else { 0 };
            (*reginfo).reg_info_fRootModule = if self.is_root_module { 1 }  else { 0 };
            (*reginfo).reg_info_fRootModuleHidden = if self.is_root_module_hidden { 1 }  else { 0 };
            // native callback registration:
            (*reginfo).reg_fn_pfnClose = impl_plugin_close_cb;
            if self.fn_list.is_some() {
                (*reginfo).reg_fn_pfnList = impl_plugin_list_cb;
            }
            if self.fn_read.is_some() {
                (*reginfo).reg_fn_pfnRead = impl_plugin_read_cb;
            }
            if self.fn_write.is_some() {
                (*reginfo).reg_fn_pfnWrite = impl_plugin_write_cb;
            }
            if self.fn_visible.is_some() {
                (*reginfo).reg_fn_pfnVisibleModule = impl_plugin_visible_cb;
            }
            if self.fn_notify.is_some() {
                (*reginfo).reg_fn_pfnNotify = impl_plugin_notify_cb;
            }
            let r = ((*reginfo).pfnPluginManager_Register)(self.h_vmm, reginfo);
            if !r {
                return Err(anyhow!("Failed registering plugin."));
            }
            return Ok(());
        }
    }
}

impl VmmPluginFileList<'_> {
    fn impl_add_file(&self, name : &str, size : u64) {
        let sz_name = CString::new(name).unwrap();
        (self.vmm.native.VMMDLL_VfsList_AddFile)(self.h_file_list, sz_name.as_ptr(), size, 0);
    }

    fn impl_add_directory(&self, name : &str) {
        let sz_name = CString::new(name).unwrap();
        (self.vmm.native.VMMDLL_VfsList_AddDirectory)(self.h_file_list, sz_name.as_ptr(), 0);
    }
}

extern "C" fn impl_plugin_close_cb<T>(_h : usize, ctxp : *const CVMMDLL_PLUGIN_CONTEXT<T>) {
    unsafe {
        drop(Box::from_raw((*ctxp).ctxM as *mut VmmPluginContext<T>));
    }
}

extern "C" fn impl_plugin_list_cb<T>(_h : usize, ctxp : *const CVMMDLL_PLUGIN_CONTEXT<T>, h_pfilelist : usize) -> bool {
    unsafe {
        let ctx = &*(*ctxp).ctxM;
        if ((*ctxp).magic != VMMDLL_PLUGIN_CONTEXT_MAGIC) || ((*ctxp).wVersion != VMMDLL_PLUGIN_CONTEXT_VERSION) {
            return true;
        }
        let callback = ctx.fn_list.unwrap();
        let process = if (*ctxp).pid > 0 { Some(VmmProcess{ vmm : &ctx.vmm, pid : (*ctxp).pid }) } else { None };
        let path_string = str::replace(CStr::from_ptr((*ctxp).uszPath).to_str().unwrap_or("[err]"), "\\", "/");
        let path = path_string.as_str();
        if path == "[err]" {
            return true;
        }
        let filelist = VmmPluginFileList {
            vmm : &ctx.vmm,
            h_file_list : h_pfilelist,
        };
        let _r = (callback)(ctx, process, path, &filelist);
        return true;
    }
}

extern "C" fn impl_plugin_read_cb<T>(_h : usize, ctxp : *const CVMMDLL_PLUGIN_CONTEXT<T>, pb : *mut u8, cb : u32, pcb_read : *mut u32, cb_offset : u64) -> u32 {
    unsafe {
        *pcb_read = 0;
        let ctx = &*(*ctxp).ctxM;
        if ((*ctxp).magic != VMMDLL_PLUGIN_CONTEXT_MAGIC) || ((*ctxp).wVersion != VMMDLL_PLUGIN_CONTEXT_VERSION) {
            return VMMDLL_STATUS_FILE_INVALID;
        }
        let callback = ctx.fn_read.unwrap();
        let process = if (*ctxp).pid > 0 { Some(VmmProcess{ vmm : &ctx.vmm, pid : (*ctxp).pid }) } else { None };
        let path_string = str::replace(CStr::from_ptr((*ctxp).uszPath).to_str().unwrap_or("[err]"), "\\", "/");
        let path = path_string.as_str();
        if path == "[err]" {
            return VMMDLL_STATUS_FILE_INVALID;
        }
        let r = match (callback)(ctx, process, path, cb, cb_offset) {
            Err(_) => return VMMDLL_STATUS_FILE_INVALID,
            Ok(r) => r,
        };
        if r.len() == 0 {
            return VMMDLL_STATUS_END_OF_FILE;
        }
        if r.len() > u32::MAX as usize {
            return VMMDLL_STATUS_FILE_INVALID;
        }
        *pcb_read = r.len() as u32;
        std::ptr::copy_nonoverlapping(r.as_ptr(), pb, r.len());
        return VMMDLL_STATUS_SUCCESS;
    }
}

extern "C" fn impl_plugin_write_cb<T>(_h : usize, ctxp : *const CVMMDLL_PLUGIN_CONTEXT<T>, pb : *const u8, cb : u32, pcb_write : *mut u32, cb_offset : u64) -> u32 {
    unsafe {
        *pcb_write = 0;
        let ctx = &*(*ctxp).ctxM;
        if ((*ctxp).magic != VMMDLL_PLUGIN_CONTEXT_MAGIC) || ((*ctxp).wVersion != VMMDLL_PLUGIN_CONTEXT_VERSION) {
            return VMMDLL_STATUS_FILE_INVALID;
        }
        let callback = ctx.fn_write.unwrap();
        let process = if (*ctxp).pid > 0 { Some(VmmProcess{ vmm : &ctx.vmm, pid : (*ctxp).pid }) } else { None };
        let path_string = str::replace(CStr::from_ptr((*ctxp).uszPath).to_str().unwrap_or("[err]"), "\\", "/");
        let path = path_string.as_str();
        if path == "[err]" {
            return VMMDLL_STATUS_FILE_INVALID;
        }
        let size = cb as usize;
        let mut data = vec![0u8; size];
        std::ptr::copy_nonoverlapping(pb, data.as_mut_ptr(), size);
        if (callback)(ctx, process, path, data, cb_offset).is_err() {
            return VMMDLL_STATUS_FILE_INVALID;
        };
        *pcb_write = cb;
        return VMMDLL_STATUS_SUCCESS;
    }
}

extern "C" fn impl_plugin_visible_cb<T>(_h : usize, ctxp : *const CVMMDLL_PLUGIN_CONTEXT<T>) -> bool {
    unsafe {
        let ctx = &*(*ctxp).ctxM;
        if ((*ctxp).magic != VMMDLL_PLUGIN_CONTEXT_MAGIC) || ((*ctxp).wVersion != VMMDLL_PLUGIN_CONTEXT_VERSION) {
            return false;
        }
        let callback = ctx.fn_visible.unwrap();
        let process = if (*ctxp).pid > 0 { Some(VmmProcess{ vmm : &ctx.vmm, pid : (*ctxp).pid }) } else { None };
        let path_string = str::replace(CStr::from_ptr((*ctxp).uszPath).to_str().unwrap_or("[err]"), "\\", "/");
        let path = path_string.as_str();
        if path == "[err]" {
            return false;
        }
        return (callback)(ctx, process).unwrap_or(false);
    }
}

extern "C" fn impl_plugin_notify_cb<T>(_h : usize, ctxp : *const CVMMDLL_PLUGIN_CONTEXT<T>, f_event : u32, _pv_event : usize, _cb_event : usize) {
    unsafe {
        let ctx = &*(*ctxp).ctxM;
        if ((*ctxp).magic != VMMDLL_PLUGIN_CONTEXT_MAGIC) || ((*ctxp).wVersion != VMMDLL_PLUGIN_CONTEXT_VERSION) {
            return;
        }
        let callback = ctx.fn_notify.unwrap();
        let _r = (callback)(ctx, f_event);
    }
}












//=============================================================================
// INTERNAL: LEECHCORE:
//=============================================================================

#[allow(dead_code)]
#[allow(non_snake_case)]
#[derive(Debug)]
struct LcNative {
    h : usize,
    library_lc : libloading::Library,
    config : CLC_CONFIG,
    LcCreate : extern "C" fn(pLcCreateConfig : *mut CLC_CONFIG) -> usize,
    LcClose : extern "C" fn(hLC : usize),
    LcMemFree : extern "C" fn(pvMem : usize),
    LcRead : extern "C" fn(hLC : usize, pa : u64, cb : u32, pb : *mut u8) -> bool,
    LcWrite : extern "C" fn(hLC : usize, pa : u64, cb : u32, pb : *const u8) -> bool,
    LcGetOption : extern "C" fn(hLC : usize, fOption : u64, pqwValue : *mut u64) -> bool,
    LcSetOption : extern "C" fn(hLC : usize, fOption : u64, qwValue : u64) -> bool,
    LcCommand : extern "C" fn(hLC : usize, fCommand : u64, cbDataIn : u32, pbDataIn : *const u8, ppbDataOut : *mut *mut u8, pcbDataOut : *mut u32) -> bool,
    LcCommandPtr : extern "C" fn(hLC : usize, fCommand : u64, cbDataIn : u32, pbDataIn : usize, ppbDataOut : *mut usize, pcbDataOut : *mut u32) -> bool,
}

impl fmt::Display for LeechCore {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "LeechCore")
    }
}

impl fmt::Display for LcBar {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if self.is_valid {
            write!(f, "LcBar:{}:[{:x}->{:x}]", self.bar_index, self.pa, self.pa + self.cb - 1)
        } else {
            write!(f, "LcBar:{}:inactive", self.bar_index)
        }
    }
}

impl fmt::Display for LcBarRequest {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let tp = if self.is_write { "write" } else { "read" };
        write!(f, "LcBarRequest:{}:{tp}:[{:x}:{:x}]", self.bar.bar_index, self.data_offset, self.data_size)
    }
}

impl<T> fmt::Display for LcBarContext<'_, T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "LcBarContext")
    }
}

impl<T> fmt::Display for LcBarContextWrap<'_, T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "LcBarContextWrap")
    }
}

impl<T> fmt::Display for LcTlpContext<'_, T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "LcTlpContext")
    }
}

impl<T> fmt::Display for LcTlpContextWrap<'_, T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "LcTlpContextWrap")
    }
}

impl Drop for LeechCore {
    fn drop(&mut self) {
        (self.native.LcClose)(self.native.h);
    }
}

impl Clone for LeechCore {
    fn clone(&self) -> Self {
        let lc_init_arg = format!("existing://0x{:x}", self.native.h);
        let lc_clone = LeechCore::new(&self.path_lc, &lc_init_arg, 0).unwrap();
        return lc_clone;
    }
}

impl<T> Drop for LcBarContext<'_, T> {
    fn drop(&mut self) {
        let mut native_ctx : usize = 0;
        let r = (self.lc.native.LcCommandPtr)(self.lc.native.h, LeechCore::LC_CMD_FPGA_BAR_CONTEXT_RD, 0, 0, &mut native_ctx, std::ptr::null_mut());
        if r && self.native_ctx == native_ctx {
            let _r = (self.lc.native.LcCommandPtr)(self.lc.native.h, LeechCore::LC_CMD_FPGA_BAR_FUNCTION_CALLBACK, 0, 0, std::ptr::null_mut(), std::ptr::null_mut());
            let _r = (self.lc.native.LcCommandPtr)(self.lc.native.h, LeechCore::LC_CMD_FPGA_BAR_CONTEXT, 0, 0, std::ptr::null_mut(), std::ptr::null_mut());
        }
    }
}

impl<T> Drop for LcBarContextWrap<'_, T> {
    fn drop(&mut self) {
        unsafe {
            drop(Box::from_raw(self.native));
        }
    }
}

impl<T> Drop for LcTlpContext<'_, T> {
    fn drop(&mut self) {
        let mut native_ctx : usize = 0;
        let r = (self.lc.native.LcCommandPtr)(self.lc.native.h, LeechCore::LC_CMD_FPGA_TLP_CONTEXT_RD, 0, 0, &mut native_ctx, std::ptr::null_mut());
        if r && self.native_ctx == native_ctx {
            let _r = (self.lc.native.LcCommandPtr)(self.lc.native.h, LeechCore::LC_CMD_FPGA_TLP_FUNCTION_CALLBACK, 0, 0, std::ptr::null_mut(), std::ptr::null_mut());
            let _r = (self.lc.native.LcCommandPtr)(self.lc.native.h, LeechCore::LC_CMD_FPGA_TLP_CONTEXT, 0, 0, std::ptr::null_mut(), std::ptr::null_mut());
        }
    }
}

impl<T> Drop for LcTlpContextWrap<'_, T> {
    fn drop(&mut self) {
        unsafe {
            drop(Box::from_raw(self.native));
        }
    }
}

#[allow(non_snake_case)]
impl LeechCore {
    #[allow(non_snake_case)]
    fn impl_new(lc_lib_path : &str, device_config : &str, remote_config : &str, lc_config_printf_verbosity : u32, pa_max : u64) -> ResultEx<LeechCore> {
        unsafe {
            // load LeechCore native library (leechcore.[dll|dylib|so]):
            let path = std::path::Path::new(lc_lib_path).canonicalize()?;
            let str_path_lc = path.to_str().unwrap_or("");
            let library_lc : libloading::Library = libloading::Library::new(str_path_lc)
                .with_context(|| format!("Failed to load leechcore library at: {}", str_path_lc))?;
            // fetch function references:
            let LcCreate : extern "C" fn(pLcCreateConfig : *mut CLC_CONFIG) -> usize = *library_lc.get(b"LcCreate")?;
            let LcClose = *library_lc.get(b"LcClose")?;
            let LcMemFree = *library_lc.get(b"LcMemFree")?;
            let LcRead = *library_lc.get(b"LcRead")?;
            let LcWrite = *library_lc.get(b"LcWrite")?;
            let LcGetOption = *library_lc.get(b"LcGetOption")?;
            let LcSetOption = *library_lc.get(b"LcSetOption")?;
            let LcCommand = *library_lc.get(b"LcCommand")?;
            let LcCommandPtr = *library_lc.get(b"LcCommand")?;
            // build config:
            let device_config_bytes = &*(device_config.as_bytes() as *const [u8] as *const [c_char]);
            let mut device_sz: [c_char; 260] = [0; 260];
            device_sz[..device_config_bytes.len().min(260-1)].copy_from_slice(device_config_bytes);
            let remote_config_bytes = &*(remote_config.as_bytes() as *const [u8] as *const [c_char]);
            let mut remote_sz: [c_char; 260] = [0; 260];
            remote_sz[..remote_config_bytes.len().min(260-1)].copy_from_slice(remote_config_bytes);
            let mut config = CLC_CONFIG {
                dwVersion : LeechCore::LC_CONFIG_VERSION,
                dwPrintfVerbosity : lc_config_printf_verbosity,
                szDevice : device_sz,
                szRemote : remote_sz,
                pfn_printf_opt : 0,
                paMax : pa_max,
                fVolatile : 0,
                fWritable : 0,
                fRemote : 0,
                fRemoteDisableCompress : 0,
                szDeviceName : [0; 260],
            };
            // initialize library
            let h: usize;
            h = (LcCreate)(&mut config);
            if h == 0 {
                return Err(anyhow!("LcCreate: fail"));
            }
            // return LeechCore struct:
            let native = LcNative {
                h,
                library_lc,
                config,
                LcCreate,
                LcClose,
                LcMemFree,
                LcRead,
                LcWrite,
                LcGetOption,
                LcSetOption,
                LcCommand,
                LcCommandPtr,
            };
            let lc = LeechCore {
                path_lc : str_path_lc.to_string(),
                native,
            };
            return Ok(lc);
        }
    }

    fn impl_get_option(&self, config_id : u64) -> ResultEx<u64> {
        let mut v = 0;
        let f = (self.native.LcGetOption)(self.native.h, config_id, &mut v);
        return if f { Ok(v) } else { Err(anyhow!("LcGetOption: fail")) };
    }

    fn impl_set_option(&self, config_id : u64, config_value : u64) -> ResultEx<()> {
        let f = (self.native.LcSetOption)(self.native.h, config_id, config_value);
        return if f { Ok(()) } else { Err(anyhow!("LcSetOption: fail")) };
    }

    fn impl_mem_read(&self, pa : u64, size : usize) -> ResultEx<Vec<u8>> {
        let cb = u32::try_from(size)?;
        let mut pb_result: Vec<u8> = vec![0u8; size];
        let r = (self.native.LcRead)(self.native.h, pa, cb, pb_result.as_mut_ptr());
        if !r {
            return Err(anyhow!("LcRead: fail."));
        }
        return Ok(pb_result);
    }

    fn impl_mem_read_as<T>(&self, pa : u64) -> ResultEx<T> {
        unsafe {
            let cb = u32::try_from(std::mem::size_of::<T>())?;
            let mut result : T = std::mem::zeroed();
            let r = (self.native.LcRead)(self.native.h, pa, cb, &mut result as *mut _ as *mut u8);
            if !r {
                return Err(anyhow!("LcRead: fail."));
            }
            return Ok(result);
        }
    }

    fn impl_mem_write(&self, va : u64, data : &Vec<u8>) -> ResultEx<()> {
        let cb = u32::try_from(data.len())?;
        let pb = data.as_ptr();
        let r = (self.native.LcWrite)(self.native.h, va, cb, pb);
        if !r {
            return Err(anyhow!("LcWrite: fail."));
        }
        return Ok(());
    }

    fn impl_mem_write_as<T>(&self, va : u64, data : &T) -> ResultEx<()> {
        let cb = u32::try_from(std::mem::size_of::<T>())?;
        let r = (self.native.LcWrite)(self.native.h, va, cb, data as *const _ as *const u8);
        if !r {
            return Err(anyhow!("LcWrite: fail."));
        }
        return Ok(());
    }

    fn impl_command(&self, command_id : u64, data : Option<&Vec<u8>>) -> ResultEx<Option<Vec<u8>>> {
        unsafe {
            let mut pb_out : *mut u8 = std::ptr::null_mut();
            let mut cb_out : u32 = 0;
            let cb_in;
            let pb_in;
            match data {
                Some(data) => {
                    cb_in = u32::try_from(data.len())?;
                    pb_in = data.as_ptr();
                },
                None => {
                    cb_in = 0;
                    pb_in = std::ptr::null();
                },
            }
            let r = (self.native.LcCommand)(self.native.h, command_id, cb_in, pb_in, &mut pb_out, &mut cb_out);
            if !r {
                return Err(anyhow!("LcCommand: fail."));
            }
            if pb_out.is_null() {
                return Ok(None);
            }
            let mut pb_result: Vec<u8> = vec![0u8; cb_out as usize];
            std::ptr::copy_nonoverlapping(pb_out, pb_result.as_mut_ptr(), cb_out as usize);
            (self.native.LcMemFree)(pb_out as usize);
            return Ok(Some(pb_result));
        }
    }

    fn impl_get_memmap(&self) -> ResultEx<String> {
        let memmap_vec = self.command(LeechCore::LC_CMD_MEMMAP_GET, None)?;
        match memmap_vec {
            Some(memmap_vec) => {
                let memmap_str = String::from_utf8(memmap_vec)?;
                return Ok(memmap_str);
            },
            None => {
                return Err(anyhow!("Failed to get memmap."));
            },
        }
    }

    fn impl_set_memmap(&self, str_memmap : &str) -> ResultEx<()> {
        let memmap_vec = str_memmap.as_bytes().to_vec();
        self.command(LeechCore::LC_CMD_MEMMAP_SET, Some(&memmap_vec))?;
        return Ok(());
    }

    fn impl_pcie_bar_info(&self) -> ResultEx<[LcBar; 6]> {
        unsafe {
            let mut cb_out = 0;
            let mut pb_out = 0;
            let r = (self.native.LcCommandPtr)(self.native.h, LeechCore::LC_CMD_FPGA_BAR_INFO, 0, 0, &mut pb_out, &mut cb_out);
            if !r {
                return Err(anyhow!("LcCommand: fail."));
            }
            if pb_out == 0 || cb_out as usize != 6 * std::mem::size_of::<CLC_BAR>() {
                return Err(anyhow!("Failed to get PCIe BARs."));
            }
            let structs = pb_out as *const CLC_BAR;
            let mut result : [LcBar; 6] = [LcBar::default(); 6];
            let pMap = std::slice::from_raw_parts(structs, 6);
            for i in 0..6 {
                let ne = &pMap[i];
                result[i] = LcBar {
                    bar_index : ne.iBar,
                    is_valid : ne.fValid != 0,
                    is_io : ne.fIO != 0,
                    is_64bit : ne.f64Bit != 0,
                    is_prefetchable : ne.fPrefetchable != 0,
                    pa : ne.pa,
                    cb : ne.cb,
                };
            }
            return Ok(result);
        }
    }

    fn impl_pcie_tlp_write(&self, tlp : &[u8]) -> ResultEx<()> {
        if tlp.len() % 4 > 0 {
            return Err(anyhow!("TLP length must be a multiple of 4."));
        }
        let r = (self.native.LcCommand)(self.native.h, LeechCore::LC_CMD_FPGA_TLP_WRITE_SINGLE, tlp.len() as u32, tlp.as_ptr(), std::ptr::null_mut(), std::ptr::null_mut());
        if !r {
            return Err(anyhow!("LcCommand: fail."));
        }
        return Ok(());
    }

    fn impl_pcie_bar_callback<T>(&self, ctx_user : T, fn_bar_callback : fn(ctx : &LcBarContext<T>, req : &LcBarRequest) -> ResultEx<()>) -> ResultEx<LcBarContextWrap<T>> {
        unsafe {
            let ctx = LcBarContext {
                lc : self,
                ctxlock : std::sync::RwLock::new(ctx_user),
                fn_callback : fn_bar_callback,
                native_ctx : 0,
            };
            let ctx_rust_box = Box::new(ctx);
            let ctx_native = Box::into_raw(ctx_rust_box);   // destroys ownership: returned LcBarContextWrap Drop is responsible for free.
            (*ctx_native).native_ctx = ctx_native as usize;
            let native_pfn = LeechCore::impl_pcie_bar_callback_external::<T> as usize;
            let r = (self.native.LcCommandPtr)(self.native.h, LeechCore::LC_CMD_FPGA_BAR_CONTEXT, 0, ctx_native as usize, std::ptr::null_mut(), std::ptr::null_mut());
            if !r {
                return Err(anyhow!("LcCommand: fail."));
            }
            let r = (self.native.LcCommandPtr)(self.native.h, LeechCore::LC_CMD_FPGA_BAR_FUNCTION_CALLBACK, 0, native_pfn, std::ptr::null_mut(), std::ptr::null_mut());
            if !r {
                return Err(anyhow!("LcCommand: fail."));
            }
            let ctx_wrap = LcBarContextWrap {
                ctx : &*ctx_native,
                native : ctx_native,
            };
            return Ok(ctx_wrap);
        }
    }

    fn impl_pcie_tlp_callback<T>(&self, ctx_user : T, fn_tlp_callback : fn(ctx : &LcTlpContext<T>, tlp : &[u8], tlp_str : &str) -> ResultEx<()>) -> ResultEx<LcTlpContextWrap<T>> {
        unsafe {
            let ctx = LcTlpContext {
                lc : self,
                ctxlock : std::sync::RwLock::new(ctx_user),
                fn_callback : fn_tlp_callback,
                native_ctx : 0,
            };
            let ctx_rust_box = Box::new(ctx);
            let ctx_native = Box::into_raw(ctx_rust_box);   // destroys ownership: returned LcTlpContextWrap Drop is responsible for free.
            (*ctx_native).native_ctx = ctx_native as usize;
            let native_pfn = LeechCore::impl_pcie_tlp_callback_external::<T> as usize;
            let r = (self.native.LcSetOption)(self.native.h, LeechCore::LC_OPT_FPGA_TLP_READ_CB_WITHINFO, 1);
            if !r {
                return Err(anyhow!("LcSetOption: fail."));
            }
            let r = (self.native.LcCommandPtr)(self.native.h, LeechCore::LC_CMD_FPGA_TLP_CONTEXT, 0, ctx_native as usize, std::ptr::null_mut(), std::ptr::null_mut());
            if !r {
                return Err(anyhow!("LcCommand: fail."));
            }
            let r = (self.native.LcCommandPtr)(self.native.h, LeechCore::LC_CMD_FPGA_TLP_FUNCTION_CALLBACK, 0, native_pfn, std::ptr::null_mut(), std::ptr::null_mut());
            if !r {
                return Err(anyhow!("LcCommand: fail."));
            }
            let ctx_wrap = LcTlpContextWrap {
                ctx : &*ctx_native,
                native : ctx_native,
            };
            return Ok(ctx_wrap);
        }
    }

    extern "C" fn impl_pcie_tlp_callback_external<T>(native_ctx : *const LcTlpContext<T>, cbTlp : u32, pbTlp : *const u8, cbInfo : u32, szInfo : *const u8) {
        unsafe {
            let ctx : &LcTlpContext<T> = &*native_ctx;
            let tlp = std::slice::from_raw_parts(pbTlp, cbTlp as usize);
            let info = std::str::from_utf8_unchecked(std::slice::from_raw_parts(szInfo, cbInfo as usize));
            let _r = (ctx.fn_callback)(ctx, tlp, info);
        }
    }

    extern "C" fn impl_pcie_bar_callback_external<T>(native_bar_request : *mut LC_BAR_REQUEST) {
        unsafe {
            let req = &*native_bar_request;
            let ctx = &*(req.ctx as *const LcBarContext<T>);
            // assign bar
            let ne = &*req.pBar;
            let bar = LcBar {
                bar_index : ne.iBar,
                is_valid : ne.fValid != 0,
                is_io : ne.fIO != 0,
                is_64bit : ne.f64Bit != 0,
                is_prefetchable : ne.fPrefetchable != 0,
                pa : ne.pa,
                cb : ne.cb,
            };
            // assign bar request
            let data_write : Option<Vec<u8>>;
            if req.fWrite != 0 {
                data_write = Some(std::slice::from_raw_parts(req.pbData.as_ptr(), req.cbData as usize).to_vec());
            } else {
                data_write = None;
            }
            let bar_request = LcBarRequest {
                native : native_bar_request,
                bar,
                tag : req.bTag,
                be_first : req.bFirstBE,
                be_last : req.bLastBE,
                is_64bit : req.f64 != 0,
                is_read : req.fRead != 0,
                is_write : req.fWrite != 0,
                data_size : req.cbData,
                data_offset : req.oData,
                data_write,
            };
            let _r = (ctx.fn_callback)(ctx, &bar_request);
        }
    }
}

#[allow(non_snake_case)]
impl LcBarRequest {
    fn impl_read_reply(&self, data_reply : &[u8], is_fail : bool) -> ResultEx<()> {
        unsafe {
            if !self.is_read {
                return Err(anyhow!("LcBarRequest: only allowed to reply to read requests."));
            }
            if !is_fail && self.data_size != data_reply.len() as u32 {
                return Err(anyhow!("LcBarRequest: reply data size mismatch."));
            }
            (*self.native).fReadReply = 1;
            (*self.native).cbData = data_reply.len() as u32;
            (*self.native).pbData[..data_reply.len()].copy_from_slice(data_reply);
            return Ok(());
        }
    }
}

#[repr(C)]
#[derive(Clone, Debug)]
#[allow(non_snake_case, non_camel_case_types)]
struct CLC_CONFIG {
    dwVersion : u32,
    dwPrintfVerbosity : u32,
    szDevice : [c_char; 260],
    szRemote : [c_char; 260],
    pfn_printf_opt : usize,
    paMax : u64,
    fVolatile : u32,
    fWritable : u32,
    fRemote : u32,
    fRemoteDisableCompress : u32,
    szDeviceName : [c_char; 260],
}

#[repr(C)]
#[derive(Clone, Debug)]
#[allow(non_snake_case, non_camel_case_types)]
struct CLC_BAR {
    fValid : u32,
    fIO : u32,
    f64Bit : u32,
    fPrefetchable : u32,
    _Filler : [u32; 3],
    iBar : u32,
    pa : u64,
    cb : u64,
}

#[repr(C)]
#[derive(Clone, Debug)]
#[allow(non_snake_case, non_camel_case_types)]
struct LC_BAR_REQUEST {
    ctx : usize,
    pBar : *const CLC_BAR,
    bTag : u8,
    bFirstBE : u8,
    bLastBE : u8,
    _Filler : u8,
    f64 : u32,
    fRead : u32,
    fReadReply : u32,
    fWrite : u32,
    cbData : u32,
    oData : u64,
    pbData : [u8; 1024],
}
