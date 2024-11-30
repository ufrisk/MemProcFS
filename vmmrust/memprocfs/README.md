# MemProcFS Rust API

The MemProcFS crate contains a wrapper API around the [MemProcFS physical
memory analysis framework](https://github.com/ufrisk/MemProcFS). The native
libray in the form of `vmm.dll` or `vmm.so` must be compiled or
[downloaded](https://github.com/ufrisk/MemProcFS/releases/latest) in order
to make use of the memprocfs rust crate.

The aim of the MemProcFS Rust Crate and API is to make MemProcFS usage
easy and smooth on Rust! Please let me know what you think or if you have
any improvement suggestions!

Physical memory analysis may take place on memory dump files for forensic
purposes. Analysis may also take place on live memory - either captured by
using [PCILeech PCIe DMA devices](https://github.com/ufrisk/pcileech-fpga)
or by using drivers - such as WinPMEM, LiveCloudKd, VMware or similar.

<b>Rust API Versioning follows MemProcFS major.minor versioning.</b>
Always use the matching MemProcFS Native library version for the major.minor
number. <b>Revision numbers</b> may however be higher (but not lower) in the
Native library than in the Rust API. Bug fixes often takes place in the Native
library without the Rust API being updated. It's possible to use Rust API
version 5.8.1 with MemProcFS 5.8.10 for example. It is not supported to use
Rust API version 5.8.1 with MemProcFS 5.7.x or MemProcFS 5.9.x.

<b>Base of the MemProcFS API</b> is the [`Vmm`](https://docs.rs/memprocfs/latest/memprocfs/struct.Vmm.html)
struct. Once the native vmm has been initialized it's possible to retrieve
processes in the form of the [`VmmProcess`](https://docs.rs/memprocfs/latest/memprocfs/struct.VmmProcess.html) struct.
Using the `Vmm` and `VmmProcess` it's possible to undertake a wide range of
actions - such as reading/writing memory and retrieving various information.

<b>Read and write memory</b> by using the methods
[`mem_read()`](https://docs.rs/memprocfs/latest/memprocfs/struct.VmmProcess.html#method.mem_read),
[`mem_read_ex()`](https://docs.rs/memprocfs/latest/memprocfs/struct.VmmProcess.html#method.mem_read_ex),
[`mem_read_as()`](https://docs.rs/memprocfs/latest/memprocfs/struct.VmmProcess.html#method.mem_read_as),
[`mem_write()`](https://docs.rs/memprocfs/latest/memprocfs/struct.VmmProcess.html#method.mem_write),
[`mem_write_as()`](https://docs.rs/memprocfs/latest/memprocfs/struct.VmmProcess.html#method.mem_write_as) of the
[`Vmm`](https://docs.rs/memprocfs/latest/memprocfs/struct.Vmm.html) and
[`VmmProcess`](https://docs.rs/memprocfs/latest/memprocfs/struct.VmmProcess.html) structs.

<b>Efficiently read and write memory</b> using the [`VmmScatterMemory`](https://docs.rs/memprocfs/latest/memprocfs/struct.VmmScatterMemory.html) struct.

<b>Get info</b> about loaded modules, memory regions, registry, process handles, kernel pool allocations and much more!

<b>Access the VFS</b> (Virtual File System) via the Rust API to get access to the full range of built-in and external plugins.

The MemProcFS rust API supports creation of native MemProcFS plugins in the form of a library `.dll` or `.so` for the more advanced user.


## Examples

```
// Initialize MemProcFS on Linux targeting a live Windows system
// by reading memory using a PCILeech PCIe FPGA hardware device.
// After initialization list all processes.
let mut args = ["-printf", "-device", "fpga"].to_vec();
let vmm = Vmm::new("/home/user/memprocfs/vmm.so", &args)?
if let Ok(process_all) = vmm.process_list() {
    for process in &*process_all {
        println!("{} : {}", process.pid, process.info()?.name);
    }
}
```

```
// Initialize MemProcFS on Windows - analyzing a memory dump file.
// Also trigger the forensic mode and scan for VMs.
// List all processes in the virtual file system directory /name/.
let mut args = ["-printf", "-forensic", "1", "-vm",
                "-device", "C:\\dumps\\memory.dmp"].to_vec();
let vmm = Vmm::new("C:\\MemProcFS\\vmm.dll", &args)?
if let Ok(vfs_all) = vmm.vfs_list("/name/") {
    println!("Number of files/directories: {}.", vfs_all.len());
    for vfs in &*vfs_all {
        println!("{vfs}");
    }
}
```


## Example projects
Check out the
[example project](https://github.com/ufrisk/MemProcFS/blob/master/vmmrust/memprocfs_example/src/main.rs) and the 
[example MemProcFS plugin](https://github.com/ufrisk/MemProcFS/blob/master/vmmrust/m_example_plugin/src/lib.rs).


## Project documentation
Check out the project documentation for MemProcFS, LeechCore and pcileech-fpga:
* [MemProcFS](https://github.com/ufrisk/MemProcFS) - [Documentation](https://github.com/ufrisk/MemProcFS/wiki).
* [LeechCore](https://github.com/ufrisk/LeechCore/) - [Documentation](https://github.com/ufrisk/LeechCore/wiki).
* [PCILeech](https://github.com/ufrisk/pcileech) - [Documentation](https://github.com/ufrisk/pcileech/wiki).
* [PCILeech-FPGA](https://github.com/ufrisk/pcileech-fpga).


## Questions and Comments
Please feel free to contact me!
* Github: <https://github.com/ufrisk/MemProcFS>
* Discord: <https://discord.gg/pcileech>
* Twitter: <https://twitter.com/UlfFrisk>
* Email: pcileech@frizk.net


## Get Started!
Check out the [MemProcFS documentation](https://docs.rs/memprocfs/latest/memprocfs/) and the [example project](https://github.com/ufrisk/MemProcFS/tree/master/vmmrust/memprocfs_example)!

<b>Best wishes with your Rust memory analysis project!</b>
