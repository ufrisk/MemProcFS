# MemProcFS Rust API

The MemProcFS crate contains a wrapper API around the [MemProcFS physical
memory analysis framework](https://github.com/ufrisk/MemProcFS). The native
libray in the form of `vmm.dll` or `vmm.so` must be downloaded or compiled
in order to make use of the memprocfs rust crate.

The aim of the MemProcFS rust crate and rust API is to make MemProcFS usage
as easy and smooth as possible on Rust! Please let me know what you think
or if you have any improvement suggestions!

Physical memory analysis may take place on memory dump files for forensic
purposes. Analysis may also take place on live memory - either captured by
using [PCILeech PCIe DMA devices](https://github.com/ufrisk/pcileech-fpga)
or by using a driver - such as WinPMEM, LiveCloudKd, VMware or similar.

The base of the MemProcFS API is the `Vmm` struct. Once the native vmm
has been initialized it's possible to retrieve processes in the form of
the `VmmProcess` struct. Using the `Vmm` and `VmmProcess` it's
possible to undertake a wide range of actions - such as reading/writing
memory or retrieve various information.

<b>Access the VFS</b> (Virtual File System) via the Rust API to get access
to the full range of built-in and external plugins.

<b>Read and write memory</b> by using the methods `mem_read()`,
`mem_read_ex()`, `mem_write()` of the `Vmm` and `VmmProcess` structs.

<b>Efficiently read and write memory</b> using the `VmmScatterMemory`
struct.

The MemProcFS rust API supports creation of native MemProcFS plugins in
the form of a library `.dll` or `.so` for the more advanced user.


## Example

```Rust
let mut args = Vec::new();
args.push("-printf");
args.push("-device");
args.push("-FPGA");
let vmm = Vmm::new("/home/user/memprocfs/vmm.so", &args)?
if let Ok(process_all) = vmm.process_list() {
    for process in &*process_all {
        println!("{} : {}", process.pid, process.info()?.name);
    }
}
```


## Example projects
Check out the example documentation, both in the form of the [example
project](https://github.com/ufrisk/MemProcFS/tree/master/vmmrust/memprocfs_example)
and the [example MemProcFS plugin](https://github.com/ufrisk/MemProcFS/tree/master/vmmrust/m_example_plugin)


## Project documentation
Check out the project documentation for MemProcFS, LeechCore and pcileech-fpga:
* [MemProcFS](https://github.com/ufrisk/MemProcFS) - [Documentation](https://github.com/ufrisk/MemProcFS/wiki).
* [LeechCore](https://github.com/ufrisk/LeechCore/) - [Documentation](https://github.com/ufrisk/LeechCore/wiki).
* [PCILeech](https://github.com/ufrisk/pcileech) - [Documentation](https://github.com/ufrisk/pcileech/wiki).
* [PCILeech-FPGA](https://github.com/ufrisk/pcileech-fpga).


## License
MemProcFS and its rust API is  open source under the [AGPL-3.0](https://github.com/ufrisk/MemProcFS/blob/master/LICENSE) license.


# Support PCILeech/MemProcFS development:
PCILeech and MemProcFS is free and open source!

I put a lot of time and energy into PCILeech and MemProcFS and related research to make this happen. Some aspects of the projects relate to hardware and I put quite some money into my projects and related research. If you think PCILeech and/or MemProcFS are awesome tools and/or if you had a use for them it's now possible to contribute by becoming a sponsor!

If you like what I've created with PCIleech and MemProcFS with regards to DMA, Memory Analysis and Memory Forensics and would like to give something back to support future development please consider becoming a sponsor at: <https://github.com/sponsors/ufrisk>

To all my sponsors, Thank You 💖


## Questions and Comments
Please feel free to contact me!
* Github: <https://github.com/ufrisk/MemProcFS>
* Discord: UlfFrisk#5780
* Discord #pcileech channel at the [Porchetta](https://discord.gg/sEkn3aa) server.
* Twitter: <https://twitter.com/UlfFrisk>
* Email: pcileech@frizk.net


## Get Started!
Check out the `Vmm` documentation and the [example project](https://github.com/ufrisk/MemProcFS/tree/master/vmmrust/memprocfs_example)!

<b>Best wishes with your memory analysis Rust project!</b>
