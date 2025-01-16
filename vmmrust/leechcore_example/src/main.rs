// main.rs - LeechCore Rust API usage examples for PCIe FPGAs.
//
// NB! This file contains examples for pure LeechCore usage in stand-alone mode.
// It's primary focus are on PCIe FPGAs and how to implement PCIe Transaction
// Layer Packets (TLPs) and PCIe Base Address Registers (BARs).
//
// For more general LeechCore useage (possibly together with MemProcFS) check
// out the MemProcFS example project.
//
// (c) Ulf Frisk, 2023-2024
// Author: Ulf Frisk, pcileech@frizk.net
// https://github.com/ufrisk/LeechCore
//

use memprocfs::*;
use std::io::{stdin, Read};
use pretty_hex::*;

pub fn main() {
    leechcore_pcie_example().unwrap();
}

// The following examples require a PCILeech PCIe FPGA device. It demonstrates
// how to receive and send raw Transaction Layer Packets (TLPs) using the FPGA.
// It will also demonstrate how a PCIe BAR can be implemented in software.
//
// For other LeechCore examples such as how to get/set options, use the memory
// map, etc. see the LeechCore examples within the MemProcFS example section.
pub fn leechcore_pcie_example() -> ResultEx<()> {
    println!("LeechCore PCIe Rust API Example - START");


    // Example: Instantiate a new LeechCore instance.
    // This is done without the involvement of MemProcFS.
    let lc_lib_path;
    if cfg!(windows) {
        lc_lib_path = "C:\\Github\\MemProcFS-dev\\files\\leechcore.dll";
    } else if cfg!(target_os = "macos") {
        lc_lib_path = "/Users/user/memprocfs/vmm.dylib";
    } else {
        lc_lib_path = "/home/user/memprocfs/vmm.so";
    }
    let lc = LeechCore::new(lc_lib_path, "fpga://algo=0", LeechCore::LC_CONFIG_PRINTF_ENABLED | LeechCore::LC_CONFIG_PRINTF_V)?;


    // Example: lc.pcie_bar_info():
    // Retrieve PCIe BAR information and display it.
    println!("========================================");
    println!("lc.pcie_bar_info():");
    let bar_info = lc.pcie_bar_info()?;
    for i in 0..bar_info.len() {
        println!("BAR {}: {}", i, bar_info[i]);
    }


    // Example: lc.pcie_tlp_callback():
    // Set up a callback to receive PCIe TLPs sent to the FPGA.
    // It's also possible to send replies/writes back to the FPGA.
    println!("========================================");
    println!("lc.pcie_tlp_callback():");
    let user_ctx_tlp = LeechCorePCIeExampleContextTLP {
        call_count : 0,
    };
    let ctx_tlp = lc.pcie_tlp_callback(user_ctx_tlp, leechcore_pcie_example_tlp_callback)?;


    // Example: lc.pcie_bar_callback():
    // Set up a callback to receive PCIe BAR read/writes sent to the FPGA.
    // Reads should be replied to within the callback function (see example).
    println!("========================================");
    println!("lc.pcie_bar_callback():");
    let user_ctx_bar = LeechCorePCIeExampleContextBAR {
        call_count : 0,
    };
    let ctx_bar = lc.pcie_bar_callback(user_ctx_bar, leechcore_pcie_example_bar_callback)?;


    // Example: lc.get_option():
    // Retrieve PCIe ID of the FPGA device.
    println!("========================================");
    println!("lc.get_option():");
    let pcie_id = lc.get_option(LeechCore::LC_OPT_FPGA_DEVICE_ID)?;
    println!("FPGA PCIe ID: {:#x}", pcie_id);


    // Example: send a custom PCIe TLP towards the target system.
    // The TLP is a MRd32 TLP which reads 4kB of data from the address 0x1000.
    // This should trigger the BAR callback and display the received TLPs.
    // Before sending the TLP must be set with the PCIe Device PCIe ID of the
    // FPGA so the return packets will return correctly. This is done by
    // replacing the dummy 0x33,0x33 values with the FPGA PCIe ID.
    println!("========================================");
    println!("lc.pcie_tlp_write():");
    let mut tlp : [u8; 12] = [0x00, 0x00, 0x00, 0x00, 0x33, 0x33, 0x01, 0xff, 0x00, 0x00, 0x10, 0x00];
    tlp[4] = ((pcie_id >> 8) & 0xff) as u8;
    tlp[5] = (pcie_id & 0xff) as u8;
    println!("{:?}", tlp.hex_dump());
    lc.pcie_tlp_write(&tlp)?;


    // Wait for user input before exiting the example.
    // This is to give the testing of the callbacks a chance to complete.
    // The BAR callback requires data from the target system.
    println!("========================================");
    println!("Press any key to exit...");
    let _ = stdin().read(&mut [0])?;


    // Example: Close/Shut down the BAR and TLP callbacks.
    // This is done automatically when the reference to the context goes
    // out of scope and is dropped. However, it's possible to close the
    // callbacks manually as well with a force drop.
    drop(ctx_bar);
    drop(ctx_tlp);


    // Finish up the example.
    // The LeechCore instance will automatically be dropped and cleaned up
    // when it goes out of scope.
    println!("LeechCore PCIe Rust API Example - COMPLETED");
    return Ok(());
}


// Example user context for the lc.pcie_bar_callback() callback.
pub struct LeechCorePCIeExampleContextBAR {
    pub call_count : u32,
}


// Example user context for the lc.pcie_tlp_callback() callback.
pub struct LeechCorePCIeExampleContextTLP {
    pub call_count : u32,
}


// Example callback function for the lc.pcie_tlp_callback() callback.
// This will receive a TLP together with a context that may be used to
// store user data and perform LeechCore operations - such sending TLPs.
pub fn leechcore_pcie_example_tlp_callback(ctx : &LcTlpContext<LeechCorePCIeExampleContextTLP>, tlp : &[u8], tlp_str : &str) -> ResultEx<()> {
    let mut user_ctx = ctx.ctxlock.write().unwrap();
    user_ctx.call_count += 1;
    println!("========================================");
    println!("LeechCore PCIe TLP Example - Call Count: {}", user_ctx.call_count);
    println!("{:?}", tlp.hex_dump());
    println!("{}", tlp_str);
    return Ok(());
}


// Example implementation of a PCIe BAR. This implementation will only
// reply with a fixed pattern based on the address of the BAR.
// Writes to the BAR will be ignored.
pub fn leechcore_pcie_example_bar_callback(ctx : &LcBarContext<LeechCorePCIeExampleContextBAR>, req : &LcBarRequest) -> ResultEx<()> {
    let mut user_ctx = ctx.ctxlock.write().unwrap();
    user_ctx.call_count += 1;
    println!("========================================");
    println!("LeechCore PCIe BAR Example - Call Count: {} :: {}", user_ctx.call_count, req);
    if req.is_write {
        // This example implementation ignores writes to the BAR from the
        // host system. When a write is received there is no need to ever
        // send a reply back to the host system - so just return here.
        return Ok(());
    }
    // The request is a read-request. A reply of the requested length must be
    // sent back to the host system. Send a read_reply with the requested len.
    // In the example the data replied to contain the byte offset of the BAR.
    let mut data = vec![0u8; req.data_size as usize];
    for i in 0..data.len() {
        data[i] = ((req.data_offset + i as u64) & 0xff) as u8;
    }
    req.read_reply(&data)?;
    return Ok(());
}
