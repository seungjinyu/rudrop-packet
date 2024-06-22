#![no_std]
#![no_main]
#![allow(nonstandard_style, dead_code)]

use aya_ebpf::{
    bindings::xdp_action,
    macros::{map,xdp}, 
    programs::XdpContext,
    maps::HashMap
};
use aya_log_ebpf::info;

use core::mem;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::Ipv4Hdr,
};


#[xdp]
pub fn rudrop_packet(ctx: XdpContext) -> u32 {
    match try_rudrop_packet(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

#[map]
static BLOCKLIST: HashMap<u32, u32> = HashMap::<u32, u32>::with_max_entries(1024, 0 );

fn try_rudrop_packet(ctx: XdpContext) -> Result<u32, ()> {

    let ethhdr: *const EthHdr = unsafe {ptr_at(&ctx, 0)? };
    match unsafe {(*ethhdr).ether_type}{
        EtherType::Ipv4 => {},
        _ => return Ok(xdp_action::XDP_PASS),
    }

    let ipv4hdr : *const Ipv4Hdr = unsafe { ptr_at(&ctx, EthHdr::LEN)?};
    let source = u32::from_be(unsafe {(*ipv4hdr).src_addr});

    let action = if block_ip(source) {
        xdp_action::XDP_DROP
    } else {
        xdp_action::XDP_PASS
    };
    info!(&ctx  , "SRC: {:i} , ACTION: {}", source, action);
    
    Ok(action)
}
#[inline(always)]
unsafe fn ptr_at<T> (ctx: &XdpContext, offset:usize) -> Result<*const T , ()>{
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }
    let ptr = (start + offset) as *const T ;

    Ok(&*ptr)

}

fn block_ip( address: u32) -> bool{
    unsafe { BLOCKLIST.get(&address).is_some()}
}


#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
