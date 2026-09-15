//! TUN adapter: Windows (wintun via tun-rs, admin required, "Starskiff"
//! adapter) and Linux (/dev/net/tun, interface `skiff0`). IPv4-only by
//! design; non-IPv4 outbound packets are dropped by the engine.

use std::net::Ipv4Addr;
use std::sync::Arc;

use skiff_core::ipam::Cidr;
use skiff_core::logging::LogFn;
use tokio::sync::mpsc;

const ADAPTER_NAME: &str = if cfg!(windows) { "Starskiff" } else { "skiff0" };
#[cfg(windows)]
const RING_CAPACITY: u32 = 4 * 1024 * 1024; // 4 MiB ring buffer
const READ_BUF: usize = 65535;

pub struct TunDevice {
    tx: mpsc::UnboundedSender<Vec<u8>>,
}

impl TunDevice {
    /// Open + configure the TUN interface. Returns the device handle and a
    /// receiver of OS-origin packets (engine outbound).
    pub fn start(
        ip: Ipv4Addr,
        cidr: Cidr,
        mtu: u32,
        log: LogFn,
    ) -> anyhow::Result<(TunDevice, mpsc::Receiver<Vec<u8>>)> {
        #[cfg(windows)]
        ensure_admin()?;
        #[cfg(not(windows))]
        ensure_root_and_dev()?;

        #[allow(unused_mut)]
        let mut builder = tun_rs::DeviceBuilder::new()
            .name(ADAPTER_NAME)
            .ipv4(ip, cidr.prefix as u8, None)
            .mtu(mtu as u16);
        #[cfg(windows)]
        {
            builder = builder.ring_capacity(RING_CAPACITY);
        }
        let device = builder
            .build_async()
            .map_err(|e| anyhow::anyhow!("TUN 设备创建失败: {e}（驱动缺失或权限不足）"))?;
        let device = Arc::new(device);

        let (outbound_tx, outbound_rx) = mpsc::channel::<Vec<u8>>(256);
        let (inject_tx, mut inject_rx) = mpsc::unbounded_channel::<Vec<u8>>();

        // OS -> engine.
        let reader_log = log.clone();
        let reader_dev = Arc::clone(&device);
        tokio::spawn(async move {
            let mut buf = vec![0u8; READ_BUF];
            loop {
                match reader_dev.recv(&mut buf).await {
                    Ok(n) => {
                        if outbound_tx.send(buf[..n].to_vec()).await.is_err() {
                            break;
                        }
                    }
                    Err(e) => {
                        (reader_log)(&format!("TUN 读取错误: {e}"));
                        break;
                    }
                }
            }
        });

        // Engine -> OS. A full wintun ring surfaces as an error here: drop
        // the packet, inner TCP retransmits.
        let writer_log = log.clone();
        let writer_dev = Arc::clone(&device);
        tokio::spawn(async move {
            while let Some(packet) = inject_rx.recv().await {
                if let Err(e) = writer_dev.send(&packet).await {
                    (writer_log)(&format!("TUN 写入失败（丢弃一包，内层 TCP 将重传）: {e}"));
                }
            }
        });

        (log)(&format!("TUN 已启动: {}/{} mtu={}", ip, cidr.prefix, mtu));
        Ok((TunDevice { tx: inject_tx }, outbound_rx))
    }

    /// Engine-inbound DATA frames -> OS (sync: never blocks the engine loop).
    pub fn write_packet(&self, packet: &[u8]) {
        let _ = self.tx.send(packet.to_vec());
    }
}

#[cfg(windows)]
fn ensure_admin() -> anyhow::Result<()> {
    if !skiff_core::platform::is_root() {
        anyhow::bail!("TUN 模式需要管理员权限运行（Windows 服务请用 service install 安装）");
    }
    Ok(())
}

#[cfg(not(windows))]
fn ensure_root_and_dev() -> anyhow::Result<()> {
    if !skiff_core::platform::is_root() {
        anyhow::bail!("TUN 模式需要 root 权限（Linux 服务请用 service install 安装）");
    }
    if !std::path::Path::new("/dev/net/tun").exists() {
        anyhow::bail!("/dev/net/tun 不存在（尝试 modprobe tun；容器需 --device /dev/net/tun）");
    }
    Ok(())
}
