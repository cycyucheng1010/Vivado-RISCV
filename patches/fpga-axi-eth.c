// SPDX-License-Identifier: GPL-2.0-or-later

#include <linux/kernel.h>
#include <linux/jiffies.h>
#include <linux/module.h>
#include <linux/interrupt.h>
#include <linux/fs.h>
#include <linux/types.h>
#include <linux/string.h>
#include <linux/socket.h>
#include <linux/errno.h>
#include <linux/fcntl.h>
#include <linux/in.h>

#include <linux/uaccess.h>
#include <linux/io.h>

#include <linux/inet.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/skbuff.h>
#include <linux/ethtool.h>
#include <net/sock.h>
#include <net/checksum.h>
#include <linux/if_ether.h> /* For the statistics structure. */
#include <linux/if_arp.h>   /* For ARPHRD_ETHER */
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/percpu.h>
#include <linux/net_tstamp.h>
#include <net/net_namespace.h>
#include <linux/u64_stats_sync.h>
#include <linux/of.h>
#include <linux/of_device.h>
#include <linux/dma-mapping.h>

/*
* AXI Ethernet driver.
*
* AXI Ethernet is open source Verilog implementation of high speed ethernet controller.
* It is mainly used in FPGA designs.
*/

#ifdef CONFIG_DEBUG_INFO
#pragma GCC optimize("O0")
#endif

#define AXI_ETH_MIN_MTU (ETH_ZLEN + ETH_HLEN)
#define AXI_ETH_MAX_MTU 9000

#define AXI_ETH_RING_MASK 0xf
#define AXI_ETH_RING_SIZE (AXI_ETH_RING_MASK + 1)

struct eth_regs {
    volatile uint32_t net_status;
    volatile uint32_t mac_status;
    volatile uint32_t int_enable;
    volatile uint32_t int_status;
    volatile uint32_t rx_inp;
    volatile uint32_t rx_out;
    volatile uint32_t tx_inp;
    volatile uint32_t tx_out;
};

struct eth_pkt_regs {
    volatile uint32_t addr;
    volatile uint32_t size;
    volatile uint32_t done;
    volatile uint32_t status;
};

#define NET_STATUS_LINK_OK      (1 << 0)
#define NET_STATUS_LINK_SYNC    (1 << 1)
#define NET_STATUS_RUDI_C       (1 << 2)
#define NET_STATUS_RUDI_I       (1 << 3)
#define NET_STATUS_RUDI_ERR     (1 << 4)
#define NET_STATUS_RXDISPERR    (1 << 5)
#define NET_STATUS_RXNOTINTABLE (1 << 6)
#define NET_STATUS_PHY_LINK_OK  (1 << 7)
#define NET_STATUS_SPEED_100    (1 << 10)
#define NET_STATUS_SPEED_1000   (1 << 11)
#define NET_STATUS_DUPLEX       (1 << 12)
#define NET_STATUS_REMOTE_FAULT (1 << 13)
#define NET_STATUS_PAUSE_SYM    (1 << 14)
#define NET_STATUS_PAUSE_ASYM   (1 << 15)

#define MAC_STATUS_RX_BUSY      (1 << 0)
#define MAC_STATUS_TX_BUSY      (1 << 1)
#define MAC_STATUS_AXI_WR_CYC   (1 << 2)
#define MAC_STATUS_AXI_WR_ERR   (1 << 3)
#define MAC_STATUS_AXI_RD_CYC   (1 << 4)
#define MAC_STATUS_AXI_RD_ERR   (1 << 5)

struct axi_eth_ring_item {
    struct sk_buff * skb;
    dma_addr_t dma_addr;
};

struct axi_eth_priv {
    struct eth_regs __iomem * regs;
    struct eth_pkt_regs __iomem * rx_pkt_regs;
    struct eth_pkt_regs __iomem * tx_pkt_regs;
    struct platform_device * pdev;
    spinlock_t lock;
    int irq;

    uint32_t int_enable;
    struct axi_eth_ring_item rx_ring[AXI_ETH_RING_SIZE];
    struct axi_eth_ring_item tx_ring[AXI_ETH_RING_SIZE];
    uint32_t rx_inp;
    uint32_t rx_out;
    uint32_t tx_inp;
    uint32_t tx_out;
};

#define tx_ring_free(p) ((p->tx_out - p->tx_inp - 1) & AXI_ETH_RING_MASK)

static const struct of_device_id axi_eth_of_match_table[] = {
    { .compatible = "riscv,axi-ethernet-1.0" },
    {},
};
MODULE_DEVICE_TABLE(of, axi_eth_of_match_table);

static netdev_tx_t axi_eth_xmit(struct sk_buff * skb, struct net_device * dev) {
    struct axi_eth_priv * priv = netdev_priv(dev);
    uint32_t tx_next = (priv->tx_inp + 1) & AXI_ETH_RING_MASK;
    dma_addr_t dma_addr;

    if (skb->len < ETH_ZLEN && skb_padto(skb, ETH_ZLEN)) {
        netdev_err(dev, "Padding error\n");
        dev_kfree_skb_any(skb);
        return NETDEV_TX_OK;
    }

    spin_lock_irq(&priv->lock);

    if (tx_next == priv->tx_out) {
        struct axi_eth_ring_item * i = priv->tx_ring + priv->tx_out;
        struct sk_buff * skb = i->skb;
        while (priv->tx_out == priv->regs->tx_out) {}
        if (skb) {
            dev_consume_skb_any(skb);
            dma_unmap_single(&priv->pdev->dev, i->dma_addr, skb->len, DMA_TO_DEVICE);
            i->skb = NULL;
        }
        priv->tx_out = (priv->tx_out + 1) & AXI_ETH_RING_MASK;
    }

    skb_tx_timestamp(skb);

    dma_addr = dma_map_single(&priv->pdev->dev, skb->data, skb->len, DMA_TO_DEVICE);
    if (dma_mapping_error(&priv->pdev->dev, dma_addr)) {
        netdev_err(dev, "DMA mapping error\n");
        dev_kfree_skb_any(skb);
    }
    else {
        struct axi_eth_ring_item * i = priv->tx_ring + priv->tx_inp;
        i->skb = skb;
        i->dma_addr = dma_addr;
        priv->tx_pkt_regs[priv->tx_inp].addr = i->dma_addr;
        priv->tx_pkt_regs[priv->tx_inp].size = skb->len;
        priv->regs->tx_inp = priv->tx_inp = tx_next;
        dev->stats.tx_bytes += skb->len;
    }

    if (tx_ring_free(priv) == 0) netif_stop_queue(dev);

    spin_unlock_irq(&priv->lock);

    return NETDEV_TX_OK;
}

static void axi_eth_get_stats64(struct net_device * dev, struct rtnl_link_stats64 * stats) {
    u64 bytes = 0;
    u64 packets = 0;
    int i;

    for_each_possible_cpu(i) {
        const struct pcpu_lstats *lb_stats;
        u64 tbytes, tpackets;
        unsigned int start;

        lb_stats = per_cpu_ptr(dev->lstats, i);
        do {
            start = u64_stats_fetch_begin_irq(&lb_stats->syncp);
            tbytes = lb_stats->bytes;
            tpackets = lb_stats->packets;
        }
        while (u64_stats_fetch_retry_irq(&lb_stats->syncp, start));
        bytes   += tbytes;
        packets += tpackets;
    }
    stats->rx_packets = packets;
    stats->tx_packets = packets;
    stats->rx_bytes   = bytes;
    stats->tx_bytes   = bytes;
}

static int axi_eth_change_mtu(struct net_device * dev, int new_mtu) {
    struct axi_eth_priv * priv = netdev_priv(dev);

    spin_lock_irq(&priv->lock);

    while (priv->rx_inp != priv->rx_out) {
        struct axi_eth_ring_item * i = priv->rx_ring + priv->rx_out;
        struct sk_buff * skb = i->skb;
        while (priv->rx_out == priv->regs->rx_out) {}
        if (skb) {
            dev_kfree_skb_any(skb);
            dma_unmap_single(&priv->pdev->dev, i->dma_addr, dev->mtu + ETH_HLEN, DMA_FROM_DEVICE);
            i->skb = NULL;
        }
        priv->rx_out = (priv->rx_out + 1) & AXI_ETH_RING_MASK;
    }

    spin_unlock_irq(&priv->lock);

    dev->mtu = new_mtu;
    return 0;
}

static irqreturn_t axi_eth_isr(int irq, void * dev_id) {
    struct net_device * dev = dev_id;
    struct axi_eth_priv * priv = netdev_priv(dev);
    unsigned long flags;

    spin_lock_irqsave(&priv->lock, flags);

    for (;;) {
        int cont = 0;
        uint32_t rx_next = (priv->rx_inp + 1) & AXI_ETH_RING_MASK;
        if (rx_next != priv->rx_out) {
            struct axi_eth_ring_item * i = priv->rx_ring + priv->rx_inp;
            struct sk_buff * skb = netdev_alloc_skb_ip_align(dev, dev->mtu + ETH_HLEN);
            if (!skb) {
                dev->stats.rx_dropped++;
                break;
            }
            i->dma_addr = dma_map_single(&priv->pdev->dev, skb->data, dev->mtu + ETH_HLEN, DMA_FROM_DEVICE);
            if (dma_mapping_error(&priv->pdev->dev, i->dma_addr)) {
                netdev_err(dev, "DMA mapping error\n");
                dev_kfree_skb_irq(skb);
                break;
            }
            i->skb = skb;
            priv->rx_pkt_regs[priv->rx_inp].addr = i->dma_addr;
            priv->rx_pkt_regs[priv->rx_inp].size = dev->mtu + ETH_HLEN;
            priv->regs->rx_inp = priv->rx_inp = rx_next;
            cont = 1;
        }
        priv->regs->int_status = 0;
        if (priv->rx_out != priv->regs->rx_out) {
            struct axi_eth_ring_item * i = priv->rx_ring + priv->rx_out;
            struct sk_buff * skb = i->skb;
            if (skb) {
                skb->dev = dev;
                skb_put(skb, priv->rx_pkt_regs[priv->rx_out].done);
                skb->protocol = eth_type_trans(skb, dev);
                skb->ip_summed = CHECKSUM_NONE;
                dev->stats.rx_packets++;
                dev->stats.rx_bytes += skb->len;
                dma_unmap_single(&priv->pdev->dev, i->dma_addr, dev->mtu + ETH_HLEN, DMA_FROM_DEVICE);
                netif_rx(skb);
                i->skb = NULL;
            }
            priv->rx_out = (priv->rx_out + 1) & AXI_ETH_RING_MASK;
            cont = 1;
        }
        if (priv->tx_out != priv->regs->tx_out) {
            struct axi_eth_ring_item * i = priv->tx_ring + priv->tx_out;
            struct sk_buff * skb = i->skb;
            if (skb) {
                dev_consume_skb_irq(skb);
                dma_unmap_single(&priv->pdev->dev, i->dma_addr, skb->len, DMA_TO_DEVICE);
                i->skb = NULL;
            }
            priv->tx_out = (priv->tx_out + 1) & AXI_ETH_RING_MASK;
            cont = 1;
        }
        if (!cont) break;
    }

    if (netif_queue_stopped(dev) &&
        tx_ring_free(priv) >= AXI_ETH_RING_SIZE / 2)
        netif_wake_queue(dev);

    spin_unlock_irqrestore(&priv->lock, flags);

    return IRQ_HANDLED;
}

static u32 always_on(struct net_device * dev) {
    return 1;
}

static const struct ethtool_ops axi_eth_ethtool_ops = {
    .get_link       = always_on,
    .get_ts_info    = ethtool_op_get_ts_info,
};

static int axi_eth_dev_init(struct net_device * dev) {
    struct axi_eth_priv * priv = netdev_priv(dev);
    int ret;

    dev->lstats = netdev_alloc_pcpu_stats(struct pcpu_lstats);
    if (!dev->lstats) return -ENOMEM;

    spin_lock_irq(&priv->lock);

    priv->regs->int_enable = priv->int_enable = 0;
    ret = request_irq(priv->irq, axi_eth_isr, IRQF_TRIGGER_HIGH, "fpga-axi-eth", dev);
    if (ret) return ret;

    priv->rx_inp = priv->regs->rx_inp;
    priv->rx_out = priv->regs->rx_out;
    priv->tx_inp = priv->regs->tx_inp;
    priv->tx_out = priv->regs->tx_out;

    priv->regs->int_enable = priv->int_enable = (1 << 16) | (1 << 17);

    spin_unlock_irq(&priv->lock);

    return 0;
}

static void axi_eth_dev_free(struct net_device * dev) {
    struct axi_eth_priv * priv = netdev_priv(dev);

    spin_lock_irq(&priv->lock);

    priv->regs->int_enable = 0;

    while (priv->rx_inp != priv->rx_out) {
        struct axi_eth_ring_item * i = priv->rx_ring + priv->rx_out;
        struct sk_buff * skb = i->skb;
        while (priv->rx_out == priv->regs->rx_out) {}
        if (skb) {
            dev_kfree_skb_any(skb);
            dma_unmap_single(&priv->pdev->dev, i->dma_addr, dev->mtu + ETH_HLEN, DMA_FROM_DEVICE);
            i->skb = NULL;
        }
        priv->rx_out = (priv->rx_out + 1) & AXI_ETH_RING_MASK;
    }
    while (priv->tx_inp != priv->tx_out) {
        struct axi_eth_ring_item * i = priv->tx_ring + priv->tx_out;
        struct sk_buff * skb = i->skb;
        while (priv->tx_out == priv->regs->tx_out) {}
        if (skb) {
            dev_consume_skb_any(skb);
            dma_unmap_single(&priv->pdev->dev, i->dma_addr, skb->len, DMA_TO_DEVICE);
            i->skb = NULL;
        }
        priv->tx_out = (priv->tx_out + 1) & AXI_ETH_RING_MASK;
    }

    spin_unlock_irq(&priv->lock);

    free_irq(priv->irq, priv);
    free_percpu(dev->lstats);
}

static const struct net_device_ops axi_eth_ops = {
    .ndo_init        = axi_eth_dev_init,
    .ndo_start_xmit  = axi_eth_xmit,
    .ndo_get_stats64 = axi_eth_get_stats64,
    .ndo_set_mac_address = eth_mac_addr,
    .ndo_change_mtu = axi_eth_change_mtu,
#ifdef CONFIG_NET_POLL_CONTROLLER
    .ndo_poll_controller = axi_eth_poll_controller,
#endif
};

/* Setup and register the device. */
static int axi_eth_probe(struct platform_device * pdev) {
    struct net_device * dev = NULL;
    struct axi_eth_priv * priv = NULL;
    struct resource * iomem;
    void __iomem * ioaddr;
    int err = -ENOMEM;
    const u8 * maddr;
    int len;
    int irq;

    iomem = platform_get_resource(pdev, IORESOURCE_MEM, 0);
    ioaddr = devm_ioremap_resource(&pdev->dev, iomem);
    if (IS_ERR(ioaddr)) return PTR_ERR(ioaddr);

    irq = platform_get_irq(pdev, 0);
    if (irq <= 0) return -ENXIO;

    dev = alloc_etherdev(sizeof(struct axi_eth_priv));
    if (!dev) goto out;

    dev->min_mtu = AXI_ETH_MIN_MTU;
    dev->max_mtu = AXI_ETH_MAX_MTU;
    dev->ethtool_ops = &axi_eth_ethtool_ops;
    dev->netdev_ops = &axi_eth_ops;
    dev->needs_free_netdev = true;
    dev->priv_destructor = axi_eth_dev_free;

    priv = netdev_priv(dev);
    spin_lock_init(&priv->lock);
    priv->regs = (struct eth_regs __iomem *)ioaddr;
    priv->rx_pkt_regs = (struct eth_pkt_regs __iomem *)((char *)ioaddr + 0x800);
    priv->tx_pkt_regs = (struct eth_pkt_regs __iomem *)((char *)ioaddr + 0xc00);
    priv->pdev = pdev;
    priv->irq = irq;

    maddr = of_get_property(pdev->dev.of_node, "local-mac-address", &len);
    if (maddr && len == ETH_ALEN) {
        memcpy(dev->dev_addr, maddr, ETH_ALEN);
    }
    else {
        printk(KERN_ERR "AXI-ETH: Can't get MAC address\n");
        err = -ENODEV;
        goto out;
    }

    err = register_netdev(dev);
    if (err) goto out;

    return 0;

out:
    if (dev) free_netdev(dev);
    return err;
}

static int axi_eth_remove(struct platform_device * pdev) {
    struct net_device * dev = platform_get_drvdata(pdev);
    unregister_netdev(dev);
    free_netdev(dev);
    return 0;
}

static struct platform_driver axi_eth_driver = {
    .driver = {
        .name = "riscv-axi-eth",
        .of_match_table = axi_eth_of_match_table,
    },
    .probe = axi_eth_probe,
    .remove = axi_eth_remove,
};

module_platform_driver(axi_eth_driver);

MODULE_DESCRIPTION("AXI Ethernet driver");
MODULE_AUTHOR("Eugene Tarassov");
MODULE_LICENSE("GPL v2");
