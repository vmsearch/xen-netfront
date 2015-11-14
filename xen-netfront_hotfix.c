#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/skbuff.h>
#include <linux/ethtool.h>
#include <linux/if_ether.h>
#include <net/tcp.h>
#include <linux/udp.h>
#include <linux/moduleparam.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <net/ip.h>
#include <linux/kallsyms.h>
#include <linux/cpu.h>

#include <asm/xen/page.h>
#include <xen/xen.h>
#include <xen/xenbus.h>
#include <xen/events.h>
#include <xen/page.h>
#include <xen/platform_pci.h>
#include <xen/grant_table.h>

#include <xen/interface/io/netif.h>
#include <xen/interface/memory.h>
#include <xen/interface/grant_table.h>

#define RELATIVEJUMP_SIZE	5
#define RELATIVEJUMP_OPCODE	0xe9
#define RX_COPY_THRESHOLD 256

#define NET_TX_RING_SIZE __CONST_RING_SIZE(xen_netif_tx, PAGE_SIZE)
#define NET_RX_RING_SIZE __CONST_RING_SIZE(xen_netif_rx, PAGE_SIZE)
#define TX_MAX_TARGET min_t(int, NET_TX_RING_SIZE, 256)


unsigned char inst[RELATIVEJUMP_SIZE];
static void *(*my_text_poke_smp)(void *addr, const void *opcode, size_t len);
static void *orig___xennet_alloc_rx_buffers;

struct mutex *my_text_mutex;

struct netfront_info {
	struct list_head list;
	struct net_device *netdev;

	struct napi_struct napi;

	/* Split event channels support, tx_* == rx_* when using
	 * single event channel.
	 */
	unsigned int tx_evtchn, rx_evtchn;
	unsigned int tx_irq, rx_irq;
	/* Only used when split event channels support is enabled */
	char tx_irq_name[IFNAMSIZ+4]; /* DEVNAME-tx */
	char rx_irq_name[IFNAMSIZ+4]; /* DEVNAME-rx */

	struct xenbus_device *xbdev;

	spinlock_t   tx_lock;
	struct xen_netif_tx_front_ring tx;
	int tx_ring_ref;

	/*
	 * {tx,rx}_skbs store outstanding skbuffs. Free tx_skb entries
	 * are linked from tx_skb_freelist through skb_entry.link.
	 *
	 *  NB. Freelist index entries are always going to be less than
	 *  PAGE_OFFSET, whereas pointers to skbs will always be equal or
	 *  greater than PAGE_OFFSET: we use this property to distinguish
	 *  them.
	 */
	union skb_entry {
		struct sk_buff *skb;
		unsigned long link;
	} tx_skbs[NET_TX_RING_SIZE];
	grant_ref_t gref_tx_head;
	grant_ref_t grant_tx_ref[NET_TX_RING_SIZE];
	unsigned tx_skb_freelist;

	spinlock_t   rx_lock ____cacheline_aligned_in_smp;
	struct xen_netif_rx_front_ring rx;
	int rx_ring_ref;

	/* Receive-ring batched refills. */
#define RX_MIN_TARGET 8
#define RX_DFL_MIN_TARGET 64
#define RX_MAX_TARGET min_t(int, NET_RX_RING_SIZE, 256)
	unsigned rx_min_target, rx_max_target, rx_target;
	struct sk_buff_head rx_batch;

	struct timer_list rx_refill_timer;

	struct sk_buff *rx_skbs[NET_RX_RING_SIZE];
	grant_ref_t gref_rx_head;
	grant_ref_t grant_rx_ref[NET_RX_RING_SIZE];

	unsigned long rx_pfn_array[NET_RX_RING_SIZE];
	struct multicall_entry rx_mcl[NET_RX_RING_SIZE+1];
	struct mmu_update rx_mmu[NET_RX_RING_SIZE];

	/* Statistics */
	struct netfront_stats __percpu *stats;

	unsigned long rx_gso_checksum_fixup;
};


struct netfront_rx_info {
	struct xen_netif_rx_response rx;
	struct xen_netif_extra_info extras[XEN_NETIF_EXTRA_TYPE_MAX - 1];
};

static int xennet_rxidx(RING_IDX idx)
{
	return idx & (NET_RX_RING_SIZE - 1);
}



static void overwrite__xennet_alloc_rx_buffers(struct net_device *dev)
{
	unsigned short id;
	struct netfront_info *np = netdev_priv(dev);
	struct sk_buff *skb;
	struct page *page;
	int i, batch_target, notify;
	RING_IDX req_prod = np->rx.req_prod_pvt;
	grant_ref_t ref;
	unsigned long pfn;
	void *vaddr;
	struct xen_netif_rx_request *req;

	if (unlikely(!netif_carrier_ok(dev)))
		return;

        if (!np->rx.sring)
        {
            printk("rx sring is null\n");
            return;
        }
        printk("req_prod is %d , np sring rsp_prod is %d\n", req_prod, np->rx.sring->rsp_prod);

	/*
	 * Allocate skbuffs greedily, even though we batch updates to the
	 * receive ring. This creates a less bursty demand on the memory
	 * allocator, so should reduce the chance of failed allocation requests
	 * both for ourself and for other kernel subsystems.
	 */
	batch_target = np->rx_target - (req_prod - np->rx.rsp_cons);
	for (i = skb_queue_len(&np->rx_batch); i < batch_target; i++) {
		skb = __netdev_alloc_skb(dev, RX_COPY_THRESHOLD + NET_IP_ALIGN,
					 GFP_ATOMIC | __GFP_NOWARN);
		if (unlikely(!skb))
			goto no_skb;

		/* Align ip header to a 16 bytes boundary */
		skb_reserve(skb, NET_IP_ALIGN);

		page = alloc_page(GFP_ATOMIC | __GFP_NOWARN);
		if (!page) {
			kfree_skb(skb);
no_skb:
			/* Any skbuffs queued for refill? Force them out. */
			//if (i != 0)
			//	goto refill;
			/* Could not allocate any skbuffs. Try again later. */
			mod_timer(&np->rx_refill_timer,
				  jiffies + (HZ/10));

                        if (i != 0)
                              goto refill;
			break;
		}

		skb_add_rx_frag(skb, 0, page, 0, 0, PAGE_SIZE);
		__skb_queue_tail(&np->rx_batch, skb);
	}
        

	/* Is the batch large enough to be worthwhile? */
	if (i < (np->rx_target/2)) {
		if (req_prod > np->rx.sring->req_prod)
			goto push;
		return;
	}

	/* Adjust our fill target if we risked running out of buffers. */
	if (((req_prod - np->rx.sring->rsp_prod) < (np->rx_target / 4)) &&((np->rx_target *= 2) > np->rx_max_target)) {
	    np->rx_target = np->rx_max_target;
        }

 refill:
	for (i = 0; ; i++) {
		skb = __skb_dequeue(&np->rx_batch);
		if (skb == NULL)
			break;

		skb->dev = dev;

		id = xennet_rxidx(req_prod + i);

		BUG_ON(np->rx_skbs[id]);
		np->rx_skbs[id] = skb;

		ref = gnttab_claim_grant_reference(&np->gref_rx_head);
		BUG_ON((signed short)ref < 0);
		np->grant_rx_ref[id] = ref;

		pfn = page_to_pfn(skb_frag_page(&skb_shinfo(skb)->frags[0]));
		vaddr = page_address(skb_frag_page(&skb_shinfo(skb)->frags[0]));

		req = RING_GET_REQUEST(&np->rx, req_prod + i);
		gnttab_grant_foreign_access_ref(ref,
						np->xbdev->otherend_id,
						pfn_to_mfn(pfn),
						0);

		req->id = id;
		req->gref = ref;
	}

	wmb();		/* barrier so backend seens requests */

	/* Above is a suitable barrier to ensure backend will see requests. */
	np->rx.req_prod_pvt = req_prod + i;
 push:
	RING_PUSH_REQUESTS_AND_CHECK_NOTIFY(&np->rx, notify);
	if (notify)
		notify_remote_via_irq(np->rx_irq);
}


static int __init xennet_alloc_rx_buffer_init(void)
{
	unsigned char e9_jmp[RELATIVEJUMP_SIZE];
	s32 offset;
        printk("alloc buffer init\n");

	my_text_poke_smp = (void *)kallsyms_lookup_name("text_poke_smp");
	if (!my_text_poke_smp)
		return -EINVAL;

	my_text_mutex = (void *)kallsyms_lookup_name("text_mutex");
	if (!my_text_mutex)
		return -EINVAL;

	orig___xennet_alloc_rx_buffers =
		(void *)kallsyms_lookup_name("xennet_alloc_rx_buffers");
	if (!orig___xennet_alloc_rx_buffers)
		return -EINVAL;

	offset = (s32)((long)overwrite__xennet_alloc_rx_buffers -
			(long)orig___xennet_alloc_rx_buffers - RELATIVEJUMP_SIZE);

	memcpy(inst, orig___xennet_alloc_rx_buffers, RELATIVEJUMP_SIZE);

	e9_jmp[0] = RELATIVEJUMP_OPCODE;
	(*(s32 *)(&e9_jmp[1])) = offset;

	get_online_cpus();
	mutex_lock(my_text_mutex);
	my_text_poke_smp(orig___xennet_alloc_rx_buffers, e9_jmp, RELATIVEJUMP_SIZE);
	mutex_unlock(my_text_mutex);
	put_online_cpus();
	
	return 0;
}

static void __exit xennet_alloc_rx_buffer_exit(void)
{
	get_online_cpus();
	mutex_lock(my_text_mutex);
	my_text_poke_smp(orig___xennet_alloc_rx_buffers, inst, RELATIVEJUMP_SIZE);
	mutex_unlock(my_text_mutex);
	put_online_cpus();

	smp_mb();
}

module_init(xennet_alloc_rx_buffer_init);
module_exit(xennet_alloc_rx_buffer_exit);

MODULE_AUTHOR("Yibo zhou <zhyb_163@163.com>");
MODULE_DESCRIPTION("info for xennet front");
MODULE_LICENSE("GPL");
MODULE_VERSION("1.0.0");
