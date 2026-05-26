// SPDX-License-Identifier: GPL-2.0+
/*
 * UDP wait trigger — wait for a UDP packet and use it to drive a TFTP boot.
 *
 * Ported from real-time-edge-uboot feature/axisb/udp_tftp_boot (originally
 * implemented for the imx8mp-edc board family). Functional architecture is
 * unchanged: a UDP listener parses an authenticated trigger packet of the
 * form  "<token>:<serverip>:<port>:<bootfile>"  and exports the fields as
 * environment variables for a follow-up tftpboot.
 *
 * Differences vs. the upstream feature branch:
 *   - The token is sourced from CONFIG_TFTP_TRIGGER_TOKEN (Kconfig string),
 *     not a hardcoded literal in this translation unit.
 *   - Diagnostics for the duplicate-packet path use debug() instead of
 *     printf() to avoid log spam under flood.
 *   - <stdbool.h> is not included; <linux/types.h> provides what we need.
 */

#include <common.h>
#include <command.h>
#include <env.h>
#include <net.h>
#include <net/udp_wait.h>
#include <linux/ctype.h>

/* Configurable parameters (populated by the udp_wait command) */
int udp_wait_port;
unsigned long udp_wait_timeout;

static int udp_wait_our_port;
static bool udp_wait_packet_received; /* Track if we've processed a packet */

#ifndef CONFIG_TFTP_TRIGGER_TOKEN
#define CONFIG_TFTP_TRIGGER_TOKEN "edcbrd01"
#endif

#ifndef CONFIG_TFTP_TRIGGER_ACK_PORT
#define CONFIG_TFTP_TRIGGER_ACK_PORT 0
#endif

/*
 * Send a broadcast UDP "check-in" announcing this device's identity so a
 * fleet-tracking listener on the LAN can record who picked up the trigger.
 *
 * Payload (single line, ':' separated):
 *   AXISBACK:<mac>:<ipaddr>:<bootfile>
 *
 * Broadcast is used deliberately so the device doesn't need to ARP the
 * trigger sender (which may be on a different IP than the one we just
 * cached in net_server_ip, and we want this to be best-effort fire-and-
 * forget anyway). The host-side trigger tool binds to the ACK port and
 * dedupes by MAC.
 *
 * Disabled if CONFIG_TFTP_TRIGGER_ACK_PORT == 0.
 */
static void udp_wait_send_ack(const char *bootfile)
{
	int port = CONFIG_TFTP_TRIGGER_ACK_PORT;
	struct in_addr bcast;
	struct in_addr saved_net_ip;
	const char *ipaddr_env;
	const char *ip_str;
	uchar *payload;
	int len;

	if (port <= 0 || port > 65535)
		return;

	/*
	 * do_tftp_trigger_boot temporarily zeroes net_ip so the receive
	 * filter accepts directed broadcasts. That zero would also become
	 * the source IP of our ACK datagram (and of the AXISBACK payload).
	 * Re-derive the link-local from the 'ipaddr' env (set just before
	 * udp_wait was invoked) and pin it for the duration of the send.
	 */
	ipaddr_env = env_get("ipaddr");
	ip_str = (ipaddr_env && *ipaddr_env) ? ipaddr_env : "0.0.0.0";

	saved_net_ip = net_ip;
	if (!net_ip.s_addr && ipaddr_env && *ipaddr_env)
		net_ip = string_to_ip(ipaddr_env);

	payload = (uchar *)net_tx_packet + net_eth_hdr_size() + IP_UDP_HDR_SIZE;
	len = snprintf((char *)payload, 256,
		       "AXISBACK:%02x:%02x:%02x:%02x:%02x:%02x:%s:%s",
		       net_ethaddr[0], net_ethaddr[1], net_ethaddr[2],
		       net_ethaddr[3], net_ethaddr[4], net_ethaddr[5],
		       ip_str,
		       bootfile ? bootfile : "");
	if (len <= 0) {
		net_ip = saved_net_ip;
		return;
	}

	bcast.s_addr = 0xFFFFFFFF;
	net_send_udp_packet((uchar *)net_bcast_ethaddr, bcast, port, port, len);
	printf("UDP wait: ACK sent (bcast port %d, src %s)\n", port, ip_str);

	net_ip = saved_net_ip;
}

static void udp_wait_copy_ip_token(char *dst, size_t dst_len, const char *src)
{
	size_t i = 0;

	if (!dst_len)
		return;

	while (*src && isspace((unsigned char)*src))
		src++;

	while (*src && i + 1 < dst_len) {
		if ((*src >= '0' && *src <= '9') || *src == '.') {
			dst[i++] = *src++;
			continue;
		}
		break;
	}

	dst[i] = '\0';
}

static void udp_wait_trim_trailing_whitespace(char *s)
{
	size_t len;

	if (!s)
		return;

	len = strlen(s);
	while (len && isspace((unsigned char)s[len - 1]))
		s[--len] = '\0';
}

static void udp_wait_timeout_handler(void)
{
	puts("UDP wait: timeout\n");
	net_set_state(NETLOOP_FAIL);
}

/*
 * UDP wait packet handler.
 * Expected payload format: "<token>:<serverip>:<port>:<bootfile>"
 * Example: "edcbrd01:192.168.1.100:69:Image"
 *
 * Only the first matching packet on udp_wait_our_port is processed; later
 * packets are silently dropped (debug log only) to avoid console spam under
 * flood.
 */
static void udp_wait_handler(uchar *pkt, unsigned dest, struct in_addr sip,
			     unsigned src, unsigned len)
{
	char buf[256];
	char *p, *token_str, *serverip_str, *port_str, *bootfile_str;
	char tmp[22];
	char serverip_clean[32];
	struct in_addr serverip_ip;

	if (dest != udp_wait_our_port)
		return;

	if (udp_wait_packet_received) {
		debug("UDP wait: already processed a packet, ignoring\n");
		return;
	}

	if (len == 0 || len >= sizeof(buf)) {
		puts("UDP wait: invalid packet length\n");
		return;
	}

	memcpy(buf, pkt, len);
	buf[len] = '\0';

	printf("UDP wait: received trigger from %pI4:%d\n", &sip, src);

	/*
	 * Parse payload: token:serverip:port:bootfile via strchr.
	 * The token MUST match CONFIG_TFTP_TRIGGER_TOKEN exactly; otherwise
	 * the packet is dropped without state change so a legitimate trigger
	 * can still be accepted later.
	 */
	token_str = buf;
	p = strchr(buf, ':');
	if (!p) {
		puts("UDP wait: malformed payload (no separator)\n");
		return;
	}

	*p = '\0';
	if (strcmp(token_str, CONFIG_TFTP_TRIGGER_TOKEN) != 0) {
		puts("UDP wait: invalid token\n");
		return;
	}

	serverip_str = p + 1;
	p = strchr(serverip_str, ':');
	if (p) {
		*p = '\0';
		port_str = p + 1;
		p = strchr(port_str, ':');
		if (p) {
			*p = '\0';
			bootfile_str = p + 1;
		} else {
			bootfile_str = NULL;
		}
	} else {
		port_str = NULL;
		bootfile_str = NULL;
	}

	/*
	 * IMPORTANT: net/net.c caches server IP in net_server_ip via an env
	 * callback that ignores H_PROGRAMMATIC updates (i.e. env_set()). Since
	 * udp_wait sets variables programmatically, update net_server_ip too.
	 */
	serverip_ip.s_addr = 0;
	serverip_clean[0] = '\0';
	if (serverip_str && *serverip_str) {
		udp_wait_copy_ip_token(serverip_clean, sizeof(serverip_clean),
				       serverip_str);
		serverip_ip = string_to_ip(serverip_clean);
	}
	if (!serverip_ip.s_addr) {
		serverip_ip = sip;
		ip_to_string(serverip_ip, tmp);
		env_set("serverip", tmp);
	} else {
		env_set("serverip", serverip_clean);
	}
	net_server_ip = serverip_ip;

	if (port_str && *port_str) {
		udp_wait_trim_trailing_whitespace(port_str);
		env_set("tftpport", port_str);
	}

	if (bootfile_str && *bootfile_str) {
		udp_wait_trim_trailing_whitespace(bootfile_str);
		env_set("bootfile", bootfile_str);
	}

	/* Store trigger source info for diagnostics */
	ip_to_string(sip, tmp);
	env_set("trigger_srcip", tmp);
	snprintf(tmp, sizeof(tmp), "%d", src);
	env_set("trigger_srcport", tmp);

	printf("UDP wait: trigger accepted, serverip=%s\n", env_get("serverip"));

	/* Best-effort fleet check-in. Failure is intentionally silent. */
	udp_wait_send_ack(bootfile_str);

	udp_wait_packet_received = true;

	/* Cancel timeout handler — we got what we need, exit immediately. */
	net_set_timeout_handler(0, NULL);

	net_set_state(NETLOOP_SUCCESS);
}

int udp_wait_prereq(void *data)
{
	if (udp_wait_port <= 0 || udp_wait_port > 65535) {
		puts("UDP wait: invalid port\n");
		return 1;
	}

	return 0;
}

int udp_wait_start(void *data)
{
	udp_wait_our_port = udp_wait_port;
	udp_wait_packet_received = false;

	printf("UDP wait: listening on port %d (timeout %lu ms)\n",
	       udp_wait_our_port, udp_wait_timeout);

	net_set_timeout_handler(udp_wait_timeout, udp_wait_timeout_handler);
	net_set_udp_handler(udp_wait_handler);
	memset(net_server_ethaddr, 0, sizeof(net_server_ethaddr));

	return 0;
}
