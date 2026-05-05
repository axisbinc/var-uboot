/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * UDP wait trigger header
 */

#ifndef __UDP_WAIT_H__
#define __UDP_WAIT_H__

#define HANDSHAKE_STR "edcbrd01"
/* Configuration for udp_wait */
extern int udp_wait_port;
extern long udp_wait_timeout;

/**
 * udp_wait_prereq() - Check prerequisites for udp_wait
 * @data: Private data (unused)
 * Return: 0 if prerequisites met, 1 otherwise
 */
int udp_wait_prereq(void *data);

/**
 * udp_wait_start() - Start UDP wait listener
 * @data: Private data (unused)
 * Return: 0 on success
 */
int udp_wait_start(void *data);

#endif /* __UDP_WAIT_H__ */
