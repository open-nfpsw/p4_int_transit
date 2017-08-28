#include <errno.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <signal.h>

#include <time.h>

#include <arpa/inet.h>

#include <sys/ioctl.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>

#define LARGE_LATENCY_STEPS

/*
 * Globals
 */

static int quit = 0;

static int latency_mode = 0;
static int latency_enabled = 0;

/*
 * Signal handlers
 */

static void shutdown_handler(int signum)
{
    quit++;
    if (quit > 1)
        exit(EXIT_FAILURE);
}

static void latency_mode_toggle(int signum)
{
    latency_mode = latency_mode ? 0 : 1;
}

static void latency_enabled_toggle(int signum)
{
    latency_enabled = latency_enabled ? 0 : 1;
}

static uint64_t get_time_us(void)
{
    struct timespec tp;
    clock_gettime(CLOCK_MONOTONIC, &tp);
    return tp.tv_sec * 1000000 + tp.tv_nsec / 1000;
}

int main(int argc, char **argv)
{
    /* Destination address */
    struct sockaddr sa;
    struct sockaddr_ll *sll = (void *)&sa;
    struct ifreq ifr;
    char ifname[IFNAMSIZ];
    char buf[1024*16];
    uint64_t prev_time = 0, curr_time;
    int latency_ms = 0;
    int sockopt = 1;
    int socket_fd;
    int ret;

    if (argc != 2) {
        fprintf(stderr, "usage: %s ifname\n", argv[0]);
        return EXIT_FAILURE;
    }

    signal(SIGHUP, shutdown_handler);
    signal(SIGINT, shutdown_handler);
    signal(SIGTERM, shutdown_handler);

    /* make sure the read can be interrupted for clean shutdown */
    siginterrupt(SIGHUP, 1);
    siginterrupt(SIGINT, 1);
    siginterrupt(SIGTERM, 1);

    signal(SIGUSR1, latency_mode_toggle);
    signal(SIGUSR2, latency_enabled_toggle);

    if (strlen(argv[1]) >= IFNAMSIZ - 1) {
        fprintf(stderr, "invalid ifname %s\n", argv[0]);
        return EXIT_FAILURE;
    }

    memset(&ifr, '\0', sizeof(ifr));
    memset(ifname, '\0', sizeof(ifname));
    strcpy(ifname, argv[1]);

    srand(get_time_us());

    socket_fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (socket_fd < 0) {
        fprintf(stderr, "socket() failed (%s)\n", strerror(errno));
        return EXIT_FAILURE;
    }

    strncpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));

    if (ioctl(socket_fd, SIOCGIFFLAGS, &ifr) < 0) {
        fprintf(stderr, "ioctl(SIOCGIFFLAGS) failed (%s)\n", strerror(errno));
        close(socket_fd);
        return EXIT_FAILURE;
    }
    ifr.ifr_flags |= IFF_PROMISC;
    if (ioctl(socket_fd, SIOCSIFFLAGS, &ifr) < 0) {
        fprintf(stderr, "ioctl(SIOCSIFFLAGS) failed (%s)\n", strerror(errno));
        close(socket_fd);
        return EXIT_FAILURE;
    }

    ret = setsockopt(socket_fd,
                     SOL_SOCKET,
                     SO_REUSEADDR,
                     &sockopt,
                     sizeof(sockopt));
    if (ret < 0) {
        fprintf(stderr,
                "setsockopt(SO_REUSEADDR) failed (%s)\n",
                strerror(errno));
        close(socket_fd);
        return EXIT_FAILURE;
    }

    if (ioctl(socket_fd, SIOCGIFINDEX, &ifr) < 0) {
        fprintf(stderr, "ioctl(SIOCGIFINDEX) failed (%s)\n", strerror(errno));
        close(socket_fd);
        return EXIT_FAILURE;
    }

    /* Index of the network device */
    memset(&sa, '\0', sizeof(sa));
    sll->sll_family = PF_PACKET;
    sll->sll_halen = ETH_ALEN;
    sll->sll_ifindex = ifr.ifr_ifindex;

    ret = bind(socket_fd,
               &sa,
               sizeof(*sll));
    if (ret < 0) {
        fprintf(stderr, "bind() failed (%s)\n", strerror(errno));
        close(socket_fd);
        return EXIT_FAILURE;
    }

    while (!quit) {
        ret = recvfrom(socket_fd, buf, sizeof(buf), 0, NULL, NULL);
        if (ret < 0) {
            if (errno == EINTR)
                break;
            fprintf(stderr, "recvfrom() failed (%s)\n", strerror(errno));
            close(socket_fd);
            return EXIT_FAILURE;
        }
        if (ret == 0)
            continue;

        /* latency selection */
        curr_time = get_time_us();
        if (latency_mode == 0 || (curr_time - prev_time > 5000)) {
            // update latency every 5ms or if latency mode is 0
            prev_time = curr_time;

#ifdef LARGE_LATENCY_STEPS
            // latency of 0, 10, 20, 30 or 40ms
            latency_ms = (rand() % 5) * 10;
#else
            // latency of 0 .. 39
            latency_ms = rand() % 40;
#endif
        }

        if (latency_enabled)
            usleep(1000 * latency_ms);

        /* copy in the destaddr */
        memcpy(sll->sll_addr, buf, ETH_ALEN);

        ret = sendto(socket_fd,
                     buf, ret, 0,
                     &sa,
                     sizeof(*sll));
        if (ret < 0) {
            fprintf(stderr, "sendto() failed (%s)\n", strerror(errno));
            close(socket_fd);
            return EXIT_FAILURE;
        }
    }

    close(socket_fd);
    return EXIT_SUCCESS;
}
