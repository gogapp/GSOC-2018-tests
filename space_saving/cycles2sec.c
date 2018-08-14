#include "cycles2sec.h"

uint64_t cycles_per_sec = 0UL;
uint64_t cycles_per_msec = 0UL;
uint64_t cycles_per_usec = 0UL;

void
cycles_to_sec_init()
{
    struct timeval tv_start;
    struct timeval tv_now;
    
    uint64_t tsc_start = rte_rdtsc();
    gettimeofday(&tv_start, NULL);

    while (1) {
        gettimeofday(&tv_now, NULL);

        uint64_t diff = (uint64_t)(tv_now.tv_sec - tv_start.tv_sec) * 1000000UL + (uint64_t)(tv_now.tv_usec - tv_start.tv_usec);

        if (diff >= 1000000UL) {
            uint64_t tsc_now = rte_rdtsc();
            cycles_per_sec = (tsc_now - tsc_start) * 1000000UL / diff;
            cycles_per_msec = cycles_per_sec / 1000UL;
            cycles_per_usec = cycles_per_msec / 1000UL;
            break;
        }
    }

    printf("\nIn current system, there are around %" PRIu64 "cycles per second!\n", cycles_per_sec);
}

extern uint64_t
time_diff_in_us(uint64_t new_tsc, uint64_t old_tsc)
{
    return (new_tsc - old_tsc) * 1000000UL / cycles_per_sec;
}

extern double
time_diff_in_s(uint64_t new_tsc, uint64_t old_tsc)
{
    return (double)time_diff_in_us(new_tsc, old_tsc) * 0.000001;
}
