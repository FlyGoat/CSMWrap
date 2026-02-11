#ifndef _TIME_H
#define _TIME_H

#include <stdint.h>

extern uint64_t tsc_freq;

void calibrate_tsc(void);
uint64_t get_nanoseconds_since_boot(void);
void delay(uint64_t cycles);
void delay_us(uint64_t us);

#endif
