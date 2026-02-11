#ifndef _IO_H
#define _IO_H

#include <efi.h>
#include <printf.h>
#include <stdbool.h>

#define barrier() __asm__ __volatile__("": : :"memory")

static inline void clflush(void *addr) {
    // Cache CPUID.01H:EDX[19] (CLFLUSH support) to avoid repeated CPUID calls
    static int has_clflush = -1;
    if (has_clflush == -1) {
        uint32_t eax, ebx, ecx, edx;
        asm volatile ("cpuid" : "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx) : "a"(1) : "memory");
        has_clflush = (edx >> 19) & 1;
    }
    if (has_clflush) {
        asm volatile ("clflush (%0)" :: "r"(addr) : "memory");
    } else {
        // Fall back to wbinvd (flushes entire cache, requires ring 0)
        asm volatile ("wbinvd" ::: "memory");
    }
}

static inline void writel(void *addr, uint32_t val) {
    barrier();
    *(volatile uint32_t *)addr = val;
}
static inline void writew(void *addr, uint16_t val) {
    barrier();
    *(volatile uint16_t *)addr = val;
}
static inline void writeb(void *addr, uint8_t val) {
    barrier();
    *(volatile uint8_t *)addr = val;
}
static inline uint64_t readq(const void *addr) {
    uint64_t val = *(volatile const uint64_t *)addr;
    barrier();
    return val;
}
static inline uint32_t readl(const void *addr) {
    uint32_t val = *(volatile const uint32_t *)addr;
    barrier();
    return val;
}
static inline uint16_t readw(const void *addr) {
    uint16_t val = *(volatile const uint16_t *)addr;
    barrier();
    return val;
}
static inline uint8_t readb(const void *addr) {
    uint8_t val = *(volatile const uint8_t *)addr;
    barrier();
    return val;
}

#ifdef __OPTIMIZE__

#define	__use_immediate_port(port) \
	(__builtin_constant_p(((int)port)) && ((int)port) < 0x100)

#else

#define	__use_immediate_port(port)	0

#endif


#define	inb(port) \
	(__use_immediate_port((int)port) ? __inbc((int)port) : __inb((int)port))

static inline uint8_t
__inbc(int port)
{
	uint8_t data;
	asm volatile("inb %w1,%0" : "=a" (data) : "id" (port) : "memory");
	return data;
}

static inline uint8_t
__inb(int port)
{
	uint8_t data;
	asm volatile("inb %w1,%0" : "=a" (data) : "d" (port) : "memory");
	return data;
}

static inline void
insb(int port, void *addr, int cnt)
{
	asm volatile("cld\n\trepne\n\tinsb"
	    : "+D" (addr), "+c" (cnt) : "d" (port) : "memory", "cc");
}

#define	inw(port) \
	(__use_immediate_port((int)port) ? __inwc((int)port) : __inw((int)port))

static inline uint16_t
__inwc(int port)
{
	uint16_t data;
	asm volatile("inw %w1,%0" : "=a" (data) : "id" (port) : "memory");
	return data;
}

static inline uint16_t
__inw(int port)
{
	uint16_t data;
	asm volatile("inw %w1,%0" : "=a" (data) : "d" (port) : "memory");
	return data;
}

static inline void
insw(int port, void *addr, int cnt)
{
	asm volatile("cld\n\trepne\n\tinsw"
	    : "+D" (addr), "+c" (cnt) : "d" (port) : "memory", "cc");
}

#define	inl(port) \
	(__use_immediate_port(port) ? __inlc((int)port) : __inl((int)port))

static inline uint32_t
__inlc(int port)
{
	uint32_t data;
	asm volatile("inl %w1,%0" : "=a" (data) : "id" (port) : "memory");
	return data;
}

static inline uint32_t
__inl(int port)
{
	uint32_t data;
	asm volatile("inl %w1,%0" : "=a" (data) : "d" (port) : "memory");
	return data;
}

static inline void
insl(int port, void *addr, int cnt)
{
	asm volatile("cld\n\trepne\n\tinsl"
	    : "+D" (addr), "+c" (cnt) : "d" (port) : "memory", "cc");
}

#define	outb(port, data) \
	(__use_immediate_port(port) ? __outbc((int)port, data) : __outb((int)port, data))

static inline void
__outbc(int port, uint8_t data)
{
	asm volatile("outb %0,%w1" : : "a" (data), "id" (port) : "memory");
}

static inline void
__outb(int port, uint8_t data)
{
	asm volatile("outb %0,%w1" : : "a" (data), "d" (port) : "memory");
}

static inline void
outsb(int port, const void *addr, int cnt)
{
	asm volatile("cld\n\trepne\n\toutsb"
	    : "+S" (addr), "+c" (cnt) : "d" (port) : "cc", "memory");
}

#define	outw(port, data) \
	(__use_immediate_port(port) ? __outwc((int)port, data) : __outw((int)port, data))

static inline void
__outwc(int port, uint16_t data)
{
	asm volatile("outw %0,%w1" : : "a" (data), "id" (port) : "memory");
}

static inline void
__outw(int port, uint16_t data)
{
	asm volatile("outw %0,%w1" : : "a" (data), "d" (port) : "memory");
}

static inline void
outsw(int port, const void *addr, int cnt)
{
	asm volatile("cld\n\trepne\n\toutsw"
	    : "+S" (addr), "+c" (cnt) : "d" (port) : "cc", "memory");
}

#define	outl(port, data) \
	(__use_immediate_port(port) ? __outlc((int)port, data) : __outl((int)port, data))

static inline void
__outlc(int port, uint32_t data)
{
	asm volatile("outl %0,%w1" : : "a" (data), "id" (port) : "memory");
}

static inline void
__outl(int port, uint32_t data)
{
	asm volatile("outl %0,%w1" : : "a" (data), "d" (port) : "memory");
}

static inline void
outsl(int port, const void *addr, int cnt)
{
	asm volatile("cld\n\trepne\n\toutsl"
	    : "+S" (addr), "+c" (cnt) : "d" (port) : "cc", "memory");
}

#define PCI_CONFIG_ADDRESS 0xcf8
#define PCI_CONFIG_DATA 0xcfc

static inline void pciSetAddress(unsigned int bus, unsigned int slot,
                   unsigned int function, unsigned int offset)
{
    uint32_t address;

    /* Address bits (inclusive):
     * 31      Enable bit (must be 1 for it to work)
     * 30 - 24 Reserved
     * 23 - 16 Bus number
     * 15 - 11 Slot number
     * 10 - 8  Function number (for multifunction devices)
     * 7 - 2   Register number (offset / 4)
     * 1 - 0   Must always be 00 */
    address = 0x80000000 | ((unsigned long) (bus & 0xff) << 16)
              | ((unsigned long) (slot & 0x1f) << 11)
              | ((unsigned long) (function & 0x7) << 8)
              | ((unsigned long) offset & 0xff);
    /* Full DWORD write to port must be used for PCI to detect new address. */
    outl(PCI_CONFIG_ADDRESS, address);
}

static inline uint8_t pciConfigReadByte(unsigned int bus, unsigned int slot,
                                unsigned int function, unsigned int offset)
{
    pciSetAddress(bus, slot, function, offset);
    /* The PCI registers are little endian,
     * so the last byte of DWORD is read
     * when offset is 0. */
    return (inb(PCI_CONFIG_DATA + (offset & 3)));
}

static inline uint16_t pciConfigReadWord(unsigned int bus, unsigned int slot,
                               unsigned int function, unsigned int offset)
{
    pciSetAddress(bus, slot, function, offset);
    /* The PCI registers are little endian,
     * so the last word of DWORD is read
     * when offset is 0. */
    return (inw(PCI_CONFIG_DATA + (offset & 2)));
}

static inline uint32_t pciConfigReadDWord(unsigned int bus, unsigned int slot,
                                 unsigned int function, unsigned int offset)
{
    pciSetAddress(bus, slot, function, offset);
    return (inl(PCI_CONFIG_DATA));
}

static inline void pciConfigWriteByte(unsigned int bus, unsigned int slot,
                        unsigned int function, unsigned int offset,
                        uint8_t data)
{
    pciSetAddress(bus, slot, function, offset);
    /* The PCI registers are little endian,
     * so the last byte of DWORD is written
     * when offset is 0. */
    outb(PCI_CONFIG_DATA + (offset & 3), data);
}

static inline void pciConfigWriteWord(unsigned int bus, unsigned int slot,
                        unsigned int function, unsigned int offset,
                        uint16_t data)
{
    pciSetAddress(bus, slot, function, offset);
    /* The PCI registers are little endian,
     * so the last word of DWORD is written
     * when offset is 0. */
    outw(PCI_CONFIG_DATA + (offset & 2), data);
}

static inline void pciConfigWriteDWord(unsigned int bus, unsigned int slot,
                         unsigned int function, unsigned int offset,
                         uint32_t data)
{
    pciSetAddress(bus, slot, function, offset);
    outl(PCI_CONFIG_DATA, data);
}

static inline uint64_t rdmsr(uint32_t index) {
    uint32_t edx, eax;
    asm volatile ("rdmsr" : "=a"(eax), "=d"(edx) : "c"(index) : "memory");
    return ((uint64_t)edx << 32) | eax;
}

static inline void wrmsr(uint32_t index, uint64_t val) {
    asm volatile ("wrmsr" :: "a"((uint32_t)val), "d"((uint32_t)(val >> 32)), "c"(index) : "memory");
}

static inline uint64_t rdtsc(void) {
    uint32_t edx, eax;
    asm volatile ("rdtsc" : "=a" (eax), "=d" (edx) :: "memory");
    return ((uint64_t)edx << 32) | eax;
}

#endif
