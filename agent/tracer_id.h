#ifndef TRACER_ID_H
#define TRACER_ID_H

#define IOC_NR(cmd) (cmd & ((1 << 8)-1))

#define ID_NR_BITS     9
#define ID_UNUSED_BITS 3
#define ID_HDR_BITS    4

#define ID_NR_SIZE     (1 << ID_NR_BITS)
#define ID_HDR_SIZE    (1 << ID_HDR_BITS)

#define ID_NR_MASK     (ID_NR_SIZE-1)
#define ID_HDR_MASK    (ID_HDR_SIZE-1)

#define ID_NR_SHIFT    0
#define ID_HDR_SHIFT   (ID_NR_BITS + ID_UNUSED_BITS)

#define ID_NR(id)      ((id >> ID_NR_SHIFT) & ID_NR_MASK)
#define ID_HDR(id)     ((id >> ID_HDR_SHIFT) & ID_HDR_MASK)

#define ID_HDR_SYSCALL 0x0
#define ID_HDR_IOCTL   0x8
#define ID_HDR_EVENT   0xf

#define ID_IOCTL(cmd)  ((ID_HDR_IOCTL << ID_HDR_SHIFT) | IOC_NR(cmd))
#define ID_EVENT_END   ((ID_HDR_EVENT << ID_HDR_SHIFT) | 0xfff)

#endif
