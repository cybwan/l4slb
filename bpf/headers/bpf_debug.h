/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __BPF_DEBUG_H__
#define __BPF_DEBUG_H__

#define DEBUG 1

#ifdef PRINTNL
#define PRINT_SUFFIX "\n"
#else
#define PRINT_SUFFIX ""
#endif

#ifndef printk
#define printk(fmt, ...)                                                       \
  ({                                                                           \
    char ____fmt[] = fmt PRINT_SUFFIX;                                         \
    bpf_trace_printk(____fmt, sizeof(____fmt), ##__VA_ARGS__);                 \
  })
#endif

#ifndef DEBUG
// do nothing
#define debugf(fmt, ...) ({})
#else
// only print traceing in debug mode
#ifndef debugf
#define debugf(fmt, ...)                                                       \
  ({                                                                           \
    char ____fmt[] = "[debug] " fmt PRINT_SUFFIX;                              \
    bpf_trace_printk(____fmt, sizeof(____fmt), ##__VA_ARGS__);                 \
  })
#endif
#endif

#endif
