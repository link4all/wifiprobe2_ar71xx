#ifndef CAOSX_DEBUG_H
#define CAOSX_DEBUG_H

extern void debug_init(void);
extern void debug_msg(const char *message, ...);

extern FILE *debug_file;

#define C_DEBUG 1

#define DEBUG_INIT() debug_init()
#define DEBUG_MSG(x, ...)  printf("DEBUG: "x"\n", ## __VA_ARGS__ );     


#endif
