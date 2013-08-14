#include <getopt.h>

typedef void (*option_cb)(int c);
void add_option_cb(struct option opt, option_cb cb);
void parse_cmdline();
