#include <stdint.h>

typedef void (*packet_cb) (const int ptype, const uint8_t *packet, const int len, const char* ifname);
typedef void (*handle_cb) (int h, void* ctx);
typedef void (*signal_cb) (int h);

void cb_add_packet_cb(packet_cb cb);
void cb_call_packet_cb(const int ptype, const uint8_t *packet, const int len, const char* ifname);
void cb_add_handle(int h, void* ctx, handle_cb cb);
void cb_add_signal(int s, signal_cb cb);

void event_runloop();
