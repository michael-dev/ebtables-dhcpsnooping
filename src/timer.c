#include "config.h"

#include "event.h"
#include <unistd.h>
#include <signal.h>

#define PRUNE_INTERVAL 300

void timer(int s)
{
	alarm (PRUNE_INTERVAL);
}

static __attribute__((constructor)) void timer_init()
{
	cb_add_signal(SIGALRM, timer);
	alarm (PRUNE_INTERVAL);
}

