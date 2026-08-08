//
//  clock_alarm.h
//  Dopamine
//
//  Created by Lars Fröder on 03.08.26.
//

#include <sys/types.h>

kern_return_t clock_alarm_preserve_port(mach_port_t surfacePort, uint32_t delaySeconds);
