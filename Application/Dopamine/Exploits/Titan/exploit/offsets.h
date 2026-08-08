#ifndef OFFSETS_H
#define OFFSETS_H

#define OFFSET_vm_map_min                   (0x20)
#define OFFSET_vm_map_max                   (0x28)
#define OFFSET_rtk_thread_saved_state       (0x48)

#define static_koffsetof(x, y) OFFSET_##x##_##y

#endif // OFFSETS_H
