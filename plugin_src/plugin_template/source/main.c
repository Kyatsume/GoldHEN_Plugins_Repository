#include <goldhen/plugin.h>
#include <goldhen/log.h>

void aiofix_network_init(void);

GHP_EXPORT int32_t module_start(size_t argc, const void *args) {
    ghp_log("[aiofix_network] Plugin loaded\n");
    aiofix_network_init();
    return 0;
}

GHP_EXPORT int32_t module_stop(size_t argc, const void *args) {
    ghp_log("[aiofix_network] Plugin unloaded\n");
    return 0;
}
