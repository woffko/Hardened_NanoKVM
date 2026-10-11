list(APPEND ADD_REQUIREMENTS vision basic peripheral)
list(APPEND ADD_INCLUDE "include")
list(APPEND ADD_LINK_DEFINITIONS_PRIVATE -Wl,--as-needed)

append_srcs_dir(ADD_SRCS "src")

register_component(DYNAMIC)
set_target_properties(kvm PROPERTIES SKIP_BUILD_RPATH TRUE)
