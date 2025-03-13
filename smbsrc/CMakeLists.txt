##################################################
#                                                #
# Main CMakeLists for UniPlayer Project.         #
#                                                #
# Author :                                       #
##################################################

AUX_SOURCE_DIRECTORY(. SRC_PLUGINS_SMBSRC)
include_directories (${PUBLIC_INCLUDE_PATH})
include_directories (.)

add_library(gstsmbsrc SHARED ${SRC_PLUGINS_SMBSRC})
add_definitions(-D_FILE_OFFSET_BITS=64)
if(${TVOS_PLATFORM} STREQUAL clang)
if(${TVOS_BUILD_PROFILE} STREQUAL 32)

TARGET_LINK_LIBRARIES(
gstsmbsrc
-Wl,--gc-sections
-Wl,--warn-shared-textrel
-Wl,--exclude-libs,libatomic.a
-Wl,--exclude-libs,libgcc.a
-Wl,--exclude-libs,libgcc_real.a
-Wl,--exclude-libs,libunwind.a
-Wl,--fix-cortex-a8
gstbase-1.0
gstreamer-1.0
gobject-2.0
gmodule-2.0
gthread-2.0
glib-2.0
smbinterface
)
else()
TARGET_LINK_LIBRARIES(
gstsmbsrc
-Wl,--gc-sections
-Wl,--warn-shared-textrel
-Wl,--exclude-libs,libatomic.a
-Wl,--exclude-libs,libgcc.a
-Wl,--exclude-libs,libgcc_real.a
-Wl,--exclude-libs,libunwind.a
gstbase-1.0
gstreamer-1.0
gobject-2.0
gmodule-2.0
gthread-2.0
glib-2.0
smbinterface
)
endif()
endif()
