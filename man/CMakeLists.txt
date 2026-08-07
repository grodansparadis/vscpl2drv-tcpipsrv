cmake_minimum_required(VERSION 3.10...3.31)
project(man LANGUAGES CXX C)
set(PACKAGE_AUTHOR "Ake Hedman, the VSCP Project")

# --- System Libraries ---
include(GNUInstallDirs)

set(PANDOCCOMMAND_FOUND 0)
find_program(PANDOCCOMMAND_PATH
  NAMES pandoc
  DOC "Path to Pandoc processor. Used to generate man pages from Markdown."
)

if(NOT EXISTS ${PANDOCCOMMAND_PATH})
  message(WARNING "Pandoc processor not found, man pages will not be generated. Install pandoc or use the CMAKE_PROGRAM_PATH variable.")
else()
  set(PANDOCCOMMAND_FOUND 1)
endif()

# if (NOT ${PANDOCCOMMAND_FOUND})
#     message("* * * PanDoc was not found * * *")
# endif()

# man pages
if (${PANDOCCOMMAND_FOUND})
  ADD_CUSTOM_COMMAND(
    OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/vscpl2drv-tcpipsrv.1
    DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/vscpl2drv-tcpipsrv.1.md
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    COMMAND ${PANDOCCOMMAND_PATH} -s -t man vscpl2drv-tcpipsrv.1.md -o ${CMAKE_CURRENT_BINARY_DIR}/vscpl2drv-tcpipsrv.1
    VERBATIM
  )

  ADD_CUSTOM_TARGET(man ALL
    DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/vscpl2drv-tcpipsrv.1
  )
endif()

install(
  FILES ${CMAKE_CURRENT_SOURCE_DIR}/vscpl2drv-tcpipsrv.1
  DESTINATION share/man/man1
)
