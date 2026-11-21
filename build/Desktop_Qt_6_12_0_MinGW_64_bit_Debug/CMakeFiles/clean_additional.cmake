# Additional clean files
cmake_minimum_required(VERSION 3.16)

if("${CONFIG}" STREQUAL "" OR "${CONFIG}" STREQUAL "Debug")
  file(REMOVE_RECURSE
  "CMakeFiles\\PacketAnalyzer_autogen.dir\\AutogenUsed.txt"
  "CMakeFiles\\PacketAnalyzer_autogen.dir\\ParseCache.txt"
  "PacketAnalyzer_autogen"
  )
endif()
