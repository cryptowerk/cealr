# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.6

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:


#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:


# Remove some rules from gmake that .SUFFIXES does not remove.
SUFFIXES =

.SUFFIXES: .hpux_make_needs_suffix_list


# Suppress display of executed commands.
$(VERBOSE).SILENT:


# A target that is always out of date.
cmake_force:

.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /Applications/CLion.app/Contents/bin/cmake/bin/cmake

# The command to remove a file.
RM = /Applications/CLion.app/Contents/bin/cmake/bin/cmake -E remove -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /Users/olaf/CLionProjects/cealr

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /Users/olaf/CLionProjects/cealr

# Include any dependencies generated for this target.
include CMakeFiles/cealr.dir/depend.make

# Include the progress variables for this target.
include CMakeFiles/cealr.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/cealr.dir/flags.make

CMakeFiles/cealr.dir/src/cealr.cpp.o: CMakeFiles/cealr.dir/flags.make
CMakeFiles/cealr.dir/src/cealr.cpp.o: src/cealr.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/Users/olaf/CLionProjects/cealr/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object CMakeFiles/cealr.dir/src/cealr.cpp.o"
	/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/c++   $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/cealr.dir/src/cealr.cpp.o -c /Users/olaf/CLionProjects/cealr/src/cealr.cpp

CMakeFiles/cealr.dir/src/cealr.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/cealr.dir/src/cealr.cpp.i"
	/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /Users/olaf/CLionProjects/cealr/src/cealr.cpp > CMakeFiles/cealr.dir/src/cealr.cpp.i

CMakeFiles/cealr.dir/src/cealr.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/cealr.dir/src/cealr.cpp.s"
	/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /Users/olaf/CLionProjects/cealr/src/cealr.cpp -o CMakeFiles/cealr.dir/src/cealr.cpp.s

CMakeFiles/cealr.dir/src/cealr.cpp.o.requires:

.PHONY : CMakeFiles/cealr.dir/src/cealr.cpp.o.requires

CMakeFiles/cealr.dir/src/cealr.cpp.o.provides: CMakeFiles/cealr.dir/src/cealr.cpp.o.requires
	$(MAKE) -f CMakeFiles/cealr.dir/build.make CMakeFiles/cealr.dir/src/cealr.cpp.o.provides.build
.PHONY : CMakeFiles/cealr.dir/src/cealr.cpp.o.provides

CMakeFiles/cealr.dir/src/cealr.cpp.o.provides.build: CMakeFiles/cealr.dir/src/cealr.cpp.o


CMakeFiles/cealr.dir/src/Properties.cpp.o: CMakeFiles/cealr.dir/flags.make
CMakeFiles/cealr.dir/src/Properties.cpp.o: src/Properties.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/Users/olaf/CLionProjects/cealr/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Building CXX object CMakeFiles/cealr.dir/src/Properties.cpp.o"
	/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/c++   $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/cealr.dir/src/Properties.cpp.o -c /Users/olaf/CLionProjects/cealr/src/Properties.cpp

CMakeFiles/cealr.dir/src/Properties.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/cealr.dir/src/Properties.cpp.i"
	/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /Users/olaf/CLionProjects/cealr/src/Properties.cpp > CMakeFiles/cealr.dir/src/Properties.cpp.i

CMakeFiles/cealr.dir/src/Properties.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/cealr.dir/src/Properties.cpp.s"
	/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /Users/olaf/CLionProjects/cealr/src/Properties.cpp -o CMakeFiles/cealr.dir/src/Properties.cpp.s

CMakeFiles/cealr.dir/src/Properties.cpp.o.requires:

.PHONY : CMakeFiles/cealr.dir/src/Properties.cpp.o.requires

CMakeFiles/cealr.dir/src/Properties.cpp.o.provides: CMakeFiles/cealr.dir/src/Properties.cpp.o.requires
	$(MAKE) -f CMakeFiles/cealr.dir/build.make CMakeFiles/cealr.dir/src/Properties.cpp.o.provides.build
.PHONY : CMakeFiles/cealr.dir/src/Properties.cpp.o.provides

CMakeFiles/cealr.dir/src/Properties.cpp.o.provides.build: CMakeFiles/cealr.dir/src/Properties.cpp.o


CMakeFiles/cealr.dir/src/CurlUtil.cpp.o: CMakeFiles/cealr.dir/flags.make
CMakeFiles/cealr.dir/src/CurlUtil.cpp.o: src/CurlUtil.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/Users/olaf/CLionProjects/cealr/CMakeFiles --progress-num=$(CMAKE_PROGRESS_3) "Building CXX object CMakeFiles/cealr.dir/src/CurlUtil.cpp.o"
	/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/c++   $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/cealr.dir/src/CurlUtil.cpp.o -c /Users/olaf/CLionProjects/cealr/src/CurlUtil.cpp

CMakeFiles/cealr.dir/src/CurlUtil.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/cealr.dir/src/CurlUtil.cpp.i"
	/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /Users/olaf/CLionProjects/cealr/src/CurlUtil.cpp > CMakeFiles/cealr.dir/src/CurlUtil.cpp.i

CMakeFiles/cealr.dir/src/CurlUtil.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/cealr.dir/src/CurlUtil.cpp.s"
	/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /Users/olaf/CLionProjects/cealr/src/CurlUtil.cpp -o CMakeFiles/cealr.dir/src/CurlUtil.cpp.s

CMakeFiles/cealr.dir/src/CurlUtil.cpp.o.requires:

.PHONY : CMakeFiles/cealr.dir/src/CurlUtil.cpp.o.requires

CMakeFiles/cealr.dir/src/CurlUtil.cpp.o.provides: CMakeFiles/cealr.dir/src/CurlUtil.cpp.o.requires
	$(MAKE) -f CMakeFiles/cealr.dir/build.make CMakeFiles/cealr.dir/src/CurlUtil.cpp.o.provides.build
.PHONY : CMakeFiles/cealr.dir/src/CurlUtil.cpp.o.provides

CMakeFiles/cealr.dir/src/CurlUtil.cpp.o.provides.build: CMakeFiles/cealr.dir/src/CurlUtil.cpp.o


# Object files for target cealr
cealr_OBJECTS = \
"CMakeFiles/cealr.dir/src/cealr.cpp.o" \
"CMakeFiles/cealr.dir/src/Properties.cpp.o" \
"CMakeFiles/cealr.dir/src/CurlUtil.cpp.o"

# External object files for target cealr
cealr_EXTERNAL_OBJECTS =

cealr: CMakeFiles/cealr.dir/src/cealr.cpp.o
cealr: CMakeFiles/cealr.dir/src/Properties.cpp.o
cealr: CMakeFiles/cealr.dir/src/CurlUtil.cpp.o
cealr: CMakeFiles/cealr.dir/build.make
cealr: /usr/lib/libcurl.dylib
cealr: CMakeFiles/cealr.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/Users/olaf/CLionProjects/cealr/CMakeFiles --progress-num=$(CMAKE_PROGRESS_4) "Linking CXX executable cealr"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/cealr.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/cealr.dir/build: cealr

.PHONY : CMakeFiles/cealr.dir/build

CMakeFiles/cealr.dir/requires: CMakeFiles/cealr.dir/src/cealr.cpp.o.requires
CMakeFiles/cealr.dir/requires: CMakeFiles/cealr.dir/src/Properties.cpp.o.requires
CMakeFiles/cealr.dir/requires: CMakeFiles/cealr.dir/src/CurlUtil.cpp.o.requires

.PHONY : CMakeFiles/cealr.dir/requires

CMakeFiles/cealr.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/cealr.dir/cmake_clean.cmake
.PHONY : CMakeFiles/cealr.dir/clean

CMakeFiles/cealr.dir/depend:
	cd /Users/olaf/CLionProjects/cealr && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /Users/olaf/CLionProjects/cealr /Users/olaf/CLionProjects/cealr /Users/olaf/CLionProjects/cealr /Users/olaf/CLionProjects/cealr /Users/olaf/CLionProjects/cealr/CMakeFiles/cealr.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/cealr.dir/depend
