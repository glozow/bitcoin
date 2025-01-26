# Copyright (c) 2025 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.

function(add_libmultiprocess subdir)
  # Set BUILD_TESTING to match BUILD_TESTS. BUILD_TESTING is a standard cmake
  # option that controls whether enable_testing() is called, but in the bitcoin
  # build a BUILD_TESTS option is used instead.
  set(BUILD_TESTING "${BUILD_TESTS}")
  add_subdirectory(${subdir} EXCLUDE_FROM_ALL)
  # Apply core_interface compile options to libmultiprocess runtime library.
  target_link_libraries(multiprocess PUBLIC $<BUILD_INTERFACE:core_interface>)
  target_link_libraries(mputil PUBLIC $<BUILD_INTERFACE:core_interface>)
  target_link_libraries(mpgen PUBLIC $<BUILD_INTERFACE:core_interface>)
  # Mark capproto options as advanced to hide by default from cmake UI
  mark_as_advanced(CapnProto_DIR)
  mark_as_advanced(CapnProto_capnpc_IMPORTED_LOCATION)
  mark_as_advanced(CapnProto_capnp_IMPORTED_LOCATION)
  mark_as_advanced(CapnProto_capnp-json_IMPORTED_LOCATION)
  mark_as_advanced(CapnProto_capnp-rpc_IMPORTED_LOCATION)
  mark_as_advanced(CapnProto_capnp-websocket_IMPORTED_LOCATION)
  mark_as_advanced(CapnProto_kj-async_IMPORTED_LOCATION)
  mark_as_advanced(CapnProto_kj-gzip_IMPORTED_LOCATION)
  mark_as_advanced(CapnProto_kj-http_IMPORTED_LOCATION)
  mark_as_advanced(CapnProto_kj_IMPORTED_LOCATION)
  mark_as_advanced(CapnProto_kj-test_IMPORTED_LOCATION)
  mark_as_advanced(CapnProto_kj-tls_IMPORTED_LOCATION)
endfunction()
