# Copyright (c) 2021 by the Zeek Project. See LICENSE for details.

# @TEST-EXEC: zeek -r ${TRACES}/dhcp.pcap %INPUT > basic.out
# @TEST-EXEC: btest-diff basic.out
# @TEST-EXEC: zeek-cut -C ts uid id.orig_h id.orig_p id.resp_h id.resp_p proto service history <conn.log >conn.log2 && mv conn.log2 conn.log
# @TEST-EXEC: btest-diff conn.log
# @TEST-EXEC: btest-diff dhcp.log
#
# @TEST-DOC: Test DHCP analyzer with small trace.

@load analyzer

event dhcp_message(c: connection, is_orig: bool, msg: DHCP::Msg, options: DHCP::Options) {
    print is_orig, msg, options;
}
