# Copyright (c) 2021 by the Zeek Project. See LICENSE for details.

# @TEST-EXEC: zeek -r ${TRACES}/dhcp.pcap %INPUT
# @TEST-EXEC: btest-diff conn.log
# @TEST-EXEC: btest-diff dhcp.log
#
# @TEST-DOC: Test DHCP analyzer with small trace.

@load analyzer

event dhcp_message(c: connection, is_orig: bool, msg: DHCP::Msg, options: DHCP::Options)
    {
    print msg$chaddr;
    }
