# Copyright (c) 2021 by the Zeek Project. See LICENSE for details.

# @TEST-EXEC: zeek -r ${TRACES}/dhcp.pcap %INPUT > basic.out
# @TEST-EXEC: btest-diff basic.out
# @TEST-EXEC: btest-diff conn.log
# @TEST-EXEC: btest-diff dhcp.log
#
# @TEST-DOC: Test DHCP analyzer with small trace.


@load analyzer

# Trigger: DHCP Discover message
event dhcp_discover(c: connection, is_orig: bool, msg: DHCP::Msg, options: DHCP::Options)
    {
    print "DHCP discover";
    }

# Trigger: DHCP Offer message
event dhcp_offer(c: connection, is_orig: bool, msg: DHCP::Msg, options: DHCP::Options)
    {
    print "DHCP offer";
    }

# Trigger: DHCP Request message
event dhcp_request(c: connection, is_orig: bool, msg: DHCP::Msg, options: DHCP::Options)
    {
    print "DHCP request";
    }

# Trigger: DHCP Decline message
event dhcp_decline(c: connection, is_orig: bool, msg: DHCP::Msg, options: DHCP::Options)
    {
    print "DHCP decline";
    }

# Trigger: DHCP Ack message
event dhcp_ack(c: connection, is_orig: bool, msg: DHCP::Msg, options: DHCP::Options)
    {
    print "DHCP ack";
    }

# Trigger: DHCP Nak message
event dhcp_nak(c: connection, is_orig: bool, msg: DHCP::Msg, options: DHCP::Options)
    {
    print "DHCP nak";
    }

# Trigger: DHCP Release message
event dhcp_release(c: connection, is_orig: bool, msg: DHCP::Msg, options: DHCP::Options)
    {
    print "DHCP release";
    }
