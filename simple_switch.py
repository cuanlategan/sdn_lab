# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
An OpenFlow 1.0 L2 learning switch implementation.
"""

import logging
import struct

from ryu.base import app_manager
from ryu.controller import mac_to_port
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_0
#from ryu.ofproto import ether
from ryu.lib.mac import haddr_to_bin
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import arp
from ryu.lib.ip import ipv4_to_bin
from ryu.lib import hub

class SimpleSwitch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_0.OFP_VERSION]
    (PRI_LOW, PRI_HIGH) = (50,100)
    controller_datapath = None

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.monitor_thread = hub.spawn(self._monitor) 
        
    def add_flow(self, datapath, in_port, dst, actions):
        ofproto = datapath.ofproto

        match = datapath.ofproto_parser.OFPMatch(
            in_port=in_port, dl_dst=haddr_to_bin(dst))

        mod = datapath.ofproto_parser.OFPFlowMod(
            datapath=datapath, match=match, cookie=0,
            command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=0,
            priority=priority_low,
            flags=ofproto.OFPFF_SEND_FLOW_REM, actions=actions)
        datapath.send_msg(mod)
        

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

	if not eth:
	    self.logger.info("packet is not eth")
            return 

        dst = eth.dst
        src = eth.src

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        self.logger.info("packet in %s %s %s %s", dpid, src, dst, msg.in_port)

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = msg.in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [datapath.ofproto_parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            self.add_flow(datapath, msg.in_port, dst, actions)
        
        self.logger.info("about to add flow, msg.buffer_id = %s",msg.buffer_id)     
  
        out = datapath.ofproto_parser.OFPPacketOut(
            datapath=datapath, buffer_id=msg.buffer_id, in_port=msg.in_port,
            actions=actions)
        datapath.send_msg(out)

    @set_ev_cls(ofp_event.EventOFPPortStatus, MAIN_DISPATCHER)
    def _port_status_handler(self, ev):
        msg = ev.msg
        reason = msg.reason
        port_no = msg.desc.port_no

        ofproto = msg.datapath.ofproto
        if reason == ofproto.OFPPR_ADD:
            self.logger.info("port added %s", port_no)
        elif reason == ofproto.OFPPR_DELETE:
            self.logger.info("port deleted %s", port_no)
        elif reason == ofproto.OFPPR_MODIFY:
            self.logger.info("port modified %s", port_no)
        else:
            self.logger.info("Illeagal port state %s %s", port_no, reason)

    @set_ev_cls(ofp_event.EventOFPStateChange, MAIN_DISPATCHER)
    def block_h2_to_h3(self, ev):
        dp = ev.datapath
        
        self.controller_datapath = dp

        ofp = dp.ofproto
        parser = dp.ofproto_parser
        self.logger.info("Switch connected (id=%s)" % dp.id)
     
         
        self.logger.info("Blocking IPv4 traffic between h2 to h3")
        src_ip = '10.0.0.2'
        dst_ip = '10.0.0.3'
        nw_src = struct.unpack('!I', ipv4_to_bin(src_ip))[0]
        nw_dst = struct.unpack('!I', ipv4_to_bin(dst_ip))[0]
        match = parser.OFPMatch(dl_type=0x0800, nw_src=nw_src, nw_dst=nw_dst)
        #ether.ETH_TYPE_IP  
     
        actions = []
                
        mod = parser.OFPFlowMod(
            datapath = dp, match=match, cookie=0,
            command  = ofp.OFPFC_ADD, idle_timeout=0, hard_timeout=0,
            priority = SimpleSwitch.PRI_HIGH,
            flags    = ofp.OFPFF_SEND_FLOW_REM, actions=actions)
        dp.send_msg(mod)

        match = parser.OFPMatch(dl_type=0x0800, nw_src=nw_dst, nw_dst=nw_src)
        mod = parser.OFPFlowMod(
            datapath = dp, match=match, cookie=0,
            command  = ofp.OFPFC_ADD, idle_timeout=0, hard_timeout=0,
            priority = SimpleSwitch.PRI_HIGH,
            flags    = ofp.OFPFF_SEND_FLOW_REM, actions=actions) 
        dp.send_msg(mod)

    def _monitor(self):
        while True:
            print('controller_datapth %d', self.controller_datapath)
            if self.controller_datapath != None:
                print self.controller_datapath.id
                ofproto = self.controller_datapath.ofproto
                parser  = self.controller_datapath.ofproto_parser
                match   = parser.OFPMatch(in_port=1)
                datapath = self.controller_datapath
                table_id = 0xff
                out_port = ofproto.OFPP_NONE
                req = parser.OFPFlowStatsRequest(datapath, 0, match, table_id, out_port)

                datapath.send_msg(req)

            hub.sleep(3)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def flow_stats_reply_handler(self, ev):
        msg = ev.msg
        ofp = msg.datapath.ofproto
        body = ev.msg.body

        flows = []
        for stat in body:
            #flows.append('count' %stat.packet_count)
            print stat.packet_count
        self.logger.debug('FlowStats: %s', flows)    
