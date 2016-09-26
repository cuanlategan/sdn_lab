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
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_0
from ryu.ofproto import ether
from ryu.lib.mac import haddr_to_bin
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.ip import ipv4_to_bin

from ryu.lib import hub

from ryu.topology.switches import LLDPPacket


from ryu.topology.api import get_switch, get_link
from ryu.app.wsgi import ControllerBase
from ryu.topology import event, switches
import networkx as nx

class SimpleSwitch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_0.OFP_VERSION]
    (PRI_LOW, PRI_HIGH) = (50,100)
    controller_datapath = None

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.monitor_thread = hub.spawn(self._monitor) 
        self.topology_api_app = self
        self.net=nx.DiGraph()
        self.nodes = {}
        self.links = {}
        self.no_of_nodes = 0
        self.no_of_links = 0
        self.i=0
        
    def add_flow(self, datapath, in_port, dst, actions):
        ofproto = datapath.ofproto

        match = datapath.ofproto_parser.OFPMatch(
            in_port=in_port, dl_dst=haddr_to_bin(dst))

        mod = datapath.ofproto_parser.OFPFlowMod(
            datapath=datapath, match=match, cookie=0,
            command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=0,
            priority=self.PRI_LOW,
            flags=ofproto.OFPFF_SEND_FLOW_REM, actions=actions)
        datapath.send_msg(mod)
        

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        
        print hex(eth.ethertype)
        if eth.ethertype == 0x88cc:
            print "LLDP found!!!!!!!!!!!!!!!"
            return
        
        if hex(eth.ethertype) == 0x88cc:
            print "LLDP found!!!!!!!!!!!!!!!"
            return


        try:
            # ignore lldp packet
            LLDPPacket.lldp_parse(msg.data)
            print "LLDP found!!!!!!!!!!!!!!!"
            return
        except LLDPPacket.LLDPUnknownFormat:
            pass
        
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
       
        actions = []

        match = parser.OFPMatch(dl_type=ether.ETH_TYPE_IP, nw_src=nw_src, nw_dst=nw_dst)        
        mod = parser.OFPFlowMod(
            datapath = dp, match=match, cookie=0,
            command  = ofp.OFPFC_ADD, idle_timeout=0, hard_timeout=0,
            priority = self.PRI_HIGH,
            flags    = ofp.OFPFF_SEND_FLOW_REM, actions=actions)
        dp.send_msg(mod)

        match = parser.OFPMatch(dl_type=ether.ETH_TYPE_IP, nw_src=nw_dst, nw_dst=nw_src)
        mod = parser.OFPFlowMod(
            datapath = dp, match=match, cookie=0,
            command  = ofp.OFPFC_ADD, idle_timeout=0, hard_timeout=0,
            priority = self.PRI_HIGH,
            flags    = ofp.OFPFF_SEND_FLOW_REM, actions=actions) 
        dp.send_msg(mod)

    def _monitor(self):
        while True:
            if self.controller_datapath != None:
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
        body = ev.msg.body
        #if len(body) > 0: 
            #self.logger.info('Host 1 packet count: %s', body[0].packet_count)
        #flows = []
        for stat in body:    
            #print stat.packet_count
            self.logger.info('Packet Count Host-1: %s', stat.packet_count)    


    @set_ev_cls(event.EventSwitchEnter)
    def get_topology_data(self, ev):
        switch_list = get_switch(self.topology_api_app, None)   
        switches=[switch.dp.id for switch in switch_list]
        self.net.add_nodes_from(switches)
         
        #print "**********List of switches"
        #for switch in switch_list:
        #self.ls(switch)
        #print switch
        #self.nodes[self.no_of_nodes] = switch
        #self.no_of_nodes += 1
	
        links_list = get_link(self.topology_api_app, None)
        #print links_list
        links=[(link.src.dpid,link.dst.dpid,{'port':link.src.port_no}) for link in links_list]
        #print links
        self.net.add_edges_from(links)
        links=[(link.dst.dpid,link.src.dpid,{'port':link.dst.port_no}) for link in links_list]
        #print links
        self.net.add_edges_from(links)
        print "**********List of links"
        print self.net.edges()
        #for link in links_list:
	    #print link.dst
            #print link.src
            #print "Novo link"
	    #self.no_of_links += 1
