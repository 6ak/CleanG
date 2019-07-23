/*
 * Copyright 2017-present Open Networking Laboratory
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package edu.ANON;


import com.google.common.collect.ImmutableSet;
import org.apache.felix.scr.annotations.Activate;
import org.apache.felix.scr.annotations.Component;
import org.apache.felix.scr.annotations.Deactivate;
//import org.apache.felix.scr.annotations.Modified;
//import org.apache.felix.scr.annotations.Property;
import org.apache.felix.scr.annotations.Reference;
import org.apache.felix.scr.annotations.ReferenceCardinality;
import org.onlab.packet.Ethernet;
import org.onlab.packet.ICMP;
import org.onlab.packet.ICMP6;
import org.onlab.packet.IPv4;
import org.onlab.packet.IPv6;
import org.onlab.packet.Ip4Prefix;
import org.onlab.packet.Ip6Prefix;
import org.onlab.packet.MacAddress;
import org.onlab.packet.TCP;
import org.onlab.packet.TpPort;
import org.onlab.packet.UDP;
import org.onlab.packet.*;
import org.onosproject.net.packet.*;
import org.onlab.packet.VlanId;
import org.onlab.util.Tools;
import org.onosproject.cfg.ComponentConfigService;
import org.onosproject.core.ApplicationId;
import org.onosproject.core.CoreService;
import org.onosproject.event.Event;
import org.onosproject.net.ConnectPoint;
import org.onosproject.net.DeviceId;
import org.onosproject.net.Host;
import org.onosproject.net.HostId;
import org.onosproject.net.Link;
import org.onosproject.net.Path;
import org.onosproject.net.PortNumber;
import org.onosproject.net.flow.DefaultTrafficSelector;
import org.onosproject.net.flow.DefaultTrafficTreatment;
import org.onosproject.net.flow.FlowEntry;
import org.onosproject.net.flow.FlowRule;
import org.onosproject.net.flow.FlowRuleService;
import org.onosproject.net.flow.TrafficSelector;
import org.onosproject.net.flow.TrafficTreatment;
import org.onosproject.net.flow.criteria.Criterion;
import org.onosproject.net.flow.criteria.EthCriterion;
import org.onosproject.net.flow.instructions.Instruction;
import org.onosproject.net.flow.instructions.Instructions;
import org.onosproject.net.flowobjective.DefaultForwardingObjective;
import org.onosproject.net.flowobjective.FlowObjectiveService;
import org.onosproject.net.flowobjective.ForwardingObjective;
import org.onosproject.net.host.HostService;
import org.onosproject.net.link.LinkEvent;
import org.onosproject.net.packet.InboundPacket;
import org.onosproject.net.packet.PacketContext;
import org.onosproject.net.packet.PacketPriority;
import org.onosproject.net.packet.PacketProcessor;
import org.onosproject.net.packet.PacketService;
import org.onosproject.net.topology.TopologyEvent;
import org.onosproject.net.topology.TopologyListener;
import org.onosproject.net.topology.TopologyService;
import org.osgi.service.component.ComponentContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Dictionary;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.nio.ByteBuffer;

//import org.slf4j.LoggerFactory.getLogger;

/**
 * Skeletal ONOS application component.
 */
@Component(immediate = true)
	public class AppComponent {

		private final static Logger log = LoggerFactory.getLogger(AppComponent.class);

		//    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
		//    protected ComponentConfigService cfgService;

		@Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
			protected CoreService coreService;

		@Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
			protected PacketService packetService;

		private ANONNamePacketProcessor processor = new ANONNamePacketProcessor();
		private ApplicationId appId;

		@Activate
			protected void activate(/*ComponentContext context*/) {
				log.info("Wow! ANONName ANONName's component Started initialization");

				//	cfgService.registerProperties(getClass());
				appId = coreService.registerApplication("ANON.ANON.app");

				// changed following line to 3 randomly instead of 2
				packetService.addProcessor(processor, PacketProcessor.director(1));
				//topologyService.addListener(topologyListener);
				//readComponentConfiguration(context);
				requestIntercepts();

				log.info("ANONName ANONName's component Started with app id:", appId.id());
			}

		@Deactivate
			protected void deactivate() {
				log.info("Wow! ANONName ANONName's component started to being Stopped");

				//	cfgService.unregisterProperties(getClass(), false);
				withdrawIntercepts();
				//flowRuleService.removeFlowRulesById(appId);
				packetService.removeProcessor(processor);
				//topologyService.removeListener(topologyListener);
				processor = null;

				log.info("ANONName ANONName's component Stopped!");
			}
		private void requestIntercepts() {
			TrafficSelector.Builder selector = DefaultTrafficSelector.builder();
			selector.matchEthType(Ethernet.TYPE_IPV4);
			packetService.requestPackets(selector.build(), PacketPriority.CONTROL, appId);
			selector.matchEthType(Ethernet.TYPE_ARP);
			packetService.requestPackets(selector.build(), PacketPriority.CONTROL, appId);

			selector.matchEthType(Ethernet.TYPE_IPV6);
			//   if (ipv6Forwarding) {
			packetService.requestPackets(selector.build(), PacketPriority.CONTROL, appId);
			//    } else {
			//       packetService.cancelPackets(selector.build(), PacketPriority.CONTROL, appId);
			//   }
		}

		/**
		 * Cancel request for packet in via packet service.
		 */
		private void withdrawIntercepts() {
			TrafficSelector.Builder selector = DefaultTrafficSelector.builder();
			selector.matchEthType(Ethernet.TYPE_IPV4);
			packetService.cancelPackets(selector.build(), PacketPriority.CONTROL, appId);
			selector.matchEthType(Ethernet.TYPE_ARP);
			packetService.cancelPackets(selector.build(), PacketPriority.CONTROL, appId);
			selector.matchEthType(Ethernet.TYPE_IPV6);
			packetService.cancelPackets(selector.build(), PacketPriority.CONTROL, appId);
		}

		private class ANONNamePacketProcessor implements PacketProcessor {
			@Override
				public void process(PacketContext context) {
					// Stop processing if the packet has been handled, since we
					// can't do any more to it.

					if (context.isHandled()) {
						return;
					}

					InboundPacket pkt = context.inPacket();
					//log.info("new packet received by ANONName packet processor");
					//log.info("its ip is: " + pkt.receivedFrom().deviceId());


					DeviceId targetDevice = null;
					if (pkt.receivedFrom().deviceId().toString().equals("of:fb04000000000000")) {
						targetDevice = DeviceId.deviceId("of:b004000000000000");
					}
					else if (pkt.receivedFrom().deviceId().toString().equals("of:b004000000000000")) {
						targetDevice = DeviceId.deviceId("of:fb04000000000000");
					}
					else if (pkt.receivedFrom().deviceId().toString().equals("of:0807000000000000")) {
						targetDevice = DeviceId.deviceId("of:5307000000000000");
					}
					else if (pkt.receivedFrom().deviceId().toString().equals("of:5307000000000000")) {
						targetDevice = DeviceId.deviceId("of:0807000000000000");
					} else {
					//	log.info("ANONName!!!Something is wrong! who is sending a message to whom???");
					}

					int portNumber = 2;
					context.treatmentBuilder().setOutput(PortNumber.portNumber(portNumber));
					//context.send();
					//context.treatmentBuilder().setIpSrc(IpAddress.valueOf("192.168.1.1"));
					//context.outPacket().data().put("AAAAAAAAAAAAAAAAAAAA".getBytes());	
					//portNumber = 13;
					//context.treatmentBuilder().setOutput(PortNumber.portNumber(portNumber));
					context.block();

					//InboundPacket pkt = context.inPacket();
					ConnectPoint outport = pkt.receivedFrom();

					TrafficTreatment treatment = DefaultTrafficTreatment.builder().
						setOutput(outport.port()).build();
					OutboundPacket packet = new DefaultOutboundPacket(targetDevice,
							treatment, pkt.unparsed());
					packetService.emit(packet);

					return;    
					/* 
					   Ethernet ethPkt = pkt.parsed();

					   if (ethPkt == null) {
					   return;
					   }

					// Bail if this is deemed to be a control packet.
					if (isControlPacket(ethPkt)) {
					return;
					}

					// Skip IPv6 multicast packet when IPv6 forward is disabled.
					if (!ipv6Forwarding && isIpv6Multicast(ethPkt)) {
					return;
					}

					HostId id = HostId.hostId(ethPkt.getDestinationMAC());

					// Do not process link-local addresses in any way.
					if (id.mac().isLinkLocal()) {
					return;
					}

					// Do not process IPv4 multicast packets, let mfwd handle them
					if (ignoreIpv4McastPackets && ethPkt.getEtherType() == Ethernet.TYPE_IPV4) {
					if (id.mac().isMulticast()) {
					return;
					}
					}

					// Do we know who this is for? If not, flood and bail.
					Host dst = hostService.getHost(id);
					if (dst == null) {
					flood(context);
					return;
					}

					// Are we on an edge switch that our destination is on? If so,
					// simply forward out to the destination and bail.
					if (pkt.receivedFrom().deviceId().equals(dst.location().deviceId())) {
					if (!context.inPacket().receivedFrom().port().equals(dst.location().port())) {
					installRule(context, dst.location().port());
					}
					return;
					}

					// Otherwise, get a set of paths that lead from here to the
					// destination edge switch.
					Set<Path> paths =
					topologyService.getPaths(topologyService.currentTopology(),
					pkt.receivedFrom().deviceId(),
					dst.location().deviceId());
					if (paths.isEmpty()) {
					// If there are no paths, flood and bail.
					flood(context);
					return;
					}

					// Otherwise, pick a path that does not lead back to where we
					// came from; if no such path, flood and bail.
					Path path = pickForwardPathIfPossible(paths, pkt.receivedFrom().port());
					if (path == null) {
					log.warn("Don't know where to go from here {} for {} -> {}",
					pkt.receivedFrom(), ethPkt.getSourceMAC(), ethPkt.getDestinationMAC());
					flood(context);
					return;
					}

					// Otherwise forward and be done with it.
					installRule(context, path.src().port());
					*/
				}
		}
	}
