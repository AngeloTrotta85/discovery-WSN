//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
// 
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Lesser General Public License for more details.
// 
// You should have received a copy of the GNU Lesser General Public License
// along with this program.  If not, see http://www.gnu.org/licenses/.
//


cplusplus {{
#include <list>
#include "DiscoveryApp.h"

}}

import inet.common.INETDefs;
import inet.common.packet.chunk.Chunk;
import inet.networklayer.common.L3Address;

namespace inet;

cplusplus {{
    
class Services;

}}

//
// Generic application packet
//
// TODO rename to ApplicationHeader and remove ByteCountChunk from ApplicationHeaderSerializer
class SyncBetterPacket extends FieldsChunk
{
    L3Address srcAddr;
    uint32_t sequenceNumber;
    uint8_t ttl;
}

cplusplus(SyncBetterPacket) {{
    public:
    	//std::list<Service> services;
    	std::list<std::tuple<L3Address, unsigned int, Services>> msg_data_vector;
}}
