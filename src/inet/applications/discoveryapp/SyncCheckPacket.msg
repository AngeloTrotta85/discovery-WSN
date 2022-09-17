//
// Copyright (C) 2016 OpenSim Ltd.
//
// SPDX-License-Identifier: LGPL-3.0-or-later
//

import inet.common.INETDefs;
import inet.common.packet.chunk.Chunk;
import inet.networklayer.common.L3Address;

namespace inet;

//
// Generic application packet
//
// TODO rename to ApplicationHeader and remove ByteCountChunk from ApplicationHeaderSerializer
class SyncCheckPacket extends FieldsChunk
{
    L3Address srcAddr;
    uint32_t sequenceNumber;
    uint8_t ttl;
    
    uint64_t hash;
}
