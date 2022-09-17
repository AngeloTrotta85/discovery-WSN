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

#include "DiscoveryApp.h"


//#include "inet/applications/base/ApplicationPacket_m.h"
#include "inet/common/ModuleAccess.h"
#include "inet/common/TagBase_m.h"
#include "inet/common/TimeTag_m.h"
#include "inet/common/lifecycle/ModuleOperations.h"
#include "inet/common/packet/Packet.h"
#include "inet/networklayer/common/FragmentationTag_m.h"
#include "inet/networklayer/common/L3AddressResolver.h"
#include "inet/transportlayer/contract/udp/UdpControlInfo_m.h"


#include "inet/common/Simsignals.h"
#include "inet/networklayer/common/L3AddressTag_m.h"
#include "inet/transportlayer/common/L4PortTag_m.h"

#include <functional>
#include <errno.h>
#include <omnetpp/checkandcast.h>

using omnetpp::check_and_cast;

namespace inet {

Define_Module(DiscoveryApp);

DiscoveryApp::~DiscoveryApp()
{
    cancelAndDelete(selfMsg);
}

void DiscoveryApp::initialize(int stage)
{
    ClockUserModuleMixin::initialize(stage);

    if (stage == INITSTAGE_LOCAL) {
        numSent = 0;
        numReceived = 0;
        myIPAddress = Ipv4Address::UNSPECIFIED_ADDRESS;
        WATCH(numSent);
        WATCH(numReceived);

        myHash = calculate_state_vector_hash();

        dmax = par("dmax");

        localPort = par("localPort");
        destPort = par("destPort");
        startTime = par("startTime");
        stopTime = par("stopTime");
        packetName = par("packetName");
        dontFragment = par("dontFragment");
        if (stopTime >= CLOCKTIME_ZERO && stopTime < startTime)
            throw cRuntimeError("Invalid startTime/stopTime parameters");
        selfMsg = new ClockEvent("sendTimer");
    }
}

void DiscoveryApp::finish()
{
    recordScalar("packets sent", numSent);
    recordScalar("packets received", numReceived);
    ApplicationBase::finish();
}

void DiscoveryApp::setSocketOptions()
{
    int timeToLive = par("timeToLive");
    if (timeToLive != -1)
        socket.setTimeToLive(timeToLive);

    int dscp = par("dscp");
    if (dscp != -1)
        socket.setDscp(dscp);

    int tos = par("tos");
    if (tos != -1)
        socket.setTos(tos);

    const char *multicastInterface = par("multicastInterface");
    if (multicastInterface[0]) {
        IInterfaceTable *ift = getModuleFromPar<IInterfaceTable>(par("interfaceTableModule"), this);
        NetworkInterface *ie = ift->findInterfaceByName(multicastInterface);
        if (!ie)
            throw cRuntimeError("Wrong multicastInterface setting: no interface named \"%s\"", multicastInterface);
        socket.setMulticastOutputInterface(ie->getInterfaceId());
    }

    bool receiveBroadcast = par("receiveBroadcast");
    if (receiveBroadcast)
        socket.setBroadcast(true);

    bool joinLocalMulticastGroups = par("joinLocalMulticastGroups");
    if (joinLocalMulticastGroups) {
        MulticastGroupList mgl = getModuleFromPar<IInterfaceTable>(par("interfaceTableModule"), this)->collectMulticastGroups();
        socket.joinLocalMulticastGroups(mgl);
    }
    socket.setCallback(this);
}

L3Address DiscoveryApp::chooseDestAddr()
{
    int k = intrand(destAddresses.size());
    if (destAddresses[k].isUnspecified() || destAddresses[k].isLinkLocal()) {
        L3AddressResolver().tryResolve(destAddressStr[k].c_str(), destAddresses[k]);
    }
    return destAddresses[k];
}

void DiscoveryApp::sendPacket()
{
    std::ostringstream str;
    str << packetName << "-" << numSent;
    Packet *packet = new Packet(str.str().c_str());
    if (dontFragment)
        packet->addTag<FragmentationReq>()->setDontFragment(true);
    const auto& payload = makeShared<SyncCheckPacket>();

    payload->setSrcAddr(myIPAddress);
    payload->setSequenceNumber(numSent);
    payload->setHash(myHash);
    payload->setTtl(dmax);

    //payload->setChunkLength(B(par("messageLength")));
    payload->setChunkLength(B(sizeof(uint32_t) + sizeof(uint64_t) + sizeof(uint8_t) + sizeof(uint32_t)));

    //payload->setHash(std::hash<std::string>{}(state_vector_string()));
    payload->addTag<CreationTimeTag>()->setCreationTime(simTime());
    packet->insertAtBack(payload);
    L3Address destAddr = Ipv4Address::ALLONES_ADDRESS;
    emit(packetSentSignal, packet);
    socket.sendTo(packet, destAddr, destPort);
    numSent++;
}

void DiscoveryApp::processStart()
{
    socket.setOutputGate(gate("socketOut"));
    const char *localAddress = par("localAddress");
    socket.bind(*localAddress ? L3AddressResolver().resolve(localAddress) : L3Address(), localPort);
    setSocketOptions();

    myIPAddress = L3AddressResolver().resolve(this->getParentModule()->getFullName()).toIpv4();

    EV_INFO << "My address is: " << myIPAddress << endl;


    /*
    const char *destAddrs = par("destAddresses");
    cStringTokenizer tokenizer(destAddrs);
    const char *token;

    while ((token = tokenizer.nextToken()) != nullptr) {
        destAddressStr.push_back(token);
        L3Address result;
        L3AddressResolver().tryResolve(token, result);
        if (result.isUnspecified())
            EV_ERROR << "cannot resolve destination address: " << token << endl;
        destAddresses.push_back(result);
    }

    if (!destAddresses.empty()) {
        selfMsg->setKind(SEND);
        processSend();
    }
    else {
        if (stopTime >= CLOCKTIME_ZERO) {
            selfMsg->setKind(STOP);
            scheduleClockEventAt(stopTime, selfMsg);
        }
    }*/
    processSend();
}

void DiscoveryApp::processSend()
{
    sendPacket();
    clocktime_t d = par("sendInterval");
    if (stopTime < CLOCKTIME_ZERO || getClockTime() + d < stopTime) {
        selfMsg->setKind(SEND);
        scheduleClockEventAfter(d, selfMsg);
    }
    else {
        selfMsg->setKind(STOP);
        scheduleClockEventAt(stopTime, selfMsg);
    }
}

void DiscoveryApp::processStop()
{
    socket.close();
}

void DiscoveryApp::handleMessageWhenUp(cMessage *msg)
{
    if (msg->isSelfMessage()) {
        ASSERT(msg == selfMsg);
        switch (selfMsg->getKind()) {
            case START:
                processStart();
                break;

            case SEND:
                processSend();
                break;

            case STOP:
                processStop();
                break;

            default:
                throw cRuntimeError("Invalid kind %d in self message", (int)selfMsg->getKind());
        }
    }
    else
        socket.processMessage(msg);
}

void DiscoveryApp::socketDataArrived(UdpSocket *socket, Packet *packet)
{
    // process incoming packet
    processPacket(packet);
}

void DiscoveryApp::socketErrorArrived(UdpSocket *socket, Indication *indication)
{
    EV_WARN << "Ignoring UDP error report " << indication->getName() << endl;
    delete indication;
}

void DiscoveryApp::socketClosed(UdpSocket *socket)
{
    if (operationalState == State::STOPPING_OPERATION)
        startActiveOperationExtraTimeOrFinish(par("stopOperationExtraTime"));
}

void DiscoveryApp::refreshDisplay() const
{
    ApplicationBase::refreshDisplay();

    char buf[100];
    sprintf(buf, "rcvd: %d pks\nsent: %d pks", numReceived, numSent);
    getDisplayString().setTagArg("t", 0, buf);
}

void DiscoveryApp::processPacket(Packet *pk)
{
    emit(packetReceivedSignal, pk);
    EV_INFO << "Received packet: " << UdpSocket::getReceivedPacketInfo(pk) << endl;

    // determine its source address/port
    L3Address remoteAddress = pk->getTag<L3AddressInd>()->getSrcAddress();
    L3Address myAddress = pk->getTag<L3AddressInd>()->getDestAddress();
    int srcPort = pk->getTag<L4PortInd>()->getSrcPort();

    EV_INFO << "Received packet form IP: " << remoteAddress << ":" << srcPort << " with destination: " << myAddress << endl;
    if (remoteAddress == Ipv4Address::LOOPBACK_ADDRESS){
        EV_INFO << "Received packet form ME!!!! : " << remoteAddress << ":" << srcPort << endl;
    }


    const auto& appmsg_check = pk->peekDataAt<SyncCheckPacket>(B(0), B(pk->getByteLength()));
    if (appmsg_check) {
        manageSyncMessage(appmsg_check, remoteAddress);
    }
    else {
        const auto& appmsg_interest = pk->peekDataAt<SyncInterestPacket>(B(0), B(pk->getByteLength()));
        if (appmsg_interest) {
            manageSyncInterestMessage(appmsg_interest, remoteAddress);
        }
        else {
            const auto& appmsg_request = pk->peekDataAt<SyncRequestPacket>(B(0), B(pk->getByteLength()));
            if (appmsg_request) {
                manageSyncRequestMessage(appmsg_request, remoteAddress);
            }
            else {
                throw cRuntimeError("Message (%s)%s is not a valid packet", pk->getClassName(), pk->getName());
            }
        }
    }

    //if (!appmsg)
    //    throw cRuntimeError("Message (%s)%s is not a SyncCheckPacket -- probably wrong client app, or wrong setting of UDP's parameters", pk->getClassName(), pk->getName());




    delete pk;
    numReceived++;
}

void DiscoveryApp::handleStartOperation(LifecycleOperation *operation)
{
    clocktime_t start = std::max(startTime, getClockTime());
    if ((stopTime < CLOCKTIME_ZERO) || (start < stopTime) || (start == stopTime && startTime == stopTime)) {
        selfMsg->setKind(START);
        scheduleClockEventAt(start, selfMsg);
    }
}

void DiscoveryApp::handleStopOperation(LifecycleOperation *operation)
{
    cancelEvent(selfMsg);
    socket.close();
    delayActiveOperationFinish(par("stopOperationTimeout"));
}

void DiscoveryApp::handleCrashOperation(LifecycleOperation *operation)
{
    cancelClockEvent(selfMsg);
    socket.destroy(); // TODO  in real operating systems, program crash detected by OS and OS closes sockets of crashed programs.
}

std::string DiscoveryApp::state_vector_string(std::list<std::pair<L3Address, unsigned int>> &sv) {
    std::stringstream ris;

    for (auto const& p : sv) {
        ris << p.first << "," << p.second << ";";
    }

    return ris.str();
}

bool compare_state_vector (const std::pair<L3Address, unsigned int>& first, const std::pair<L3Address, unsigned int>& second)
{
    return (first.first < second.first);
}

uint64_t DiscoveryApp::calculate_state_vector_hash() {
    std::list<std::pair<L3Address, unsigned int>> state_vector;
    for (auto const& mapel : state_map) {
        state_vector.push_back(std::make_pair(mapel.second.first, mapel.second.second));
    }
    state_vector.sort(compare_state_vector);

    return std::hash<std::string>{}(state_vector_string(state_vector));
}

void DiscoveryApp::manageSyncMessage(Ptr<const SyncCheckPacket> rcvMsg, L3Address rcdAddr) {

    //EV_INFO << "Received HASH: " << rcvMsg->getHash() << endl;

    //chekc if need to forward
    if ((rcvMsg->getTtl() > 1) && checkForward(rcvMsg, rcdAddr)) {
        forwardSyncCheck(rcvMsg);

        labelForward(rcvMsg);
    }

    //check message if different hashes
    if (rcvMsg->getHash() != myHash) {
        //TO-DO
    }
}

bool DiscoveryApp::checkForward(Ptr<const SyncCheckPacket> rcvMsg, L3Address rcdAddr) {
    if (forward_sync_check_map.count(rcvMsg->getSrcAddr()) == 0) {
        return true;
    }
    else{
        return (rcvMsg->getSequenceNumber() > forward_sync_check_map[rcvMsg->getSrcAddr()]);
    }
}

void DiscoveryApp::labelForward(Ptr<const SyncCheckPacket> rcvMsg) {
    forward_sync_check_map[rcvMsg->getSrcAddr()] = rcvMsg->getSequenceNumber();
}

void DiscoveryApp::forwardSyncCheck(Ptr<const SyncCheckPacket> rcvMsg) {

    std::ostringstream str;
    str << packetName << "- FWD -" << rcvMsg->getSequenceNumber();
    Packet *packet = new Packet(str.str().c_str());
    if (dontFragment)
        packet->addTag<FragmentationReq>()->setDontFragment(true);
    const auto& payload = makeShared<SyncCheckPacket>();

    payload->setSequenceNumber(rcvMsg->getSequenceNumber());
    payload->setSrcAddr(rcvMsg->getSrcAddr());
    payload->setHash(rcvMsg->getHash());
    payload->setTtl(rcvMsg->getTtl() - 1);

    //payload->setChunkLength(B(par("messageLength")));
    payload->setChunkLength(B(sizeof(uint32_t) + sizeof(uint64_t) + sizeof(uint8_t) + sizeof(uint32_t)));

    //payload->setHash(std::hash<std::string>{}(state_vector_string()));
    payload->addTag<CreationTimeTag>()->setCreationTime(simTime());
    packet->insertAtBack(payload);
    L3Address destAddr = Ipv4Address::ALLONES_ADDRESS;
    emit(packetSentSignal, packet);
    socket.sendTo(packet, destAddr, destPort);
    //numSent++;
}

void DiscoveryApp::manageSyncInterestMessage(Ptr<const SyncInterestPacket> rcvMsg, L3Address rcdAddr) {

    EV_INFO << "Received getSv_addrArraySize: " << rcvMsg->getSv_addrArraySize() << endl;


    //chekc if need to forward
    if ((rcvMsg->getTtl() > 1) && checkInterestForward(rcvMsg, rcdAddr)) {
        forwardSyncInterest(rcvMsg);

        labelInterestForward(rcvMsg);
    }

    //check message if different hashes
    //TO-DO
    std::list<std::pair<L3Address, unsigned int>> worse;
    std::list<std::tuple<L3Address, unsigned int, Services>> better;

    for (int i = 0; i < rcvMsg->getSv_addrArraySize(); i++){
        if ((state_map.count(rcvMsg->getSv_addr(i)) == 0 ) || (rcvMsg->getSv_counter(i) > state_map[rcvMsg->getSv_addr(i)].second) ){
            worse.push_back(std::make_pair(rcvMsg->getSv_addr(i), state_map[rcvMsg->getSv_addr(i)].second));
        }
        else if ( (state_map.count(rcvMsg->getSv_addr(i)) != 0 ) && (rcvMsg->getSv_counter(i) < state_map[rcvMsg->getSv_addr(i)].second) ){
            better.push_back(std::make_touple(
                    rcvMsg->getSv_addr(i),
                    std::get<1>(data_map[rcvMsg->getSv_addr(i)]),
                    std::get<2>(data_map[rcvMsg->getSv_addr(i)])));
        }
    }

    for (auto& wel : worse) {

    }
}

bool DiscoveryApp::checkInterestForward(Ptr<const SyncInterestPacket> rcvMsg, L3Address rcdAddr) {
    if (forward_sync_interest_map.count(rcvMsg->getSrcAddr()) == 0) {
        return true;
    }
    else{
        return (rcvMsg->getSequenceNumber() > forward_sync_interest_map[rcvMsg->getSrcAddr()]);
    }
}

void DiscoveryApp::labelInterestForward(Ptr<const SyncInterestPacket> rcvMsg) {
    forward_sync_interest_map[rcvMsg->getSrcAddr()] = rcvMsg->getSequenceNumber();
}

void DiscoveryApp::forwardSyncInterest(Ptr<const SyncInterestPacket> rcvMsg) {

    std::ostringstream str;
    str << packetName << "-InterestFWD-" << rcvMsg->getSequenceNumber();
    Packet *packet = new Packet(str.str().c_str());
    if (dontFragment)
        packet->addTag<FragmentationReq>()->setDontFragment(true);
    const auto& payload = makeShared<SyncInterestPacket>();

    payload->setSrcAddr(rcvMsg->getSrcAddr());
    payload->setSequenceNumber(rcvMsg->getSequenceNumber());
    payload->setTtl(rcvMsg->getTtl() - 1);

    payload->setSv_addrArraySize(rcvMsg->getSv_addrArraySize());
    payload->setSv_counterArraySize(rcvMsg->getSv_counterArraySize());

    for (int i = 0; i < rcvMsg->getSv_addrArraySize(); i++) {
        payload->setSv_addr(i, rcvMsg->getSv_addr(i));
        payload->setSv_counter(i, rcvMsg->getSv_counter(i));
    }

    //payload->setChunkLength(B(par("messageLength")));
    payload->setChunkLength(B(sizeof(uint32_t) + sizeof(uint8_t) + sizeof(uint32_t) + (state_map.size() * (sizeof(uint32_t) + sizeof(uint32_t))) ));

    //payload->setHash(std::hash<std::string>{}(state_vector_string()));
    payload->addTag<CreationTimeTag>()->setCreationTime(simTime());
    packet->insertAtBack(payload);
    L3Address destAddr = Ipv4Address::ALLONES_ADDRESS;
    emit(packetSentSignal, packet);
    socket.sendTo(packet, destAddr, destPort);
    //numInterestSent++;
}

void DiscoveryApp::manageSyncRequestMessage(Ptr<const SyncRequestPacket> rcvMsg, L3Address rcdAddr) {

    //EV_INFO << "Received msg_data_vector: " << rcvMsg->msg_data_vector.size() << endl;
}

void DiscoveryApp::addNewService(Service newService){

    if (myIPAddress != Ipv4Address::UNSPECIFIED_ADDRESS) {
        myCounter++;

        // check if I have already at least one service
        if (state_map.count(myIPAddress) == 0) {
            state_map[myIPAddress] = std::make_pair(myIPAddress, myCounter);
        }
        else{
            state_map[myIPAddress].second = myCounter;
        }

        if (data_map.count(myIPAddress) == 0) {
            data_map[myIPAddress] = std::make_tuple(myIPAddress, myCounter, Services(newService));
        }
        else {
            std::get<1>(data_map[myIPAddress]) = myCounter;
            std::get<2>(data_map[myIPAddress]).add_service(newService);
        }

        myHash = calculate_state_vector_hash();

        //TO-DO send BETTER
    }

}



void DiscoveryApp::sendSyncInterestPacket()
{
    std::ostringstream str;
    str << packetName << "-Interest-" << numInterestSent;
    Packet *packet = new Packet(str.str().c_str());
    if (dontFragment)
        packet->addTag<FragmentationReq>()->setDontFragment(true);
    const auto& payload = makeShared<SyncInterestPacket>();

    payload->setSrcAddr(myIPAddress);
    payload->setSequenceNumber(numInterestSent);
    payload->setTtl(dmax);

    payload->setSv_addrArraySize(state_map.size());
    payload->setSv_counterArraySize(state_map.size());

    int i = 0;
    for (const auto& svel : state_map){
        payload->setSv_addr(i, svel.second.first);
        payload->setSv_counter(i, svel.second.second);
        i++;
    }

    //payload->setChunkLength(B(par("messageLength")));
    payload->setChunkLength(B(sizeof(uint32_t) + sizeof(uint8_t) + sizeof(uint32_t) + (state_map.size() * (sizeof(uint32_t) + sizeof(uint32_t))) ));

    //payload->setHash(std::hash<std::string>{}(state_vector_string()));
    payload->addTag<CreationTimeTag>()->setCreationTime(simTime());
    packet->insertAtBack(payload);
    L3Address destAddr = Ipv4Address::ALLONES_ADDRESS;
    emit(packetSentSignal, packet);
    socket.sendTo(packet, destAddr, destPort);
    numInterestSent++;
}

} // namespace inet



