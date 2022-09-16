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

    payload->setSequenceNumber(numSent);
    payload->setHash(calculate_state_vector_hash());

    //payload->setChunkLength(B(par("messageLength")));
    payload->setChunkLength(B(sizeof(uint32_t) + sizeof(uint64_t)));

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

std::string DiscoveryApp::state_vector_string() {
    std::stringstream ris;

    for (auto const& p : state_vector) {
        ris << p.first << "," << p.second << ";";
    }

    return ris.str();
}

bool compare_state_vector (const std::pair<unsigned int, unsigned int>& first, const std::pair<unsigned int, unsigned int>& second)
{
    return (first.first < second.first);
}

uint64_t DiscoveryApp::calculate_state_vector_hash() {

    state_vector.sort(compare_state_vector);

    return std::hash<std::string>{}(state_vector_string());
}

void DiscoveryApp::manageSyncMessage(Ptr<const SyncCheckPacket> rcvMsg, L3Address rcdAddr) {

    EV_INFO << "Received HASH: " << rcvMsg->getHash() << endl;
}

void DiscoveryApp::manageSyncInterestMessage(Ptr<const SyncInterestPacket> rcvMsg, L3Address rcdAddr) {

    EV_INFO << "Received getSv_addrArraySize: " << rcvMsg->getSv_addrArraySize() << endl;
}


} // namespace inet



