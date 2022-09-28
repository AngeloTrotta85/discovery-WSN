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
#include "inet/networklayer/common/HopLimitTag_m.h"
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
    cancelAndDelete(selfTimer100ms);
    cancelAndDelete(selfTimerXs);
}

void DiscoveryApp::initialize(int stage)
{
    ClockUserModuleMixin::initialize(stage);

    if (stage == INITSTAGE_LOCAL) {
        numSent = 0;
        numReceived = 0;
        myIPAddress = Ipv4Address::UNSPECIFIED_ADDRESS;//L3AddressResolver().resolve(this->getParentModule()->getFullName()).toIpv4();
        WATCH(numSent);
        WATCH(numReceived);

        WATCH(myIPAddress);

        WATCH_MAP(state_map);
        WATCH_MAP(data_map);
        WATCH_MAP(service_creation_time);
        WATCH_MAP(service_registration_time);

        myHash = calculate_state_vector_hash();
        myHostAddress = this->getParentModule()->getIndex();

        dmax = par("dmax");
        broadcastInterest = par("broadcastInterest");
        numServiceInit = par("numServices");
        timeCheckServiceOnOff = par("timeCheckServiceOnOff");
        probabilityServiceOnOff = par("probabilityServiceOnOff");

        localPort = par("localPort");
        destPort = par("destPort");
        startTime = par("startTime");
        stopTime = par("stopTime");
        packetName = par("packetName");
        dontFragment = par("dontFragment");
        if (stopTime >= CLOCKTIME_ZERO && stopTime < startTime)
            throw cRuntimeError("Invalid startTime/stopTime parameters");
        selfMsg = new ClockEvent("sendTimer");

        selfTimer100ms = new ClockEvent("timer100ms");



    }
    else if (stage == INITSTAGE_LAST) {
        ///TEST

        myIPAddress = L3AddressResolver().resolve(this->getParentModule()->getFullName()).toIpv4();
        generateInitNewService(numServiceInit);
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
    if (simTime() < 100) {
        generateRandomNewService(); //TODO remove
    }

    std::ostringstream str;
    str << packetName << "-Check-" << numSent;
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

    payload->addTag<HopLimitReq>()->setHopLimit(1);

    //payload->setHash(std::hash<std::string>{}(state_vector_string()));
    payload->addTag<CreationTimeTag>()->setCreationTime(simTime());
    packet->insertAtBack(payload);
    L3Address destAddr = Ipv4Address::ALLONES_ADDRESS;
    emit(packetSentSignal, packet);
    socket.sendTo(packet, destAddr, destPort);
    numSent++;

    numCheckSent++;
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

    clocktime_t d = ClockTime(100, SIMTIME_MS);
    scheduleClockEventAfter(d, selfTimer100ms);

    clocktime_t d1 = ClockTime(truncnormal(timeCheckServiceOnOff, timeCheckServiceOnOff / 20.0), SIMTIME_S);
    scheduleClockEventAfter(d1, selfTimerXs);

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
        if (msg == selfMsg) {
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
        else if (msg == selfTimer100ms) {
            execute100ms();
            scheduleClockEventAfter(ClockTime(100, SIMTIME_MS), selfTimer100ms);
        }
        else if (msg == selfTimerXs) {
            executeXtimer();

            scheduleClockEventAfter(ClockTime(truncnormal(timeCheckServiceOnOff, timeCheckServiceOnOff / 10.0), SIMTIME_S), selfTimer100ms);
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

void DiscoveryApp::execute100ms (void) {
    if (myHostAddress == 0) {

    }
}

void DiscoveryApp::executeXtimer (void) {
    if (dblrand() < probabilityServiceOnOff) {
        int n_service = my_service_vec.size();
        int s2change = intrand(n_service);

        auto myL3Address = L3Address(myIPAddress);
        myCounter++;//update my main counter because I'm changing the service list

        my_service_vec[s2change].version++;
        if (my_service_vec[s2change].active) {
            my_service_vec[s2change].active = false;

            if (state_map.count(myL3Address) == 0) {
                // warning! I should not be here
                printf("WARNING!!! you should not be here: DiscoveryApp::executeXtimer 1\n");
            }
            else {
                //if (state_map[myL3Address].s)
            }
        }
        else {
            my_service_vec[s2change].active = true;

            // check if I have already at least one service
            if (state_map.count(myL3Address) == 0) {
                state_map[myL3Address] = std::make_pair(myL3Address, myCounter);
            }
            else{
                state_map[myL3Address].second = myCounter;
            }


            if (data_map.count(myL3Address) == 0) {
                //data_map[myL3Address] = std::make_tuple(myL3Address, myCounter, Services(newService));
                data_map[myL3Address] = std::make_tuple(myL3Address, myCounter, Services());
                std::get<2>(data_map[myL3Address]).add_service(my_service_vec[s2change]);
            }
            else {
                std::get<1>(data_map[myL3Address]) = myCounter;
                std::get<2>(data_map[myL3Address]).add_service(my_service_vec[s2change]);
            }

            //service_creation_time[my_service_vec[i].id] = simTime();

        }

        myHash = calculate_state_vector_hash();

        //send BETTER
        std::list<std::tuple<L3Address, unsigned int, Services>> better;

        std::tuple<L3Address, unsigned int, Services> nt;
        std::get<0>(nt) = myL3Address;
        std::get<1>(nt) = myCounter;
        std::get<2>(nt) = Services();
        for (auto& l : std::get<2>(data_map[myL3Address]).list_services){
            std::get<2>(nt).add_service(l);
        }

        better.push_back(nt);

        sendSyncBetterPacket(Ipv4Address::ALLONES_ADDRESS, better);
    }
}


void DiscoveryApp::processPacket(Packet *pk)
{
    if (printDebug) { printf("START - DiscoveryApp::processPacket \n");fflush(stdout); }

    emit(packetReceivedSignal, pk);
    EV_INFO << "Received packet: " << UdpSocket::getReceivedPacketInfo(pk) << endl;

    // determine its source address/port
    L3Address remoteAddress = pk->getTag<L3AddressInd>()->getSrcAddress();
    L3Address destAddress = pk->getTag<L3AddressInd>()->getDestAddress();
    int srcPort = pk->getTag<L4PortInd>()->getSrcPort();

    EV_INFO << myIPAddress << " Received packet from IP: " << remoteAddress << ":" << srcPort << " with destination: " << destAddress << endl;
    if (remoteAddress == Ipv4Address::LOOPBACK_ADDRESS){
        EV_INFO << "Received packet form ME!!!! : " << remoteAddress << ":" << srcPort << endl;
    }
    else {

        //EV_INFO << "RECEIVED: " << pk->getClassName() << " - " << pk->getName() << " - " << pk->getClassAndFullName();
        //std::stringstream ccc;
        //ccc << "RECEIVED: " << pk->getClassName() << "|" << pk->getName() << "|" << pk->getClassAndFullName() << "|" << pk->getDisplayString() << "|" << pk->;

        //printf("%s\n", ccc.str().c_str());fflush(stdout);

        //check_and_cast(p)
        std::string sName = std::string(pk->getName());
        if (sName.find("Check") != std::string::npos) {
            const auto& appmsg_check = pk->peekDataAt<SyncCheckPacket>(B(0), B(pk->getByteLength()));
            if (appmsg_check) {
                manageSyncMessage(appmsg_check, remoteAddress);
            }
        }
        else if (sName.find("Interest") != std::string::npos) {
            const auto& appmsg_interest = pk->peekDataAt<SyncInterestPacket>(B(0), B(pk->getByteLength()));
            if (appmsg_interest) {
                manageSyncInterestMessage(appmsg_interest, remoteAddress);
            }
        }
        else if (sName.find("Request") != std::string::npos) {
            const auto& appmsg_request = pk->peekDataAt<SyncRequestPacket>(B(0), B(pk->getByteLength()));
            if (appmsg_request) {
                manageSyncRequestMessage(appmsg_request, remoteAddress);
            }
        }
        else if (sName.find("Better") != std::string::npos) {
            const auto& appmsg_better = pk->peekDataAt<SyncBetterPacket>(B(0), B(pk->getByteLength()));
            if (appmsg_better) {
                manageSyncBetterMessage(appmsg_better, remoteAddress, destAddress);
            }
        }
        else {
            throw cRuntimeError("Message (%s)%s is not a valid packet", pk->getClassName(), pk->getName());
        }
    }


//    const auto& appmsg_check = pk->peekDataAt<SyncCheckPacket>(B(0), B(pk->getByteLength()));
//    if (appmsg_check) {
//        manageSyncMessage(appmsg_check, remoteAddress);
//    }
//    else {
//        const auto& appmsg_interest = pk->peekDataAt<SyncInterestPacket>(B(0), B(pk->getByteLength()));
//        if (appmsg_interest) {
//            manageSyncInterestMessage(appmsg_interest, remoteAddress);
//        }
//        else {
//            const auto& appmsg_request = pk->peekDataAt<SyncRequestPacket>(B(0), B(pk->getByteLength()));
//            if (appmsg_request) {
//                manageSyncRequestMessage(appmsg_request, remoteAddress);
//            }
//            else {
//                throw cRuntimeError("Message (%s)%s is not a valid packet", pk->getClassName(), pk->getName());
//            }
//        }
//    }

    //if (!appmsg)
    //    throw cRuntimeError("Message (%s)%s is not a SyncCheckPacket -- probably wrong client app, or wrong setting of UDP's parameters", pk->getClassName(), pk->getName());




    delete pk;
    if (remoteAddress != Ipv4Address::LOOPBACK_ADDRESS){
        numReceived++;
    }

    if (printDebug) { printf("END - DiscoveryApp::processPacket \n");fflush(stdout); }
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
    numCheckReceived++;

    EV_INFO << "Received SYNC-CHECK packet from: " << rcvMsg->getSrcAddr() << " with hash: " << rcvMsg->getHash() << endl;

    //chekc if need to forward
    if ((rcvMsg->getTtl() > 1) && checkForward(rcvMsg, rcdAddr)) {
        forwardSyncCheck(rcvMsg);

        labelForward(rcvMsg);
    }

    if (    (max_saw_sync_check_map.count(rcvMsg->getSrcAddr()) == 0) ||
            (max_saw_sync_check_map[rcvMsg->getSrcAddr()] < rcvMsg->getSequenceNumber())) {
        max_saw_sync_check_map[rcvMsg->getSrcAddr()] = rcvMsg->getSequenceNumber();

        EV_INFO << "Managing SYNC-CHECK. My HASH is: " << myHash << endl;

        //check message if different hashes
        if (rcvMsg->getHash() != myHash) {
            sendSyncInterestPacket(rcdAddr);
        }
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
    str << packetName << "-Check-fwd-" << rcvMsg->getSequenceNumber();
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

    payload->addTag<HopLimitReq>()->setHopLimit(1);

    //payload->setHash(std::hash<std::string>{}(state_vector_string()));
    payload->addTag<CreationTimeTag>()->setCreationTime(simTime());
    packet->insertAtBack(payload);
    L3Address destAddr = Ipv4Address::ALLONES_ADDRESS;
    emit(packetSentSignal, packet);
    socket.sendTo(packet, destAddr, destPort);
    //numSent++;
    numCheckForwarded++;
}

void DiscoveryApp::manageSyncInterestMessage(Ptr<const SyncInterestPacket> rcvMsg, L3Address rcvAddr) {

    if (printDebug) { printf("START - DiscoveryApp::manageSyncInterestMessage \n");fflush(stdout); }

    std::list<std::pair<L3Address, unsigned int>> worse;
    std::list<std::tuple<L3Address, unsigned int, Services>> better;

    EV_INFO << "Received SYNC-INTEREST packet from: " << rcvMsg->getSrcAddr() << " with: ";
    for (int i = 0; i < rcvMsg->getSv_addrArraySize(); i++) {
        EV_INFO << "(" << rcvMsg->getSv_addr(i) << "|" << rcvMsg->getSv_counter(i) << ") ";
    }
    EV_INFO << endl;

    EV_INFO << "My state_map is: ";
    for (auto& sv : state_map) {
        EV_INFO << "(" << sv.second << ") ";
    }
    EV_INFO << endl;

    numInterestReceived++;

    //chekc if need to forward
    if (    broadcastInterest &&
            (rcvMsg->getTtl() > 1) &&
            checkInterestForward(rcvMsg, rcvAddr)) {
        forwardSyncInterest(rcvMsg);

        labelInterestForward(rcvMsg);
    }

    if (    (max_saw_sync_interest_map.count(rcvMsg->getSrcAddr()) == 0) ||
                (max_saw_sync_interest_map[rcvMsg->getSrcAddr()] < rcvMsg->getSequenceNumber())) {
        max_saw_sync_interest_map[rcvMsg->getSrcAddr()] = rcvMsg->getSequenceNumber();

        EV_INFO << "Managing SYNC-INTEREST" << endl;

        for (int i = 0; i < rcvMsg->getSv_addrArraySize(); i++){
            if (    (state_map.count(rcvMsg->getSv_addr(i)) == 0 ) ||
                    (rcvMsg->getSv_counter(i) > state_map[rcvMsg->getSv_addr(i)].second) ){
                std::pair<L3Address, unsigned int> np;
                np.first = rcvMsg->getSv_addr(i);
                np.second = rcvMsg->getSv_counter(i);
                worse.push_back(np);
            }
        }

        for (auto& dm : data_map){
            bool isbetter = true;
            for (int i = 0; i < rcvMsg->getSv_addrArraySize(); i++){
                if ((rcvMsg->getSv_addr(i) == std::get<0>(dm.second)) && (rcvMsg->getSv_counter(i) >= std::get<1>(dm.second))){
                    isbetter = false;
                }
            }

            if (isbetter) {
                std::tuple<L3Address, unsigned int, Services> nt;
                std::get<0>(nt) = std::get<0>(dm.second);// rcvMsg->getSv_addr(i);
                std::get<1>(nt) = std::get<1>(dm.second);// std::get<1>(data_map[rcvMsg->getSv_addr(i)]);
                std::get<2>(nt) = Services();
                for (auto& l : std::get<2>(dm.second).list_services){
                    std::get<2>(nt).add_service(l);
                }

                better.push_back(nt);

            }
        }

        /*
        for (int i = 0; i < rcvMsg->getSv_addrArraySize(); i++){
            if (printDebug) { printf("C0 I%d - DiscoveryApp::manageSyncInterestMessage \n", i);fflush(stdout); }

            if (state_map.count(rcvMsg->getSv_addr(i)) == 0 ) {
                if (printDebug) { printf("C1 - DiscoveryApp::manageSyncInterestMessage \n");fflush(stdout); }
                std::pair<L3Address, unsigned int> np;
                np.first = rcvMsg->getSv_addr(i);
                np.second = rcvMsg->getSv_counter(i);
                worse.push_back(np);
            }
            else {
                if (rcvMsg->getSv_counter(i) > state_map[rcvMsg->getSv_addr(i)].second) {
                    if (printDebug) { printf("C2 - DiscoveryApp::manageSyncInterestMessage \n");fflush(stdout); }
                    std::pair<L3Address, unsigned int> np;
                    np.first = rcvMsg->getSv_addr(i);
                    np.second = rcvMsg->getSv_counter(i);

                    worse.push_back(np);
                }
                else if (rcvMsg->getSv_counter(i) < state_map[rcvMsg->getSv_addr(i)].second){
                    if (printDebug) { printf("C3 - DiscoveryApp::manageSyncInterestMessage \n");fflush(stdout); }
                    std::tuple<L3Address, unsigned int, Services> nt;
                    std::get<0>(nt) = rcvMsg->getSv_addr(i);
                    std::get<1>(nt) = std::get<1>(data_map[rcvMsg->getSv_addr(i)]);
                    std::get<2>(nt) = Services();
                    for (auto& l : std::get<2>(data_map[rcvMsg->getSv_addr(i)]).list_services){
                        std::get<2>(nt).add_service(l);
                    }

                    better.push_back(nt);
                }
            }
        }
        */

        EV_INFO << "The WORSE are " << worse.size() << ": ";
        for (auto& sv : worse) {
            EV_INFO << "(" << sv << ") ";
        }
        EV_INFO << endl;
        if (worse.size() > 0) {
            sendSyncRequestPacket(rcvMsg->getSrcAddr(), worse);
        }


        EV_INFO << "The BETTER are " << better.size() << ": ";
        for (auto& sv : better) {
            EV_INFO << "(" << sv << ") ";
        }
        EV_INFO << endl;
        if (better.size() > 0) {
            sendSyncBetterPacket(rcvMsg->getSrcAddr(), better);
        }
    }

    if (printDebug) { printf("END - DiscoveryApp::manageSyncInterestMessage \n");fflush(stdout); }
}

void DiscoveryApp::manageSyncInterestMessage_old(Ptr<const SyncInterestPacket> rcvMsg, L3Address rcdAddr) {

    if (printDebug) { printf("START - DiscoveryApp::manageSyncInterestMessage \n");fflush(stdout); }

    EV_INFO << "Received getSv_addrArraySize: " << rcvMsg->getSv_addrArraySize() << endl;
    EV_INFO << "Received getSv_counterArraySize: " << rcvMsg->getSv_counterArraySize() << endl;
    EV_INFO << "Received getSrcAddr: " << rcvMsg->getSrcAddr() << endl;

    if (printDebug) { printf("C0 - DiscoveryApp::manageSyncInterestMessage \n");fflush(stdout); }

    //printf("[%s] - Received from %s \n", myIPAddress.str().c_str(), rcdAddr.str().c_str());

    //chekc if need to forward
    /*if ((rcvMsg->getTtl() > 1) && checkInterestForward(rcvMsg, rcdAddr)) {
        forwardSyncInterest(rcvMsg);

        labelInterestForward(rcvMsg);
    }*/

    //return;

    //check message if different hashes
    //TO-DO
    std::list<std::pair<L3Address, unsigned int>> worse;
    std::list<std::tuple<L3Address, unsigned int, Services>> better;

    /*for (int i = 0; i < rcvMsg->getSv_addrArraySize(); i++){
        printf("rcvMsg->getSv_addr(i): %s \n", rcvMsg->getSv_addr(i).str().c_str());
    }
    for (int i = 0; i < rcvMsg->getSv_counterArraySize(); i++){
        printf("rcvMsg->getSv_counter(i): %u \n", rcvMsg->getSv_counter(i));
    }*/

    for (int i = 0; i < rcvMsg->getSv_addrArraySize(); i++){

        if (printDebug) { printf("C0 I%d - DiscoveryApp::manageSyncInterestMessage \n", i);fflush(stdout); }

        //printf("rcvMsg->getSv_addr(i): %s \n", rcvMsg->getSv_addr(i).str().c_str());fflush(stdout);

        if (state_map.count(rcvMsg->getSv_addr(i)) == 0 ) {
            if (printDebug) { printf("C1 - DiscoveryApp::manageSyncInterestMessage \n");fflush(stdout); }
            worse.push_back(std::make_pair(rcvMsg->getSv_addr(i), state_map[rcvMsg->getSv_addr(i)].second));
        }
        else {
            if (printDebug) { printf("C2 - DiscoveryApp::manageSyncInterestMessage \n");fflush(stdout); }
            if (rcvMsg->getSv_counter(i) > state_map[rcvMsg->getSv_addr(i)].second) {
                if (printDebug) { printf("C3 - DiscoveryApp::manageSyncInterestMessage \n");fflush(stdout); }
                worse.push_back(std::make_pair(rcvMsg->getSv_addr(i), state_map[rcvMsg->getSv_addr(i)].second));
            }
            else if (rcvMsg->getSv_counter(i) < state_map[rcvMsg->getSv_addr(i)].second){
                if (printDebug) { printf("C4 - DiscoveryApp::manageSyncInterestMessage \n");fflush(stdout); }
                better.push_back(std::make_tuple(
                        //rcvMsg->getSv_addr(i),
                        std::get<0>(data_map[rcvMsg->getSv_addr(i)]),
                        std::get<1>(data_map[rcvMsg->getSv_addr(i)]),
                        std::get<2>(data_map[rcvMsg->getSv_addr(i)])));
            }

        }

//        if ((state_map.count(rcvMsg->getSv_addr(i)) == 0 ) || (rcvMsg->getSv_counter(i) > state_map[rcvMsg->getSv_addr(i)].second) ){
//            worse.push_back(std::make_pair(rcvMsg->getSv_addr(i), state_map[rcvMsg->getSv_addr(i)].second));
//        }
//        else if ( (state_map.count(rcvMsg->getSv_addr(i)) != 0 ) && (rcvMsg->getSv_counter(i) < state_map[rcvMsg->getSv_addr(i)].second) ){
//            better.push_back(std::make_tuple(
//                    //rcvMsg->getSv_addr(i),
//                    std::get<0>(data_map[rcvMsg->getSv_addr(i)]),
//                    std::get<1>(data_map[rcvMsg->getSv_addr(i)]),
//                    std::get<2>(data_map[rcvMsg->getSv_addr(i)])));
//        }
    }

    //for (auto& wel : worse) {

    //}

    if (printDebug) { printf("END - DiscoveryApp::manageSyncInterestMessage \n");fflush(stdout); }
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
    numInterestForwarded++;
}


void DiscoveryApp::sendSyncRequestPacket(L3Address dest, std::list<std::pair<L3Address, unsigned int>> &wl) {
        std::ostringstream str;
        str << packetName << "-Request-" << numRequestSent;
        Packet *packet = new Packet(str.str().c_str());
        if (dontFragment)
            packet->addTag<FragmentationReq>()->setDontFragment(true);
        const auto& payload = makeShared<SyncRequestPacket>();

        payload->setSrcAddr(myIPAddress);
        payload->setSequenceNumber(numInterestSent);
        payload->setTtl(dmax);

        payload->setSv_addrArraySize(wl.size());
        payload->setSv_counterArraySize(wl.size());


        //printf("[%s] - wl:%d\n", myIPAddress.str().c_str(), ((int) wl.size()));

        int i = 0;
        for (const auto& svel : wl){
            payload->setSv_addr(i, svel.first);
            payload->setSv_counter(i, svel.second);

            //printf("[%s] - Sending %s - %u\n", myIPAddress.str().c_str(), payload->getSv_addr(i).str().c_str(), payload->getSv_counter(i));

            i++;
        }

        EV_INFO << "Sending REQUEST: ";
        for (int j = 0; j < payload->getSv_counterArraySize(); j++) {
            EV_INFO << "(" << payload->getSv_addr(j) << "-" << payload->getSv_counter(j) << ") ";
        }
        EV_INFO << endl;


        //payload->setChunkLength(B(par("messageLength")));
        payload->setChunkLength(B(sizeof(uint32_t) + sizeof(uint8_t) + sizeof(uint32_t) + (state_map.size() * (sizeof(uint32_t) + sizeof(uint32_t))) ));

        //payload->setHash(std::hash<std::string>{}(state_vector_string()));
        payload->addTag<CreationTimeTag>()->setCreationTime(simTime());
        packet->insertAtBack(payload);
        L3Address destAddr = dest; //Ipv4Address::ALLONES_ADDRESS;

        EV_INFO << "Sending CHECK-REQUEST to : " << destAddr << endl;

        emit(packetSentSignal, packet);
        socket.sendTo(packet, destAddr, destPort);
        numRequestSent++;

}

void DiscoveryApp::manageSyncRequestMessage(Ptr<const SyncRequestPacket> rcvMsg, L3Address rcdAddr) {

    //EV_INFO << "Received msg_data_vector: " << rcvMsg->msg_data_vector.size() << endl;

    std::list<std::tuple<L3Address, unsigned int, Services>> better;

    EV_INFO << "Received SYNC-REQUEST packet from: " << rcvMsg->getSrcAddr() << " with: ";
    for (int i = 0; i < rcvMsg->getSv_addrArraySize(); i++) {
        EV_INFO << "(" << rcvMsg->getSv_addr(i) << "|" << rcvMsg->getSv_counter(i) << ") ";
    }
    EV_INFO << endl;

    EV_INFO << "My state_map is: ";
    for (auto& sv : state_map) {
        EV_INFO << "(" << sv.second << ") ";
    }
    EV_INFO << endl;

    for (int i = 0; i < rcvMsg->getSv_addrArraySize(); i++){

        if (state_map.count(rcvMsg->getSv_addr(i)) != 0 ) {

            if (rcvMsg->getSv_counter(i) < state_map[rcvMsg->getSv_addr(i)].second){

                std::tuple<L3Address, unsigned int, Services> nt;
                std::get<0>(nt) = rcvMsg->getSv_addr(i);
                std::get<1>(nt) = std::get<1>(data_map[rcvMsg->getSv_addr(i)]);
                std::get<2>(nt) = Services();
                for (auto& l : std::get<2>(data_map[rcvMsg->getSv_addr(i)]).list_services){
                    std::get<2>(nt).add_service(l);
                }

                better.push_back(nt);
            }
        }
    }

    EV_INFO << "Sending BETTER? list size: " << better.size() << endl;

    if (better.size() > 0) {
        sendSyncBetterPacket(rcvMsg->getSrcAddr(), better);
    }

    numRequestReceived++;

}

void DiscoveryApp::sendSyncBetterPacket(L3Address dest, std::list<std::tuple<L3Address, unsigned int, Services>> &bl) {
    std::ostringstream str;
    str << packetName << "-Better-" << numBetterSent;
    Packet *packet = new Packet(str.str().c_str());
    if (dontFragment)
        packet->addTag<FragmentationReq>()->setDontFragment(true);
    const auto& payload = makeShared<SyncBetterPacket>();

    payload->setSrcAddr(myIPAddress);
    payload->setSequenceNumber(numInterestSent);
    payload->setTtl(dmax);

    int services_size = 0;

    for (auto& blel : bl){
        payload->msg_data_vector.push_back(blel);
        services_size += sizeof(uint32_t) + sizeof(uint32_t) + (std::get<2>(blel).list_services.size() * (sizeof(uint32_t) + 128));
    }

    EV_INFO << "Sending BETTER: ";
    for (auto& bbb : payload->msg_data_vector) {
        EV_INFO << "(" << bbb << ") ";
    }
    EV_INFO << endl;


    //payload->setChunkLength(B(par("messageLength")));
    payload->setChunkLength(B(sizeof(uint32_t) + sizeof(uint8_t) + sizeof(uint32_t) + services_size ));

    //payload->setHash(std::hash<std::string>{}(state_vector_string()));
    payload->addTag<CreationTimeTag>()->setCreationTime(simTime());
    packet->insertAtBack(payload);
    L3Address destAddr = dest; //Ipv4Address::ALLONES_ADDRESS;

    EV_INFO << "Sending CHECK-BETTER to : " << destAddr << endl;

    emit(packetSentSignal, packet);
    socket.sendTo(packet, destAddr, destPort);
    numBetterSent++;

}

void DiscoveryApp::manageSyncBetterMessage(Ptr<const SyncBetterPacket> rcvMsg, L3Address rcdAddr, L3Address destAddr) {

    EV_INFO << "Received SYNC-BETTER packet from: " << rcvMsg->getSrcAddr() << " with: ";
    for (auto& bbb : rcvMsg->msg_data_vector) {
        EV_INFO << "(" << bbb << ") ";
    }
    EV_INFO << endl;

    //chekc if need to forward
        if (    (destAddr == Ipv4Address::ALLONES_ADDRESS) &&
                (rcvMsg->getTtl() > 1) &&
                checkBetterForward(rcvMsg, rcdAddr)) {
            forwardSyncBetter(rcvMsg);

            labelBetterForward(rcvMsg);
        }

        if (    (max_saw_sync_better_map.count(rcvMsg->getSrcAddr()) == 0) ||
                (max_saw_sync_better_map[rcvMsg->getSrcAddr()] < rcvMsg->getSequenceNumber())) {
            max_saw_sync_better_map[rcvMsg->getSrcAddr()] = rcvMsg->getSequenceNumber();

            EV_INFO << "Managing SYNC-BETTER" << endl;

            for(auto& bm : rcvMsg->msg_data_vector) {


                if ((state_map.count(std::get<0>(bm)) == 0) || (std::get<1>(bm) > state_map[std::get<0>(bm)].second)) {

                    std::tuple<L3Address, unsigned int, Services> nt;
                    std::get<0>(nt) = std::get<0>(bm);
                    std::get<1>(nt) = std::get<1>(bm);
                    std::get<2>(nt) = Services();
                    for (auto& l : std::get<2>(bm).list_services){
                        std::get<2>(nt).add_service(l);
                    }

                    data_map[std::get<0>(bm)] = nt;

                    doSomethingWhenAddService(nt);

                    state_map[std::get<0>(bm)] = std::make_pair(std::get<0>(bm), std::get<1>(bm));
                }

            }

            EV_INFO << "My new state_map is: " << endl;
            for (auto& dm : state_map) {
                EV_INFO << "(" << dm.second << ") " << endl;
            }
            EV_INFO << "My new data_map is: " << endl;
            for (auto& dm : data_map) {
                EV_INFO << "(" << dm.second << ") " << endl;
            }

            myHash = calculate_state_vector_hash();

            numBetterReceived++;
        }
}



bool DiscoveryApp::checkBetterForward(Ptr<const SyncBetterPacket> rcvMsg, L3Address rcdAddr) {
    if (forward_sync_better_map.count(rcvMsg->getSrcAddr()) == 0) {
        return true;
    }
    else{
        return (rcvMsg->getSequenceNumber() > forward_sync_better_map[rcvMsg->getSrcAddr()]);
    }
}

void DiscoveryApp::labelBetterForward(Ptr<const SyncBetterPacket> rcvMsg) {
    forward_sync_better_map[rcvMsg->getSrcAddr()] = rcvMsg->getSequenceNumber();
}

void DiscoveryApp::forwardSyncBetter(Ptr<const SyncBetterPacket> rcvMsg) {

    std::ostringstream str;
    str << packetName << "-BetterFWD-" << rcvMsg->getSequenceNumber();
    Packet *packet = new Packet(str.str().c_str());
    if (dontFragment)
        packet->addTag<FragmentationReq>()->setDontFragment(true);
    const auto& payload = makeShared<SyncBetterPacket>();

    payload->setSrcAddr(rcvMsg->getSrcAddr());
    payload->setSequenceNumber(rcvMsg->getSequenceNumber());
    payload->setTtl(rcvMsg->getTtl() - 1);

    int services_size = 0;

    for (auto& blel : rcvMsg->msg_data_vector){
        payload->msg_data_vector.push_back(blel);
        services_size += sizeof(uint32_t) + sizeof(uint32_t) + (std::get<2>(blel).list_services.size() * (sizeof(uint32_t) + 128));
    }

    //payload->setChunkLength(B(par("messageLength")));
    payload->setChunkLength(B(sizeof(uint32_t) + sizeof(uint8_t) + sizeof(uint32_t) + services_size ));

    //payload->setHash(std::hash<std::string>{}(state_vector_string()));
    payload->addTag<CreationTimeTag>()->setCreationTime(simTime());
    packet->insertAtBack(payload);
    L3Address destAddr = Ipv4Address::ALLONES_ADDRESS;
    emit(packetSentSignal, packet);
    socket.sendTo(packet, destAddr, destPort);
    numBetterForwarded++;
}

void DiscoveryApp::addNewService(Service newService){

    if (myIPAddress != Ipv4Address::UNSPECIFIED_ADDRESS) {
        myCounter++;

        auto myL3Address = L3Address(myIPAddress);

        // check if I have already at least one service
        if (state_map.count(myL3Address) == 0) {
            state_map[myL3Address] = std::make_pair(myL3Address, myCounter);
        }
        else{
            state_map[myL3Address].second = myCounter;
        }

        /*for (const auto& svel : state_map){

            printf("[%s] State_map after adding service %s - %u\n", myL3Address.str().c_str(), svel.second.first.str().c_str(), svel.second.second);

        }*/

        if (data_map.count(myL3Address) == 0) {
            //data_map[myL3Address] = std::make_tuple(myL3Address, myCounter, Services(newService));
            data_map[myL3Address] = std::make_tuple(myL3Address, myCounter, Services());
            std::get<2>(data_map[myL3Address]).add_service(newService);
        }
        else {
            std::get<1>(data_map[myL3Address]) = myCounter;
            std::get<2>(data_map[myL3Address]).add_service(newService);
        }

        myHash = calculate_state_vector_hash();

        //send BETTER
        std::list<std::tuple<L3Address, unsigned int, Services>> better;

        std::tuple<L3Address, unsigned int, Services> nt;
        std::get<0>(nt) = myL3Address;
        std::get<1>(nt) = myCounter;
        std::get<2>(nt) = Services();
        for (auto& l : std::get<2>(data_map[myL3Address]).list_services){
            std::get<2>(nt).add_service(l);
        }

        better.push_back(nt);

        sendSyncBetterPacket(Ipv4Address::ALLONES_ADDRESS, better);
    }

}

void DiscoveryApp::generateRandomNewService(void){
    //if (dblrand() < 0.1) {
    if (false) {
        Service newS;

        newS.id = myServiceIDCounter; //rand();
        newS.active = true;
        myServiceIDCounter++;
        //newS.description = std::string("NewService-" + simTime().str()).c_str();
        strcpy(newS.description, std::string("NewService-" + simTime().str()).c_str());

        service_creation_time[newS.id] = simTime();

        addNewService(newS);
    }
}

void DiscoveryApp::generateInitNewService(int ns) {

    auto myL3Address = L3Address(myIPAddress);

    my_service_vec.resize(ns, Service());

    for (int i = 0; i < ns; i++) {
        my_service_vec[i].id = myServiceIDCounter;
        my_service_vec[i].active = (dblrand() < 0.5);
        my_service_vec[i].version = 0;

        std::stringstream ss;
        ss << "NewService-" << myHostAddress << "-" << myServiceIDCounter << "-" << simTime();
        strcpy(my_service_vec[i].description, ss.str().c_str());

        myServiceIDCounter++;

        if (my_service_vec[i].active) {
            // check if I have already at least one service
            if (state_map.count(myL3Address) == 0) {
                state_map[myL3Address] = std::make_pair(myL3Address, myCounter);
            }
            else{
                state_map[myL3Address].second = myCounter;
            }


            if (data_map.count(myL3Address) == 0) {
                //data_map[myL3Address] = std::make_tuple(myL3Address, myCounter, Services(newService));
                data_map[myL3Address] = std::make_tuple(myL3Address, myCounter, Services());
                std::get<2>(data_map[myL3Address]).add_service(my_service_vec[i]);
            }
            else {
                std::get<1>(data_map[myL3Address]) = myCounter;
                std::get<2>(data_map[myL3Address]).add_service(my_service_vec[i]);
            }

            service_creation_time[my_service_vec[i].id] = simTime();
        }
    }

    /*

    for (int i = 0; i < ns; i++) {
        Service newS;

        newS.id = myServiceIDCounter;
        newS.active = (dblrand() < 0.5);

        std::stringstream ss;
        ss << "NewService-" << myHostAddress << "-" << myServiceIDCounter << "-" << simTime();

        //strcpy(newS.description, std::string("NewService-" + std::string(myHostAddress).c_str() + "-" + std::string(myServiceIDCounter).c_str() + "-" + simTime().str()).c_str());
        strcpy(newS.description, ss.str().c_str());

        myServiceIDCounter++;

        //my_service_vec


        // check if I have already at least one service
        if (state_map.count(myL3Address) == 0) {
            state_map[myL3Address] = std::make_pair(myL3Address, myCounter);
        }
        else{
            state_map[myL3Address].second = myCounter;
        }


        if (data_map.count(myL3Address) == 0) {
            //data_map[myL3Address] = std::make_tuple(myL3Address, myCounter, Services(newService));
            data_map[myL3Address] = std::make_tuple(myL3Address, myCounter, Services());
            std::get<2>(data_map[myL3Address]).add_service(newS);
        }
        else {
            std::get<1>(data_map[myL3Address]) = myCounter;
            std::get<2>(data_map[myL3Address]).add_service(newS);
        }

        service_creation_time[newS.id] = simTime();
    }

    */

    myHash = calculate_state_vector_hash();
}



void DiscoveryApp::sendSyncInterestPacket(L3Address dest)
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


    //printf("[%s] - state_map:%d; data_map:%d\n", myIPAddress.str().c_str(), ((int) state_map.size()), ((int) data_map.size()));

    int i = 0;
    for (const auto& svel : state_map){
        payload->setSv_addr(i, svel.second.first);
        payload->setSv_counter(i, svel.second.second);

        //printf("[%s] - Sending %s - %u\n", myIPAddress.str().c_str(), payload->getSv_addr(i).str().c_str(), payload->getSv_counter(i));

        i++;
    }

    EV_INFO << "Sending INTEREST: ";
    for (int j = 0; j < payload->getSv_counterArraySize(); j++) {
        EV_INFO << "(" << payload->getSv_addr(j) << "-" << payload->getSv_counter(j) << ") ";
    }
    EV_INFO << endl;

    //payload->setChunkLength(B(par("messageLength")));
    payload->setChunkLength(B(sizeof(uint32_t) + sizeof(uint8_t) + sizeof(uint32_t) + (state_map.size() * (sizeof(uint32_t) + sizeof(uint32_t))) ));

    //payload->setHash(std::hash<std::string>{}(state_vector_string()));
    payload->addTag<CreationTimeTag>()->setCreationTime(simTime());
    packet->insertAtBack(payload);
    L3Address destAddr = dest; //Ipv4Address::ALLONES_ADDRESS;
    if (broadcastInterest) {
        destAddr = Ipv4Address::ALLONES_ADDRESS;
    }

    EV_INFO << "Sending CHECK-INTEREST to : " << destAddr << endl;

    emit(packetSentSignal, packet);
    socket.sendTo(packet, destAddr, destPort);
    numInterestSent++;
}

void DiscoveryApp::doSomethingWhenAddService (std::tuple<L3Address, unsigned int, Services> &nt) {

    printf("%s - %s - doSomethingWhenAddService - START\n", myIPAddress.str().c_str(), simTime().str().c_str());

    for (auto& s : std::get<2>(nt).list_services) {
        service_owner_t so;
        so.node_addr = std::get<0>(nt);
        so.service_id = s.id;

        if(service_registration_time.count(so) == 0) {
            service_registration_time[so] = simTime();

            //check i I'm the last one
            int nnodes = this->getParentModule()->getVectorSize();
            int countUpdate = 0;
            for (int i = 0; i < nnodes; i++) {
                //DiscoveryApp *app = check_and_cast<DiscoveryApp *>(this->getParentModule()->getParentModule()->getSubmodule(this->getName(), i));
                DiscoveryApp *app = check_and_cast<DiscoveryApp *>(this->getParentModule()->getParentModule()->getSubmodule(this->getParentModule()->getName(), i)->getSubmodule(this->getName(), 0));

                if (app->service_registration_time.count(so) != 0) {
                    countUpdate++;
                }
            }

            printf("%d\n", countUpdate);
            if (countUpdate == nnodes) {
                printf("SYNC!!!\n");
            }
            fflush(stdout);
        }
    }

    printf("%s - doSomethingWhenAddService - END\n", myIPAddress.str().c_str());
}

} // namespace inet



