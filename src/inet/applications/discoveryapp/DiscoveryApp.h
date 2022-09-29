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

#ifndef INET_APPLICATIONS_DISCOVERYAPP_DISCOVERYAPP_H_
#define INET_APPLICATIONS_DISCOVERYAPP_DISCOVERYAPP_H_

#include <vector>
#include <list>
#include <string>
#include <map>

#include "SyncCheckPacket_m.h"
#include "SyncInterestPacket_m.h"
#include "SyncRequestPacket_m.h"
#include "SyncBetterPacket_m.h"

#include "inet/applications/base/ApplicationBase.h"
#include "inet/common/clock/ClockUserModuleMixin.h"
#include "inet/transportlayer/contract/udp/UdpSocket.h"


namespace inet {

extern template class ClockUserModuleMixin<ApplicationBase>;


class Service {
public:
    Service() {};
    ~Service() {};

    uint32_t id;
    bool active;
    int version;
    char description[128];
};

class Services {
public:
    Services() {};
    Services(Service serv) {
        list_services.push_back(serv);
    };
    ~Services() {};

    std::list<Service> list_services;

    void add_service(Service s2add){
        list_services.push_back(s2add);
    }

    //friend std::ostream& operator<<(std::ostream& os, const Services& ss);

    /*std::ostream & operator<< (std::ostream &out, Services const &ss) {
        for (auto& s : ss.list_services){
            out << "[" << s.id << "] - (" << s.description << ")";
        }
        return out;
    }*/
};

inline std::ostream& operator<<(std::ostream& os, const Services& ss)
{
    os << "{";
    for (auto& s : ss.list_services){
        os << "[" << s.id << "-" << (s.active ? "A" : "NA") << "-V" << s.version << "]-(" << s.description << ") ";
    }
    os << "}";
    return os;
}

inline std::ostream& operator<<(std::ostream& os, const std::pair<L3Address, unsigned int>& pp)
{
    os << "<" << pp.first << "|" << pp.second << ">";
    return os;
}

inline std::ostream& operator<<(std::ostream& os, const std::tuple<L3Address, unsigned int, Services>& pp)
{
    os << "<" << std::get<0>(pp) << "|" << std::get<1>(pp) << "|" << std::get<2>(pp) << ">";
    return os;
}



//std::ostream& operator<<(std::ostream& os, const Services& ss)
//{
//    for (auto& s : ss.list_services){
//        os << "[" << s.id << "] - (" << s.description << ")";
//    }
//    return os;
//}

class INET_API DiscoveryApp : public ClockUserModuleMixin<ApplicationBase>, public UdpSocket::ICallback
{
public:
    typedef struct {
        simtime_t timestamp;
        unsigned int service_id;
    } service_time_t;

    typedef struct service_owner {
        L3Address node_addr;
        uint32_t service_id;
        uint32_t service_counter;
    } service_owner_t;

    friend bool operator==(const service_owner_t& a, const service_owner_t& b) {
        return (a.node_addr == b.node_addr) && (a.service_id == b.service_id) && (a.service_counter == b.service_counter);
    }

    friend bool operator<(const service_owner_t& a, const service_owner_t& b) {
        return (a.node_addr < b.node_addr) && (a.service_id < b.service_id) && (a.service_counter < b.service_counter);
    }

    friend std::ostream& operator<<(std::ostream& os, const service_owner_t& so) {
        os << "<" << so.node_addr << "|ID:" << so.service_id << "|C:" << so.service_counter << ">";
        return os;
    }

public:
    std::map<uint32_t, simtime_t> service_creation_time;
    std::map<service_owner_t, simtime_t> service_registration_time;
    std::vector<Service> my_service_vec;
    Ipv4Address myIPAddress;
    int myHostAddress;

  protected:
    enum SelfMsgKinds { START = 1, SEND, STOP };

    // parameters
    std::vector<L3Address> destAddresses;
    std::vector<std::string> destAddressStr;
    int localPort = -1, destPort = -1;
    clocktime_t startTime;
    clocktime_t stopTime;
    bool dontFragment = false;
    const char *packetName = nullptr;
    int dmax;

    bool broadcastInterest = false;
    int numServiceInit;
    double timeCheckServiceOnOff;
    double probabilityServiceOnOff;

    // state
    UdpSocket socket;
    ClockEvent *selfMsg = nullptr;
    ClockEvent *selfTimer100ms = nullptr;
    ClockEvent *selfTimerXs = nullptr;

    // statistics
    int numSent = 0;
    int numReceived = 0;

    bool printDebug = false;

    //State and data LISTS
    //std::list<std::pair<L3Address, unsigned int>> state_vector;
    //std::list<std::tuple<L3Address, unsigned int, Services>> data_vector;
    std::map<L3Address, std::pair<L3Address, unsigned int>> state_map;
    std::map<L3Address, std::tuple<L3Address, unsigned int, Services>> data_map;
    unsigned int myCounter = 0;

    unsigned int myServiceIDCounter = 0;

    std::map<L3Address, int> forward_sync_check_map;
    std::map<L3Address, int> forward_sync_interest_map;
    std::map<L3Address, int> forward_sync_better_map;

    std::map<L3Address, int> max_saw_sync_check_map;
    std::map<L3Address, int> max_saw_sync_interest_map;
    std::map<L3Address, int> max_saw_sync_better_map;

    int numCheckSent = 0;
    int numCheckReceived = 0;
    int numCheckForwarded = 0;

    int numInterestSent = 0;
    int numInterestReceived = 0;
    int numInterestForwarded = 0;

    int numRequestSent = 0;
    int numRequestReceived = 0;

    int numBetterSent = 0;
    int numBetterReceived = 0;
    int numBetterForwarded = 0;

    std::size_t myHash;

  protected:
    virtual int numInitStages() const override { return NUM_INIT_STAGES; }
    virtual void initialize(int stage) override;
    virtual void handleMessageWhenUp(cMessage *msg) override;
    virtual void finish() override;
    virtual void refreshDisplay() const override;

    // chooses random destination address
    virtual L3Address chooseDestAddr();
    virtual void sendPacket();
    virtual void processPacket(Packet *msg);
    virtual void setSocketOptions();

    virtual void processStart();
    virtual void processSend();
    virtual void processStop();

    virtual void handleStartOperation(LifecycleOperation *operation) override;
    virtual void handleStopOperation(LifecycleOperation *operation) override;
    virtual void handleCrashOperation(LifecycleOperation *operation) override;

    virtual void socketDataArrived(UdpSocket *socket, Packet *packet) override;
    virtual void socketErrorArrived(UdpSocket *socket, Indication *indication) override;
    virtual void socketClosed(UdpSocket *socket) override;

    //tools
    std::string state_vector_string(std::list<std::pair<L3Address, unsigned int>> &sv);
    uint64_t calculate_state_vector_hash();

    bool checkForward(Ptr<const SyncCheckPacket> rcvMsg, L3Address rcdAddr);
    void labelForward(Ptr<const SyncCheckPacket> rcvMsg);
    void forwardSyncCheck(Ptr<const SyncCheckPacket> rcvMsg);

    bool checkInterestForward(Ptr<const SyncInterestPacket> rcvMsg, L3Address rcdAddr);
    void labelInterestForward(Ptr<const SyncInterestPacket> rcvMsg);
    void forwardSyncInterest(Ptr<const SyncInterestPacket> rcvMsg);

    bool checkBetterForward(Ptr<const SyncBetterPacket> rcvMsg, L3Address rcdAddr);
    void labelBetterForward(Ptr<const SyncBetterPacket> rcvMsg);
    void forwardSyncBetter(Ptr<const SyncBetterPacket> rcvMsg);

    //message managers
    void manageSyncMessage(Ptr<const SyncCheckPacket> rcvMsg, L3Address rcdAddr);
    void manageSyncInterestMessage_old(Ptr<const SyncInterestPacket> rcvMsg, L3Address rcdAddr);
    void manageSyncInterestMessage(Ptr<const SyncInterestPacket> rcvMsg, L3Address rcvAddr);
    void manageSyncRequestMessage(Ptr<const SyncRequestPacket> rcvMsg, L3Address rcdAddr);
    void manageSyncBetterMessage(Ptr<const SyncBetterPacket> rcvMsg, L3Address rcdAddr, L3Address destAddr);

    void sendSyncInterestPacket(L3Address dest);
    void sendSyncRequestPacket(L3Address dest, std::list<std::pair<L3Address, unsigned int>> &wl);
    void sendSyncBetterPacket(L3Address dest, std::list<std::tuple<L3Address, unsigned int, Services>> &bl);

    void generateRandomNewService(void);
    void addNewService(Service newService);
    void generateInitNewService(int ns);

    void doSomethingWhenAddService (std::tuple<L3Address, unsigned int, Services> &nt_new, std::tuple<L3Address, unsigned int, Services> &nt_old);

    void execute100ms(void);
    void executeXtimer(void);

public:
    DiscoveryApp() {};
    virtual ~DiscoveryApp();
};

} // namespace inet

#endif /* INET_APPLICATIONS_DISCOVERYAPP_DISCOVERYAPP_H_ */
