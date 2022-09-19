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
    os << "}";
    for (auto& s : ss.list_services){
        os << "[" << s.id << "]-(" << s.description << ") ";
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

    // state
    UdpSocket socket;
    ClockEvent *selfMsg = nullptr;

    // statistics
    int numSent = 0;
    int numReceived = 0;

    //State and data LISTS
    //std::list<std::pair<L3Address, unsigned int>> state_vector;
    //std::list<std::tuple<L3Address, unsigned int, Services>> data_vector;
    std::map<L3Address, std::pair<L3Address, unsigned int>> state_map;
    std::map<L3Address, std::tuple<L3Address, unsigned int, Services>> data_map;
    unsigned int myCounter = 0;
    Ipv4Address myIPAddress;

    std::map<L3Address, int> forward_sync_check_map;
    std::map<L3Address, int> forward_sync_interest_map;

    int numInterestSent = 0;
    int numInterestReceived = 0;

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

    //message managers
    void manageSyncMessage(Ptr<const SyncCheckPacket> rcvMsg, L3Address rcdAddr);
    void manageSyncInterestMessage(Ptr<const SyncInterestPacket> rcvMsg, L3Address rcdAddr);
    void manageSyncRequestMessage(Ptr<const SyncRequestPacket> rcvMsg, L3Address rcdAddr);

    void sendSyncInterestPacket(L3Address dest);

    void generateRandomNewService(void);
    void addNewService(Service newService);

public:
    DiscoveryApp() {};
    virtual ~DiscoveryApp();
};

} // namespace inet

#endif /* INET_APPLICATIONS_DISCOVERYAPP_DISCOVERYAPP_H_ */
