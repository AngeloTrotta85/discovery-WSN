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

#include "SyncCheckPacket_m.h"
#include "SyncInterestPacket_m.h"

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
    ~Services() {};

    std::list<Service> list_services;
};

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

    // state
    UdpSocket socket;
    ClockEvent *selfMsg = nullptr;

    // statistics
    int numSent = 0;
    int numReceived = 0;

    //State and data LISTS
    std::list<std::pair<unsigned int, unsigned int>> state_vector;
    std::list<std::tuple<unsigned int, unsigned int, Services>> data_vector;
    unsigned int myCounter = 0;
    Ipv4Address myIPAddress;

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
    std::string state_vector_string();
    uint64_t calculate_state_vector_hash();

    //message managers
    void manageSyncMessage(Ptr<const SyncCheckPacket> rcvMsg, L3Address rcdAddr);
    void manageSyncInterestMessage(Ptr<const SyncInterestPacket> rcvMsg, L3Address rcdAddr);

public:
    DiscoveryApp() {};
    virtual ~DiscoveryApp();
};

} // namespace inet

#endif /* INET_APPLICATIONS_DISCOVERYAPP_DISCOVERYAPP_H_ */
