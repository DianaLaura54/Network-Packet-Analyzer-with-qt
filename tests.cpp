#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include "PacketTableModel.h"
#include "PacketParser.h"

using ::testing::Return;
using ::testing::_;

// Mocking the Parser to simulate specific network scenarios
class MockPacketParser : public PacketParser {
public:
    MOCK_METHOD(PacketInfo, parse, (const unsigned char* buffer, int size), (override));
};

// Test Case 1: Validate Table Model Row Management
TEST(PacketTableTest, RowAdditionIncrementsCount) {
    PacketTableModel model;
    PacketInfo packet;
    packet.protocol = "TCP";

    EXPECT_EQ(model.rowCount(), 0);
    model.addPacket(packet);
    EXPECT_EQ(model.rowCount(), 1);
}

// Test Case 2: Validate Data Retrieval
TEST(PacketTableTest, RetrievesCorrectData) {
    PacketTableModel model;
    PacketInfo packet;
    packet.source_ip = "127.0.0.1";
    model.addPacket(packet);

    QModelIndex index = model.index(0, 2); // Source IP column
    EXPECT_EQ(model.data(index, Qt::DisplayRole).toString(), "127.0.0.1");
}

// Test Case 3: Mocking a Parser result
TEST(ParserTest, MockedParseReturnsCorrectProtocol) {
    MockPacketParser mock;
    PacketInfo fakePacket;
    fakePacket.protocol = "ICMP";

    EXPECT_CALL(mock, parse(_, _))
        .WillOnce(Return(fakePacket));

    unsigned char dummyBuffer[1];
    PacketInfo result = mock.parse(dummyBuffer, 1);
    EXPECT_EQ(result.protocol, "ICMP");
}

// Entry point for tests
int runTests(int argc, char **argv) {
    ::testing::InitGoogleMock(&argc, argv);
    return RUN_ALL_TESTS();
}