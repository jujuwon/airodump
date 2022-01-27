#pragma once

#include<stdint.h>
#include "mac.h"


struct RadiotapHdr {
    uint8_t revision_;
    uint8_t pad_;
    uint16_t len_;
    // present
};

struct RadiotapData
{
    uint8_t flag_;
    uint8_t dataRate_;
    uint16_t chFreq_;
    uint16_t chFlag_;
    int8_t signal_;
};


struct Dot11Hdr {
    uint8_t ver_:2;
    uint8_t type_:2;
    uint16_t subtype_:4;
    uint8_t flags_;
    uint16_t duration_;

    uint8_t typeSubtype() { return type_ << 4 | subtype_; }

    enum TypeSubtype : uint8_t {
		//
		// Management Frame
		//
		AssociationRequest = 0x00,
		AssociationResponse = 0x01,
		ReassociationRequest = 0x02,
		ReassociationResponse = 0x03,
		ProbeRequest = 0x04,
		ProbeResponse = 0x05,
		TimingAdvertisement = 0x06,
		Reserved = 0x07,
		Beacon = 0x08,
		Atim = 0x09,
		Disassociation = 0x0A,
		Authentication = 0x0B,
		Deauthentication = 0x0C,
		Action = 0x0D,
		ActionNoAck = 0x0E,
		// Reserved = 0x0F,

		//
		// Control Frame
		//
		// Reserved = 0x10,
		// Reserved = 0x11,
		Trigger = 0x12,
		Tack = 0x13,
		BeamformingReportPoll = 0x14,
		VhtHeNdpAnnouncement = 0x15,
		ControlFrameExtension = 0x16,
		ControlWrapper = 0x17,
		BlockAckRequest = 0x18,
		BlockAck = 0x19,
		PsPoll = 0x1A,
		Rts = 0x1B,
		Cts = 0x1C,
		Ack = 0x1D,
		CfEnd = 0x1E,
		CfEndCfACK = 0x1F,

		//
		// Data Frame
		//
		Data = 0x20,
		// Reserved = 0x21,
		// Reserved = 0x22,
		// Reserved = 0x23,
		Null = 0x24,
		// Reserved = 0x25,
		// Reserved = 0x26,
		// Reserved = 0x27,
		QoSData = 0x28,
		QoSDataCfACK = 0x29,
		QoSDataCfPoll = 0x2A,
		QoSDataCfACKCfPoll = 0x2B,
		QoSNull = 0x2C,
		// Reserved = 0x2D,
		QoSCfPoll = 0x2E,
		QoSCfACKCfPoll = 0x2F,

		//
		// Extension Frame
		//
		DmgBeacon = 0x30,
		S1gBeacon = 0x31
	};
};

struct Dot11ExtHdr : Dot11Hdr {
    Mac addr1_;
    Mac addr2_;
    Mac addr3_;
    uint16_t nums_;
};

struct BeaconHdr : Dot11ExtHdr {
    struct Fix {
        uint64_t timestamp_;
        uint16_t interval_;
        uint16_t info_;
    };

    struct Tag {
        uint8_t num_;
        uint8_t len_;

        void* value() {
            return (char*)this + sizeof(Tag);
        }

        Tag* next() {
            char* res = (char*)this;
            res += sizeof(Tag) + this->len_;
            return (Tag*)res;
        }
    };

    Tag* getTag() {
        char *p = (char*)this;
        p += sizeof(BeaconHdr);
        return (Tag*)p;
    }
};
