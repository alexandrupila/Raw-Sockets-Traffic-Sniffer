struct dnshdr
	{
		/** DNS query identification */
		uint16_t transactionID;
#if (BYTE_ORDER == LITTLE_ENDIAN)
		uint16_t
		/** Recursion desired flag */
			recursionDesired:1,
		/** Truncated flag */
			truncation:1,
		/** Authoritative answer flag */
			authoritativeAnswer:1,
		/** Operation Code */
			opcode:4,
		/** Query/Response flag */
			queryOrResponse:1,
		/** Return Code */
			responseCode:4,
		/** Checking disabled flag */
			checkingDisabled:1,
		/** Authenticated data flag */
			authenticData:1,
		/** Zero flag (Reserved) */
			zero:1,
		/** Recursion available flag */
			recursionAvailable:1;
#elif (BYTE_ORDER == BIG_ENDIAN)
		uint16_t
		/** Query/Response flag */
			queryOrResponse:1,
		/** Operation Code */
			opcode:4,
		/** Authoritative answer flag */
			authoritativeAnswer:1,
		/** Truncated flag */
			truncation:1,
		/** Recursion desired flag */
			recursionDesired:1,
		/** Recursion available flag */
			recursionAvailable:1,
		/** Zero flag (Reserved) */
			zero:1,
		/** Authenticated data flag */
			authenticData:1,
		/** Checking disabled flag */
			checkingDisabled:1,
		/** Return Code */
			responseCode:4;
#endif
		/** Number of DNS query records in packet */
		uint16_t numberOfQuestions;
		/** Number of DNS answer records in packet */
		uint16_t numberOfAnswers;
		/** Number of authority records in packet */
		uint16_t numberOfAuthority;
		/** Number of additional records in packet */
		uint16_t numberOfAdditional;
	};

struct arphdr
	{
		/** Hardware type (HTYPE) */
		uint16_t hardwareType;
		/** Protocol type (PTYPE). The permitted PTYPE values share a numbering space with those for EtherType */
		uint16_t protocolType;
		/** Hardware address length (HLEN). For IPv4, this has the value 0x0800 */
		uint8_t	hardwareSize;
		/** Protocol length (PLEN). Length (in octets) of addresses used in the upper layer protocol. (The upper layer protocol specified in PTYPE.) IPv4 address size is 4 */
		uint8_t	protocolSize;
		/** Specifies the operation that the sender is performing: 1 (::ARP_REQUEST) for request, 2 (::ARP_REPLY) for reply */
		uint16_t opcode;
		/** Sender hardware address (SHA) */
		uint8_t senderMacAddr[6];
		/** Sender protocol address (SPA) */
		uint32_t senderIpAddr;
		/** Target hardware address (THA) */
		uint8_t targetMacAddr[6];
		/** Target protocol address (TPA) */
		uint32_t targetIpAddr;
	};

struct igmp_header
{
	/** Indicates the message type. The enum for message type is pcpp::IgmpType */
	uint8_t type;
	/** Specifies the time limit for the corresponding report. The field has a resolution of 100 milliseconds */
	uint8_t maxResponseTime;
	/** This is the 16-bit one's complement of the one's complement sum of the entire IGMP message */
	uint16_t checksum;
	/** This is the multicast address being queried when sending a Group-Specific or Group-and-Source-Specific Query */
	uint32_t groupAddress;
};


/**
 * @struct igmpv3_query_header
 * IGMPv3 membership query basic header
 */
struct igmpv3_query_header
{
	/** IGMP message type. Should always have value of membership query (::IgmpType_MembershipQuery)  */
	uint8_t type;
	/** This field specifies the maximum time (in 1/10 second) allowed before sending a responding report */
	uint8_t maxResponseTime;
	/** This is the 16-bit one's complement of the one's complement sum of the entire IGMP message */
	uint16_t checksum;
	/** This is the multicast address being queried when sending a Group-Specific or Group-and-Source-Specific Query */
	uint32_t groupAddress;
	/** Suppress Router-side Processing Flag + Querier's Robustness Variable */
	uint8_t s_qrv;
	/** Querier's Query Interval Code */
	uint8_t qqic;
	/** This field specifies the number of source addresses present in the Query */
	uint16_t numOfSources;
};


/**
 * @struct igmpv3_report_header
 * IGMPv3 membership report basic header
 */
struct igmpv3_report_header
{
	/** IGMP message type. Should always have value of IGMPv3 membership report (::IgmpType_MembershipReportV3)  */
	uint8_t type;
	/** Unused byte */
	uint8_t reserved1;
	/** This is the 16-bit one's complement of the one's complement sum of the entire IGMP message */
	uint16_t checksum;
	/** Unused bytes */
	uint16_t reserved2;
	/** This field specifies the number of group records present in the Report */
	uint16_t numOfGroupRecords;
};


/**
 * @struct igmpv3_group_record
 * A block of fields containing information pertaining to the sender's membership in a single multicast group on the interface
 * from which the Report is sent. Relevant only for IGMPv3 membership report messages
 */
struct igmpv3_group_record
{
	/** Group record type */
	uint8_t recordType;
	/** Contains the length of the Auxiliary Data field in this Group Record. A value other than 0 isn't supported */
	uint8_t auxDataLen;
	/** Specifies how many source addresses are present in this Group Record */
	uint16_t numOfSources;
	/** Contains the IP multicast address to which this Group Record pertains */
	uint32_t multicastAddress;
	/** A vector of n IP unicast addresses, where n is the value in this record's Number of Sources field */
	uint8_t sourceAddresses[];
};


/**
 * IGMP message types
 */
enum IgmpType
{
	/** Unknown message type */
	IgmpType_Unknown = 0,
	/** IGMP Membership Query */
	IgmpType_MembershipQuery = 0x11,
	/** IGMPv1 Membership Report */
	IgmpType_MembershipReportV1 = 0x12,
	/** DVMRP */
	IgmpType_DVMRP = 0x13,
	/** PIM version 1 */
	IgmpType_P1Mv1 = 0x14,
	/** Cisco Trace Messages */
	IgmpType_CiscoTrace = 0x15,
	/** IGMPv2 Membership Report */
	IgmpType_MembershipReportV2 = 0x16,
	/** IGMPv2 Leave Group */
	IgmpType_LeaveGroup = 0x17,
	/** Multicast Traceroute Response */
	IgmpType_MulticastTracerouteResponse = 0x1e,
	/** Multicast Traceroute */
	IgmpType_MulticastTraceroute = 0x1f,
	/** IGMPv3 Membership Report */
	IgmpType_MembershipReportV3 = 0x22,
	/** MRD, Multicast Router Advertisement */
	IgmpType_MulticastRouterAdvertisement = 0x30,
	/** MRD, Multicast Router Solicitation */
	IgmpType_MulticastRouterSolicitation = 0x31,
	/** MRD, Multicast Router Termination */
	IgmpType_MulticastRouterTermination = 0x32,
};
