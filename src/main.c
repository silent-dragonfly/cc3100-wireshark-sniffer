#include <assert.h>
#include <stdint.h>

#include <simplelink.h>

#include "helpers.h"
#include "sl_common.h"

#define Delay(X) Sleep(X)
#define MAX_PACKET_SIZE (1472)

#define APPLICATION_VERSION "1.3.0"

#define SL_STOP_TIMEOUT        0xFF

/* Power level tone valid range 0-15 */
#define POWER_LEVEL_TONE    1
/* Preamble value 0- short, 1- long */
#define PREAMBLE            1

#define RATE                RATE_11M

/* Channel (1-13) used during the tx and rx*/
#define CHANNEL             10

#define BUF_SIZE 1400
#define NO_OF_PACKETS 100

/* Application specific status/error codes */
typedef enum {
	DEVICE_NOT_IN_STATION_MODE = -0x7D0, /* Choosing this number to avoid overlap w/ host-driver's error codes */

	STATUS_CODE_MAX = -0xBB8
} e_AppStatusCodes;

// https://wiki.wireshark.org/Development/LibpcapFileFormat

typedef struct wireSharkGlobalHeader_t {
	uint32_t magic_number; /* magic number */
	uint16_t version_major; /* major version number */
	uint16_t version_minor; /* minor version number */
	int32_t thiszone; /* GMT to local correction */
	uint32_t sigfigs; /* accuracy of timestamps */
	uint32_t snaplen; /* max length of captured packets, in octets */
	uint32_t network; /* data link type */
} wireSharkGlobalHeader_t;

typedef struct pcaprec_hdr_s {
        uint32_t ts_sec;         /* timestamp seconds */
        uint32_t ts_usec;        /* timestamp microseconds */
        uint32_t incl_len;       /* number of octets of packet saved in file */
        uint32_t orig_len;       /* actual length of packet */
} pcaprec_hdr_t;

// http://www.radiotap.org/
typedef struct ieee80211_radiotap_header {
	uint8_t it_version; /* set to 0 */
	uint8_t it_pad;
	uint16_t it_len; /* entire length */
	uint32_t it_present; /* fields present */
} ieee80211_radiotap_header;

_u8 g_Status = 0;

static _i32 configureSimpleLinkToDefaultState();
static void Sniffer(_i16 channel);

/*
 * ASYNCHRONOUS EVENT HANDLERS -- Start
 */
void SimpleLinkWlanEventHandler(SlWlanEvent_t *pWlanEvent) {
	if (pWlanEvent == NULL) {
		DEBUG("[WLAN EVENT] NULL Pointer Error");
		return;
	}

	switch (pWlanEvent->Event) {
	case SL_WLAN_CONNECT_EVENT: {
		SET_STATUS_BIT(g_Status, STATUS_BIT_CONNECTION);

		/*
		 * Information about the connected AP (like name, MAC etc) will be
		 * available in 'slWlanConnectAsyncResponse_t' - Applications
		 * can use it if required
		 *
		 * slWlanConnectAsyncResponse_t *pEventData = NULL;
		 * pEventData = &pWlanEvent->EventData.STAandP2PModeWlanConnected;
		 *
		 */
	}
		break;

	case SL_WLAN_DISCONNECT_EVENT: {
		slWlanConnectAsyncResponse_t* pEventData = NULL;

		CLR_STATUS_BIT(g_Status, STATUS_BIT_CONNECTION);

		pEventData = &pWlanEvent->EventData.STAandP2PModeDisconnected;

		/* If the user has initiated 'Disconnect' request, 'reason_code' is
		 * SL_USER_INITIATED_DISCONNECTION */
		if (SL_WLAN_DISCONNECT_USER_INITIATED_DISCONNECTION
				== pEventData->reason_code) {
			DEBUG("Device disconnected from the AP on application's request");
		} else {
			DEBUG("Device disconnected from the AP on an ERROR..!!");
		}
	}
		break;

	default: {
		DEBUG("[WLAN EVENT] Unexpected event");
	}
		break;
	}
}

void SimpleLinkNetAppEventHandler(SlNetAppEvent_t *pNetAppEvent) {
	if (pNetAppEvent == NULL) {
		DEBUG("[NETAPP EVENT] NULL Pointer Error");
		return;
	}

	switch (pNetAppEvent->Event) {
	case SL_NETAPP_IPV4_IPACQUIRED_EVENT: {
		SET_STATUS_BIT(g_Status, STATUS_BIT_IP_ACQUIRED);

		/*
		 * Information about the connection (like IP, gateway address etc)
		 * will be available in 'SlIpV4AcquiredAsync_t'
		 * Applications can use it if required
		 *
		 * SlIpV4AcquiredAsync_t *pEventData = NULL;
		 * pEventData = &pNetAppEvent->EventData.ipAcquiredV4;
		 *
		 */
	}
		break;

	default: {
		DEBUG("[NETAPP EVENT] Unexpected event");
	}
		break;
	}
}

void SimpleLinkHttpServerCallback(SlHttpServerEvent_t *pHttpEvent,
		SlHttpServerResponse_t *pHttpResponse) {
	/* Unused in this application */
	DEBUG("[HTTP EVENT] Unexpected event");
}

void SimpleLinkGeneralEventHandler(SlDeviceEvent_t *pDevEvent) {
	/*
	 * Most of the general errors are not FATAL are are to be handled
	 * appropriately by the application
	 */
	DEBUG("[GENERAL EVENT]");
}

void SimpleLinkSockEventHandler(SlSockEvent_t *pSock) {
	if (pSock == NULL) {
		DEBUG("[SOCK EVENT] NULL Pointer Error");
		return;
	}

	switch (pSock->Event) {
	case SL_SOCKET_TX_FAILED_EVENT:
		/*
		 * TX Failed
		 *
		 * Information about the socket descriptor and status will be
		 * available in 'SlSockEventData_t' - Applications can use it if
		 * required
		 *
		 * SlSockEventData_u *pEventData = NULL;
		 * pEventData = & pSock->socketAsyncEvent;
		 */
		switch (pSock->socketAsyncEvent.SockTxFailData.status) {
		case SL_ECLOSE:
			DEBUG(
					"[SOCK EVENT] Close socket operation failed to transmit all queued packets");
			break;
		default:
			DEBUG("[SOCK EVENT] Unexpected event");
			break;
		}
		break;

	default:
		DEBUG("[SOCK EVENT] Unexpected event");
		break;
	}
}
/*
 * ASYNCHRONOUS EVENT HANDLERS -- End
 */

/*
 * Application's entry point
 */
int main(int argc, char** argv) {
	_i32 retVal = -1;

	/*
	 * Following function configures the device to default state by cleaning
	 * the persistent settings stored in NVMEM (viz. connection profiles &
	 * policies, power policy etc)
	 *
	 * Applications may choose to skip this step if the developer is sure
	 * that the device is in its default state at start of application
	 *
	 * Note that all profiles and persistent settings that were done on the
	 * device will be lost
	 */
	retVal = configureSimpleLinkToDefaultState();
	if (retVal < 0) {
		DEBUG(" Failed to configure the device in its default state");
		return -1;
	}

	DEBUG(" Device is configured in default state");

	/*
	 * Assumption is that the device is configured in station mode already
	 * and it is in its default state
	 */
	retVal = sl_Start(0, 0, 0);
	if ((retVal < 0) || (ROLE_STA != retVal)) {
		DEBUG(" Failed to start the device");
		return -1;
	}

	DEBUG("Device started as STATION");

	/* Remove any connection policies for working in transceiver mode */
	retVal = sl_WlanPolicySet(SL_POLICY_CONNECTION,
			SL_CONNECTION_POLICY(0, 0, 0, 0, 0), NULL, 0);
	ASSERT_ON_ERROR(retVal);
	DEBUG("Connection policies are cleared");

	DEBUG("Start Sniffer function");

	Sniffer(CHANNEL);

	return 0;
}

static _i32 configureSimpleLinkToDefaultState() {
	SlVersionFull ver = { 0 };
	_WlanRxFilterOperationCommandBuff_t RxFilterIdMask = { 0 };

	_u8 val = 1;
	_u8 configOpt = 0;
	_u8 configLen = 0;
	_u8 power = 0;

	_i32 retVal = -1;
	_i32 mode = -1;

	mode = sl_Start(0, 0, 0);
	ASSERT_ON_ERROR(mode);

	/* If the device is not in station-mode, try configuring it in station-mode */
	if (ROLE_STA != mode) {
		if (ROLE_AP == mode) {
			/* If the device is in AP mode, we need to wait for this event before doing anything */
			while (!IS_IP_ACQUIRED(g_Status)) {
				Delay(100);
			}
		}

		/* Switch to STA role and restart */
		retVal = sl_WlanSetMode(ROLE_STA);
		ASSERT_ON_ERROR(retVal);

		retVal = sl_Stop(SL_STOP_TIMEOUT);
		ASSERT_ON_ERROR(retVal);

		retVal = sl_Start(0, 0, 0);
		ASSERT_ON_ERROR(retVal);

		/* Check if the device is in station again */
		if (ROLE_STA != retVal) {
			/* We don't want to proceed if the device is not coming up in station-mode */
			ASSERT_ON_ERROR(DEVICE_NOT_IN_STATION_MODE);
		}
	}

	/* Get the device's version-information */
	configOpt = SL_DEVICE_GENERAL_VERSION;
	configLen = sizeof(ver);
	retVal = sl_DevGet(SL_DEVICE_GENERAL_CONFIGURATION, &configOpt, &configLen,
			(_u8 *) (&ver));
	ASSERT_ON_ERROR(retVal);

	/* Set connection policy to Auto + SmartConfig (Device's default connection policy) */
	retVal = sl_WlanPolicySet(SL_POLICY_CONNECTION,
			SL_CONNECTION_POLICY(1, 0, 0, 0, 1), NULL, 0);
	ASSERT_ON_ERROR(retVal);

	/* Remove all profiles */
	retVal = sl_WlanProfileDel(0xFF);
	ASSERT_ON_ERROR(retVal);

	/*
	 * Device in station-mode. Disconnect previous connection if any
	 * The function returns 0 if 'Disconnected done', negative number if already disconnected
	 * Wait for 'disconnection' event if 0 is returned, Ignore other return-codes
	 */
	retVal = sl_WlanDisconnect();
	if (0 == retVal) {
		/* Wait */
		while (IS_CONNECTED(g_Status)) {
			Delay(100);
		}
	}

	/* Enable DHCP client*/
	retVal = sl_NetCfgSet(SL_IPV4_STA_P2P_CL_DHCP_ENABLE, 1, 1, &val);
	ASSERT_ON_ERROR(retVal);

	/* Disable scan */
	configOpt = SL_SCAN_POLICY(0);
	retVal = sl_WlanPolicySet(SL_POLICY_SCAN, configOpt, NULL, 0);
	ASSERT_ON_ERROR(retVal);

	/* Set Tx power level for station mode
	 Number between 0-15, as dB offset from max power - 0 will set maximum power */
	power = 0;
	retVal = sl_WlanSet(SL_WLAN_CFG_GENERAL_PARAM_ID,
	WLAN_GENERAL_PARAM_OPT_STA_TX_POWER, 1, (_u8 *) &power);
	ASSERT_ON_ERROR(retVal);

	/* Set PM policy to normal */
	retVal = sl_WlanPolicySet(SL_POLICY_PM, SL_NORMAL_POLICY, NULL, 0);
	ASSERT_ON_ERROR(retVal);

	/* Unregister mDNS services */
	retVal = sl_NetAppMDNSUnRegisterService(0, 0);
	ASSERT_ON_ERROR(retVal);

	/* Remove  all 64 filters (8*8) */
	pal_Memset(RxFilterIdMask.FilterIdMask, 0xFF, 8);
	retVal = sl_WlanRxFilterSet(SL_REMOVE_RX_FILTER, (_u8 *) &RxFilterIdMask,
			sizeof(_WlanRxFilterOperationCommandBuff_t));
	ASSERT_ON_ERROR(retVal);

	retVal = sl_Stop(SL_STOP_TIMEOUT);
	ASSERT_ON_ERROR(retVal);

	return retVal; /* Success */
}

void Sniffer(_i16 channel) {
	HANDLE hPipe = CreateNamedPipe(TEXT("\\\\.\\pipe\\cc3100"),
	PIPE_ACCESS_OUTBOUND,
	PIPE_TYPE_MESSAGE | PIPE_WAIT,
	PIPE_UNLIMITED_INSTANCES, 65536, 65536,
	NMPWAIT_USE_DEFAULT_WAIT,
	NULL);

	if (hPipe == INVALID_HANDLE_VALUE) {
		DEBUG("[ERROR] Failed to create pipe");
		exit(-1);
	}

	DEBUG("Waiting for connection from WireShark...");
	DEBUG("pipe: \\\\.\\pipe\\cc3100");

	BOOL fConnected = ConnectNamedPipe(hPipe, NULL);

	if (fConnected == 0) {
		DEBUG("[ERROR] Failed to ConnectNamedPipe");
		exit(-1);
	}
	DEBUG("WireShark connected");

	wireSharkGlobalHeader_t gHeader = { .magic_number = 0xA1B2C3d4,
			.version_major = 2, .version_minor = 4, .thiszone = 0, .sigfigs = 0,
			.snaplen = 0x0000FFFF, .network = 127, };

	LPDWORD byteWritten;
	BOOL result = WriteFile(hPipe, &gHeader, sizeof(gHeader), &byteWritten,
	NULL);

	if (result == FALSE) {
		DEBUG("[ERROR] Failed to write global header");
		exit(-1);
	}

	_i16 SockID = sl_Socket(SL_AF_RF, SL_SOCK_RAW, channel);

	if (SockID < 0) {
		DEBUG("Can not create socket: %d", SockID);
		exit(-1);
	}

	const int BUFFER_SIZE = 1536;
	_u8 buffer[BUFFER_SIZE];
	_i16 recievedBytes;
	SlTransceiverRxOverHead_t *radioHeader;
	ieee80211_radiotap_header frame = { .it_version = 0, .it_len =
			sizeof(ieee80211_radiotap_header), };

	while (TRUE) {
		recievedBytes = sl_Recv(SockID, buffer, sizeof(buffer), 0);

		if (recievedBytes < 0) {
			DEBUG("[ERROR] Recv: %d", recievedBytes);
			exit(-1);
		}

		radioHeader = (SlTransceiverRxOverHead_t *) buffer;

		pcaprec_hdr_t pcapHeader = {
			.ts_sec = 0,
			.ts_usec = 0,
			.incl_len = recievedBytes - sizeof(SlTransceiverRxOverHead_t) + sizeof(frame),
			.orig_len = recievedBytes - sizeof(SlTransceiverRxOverHead_t) + sizeof(frame)
		};

		result = WriteFile(hPipe, &pcapHeader, sizeof(pcapHeader), &byteWritten, NULL);
		if (result == FALSE) {
			DEBUG("[ERROR] Failed to write pcapHeader");
			exit(-1);
		}


		result = WriteFile(hPipe, &frame, sizeof(frame), &byteWritten, NULL);
		if (result == FALSE) {
			DEBUG("[ERROR] Failed to write ieee80211_radiotap_header");
			exit(-1);
		}

		result = WriteFile(hPipe, &(buffer[sizeof(SlTransceiverRxOverHead_t)]),
				recievedBytes - sizeof(SlTransceiverRxOverHead_t), &byteWritten,
				NULL);

		if (result == FALSE) {
			DEBUG("[ERROR] Failed to write buffer");
			exit(-1);
		}
	}
	sl_Close(SockID);
}

/*!
 \brief Entering raw Transmitter\Receiver mode in order to send raw data
 over the WLAN PHY

 This function shows how to send raw data, in this case ping packets over
 the air in transmitter mode.

 \param[in]      Channel number on which the data will be sent

 \return         0 on success, Negative on Error.

 \note

 \warning        We must be disconnected from WLAN AP in order to succeed
 changing to transmitter mode
 */
//static _i32 RxEvaluation(_i16 channel) {
//	_i16 SockID = 0;
//	_i32 Status = 0;
//	_u16 Len = 0;
//	_i16 count = 0;
//
//	/*
//	 * Disconnect previous connection if any
//	 * The function returns 0 if 'Disconnected done', negative number if already disconnected
//	 * Wait for 'disconnection' event if 0 is returned, Ignore other return-codes
//	 */
//	Status = sl_WlanDisconnect();
//	if (0 == Status) {
//		/* Wait */
//		while (IS_CONNECTED(g_Status)) {
//			Delay(300);
//		}
//	}
//
//	/* make sure device is disconnected & auto mode is off */
//	SockID = sl_Socket(SL_AF_RF, SL_SOCK_RAW, channel);
//	ASSERT_ON_ERROR(SockID);
//
////    Changing rate is not affect for receiving
////    _u32 rate = RATE;
////    Status = sl_SetSockOpt(SockID, SL_SOL_PHY_OPT, SL_SO_PHY_RATE, &rate, sizeof(rate));
////    assert(Status == 0);
//
//	_u32 preamble = PREAMBLE;
//	Status = sl_SetSockOpt(SockID, SL_SOL_PHY_OPT, SL_SO_PHY_PREAMBLE,
//			&preamble, sizeof(preamble));
//	assert(Status == 0);
//
//	Len = sizeof(RawData_Ping);
//
//	_u8 buffer[MAX_PACKET_SIZE];
//
//	SlTransceiverRxOverHead_t *rxHeader = buffer;
//	FrameControl *fc = buffer + sizeof(SlTransceiverRxOverHead_t);
//
//	while (TRUE) {
//		Status = sl_Recv(SockID, buffer, MAX_PACKET_SIZE, 0);
//
//		if (Status < 0) {
//			DEBUG("Broken socket. Exiting...");
//			sl_Close(SockID);
//			return -1;
//		}
//
//		if (fc->ProtocolVersion != 0) {
//			DEBUG("[MAGIC] Protocol version is not a zero!!!!!!!!");
//			continue;
//		}
//
//		if (fc->Type != TYPE_DATA) {
//			continue;
//		}
//
//		if (fc->Subtype != DATA_SUBTYPE_QOS) {
//			continue;
//		}
//
//		if (memcmp(&(RawData_Ping[DEST_MAC_OFFSET]),
//				&(buffer[sizeof(SlTransceiverRxOverHead_t) + DEST_MAC_OFFSET]),
//				6) != 0) {
//			continue;
//		}
//
//		DEBUG("[%lu]Recv: %d bytes; ch %u; rate: %u; rssi %d",
//				rxHeader->timestamp, Status, rxHeader->channel, rxHeader->rate,
//				rxHeader->rssi);
//
//	}
//
//	Status = sl_Close(SockID);
//	ASSERT_ON_ERROR(Status);
//
//	return SUCCESS;
//}
