#include "main.h"

// https://wiki.wireshark.org/Development/LibpcapFileFormat
typedef struct wireSharkGlobalHeader {
    uint32_t magic_number; /* magic number */
    uint16_t version_major; /* major version number */
    uint16_t version_minor; /* minor version number */
    int32_t thiszone; /* GMT to local correction */
    uint32_t sigfigs; /* accuracy of timestamps */
    uint32_t snaplen; /* max length of captured packets, in octets */
    uint32_t network; /* data link type */
} wireSharkGlobalHeader_t;

typedef struct pcapRecordHeader {
    uint32_t ts_sec; /* timestamp seconds */
    uint32_t ts_usec; /* timestamp microseconds */
    uint32_t incl_len; /* number of octets of packet saved in file */
    uint32_t orig_len; /* actual length of packet */
} pcapRecordHeader_t;

// http://www.radiotap.org/
typedef struct ieee80211RadiotapHeader {
    uint8_t it_version; /* set to 0 */
    uint8_t it_pad;
    uint16_t it_len; /* entire length */
    uint32_t it_present; /* fields present */
} ieee80211RadiotapHeader_t;

int sniffByWireshark(_i16 channel) {
    HANDLE hPipe = CreateNamedPipe(TEXT("\\\\.\\pipe\\cc3100"), PIPE_ACCESS_OUTBOUND,
    PIPE_TYPE_MESSAGE | PIPE_WAIT, PIPE_UNLIMITED_INSTANCES, 65536, 65536,
    NMPWAIT_USE_DEFAULT_WAIT, NULL);

    if (hPipe == INVALID_HANDLE_VALUE) {
        DEBUG("[ERROR] Failed to create pipe");
        return -1;
    }

    DEBUG("Waiting for connection from WireShark...");
    DEBUG("pipe: \\\\.\\pipe\\cc3100");

    BOOL fConnected = ConnectNamedPipe(hPipe, NULL);

    if (fConnected == 0) {
        DEBUG("[ERROR] Failed to ConnectNamedPipe");
        return -1;
    }
    DEBUG("WireShark connected");

    wireSharkGlobalHeader_t gHeader = {
            .magic_number = 0xA1B2C3d4,
            .version_major = 2,
            .version_minor = 4,
            .thiszone = 0,
            .sigfigs = 0,
            .snaplen = 0x0000FFFF,
            .network = 127,
    };

    LPDWORD byteWritten;
    BOOL result = WriteFile(hPipe, &gHeader, sizeof(gHeader), &byteWritten, NULL);

    if (result == FALSE) {
        DEBUG("[ERROR] Failed to write global header");
        return -1;
    }

    _i16 SockID = sl_Socket(SL_AF_RF, SL_SOCK_RAW, channel);

    if (SockID < 0) {
        DEBUG("Can not create socket: %d", SockID);
        return -1;
    }

    const int BUFFER_SIZE = 1536;
    _u8 buffer[BUFFER_SIZE];
    while (TRUE) {
        _i16 recievedBytes = sl_Recv(SockID, buffer, sizeof(buffer), 0);

        if (recievedBytes < 0) {
            DEBUG("[ERROR] Recv: %d", recievedBytes);
            goto finally;
        }

        SlTransceiverRxOverHead_t * radioHeader = (SlTransceiverRxOverHead_t *) buffer;
        DEBUG("RSSI: %d, channel: %u, RATE: %u", radioHeader->rssi, radioHeader->channel,
                radioHeader->rate);

        const int MICROSECONDS_IN_SECOND = 1000000;
        pcapRecordHeader_t pcapHeader = {
                .ts_sec = radioHeader->timestamp / MICROSECONDS_IN_SECOND,
                .ts_usec = radioHeader->timestamp % MICROSECONDS_IN_SECOND,
                .incl_len = recievedBytes - sizeof(SlTransceiverRxOverHead_t)
                        + sizeof(ieee80211RadiotapHeader_t),
                .orig_len = recievedBytes - sizeof(SlTransceiverRxOverHead_t)
                        + sizeof(ieee80211RadiotapHeader_t),
        };
        result = WriteFile(hPipe, &pcapHeader, sizeof(pcapHeader), &byteWritten, NULL);
        if (result == FALSE) {
            DEBUG("[ERROR] Failed to write pcapRecordHeader_t");
            goto finally;
        }

        ieee80211RadiotapHeader_t radiotapHeader = {
                .it_version = 0,
                .it_len = sizeof(ieee80211RadiotapHeader_t),
        };
        result = WriteFile(hPipe, &radiotapHeader, sizeof(radiotapHeader), &byteWritten, NULL);
        if (result == FALSE) {
            DEBUG("[ERROR] Failed to write pcapRecordHeader_t");
            goto finally;
        }

        result = WriteFile(hPipe, &(buffer[sizeof(SlTransceiverRxOverHead_t)]),
                recievedBytes - sizeof(SlTransceiverRxOverHead_t), &byteWritten, NULL);

        if (result == FALSE) {
            DEBUG("[ERROR] Failed to write buffer");
            goto finally;
        }
    }

    _i16 retVal;
finally:
    retVal = sl_Close(SockID);
    if (retVal < 0) {
        DEBUG("[ERROR]sl_Close: %d", retVal);
        return -1;
    }
    return 0;
}
