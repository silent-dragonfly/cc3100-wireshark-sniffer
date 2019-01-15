#define __MAIN_C__
#include "main.h"

int main(int argc, char** argv) {
    _i32 retVal = -1;

    retVal = configureSimpleLinkToDefaultState();
    if (retVal < 0) {
        DEBUG(" Failed to configure the device in its default state");
        return -1;
    }
    DEBUG(" Device is configured in default state");

    retVal = sl_Start(0, 0, 0);
    if ((retVal < 0) || (ROLE_STA != retVal)) {
        DEBUG(" Failed to start the device");
        return -1;
    }

    DEBUG("Device started as STATION");

    retVal = sl_WlanPolicySet(SL_POLICY_SCAN, SL_SCAN_POLICY(0), NULL, 0); // disable scan procedure

    if (retVal < 0) {
        DEBUG("[ERROR] Failed to disable SL_POLICY_SCAN");
        system("PAUSE");
        return -1;
    }
    DEBUG("Default Active Scan is disabled");

    retVal = sl_WlanPolicySet(SL_POLICY_CONNECTION,
            SL_CONNECTION_POLICY(0, 0, 0, 0, 0), NULL, 0);

    if (retVal < 0) {
        DEBUG("[ERROR] Failed to clear WLAN_CONNECTION_POLICY");
        system("PAUSE");
        return -1;
    }

    retVal = sl_WlanDisconnect();

    if (retVal == 0) {
        DEBUG("Disconnected from AP");
    } else {
        // already disconnected
    }
    DEBUG("Connection policy is cleared and CC3100 has been disconnected");

    retVal = addBeaconRxFilter();
    if (retVal < 0) {
        DEBUG("ERROR:addBeaconRxFilter: %d", retVal);
        return -1;
    }
    DEBUG("Beacon RXFilter are set");

    {
        printf("\n## Rx Filters (sl_WlanRxFilterGet)\n");

        _WlanRxFilterRetrieveEnableStatusCommandResponseBuff_t buf;
        _i16 retVal = sl_WlanRxFilterGet(SL_FILTER_RETRIEVE_ENABLE_STATE, &buf,
                sizeof(buf));
        if (retVal < 0) {
            DEBUG("Failed sl_WlanRxFilterGet: %d", retVal);
            return -1;
        }

        printf("Enabled Filters: \n");
        printf("\t%08X\n", ((_u32*) &buf.FilterIdMask)[0]);
        printf("\t%08X\n", ((_u32*) &buf.FilterIdMask)[1]);
        printf("\t%08X\n", ((_u32*) &buf.FilterIdMask)[2]);
        printf("\t%08X\n", ((_u32*) &buf.FilterIdMask)[3]);
    }

    DEBUG("Starting sniffing");
    const _i16 channel = 10; // 1-13
    retVal = sniffByWireshark(channel);
    if (retVal < 0) {
        DEBUG("ERROR:sniffByWireshark: %d", retVal);
        return -1;
    }
    return 0;
}
