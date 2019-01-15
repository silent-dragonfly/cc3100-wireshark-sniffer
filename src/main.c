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
    DEBUG("Beacon RXFilter added");

    retVal = enableBeaconRxFilter();
    if (retVal < 0) {
        DEBUG("ERROR:switchBeaconRxFilter: %d", retVal);
        return -1;
    }
    DEBUG("Filters are successfully enabled");

    retVal = printRxFilterMask();
    if (retVal < 0) {
        DEBUG("ERROR:printRxFilterMask: %d", retVal);
        return -1;
    }

    // Check in wireshark that there is only Beacon frames
    DEBUG("Starting sniffing");
    const _i16 channel = 10; // 1-13
    sniffByWireshark(channel);

    // restart tested here - helped

    retVal = disableBeaconRxFilter();
    if (retVal < 0) {
        DEBUG("ERROR:switchBeaconRxFilter: %d", retVal);
        return -1;
    }
    DEBUG("Filters are successfully disabled");

    retVal = printRxFilterMask();
    if (retVal < 0) {
        DEBUG("ERROR:printRxFilterMask: %d", retVal);
        return -1;
    }

    // restart tested here - helped
    retVal = sl_Stop(SL_STOP_TIMEOUT);
    ASSERT_ON_ERROR(retVal);
    retVal = sl_Start(0, 0, 0);
    if ((retVal < 0) || (ROLE_STA != retVal)) {
        DEBUG(" Failed to start the device");
        return -1;
    }
    DEBUG("Device re-started as STATION");

    // Check in wireshark that now we are capturing the
    sniffByWireshark(channel);

    return 0;
}
