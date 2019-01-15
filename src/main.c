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
    DEBUG("Start sniffing");

    const _i16 channel = 10; // 1-13
    retVal = sniffByWireshark(channel);
    if (retVal < 0) {
        DEBUG("ERROR:sniffByWireshark");
        return -1;
    }
    return 0;
}
