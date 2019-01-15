#include "main.h"

typedef enum IEEE80211_Types_e {
    TYPE_MANAGEMENT = 0,
    TYPE_CONTROL = 1,
    TYPE_DATA = 2
} IEEE80211_Types_e;

typedef enum IEEE80211_MgmSubtypes_e {
    MGM_SUBTYPE_ASSOC_REQ = 0x00,
    MGM_SUBTYPE_ASSOC_RES = 0x10,
    MGM_SUBTYPE_REASSOC_REQ = 0x20,
    MGM_SUBTYPE_REASSOC_RES = 0x30,
    MGM_SUBTYPE_PROBE_REQ = 0x40,
    MGM_SUBTYPE_PROBE_RES = 0x50,
    MGM_SUBTYPE_BEACON = 0x80,
} IEEE80211_MgmSubtypes_e;

int addBeaconRxFilter()
{
    /**
     * We are creating two decision tree:
     * 1. FRAME_TYPE != 'MANAGEMENT' then DROP
     * 2. FRAME_TYPE == 'MANAGEMENT' -> FRAME_TYPE != BEACON then DROP
     */

    SlrxFilterRuleType_t RuleType;
    SlrxFilterID_t FilterId = 0;
    SlrxFilterFlags_t FilterFlags;

    SlrxFilterRule_t Rule;
    SlrxFilterTrigger_t Trigger;
    SlrxFilterAction_t Action;
    SlrxFilterIdMask_t FiltersIdMask;

    uint8_t FrameType;
    uint8_t FrameSubtype;
    uint8_t FrameTypeMask;

    memset(FiltersIdMask, 0, sizeof(FiltersIdMask));

    RuleType = HEADER;
    FilterFlags.IntRepresentation = RX_FILTER_BINARY;
    FrameType = TYPE_MANAGEMENT;
    FrameTypeMask = 0xFF;

    Rule.HeaderType.RuleHeaderfield = FRAME_TYPE_FIELD;
    memcpy(Rule.HeaderType.RuleHeaderArgsAndMask.RuleHeaderArgs.RxFilterDB1BytesRuleArgs[0], &FrameType, 1);
    memcpy(Rule.HeaderType.RuleHeaderArgsAndMask.RuleHeaderArgsMask, &FrameTypeMask, 1);
    Rule.HeaderType.RuleCompareFunc = COMPARE_FUNC_NOT_EQUAL_TO;

    Trigger.ParentFilterID = 0;
    Trigger.Trigger = NO_TRIGGER;
    Trigger.TriggerArgConnectionState.IntRepresentation = RX_FILTER_CONNECTION_STATE_STA_NOT_CONNECTED;
    Trigger.TriggerArgRoleStatus.IntRepresentation = RX_FILTER_ROLE_PROMISCUOUS;

    Action.ActionType.IntRepresentation = RX_FILTER_ACTION_DROP;

    int16_t retVal = sl_WlanRxFilterAdd(RuleType, FilterFlags, &Rule, &Trigger, &Action, &FilterId);
    if (retVal != 0) {
        DEBUG("[ERROR] Can not add filter: %d", retVal);
        return -1;
    }
    DEBUG("Filter created, id: %d", FilterId);

    SETBIT8(FiltersIdMask, FilterId);

    Rule.HeaderType.RuleCompareFunc = COMPARE_FUNC_EQUAL;
    Action.ActionType.IntRepresentation = RX_FILTER_ACTION_NULL;

    retVal = sl_WlanRxFilterAdd(RuleType, FilterFlags, &Rule, &Trigger, &Action, &FilterId);
    if (retVal != 0) {
        DEBUG("[ERROR] Can not add filter: %d", retVal);
        return -1;
    }
    DEBUG("Filter created, id: %d", FilterId);

    SETBIT8(FiltersIdMask, FilterId);

    Trigger.ParentFilterID = FilterId;
    Rule.HeaderType.RuleCompareFunc = COMPARE_FUNC_NOT_EQUAL_TO;
    Action.ActionType.IntRepresentation = RX_FILTER_ACTION_DROP;
    FrameSubtype = MGM_SUBTYPE_BEACON;
    Rule.HeaderType.RuleHeaderfield = FRAME_SUBTYPE_FIELD;
    memcpy(Rule.HeaderType.RuleHeaderArgsAndMask.RuleHeaderArgs.RxFilterDB1BytesRuleArgs[0], &FrameSubtype, 1);

    retVal = sl_WlanRxFilterAdd(RuleType, FilterFlags, &Rule, &Trigger, &Action, &FilterId);
    if (retVal != 0) {
        DEBUG("[ERROR] Can not add filter: %d", retVal);
        return -1;
    }
    DEBUG("Filter created, id: %d", FilterId);

    SETBIT8(FiltersIdMask, FilterId);


    _WlanRxFilterOperationCommandBuff_t filterOperation;
    memset(&filterOperation, 0, sizeof(filterOperation));
    memcpy(filterOperation.FilterIdMask, FiltersIdMask, sizeof(FiltersIdMask));

    retVal = sl_WlanRxFilterSet(SL_ENABLE_DISABLE_RX_FILTER , &filterOperation, sizeof(filterOperation));
    if(retVal != 0) {
        DEBUG("[ERROR]sl_WlanRxFilterSet, retVal: %d", retVal);
        return -1;
    }
    DEBUG("Filters are successfully enabled");

    return 0;
}
