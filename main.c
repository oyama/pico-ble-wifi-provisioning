/*
 * Copyright 2025, Hiroyuki OYAMA. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include <stdio.h>

#include "btstack.h"
#include "pico/btstack_cyw43.h"
#include "pico/cyw43_arch.h"
#include "pico/stdlib.h"
#include "wifi_provisioning.h"

typedef enum {
    DEVICE_START_UP = 0,
    DEVICE_WIFI_LINK_DOWN,
    DEVICE_WIFI_LINK_TO_UP,
    DEVICE_WIFI_LINK_UP,
    DEVICE_WIFI_LINK_CONNECTED,
    DEVICE_RUNNING,
    DEVICE_ERROR
} device_state_t;

typedef enum {
    EVENT_NONE = 0,
    EVENT_WIFI_CONFIGURED,
    EVENT_WIFI_CONNECT,
    EVENT_WIFI_CONNECTED,
    EVENT_WIFI_ERROR,
    EVENT_IP_ACQUIRED,
    EVENT_WIFI_DISCONNECTED,
    EVENT_ERROR_OCCURED
} device_event_t;

typedef enum {
    WIFI_SSID_HANDLE = ATT_CHARACTERISTIC_be3d7601_0ea0_4e96_82e0_89aa6a3dc19f_01_VALUE_HANDLE,
    WIFI_PASSWORD_HANDLE = ATT_CHARACTERISTIC_be3d7602_0ea0_4e96_82e0_89aa6a3dc19f_01_VALUE_HANDLE,
    IP_ADDRESS_HANDLE = ATT_CHARACTERISTIC_be3d7603_0ea0_4e96_82e0_89aa6a3dc19f_01_VALUE_HANDLE
} attribute_handle_t;

typedef struct {
    char ssid[33];
    char password[64];
    char ip_address[16];
    uint8_t link_status;
} wifi_setting_t;

static device_state_t current_state = DEVICE_START_UP;
static wifi_setting_t wifi_setting;
static int le_notification_enabled;
hci_con_handle_t con_handle;
static btstack_packet_callback_registration_t hci_event_callback_registration;
static btstack_packet_callback_registration_t sm_event_callback_registration;

#define APP_AD_FLAGS 0x06

// clang-format off
static uint8_t adv_data[] = {
    // Flags general discoverable
    0x02, BLUETOOTH_DATA_TYPE_FLAGS, APP_AD_FLAGS,
    // Name
    0x17, BLUETOOTH_DATA_TYPE_COMPLETE_LOCAL_NAME, 'P', 'i', 'c', 'o', ' ', '0', '0', ':', '0', '0', ':', '0', '0', ':', '0', '0', ':', '0', '0', ':', '0', '0',
    0x03, BLUETOOTH_DATA_TYPE_COMPLETE_LIST_OF_16_BIT_SERVICE_CLASS_UUIDS, 0x10, 0xff,
};
// clang-format on

static const uint8_t adv_data_len = sizeof(adv_data);

/**
 * @brief Converts a device state enum to a human-readable string.
 *
 * @param state The device state to convert.
 * @return A string representation of the device state.
 */
static const char *device_state_string(device_state_t state) {
    if (state == DEVICE_START_UP)
        return "DEVICE_START_UP";
    if (state == DEVICE_WIFI_LINK_TO_UP)
        return "DEVICE_WIFI_LINK_TO_UP";
    if (state == DEVICE_WIFI_LINK_UP)
        return "DEVICE_WIFI_LINK_UP";
    if (state == DEVICE_WIFI_LINK_CONNECTED)
        return "DEVICE_WIFI_LINK_CONNECTED";
    if (state == DEVICE_WIFI_LINK_DOWN)
        return "DEVICE_WIFI_LINK_DOWN";
    if (state == DEVICE_RUNNING)
        return "DEVICE_RUNNING";
    if (state == DEVICE_ERROR)
        return "DEVICE_ERROR";
    return "UNKNOWN";
}

/**
 * @brief Converts a device event enum to a human-readable string.
 *
 * @param event The device event to convert.
 * @return A string representation of the device event.
 */
static const char *device_event_string(device_event_t event) {
    if (event == EVENT_NONE)
        return "EVENT_NONE";
    if (event == EVENT_WIFI_CONFIGURED)
        return "EVENT_WIFI_CONFIGURED";
    if (event == EVENT_WIFI_CONNECT)
        return "EVENT_WIFI_CONNECT";
    if (event == EVENT_WIFI_CONNECTED)
        return "EVENT_WIFI_CONNECTED";
    if (event == EVENT_WIFI_ERROR)
        return "EVENT_WIFI_ERROR";
    if (event == EVENT_IP_ACQUIRED)
        return "EVENT_IP_ACQUIRED";
    if (event == EVENT_WIFI_DISCONNECTED)
        return "EVENT_WIFI_DISCONNECTED";
    if (event == EVENT_ERROR_OCCURED)
        return "EVENT_ERROR_OCCURED";
    return "UNKNOWN";
}

/**
 * @brief Defines the state transition logic based on the current state and event.
 *
 * @param state The current device state.
 * @param event The event that occurred.
 * @return The new device state after the transition.
 */
static device_state_t state_transition(device_state_t state, device_event_t event) {
    switch (state) {
        case DEVICE_START_UP:
            if (event == EVENT_WIFI_CONFIGURED)
                return DEVICE_WIFI_LINK_DOWN;
            break;
        case DEVICE_WIFI_LINK_DOWN:
            if (event == EVENT_WIFI_CONNECT)
                return DEVICE_WIFI_LINK_TO_UP;
            break;
        case DEVICE_WIFI_LINK_TO_UP:
            if (event == EVENT_WIFI_CONNECTED)
                return DEVICE_WIFI_LINK_UP;
            if (event == EVENT_WIFI_ERROR)
                return DEVICE_WIFI_LINK_DOWN;
            break;
        case DEVICE_WIFI_LINK_UP:
            if (event == EVENT_IP_ACQUIRED)
                return DEVICE_WIFI_LINK_CONNECTED;
            if (event == EVENT_WIFI_CONNECT)
                return DEVICE_WIFI_LINK_DOWN;
            if (event == EVENT_WIFI_ERROR)
                return DEVICE_WIFI_LINK_DOWN;
            break;
        case DEVICE_WIFI_LINK_CONNECTED:
            if (event == EVENT_WIFI_CONNECTED)
                return DEVICE_RUNNING;
            if (event == EVENT_WIFI_DISCONNECTED)
                return DEVICE_WIFI_LINK_DOWN;
            break;
        case DEVICE_RUNNING:
            if (event == EVENT_WIFI_CONNECT)
                return DEVICE_WIFI_LINK_DOWN;
            if (event == EVENT_WIFI_DISCONNECTED)
                return DEVICE_WIFI_LINK_DOWN;
            break;
        default:
            break;
    }
    return state;
}

typedef struct {
    char *data;
    size_t len;
    hci_con_handle_t *con_handle;
} notify_string_t;

/**
 * @brief Callback function to notify the connected BLE device about the IP address.
 *
 * @param context Pointer to the notify_string_t structure containing notification data.
 */
static void notify_ip_address_callback(void *context) {
    notify_string_t *notify = (notify_string_t *)context;
    int err = att_server_notify(*notify->con_handle, IP_ADDRESS_HANDLE, notify->data, notify->len);
    if (err) {
        printf("[ATT] Notification error=%d\n", err);
    }
}

static void process_event(device_event_t event);

/**
 * @brief Executes actions upon entering a specific device state.
 *
 * @param state The device state being entered.
 */
static void state_entry_action(device_state_t state) {
    switch (state) {
        case DEVICE_WIFI_LINK_TO_UP: {
            printf(
                "[STATE] Entering: DEVICE_WIFI_LINK_TO_UP, attempting Wi-Fi connection to SSID: "
                "%s\n",
                wifi_setting.ssid);
            cyw43_arch_enable_sta_mode();
            int rc = cyw43_wifi_leave(&cyw43_state, CYW43_ITF_STA);
            rc = cyw43_arch_wifi_connect_async(wifi_setting.ssid, wifi_setting.password,
                                               CYW43_AUTH_WPA2_AES_PSK);
            if (rc != 0) {
                printf("[WIFI] Wi-Fi connect async failed, error code: %d\n", rc);
                process_event(EVENT_ERROR_OCCURED);
            }
            break;
        }
        case DEVICE_WIFI_LINK_UP:
            printf("[STATE] Entering: DEVICE_WIFI_LINK_UP, waiting for IP address...\n");
            break;
        case DEVICE_WIFI_LINK_CONNECTED: {
            printf("[STATE] Entering: DEVICE_WIFI_LINK_CONNECTED, Wi-Fi connected\n");
            if (con_handle != HCI_CON_HANDLE_INVALID) {
                notify_string_t notify;
                notify.data = wifi_setting.ip_address;
                notify.len = strlen(wifi_setting.ip_address);
                notify.con_handle = &con_handle;
                btstack_context_callback_registration_t context_registration;
                context_registration.callback = &notify_ip_address_callback;
                context_registration.context = &notify;
                att_server_request_to_send_notification(&context_registration, con_handle);
            }
            break;
        }
        case DEVICE_WIFI_LINK_DOWN: {
            printf("[STATE] Entering: DEVICE_WIFI_LINK_DOWN\n");
            cyw43_wifi_leave(&cyw43_state, CYW43_ITF_STA);
            cyw43_cb_tcpip_deinit(&cyw43_state, 0);
            cyw43_cb_tcpip_deinit(&cyw43_state, 1);
            cyw43_cb_tcpip_init(&cyw43_state, 0);
            cyw43_cb_tcpip_init(&cyw43_state, 1);
            wifi_setting.ip_address[0] = '\0';

            if (con_handle != HCI_CON_HANDLE_INVALID) {
                att_server_notify(con_handle, IP_ADDRESS_HANDLE,
                                  (uint8_t *)&wifi_setting.ip_address,
                                  strlen(wifi_setting.ip_address));
            }
            break;
        }
        case DEVICE_RUNNING:
            printf("[STATE] Entering: DEVICE_RUNNING, device is fully operational\n");
            break;
        default:
            break;
    }
}

/**
 * @brief Processes a device event by performing a state transition and executing entry actions.
 *
 * @param event The device event to process.
 */
static void process_event(device_event_t event) {
    device_state_t new_state = state_transition(current_state, event);
    printf("[EVENT] Processing: %s, current state: %s -> new state: %s\n",
           device_event_string(event), device_state_string(current_state),
           device_state_string(new_state));
    if (new_state != current_state) {
        current_state = new_state;
        state_entry_action(current_state);
    }
}

/**
 * @brief Handles Bluetooth Low Energy (BLE) events.
 *
 * @param packet_type The type of the received packet.
 * @param channel The channel the packet was received on.
 * @param packet Pointer to the received packet data.
 * @param size The size of the received packet data.
 */
static void ble_event_handler(uint8_t packet_type, uint16_t channel, uint8_t *packet,
                              uint16_t size) {
    (void)size;
    (void)channel;
    bd_addr_t local_addr;
    if (packet_type != HCI_EVENT_PACKET)
        return;

    uint8_t event_type = hci_event_packet_get_type(packet);
    switch (event_type) {
        case BTSTACK_EVENT_STATE:
            if (btstack_event_state_get_state(packet) != HCI_STATE_WORKING)
                return;
            gap_local_bd_addr(local_addr);
            printf("[BLE] BTstack up and running on %s.\n", bd_addr_to_str(local_addr));

            // setup advertisements
            uint16_t adv_int_min = 800;
            uint16_t adv_int_max = 800;
            uint8_t adv_type = 0;
            bd_addr_t null_addr;
            memset(null_addr, 0, 6);
            gap_advertisements_set_params(adv_int_min, adv_int_max, adv_type, 0, null_addr, 0x07,
                                          0x00);
            assert(adv_data_len <= 31);  // ble limitation

            gap_advertisements_set_data(adv_data_len, (uint8_t *)adv_data);
            gap_advertisements_enable(1);

            break;
        case HCI_EVENT_LE_META:
            uint8_t subevent = hci_event_le_meta_get_subevent_code(packet);
            if (subevent == HCI_SUBEVENT_LE_CONNECTION_COMPLETE) {
                con_handle = hci_subevent_le_connection_complete_get_connection_handle(packet);
                printf("[BLE] Connection established, handle: 0x%04x\n", con_handle);
            }
            break;
        case HCI_EVENT_DISCONNECTION_COMPLETE:
            con_handle = HCI_CON_HANDLE_INVALID;
            le_notification_enabled = 0;
            printf("[BLE] Disconnected, handle: 0x%04x\n",
                   hci_event_disconnection_complete_get_connection_handle(packet));
            break;
        case ATT_EVENT_CAN_SEND_NOW:
            if (con_handle != HCI_CON_HANDLE_INVALID) {
                att_server_notify(con_handle, WIFI_SSID_HANDLE, (uint8_t *)&wifi_setting.ssid,
                                  strlen(wifi_setting.ssid));
                att_server_notify(con_handle, IP_ADDRESS_HANDLE,
                                  (uint8_t *)&wifi_setting.ip_address,
                                  strlen(wifi_setting.ip_address));
                printf("[ATT] Can send notification now\n");
            }
            break;
        default:
            break;
    }
}

/**
 * @brief Callback function to handle read requests on GATT attributes.
 *
 * @param connection_handle The handle of the connection.
 * @param att_handle The handle of the attribute being read.
 * @param offset The offset to read from.
 * @param buffer The buffer to store the read data.
 * @param buffer_size The size of the buffer.
 * @return The number of bytes read.
 */
static uint16_t att_read_callback(hci_con_handle_t connection_handle, uint16_t att_handle,
                                  uint16_t offset, uint8_t *buffer, uint16_t buffer_size) {
    (void)connection_handle;

    if (att_handle == WIFI_SSID_HANDLE) {
        printf("[ATT] Read request for SSID: \"%s\"\n", wifi_setting.ssid);
        return att_read_callback_handle_blob((const uint8_t *)&wifi_setting.ssid,
                                             strlen(wifi_setting.ssid), offset, buffer,
                                             buffer_size);
    }
    if (att_handle == IP_ADDRESS_HANDLE) {
        printf("[ATT] Read request for IP address: %s\n", wifi_setting.ip_address);
        return att_read_callback_handle_blob((const uint8_t *)&wifi_setting.ip_address,
                                             strlen(wifi_setting.ip_address), offset, buffer,
                                             buffer_size);
    }
    return 0;
}

/**
 * @brief Callback function to handle write requests on GATT attributes.
 *
 * @param connection_handle The handle of the connection.
 * @param att_handle The handle of the attribute being written to.
 * @param transaction_mode The transaction mode (not used here).
 * @param offset The offset to write to.
 * @param buffer The buffer containing the data to write.
 * @param buffer_size The size of the data to write.
 * @return ATT_ERROR_SUCCESS if the write was successful, otherwise an error code.
 */
static int att_write_callback(hci_con_handle_t connection_handle, uint16_t att_handle,
                              uint16_t transaction_mode, uint16_t offset, uint8_t *buffer,
                              uint16_t buffer_size) {
    (void)transaction_mode;
    (void)offset;
    switch (att_handle) {
        case WIFI_SSID_HANDLE:
            if (sizeof(wifi_setting.ssid) < buffer_size) {
                printf("[ATT] WARN: Write message to SSID characteristic is too long\n");
                return ATT_ERROR_INVALID_ATTRIBUTE_VALUE_LENGTH;
            }
            memcpy(wifi_setting.ssid, buffer, buffer_size);
            wifi_setting.ssid[buffer_size] = '\0';
            printf("[ATT] Write to SSID characteristic: \"%s\"\n", wifi_setting.ssid);
            if (strlen(wifi_setting.ssid) > 0 && strlen(wifi_setting.password) > 0) {
                process_event(EVENT_WIFI_CONNECT);
            }
            break;
        case WIFI_PASSWORD_HANDLE:
            if (sizeof(wifi_setting.password) < buffer_size) {
                printf("[ATT] WARN: Write message to Password characteristic is too long\n");
                return ATT_ERROR_INVALID_ATTRIBUTE_VALUE_LENGTH;
            }
            memcpy(wifi_setting.password, buffer, buffer_size);
            wifi_setting.password[buffer_size] = '\0';
            printf("[ATT] Write to Password characteristic: ");
            for (size_t i = 0; i < strlen(wifi_setting.password); i++) printf("*");
            printf("\n");
            if (strlen(wifi_setting.ssid) > 0 && strlen(wifi_setting.password) > 0) {
                process_event(EVENT_WIFI_CONNECT);
            }
            break;
        default:
            break;
    }
    return ATT_ERROR_SUCCESS;
}

/**
 * @brief Handles Security Manager (SM) events related to BLE pairing and bonding.
 *
 * @param packet_type The type of the received packet.
 * @param channel The channel the packet was received on.
 * @param packet Pointer to the received packet data.
 * @param size The size of the received packet data.
 */
static void sm_event_handler(uint8_t packet_type, uint16_t channel, uint8_t *packet,
                             uint16_t size) {
    (void)channel;
    (void)size;

    if (packet_type != HCI_EVENT_PACKET)
        return;

    hci_con_handle_t con_handle;
    bd_addr_t addr;
    bd_addr_type_t addr_type;
    uint8_t status;

    switch (hci_event_packet_get_type(packet)) {
        case HCI_EVENT_META_GAP:
            switch (hci_event_gap_meta_get_subevent_code(packet)) {
                case GAP_SUBEVENT_LE_CONNECTION_COMPLETE:
                    printf("[SM] Connection complete\n");
                    con_handle = gap_subevent_le_connection_complete_get_connection_handle(packet);
                    (void)con_handle;

                    // for testing, choose one of the following actions

                    // manually start pairing
                    // sm_request_pairing(con_handle);

                    // gatt client request to authenticated characteristic in
                    // sm_pairing_central (short cut, uses hard-coded value
                    // handle)
                    // gatt_client_read_value_of_characteristic_using_value_handle(&packet_handler,
                    // con_handle, 0x0009);

                    // general gatt client request to trigger mandatory
                    // authentication
                    // gatt_client_discover_primary_services(&packet_handler,
                    // con_handle);
                    break;
                default:
                    break;
            }
            break;
        case SM_EVENT_JUST_WORKS_REQUEST:
            printf("[SM] Just Works requested\n");
            sm_just_works_confirm(sm_event_just_works_request_get_handle(packet));
            break;
        case SM_EVENT_NUMERIC_COMPARISON_REQUEST:
            printf("[SM] Confirming numeric comparison: %" PRIu32 "\n",
                   sm_event_numeric_comparison_request_get_passkey(packet));
            sm_numeric_comparison_confirm(sm_event_passkey_display_number_get_handle(packet));
            break;
        case SM_EVENT_PASSKEY_DISPLAY_NUMBER:
            printf("[SM] Display Passkey: %" PRIu32 "\n",
                   sm_event_passkey_display_number_get_passkey(packet));
            break;
        case SM_EVENT_IDENTITY_CREATED:
            sm_event_identity_created_get_identity_address(packet, addr);
            printf("[SM] Identity created: type %u address %s\n",
                   sm_event_identity_created_get_identity_addr_type(packet), bd_addr_to_str(addr));
            break;
        case SM_EVENT_IDENTITY_RESOLVING_SUCCEEDED:
            sm_event_identity_resolving_succeeded_get_identity_address(packet, addr);
            printf("[SM] Identity resolved: type %u address %s\n",
                   sm_event_identity_resolving_succeeded_get_identity_addr_type(packet),
                   bd_addr_to_str(addr));
            break;
        case SM_EVENT_IDENTITY_RESOLVING_FAILED:
            sm_event_identity_created_get_address(packet, addr);
            printf("[SM] Identity resolving failed\n");
            break;
        case SM_EVENT_PAIRING_STARTED:
            printf("[SM] Pairing started\n");
            break;
        case SM_EVENT_PAIRING_COMPLETE:
            switch (sm_event_pairing_complete_get_status(packet)) {
                case ERROR_CODE_SUCCESS:
                    printf("[SM] Pairing complete, success\n");
                    break;
                case ERROR_CODE_CONNECTION_TIMEOUT:
                    printf("[SM] Pairing failed, timeout\n");
                    break;
                case ERROR_CODE_REMOTE_USER_TERMINATED_CONNECTION:
                    printf("[SM] Pairing failed, disconnected\n");
                    break;
                case ERROR_CODE_AUTHENTICATION_FAILURE:
                    printf("[SM] Pairing failed, authentication failure with reason = %u\n",
                           sm_event_pairing_complete_get_reason(packet));
                    break;
                default:
                    break;
            }
            break;
        case SM_EVENT_REENCRYPTION_STARTED:
            sm_event_reencryption_complete_get_address(packet, addr);
            printf(
                "[SM] Bonding information exists for addr type %u, identity addr %s -> "
                "re-encryption started\n",
                sm_event_reencryption_started_get_addr_type(packet), bd_addr_to_str(addr));
            break;
        case SM_EVENT_REENCRYPTION_COMPLETE:
            switch (sm_event_reencryption_complete_get_status(packet)) {
                case ERROR_CODE_SUCCESS:
                    printf("[SM] Re-encryption complete, success\n");
                    break;
                case ERROR_CODE_CONNECTION_TIMEOUT:
                    printf("[SM] Re-encryption failed, timeout\n");
                    break;
                case ERROR_CODE_REMOTE_USER_TERMINATED_CONNECTION:
                    printf("[SM] Re-encryption failed, disconnected\n");
                    break;
                case ERROR_CODE_PIN_OR_KEY_MISSING:
                    printf(
                        "[SM] Re-encryption failed, bonding information missing\n"
                        "[SM] Assuming remote lost bonding information\n"
                        "[SM] Deleting local bonding information to allow for new pairing...\n");
                    sm_event_reencryption_complete_get_address(packet, addr);
                    addr_type = sm_event_reencryption_started_get_addr_type(packet);
                    gap_delete_bonding(addr_type, addr);
                    break;
                default:
                    break;
            }
            break;
        case GATT_EVENT_QUERY_COMPLETE:
            status = gatt_event_query_complete_get_att_status(packet);
            switch (status) {
                case ATT_ERROR_INSUFFICIENT_ENCRYPTION:
                    printf("[GATT] Query failed, Insufficient Encryption\n");
                    break;
                case ATT_ERROR_INSUFFICIENT_AUTHENTICATION:
                    printf("[GATT] Query failed, Insufficient Authentication\n");
                    break;
                case ATT_ERROR_BONDING_INFORMATION_MISSING:
                    printf("[GATT] Query failed, Bonding Information Missing\n");
                    break;
                case ATT_ERROR_SUCCESS:
                    printf("[GATT] Query successful\n");
                    break;
                default:
                    printf("[GATT] Query failed, status 0x%02x\n",
                           gatt_event_query_complete_get_att_status(packet));
                    break;
            }
            break;
        default:
            break;
    }
}

/**
 * @brief Initializes the Wi-Fi functionality using the CYW43 driver.
 */
static void wifi_init(void) {
    if (cyw43_arch_init()) {
        panic("failed to initialize cyw43_arch\n");
    }
    cyw43_arch_enable_sta_mode();
}

/**
 * @brief Initializes the Bluetooth Low Energy (BLE) stack.
 */
static void bluetooth_init(void) {
    l2cap_init();
    sm_init();
    att_server_init(profile_data, att_read_callback, att_write_callback);
    hci_event_callback_registration.callback = &ble_event_handler;
    hci_add_event_handler(&hci_event_callback_registration);
    att_server_register_packet_handler(ble_event_handler);

    sm_event_callback_registration.callback = &sm_event_handler;
    sm_add_event_handler(&sm_event_callback_registration);

    sm_set_io_capabilities(IO_CAPABILITY_NO_INPUT_NO_OUTPUT);
    sm_set_authentication_requirements(SM_AUTHREQ_NO_BONDING);

    hci_power_control(HCI_POWER_ON);
}

/**
 * @brief Periodically checks the Wi-Fi link status and processes relevant events.
 */
static void wifi_task(void) {
    int status;

    switch (current_state) {
        case DEVICE_WIFI_LINK_TO_UP:
            status = cyw43_wifi_link_status(&cyw43_state, CYW43_ITF_STA);
            printf("[WIFI] Link status: %d\n", status);
            if (status == CYW43_LINK_JOIN) {
                process_event(EVENT_WIFI_CONNECTED);
            } else if (status < 0) {
                process_event(EVENT_WIFI_ERROR);
            }
            break;
        case DEVICE_WIFI_LINK_UP:
            status = cyw43_wifi_link_status(&cyw43_state, CYW43_ITF_STA);
            if (status == CYW43_LINK_NONET) {
                printf("[WIFI] Error: No matching SSID found\n");
                wifi_setting.ssid[0] = '\0';
                process_event(EVENT_WIFI_ERROR);
            } else if (status == CYW43_LINK_BADAUTH) {
                printf("[WIFI] Error: Authentication failure\n");
                wifi_setting.password[0] = '\0';
                process_event(EVENT_WIFI_ERROR);
            }

            if (status == CYW43_LINK_JOIN && (*(uint32_t *)&cyw43_state.netif[0].ip_addr) != 0) {
                char *ip_address = ip4addr_ntoa(&cyw43_state.netif[0].ip_addr);
                strcpy(wifi_setting.ip_address, ip_address);
                printf("[WIFI] Acquired IP address: %s\n", wifi_setting.ip_address);
                wifi_setting.link_status = 1;

                process_event(EVENT_IP_ACQUIRED);
            }
            break;
        case DEVICE_WIFI_LINK_CONNECTED:
            process_event(EVENT_WIFI_CONNECTED);
            break;
        case DEVICE_WIFI_LINK_DOWN:
            if (strlen(wifi_setting.ssid) > 0 && strlen(wifi_setting.password) > 0) {
                process_event(EVENT_WIFI_CONNECT);
            }
            break;
        default:
            break;
    }
}

#define LED_BLINK_INTERVAL_US 500000

/**
 * @brief Controls device-specific tasks unrelated to Wi-Fi or BLE, such as LED blinking based on
 * the device state.
 */
static void device_task(void) {
    static uint64_t last_toggle_time = 0;
    bool led_state = cyw43_arch_gpio_get(CYW43_WL_GPIO_LED_PIN);

    switch (current_state) {
        case DEVICE_WIFI_LINK_DOWN:
        case DEVICE_WIFI_LINK_TO_UP:
        case DEVICE_WIFI_LINK_UP:
            if (time_us_64() - last_toggle_time > LED_BLINK_INTERVAL_US) {
                cyw43_arch_gpio_put(CYW43_WL_GPIO_LED_PIN, !led_state);
                last_toggle_time = time_us_64();
            }
            break;
        case DEVICE_RUNNING:
            cyw43_arch_gpio_put(CYW43_WL_GPIO_LED_PIN, true);
            break;
        default:
            if (led_state)
                cyw43_arch_gpio_put(CYW43_WL_GPIO_LED_PIN, false);
            break;
    }
}

int main() {
    stdio_init_all();
    current_state = DEVICE_START_UP;
    printf("[MAIN] BLE Wi-Fi provisioning started\n");

    wifi_init();
    bluetooth_init();

    process_event(EVENT_WIFI_CONFIGURED);
    while (true) {
        wifi_task();
        device_task();

        if (le_notification_enabled) {
            att_server_request_can_send_now_event(con_handle);
        }
    }
    return 0;
}
