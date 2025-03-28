/*
 * Copyright 2025, Hiroyuki OYAMA. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include <stdio.h>
#include "btstack.h"
#include "pico/cyw43_arch.h"
#include "pico/btstack_cyw43.h"
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

static device_state_t current_state = DEVICE_START_UP;


typedef struct {
    char ssid[33];
    char password[64];
    char ip_address[16];
    uint8_t link_status;
} wifi_setting_t;

static wifi_setting_t wifi_setting;


int le_notification_enabled;
hci_con_handle_t con_handle;
static btstack_packet_callback_registration_t hci_event_callback_registration;

#define APP_AD_FLAGS 0x06

static uint8_t adv_data[] = {
    // Flags general discoverable
    0x02, BLUETOOTH_DATA_TYPE_FLAGS, APP_AD_FLAGS,
    // Name
    0x17, BLUETOOTH_DATA_TYPE_COMPLETE_LOCAL_NAME, 'P', 'i', 'c', 'o', ' ', '0', '0', ':', '0', '0', ':', '0', '0', ':', '0', '0', ':', '0', '0', ':', '0', '0',
    0x03, BLUETOOTH_DATA_TYPE_COMPLETE_LIST_OF_16_BIT_SERVICE_CLASS_UUIDS, 0x10, 0xff,
};
static const uint8_t adv_data_len = sizeof(adv_data);


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

void process_event(device_event_t event);


typedef struct {
    char *data;
    size_t len;
    hci_con_handle_t *con_handle;
} notify_string_t;


static void notify_ip_address_callback(void *context) {
    notify_string_t *notify = (notify_string_t *)context;
    int err = att_server_notify(*notify->con_handle,
                                ATT_CHARACTERISTIC_be3d7603_0ea0_4e96_82e0_89aa6a3dc19f_01_VALUE_HANDLE,
                                notify->data, notify->len);
    if (err) {
        printf("notify_callback - error!\n");
    }
}

void state_entry_action(device_state_t state) {
    switch (state) {
    case DEVICE_WIFI_LINK_TO_UP:
        printf("Entry: DEVICE_WIFI_LINK_TO_UP, attempting Wi-Fi connection to SSID: %s\n", wifi_setting.ssid);
        {
            cyw43_arch_enable_sta_mode();
            int rc = cyw43_wifi_leave(&cyw43_state, CYW43_ITF_STA);
            rc = cyw43_arch_wifi_connect_async(wifi_setting.ssid, wifi_setting.password, CYW43_AUTH_WPA2_AES_PSK);
            if (rc != 0) {
                printf("cyw43_arch_wifi_connect_async failed, rc=%d\n", rc);
                process_event(EVENT_ERROR_OCCURED);
            }
        }
        break;
    case DEVICE_WIFI_LINK_UP:
        printf("Entry: DEVICE_WIFI_LINK_UP, waiting for IP address...\n");
        break;
    case DEVICE_WIFI_LINK_CONNECTED: {
        printf("Entry: DEVICE_WIFI_LINK_CONNECTED, Wi-Fi connected\n");
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
        }
        break;
    case DEVICE_WIFI_LINK_DOWN: {
        printf("Entry: DEVICE_WIFI_LINK_DOWN\n");
        cyw43_wifi_leave(&cyw43_state, CYW43_ITF_STA);
        cyw43_cb_tcpip_deinit(&cyw43_state, 0);
        cyw43_cb_tcpip_deinit(&cyw43_state, 1);
        cyw43_cb_tcpip_init(&cyw43_state, 0);
        cyw43_cb_tcpip_init(&cyw43_state, 1);
        wifi_setting.ip_address[0] = '\0';

        if (con_handle != HCI_CON_HANDLE_INVALID) {
            att_server_notify(con_handle, ATT_CHARACTERISTIC_be3d7603_0ea0_4e96_82e0_89aa6a3dc19f_01_VALUE_HANDLE, (uint8_t *)&wifi_setting.ip_address, strlen(wifi_setting.ip_address));
        }
        }
        break;
    case DEVICE_RUNNING:
        printf("Entry: DEVICE_RUNNING, device is fully operational\n");
        break;
    default:
        break;
    }
}

void process_event(device_event_t event) {
    device_state_t new_state = state_transition(current_state, event);
    printf("Transition state state=%d, event=%d -> state=%d\n", current_state, event, new_state);
    if (new_state != current_state) {
        current_state = new_state;
        state_entry_action(current_state);
    }
}

void packet_handler(uint8_t packet_type, uint16_t channel, uint8_t *packet, uint16_t size) {
    UNUSED(size);
    UNUSED(channel);
    bd_addr_t local_addr;
    if (packet_type != HCI_EVENT_PACKET) return;

    uint8_t event_type = hci_event_packet_get_type(packet);
    switch(event_type){
        case BTSTACK_EVENT_STATE:
            if (btstack_event_state_get_state(packet) != HCI_STATE_WORKING) return;
            gap_local_bd_addr(local_addr);
            printf("BTstack up and running on %s.\n", bd_addr_to_str(local_addr));

            // setup advertisements
            uint16_t adv_int_min = 800;
            uint16_t adv_int_max = 800;
            uint8_t adv_type = 0;
            bd_addr_t null_addr;
            memset(null_addr, 0, 6);
            gap_advertisements_set_params(adv_int_min, adv_int_max, adv_type, 0, null_addr, 0x07, 0x00);
            assert(adv_data_len <= 31); // ble limitation
            gap_advertisements_set_data(adv_data_len, (uint8_t*) adv_data);
            gap_advertisements_enable(1);

            break;
        case HCI_EVENT_LE_META:
            uint8_t subevent = hci_event_le_meta_get_subevent_code(packet);
            if (subevent == HCI_SUBEVENT_LE_CONNECTION_COMPLETE) {
                con_handle = hci_subevent_le_connection_complete_get_connection_handle(packet);
                printf("BLE connection established, handle: 0x%04x\n", con_handle);
            }
            break;
        case HCI_EVENT_DISCONNECTION_COMPLETE:
            con_handle = HCI_CON_HANDLE_INVALID;
            le_notification_enabled = 0;
            break;
        case ATT_EVENT_CAN_SEND_NOW:
            if (con_handle != HCI_CON_HANDLE_INVALID) {
                att_server_notify(con_handle, ATT_CHARACTERISTIC_be3d7601_0ea0_4e96_82e0_89aa6a3dc19f_01_VALUE_HANDLE, (uint8_t *)&wifi_setting.ssid, strlen(wifi_setting.ssid));
                att_server_notify(con_handle, ATT_CHARACTERISTIC_be3d7603_0ea0_4e96_82e0_89aa6a3dc19f_01_VALUE_HANDLE, (uint8_t *)&wifi_setting.ip_address, strlen(wifi_setting.ip_address));
            }
            break;
        default:
            break;
    }
}

uint16_t att_read_callback(hci_con_handle_t connection_handle, uint16_t att_handle, uint16_t offset, uint8_t * buffer, uint16_t buffer_size) {
    UNUSED(connection_handle);

    if (att_handle == ATT_CHARACTERISTIC_be3d7601_0ea0_4e96_82e0_89aa6a3dc19f_01_VALUE_HANDLE){
        printf("Read characteristic SSID: \"%s\"\n", wifi_setting.ssid);
        return att_read_callback_handle_blob((const uint8_t *)&wifi_setting.ssid, strlen(wifi_setting.ssid), offset, buffer, buffer_size);
    }
    if (att_handle == ATT_CHARACTERISTIC_be3d7603_0ea0_4e96_82e0_89aa6a3dc19f_01_VALUE_HANDLE){
        printf("Read characteristic IP address: %s\n", wifi_setting.ip_address);
        return att_read_callback_handle_blob((const uint8_t *)&wifi_setting.ip_address, strlen(wifi_setting.ip_address), offset, buffer, buffer_size);
    }
    return 0;
}

int att_write_callback(hci_con_handle_t connection_handle, uint16_t att_handle, uint16_t transaction_mode, uint16_t offset, uint8_t *buffer, uint16_t buffer_size) {
    UNUSED(transaction_mode);
    UNUSED(offset);
    switch (att_handle) {
        case ATT_CHARACTERISTIC_be3d7601_0ea0_4e96_82e0_89aa6a3dc19f_01_VALUE_HANDLE:
            memcpy(wifi_setting.ssid, buffer, buffer_size);
            wifi_setting.ssid[buffer_size] = '\0';
            printf("Write characteristic SSID: \"%s\"\n", wifi_setting.ssid);
            if (strlen(wifi_setting.ssid) > 0 && strlen(wifi_setting.password) > 0) {
                process_event(EVENT_WIFI_CONNECT);
            }
            break;
        case ATT_CHARACTERISTIC_be3d7602_0ea0_4e96_82e0_89aa6a3dc19f_01_VALUE_HANDLE:
            memcpy(wifi_setting.password, buffer, buffer_size);
            wifi_setting.password[buffer_size] = '\0';
            printf("Write characteristic Password: %s\n", wifi_setting.password);
            if (strlen(wifi_setting.ssid) > 0 && strlen(wifi_setting.password) > 0) {
                process_event(EVENT_WIFI_CONNECT);
            }
            break;
        default:
            break;
    }
    return 0;
}

static void wifi_task(void) {
    int status;
    switch (current_state) {
    case DEVICE_WIFI_LINK_TO_UP:
        status = cyw43_wifi_link_status(&cyw43_state, CYW43_ITF_STA);
        printf("Wi-Fi up link, link_status=%d\n", status);
        if (status == CYW43_LINK_JOIN) {
            process_event(EVENT_WIFI_CONNECTED);
        } else if (status < 0) {
            process_event(EVENT_WIFI_ERROR);
        }
        break;
    case DEVICE_WIFI_LINK_UP:
        status = cyw43_wifi_link_status(&cyw43_state, CYW43_ITF_STA);
        if (status == CYW43_LINK_NONET) {
            // No matching SSID found
            wifi_setting.ssid[0] = '\0';
            process_event(EVENT_WIFI_ERROR);
        } else if (status == CYW43_LINK_BADAUTH) {
            wifi_setting.password[0] = '\0';
            process_event(EVENT_WIFI_ERROR);
        }

        if (status == CYW43_LINK_JOIN && (*(uint32_t *)&cyw43_state.netif[0].ip_addr) != 0) {
            char *ip_address = ip4addr_ntoa(&cyw43_state.netif[0].ip_addr);
            strcpy(wifi_setting.ip_address, ip_address);
            printf("Acquired IP address=%s\n", wifi_setting.ip_address);
            wifi_setting.link_status = 1;
            cyw43_arch_gpio_put(CYW43_WL_GPIO_LED_PIN, 1);

            process_event(EVENT_IP_ACQUIRED);
        }
        break;
    case DEVICE_WIFI_LINK_CONNECTED:
        process_event(EVENT_WIFI_CONNECTED);
        break;
    case DEVICE_WIFI_LINK_DOWN:
        cyw43_arch_gpio_put(CYW43_WL_GPIO_LED_PIN, 0);
        if (strlen(wifi_setting.ssid) > 0 && strlen(wifi_setting.password) > 0) {
            process_event(EVENT_WIFI_CONNECT);
        }
        break;
    default:
        break;
    }
}

int main() {
    stdio_init_all();
    current_state = DEVICE_START_UP;
    printf("device status=DEVICE_START_UP\n");

    if (cyw43_arch_init()) {
        printf("failed to initialize cyw43_arch\n");
        return -1;
    }

    l2cap_init();
    sm_init();
    att_server_init(profile_data, att_read_callback, att_write_callback);
    hci_event_callback_registration.callback = &packet_handler;
    hci_add_event_handler(&hci_event_callback_registration);
    att_server_register_packet_handler(packet_handler);
    hci_power_control(HCI_POWER_ON);

    cyw43_arch_enable_sta_mode();
    process_event(EVENT_WIFI_CONFIGURED);
    while (true) {
        wifi_task();

        if (le_notification_enabled) {
            att_server_request_can_send_now_event(con_handle);
        }
    }
    return 0;
}
