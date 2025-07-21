#ifndef WIFI_IEEE_802_11_ENUMS_H
#define WIFI_IEEE_802_11_ENUMS_H

/* --- WiFi IEEE 802.11 TYPES --- */
typedef enum{
  WIFI_PKT_MGMT,
  WIFI_PKT_CTRL,
  WIFI_PKT_DATA,
  WIFI_PKT_MISC
} wifi_pkt_type_t;

/* --- WiFi IEEE 802.11 SUBTYPES --- */
typedef enum {
  ASSOCIATION_REQ,
  ASSOCIATION_RES,
  REASSOCIATION_REQ,
  REASSOCIATION_RES,
  PROBE_REQ,
  PROBE_RES,
  NU1, /* ......................*/
  NU2, /* 0110, 0111 not used */
  BEACON,
  ATIM,
  DISASSOCIATION,
  AUTHENTICATION,
  DEAUTHENTICATION,
  ACTION,
  ACTION_NACK,
} wifi_mgmt_subtypes_t;

typedef enum {
  CTRL_WRAPPER = 7,
  BLOCK_ACK = 8,
  BLOCK_ACK_REQ = 9,
  PS_POLL = 10,
  RTS = 11,
  CTS = 12,
  ACK_SUB = 13,
  CF_END = 14,
  CF_END_ACK = 15
} wifi_ctrl_subtypes_t;

typedef enum {
  DATA,
  DATA_CF_ACK,
  DATA_CF_POLL,
  DATA_CF_ACK_POLL,
  NULL_FRAME,
  CF_ACK,
  CF_POLL,
  CF_ACK_POLL,
  QOS_DATA,
  QOS_DATA_CF_ACK,
  QOS_DATA_CF_POLL,
  QOS_DATA_CF_ACK_POLL,
  QOS_NULL,
  QOS_CF_ACK,
  QOS_CF_POLL,
  QOS_CF_ACK_POLL
} wifi_data_subtypes_t;

/* ENCRYPTION */
typedef enum {
  ENC_OPEN,      // None
  ENC_WEP,       // Old WEP (insecure)
  ENC_WPA,       // WPA (Vendor Specific tag 0xdd)
  ENC_WPA2,      // WPA2 (RSN Element ID 0x30)
  ENC_WPA_WPA2,  // Both WPA e WPA2
  ENC_UNKNOWN
} wifi_encryption_t;

#endif