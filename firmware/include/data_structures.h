#ifndef DATA_STRUCTURES_H
#define DATA_STRUCTURES_H

/* --- LIBS --- */
#include <stdint.h>
#include <vector>
#include "wifi_ieee_802_11_enums.h"

/* --- COSTANT --- */
#define SSID_MAX_LEN 33

using namespace std;

/* --- FORWARD DECLARATIONS --- */
typedef struct STA_fingerprint_t STA_fingerprint_t;
typedef struct AP_fingerprint_t  AP_fingerprint_t;

/* --- FINGERPRINT TYPES --- */
struct AP_fingerprint_t{
  int8_t rssi;
	char ssid[SSID_MAX_LEN];
  uint8_t mac[6];           // addr2 (di solito uguale a bssid)
	uint8_t bssid[6];         // addr3
  uint8_t channel;          // For sniffed MGMT pkt
  uint8_t data_channel;     // For sniffed DATA pkt
	uint16_t capability_info; // For more credible SPOOFING!?!?!?!?!
  uint8_t vendor_oui[3];    //could be really interesting
	wifi_encryption_t encryption;
  std::vector<STA_fingerprint_t*> linked_sta;  //array connected STAs
};

struct STA_fingerprint_t {
  int8_t rssi;
  uint8_t mac[6];         // STA MAC (addr2)
  bool broadcast;         // true if ssid_len = 0 in probe request
  char ssid_ap[33];       // Rete cercata (se presente)
  uint8_t channel;        // For sniffed MGMT pkt
  uint8_t data_channel;   // For sniffed DATA pkt
  std::vector<AP_fingerprint_t*> linked_ap;   //array of the connected APs
};

/* --- WiFi IEEE 802.11 FRAME STRUCTURES ---*/
//Frame control
typedef struct __attribute__((packed)){
  unsigned protocol:2;
  unsigned type:2;
  unsigned subtype:4;
  unsigned to_ds:1;
  unsigned from_ds:1;
  unsigned more_frag:1;
  unsigned retry:1;
  unsigned pwr_mgmt:1;
  unsigned more_data:1;
  unsigned wep:1;
  unsigned strict:1;
} wifi_hdr_frame_control_t;

//MGMT & DATA Header essential fields ieee 802.11
typedef struct __attribute__((packed)){
  wifi_hdr_frame_control_t frame_ctrl;
  uint16_t duration_id; 
  uint8_t addr1[6]; // receiver address
  uint8_t addr2[6]; // sender address
  uint8_t addr3[6]; // filtering address
  uint16_t sequence_ctrl;
} wifi_ieee80211_mac_hdr_t;

/*
===================================
 from ESPE8266 TECHNICAL REFERENCE
===================================
*/
#define HDR_MGMT_LEN sizeof(wifi_ieee80211_mac_hdr_t)
#define FRAME_LEN 112   //CIT from DOC :(  "may be 240, please refer to the real source code"

typedef struct __attribute__((packed)){
  signed rssi: 8;
  unsigned rate: 4;
  unsigned is_group: 1;
  unsigned : 1;
  unsigned sig_mode: 2;
  unsigned legacy_length: 12;
  unsigned damatch0: 1;
  unsigned damatch1: 1;
  unsigned bssidmatch0: 1;
  unsigned bssidmatch1: 1;
  unsigned MCS: 7;
  unsigned CWB: 1;
  unsigned HT_length: 16;
  unsigned Smoothing: 1;
  unsigned Not_Sounding: 1;
  unsigned : 1;
  unsigned Aggregation: 1;
  unsigned STBC: 2;
  unsigned FEC_CODING: 1;
  unsigned SGI: 1;
  unsigned rxend_state: 8;
  unsigned ampdu_cnt: 8;
  unsigned channel: 4;
  unsigned : 12;
} RxControl;

//AKA sniffer_buf2 in ESP8266 Technical Reference
typedef struct{
  RxControl rx_ctrl;
  wifi_ieee80211_mac_hdr_t mac_hdr;
  uint8_t buf[FRAME_LEN - HDR_MGMT_LEN];     
  uint16_t cnt;
  uint16_t len;       //true length of packet
} mgmt_pkt_t;

#endif