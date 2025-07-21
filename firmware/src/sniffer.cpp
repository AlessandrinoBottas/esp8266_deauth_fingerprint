  /* --- MACROS --- */
  #define MIN(a,b) ((a) < (b) ? (a) : (b))

  /* --- LIBS --- */
  #include <ESP8266WiFi.h>
  #include <string.h>
  #include "../include/wifi_ieee_802_11_enums.h"
  #include "../include/sniffer.h"
  extern "C"{
    #include <user_interface.h> //Including NON-OS SDJ API
  }

  using namespace std;

  /* --- GLOBAL VARIABLES --- */
  bool status_sniff = false;
  list<AP_fingerprint_t> APs;
  list<STA_fingerprint_t> STAs;
  os_timer_t channel_hop_timer;
  uint8_t    current_channel = 1;

  /* --- FUNCITON FIRMS --- */
  //SNIFFER operation handlers
  void ICACHE_FLASH_ATTR sniff_start();
  void ICACHE_FLASH_ATTR sniff_stop();
  void ICACHE_RAM_ATTR channel_hop_cb(void *arg);
  void ICACHE_RAM_ATTR sniffer_callback(uint8_t *buf, uint16_t len);

  //PARSER mgmt pkt
  void ICACHE_RAM_ATTR parse_beacon(uint8_t *buf, uint16_t len);
  void ICACHE_RAM_ATTR parse_probe_response(uint8_t *buf, uint16_t len);
  void ICACHE_RAM_ATTR parse_probe_request(uint8_t *buf, uint16_t len);
  void ICACHE_RAM_ATTR parse_action(uint8_t *buf);
  //PARSER data pkt
  void ICACHE_RAM_ATTR parse_data_pkt(uint8_t *pkt);
  //Linking operation
  void ICACHE_RAM_ATTR linking(uint8_t *addr1, uint8_t *addr2, bool to_DS, bool from_DS);


  /* --- FUNCTIONS IMPLEMENTATION---*/
void ICACHE_RAM_ATTR channel_hop_cb(void *arg) {
  current_channel = (current_channel % MAX_CHANNEL) + 1;
  wifi_set_channel(current_channel);
}

void ICACHE_FLASH_ATTR sniff_start(){
  if(!STAs.empty()) STAs.clear();
  if(!APs.empty())  APs.clear(); 
  current_channel = 1;
  //Setup STATION_MODE for sniffing
  wifi_set_opmode(STATION_MODE);
  ///SNIFF: enable promiscous mode and setting up callback function
  wifi_promiscuous_enable(false);
  wifi_set_promiscuous_rx_cb(sniffer_callback);
  wifi_set_channel(current_channel);
  wifi_promiscuous_enable(true);
  ///HOOPING: setup timer for channel hooping
  os_timer_disarm(&channel_hop_timer);
  os_timer_setfn(&channel_hop_timer, (os_timer_func_t *)channel_hop_cb, NULL);
  os_timer_arm(&channel_hop_timer, CH_HOP_PERIOD, true);  // true = repeat
  status_sniff = true;
}

void ICACHE_FLASH_ATTR sniff_stop(){
  os_timer_disarm(&channel_hop_timer);
  status_sniff = false;
}

void ICACHE_RAM_ATTR sniffer_callback(uint8_t *buf, uint16_t len) {
  if(len <= sizeof(RxControl)) return;//CORRUPTED packet: only metadata

  RxControl* rx = (RxControl*) buf;
  
  if (rx->rssi < -75) return; //FILTER from RSSI packets too weak

  //Fast extracting type e subtype
  uint8_t *pkt = buf + sizeof(RxControl);
  uint8_t fc = pkt[0];                  //first half of frame control
  uint8_t type = (fc >> 2) & 0x03;
  uint8_t subtype = (fc >> 4) & 0x0F;

  switch (type) {
    case WIFI_PKT_MGMT:
      switch (subtype) {
        case PROBE_REQ:   parse_probe_request(buf, len); break;
        case PROBE_RES:   parse_probe_response(buf, len); break;
        case BEACON:      parse_beacon(buf, len);         break;
        case ACTION:      parse_action(buf);              break;
        case ACTION_NACK: parse_action(buf);              break;
        default: break;
      } break;
    /* SAVE SOME MEMORY :)
    case WIFI_PKT_CTRL:
      switch (subtype) {
        case CTRL_WRAPPER:  break;
        case BLOCK_ACK:     break;
        case BLOCK_ACK_REQ: break;
        case PS_POLL:       break;
        case RTS:           break;
        case CTS:           break;
        case ACK:           break;
        case CF_END:        break;
        case CF_END_ACK:    break;
      } break;
    */
    case WIFI_PKT_DATA:
      switch (subtype) {
        case DATA:
        case NULL_FRAME:
        case QOS_DATA:
        case QOS_NULL:
          parse_data_pkt(pkt);
        default: break;
      } break;

  }
}

void ICACHE_RAM_ATTR parse_data_pkt(uint8_t *pkt){
  uint8_t fc0 = pkt[0];   //first  half of FRAME CONTROL
  uint8_t fc1 = pkt[1];   //second half of FRAME CONTROL

  bool to_DS   = (fc1 & 0x01);
  bool from_DS = (fc1 & 0x02) >> 1;
  uint8_t *addr1 = pkt + 4;   // Destination
  uint8_t *addr2 = pkt + 10;  // Source

  linking(addr1, addr2, to_DS, from_DS);
}

void ICACHE_RAM_ATTR parse_probe_request(uint8_t *buf, uint16_t len){
  RxControl* rx = (RxControl*) buf;
  mgmt_pkt_t* mgmt_pkt = (mgmt_pkt_t*) buf;
  wifi_ieee80211_mac_hdr_t *hdr = &mgmt_pkt->mac_hdr;
  uint8_t *frame_body = mgmt_pkt->buf;

  ///Checking for duplicates
  STA_fingerprint_t *existing_sta = NULL;
  if(!STAs.empty()) {
    for(auto it = STAs.begin(); it != STAs.end(); ++it) { 
      if( !memcmp(hdr->addr2, it->mac, sizeof(hdr->addr2)) ){ 
        existing_sta = &(*it);
        break;
      }
    }
  }

  if (existing_sta) {
      existing_sta->channel = current_channel;
      existing_sta->rssi = rx->rssi;
      return;
  }

  STA_fingerprint_t new_sta_data = {0}; // Create a temporary STA struct for data
  new_sta_data.rssi = rx->rssi;
  new_sta_data.channel = current_channel;
  memcpy(new_sta_data.mac, hdr->addr2, sizeof(new_sta_data.mac));  //STA MAC addr
  new_sta_data.broadcast = true;
  strcpy(new_sta_data.ssid_ap, "<broadcast>");
  ///SSID of AP looking for
  uint8_t i = 0;
  uint8_t validLength = MIN(FRAME_LEN, mgmt_pkt->len);
  while( (i < validLength) && (i+2+frame_body[i+1] < validLength) ){
    if(frame_body[i] == 0x00 && frame_body[i+1] != 0){
      new_sta_data.broadcast = false;
      memcpy(new_sta_data.ssid_ap, &frame_body[i+2], frame_body[i+1]);
      new_sta_data.ssid_ap[frame_body[i+1]] = '\0';
    }
    i+= 2 + frame_body[i+1];
  }
  STAs.push_back(new_sta_data);
}

void ICACHE_RAM_ATTR parse_probe_response(uint8_t *buf, uint16_t len){
  RxControl* rx = (RxControl*) buf;
  mgmt_pkt_t* mgmt_pkt = (mgmt_pkt_t*) buf;
  wifi_ieee80211_mac_hdr_t *hdr = &mgmt_pkt->mac_hdr;
  uint8_t *frame_body = mgmt_pkt->buf;

  ///Checking for duplicates
  AP_fingerprint_t *existing_ap = NULL;
  if(!APs.empty()) {
      for(auto it = APs.begin(); it != APs.end(); ++it) { //
          if( !memcmp(hdr->addr2, it->mac, sizeof(hdr->addr2)) ){ //
              existing_ap = &(*it); // Get pointer to the element
              break; //
          }
      }
  }

  if (existing_ap) {
      existing_ap->channel = current_channel;
      existing_ap->rssi = rx->rssi;
      return;
  }
  
  bool has_rsn = false;
  bool has_wpa = false;
  
  AP_fingerprint_t new_ap_data = {0}; // Create temporary for data

  new_ap_data.channel = current_channel;
  new_ap_data.rssi    = rx->rssi;
  memcpy(&new_ap_data.capability_info, frame_body + 10, sizeof(uint16_t));
  memcpy(new_ap_data.mac  , hdr->addr2, sizeof(hdr->addr2));
  memcpy(new_ap_data.bssid, hdr->addr3, sizeof(hdr->addr3));

  uint8_t validLength = MIN(FRAME_LEN, mgmt_pkt->len);
  uint16_t i = 12; //jump timestamp, beacon interval, cap info
  new_ap_data.ssid[0] = '\0';
  

  while( (i < validLength) && (i+2+frame_body[i+1] < validLength) ){
    switch(frame_body[i]){
      //Looking for SSID
      case 0x00:
        if(frame_body[i+1] != 0){
          memcpy(new_ap_data.ssid, &frame_body[i+2], frame_body[i+1]);
          new_ap_data.ssid[frame_body[i+1]] = '\0';
        } break;
      //channel
      case 0x03:
        if(frame_body[i+1] == 1){
          new_ap_data.channel = frame_body[i+2];
        } break;
      //WPA2 → RSN tag
      case 0x30: has_rsn = true; break;
      //Vendor Specific (0xdd) - gestisce sia Vendor OUI che WPA
      case 0xdd:
        if(frame_body[i+1] >= 3){
          if(frame_body[i+1] >= 4 && 
            frame_body[i+2] == 0x00 && 
            frame_body[i+3] == 0x50 && 
            frame_body[i+4] == 0xF2){ has_wpa = true;}
        } break;
    }
    i+= 2 + frame_body[i+1];
  }

  if(has_rsn && has_wpa)             new_ap_data.encryption = ENC_WPA_WPA2;
  else if(has_rsn)                   new_ap_data.encryption = ENC_WPA2;
  else if(has_wpa)                   new_ap_data.encryption = ENC_WPA;
  else if(new_ap_data.capability_info & 0x10) new_ap_data.encryption = ENC_WEP;
  else                               new_ap_data.encryption = ENC_OPEN;

  // Add the new AP to the global list. std::list::push_back adds a copy and doesn't invalidate existing pointers.
  APs.push_back(new_ap_data);
}

void ICACHE_RAM_ATTR parse_beacon(uint8_t *buf, uint16_t len){
  RxControl* rx = (RxControl*) buf;
  mgmt_pkt_t* mgmt_pkt = (mgmt_pkt_t*) buf;
  wifi_ieee80211_mac_hdr_t *hdr = &mgmt_pkt->mac_hdr;
  uint8_t *frame_body = mgmt_pkt->buf;
  
  ///Checking for duplicates
  // CHANGE: Iterate through std::list to find and update existing AP
  AP_fingerprint_t *existing_ap = NULL;
  if(!APs.empty()) {
      for(auto it = APs.begin(); it != APs.end(); ++it) { //
          if( !memcmp(hdr->addr2, it->mac, sizeof(hdr->addr2)) ){ //
              existing_ap = &(*it); // Get pointer to the element
              break; //
          }
      }
  }

  if (existing_ap) { // If AP found, update it and return
      existing_ap->channel = current_channel;
      existing_ap->rssi = rx->rssi;
      return; //
  }

  bool has_rsn = false;
  bool has_wpa = false;
  
  AP_fingerprint_t new_ap_data = {0}; // Create temporary for data

  new_ap_data.channel = current_channel;
  new_ap_data.rssi    = rx->rssi;
  memcpy(&new_ap_data.capability_info, frame_body + 10, sizeof(uint16_t));
  memcpy(new_ap_data.mac  , hdr->addr2, sizeof(hdr->addr2));
  memcpy(new_ap_data.bssid, hdr->addr3, sizeof(hdr->addr3));

  uint8_t validLength = MIN(FRAME_LEN, mgmt_pkt->len);
  uint16_t i = 12; //jump timestamp, beacon interval, cap info
  new_ap_data.ssid[0] = '\0';

   while( (i < validLength) && (i+2+frame_body[i+1] < validLength) ){
    switch(frame_body[i]){
      //Looking for SSID
      case 0x00:
        if(frame_body[i+1] != 0){
          memcpy(new_ap_data.ssid, &frame_body[i+2], frame_body[i+1]);
          new_ap_data.ssid[frame_body[i+1]] = '\0';
        } break;
      //Vendor OUI
      //channel
      case 0x03:
        if(frame_body[i+1] == 1){
          new_ap_data.channel = frame_body[i+2];
        } break;
      //WPA2 → RSN tag
      case 0x30:
        has_rsn = true;
        break;
      //Vendor Specific (0xdd) - gestisce sia Vendor OUI che WPA
      case 0xdd:
        if(frame_body[i+1] >= 3){
          // Always Vendor OUI - Note: vendor_oui commented out in struct
          // new_ap_data.vendor_oui[0] = frame_body[i+2];
          // new_ap_data.vendor_oui[1] = frame_body[i+3];
          // new_ap_data.vendor_oui[2] = frame_body[i+4];
          // Check if WPA (OUI 00:50:F2)
          if(frame_body[i+1] >= 4 && 
            frame_body[i+2] == 0x00 && 
            frame_body[i+3] == 0x50 && 
            frame_body[i+4] == 0xF2){
            has_wpa = true;
          }
        } break;
    }
    i+= 2 + frame_body[i+1];
  }

  if(has_rsn && has_wpa)             new_ap_data.encryption = ENC_WPA_WPA2;
  else if(has_rsn)                   new_ap_data.encryption = ENC_WPA2;
  else if(has_wpa)                   new_ap_data.encryption = ENC_WPA;
  else if(new_ap_data.capability_info & 0x10) new_ap_data.encryption = ENC_WEP;
  else                               new_ap_data.encryption = ENC_OPEN;

  // Add the new AP to the global list. std::list::push_back adds a copy and doesn't invalidate existing pointers.
  APs.push_back(new_ap_data);
}

void ICACHE_RAM_ATTR parse_action(uint8_t *buf){
  uint8_t fc0 = buf[0];   //first  half of FRAME CONTROL
  uint8_t fc1 = buf[1];   //second half of FRAME CONTROL

  bool to_DS   = (fc1 & 0x01);
  bool from_DS = (fc1 & 0x02) >> 1;
  uint8_t *addr1 = buf + 4;   // Destination
  uint8_t *addr2 = buf + 10;  // Source

  linking(addr1, addr2, to_DS, from_DS);
}

void ICACHE_RAM_ATTR linking(uint8_t *addr1, uint8_t *addr2, bool to_DS, bool from_DS){

  if(!from_DS && !to_DS)  return;   //Skip FOR NOW - peer2peer ad hoc network
  if(to_DS && from_DS)    return;   //Skip FOR NOW - WDS (AP to AP)

  uint8_t *sta_mac = NULL;
  uint8_t *ap_mac = NULL;

  if (to_DS && !from_DS) {
    sta_mac = addr2;  // Source STA
    ap_mac  =  addr1; // Destination AP
  }else if (!to_DS && from_DS) {
    ap_mac  = addr2;  // Source AP  
    sta_mac = addr1;  // Destination STA
  }

  // Searching if they exist in the global lists
  AP_fingerprint_t *ap_ptr = NULL;   // Pointer to AP instance
  STA_fingerprint_t *sta_ptr = NULL; // Pointer to STA instance
  if(!STAs.empty()) {
      for(auto it = STAs.begin(); it != STAs.end(); ++it) {
          if(!memcmp(it->mac, sta_mac, sizeof(it->mac))) {
              sta_ptr = &(*it);
              break;
          }
      }
  }
  if(!APs.empty()) {
      for(auto it = APs.begin(); it != APs.end(); ++it) {
          if(!memcmp(it->mac, ap_mac,  sizeof(it->mac))) {
              ap_ptr = &(*it);
              break;
          }
      }
  }

  if(ap_ptr == NULL && sta_ptr == NULL) return; // SHOULD WE SAVING THEM???

  if(ap_ptr && sta_ptr) { // Both AP and STA exist
    ap_ptr->data_channel = current_channel;
    sta_ptr->data_channel = current_channel;
    // Check if already linked from STA to AP to avoid duplicates in the linked_ap vector
    bool already_linked_sta_to_ap = false;
    for(auto linked_ap_ptr : sta_ptr->linked_ap) {
      if(linked_ap_ptr && !memcmp(linked_ap_ptr->bssid, ap_ptr->bssid, 6)) {
          already_linked_sta_to_ap = true;
          break;
      }
    }
    // Check if already linked from AP to STA to avoid duplicates in the linked_sta vector
    bool already_linked_ap_to_sta = false;
    for(auto linked_sta_ptr : ap_ptr->linked_sta) {
      if(linked_sta_ptr && !memcmp(linked_sta_ptr->mac, sta_ptr->mac, 6)) {
          already_linked_ap_to_sta = true;
          break;
      }
    }

    if(!already_linked_sta_to_ap) sta_ptr->linked_ap.push_back(ap_ptr);
    if(!already_linked_ap_to_sta) ap_ptr->linked_sta.push_back(sta_ptr);

  } else if (!ap_ptr && sta_ptr){ // STA found, AP not found (AP is new)
    sta_ptr->data_channel = current_channel;
    //creating new AP
    AP_fingerprint_t new_ap_data = {0}; // Temporary data container
    memcpy(new_ap_data.mac,   ap_mac, 6);
    memcpy(new_ap_data.bssid, ap_mac, 6);
    new_ap_data.data_channel = current_channel;
    strcpy(new_ap_data.ssid, "<DATA_ONLY>");
    APs.push_back(new_ap_data);
    AP_fingerprint_t *new_ap_ptr = &APs.back(); // Get pointer to the newly added AP
    // Linking (and checking for duplicates in the new AP's linked list)
    bool already_linked_sta_to_new_ap = false;
    for(auto linked_ap_ptr : sta_ptr->linked_ap) {
      if(linked_ap_ptr && !memcmp(linked_ap_ptr->bssid, new_ap_ptr->bssid, 6)) {
          already_linked_sta_to_new_ap = true;
          break;
      }
    }
    if(!already_linked_sta_to_new_ap) sta_ptr->linked_ap.push_back(new_ap_ptr);
    // Check for duplicates in the new AP's linked_sta vector
    bool already_linked_new_ap_to_sta = false;
    for(auto linked_sta_ptr : new_ap_ptr->linked_sta) {
      if(linked_sta_ptr && !memcmp(linked_sta_ptr->mac, sta_ptr->mac, 6)) {
          already_linked_new_ap_to_sta = true;
          break;
      }
    }

    if(!already_linked_new_ap_to_sta) new_ap_ptr->linked_sta.push_back(sta_ptr);

  } else if (ap_ptr && !sta_ptr){ // AP found, STA not found (STA is new)
    //creating new STA
    STA_fingerprint_t new_sta_data = {0}; // Temporary data container
    memcpy(new_sta_data.mac, sta_mac, 6);
    new_sta_data.broadcast = false;
    new_sta_data.data_channel = current_channel;
    STAs.push_back(new_sta_data);
    
    STA_fingerprint_t *new_sta_ptr = &STAs.back(); // Get pointer to the newly added STA
    
    // Linking (and checking for duplicates in the new STA's linked list)
    bool already_linked_new_sta_to_ap = false;
    for(auto linked_ap_ptr : new_sta_ptr->linked_ap) {
      if(linked_ap_ptr && !memcmp(linked_ap_ptr->bssid, ap_ptr->bssid, 6)) {
          already_linked_new_sta_to_ap = true;
          break;
      }
    }
    
    if(!already_linked_new_sta_to_ap) new_sta_ptr->linked_ap.push_back(ap_ptr);
    // Check for duplicates in the AP's linked_sta vector
    bool already_linked_ap_to_new_sta = false;
    for(auto linked_sta_ptr : ap_ptr->linked_sta) {
      if(linked_sta_ptr && !memcmp(linked_sta_ptr->mac, new_sta_ptr->mac, 6)) {
          already_linked_ap_to_new_sta = true;
          break;
      }
    }
    if(!already_linked_ap_to_new_sta) ap_ptr->linked_sta.push_back(new_sta_ptr);
  }
  return;
}
