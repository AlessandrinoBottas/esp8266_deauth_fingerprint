#ifndef DEAUTHER_H
#define DEAUTHER_H

#include "data_structures.h"
#include "wifi_ieee_802_11_enums.h"
extern "C"{
  #include <user_interface.h> //Including NON-OS SDJ API
}

//DEAUTH REASON CODE (usually used) https://dox.ipxe.org/group__ieee80211__reason.html#gacbbb8855faa3867e2e7f9749d1e6cd32
#define IEEE80211_REASON_BAD_POWER 10
#define IEEE80211_REASON_AUTH_NO_LONGER_VALID   2

#define CH_DEAUTH_PERIOD 50
#define BURST 5

/* --- GLOBAL VARIABLES --- */
extern bool status_deauth;

/* --- FUNCITON FIRMS --- */
void ICACHE_FLASH_ATTR deauth_start(uint8_t ch, uint8_t *source, uint8_t *dest);
void ICACHE_FLASH_ATTR deauth_stop();

#endif