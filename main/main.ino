//ESP8266_Network_Fingerprint_Deauther
/* --- LIBS --- */
#include <ESP8266WiFi.h> ///SDK VERSION: 2.2.2
extern "C"{
  #include <user_interface.h> //Including NON-OS SDJ API
}
#include "include/data_structures.h"
#include "include/sniffer.h"
#include "include/deauther.h"
#include <string>

typedef enum {
  SNIFF = 0,
  DEAUTH,
  PING,
  INFO,
  ACK,
  ERR,
} CMD;

typedef enum {
  STOP = 0,
  START,
  FETCH
} ARG;

/* --- FUNCTIONS FIRMS ---*/
void ICACHE_FLASH_ATTR send_device_fingerprint();
void ICACHE_FLASH_ATTR send_status();
void ICACHE_FLASH_ATTR send_ack();
void ICACHE_FLASH_ATTR send_err();
void ICACHE_FLASH_ATTR send_info();

/* --- FUNCTIONS IMPLEMENTATION---*/
void ICACHE_FLASH_ATTR setup() {
  Serial.begin(115200);                 
  delay(1000);
}

void ICACHE_FLASH_ATTR loop() {
    if(Serial.available()){
      int cmd = Serial.read();  //First  byte: COMMANDS
      int arg = Serial.read();  //Second byte: ARGUMENTS
      switch(cmd){
        case SNIFF:
          switch(arg){
            case START: sniff_start(); send_ack(); break;
            case STOP:  sniff_stop();  send_ack(); break;
            case FETCH: send_device_fingerprint(); break;
            default:    send_err();                break;
          } break;
        case DEAUTH:
          switch(arg){
            case START:{
            uint8_t target_channel;
            uint8_t source[6];
            uint8_t dest[6];
            target_channel = Serial.read();
            for(int i=0; i<6; i++) source[i] = Serial.read();
            for(int i=0; i<6; i++) dest[i]   = Serial.read();
            deauth_start(target_channel, source, dest);
            } send_ack(); break;
            case STOP: deauth_stop(); send_ack(); break;
            default:   send_err();                break;
          } break;
        case PING: send_ack();  break;
        case INFO: send_info(); break;
        default: break;
      }
    }
    delay(500);
}

void ICACHE_FLASH_ATTR send_info(){
  Serial.write((uint8_t) status_sniff  & 0x01);
  Serial.write((uint8_t) status_deauth & 0x01);
  Serial.flush();
}

void ICACHE_FLASH_ATTR send_device_fingerprint() {
  ///TODO: HUGE PROBLEM, IF A NEW DISCOVER HAPPEN DURING THE STAMP
  Serial.flush();
  Serial.write((uint8_t) APs.size() & 0xff);// Send number of APs
  if(APs.size()) for (const auto& ap : APs) {
    Serial.write(ap.rssi);
    Serial.write((uint8_t) strlen(ap.ssid));
    Serial.write((uint8_t*)ap.ssid, strlen(ap.ssid));
    Serial.write(ap.mac, 6);
    Serial.write(ap.bssid, 6);
    Serial.write(ap.channel);
    Serial.write(ap.data_channel);
    Serial.write(highByte(ap.capability_info));   // MSB (Most Significant Byte)
    Serial.write(lowByte(ap.capability_info));    // LSB (Least Significant Byte)
    Serial.write((uint8_t)ap.encryption);
    Serial.flush();
    Serial.write((uint8_t) ap.linked_sta.size() & 0xff); // Send number of linked STAs for this APs
    if(ap.linked_sta.size()){
      for (const auto& sta : ap.linked_sta) if (sta) Serial.write(sta->mac, 6); // Send the MAC address of the linked STA
    }
    Serial.flush();
  }
  Serial.flush();
  Serial.write((uint8_t) STAs.size() & 0xff);// Send number of STAs
  if(STAs.size()) for (const auto& sta : STAs) { // Iterate through the actual STA objects in the global list
    Serial.write(sta.rssi);
    Serial.write(sta.mac, 6);
    Serial.write(sta.broadcast ? 1 : 0);
    Serial.write((uint8_t) strlen(sta.ssid_ap));
    Serial.write((uint8_t*)sta.ssid_ap, strlen(sta.ssid_ap));
    Serial.write(sta.channel);
    Serial.write(sta.data_channel);
    Serial.flush();
    Serial.write((uint8_t) sta.linked_ap.size()& 0xff); // Send number of linked APs for this STA
    if(sta.linked_ap.size()){
      for (const auto& ap : sta.linked_ap) if (ap) Serial.write(ap->mac, 6); // Send the MAC address of the linked AP
    }
    Serial.flush(); // Flush after sending linked APs
  }
}

void ICACHE_FLASH_ATTR send_ack(){ Serial.write(ACK); Serial.flush(); }
void ICACHE_FLASH_ATTR send_err(){ Serial.write(ERR); Serial.flush(); }