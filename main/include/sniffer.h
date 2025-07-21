#ifndef SNIFFER_H
#define SNIFFER_H

/* --- LIBS --- */
#include <list>
#include "data_structures.h"

using namespace std;

/* --- COSTANT --- */
#define TBTT 102.4                //Target Beacon Transmission Time 102.4 millis
#define MAX_CHANNEL 13            //number of channels
#define CH_HOP_PERIOD 3*TBTT      //FULL_SCAN_PERIOD = MAX_CHANNEL * CH_HOP_PERIOD

/* --- GLOBAL VARIABLES --- */
extern bool status_sniff;
extern list<AP_fingerprint_t> APs;
extern list<STA_fingerprint_t> STAs;

/* --- FUNCITON FIRMS --- */
void ICACHE_FLASH_ATTR sniff_start();
void ICACHE_FLASH_ATTR sniff_stop();

#endif