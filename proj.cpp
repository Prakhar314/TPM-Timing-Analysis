// TPMTest1.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <string>
#include <fstream>
#include <iterator>
#include <vector>
#include <filesystem>
#include <chrono>
#include "stdafx.h"
#include "Tpm2.h"

using namespace std;
using namespace TpmCpp;
Tpm2 tpm;
TpmTbsDevice device;

int total_time_tpm_only = 0;
void connectTPM() {
    if (!device.Connect()) {
        cerr << "Could not connect to the TPM device";
        return;
    }

    // Create a Tpm2 object "on top" of the device.
    tpm._SetDevice(device);
}
int getTime(){
    return chrono::duration_cast<chrono::milliseconds>(chrono::system_clock::now().time_since_epoch()).count();
}
int main(){
    connectTPM();

    int start_time = getTime();
    for(int i = 0 ; i < 200;i++){
        tpm.PCR_Read(TPMS_PCR_SELECTION::GetSelectionArray(TPM_ALG_ID::SHA256,rand()%20)).pcrValues;
    }
    int total_time = (getTime() - start_time);
    cout << total_time/200.0 << "\t";

    vector<int> tests = {16,512,1024};
    for(auto b:tests){
        total_time = 0;
        for(int i = 0 ; i < 200;i++){
            ByteVec bytes = Crypto::GetRand(b);
            start_time = getTime();
            tpm.Hash(bytes,TPM_ALG_ID::SHA256,TPM_RH_NULL).outHash;
            total_time += (getTime() - start_time);
        }
        cout << total_time/200.0 << "\t";
    }
    cout << endl;
    return 0;
}