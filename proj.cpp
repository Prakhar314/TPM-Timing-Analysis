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

    int times[] = {0,0,0,0,0};
    vector<int> tests = {16,512,1024};
    int iterations = 1000;
    for(int i = 0 ; i < iterations;i++){

        int start_time = getTime();
        tpm.ReadClock();
        times[0] += (getTime() - start_time);

        start_time = getTime();
        tpm.PCR_Read({}).pcrValues;
        times[1] += (getTime() - start_time);
        
        for(int tn = 0;tn<(int)tests.size();tn++){
            auto b = tests[tn];
            ByteVec bytes = Crypto::GetRand(b);
            start_time = getTime();
            tpm.Hash(bytes,TPM_ALG_ID::SHA256,TPM_RH_NULL).outHash;
            times[tn+2] += (getTime() - start_time);
        }
    }
    cout << 1.0*times[0]/iterations << "\t" << 1.0*times[1]/iterations << "\t" << 1.0*times[2]/iterations << "\t" << 1.0*times[3]/iterations<<"\t"<< 1.0*times[4]/iterations << "\t" << endl;
    return 0;
}