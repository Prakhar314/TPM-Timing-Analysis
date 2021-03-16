// TPMTest1.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <string>
#include <fstream>
#include <iterator>
#include <vector>
#include "stdafx.h"
#include "Tpm2.h"

using namespace std;
using namespace TpmCpp;

Tpm2 tpm;

ByteVec getBlobHash(string filename) {
    //input as char vec
    ifstream input(filename, ios::binary);
    vector<char> blob(
        (istreambuf_iterator<char>(input)),
        (istreambuf_iterator<char>()));
    input.close();

    //make prefix
    int si = blob.size();
    stringstream ss;
    ss << "blob " << si;
    string prefix = ss.str();

    //make byte vec from prefix char vec
    ByteVec bytes(prefix.begin(), prefix.end());
    bytes.push_back('\0');
    bytes.insert(bytes.end(), blob.begin(), blob.end());
    //cout << bytes << endl;
    //get SHA1 hash
    HashResponse h = tpm.Hash(bytes, TPM_ALG_ID::SHA1, TPM_RH_NULL);
    return h.outHash;
}

int main(int argc, char* argv[])
{
    TpmTcpDevice device;
    if (!device.Connect("127.0.0.1", 2321)) {
        cerr << "Could not connect to the TPM device";
        return 0;
    }
    // Create a Tpm2 object "on top" of the device.
    tpm._SetDevice(device);
    // startup cycle
    device.PowerOff();
    device.PowerOn();
    tpm.Startup(TPM_SU::CLEAR);

    // Get blob hash
    //cout << argv[1] << endl;

    cout << getBlobHash(argv[1]) << endl;
    // And shut down the TPM
    tpm.Shutdown(TPM_SU::CLEAR);
    device.PowerOff();
    return 0;
}
