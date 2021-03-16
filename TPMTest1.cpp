// TPMTest1.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include "stdafx.h"
#include "Tpm2.h"

using namespace std;
using namespace TpmCpp;

int main()
{
    TpmTcpDevice device;
    if (!device.Connect("127.0.0.1", 2321)) {
        cerr << "Could not connect to the TPM device";
        return 0;
    }
    // Create a Tpm2 object "on top" of the device.
    Tpm2 tpm(device);
    // When talking to the simulator you must perform some of the startup
    // functions that would normally happen automatically or be done by
    // the BIOS (note: PowerOff does nothing if the TPM is already powered
    // off, but let’s this sample run whatever the state of the TPM.)
    device.PowerOff();
    device.PowerOn();
    tpm.Startup(TPM_SU::CLEAR);
    // Get 20 bytes of random data
    std::vector<BYTE> rand = tpm.GetRandom(20);
    // And print it out.
    cout << "Random bytes: " << rand << endl;
    // And shut down the TPM
    tpm.Shutdown(TPM_SU::CLEAR);
    device.PowerOff();
    return 0;
}

// Run program: Ctrl + F5 or Debug > Start Without Debugging menu
// Debug program: F5 or Debug > Start Debugging menu

// Tips for Getting Started: 
//   1. Use the Solution Explorer window to add/manage files
//   2. Use the Team Explorer window to connect to source control
//   3. Use the Output window to see build output and other messages
//   4. Use the Error List window to view errors
//   5. Go to Project > Add New Item to create new code files, or Project > Add Existing Item to add existing code files to the project
//   6. In the future, to open this project again, go to File > Open > Project and select the .sln file
