// TPMTest1.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <string>
#include <fstream>
#include <iterator>
#include <vector>
#include <chrono>
#include "stdafx.h"
#include "Tpm2.h"

using namespace std;
using namespace TpmCpp;

Tpm2 tpm;
TpmTcpDevice device;


void write_csv(vector<long long> points, string fileout) {
    ofstream OutFile(fileout);
    for (auto i : points) {
        OutFile << i << "\n";
    }
    OutFile.close();
}
void InitTpm() {
    if (!device.Connect()) {
        cerr << "Could not connect to the TPM device";
        return;
    }
    tpm._SetDevice(device);
}
void InitTpmSim() {
    // Connect the Tpm2 device to a simulator running on the same machine
    if (!device.Connect("127.0.0.1", 2321)) {
        cerr << "Could not connect to the TPM device";
        return;
    }

    // Instruct the Tpm2 object to send commands to the local TPM simulator
    tpm._SetDevice(device);

    // Power-cycle the simulator
    device.PowerOff();
    device.PowerOn();

    // And startup the TPM
    tpm.Startup(TPM_SU::CLEAR);

    return;

}
vector<long long> sign_multiple(TPM_HANDLE signKey, int iterations) {
    
   
    vector<long long> res;
    for (int i = 0; i < iterations; i++) {
        ostringstream oss;
        oss << "print";
        TPM_HASH dataToSign = TPM_HASH::FromHashOfString(TPM_ALG_ID::SHA256, oss.str());

   

        auto sig = tpm.Sign(signKey, dataToSign, TPMS_NULL_SIG_SCHEME(), TPMT_TK_HASHCHECK());
        //cout << "Data to be signed:" << dataToSign.digest << endl;
        cout << "Signature:" << endl << sig->ToString(false) << endl; 



        if (i % 1000 == 0) {
            cout << 1.0 * i / iterations * 100 <<"%"<< endl;
        }
    }
    return res;
}

void validate_sig() {
    TpmTbsDevice device;
    if (!device.Connect()) {
        cerr << "Could not connect to the TPM device";
    }
    Tpm2 tpm(device);

    TPMT_PUBLIC templ(TPM_ALG_ID::SHA256,
        TPMA_OBJECT::sign | TPMA_OBJECT::fixedParent | TPMA_OBJECT::fixedTPM
        | TPMA_OBJECT::sensitiveDataOrigin | TPMA_OBJECT::userWithAuth, ByteVec(), TPMS_ECC_PARMS(TPMT_SYM_DEF_OBJECT(), TPMS_SCHEME_ECDSA(TPM_ALG_ID::SHA256), TPM_ECC_CURVE::NIST_P256, TPMS_NULL_KDF_SCHEME()), TPMS_ECC_POINT());


    ByteVec userAuth = { 1, 2, 3, 4 };
    TPMS_SENSITIVE_CREATE sensCreate(userAuth, ByteVec());

    auto newPrimary = tpm.CreatePrimary(TPM_RH::OWNER, sensCreate, templ, ByteVec(), vector<TpmCpp::TPMS_PCR_SELECTION>());

    
    TPM_HANDLE& signKey = newPrimary.handle;
    signKey.SetAuth(userAuth);
    TPM_HASH dataToSign = TPM_HASH::FromHashOfString(TPM_ALG_ID::SHA256, "data to sign");
    auto sig = tpm.Sign(signKey, dataToSign, TPMS_NULL_SIG_SCHEME(), TPMT_TK_HASHCHECK());

    cout << "Data to be signed:" << dataToSign.digest << endl;
    cout << "Signature:" << endl << sig->ToString(false) << endl;

    auto sigVerify = tpm._AllowErrors().VerifySignature(signKey, dataToSign, *sig);
    if (tpm._LastCommandSucceeded())
        cout << "Signature verification succeeded" << endl;
}

vector<long long> generate_ecdsa_key(int iterations) {
    TpmTbsDevice device;
    if (!device.Connect()) {
        cerr << "Could not connect to the TPM device";
    }
    Tpm2 tpm(device);
   
    TPMT_PUBLIC templ(TPM_ALG_ID::SHA256,
        TPMA_OBJECT::sign | TPMA_OBJECT::fixedParent | TPMA_OBJECT::fixedTPM
        | TPMA_OBJECT::sensitiveDataOrigin | TPMA_OBJECT::userWithAuth, ByteVec(), TPMS_ECC_PARMS(TPMT_SYM_DEF_OBJECT(), TPMS_SCHEME_ECDSA(TPM_ALG_ID::SHA256), TPM_ECC_CURVE::NIST_P256, TPMS_NULL_KDF_SCHEME()), TPMS_ECC_POINT());


    ByteVec userAuth = { 1, 2, 3, 4 };
    TPMS_SENSITIVE_CREATE sensCreate(userAuth, ByteVec());

    // Create the key (no PCR-state captured)
    auto newPrimary = tpm.CreatePrimary(TPM_RH::OWNER, sensCreate, templ, ByteVec(), vector<TpmCpp::TPMS_PCR_SELECTION>());

    cout << "New ECDSA primary key" << endl << newPrimary.outPublic.ToString(false) << endl;
    TPM_HANDLE& signKey = newPrimary.handle;
    signKey.SetAuth(userAuth);
    TPM_HASH dataToSign = TPM_HASH::FromHashOfString(TPM_ALG_ID::SHA256, "data to sign");
    vector<long long> res;
    for (int i = 0; i < iterations; i++) {
        
        auto a = tpm.ReadClock().time;

        auto sig = tpm.Sign(signKey, dataToSign, TPMS_NULL_SIG_SCHEME(), TPMT_TK_HASHCHECK());

        auto b = tpm.ReadClock().time;

        res.push_back(b - a);
        if (i % 100 == 0) {
            cout << 1.0 * i / iterations * 100 <<"%"<< endl;
        }
    }
    return res;
    
    // Get blob hash
    //cout << argv[1] << endl;
    
    // And shut down the TPM
    // sign_multiple(signKey, 100);
    
}


int main(int argc, char* argv[])
{
    write_csv(generate_ecdsa_key(10000), "out.csv");
    
    // validate_sig();
    cout << "\n";
    return 0;
}
