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
void generate_ecdsa_key(){
	TPMT_PUBLIC templ(TPM_ALG_ID::SHA256,
	TPMA_OBJECT::sign | TPMA_OBJECT::fixedParent | TPMA_OBJECT::fixedTPM
	  | TPMA_OBJECT::sensitiveDataOrigin | TPMA_OBJECT::userWithAuth, ByteVec(), TPMS_ECC_PARMS(TPMT_SYM_DEF_OBJECT(), TPMS_SCHEME_ECDSA(TPM_ALG_ID::SHA256), TPM_ECC_CURVE::NIST_P256, TPMS_NULL_KDF_SCHEME()), TPMS_ECC_POINT());


	ByteVec userAuth = { 1, 2, 3, 4 };
    TPMS_SENSITIVE_CREATE sensCreate(userAuth, ByteVec());

    // Create the key (no PCR-state captured)
    auto newPrimary = tpm.CreatePrimary(TPM_RH::OWNER, sensCreate, templ, ByteVec(), vector<TpmCpp::TPMS_PCR_SELECTION>());

    // if (!tpm._LastCommandSucceeded())
    // {
    //     // Some TPMs only allow primary keys of no lower than a particular strength.
    //     _ASSERT(tpm._GetLastResponseCode() == TPM_RC::VALUE);
    //     newPrimary = tpm.CreatePrimary(TPM_RH::OWNER, sensCreate, templ, ByteVec(), vector<TpmCpp::TPMS_PCR_SELECTION>());
    // }

    cout << "New ECDSA primary key" << endl << newPrimary.outPublic.ToString(false) << endl;
    TPM_HANDLE& signKey = newPrimary.handle;
    signKey.SetAuth(userAuth);

    TPM_HASH dataToSign = TPM_HASH::FromHashOfString(TPM_ALG_ID::SHA256, "abc");

    auto sig = tpm.Sign(signKey, dataToSign, TPMS_NULL_SIG_SCHEME(), TPMT_TK_HASHCHECK());
    cout << "Data to be signed:" << dataToSign.digest << endl;
    cout << "Signature:" << endl << sig->ToString(false) << endl;
}
void generate_rsa_key() {
    TPMT_PUBLIC templ(TPM_ALG_ID::SHA1,
        TPMA_OBJECT::sign | TPMA_OBJECT::fixedParent | TPMA_OBJECT::fixedTPM
        | TPMA_OBJECT::sensitiveDataOrigin | TPMA_OBJECT::userWithAuth,
        ByteVec(), TPMS_RSA_PARMS(TPMT_SYM_DEF_OBJECT(), TPMS_SCHEME_RSASSA(TPM_ALG_ID::SHA256), 1024, 65537), TPM2B_PUBLIC_KEY_RSA());

    // Set the use-auth for the nex key. Note the second parameter is
    // NULL because we are asking the TPM to create a new key.
    ByteVec userAuth = { 1, 2, 3, 4 };
    TPMS_SENSITIVE_CREATE sensCreate(userAuth, ByteVec());

    // Create the key (no PCR-state captured)
    auto newPrimary = tpm._AllowErrors()
        .CreatePrimary(TPM_RH::OWNER, sensCreate, templ, ByteVec(), vector<TPMS_PCR_SELECTION>());
    if (!tpm._LastCommandSucceeded())
    {
        // Some TPMs only allow primary keys of no lower than a particular strength.
        _ASSERT(tpm._GetLastResponseCode() == TPM_RC::VALUE);
        dynamic_cast<TPMS_RSA_PARMS*>(&*templ.parameters)->keyBits = 2048;
        newPrimary = tpm.CreatePrimary(TPM_RH::OWNER, sensCreate, templ, ByteVec(), vector<TPMS_PCR_SELECTION>());
    }

    // Print out the public data for the new key. Note the parameter to
    // ToString() "pretty-prints" the byte-arrays.
    cout << "New RSA primary key" << endl << newPrimary.outPublic.ToString(false) << endl;
    cout << "Returned by TPM " << newPrimary.name << endl;

    TPM_HANDLE& signKey = newPrimary.handle;
    signKey.SetAuth(userAuth);

    TPM_HASH dataToSign = TPM_HASH::FromHashOfString(TPM_ALG_ID::SHA256, "abc");

    auto sig = tpm.Sign(signKey, dataToSign, TPMS_NULL_SIG_SCHEME(), TPMT_TK_HASHCHECK());
    cout << "Data to be signed:" << dataToSign.digest << endl;
    cout << "Signature:" << endl << sig->ToString(false) << endl;

    // // We can put the primary key into NV with EvictControl
    // TPM_HANDLE persistentHandle = TPM_HANDLE::Persistent(1000);

    // // First delete anything that might already be there
    // tpm._AllowErrors().EvictControl(TPM_RH::OWNER, persistentHandle, persistentHandle);

    // // Make our primary persistent
    // tpm.EvictControl(TPM_RH::OWNER, newPrimary.handle, persistentHandle);

    // // Flush the old one
    // tpm.FlushContext(newPrimary.handle);

    // // ReadPublic of the new persistent one
    // auto persistentPub = tpm.ReadPublic(persistentHandle);
    // cout << "Public part of persistent primary" << endl << persistentPub.ToString(false);

    // // And delete it
    // tpm.EvictControl(TPM_RH::OWNER, persistentHandle, persistentHandle);

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
    generate_ecdsa_key();
    cout<<"\n";
    // And shut down the TPM
    tpm.Shutdown(TPM_SU::CLEAR);
    device.PowerOff();
    return 0;
}
