// TPMTest1.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <string>
#include <fstream>
#include <iterator>
#include <vector>
#include <intrin.h>
#include "stdafx.h"
#include "Tpm2.h"

using namespace std;
using namespace TpmCpp;

Tpm2 tpm;
TpmTcpDevice device;

void getBlobHash(string filename) {
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
    cout<< h.outHash<<endl;
}

void write_csv(vector<long long> points, string fileout) {
    ofstream OutFile(fileout);
    for (auto i : points) {
        OutFile << i << "\n";
    }
    OutFile.close();
}

vector<long long> sign_multiple(TPM_HANDLE signKey, int iterations) {

    vector<long long> res;
    TPM_HASH dataToSign = TPM_HASH::FromHashOfString(TPM_ALG_ID::SHA256, "data to sign");

    for (int i = 0; i < iterations; i++) {

        //auto a = tpm.ReadClock().time;
        auto a = __rdtsc();

        auto sig = tpm.Sign(signKey, dataToSign, TPMS_NULL_SIG_SCHEME(), TPMT_TK_HASHCHECK());
        //cout << "Data to be signed:" << dataToSign.digest << endl;
        //cout << "Signature:" << endl << sig->ToString(false) << endl; 

        //auto b = tpm.ReadClock().time;
        auto b = __rdtsc();

        res.push_back(b - a);
        if (i % 100 == 0) {
            cout << 1.0 * i / iterations * 100 << "%" << endl;
        }
    }
    return res;
}

template<class EC_SCHEME = TPMS_SIG_SCHEME_ECDSA>
TPM_HANDLE generate_ec_key(TPM_ECC_CURVE curveId = TPM_ECC_CURVE::NIST_P256) {
    TPMT_PUBLIC templ(TPM_ALG_ID::SHA256,
        TPMA_OBJECT::sign | TPMA_OBJECT::fixedParent | TPMA_OBJECT::fixedTPM
        | TPMA_OBJECT::sensitiveDataOrigin | TPMA_OBJECT::userWithAuth, ByteVec(), TPMS_ECC_PARMS(TPMT_SYM_DEF_OBJECT(), EC_SCHEME(TPM_ALG_ID::SHA256), curveId, TPMS_NULL_KDF_SCHEME()), TPMS_ECC_POINT());


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

    //cout << "New ECDSA primary key" << endl << newPrimary.outPublic.ToString(false) << endl;
    TPM_HANDLE& signKey = newPrimary.handle;
    signKey.SetAuth(userAuth);

    // And shut down the TPM
    // sign_multiple(signKey, 100);
    return signKey;
}

TPM_HANDLE generate_rsa_key() {
    TPMT_PUBLIC templ(TPM_ALG_ID::SHA1,
        TPMA_OBJECT::sign | TPMA_OBJECT::fixedParent | TPMA_OBJECT::fixedTPM
        | TPMA_OBJECT::sensitiveDataOrigin | TPMA_OBJECT::userWithAuth,
        ByteVec(), TPMS_RSA_PARMS(TPMT_SYM_DEF_OBJECT(), TPMS_SCHEME_RSASSA(TPM_ALG_ID::SHA256), 1024, 65537), TPM2B_PUBLIC_KEY_RSA());

    ByteVec userAuth = { 1, 2, 3, 4 };
    TPMS_SENSITIVE_CREATE sensCreate(userAuth, ByteVec());

    // Create the key (no PCR-state captured)
    auto newPrimary = tpm._AllowErrors()
        .CreatePrimary(TPM_RH::OWNER, sensCreate, templ, ByteVec(), vector<TPMS_PCR_SELECTION>());

    TPM_HANDLE& signKey = newPrimary.handle;
    signKey.SetAuth(userAuth);

    return signKey;
}

void write_to_file(string filename, ByteVec content) {
    ofstream  outFile(filename);
    outFile << content;
    outFile.close();
}

void write_to_file(string filename, string content) {
    ofstream  outFile(filename);
    outFile << content;
    outFile.close();
}


string read_from_file(string filename) {
    ifstream signFile(filename);
    stringstream buffer;
    buffer << signFile.rdbuf();
    signFile.close();
    return buffer.str();
}

void sign_message() {

    cout << "Enter message" << endl;
    string message;
    cin >> message;
    write_to_file("message.txt", message);

    TPMT_PUBLIC templ(TPM_ALG_ID::SHA256,
        TPMA_OBJECT::sign | TPMA_OBJECT::fixedParent | TPMA_OBJECT::fixedTPM
        | TPMA_OBJECT::sensitiveDataOrigin | TPMA_OBJECT::userWithAuth, ByteVec(), TPMS_ECC_PARMS(TPMT_SYM_DEF_OBJECT(), TPMS_SCHEME_ECDSA(TPM_ALG_ID::SHA256), TPM_ECC_CURVE::NIST_P256, TPMS_NULL_KDF_SCHEME()), TPMS_ECC_POINT());


    ByteVec userAuth = { 1, 2, 3, 4 };
    TPMS_SENSITIVE_CREATE sensCreate(userAuth, ByteVec());
    auto newPrimary = tpm.CreatePrimary(TPM_RH::OWNER, sensCreate, templ, ByteVec(), vector<TpmCpp::TPMS_PCR_SELECTION>());

    //cout << "New ECDSA primary key" << endl << newPrimary.outPublic.ToString(false) << endl;
   
    TPM_HANDLE& signKey = newPrimary.handle;
    signKey.SetAuth(userAuth);

    write_to_file("key.txt", newPrimary.outPublic.unique->Serialize(SerializationType::JSON));
    cout << "Public Key generated and written to key.txt" << endl;

    TPM_HASH dataToSign = TPM_HASH::FromHashOfString(TPM_ALG_ID::SHA256, message);

    auto sig = tpm.Sign(signKey, dataToSign, TPMS_NULL_SIG_SCHEME(), TPMT_TK_HASHCHECK());
    write_to_file("sign.txt", sig->Serialize(SerializationType::JSON));
    cout << "Signed and written to sign.txt" << endl;
}

void deserialize_json(string filename, TpmStructure &tpms) {
    string jsonStr = read_from_file(filename);
    JsonSerializer(jsonStr).readObj(tpms);
}

void val_message() {
    //Get signature
    TPMS_SIGNATURE_ECDSA sig;
    deserialize_json("sign.txt", sig);

    //Get public key
    TPMS_ECC_POINT ecKey;
    deserialize_json("key.txt", ecKey);
    
    // load key
    TPMT_PUBLIC templ(TPM_ALG_ID::SHA256,
        TPMA_OBJECT::sign | TPMA_OBJECT::fixedParent | TPMA_OBJECT::fixedTPM
        | TPMA_OBJECT::sensitiveDataOrigin | TPMA_OBJECT::userWithAuth, ByteVec(), TPMS_ECC_PARMS(TPMT_SYM_DEF_OBJECT(), TPMS_SCHEME_ECDSA(TPM_ALG_ID::SHA256), TPM_ECC_CURVE::NIST_P256, TPMS_NULL_KDF_SCHEME()), ecKey);

    TPM_HANDLE pubHandle = tpm.LoadExternal(TPMT_SENSITIVE(), templ, TPM_HANDLE(TPM_RH::_NULL));

    // hash message
    string message = read_from_file("message.txt");
    TPM_HASH dataToSign = TPM_HASH::FromHashOfString(TPM_ALG_ID::SHA256, message);

    // verify
    auto sigVerify = tpm._AllowErrors().VerifySignature(pubHandle, dataToSign, sig);
    cout << "Signature is " << (tpm._LastCommandSucceeded() ? "OK" : "BAD") << endl;
}

int main(int argc, char* argv[])
{
    TpmTbsDevice device;
    //TpmTcpDevice device;
    if (!device.Connect()) {
    //if (!device.Connect("127.0.0.1", 2321)) {
        cerr << "Could not connect to the TPM device";
    }
    tpm._SetDevice(device);

    // Power-cycle the simulator
    //device.PowerOff();
    //device.PowerOn();

    // And startup the TPM
    //tpm.Startup(TPM_SU::CLEAR);
    if (argc == 2) {
        string s;
        int i = 0;
        switch (stoi(argv[1])) {
            case 0:
                cout << "Enter file name: ";
                cin >> s;
                getBlobHash(s);
                break;
            case 1:
                cout << "Enter number of iterations: ";
                cin >> i;
                write_csv(sign_multiple(generate_ec_key<>(TPM_ECC_CURVE::BN_P256), i), "out-ecdsa.csv");
                break;
            case 2:
                cout << "Enter number of iterations: ";
                cin >> i;
                write_csv(sign_multiple(generate_rsa_key(), i), "out-rsa.csv");
                break;
            case 3:
                sign_message();
                break;
            case 4:
                val_message();
                break;
            default:
                cout << "invalid argument\n";
        }
        cout << "\n";
    }
    return 0;
}
