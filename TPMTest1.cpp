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
static const TPMT_SYM_DEF_OBJECT Aes128Cfb{ TPM_ALG_ID::AES, 128, TPM_ALG_ID::CFB };
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

        auto a = tpm.ReadClock().time;

        auto sig = tpm.Sign(signKey, dataToSign, TPMS_NULL_SIG_SCHEME(), TPMT_TK_HASHCHECK());
        //cout << "Data to be signed:" << dataToSign.digest << endl;
        //cout << "Signature:" << endl << sig->ToString(false) << endl; 

        auto b = tpm.ReadClock().time;

        res.push_back(b - a);
        if (i % 100 == 0) {
            cout << 1.0 * i / iterations * 100 << "%" << endl;
        }
    }
    return res;
}
TPM_HANDLE gen_prim_key() {
    TPMT_PUBLIC storagePrimaryTemplate(TPM_ALG_ID::SHA1,
        TPMA_OBJECT::decrypt | TPMA_OBJECT::restricted
        | TPMA_OBJECT::fixedParent | TPMA_OBJECT::fixedTPM
        | TPMA_OBJECT::sensitiveDataOrigin | TPMA_OBJECT::userWithAuth,
        ByteVec(),           // No policy
        TPMS_RSA_PARMS(Aes128Cfb, TPMS_NULL_ASYM_SCHEME(), 2048, 65537),
        TPM2B_PUBLIC_KEY_RSA());
    return tpm.CreatePrimary(TPM_RH::OWNER, TPMS_SENSITIVE_CREATE(), storagePrimaryTemplate, ByteVec(), vector<TpmCpp::TPMS_PCR_SELECTION>())
        .handle;
}

TPM_HANDLE generate_ecdsa_key() {   
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

    //cout << "New ECDSA primary key" << endl << newPrimary.outPublic.ToString(false) << endl;
    TPM_HANDLE& signKey = newPrimary.handle;
    signKey.SetAuth(userAuth);

    // And shut down the TPM
    // sign_multiple(signKey, 100);
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
void encrypt_decrypt(string inFile) {
    TPM_HANDLE prim = gen_prim_key();

    // Make an AES key
    TPMT_PUBLIC inPublic(TPM_ALG_ID::SHA256,
        TPMA_OBJECT::decrypt | TPMA_OBJECT::sign |TPMA_OBJECT::userWithAuth
        | TPMA_OBJECT::sensitiveDataOrigin,
        ByteVec(),
        TPMS_SYMCIPHER_PARMS(Aes128Cfb),
        TPM2B_DIGEST_SYMCIPHER());
  

    auto aesKey = tpm.Create(prim, TPMS_SENSITIVE_CREATE(), inPublic, ByteVec(), vector<TPMS_PCR_SELECTION>());
    
    TPM_HANDLE aesHandle = tpm.Load(prim, aesKey.outPrivate, aesKey.outPublic);
    string toEnc_str = read_from_file(inFile);
    ByteVec toEncrypt(toEnc_str.begin(), toEnc_str.end());
    ByteVec iv(16);

    auto encrypted = tpm.EncryptDecrypt(aesHandle, (BYTE)0, TPM_ALG_ID::CFB, iv, toEncrypt);
    auto decrypted = tpm.EncryptDecrypt(aesHandle, (BYTE)1, TPM_ALG_ID::CFB, iv, encrypted.outData);
    string dec_str(reinterpret_cast<const char*>(&decrypted.outData[0]), decrypted.outData.size());
    write_to_file("out_enc.txt", dec_str);
    cout << "AES encryption" << endl <<
        "in:  " << toEncrypt << endl <<
        "enc: " << encrypted.outData << endl <<
        "dec: " << decrypted.outData << endl;

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

    //// Power-cycle the simulator
    //device.PowerOff();
    //device.PowerOn();

    //// And startup the TPM
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
                write_csv(sign_multiple(generate_ecdsa_key(), i), "out.csv");
                break;
            case 2:
                sign_message();
                break;
            case 3:
                val_message();
                break;
            case 4:
                cout << "Enter file name: ";
                cin >> s;
                encrypt_decrypt(s);
                break;
            default:
                cout << "invalid argument\n";
        }
        cout << "\n";
    }
    return 0;
}
