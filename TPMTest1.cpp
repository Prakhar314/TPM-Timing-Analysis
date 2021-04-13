// TPMTest1.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <string>
#include <fstream>
#include <iterator>
#include <vector>
#include <intrin.h>
#include <filesystem>
#include "stdafx.h"
#include "Tpm2.h"

using namespace std;
using namespace TpmCpp;
namespace fs = std::filesystem;
static const TPMT_SYM_DEF_OBJECT Aes128Cfb{ TPM_ALG_ID::AES, 128, TPM_ALG_ID::CFB };
Tpm2 tpm;
TpmTcpDevice device2;
TpmTbsDevice device1;
class hostSystem {
private:
    Tpm2 tpm;
    TpmTcpDevice device;
    vector<pair<string, pair<int, ByteVec>>> event_log{};
    TPM_HANDLE primaryKey;
    TPM_HANDLE aik;
    vector<TPMS_PCR_SELECTION> pcrsToQuote = { {TPM_ALG_ID::SHA256, 0}, {TPM_ALG_ID::SHA256, 1}, {TPM_ALG_ID::SHA256, 2} };

    
    void update_event_log(string description, int pcr, ByteVec& event_data) {
        event_log.push_back({ description, {pcr, event_data} });
    }
    void reset_event_log() {
        event_log.clear();
    }

    void perform_action(string des, int pcr, ByteVec& event_data) {
        tpm.PCR_Event(TPM_HANDLE::Pcr(pcr), event_data);
        std::cout << des << "\n";
        update_event_log(des, pcr, event_data);
    }
    void action0() {
        string des = "Performing action 1";
        ByteVec event_data = { 1,2,3 };
        perform_action(des, 0, event_data);
    }
    void action1() {
        string des = "Performing action 2";
        ByteVec event_data = { 2,3,4 };
        perform_action(des, 1, event_data);
    }
    void action2() {
        string des = "Performing action 3";
        ByteVec event_data = { 3,4,5 };
        perform_action(des, 2, event_data);
    }
    TPM_HANDLE gen_prim_key() {
        TPMT_PUBLIC storagePrimaryTemplate(TPM_ALG_ID::SHA256,
            TPMA_OBJECT::decrypt | TPMA_OBJECT::restricted
            | TPMA_OBJECT::fixedParent | TPMA_OBJECT::fixedTPM
            | TPMA_OBJECT::sensitiveDataOrigin | TPMA_OBJECT::userWithAuth,
            ByteVec(),           // No policy
            TPMS_RSA_PARMS(Aes128Cfb, TPMS_NULL_ASYM_SCHEME(), 2048, 65537),
            TPM2B_PUBLIC_KEY_RSA());
        return tpm.CreatePrimary(TPM_RH::OWNER, TPMS_SENSITIVE_CREATE(), storagePrimaryTemplate, ByteVec(), vector<TpmCpp::TPMS_PCR_SELECTION>())
            .handle;
    }

    TPM_HANDLE MakeChildSigningKey(TPM_HANDLE parent, bool restricted)
    {
        TPMA_OBJECT restrictedAttribute = restricted ? TPMA_OBJECT::restricted : 0;

        TPMT_PUBLIC templ(TPM_ALG_ID::SHA256,
            TPMA_OBJECT::sign | TPMA_OBJECT::fixedParent | TPMA_OBJECT::fixedTPM
            | TPMA_OBJECT::sensitiveDataOrigin | TPMA_OBJECT::userWithAuth | restrictedAttribute,
            ByteVec(),  // No policy
            TPMS_RSA_PARMS(TPMT_SYM_DEF_OBJECT(), TPMS_SCHEME_RSASSA(TPM_ALG_ID::SHA256), 2048, 65537), // PKCS1.5
            TPM2B_PUBLIC_KEY_RSA());

        auto newSigningKey = tpm.Create(parent, TPMS_SENSITIVE_CREATE(), templ, ByteVec(), vector<TpmCpp::TPMS_PCR_SELECTION>());

        return tpm.Load(parent, newSigningKey.outPrivate, newSigningKey.outPublic);
    }

public:
    hostSystem() {
        if (!device.Connect("127.0.0.1", 2321)) {
            cerr << "Could not connect to the TPM device";
        }
        tpm._SetDevice(device);

        // Power-cycle the simulator
        device.PowerOff();
        device.PowerOn();

        // And startup the TPM
        tpm.Startup(TPM_SU::CLEAR);
        primaryKey = gen_prim_key();
        aik = MakeChildSigningKey(primaryKey, true);
    }
    vector<pair<string, pair<int, ByteVec>>> requestEventLog() {
        return event_log;
    }
    TpmCpp::QuoteResponse requestQuote(ByteVec Nonce) {
        return tpm.Quote(aik, Nonce, TPMS_NULL_SIG_SCHEME(), pcrsToQuote);
    }
    TpmCpp::ReadPublicResponse requestPubAikKey() {
        return tpm.ReadPublic(aik);
    }
    TpmCpp::PCR_ReadResponse requestPcrVal() {
        return tpm.PCR_Read(pcrsToQuote);
    }
    void performActions() {
        action0();
        action1();
        action2();
    }
};

void connectSimTPM(){
    
    if (!device2.Connect("127.0.0.1", 2321)) {
        cerr << "Could not connect to the TPM device";
    }
    tpm._SetDevice(device2);

    device2.PowerOff();
    device2.PowerOn();
    tpm.Startup(TPM_SU::CLEAR);
}
void shutDownSimTPM(){
    tpm.Shutdown(TPM_SU::CLEAR);
    device2.PowerOff();
}

void connectTPM() {
    if (!device1.Connect()) {
        cerr << "Could not connect to the TPM device";
        return;
    }

    // Create a Tpm2 object "on top" of the device.
    tpm._SetDevice(device1);
}

ByteVec getBlobHash(string filename) {
    //input as char vec
    ifstream input(filename, ios::in | ios::binary);
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
    //cout << "bytes " << bytes << endl;
    //get SHA256 hash
    TPM_HASH x = TPM_HASH::FromHashOfData(TPM_ALG_ID::SHA256, bytes);
    return x.digest;
}

ByteVec getDirectoryHash(string path) {
    ByteVec table;
    for (const auto& entry : fs::recursive_directory_iterator(path)) {
        string filename = entry.path().string();
        cout << "reading file " << filename << " ... ";
        ByteVec hash = getBlobHash(entry.path().string());
        //cout << hash.size()<<endl;
        table.insert(table.end(), hash.begin(), hash.end());
        table.push_back('\0');
        table.insert(table.end(), filename.begin(), filename.end());
        table.push_back('\n');
        cout << "done" << endl;
    }
    return TPM_HASH::FromHashOfData(TPM_ALG_ID::SHA256, table).digest;
}

TPM_HANDLE gen_prim_key() {
    TPMT_PUBLIC storagePrimaryTemplate(TPM_ALG_ID::SHA256,
        TPMA_OBJECT::decrypt | TPMA_OBJECT::restricted
        | TPMA_OBJECT::fixedParent | TPMA_OBJECT::fixedTPM
        | TPMA_OBJECT::sensitiveDataOrigin | TPMA_OBJECT::userWithAuth,
        ByteVec(),           // No policy
        TPMS_RSA_PARMS(Aes128Cfb, TPMS_NULL_ASYM_SCHEME(), 2048, 65537),
        TPM2B_PUBLIC_KEY_RSA());
    return tpm.CreatePrimary(TPM_RH::OWNER, TPMS_SENSITIVE_CREATE(), storagePrimaryTemplate, ByteVec(), vector<TpmCpp::TPMS_PCR_SELECTION>())
        .handle;
}


TPM_HANDLE MakeChildSigningKey(TPM_HANDLE parent, bool restricted)
{
    TPMA_OBJECT restrictedAttribute = restricted ? TPMA_OBJECT::restricted : 0;

    TPMT_PUBLIC templ(TPM_ALG_ID::SHA256,
        TPMA_OBJECT::sign | TPMA_OBJECT::fixedParent | TPMA_OBJECT::fixedTPM
        | TPMA_OBJECT::sensitiveDataOrigin | TPMA_OBJECT::userWithAuth | restrictedAttribute,
        ByteVec(),  // No policy
        TPMS_RSA_PARMS(TPMT_SYM_DEF_OBJECT(), TPMS_SCHEME_RSASSA(TPM_ALG_ID::SHA256), 2048, 65537), // PKCS1.5
        TPM2B_PUBLIC_KEY_RSA());

    auto newSigningKey = tpm.Create(parent, TPMS_SENSITIVE_CREATE(), templ, ByteVec(), vector<TpmCpp::TPMS_PCR_SELECTION>());

    return tpm.Load(parent, newSigningKey.outPrivate, newSigningKey.outPublic);
}



vector<TPM_HASH> get_pcr_vals(PCR_ReadResponse pcrVals_old, vector<pair<string, pair<int, ByteVec>>>& event_log) {
    TPM_HASH pcrSim0(TPM_ALG_ID::SHA256, pcrVals_old.pcrValues[0]);
    TPM_HASH pcrSim1(TPM_ALG_ID::SHA256, pcrVals_old.pcrValues[1]);
    TPM_HASH pcrSim2(TPM_ALG_ID::SHA256, pcrVals_old.pcrValues[2]);
    for (auto x : event_log) {
        if (x.second.first == 0) {
            pcrSim0.Event(x.second.second);
        }
        else if (x.second.first == 1) {
            pcrSim1.Event(x.second.second);
        }
        else {
            pcrSim2.Event(x.second.second);
        }

    }
    return { pcrSim0, pcrSim1, pcrSim2 };
}

void attestation() {
    hostSystem system1;
    // get public ket
    auto pubKey = system1.requestPubAikKey();

    //initial pcr val
    std::cout << "PCR Quoting" << endl;
    auto pcrVals_old = system1.requestPcrVal();
    
    //perform actions and get event logs
    system1.performActions();
    auto event_log = system1.requestEventLog();

    // Do the quote.  Note that we provide a nonce.
    ByteVec Nonce = Crypto::GetRand(16);

    // get quote and new pcr vals
    auto quote = system1.requestQuote(Nonce);
    auto pcrVals_new = system1.requestPcrVal();

    //validate signature and nonce
    bool sigOk = pubKey.outPublic.ValidateQuote(pcrVals_new, Nonce, quote);
    if (sigOk)
        std::cout << "The quote was verified correctly" << endl;
    _ASSERT(sigOk);

    // Regenerate pcr digest on client
    auto pcrVals_hash_calc = get_pcr_vals(pcrVals_old, event_log);

    TPMS_ATTEST qAttest = quote.quoted;
    TPMS_QUOTE_INFO* qInfo = dynamic_cast<TPMS_QUOTE_INFO*>(&*qAttest.attested);
    auto d_quote = qInfo->pcrDigest;

    ByteVec pcrDigests;
    for (auto i : pcrVals_hash_calc) {
        pcrDigests.insert(pcrDigests.end(), i.digest.begin(), i.digest.end());
    }
    auto d_calc = TPM_HASH::FromHashOfData(TPM_ALG_ID::SHA256, pcrDigests).digest;
    if (d_quote == d_calc) {
        cout << "pcr values match" << endl;
    }
    else {
        cout << "Attestation failed" << endl;
    }
}

int main(int argc, char* argv[])
{
    attestation();

    cout << "enter directory path" << endl;
    string x;
    cin >> x;

    if (!device2.Connect("127.0.0.1", 2321)) {
        cerr << "Could not connect to the TPM device";
    }
    tpm._SetDevice(device2);

    device2.PowerOff();
    device2.PowerOn();
    tpm.Startup(TPM_SU::CLEAR);
    cout << "SHA3-256: "<< getDirectoryHash(x) << endl;
    return 0;
}
