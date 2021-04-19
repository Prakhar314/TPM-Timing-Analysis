// TPMTest1.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <string>
#include <fstream>
#include <iterator>
#include <vector>
#include <intrin.h>
#include <filesystem>
#include <chrono>
#include "stdafx.h"
#include "Tpm2.h"

using namespace std;
using namespace TpmCpp;
namespace fs = std::filesystem;
static const TPMT_SYM_DEF_OBJECT Aes128Cfb{ TPM_ALG_ID::AES, 128, TPM_ALG_ID::CFB };
Tpm2 tpm;
TpmTcpDevice device2;
TpmTbsDevice device1;


void connectSimTPM() {

    if (!device2.Connect("127.0.0.1", 2321)) {
        cerr << "Could not connect to the TPM device";
    }
    tpm._SetDevice(device2);

    device2.PowerOff();
    device2.PowerOn();
    tpm.Startup(TPM_SU::CLEAR);
}
void shutDownSimTPM() {
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

class hostSystem {
private:
    bool verbose = true;
    vector<pair<string, pair<int, ByteVec>>> event_log{};
    TPM_HANDLE primaryKey;
    TPM_HANDLE aik;
    vector<TPMS_PCR_SELECTION> pcrsToQuote = { {TPM_ALG_ID::SHA256, 0}, {TPM_ALG_ID::SHA256, 1}, {TPM_ALG_ID::SHA256, 2} };

    void update_pcrs_to_quote(vector<UINT32> pcrs){
    	vector<TPMS_PCR_SELECTION>().swap(pcrsToQuote);
    	for (auto x:pcrs){
    		pcrsToQuote.push_back({TPM_ALG_ID::SHA256, x});
    	}
    }
    void update_event_log(string description, int pcr, ByteVec& event_data) {
        event_log.push_back({ description, {pcr, event_data} });
    }
    void reset_event_log() {
        event_log.clear();
    }

    void perform_action(string des, int pcr, ByteVec& event_data) {
        tpm.PCR_Event(TPM_HANDLE::Pcr(pcr), event_data);
        if(verbose)
            cout << des << "\n";
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
    ByteVec getBlobHash(string filename) {
	    //input as char vec
	    ifstream input(filename, ios::in | ios::binary | ios::ate);
	    int size = input.tellg();
	    //cout << size << endl;
	    auto hashHandle = tpm.HashSequenceStart(ByteVec(), TPM_ALG_ID::SHA256);

	    stringstream ss;
	    ss << "blob " << size;
	    string prefix = ss.str();
	    prefix.push_back('\0');
	    //make byte vec from prefix char vec
	    ByteVec bytes,accum;
	    bytes = ByteVec(prefix.begin(), prefix.end());
	    // to verify with library
	    accum.insert(accum.begin(), bytes.begin(), bytes.end());

	    vector<char> buffer(1024>size?size:1024, 0);
	    while (!input.eof()) {

	        tpm.SequenceUpdate(hashHandle, bytes);

	        input.read(buffer.data(), buffer.size());
	        streamsize dataSize = input.gcount();
	        bytes = ByteVec(buffer.begin(), buffer.begin()+dataSize);

	        accum.insert(accum.begin(), bytes.begin(), bytes.end());
	    }

	    input.close();
	    //get SHA256 finally
	    auto y = tpm.SequenceComplete(hashHandle,bytes,TPM_RH_NULL);
	    //get SHA256 hash using Crypto lib
	    TPM_HASH x = TPM_HASH::FromHashOfData(TPM_ALG_ID::SHA256, accum);
	    // verify
	    _ASSERT(x.digest == y.result);
	    return y.result;
	}
	ByteVec getDirectoryHash(string path) {
	    ByteVec table;
	    for (const auto& entry : fs::directory_iterator(path)) {
	        string filename = entry.path().string();
	        if (fs::is_directory(entry)){
	        	ByteVec hash = getDirectoryHash(entry.path().string());
	        	table.insert(table.end(), hash.begin(), hash.end());
	       		table.push_back('\0');
	       		table.insert(table.end(), filename.begin(), filename.end());
	        	table.push_back('\n');
	        }
	        else{
                if (verbose) {
                    cout << "reading file " << filename << " ... ";
                }
		        ByteVec hash = getBlobHash(entry.path().string());
		        //cout << hash.size()<<endl;
		        table.insert(table.end(), hash.begin(), hash.end());
		        table.push_back('\0');
		        table.insert(table.end(), filename.begin(), filename.end());
		        table.push_back('\n');
                if (verbose) {
                    cout << "done" << endl;
                }
	    	}
	    }
        if (table.size() != 0) {
	        auto hashHandle = tpm.HashSequenceStart(ByteVec(), TPM_ALG_ID::SHA256);
	        ByteVec buffer;
	        int buf_size = 1024;
	        ByteVec::iterator ptr = table.begin();
	        for (int i = 0; i < table.size() / buf_size; i++) {
	            buffer = ByteVec(ptr, ptr + buf_size);
	            tpm.SequenceUpdate(hashHandle, buffer);
	            advance(ptr, buf_size);
	        }
	        buffer = ByteVec(ptr, ptr + table.size()%buf_size);
	        auto y = tpm.SequenceComplete(hashHandle, buffer, TPM_RH_NULL);
	        auto x = TPM_HASH::FromHashOfData(TPM_ALG_ID::SHA256, table);
	        _ASSERT(x.digest == y.result);
	        return y.result;
        }
        return ByteVec(32, 0);
	}

public:
    hostSystem(bool v = true) {
        verbose = v;
        if (!device2.Connect("127.0.0.1", 2321)) {
            cerr << "Could not connect to the TPM device";
        }
        tpm._SetDevice(device2);

        // Power-cycle the simulator
        device2.PowerOff();
        device2.PowerOn();

        // And startup the TPM
        tpm.Startup(TPM_SU::CLEAR);
        primaryKey = gen_prim_key();
        aik = MakeChildSigningKey(primaryKey, true);
    }

    ~hostSystem() {
        tpm.FlushContext(aik);
        tpm.FlushContext(primaryKey);
        shutDownSimTPM();
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
    TpmCpp::QuoteResponse requestDirHashQuote(string path, ByteVec Nonce){
        ByteVec dir_hash = getDirectoryHash(path);
    	perform_action("Updating PCR with directory hash", 0, dir_hash);

    	update_pcrs_to_quote({0});
        return tpm.Quote(aik, Nonce, TPMS_NULL_SIG_SCHEME(), pcrsToQuote);
    }

};


vector<TPM_HASH> get_pcr_vals(PCR_ReadResponse pcrVals_old, vector<pair<string, pair<int, ByteVec>>>& event_log, int pcrs) {
	vector<TPM_HASH> pcrSim(pcrs);
	for (int i=0; i<pcrs; i++){
    	pcrSim[i] = TPM_HASH(TPM_ALG_ID::SHA256, pcrVals_old.pcrValues[i]);
	}
    for (auto x : event_log) {
        pcrSim[x.second.first].Event(x.second.second);
    }
    return pcrSim;
}

void attestation(bool verbose = true, string path="") {
    bool hash_dir = path.size() != 0;

    hostSystem system1(verbose);
    // get public ket
    auto pubKey = system1.requestPubAikKey();

    //initial pcr val
    if(verbose)
        cout << "PCR Quoting" << endl;

    auto pcrVals_old = system1.requestPcrVal();
    
    //perform actions and get event logs
    if (!hash_dir) {
        system1.performActions();
    }

    // Do the quote.  Note that we provide a nonce.
    ByteVec Nonce = Crypto::GetRand(16);

    // get quote and new pcr vals
    QuoteResponse quote;
    if (hash_dir) {
        quote = system1.requestDirHashQuote(path, Nonce);
    }
    else {
        quote = system1.requestQuote(Nonce);
    }

    auto event_log = system1.requestEventLog();
    auto pcrVals_new = system1.requestPcrVal();

    //validate signature and nonce
    bool sigOk = pubKey.outPublic.ValidateQuote(pcrVals_new, Nonce, quote);
    if (sigOk && verbose)
        cout << "The quote was verified correctly" << endl;

    _ASSERT(sigOk);

    // Regenerate pcr digest on client
    auto pcrVals_hash_calc = get_pcr_vals(pcrVals_old, event_log, hash_dir?1:3);

    TPMS_ATTEST qAttest = quote.quoted;
    TPMS_QUOTE_INFO* qInfo = dynamic_cast<TPMS_QUOTE_INFO*>(&*qAttest.attested);
    auto d_quote = qInfo->pcrDigest;

    ByteVec pcrDigests;
    for (auto i : pcrVals_hash_calc) {
        pcrDigests.insert(pcrDigests.end(), i.digest.begin(), i.digest.end());
    }
    auto d_calc = TPM_HASH::FromHashOfData(TPM_ALG_ID::SHA256, pcrDigests).digest;
    if (verbose) {
        if (d_quote == d_calc) {
            cout << "pcr values match" << endl;
        }
        else {
            cout << "Attestation failed" << endl;
        }
    }
}

void generate_files(string path, int size) {
    fs::remove_all(path);
    vector<string> folders = { "f1","f2","f1/f3","f1/f3/f4",path};
    fs::create_directory(path);
    for (int i = 0; i < folders.size()-1; i++) {
        stringstream nf;
        nf << path << "/" << folders[i];
        folders[i] = nf.str();
        fs::create_directory(folders[i]);
    }
    int file_num = 0;
    while (size > 0) {
        stringstream nf;
        nf << folders[rand() % folders.size()] << "/" << "file"<<file_num++;
        ofstream new_file(nf.str());
        int file_size = 0;
        while (file_size == 0) {
            file_size = rand() % size+1;
        }
        new_file << Crypto::GetRand(file_size);
        size -= file_size;
        //cout << file_size << endl;
        new_file.close();
    }
}

void benchmark() {
    string path = "test_files";
    const int num_iter = 200;
    hostSystem system1(false);
    cout << "starting" << endl;
    vector<int> sizes = { 10,100,1000,10000,100000,1000000 };
    ofstream  logs("logs.csv");
    for (auto file_size : sizes) {
        cout << "\nsize: " << file_size << endl;
        cout << "generating files " << endl;
        generate_files(path, file_size);
        cout << "quoting " << endl;
        int start_time = chrono::duration_cast<chrono::milliseconds>(chrono::system_clock::now().time_since_epoch()).count();
        for (int i = 0; i < num_iter; i++) {
            if ((i * 100) % (5 * num_iter) == 0) {
                cout << (i * 100) / num_iter << "%" << endl;
            }
            ByteVec Nonce = Crypto::GetRand(16);
            system1.requestDirHashQuote(path, Nonce);
        }
        int total_time = chrono::duration_cast<chrono::milliseconds>(chrono::system_clock::now().time_since_epoch()).count() - start_time;
        cout << "Took " << total_time << " ms for " << num_iter << " quotes" << endl;
        cout << "Avg " << total_time / num_iter << " ms" << endl;
        logs << file_size << "," << total_time / num_iter << endl;
    }
    logs.close();
    fs::remove_all(path);
}

int main(int argc, char* argv[])
{
    //attestation();

    //cout << "enter directory path" << endl;
    //string x;
    //cin >> x;
    benchmark();
    //attestation(true, x);
    return 0;
}
