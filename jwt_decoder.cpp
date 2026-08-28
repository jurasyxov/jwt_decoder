// jwt_decoder.cpp
#include <iostream>
#include <string>
#include <vector>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <cstring>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/kdf.h>
#include <json/json.h> // nlohmann/json recommended, but using jsoncpp

using namespace std;

string base64url_decode(const string& input) {
    string b64 = input;
    // Replace URL-safe chars
    for (char& c : b64) {
        if (c == '-') c = '+';
        else if (c == '_') c = '/';
    }
    // Add padding
    int pad = (4 - (b64.size() % 4)) % 4;
    b64.append(pad, '=');
    vector<unsigned char> out;
    out.resize(b64.size() * 3 / 4);
    size_t len = EVP_DecodeBlock(out.data(), reinterpret_cast<const unsigned char*>(b64.c_str()), b64.size());
    if (len > 0 && b64.find('=') != string::npos) {
        // Remove padding bytes from decoded data
        int pad_count = 0;
        for (int i = b64.size() - 1; i >= 0 && b64[i] == '='; --i) pad_count++;
        len -= pad_count;
    }
    return string(out.begin(), out.begin() + len);
}

string hmac_sha256(const string& key, const string& data) {
    unsigned char* result;
    unsigned int len;
    result = HMAC(EVP_sha256(), key.c_str(), key.size(),
                  reinterpret_cast<const unsigned char*>(data.c_str()), data.size(),
                  nullptr, &len);
    string out(reinterpret_cast<char*>(result), len);
    // Base64URL encode
    string b64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    string enc;
    size_t i = 0;
    while (i < out.size()) {
        uint32_t octet_a = i < out.size() ? (unsigned char)out[i++] : 0;
        uint32_t octet_b = i < out.size() ? (unsigned char)out[i++] : 0;
        uint32_t octet_c = i < out.size() ? (unsigned char)out[i++] : 0;
        uint32_t triple = (octet_a << 16) + (octet_b << 8) + octet_c;
        enc += b64[(triple >> 18) & 0x3F];
        enc += b64[(triple >> 12) & 0x3F];
        enc += b64[(triple >> 6) & 0x3F];
        enc += b64[triple & 0x3F];
    }
    // Remove padding
    while (enc.size() > 0 && enc.back() == '=') enc.pop_back();
    return enc;
}

int main(int argc, char* argv[]) {
    string token, key, filePath;
    bool jsonOut = false, color = false;

    for (int i = 1; i < argc; ++i) {
        string arg = argv[i];
        if (arg == "--key" && i+1 < argc) key = argv[++i];
        else if (arg == "--file" && i+1 < argc) filePath = argv[++i];
        else if (arg == "--json") jsonOut = true;
        else if (arg == "--color") color = true;
        else if (token.empty()) token = arg;
    }

    if (!filePath.empty()) {
        ifstream ifs(filePath);
        if (ifs) {
            getline(ifs, token, '\0');
        } else {
            cerr << "Error reading file" << endl;
            return 1;
        }
    }
    if (token.empty()) {
        // try stdin
        if (!isatty(fileno(stdin))) {
            string line;
            getline(cin, token);
        } else {
            cerr << "Error: no token provided" << endl;
            return 1;
        }
    }

    // Decode
    vector<string> parts;
    stringstream ss(token);
    string part;
    while (getline(ss, part, '.')) parts.push_back(part);
    if (parts.size() != 3) {
        cerr << "Invalid JWT format" << endl;
        return 1;
    }

    Json::Value headerJson, payloadJson;
    try {
        string headerStr = base64url_decode(parts[0]);
        string payloadStr = base64url_decode(parts[1]);
        Json::Reader reader;
        if (!reader.parse(headerStr, headerJson) || !reader.parse(payloadStr, payloadJson)) {
            cerr << "Invalid JSON" << endl;
            return 1;
        }
    } catch (...) {
        cerr << "Decoding error" << endl;
        return 1;
    }

    // Check exp
    bool expired = false;
    if (payloadJson.isMember("exp")) {
        time_t exp = payloadJson["exp"].asInt64();
        expired = time(nullptr) > exp;
    }

    // Verify signature
    bool validSig = false;
    if (!key.empty()) {
        string data = parts[0] + "." + parts[1];
        string sigB64 = hmac_sha256(key, data);
        validSig = (sigB64 == parts[2]);
    }

    if (jsonOut) {
        Json::Value root;
        root["header"] = headerJson;
        root["payload"] = payloadJson;
        root["signature"] = parts[2];
        root["token"] = token;
        if (!key.empty()) root["valid_signature"] = validSig;
        if (payloadJson.isMember("exp")) root["expired"] = expired;
        cout << root.toStyledString();
    } else {
        cout << "Header:" << endl;
        for (auto& key : headerJson.getMemberNames()) {
            cout << "  " << key << ": " << headerJson[key] << endl;
        }
        cout << "Payload:" << endl;
        for (auto& key : payloadJson.getMemberNames()) {
            cout << "  " << key << ": " << payloadJson[key] << endl;
        }
        if (payloadJson.isMember("exp")) {
            cout << "  Token " << (expired ? "expired" : "valid") << endl;
        }
        if (!key.empty()) {
            cout << "  Signature " << (validSig ? "verified" : "invalid") << endl;
        }
        cout << "Signature: " << parts[2] << endl;
    }
    return 0;
}
