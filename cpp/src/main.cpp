#include <algorithm>
#include <cctype>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <map>
#include <stdexcept>
#include <string>
#include <vector>

#include "ciphertext-ser.h"
#include "cryptocontext-ser.h"
#include "key/key-ser.h"
#include "openfhe.h"
#include "scheme/bfvrns/bfvrns-ser.h"

#include "vote_evaluator.h"

namespace fs = std::filesystem;
using namespace lbcrypto;

namespace {

constexpr uint64_t kPlaintextModulus = 65537;
constexpr uint32_t kPackedSlots = 4;

struct Arguments {
    std::string command;
    std::map<std::string, std::string> values;
};

Arguments parseArguments(int argc, char** argv) {
    if (argc < 2) {
        throw std::runtime_error("missing command");
    }

    Arguments parsed;
    parsed.command = argv[1];
    for (int i = 2; i < argc; ++i) {
        std::string key = argv[i];
        if (key.rfind("--", 0) != 0) {
            throw std::runtime_error("expected option, got: " + key);
        }
        if (i + 1 >= argc) {
            throw std::runtime_error("missing value for option: " + key);
        }
        parsed.values[key.substr(2)] = argv[++i];
    }
    return parsed;
}

std::string required(const Arguments& arguments, const std::string& key) {
    const auto found = arguments.values.find(key);
    if (found == arguments.values.end() || found->second.empty()) {
        throw std::runtime_error("missing required option --" + key);
    }
    return found->second;
}

std::string optional(
    const Arguments& arguments,
    const std::string& key,
    const std::string& defaultValue) {
    const auto found = arguments.values.find(key);
    return found == arguments.values.end() ? defaultValue : found->second;
}

void requireFile(const fs::path& path) {
    if (!fs::is_regular_file(path)) {
        throw std::runtime_error("required file does not exist: " + path.string());
    }
}

template <typename T>
void serializeToFile(const fs::path& path, const T& value) {
    fs::create_directories(path.parent_path());
    if (!Serial::SerializeToFile(path.string(), value, SerType::BINARY)) {
        throw std::runtime_error("cannot serialize: " + path.string());
    }
}

template <typename T>
T deserializeFromFile(const fs::path& path) {
    requireFile(path);
    T value;
    if (!Serial::DeserializeFromFile(path.string(), value, SerType::BINARY)) {
        throw std::runtime_error("cannot deserialize: " + path.string());
    }
    return value;
}

CryptoContext<DCRTPoly> loadContext(const fs::path& publicDirectory) {
    return deserializeFromFile<CryptoContext<DCRTPoly>>(
        publicDirectory / "crypto_context.bin");
}

PublicKey<DCRTPoly> loadPublicKey(const fs::path& publicDirectory) {
    return deserializeFromFile<PublicKey<DCRTPoly>>(
        publicDirectory / "public_key.bin");
}

void loadEvaluationKeys(
    const CryptoContext<DCRTPoly>& context,
    const fs::path& publicDirectory) {
    const auto path = publicDirectory / "eval_mult_keys.bin";
    requireFile(path);
    std::ifstream input(path, std::ios::in | std::ios::binary);
    if (!input.is_open() ||
        !context->DeserializeEvalMultKey(input, SerType::BINARY)) {
        throw std::runtime_error(
            "cannot deserialize multiplication evaluation keys: " +
            path.string());
    }
}

Ciphertext<DCRTPoly> encryptVector(
    const CryptoContext<DCRTPoly>& context,
    const PublicKey<DCRTPoly>& publicKey,
    const std::vector<int64_t>& values) {
    const auto plaintext = context->MakePackedPlaintext(values);
    return context->Encrypt(publicKey, plaintext);
}

std::vector<int64_t> decryptVector(
    const CryptoContext<DCRTPoly>& context,
    const PrivateKey<DCRTPoly>& secretKey,
    const Ciphertext<DCRTPoly>& ciphertext,
    size_t length) {
    Plaintext plaintext;
    const auto result = context->Decrypt(secretKey, ciphertext, &plaintext);
    if (!result.isValid) {
        throw std::runtime_error("OpenFHE decryption failed");
    }
    plaintext->SetLength(length);
    auto values = plaintext->GetPackedValue();
    values.resize(length);
    return values;
}

std::string trim(std::string value) {
    const auto notSpace = [](unsigned char character) {
        return !std::isspace(character);
    };
    value.erase(value.begin(), std::find_if(value.begin(), value.end(), notSpace));
    value.erase(std::find_if(value.rbegin(), value.rend(), notSpace).base(), value.end());
    return value;
}

bool isTokenKey(const std::string& value) {
    return value.size() == 64 &&
           std::all_of(value.begin(), value.end(), [](unsigned char character) {
               return std::isdigit(character) ||
                      (character >= 'a' && character <= 'f');
           });
}

void commandSetup(const Arguments& arguments) {
    const fs::path publicDirectory = required(arguments, "public-dir");
    const fs::path trusteeDirectory = required(arguments, "trustee-dir");
    const fs::path stateDirectory = required(arguments, "state-dir");

    fs::create_directories(publicDirectory);
    fs::create_directories(trusteeDirectory);
    fs::create_directories(stateDirectory);

    CCParams<CryptoContextBFVRNS> parameters;
    parameters.SetPlaintextModulus(kPlaintextModulus);
    parameters.SetMultiplicativeDepth(2);
    parameters.SetBatchSize(kPackedSlots);
    parameters.SetSecurityLevel(HEStd_128_classic);

    auto context = GenCryptoContext(parameters);
    context->Enable(PKE);
    context->Enable(KEYSWITCH);
    context->Enable(LEVELEDSHE);

    const auto keys = context->KeyGen();
    if (!keys.good()) {
        throw std::runtime_error("OpenFHE key generation failed");
    }
    context->EvalMultKeyGen(keys.secretKey);

    serializeToFile(publicDirectory / "crypto_context.bin", context);
    serializeToFile(publicDirectory / "public_key.bin", keys.publicKey);
    serializeToFile(trusteeDirectory / "secret_key.bin", keys.secretKey);

    {
        std::ofstream output(
            publicDirectory / "eval_mult_keys.bin",
            std::ios::out | std::ios::binary);
        if (!output.is_open() ||
            !context->SerializeEvalMultKey(output, SerType::BINARY)) {
            throw std::runtime_error(
                "cannot serialize multiplication evaluation keys");
        }
    }

    const auto encryptedZero = encryptVector(
        context, keys.publicKey, {0, 0, 0, 0});
    const auto encryptedOne = encryptVector(
        context, keys.publicKey, {1, 1, 1, 0});
    serializeToFile(stateDirectory / "tally.ct", encryptedZero);
    serializeToFile(publicDirectory / "encrypted_one.ct", encryptedOne);

    std::cout
        << "{\"scheme\":\"BFV-RNS\",\"plaintext_modulus\":"
        << kPlaintextModulus
        << ",\"slots\":" << kPackedSlots
        << ",\"security\":\"HEStd_128_classic\"}\n";
}

void commandInitializeFlags(const Arguments& arguments) {
    const fs::path publicDirectory = required(arguments, "public-dir");
    const fs::path tokenKeysPath = required(arguments, "token-keys");
    const fs::path flagsDirectory = required(arguments, "flags-dir");

    const auto context = loadContext(publicDirectory);
    const auto publicKey = loadPublicKey(publicDirectory);
    fs::create_directories(flagsDirectory);

    std::ifstream input(tokenKeysPath);
    if (!input.is_open()) {
        throw std::runtime_error(
            "cannot open token-key list: " + tokenKeysPath.string());
    }

    size_t count = 0;
    std::string line;
    while (std::getline(input, line)) {
        const auto tokenKey = trim(line);
        if (tokenKey.empty()) {
            continue;
        }
        if (!isTokenKey(tokenKey)) {
            throw std::runtime_error(
                "invalid token key in list: " + tokenKey);
        }
        const auto encryptedFlag = encryptVector(
            context, publicKey, {0, 0, 0, 0});
        serializeToFile(
            flagsDirectory / (tokenKey + ".ct"),
            encryptedFlag);
        ++count;
    }

    std::cout << "{\"initialized_flags\":" << count << "}\n";
}

void commandEncryptChoice(const Arguments& arguments) {
    const fs::path publicDirectory = required(arguments, "public-dir");
    const fs::path outputPath = required(arguments, "out");
    std::string choice = required(arguments, "choice");
    std::transform(
        choice.begin(), choice.end(), choice.begin(),
        [](unsigned char character) {
            return static_cast<char>(std::toupper(character));
        });

    std::vector<int64_t> encoded;
    if (choice == "A") {
        encoded = {1, 0, 0, 0};
    }
    else if (choice == "B") {
        encoded = {0, 1, 0, 0};
    }
    else if (choice == "C") {
        encoded = {0, 0, 1, 0};
    }
    else {
        throw std::runtime_error("choice must be A, B, or C");
    }

    const auto context = loadContext(publicDirectory);
    const auto publicKey = loadPublicKey(publicDirectory);
    const auto ciphertext = encryptVector(context, publicKey, encoded);
    serializeToFile(outputPath, ciphertext);
    std::cout << "{\"encrypted\":true}\n";
}

void commandEvaluate(const Arguments& arguments) {
    const fs::path publicDirectory = required(arguments, "public-dir");
    const fs::path flagInput = required(arguments, "flag-in");
    const fs::path tallyInput = required(arguments, "tally-in");
    const fs::path ballotInput = required(arguments, "ballot-in");
    const fs::path flagOutput = required(arguments, "flag-out");
    const fs::path tallyOutput = required(arguments, "tally-out");
    const std::string evaluatorName = optional(
        arguments, "evaluator", "openfhe");

    const auto context = loadContext(publicDirectory);
    loadEvaluationKeys(context, publicDirectory);

    he_voting::EncryptedVoteState currentState;
    currentState.hasVoted =
        deserializeFromFile<Ciphertext<DCRTPoly>>(flagInput);
    currentState.tally =
        deserializeFromFile<Ciphertext<DCRTPoly>>(tallyInput);
    const auto encryptedChoice =
        deserializeFromFile<Ciphertext<DCRTPoly>>(ballotInput);
    const auto encryptedOne =
        deserializeFromFile<Ciphertext<DCRTPoly>>(
            publicDirectory / "encrypted_one.ct");

    const auto evaluator = he_voting::createVoteEvaluator(evaluatorName);
    const auto nextState = evaluator->evaluate(
        context, encryptedChoice, currentState, encryptedOne);

    serializeToFile(flagOutput, nextState.hasVoted);
    serializeToFile(tallyOutput, nextState.tally);
    std::cout
        << "{\"evaluated\":true,\"evaluator\":\""
        << evaluator->name() << "\"}\n";
}

void commandDecryptResult(const Arguments& arguments) {
    const fs::path publicDirectory = required(arguments, "public-dir");
    const fs::path trusteeDirectory = required(arguments, "trustee-dir");
    const fs::path tallyPath = required(arguments, "tally");

    const auto context = loadContext(publicDirectory);
    const auto secretKey = deserializeFromFile<PrivateKey<DCRTPoly>>(
        trusteeDirectory / "secret_key.bin");
    const auto tally =
        deserializeFromFile<Ciphertext<DCRTPoly>>(tallyPath);
    const auto values = decryptVector(context, secretKey, tally, 3);

    std::cout
        << "{\"A\":" << values[0]
        << ",\"B\":" << values[1]
        << ",\"C\":" << values[2]
        << "}\n";
}

void commandDecryptFlag(const Arguments& arguments) {
    const fs::path publicDirectory = required(arguments, "public-dir");
    const fs::path trusteeDirectory = required(arguments, "trustee-dir");
    const fs::path flagPath = required(arguments, "flag");

    const auto context = loadContext(publicDirectory);
    const auto secretKey = deserializeFromFile<PrivateKey<DCRTPoly>>(
        trusteeDirectory / "secret_key.bin");
    const auto flag =
        deserializeFromFile<Ciphertext<DCRTPoly>>(flagPath);
    const auto values = decryptVector(context, secretKey, flag, 1);
    std::cout << "{\"has_voted\":" << values[0] << "}\n";
}

void printUsage() {
    std::cerr
        << "Usage:\n"
        << "  he_voting_crypto setup --public-dir DIR --trustee-dir DIR "
           "--state-dir DIR\n"
        << "  he_voting_crypto init-flags --public-dir DIR "
           "--token-keys FILE --flags-dir DIR\n"
        << "  he_voting_crypto encrypt-choice --public-dir DIR "
           "--choice A|B|C --out FILE\n"
        << "  he_voting_crypto evaluate --public-dir DIR --flag-in FILE "
           "--tally-in FILE --ballot-in FILE --flag-out FILE "
           "--tally-out FILE [--evaluator openfhe]\n"
        << "  he_voting_crypto decrypt-result --public-dir DIR "
           "--trustee-dir DIR --tally FILE\n"
        << "  he_voting_crypto decrypt-flag --public-dir DIR "
           "--trustee-dir DIR --flag FILE\n";
}

}  // namespace

int main(int argc, char** argv) {
    try {
        const auto arguments = parseArguments(argc, argv);
        if (arguments.command == "setup") {
            commandSetup(arguments);
        }
        else if (arguments.command == "init-flags") {
            commandInitializeFlags(arguments);
        }
        else if (arguments.command == "encrypt-choice") {
            commandEncryptChoice(arguments);
        }
        else if (arguments.command == "evaluate") {
            commandEvaluate(arguments);
        }
        else if (arguments.command == "decrypt-result") {
            commandDecryptResult(arguments);
        }
        else if (arguments.command == "decrypt-flag") {
            commandDecryptFlag(arguments);
        }
        else {
            printUsage();
            throw std::runtime_error(
                "unknown command: " + arguments.command);
        }
        return 0;
    }
    catch (const std::exception& error) {
        std::cerr << "error: " << error.what() << '\n';
        return 1;
    }
}
