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

Ciphertext<DCRTPoly> encryptScalar(
    const CryptoContext<DCRTPoly>& context,
    const PublicKey<DCRTPoly>& publicKey,
    int64_t value) {
    const auto plaintext = context->MakeCoefPackedPlaintext({value});
    return context->Encrypt(publicKey, plaintext);
}

int64_t decryptScalar(
    const CryptoContext<DCRTPoly>& context,
    const PrivateKey<DCRTPoly>& secretKey,
    const Ciphertext<DCRTPoly>& ciphertext) {
    Plaintext plaintext;
    const auto result = context->Decrypt(secretKey, ciphertext, &plaintext);
    if (!result.isValid) {
        throw std::runtime_error("OpenFHE decryption failed");
    }
    plaintext->SetLength(1);
    return plaintext->GetCoefPackedValue().at(0);
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

    const auto encryptedTallyA = encryptScalar(context, keys.publicKey, 0);
    const auto encryptedTallyB = encryptScalar(context, keys.publicKey, 0);
    const auto encryptedTallyC = encryptScalar(context, keys.publicKey, 0);
    const auto encryptedOne = encryptScalar(context, keys.publicKey, 1);
    serializeToFile(stateDirectory / "tally_a.ct", encryptedTallyA);
    serializeToFile(stateDirectory / "tally_b.ct", encryptedTallyB);
    serializeToFile(stateDirectory / "tally_c.ct", encryptedTallyC);
    serializeToFile(publicDirectory / "encrypted_one.ct", encryptedOne);

    std::cout
        << "{\"scheme\":\"BFV-RNS\",\"plaintext_modulus\":"
        << kPlaintextModulus
        << ",\"encoding\":\"coefficient-scalar\""
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
        const auto encryptedFlag = encryptScalar(context, publicKey, 0);
        serializeToFile(
            flagsDirectory / (tokenKey + ".ct"),
            encryptedFlag);
        ++count;
    }

    std::cout << "{\"initialized_flags\":" << count << "}\n";
}

void commandEncryptChoice(const Arguments& arguments) {
    const fs::path publicDirectory = required(arguments, "public-dir");
    const fs::path outputDirectory = required(arguments, "out-dir");
    std::string choice = required(arguments, "choice");
    std::transform(
        choice.begin(), choice.end(), choice.begin(),
        [](unsigned char character) {
            return static_cast<char>(std::toupper(character));
        });

    if (choice != "A" && choice != "B" && choice != "C") {
        throw std::runtime_error("choice must be A, B, or C");
    }

    const auto context = loadContext(publicDirectory);
    const auto publicKey = loadPublicKey(publicDirectory);
    fs::create_directories(outputDirectory);
    serializeToFile(
        outputDirectory / "choice_a.ct",
        encryptScalar(context, publicKey, choice == "A" ? 1 : 0));
    serializeToFile(
        outputDirectory / "choice_b.ct",
        encryptScalar(context, publicKey, choice == "B" ? 1 : 0));
    serializeToFile(
        outputDirectory / "choice_c.ct",
        encryptScalar(context, publicKey, choice == "C" ? 1 : 0));
    std::cout
        << "{\"encrypted\":true,\"ciphertexts\":3,"
           "\"encoding\":\"coefficient-scalar\"}\n";
}

void commandEvaluate(const Arguments& arguments) {
    const fs::path publicDirectory = required(arguments, "public-dir");
    const fs::path flagInput = required(arguments, "flag-in");
    const fs::path tallyInputDirectory =
        required(arguments, "tally-dir-in");
    const fs::path ballotDirectory = required(arguments, "ballot-dir");
    const fs::path flagOutput = required(arguments, "flag-out");
    const fs::path tallyOutputDirectory =
        required(arguments, "tally-dir-out");
    const std::string evaluatorName = optional(
        arguments, "evaluator", "openfhe");

    const auto context = loadContext(publicDirectory);
    loadEvaluationKeys(context, publicDirectory);

    he_voting::EncryptedVoteState currentState;
    currentState.hasVoted =
        deserializeFromFile<Ciphertext<DCRTPoly>>(flagInput);
    currentState.tallyA = deserializeFromFile<Ciphertext<DCRTPoly>>(
        tallyInputDirectory / "tally_a.ct");
    currentState.tallyB = deserializeFromFile<Ciphertext<DCRTPoly>>(
        tallyInputDirectory / "tally_b.ct");
    currentState.tallyC = deserializeFromFile<Ciphertext<DCRTPoly>>(
        tallyInputDirectory / "tally_c.ct");
    he_voting::EncryptedChoice encryptedChoice;
    encryptedChoice.choiceA = deserializeFromFile<Ciphertext<DCRTPoly>>(
        ballotDirectory / "choice_a.ct");
    encryptedChoice.choiceB = deserializeFromFile<Ciphertext<DCRTPoly>>(
        ballotDirectory / "choice_b.ct");
    encryptedChoice.choiceC = deserializeFromFile<Ciphertext<DCRTPoly>>(
        ballotDirectory / "choice_c.ct");
    const auto encryptedOne =
        deserializeFromFile<Ciphertext<DCRTPoly>>(
            publicDirectory / "encrypted_one.ct");

    const auto evaluator = he_voting::createVoteEvaluator(evaluatorName);
    const auto nextState = evaluator->evaluate(
        context, encryptedChoice, currentState, encryptedOne);

    serializeToFile(flagOutput, nextState.hasVoted);
    serializeToFile(
        tallyOutputDirectory / "tally_a.ct", nextState.tallyA);
    serializeToFile(
        tallyOutputDirectory / "tally_b.ct", nextState.tallyB);
    serializeToFile(
        tallyOutputDirectory / "tally_c.ct", nextState.tallyC);
    std::cout
        << "{\"evaluated\":true,\"evaluator\":\""
        << evaluator->name() << "\"}\n";
}

void commandDecryptResult(const Arguments& arguments) {
    const fs::path publicDirectory = required(arguments, "public-dir");
    const fs::path trusteeDirectory = required(arguments, "trustee-dir");
    const fs::path tallyDirectory = required(arguments, "tally-dir");

    const auto context = loadContext(publicDirectory);
    const auto secretKey = deserializeFromFile<PrivateKey<DCRTPoly>>(
        trusteeDirectory / "secret_key.bin");
    const auto tallyA = deserializeFromFile<Ciphertext<DCRTPoly>>(
        tallyDirectory / "tally_a.ct");
    const auto tallyB = deserializeFromFile<Ciphertext<DCRTPoly>>(
        tallyDirectory / "tally_b.ct");
    const auto tallyC = deserializeFromFile<Ciphertext<DCRTPoly>>(
        tallyDirectory / "tally_c.ct");
    const auto valueA = decryptScalar(context, secretKey, tallyA);
    const auto valueB = decryptScalar(context, secretKey, tallyB);
    const auto valueC = decryptScalar(context, secretKey, tallyC);

    std::cout
        << "{\"A\":" << valueA
        << ",\"B\":" << valueB
        << ",\"C\":" << valueC
        << "}\n";
}

void printUsage() {
    std::cerr
        << "Usage:\n"
        << "  he_voting_crypto setup --public-dir DIR --trustee-dir DIR "
           "--state-dir DIR\n"
        << "  he_voting_crypto init-flags --public-dir DIR "
           "--token-keys FILE --flags-dir DIR\n"
        << "  he_voting_crypto encrypt-choice --public-dir DIR "
           "--choice A|B|C --out-dir DIR\n"
        << "  he_voting_crypto evaluate --public-dir DIR --flag-in FILE "
           "--tally-dir-in DIR --ballot-dir DIR --flag-out FILE "
           "--tally-dir-out DIR [--evaluator openfhe]\n"
        << "  he_voting_crypto decrypt-result --public-dir DIR "
           "--trustee-dir DIR --tally-dir DIR\n";
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
