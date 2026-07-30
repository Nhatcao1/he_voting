#pragma once

#include <memory>
#include <string>

#include "openfhe.h"

namespace he_voting {

using lbcrypto::Ciphertext;
using lbcrypto::CryptoContext;
using lbcrypto::DCRTPoly;

struct EncryptedVoteState {
    Ciphertext<DCRTPoly> hasVoted;
    Ciphertext<DCRTPoly> tallyA;
    Ciphertext<DCRTPoly> tallyB;
    Ciphertext<DCRTPoly> tallyC;
};

struct EncryptedChoice {
    Ciphertext<DCRTPoly> choiceA;
    Ciphertext<DCRTPoly> choiceB;
    Ciphertext<DCRTPoly> choiceC;
};

class VoteEvaluator {
  public:
    virtual ~VoteEvaluator() = default;

    virtual std::string name() const = 0;

    virtual EncryptedVoteState evaluate(
        const CryptoContext<DCRTPoly>& context,
        const EncryptedChoice& encryptedChoice,
        const EncryptedVoteState& currentState,
        const Ciphertext<DCRTPoly>& encryptedOne) const = 0;
};

std::unique_ptr<VoteEvaluator> createVoteEvaluator(const std::string& name);

}  // namespace he_voting
