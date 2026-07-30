#include "vote_evaluator.h"

#include <stdexcept>

namespace he_voting {
namespace {

class OpenFheVoteEvaluator final : public VoteEvaluator {
  public:
    std::string name() const override {
        return "openfhe";
    }

    EncryptedVoteState evaluate(
        const CryptoContext<DCRTPoly>& context,
        const EncryptedChoice& encryptedChoice,
        const EncryptedVoteState& currentState,
        const Ciphertext<DCRTPoly>& encryptedOne) const override {
        // All values stay encrypted:
        // can_vote      = 1 - has_voted
        // accepted_A    = can_vote * choice_A
        // accepted_B    = can_vote * choice_B
        // accepted_C    = can_vote * choice_C
        // next_tally_X  = tally_X + accepted_X
        // next_flag     = has_voted + can_vote
        //
        // Every operand is a separate scalar ciphertext. No SIMD packing is
        // used for the choice, flag, or counters.
        const auto canVote = context->EvalSub(encryptedOne, currentState.hasVoted);
        const auto acceptedA = context->EvalMult(canVote, encryptedChoice.choiceA);
        const auto acceptedB = context->EvalMult(canVote, encryptedChoice.choiceB);
        const auto acceptedC = context->EvalMult(canVote, encryptedChoice.choiceC);

        EncryptedVoteState nextState;
        nextState.tallyA = context->EvalAdd(currentState.tallyA, acceptedA);
        nextState.tallyB = context->EvalAdd(currentState.tallyB, acceptedB);
        nextState.tallyC = context->EvalAdd(currentState.tallyC, acceptedC);
        nextState.hasVoted = context->EvalAdd(currentState.hasVoted, canVote);
        return nextState;
    }
};

}  // namespace

std::unique_ptr<VoteEvaluator> createVoteEvaluator(const std::string& name) {
    if (name == "openfhe") {
        return std::make_unique<OpenFheVoteEvaluator>();
    }
    if (name == "heir-openfhe") {
        throw std::runtime_error(
            "heir-openfhe is an optional build-time evaluator and no "
            "HEIR-generated kernel is present in this build");
    }
    throw std::runtime_error("unknown HE evaluator: " + name);
}

}  // namespace he_voting
