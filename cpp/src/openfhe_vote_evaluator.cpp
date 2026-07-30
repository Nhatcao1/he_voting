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
        const Ciphertext<DCRTPoly>& encryptedChoice,
        const EncryptedVoteState& currentState,
        const Ciphertext<DCRTPoly>& encryptedOne) const override {
        // All values stay encrypted:
        // can_vote      = 1 - has_voted
        // accepted_vote = can_vote * [choice_A, choice_B, choice_C]
        // next_tally    = tally + accepted_vote
        // next_flag     = has_voted + can_vote
        //
        // next_flag is Enc([1,1,1]) after the first request for a token and
        // remains Enc([1,1,1]) for every duplicate request.
        const auto canVote = context->EvalSub(encryptedOne, currentState.hasVoted);
        const auto acceptedVote = context->EvalMult(canVote, encryptedChoice);

        EncryptedVoteState nextState;
        nextState.tally = context->EvalAdd(currentState.tally, acceptedVote);
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

