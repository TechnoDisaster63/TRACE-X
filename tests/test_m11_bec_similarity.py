from modules.m11_prevention_recommendation.bec import similarity_matches, assess_bec

def test_paraphrased_payment_phrase_matches_and_cites_reference():
    matches = similarity_matches("Please process this payment as discussed with the finance team")
    assert matches
    assert matches[0]["reference_phrase"]
    assert matches[0]["reference_version"]

def test_benign_business_language_does_not_match():
    assert similarity_matches("The weekly project meeting starts at ten and notes are attached") == []

def test_assessment_calls_similarity_not_classifier():
    result=assess_bec({"body_plain":"process this payment as discussed"},{"evidence":[]},{})
    basis=" ".join(i["basis"] for i in result["indicators"])
    assert "Similarity is not a trained classifier" in basis
    assert result["executable"] is False
