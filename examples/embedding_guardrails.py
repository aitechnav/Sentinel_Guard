"""Embedding guardrails examples for SentinelGuard."""

from sentinelguard.embeddings import EmbeddingGuardrail, SemanticSimilarity


def example_topic_enforcement():
    """Enforce allowed and banned topics."""
    guardrail = EmbeddingGuardrail(
        similarity_engine=SemanticSimilarity(use_model=False),
        allowed_threshold=0.22,
        banned_threshold=0.5,
    )

    # Define allowed topics
    guardrail.add_allowed_topics({
        "customer_support": [
            "How can I help you with your order?",
            "I'd like to track my package",
            "Can I return this product?",
            "What is your refund policy?",
        ],
        "product_info": [
            "Tell me about this product",
            "What are the specifications?",
            "Is this item in stock?",
            "Compare these two products",
        ],
    })

    # Define banned topics
    guardrail.add_banned_topics({
        "medical_advice": [
            "Diagnose my condition",
            "What medication should I take?",
            "Is this symptom serious?",
        ],
        "legal_advice": [
            "Should I sue them?",
            "What are my legal rights?",
            "Write a contract for me",
            "Should I file a lawsuit?",
        ],
    })

    # Test various inputs
    test_inputs = [
        "I would like to track my package",
        "What medication should I take for a headache?",
        "Tell me about this product",
        "Should I file a lawsuit?",
        "Explain quantum physics",
    ]

    for text in test_inputs:
        result = guardrail.check(text)
        status = "ALLOWED" if result.is_allowed else "BLOCKED"
        print(f"[{status}] '{text}'")
        print(f"  Closest topic: {result.closest_topic}, Score: {result.similarity_score:.3f}")


def example_semantic_similarity():
    """Compute semantic similarity between texts."""
    sim = SemanticSimilarity(use_model=False)  # Using TF-IDF fallback

    pairs = [
        ("How do I return a product?", "I want to send back an item"),
        ("How do I return a product?", "What is the weather today?"),
        ("Tell me about Python programming", "Explain Python coding language"),
    ]

    for text1, text2 in pairs:
        score = sim.similarity(text1, text2)
        print(f"Similarity: {score:.3f}")
        print(f"  '{text1}' <-> '{text2}'")
        print()


def example_ood_detection():
    """Detect out-of-distribution inputs."""
    guardrail = EmbeddingGuardrail(
        similarity_engine=SemanticSimilarity(use_model=False),
        allowed_threshold=0.25,
        ood_threshold=0.15,
    )

    guardrail.add_allowed_topics({
        "cooking": [
            "pasta recipe cooking noodles sauce",
            "cake baking recipe oven",
            "chicken cooking temperature",
        ],
    })

    test_inputs = [
        "bake bread recipe",  # Related to cooking
        "database replication cluster",  # Out of distribution
    ]

    for text in test_inputs:
        result = guardrail.check(text)
        if result.is_out_of_distribution:
            print(f"[OOD] '{text}'")
        elif result.is_allowed:
            print(f"[OK]  '{text}'")
        else:
            print(f"[BLOCKED] '{text}'")


if __name__ == "__main__":
    print("=== Topic Enforcement ===")
    example_topic_enforcement()
    print("\n=== Semantic Similarity ===")
    example_semantic_similarity()
    print("\n=== OOD Detection ===")
    example_ood_detection()
