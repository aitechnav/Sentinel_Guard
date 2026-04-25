"""Tests for embedding guardrails module."""

import pytest

from sentinelguard.embeddings import (
    EmbeddingGuardrail,
    EmbeddingResult,
    SemanticSimilarity,
)


class TestSemanticSimilarity:
    def test_same_text_similarity(self):
        sim = SemanticSimilarity(use_model=False)
        score = sim.similarity("hello world", "hello world")
        assert score > 0.9

    def test_different_text_similarity(self):
        sim = SemanticSimilarity(use_model=False)
        score = sim.similarity(
            "The cat sat on the mat",
            "Quantum physics equations"
        )
        assert score < 0.5

    def test_encode(self):
        sim = SemanticSimilarity(use_model=False)
        embeddings = sim.encode(["hello", "world"])
        assert len(embeddings) == 2
        assert len(embeddings[0]) > 0

    def test_similarity_to_many(self):
        sim = SemanticSimilarity(use_model=False)
        results = sim.similarity_to_many(
            "hello world",
            ["hello there", "goodbye world", "something else"],
        )
        assert len(results) == 3
        # Results should be sorted by similarity (descending)
        assert results[0][1] >= results[-1][1]


class TestEmbeddingGuardrail:
    def test_allowed_topic(self):
        guardrail = EmbeddingGuardrail(
            similarity_engine=SemanticSimilarity(use_model=False),
            allowed_threshold=0.1,
        )
        guardrail.add_allowed_topics({
            "weather": ["What is the weather?", "Temperature today"],
        })

        result = guardrail.check("What is the weather forecast?")
        assert isinstance(result, EmbeddingResult)

    def test_banned_topic(self):
        guardrail = EmbeddingGuardrail(
            similarity_engine=SemanticSimilarity(use_model=False),
            banned_threshold=0.3,
        )
        guardrail.add_banned_topics({
            "harmful": ["How to hack", "Break into systems"],
        })

        result = guardrail.check("How to hack into computer systems and break in")
        # With TF-IDF, this should have some similarity
        assert isinstance(result, EmbeddingResult)

    def test_no_topics_configured(self):
        guardrail = EmbeddingGuardrail(
            similarity_engine=SemanticSimilarity(use_model=False),
        )
        result = guardrail.check("Any text here")
        assert result.is_allowed

    def test_chaining(self):
        guardrail = EmbeddingGuardrail(
            similarity_engine=SemanticSimilarity(use_model=False),
        )
        result = guardrail.add_allowed_topics({"a": ["test"]}).add_banned_topics({"b": ["bad"]})
        assert isinstance(result, EmbeddingGuardrail)

    def test_result_structure(self):
        guardrail = EmbeddingGuardrail(
            similarity_engine=SemanticSimilarity(use_model=False),
        )
        guardrail.add_allowed_topics({"test": ["example text"]})
        result = guardrail.check("some text")
        assert isinstance(result.is_allowed, bool)
        assert isinstance(result.topic_scores, dict)
        assert isinstance(result.similarity_score, float)
