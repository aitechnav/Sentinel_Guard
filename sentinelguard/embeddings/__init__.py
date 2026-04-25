"""Embedding-based guardrails module for SentinelGuard.

Provides semantic content control using vector embeddings for
topic enforcement, out-of-distribution detection, and
semantic similarity scoring.

Usage:
    from sentinelguard.embeddings import EmbeddingGuardrail, SemanticSimilarity

    guardrail = EmbeddingGuardrail()
    guardrail.add_allowed_topics({
        "customer_support": ["How can I help?", "Order questions"]
    })
    guardrail.add_banned_topics({
        "medical_advice": ["Diagnose condition", "Medication advice"]
    })
    result = guardrail.check(text)
"""

from __future__ import annotations

import logging
import math
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


@dataclass
class EmbeddingResult:
    """Result from embedding-based guardrail check.

    Attributes:
        is_allowed: Whether the text passed the guardrail.
        closest_topic: The closest matching topic.
        similarity_score: Similarity to the closest topic.
        topic_scores: Scores for all checked topics.
        is_out_of_distribution: Whether text is OOD.
        details: Additional analysis details.
    """

    is_allowed: bool
    closest_topic: str = ""
    similarity_score: float = 0.0
    topic_scores: Dict[str, float] = field(default_factory=dict)
    is_out_of_distribution: bool = False
    details: Dict[str, Any] = field(default_factory=dict)


def _cosine_similarity(a: List[float], b: List[float]) -> float:
    """Compute cosine similarity between two vectors."""
    dot = sum(x * y for x, y in zip(a, b))
    norm_a = math.sqrt(sum(x * x for x in a))
    norm_b = math.sqrt(sum(x * x for x in b))
    if norm_a == 0 or norm_b == 0:
        return 0.0
    return dot / (norm_a * norm_b)


class SemanticSimilarity:
    """Compute semantic similarity between texts using embeddings.

    Supports multiple embedding backends:
    - sentence-transformers (default)
    - Simple TF-IDF fallback

    Args:
        model_name: Sentence-transformer model name. Default "all-MiniLM-L6-v2".
        use_model: Whether to use transformer model. Default True.
    """

    def __init__(
        self,
        model_name: str = "all-MiniLM-L6-v2",
        use_model: bool = True,
    ):
        self.model_name = model_name
        self._use_model = use_model
        self._model = None
        self._model_available = None

    def _init_model(self) -> bool:
        """Initialize the embedding model."""
        if self._model_available is not None:
            return self._model_available
        if not self._use_model:
            self._model_available = False
            return False
        try:
            from sentence_transformers import SentenceTransformer
            self._model = SentenceTransformer(self.model_name)
            self._model_available = True
        except ImportError:
            self._model_available = False
            logger.info("sentence-transformers not available, using TF-IDF fallback")
        return self._model_available

    def encode(self, texts: List[str]) -> List[List[float]]:
        """Encode texts into embeddings.

        Args:
            texts: List of texts to encode.

        Returns:
            List of embedding vectors.
        """
        if self._init_model():
            embeddings = self._model.encode(texts)
            return [e.tolist() for e in embeddings]
        return self._tfidf_encode(texts)

    def similarity(self, text1: str, text2: str) -> float:
        """Compute similarity between two texts.

        Args:
            text1: First text.
            text2: Second text.

        Returns:
            Similarity score between 0.0 and 1.0.
        """
        embeddings = self.encode([text1, text2])
        return _cosine_similarity(embeddings[0], embeddings[1])

    def similarity_to_many(
        self, text: str, references: List[str]
    ) -> List[Tuple[str, float]]:
        """Compute similarity between text and multiple references.

        Args:
            text: The text to compare.
            references: Reference texts to compare against.

        Returns:
            List of (reference, similarity) tuples sorted by similarity.
        """
        all_texts = [text] + references
        embeddings = self.encode(all_texts)
        text_emb = embeddings[0]

        results = []
        for i, ref in enumerate(references):
            sim = _cosine_similarity(text_emb, embeddings[i + 1])
            results.append((ref, sim))

        results.sort(key=lambda x: x[1], reverse=True)
        return results

    def _tfidf_encode(self, texts: List[str]) -> List[List[float]]:
        """Simple TF-IDF-like encoding fallback."""
        import re
        from collections import Counter

        # Build vocabulary from all texts
        all_words: set = set()
        text_word_counts = []
        for text in texts:
            words = re.findall(r"\b\w+\b", text.lower())
            counter = Counter(words)
            text_word_counts.append(counter)
            all_words.update(words)

        vocab = sorted(all_words)
        vocab_idx = {w: i for i, w in enumerate(vocab)}

        # Compute TF vectors
        embeddings = []
        for counter in text_word_counts:
            total = max(sum(counter.values()), 1)
            vec = [0.0] * len(vocab)
            for word, count in counter.items():
                if word in vocab_idx:
                    vec[vocab_idx[word]] = count / total
            # Normalize
            norm = math.sqrt(sum(x * x for x in vec))
            if norm > 0:
                vec = [x / norm for x in vec]
            embeddings.append(vec)

        return embeddings


class EmbeddingGuardrail:
    """Semantic guardrail using vector embeddings.

    Enforces topic boundaries by checking text similarity against
    allowed and banned topic descriptions.

    Args:
        similarity_engine: SemanticSimilarity instance.
        allowed_threshold: Min similarity to allowed topics. Default 0.3.
        banned_threshold: Max similarity to banned topics. Default 0.6.
        ood_threshold: Threshold for out-of-distribution. Default 0.2.
    """

    def __init__(
        self,
        similarity_engine: Optional[SemanticSimilarity] = None,
        allowed_threshold: float = 0.3,
        banned_threshold: float = 0.6,
        ood_threshold: float = 0.2,
    ):
        self._similarity = similarity_engine or SemanticSimilarity()
        self.allowed_threshold = allowed_threshold
        self.banned_threshold = banned_threshold
        self.ood_threshold = ood_threshold
        self._allowed_topics: Dict[str, List[str]] = {}
        self._banned_topics: Dict[str, List[str]] = {}
        self._allowed_embeddings: Dict[str, List[List[float]]] = {}
        self._banned_embeddings: Dict[str, List[List[float]]] = {}

    def add_allowed_topics(
        self, topics: Dict[str, List[str]]
    ) -> EmbeddingGuardrail:
        """Add allowed topics with example descriptions.

        Args:
            topics: Dict mapping topic names to example descriptions.

        Returns:
            Self for chaining.
        """
        for name, examples in topics.items():
            self._allowed_topics[name] = examples
            self._allowed_embeddings[name] = self._similarity.encode(examples)
        return self

    def add_banned_topics(
        self, topics: Dict[str, List[str]]
    ) -> EmbeddingGuardrail:
        """Add banned topics with example descriptions.

        Args:
            topics: Dict mapping topic names to example descriptions.

        Returns:
            Self for chaining.
        """
        for name, examples in topics.items():
            self._banned_topics[name] = examples
            self._banned_embeddings[name] = self._similarity.encode(examples)
        return self

    def check(self, text: str) -> EmbeddingResult:
        """Check text against allowed and banned topics.

        Args:
            text: The text to check.

        Returns:
            EmbeddingResult with topic matching details.
        """
        text_embedding = self._similarity.encode([text])[0]

        # Check against banned topics
        banned_scores: Dict[str, float] = {}
        for name, embeddings in self._banned_embeddings.items():
            max_sim = max(
                _cosine_similarity(text_embedding, e) for e in embeddings
            ) if embeddings else 0.0
            banned_scores[name] = max_sim

        # Check if text matches any banned topic
        max_banned_topic = ""
        max_banned_score = 0.0
        for name, score in banned_scores.items():
            if score > max_banned_score:
                max_banned_score = score
                max_banned_topic = name

        if max_banned_score >= self.banned_threshold:
            return EmbeddingResult(
                is_allowed=False,
                closest_topic=max_banned_topic,
                similarity_score=max_banned_score,
                topic_scores={**banned_scores},
                details={
                    "reason": "matches_banned_topic",
                    "banned_topic": max_banned_topic,
                    "banned_score": max_banned_score,
                },
            )

        # Check against allowed topics
        allowed_scores: Dict[str, float] = {}
        for name, embeddings in self._allowed_embeddings.items():
            max_sim = max(
                _cosine_similarity(text_embedding, e) for e in embeddings
            ) if embeddings else 0.0
            allowed_scores[name] = max_sim

        max_allowed_topic = ""
        max_allowed_score = 0.0
        for name, score in allowed_scores.items():
            if score > max_allowed_score:
                max_allowed_score = score
                max_allowed_topic = name

        # Check if text is within allowed topics
        if self._allowed_topics:
            if max_allowed_score < self.allowed_threshold:
                # Check if it's out of distribution
                is_ood = max_allowed_score < self.ood_threshold
                return EmbeddingResult(
                    is_allowed=False,
                    closest_topic=max_allowed_topic,
                    similarity_score=max_allowed_score,
                    topic_scores={**allowed_scores, **banned_scores},
                    is_out_of_distribution=is_ood,
                    details={
                        "reason": "outside_allowed_topics" if not is_ood else "out_of_distribution",
                    },
                )

        all_scores = {**allowed_scores, **banned_scores}
        closest = max_allowed_topic or max_banned_topic

        return EmbeddingResult(
            is_allowed=True,
            closest_topic=closest,
            similarity_score=max(max_allowed_score, max_banned_score),
            topic_scores=all_scores,
            details={"reason": "within_allowed_topics"},
        )


__all__ = [
    "EmbeddingGuardrail",
    "EmbeddingResult",
    "SemanticSimilarity",
]
