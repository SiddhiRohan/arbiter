"""
Arbiter — Query Intent Scoping
Determines the MINIMUM set of resources a query actually needs,
within the user's authorized scope.

Instead of dumping all authorized data into the LLM context,
this module answers: "What does this specific question need?"

The LLM sees the INTERSECTION of:
  - What the role is authorized to access (policy engine)
  - What the query actually requires (this module)

This implements the Minimum Necessary Access principle
required by FERPA, HIPAA, and GDPR.

Fully generic — resource patterns are defined as config, not hardcoded.
New resources just need a keyword entry in RESOURCE_PATTERNS.
"""

import re
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class QueryIntent:
    """Result of classifying a user query."""
    required_resources: list[str]
    intent_category: str
    confidence: float
    explanation: str
    keywords_matched: list[str] = field(default_factory=list)


# ================================================================
# Resource Pattern Registry
#
# Maps resource names to keywords and regex phrases that indicate
# the query needs that resource. Add a new resource here and
# the classifier picks it up automatically.
#
# "weight" determines priority when multiple resources match.
# Higher weight = more likely to be the primary intent.
# ================================================================

RESOURCE_PATTERNS = {
    "grades": {
        "keywords": [
            "grade", "grades", "gpa", "midterm", "final exam", "final grade",
            "score", "scores", "academic record", "transcript", "marks",
            "academic performance", "test score", "exam", "pass", "fail",
            "attendance", "attendance rate", "report card",
        ],
        "phrases": [
            r"how (?:am i|is \w+) doing in",
            r"did (?:i|they|\w+) pass",
            r"what (?:grade|score|mark)",
        ],
        "weight": 3,
    },
    "financial_information": {
        "keywords": [
            "salary", "salaries", "pay", "compensation", "wage", "income",
            "tuition", "fees", "balance", "payment", "financial aid",
            "scholarship", "billing", "cost", "owe", "owed", "stipend",
            "budget personal", "expense", "amount due", "amount paid",
            "how much do", "how much does", "how much is",
        ],
        "phrases": [
            r"how much (?:do|does|is|are)",
            r"(?:tuition|salary|pay|cost|fee|balance)",
            r"financial (?:record|information|data|status|aid)",
        ],
        "weight": 3,
    },
    "persons": {
        "keywords": [
            "who is", "who are", "contact", "email", "phone", "name",
            "person", "people", "staff", "faculty", "student list",
            "directory", "department member", "professor", "teacher",
            "instructor", "advisor", "dean", "role", "title",
        ],
        "phrases": [
            r"who (?:is|are|teaches)",
            r"tell me about",
            r"information (?:about|on|for)",
            r"contact (?:info|information|details)",
        ],
        "weight": 1,
    },
    "classes": {
        "keywords": [
            "class", "classes", "course", "courses", "schedule", "room",
            "section", "enrollment", "enrolled", "register", "credit",
            "credits", "syllabus", "classroom", "lecture", "lab",
            "meeting time", "office hours", "prerequisite", "where is",
            "when is", "what time",
        ],
        "phrases": [
            r"what (?:room|time|class|course)",
            r"where is (?:the )?(?:class|course|lecture)",
            r"when (?:is|does) (?:the )?(?:class|course)",
            r"(?:enrolled|registered) (?:in|for)",
        ],
        "weight": 2,
    },
    "departments": {
        "keywords": [
            "department", "departments", "dept", "faculty count",
            "department budget", "research budget", "operating budget",
            "ta stipend", "department head", "how many faculty",
            "department funding",
        ],
        "phrases": [
            r"(?:department|dept) (?:budget|funding|head|size)",
            r"how many (?:faculty|professors|teachers) in",
        ],
        "weight": 2,
    },
    "academic_standing": {
        "keywords": [
            "standing", "academic standing", "probation", "dean's list",
            "good standing", "academic status", "credits completed",
            "gpa", "cumulative gpa", "academic probation", "suspension",
        ],
        "phrases": [
            r"(?:academic )?(?:standing|probation|status)",
            r"(?:on|is .* on) (?:probation|dean.s list)",
            r"how many credits",
        ],
        "weight": 3,
    },
}

# Queries that are clearly general / conversational and need no data
GENERAL_PATTERNS = [
    r"^(?:hi|hello|hey|thanks|thank you|bye|goodbye|good morning|good afternoon)",
    r"^(?:what can you|how can you|what do you|help me|can you help)",
    r"^(?:who are you|what are you|what is arbiter)",
]

# Broad queries that should get all authorized resources
BROAD_PATTERNS = [
    r"(?:show|give|tell|list|display) (?:me )?(?:all|everything|all data)",
    r"what (?:data|information|records) (?:do i|can i|do you have)",
    r"(?:full|complete) (?:report|summary|overview|breakdown)",
    r"summarize (?:all|everything)",
]


def classify_query(query: str, available_resources: Optional[list[str]] = None) -> QueryIntent:
    """
    Classify a user query to determine which resources it requires.

    Args:
        query: the raw user query string
        available_resources: optional list of resource names to consider
            (if None, checks against all patterns)

    Returns:
        QueryIntent with the minimum set of resources needed.
        If ambiguous or broad, returns all available resources.
    """
    query_lower = query.lower().strip()

    # Check for general/conversational queries — no data needed
    for pattern in GENERAL_PATTERNS:
        if re.search(pattern, query_lower):
            return QueryIntent(
                required_resources=[],
                intent_category="general",
                confidence=0.9,
                explanation="Conversational query — no data resources needed.",
            )

    # Check for broad queries — return everything
    for pattern in BROAD_PATTERNS:
        if re.search(pattern, query_lower):
            resources = available_resources or list(RESOURCE_PATTERNS.keys())
            return QueryIntent(
                required_resources=resources,
                intent_category="broad",
                confidence=0.8,
                explanation="Broad data request — all authorized resources included.",
            )

    # Score each resource by keyword and phrase matches
    scores = {}
    matched_keywords = {}

    for resource_name, patterns in RESOURCE_PATTERNS.items():
        if available_resources and resource_name not in available_resources:
            continue

        score = 0
        matches = []

        # Keyword matching
        for keyword in patterns["keywords"]:
            if keyword in query_lower:
                score += patterns["weight"]
                matches.append(keyword)

        # Phrase matching (regex)
        for phrase in patterns["phrases"]:
            if re.search(phrase, query_lower):
                score += patterns["weight"] * 2  # phrases are stronger signals
                matches.append(f"/{phrase}/")

        if score > 0:
            scores[resource_name] = score
            matched_keywords[resource_name] = matches

    # No matches — ambiguous, return all available
    if not scores:
        resources = available_resources or list(RESOURCE_PATTERNS.keys())
        return QueryIntent(
            required_resources=resources,
            intent_category="ambiguous",
            confidence=0.3,
            explanation="No specific resource keywords detected — including all authorized resources.",
        )

    # Sort by score, take resources above threshold
    max_score = max(scores.values())
    threshold = max_score * 0.3  # include resources with at least 30% of top score

    required = [r for r, s in scores.items() if s >= threshold]
    all_matches = []
    for r in required:
        all_matches.extend(matched_keywords.get(r, []))

    # Always include 'persons' if other resources are needed
    # (names are needed for context in almost every query)
    if required and "persons" not in required:
        if available_resources is None or "persons" in available_resources:
            required.append("persons")

    # Confidence based on how clear the top signal is
    if len(scores) == 1:
        confidence = 0.95
    elif max_score > 6:
        confidence = 0.85
    else:
        confidence = 0.65

    # Determine intent category from top-scoring resource
    top_resource = max(scores, key=scores.get)
    category_map = {
        "grades": "academic_query",
        "financial_information": "financial_query",
        "persons": "directory_query",
        "classes": "schedule_query",
        "departments": "institutional_query",
        "academic_standing": "standing_query",
    }
    category = category_map.get(top_resource, "data_query")

    return QueryIntent(
        required_resources=required,
        intent_category=category,
        confidence=confidence,
        explanation=f"Query targets {', '.join(required)} based on keyword analysis.",
        keywords_matched=all_matches,
    )


def scope_resources(intent: QueryIntent, authorized_resources: list[str]) -> list[str]:
    """
    Intersect query intent with authorized resources.
    Returns the minimum necessary set: only what the query needs
    AND the role is allowed to see.
    """
    if not intent.required_resources:
        return []

    return [r for r in intent.required_resources if r in authorized_resources]