import math
from collections import Counter

def shannon_entropy(data: str) -> float:
    """Calculate the Shannon entropy of a string."""
    if not data:
        return 0.0

    length = len(data)
    frequency = Counter(data)

    entropy = -sum((count / length) * math.log2(count / length) for count in frequency.values())

    return entropy

# Example usage
if __name__ == "__main__":
    test_string = "123456"
    print(f"Shannon Entropy of '{test_string}': {shannon_entropy(test_string)}")