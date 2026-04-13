"""
AnaLM inference helper (llama.cpp backend) -- invoked as subprocess by security-analyst.ts.

Usage: python3 analm-infer-llamacpp.py <gguf_path> <task_type> <system_prompt_json> <user_message_json>

Loads the GGUF model via llama-cpp-python, runs inference, extracts JSON from the response.
Falls back to constructing structured data from prose if JSON extraction fails.
"""
import json
import sys
import re


def extract_json(text, task):
    """Try multiple strategies to extract JSON from model output."""
    # Strategy 1: direct parse
    try:
        return json.loads(text)
    except Exception:
        pass

    # Strategy 2: markdown code fence
    fence = re.search(r'```(?:json)?\s*(.+?)```', text, re.DOTALL)
    if fence:
        try:
            return json.loads(fence.group(1).strip())
        except Exception:
            pass

    # Strategy 3: find JSON object via brace matching
    depth = 0
    start = -1
    for i, c in enumerate(text):
        if c == '{':
            if depth == 0:
                start = i
            depth += 1
        elif c == '}':
            depth -= 1
            if depth == 0 and start >= 0:
                try:
                    return json.loads(text[start:i+1])
                except Exception:
                    start = -1

    # Strategy 4: construct structured data from prose
    if task == "threatAnalysis":
        r = {"confidence": 0.6, "description": text[:300].strip(), "mitigations": []}
        low = text.lower()
        for lv in ["critical", "high", "medium", "low", "none"]:
            if lv in low:
                r["threatLevel"] = lv
                break
        for line in text.split("\n"):
            s = line.strip()
            if s.startswith(("-", "*")) and len(s) > 12:
                r["mitigations"].append(re.sub(r'^[-*]\s*', '', s))
        if r.get("threatLevel"):
            return r

    if task == "credentialContextClassification":
        low = text.lower()
        for cls in ["real", "test", "example", "placeholder"]:
            if cls in low:
                return {"classification": cls, "reasoning": text[:300].strip(), "confidence": 0.6}

    if task == "falsePositiveDetection":
        low = text.lower()
        is_fp = "false positive" in low or "not a real" in low or "benign" in low
        return {"isFalsePositive": is_fp, "reasoning": text[:300].strip(), "confidence": 0.5}

    return None


def main():
    if len(sys.argv) != 5:
        print(json.dumps({"ok": False, "error": "usage: analm-infer-llamacpp.py <gguf_path> <task> <system_json> <user_json>"}))
        sys.exit(1)

    gguf_path = sys.argv[1]
    task_type = sys.argv[2]
    system_prompt = json.loads(sys.argv[3])
    user_message = json.loads(sys.argv[4])

    from llama_cpp import Llama

    llm = Llama(
        model_path=gguf_path,
        n_ctx=2048,
        n_threads=4,
        verbose=False,
    )

    response = llm.create_chat_completion(
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_message},
        ],
        max_tokens=512,
        temperature=0.1,
    )

    text = response["choices"][0]["message"]["content"]

    parsed = extract_json(text, task_type)
    if parsed:
        print(json.dumps({"ok": True, "result": parsed}))
    else:
        print(json.dumps({"ok": False, "raw": text[:500]}))


if __name__ == "__main__":
    main()
