"""AI SecOps pipeline core — notebook과 테스트 공용."""
from __future__ import annotations

import json
import os
import re
from enum import Enum
from typing import Any, TypedDict

from langgraph.graph import END, START, StateGraph
from pydantic import BaseModel, Field

# ── Models ──────────────────────────────────────────────────────────


class LogType(str, Enum):
    WAF = "waf"
    EDR = "edr"
    AUTO = "auto"


class IOC(BaseModel):
    type: str
    value: str


class ParsedLog(BaseModel):
    log_type: str
    raw: str
    normalized: dict[str, Any] = Field(default_factory=dict)
    iocs: list[IOC] = Field(default_factory=list)


class ClassificationResult(BaseModel):
    is_attack: bool = False
    confidence: float = 0.0
    attack_type: str = ""
    summary: str = ""


class RedTeamAnalysis(BaseModel):
    attack_hypothesis: str = ""
    evidence: list[str] = Field(default_factory=list)
    confidence: float = 0.5


class BlueTeamAnalysis(BaseModel):
    benign_hypothesis: str = ""
    evidence: list[str] = Field(default_factory=list)
    confidence: float = 0.5


class JudgeVerdict(BaseModel):
    verdict: str = "investigate"
    tp_fp: str = "추가조사"
    confidence: float = 0.5
    rationale: str = ""           # 한 줄 요약
    final_rationale: str = ""       # LLM이 작성하는 최종 판단 근거 (상세)


class MitreMapping(BaseModel):
    technique_ids: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    severity: str = "medium"


class IncidentReport(BaseModel):
    title: str = "Security Incident Report"
    executive_summary: str = ""
    full_report_markdown: str = ""


class SOCState(TypedDict, total=False):
    raw_log: str | dict[str, Any]
    log_type: str
    parsed_log: ParsedLog
    classification: ClassificationResult
    red_team: RedTeamAnalysis
    blue_team: BlueTeamAnalysis
    verdict: JudgeVerdict
    mitre: MitreMapping
    incident_report: IncidentReport


# ── Parser ──────────────────────────────────────────────────────────

IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
ATTACK_KW = (
    "union select", "sql injection", "drop table", "powershell -enc",
    "mimikatz", "<script", "../", "or 1=1", "exec(", "xss",
)


def parse_log(raw_log: str | dict, log_type: str = "auto") -> ParsedLog:
    raw = json.dumps(raw_log, ensure_ascii=False) if isinstance(raw_log, dict) else str(raw_log).strip()
    data = dict(raw_log) if isinstance(raw_log, dict) else {"message": raw}
    lt = log_type if log_type != "auto" else (
        "edr" if any(k in raw.lower() for k in ("process", "command_line", "powershell")) else "waf"
    )
    iocs: list[IOC] = []
    for ip in IP_RE.findall(raw):
        iocs.append(IOC(type="ip", value=ip))
    uri = str(data.get("uri") or data.get("url") or "")
    if uri:
        iocs.append(IOC(type="url", value=uri))
    return ParsedLog(log_type=lt, raw=raw, normalized=data, iocs=iocs)


def dataset_row_to_log(row: dict) -> dict:
    text = row["text"]
    lines = text.strip().split("\n")
    method, uri = "GET", "/"
    if lines and " " in lines[0]:
        parts = lines[0].split(" ")
        method = parts[0]
        uri = parts[1] if len(parts) > 1 else "/"
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if ": " in line:
            k, v = line.split(": ", 1)
            headers[k.lower()] = v
    return {
        "source": "ai-waf-dataset",
        "http_method": method,
        "uri": uri,
        "user_agent": headers.get("user-agent", ""),
        "host": headers.get("host", ""),
        "client_ip": "198.51.100.1",
        "action": "BLOCK" if row.get("label") == "malicious" else "ALLOW",
        "message": text[:800],
    }


def log_is_attack(raw: str) -> bool:
    t = raw.lower()
    return any(k in t for k in ATTACK_KW)


# ── LLM ─────────────────────────────────────────────────────────────


def _to_text(content: Any) -> str:
    if content is None:
        return ""
    if isinstance(content, str):
        return content
    if isinstance(content, dict):
        if content.get("type") == "text" and "text" in content:
            return str(content["text"])
        return json.dumps(content, ensure_ascii=False)
    if isinstance(content, list):
        parts: list[str] = []
        for block in content:
            if isinstance(block, str):
                parts.append(block)
            elif isinstance(block, dict):
                parts.append(str(block.get("text") or block.get("content") or ""))
            elif hasattr(block, "text"):
                parts.append(str(block.text or ""))
            else:
                parts.append(str(block))
        return "".join(parts)
    return str(content)


def _strip_code_fence(text: str) -> str:
    text = text.strip()
    if not text.startswith("```"):
        return text
    lines = text.splitlines()
    body = lines[1:-1] if lines and lines[-1].startswith("```") else lines[1:]
    if body and body[0].strip().lower() == "json":
        body = body[1:]
    return "\n".join(body).strip()


def _parse_json_text(text: str) -> dict:
    """LLM 응답 → dict. json → json5 → json_repair 순으로 시도."""
    last_err: Exception | None = None
    raw = _strip_code_fence(text)
    candidates = [raw]
    start, end = raw.find("{"), raw.rfind("}")
    if start >= 0 and end > start:
        candidates.append(raw[start : end + 1])

    loaders: list[tuple[str, Any]] = [("json", json.loads)]
    try:
        import json5

        loaders.append(("json5", json5.loads))
    except ImportError:
        pass
    try:
        from json_repair import repair_json

        loaders.append(("json_repair", lambda s: json.loads(repair_json(s))))
    except ImportError:
        pass

    for cand in candidates:
        for name, loader in loaders:
            try:
                data = loader(cand)
                if isinstance(data, dict):
                    return data
            except Exception as e:
                last_err = e
    if isinstance(last_err, json.JSONDecodeError):
        raise last_err
    raise json.JSONDecodeError(str(last_err or "JSON parse failed"), raw, 0)


def get_chat_model():
    provider = os.environ.get("LLM_PROVIDER", "mock")
    if provider == "mock":
        return None
    from langchain.chat_models import init_chat_model

    if provider == "gemini":
        model_name = os.environ.get("GEMINI_MODEL", "gemini-2.0-flash")
        return init_chat_model(model_name, model_provider="google_genai", temperature=0.1)
    model_name = os.environ.get("OPENAI_MODEL", "gpt-4o-mini")
    return init_chat_model(model_name, model_provider="openai", temperature=0.1)


def ask_json(
    model,
    system: str,
    user: str,
    log_raw: str = "",
    schema: type[BaseModel] | None = None,
) -> dict:
    if model is None:
        return _mock_json(system, user, log_raw)

    prompt = f"{system}\n\n{user}"

    if schema is not None:
        try:
            structured = model.with_structured_output(schema)
            out = structured.invoke(prompt)
            if isinstance(out, BaseModel):
                return out.model_dump()
            if isinstance(out, dict):
                return out
        except Exception:
            pass

    strict = (
        "\n\n반드시 유효한 JSON 객체만 출력하세요. "
        "문자열 값 안의 따옴표는 \\\" 로 이스케이프. 마크다운 코드블록 없이."
    )
    response = model.invoke(prompt + strict)
    text = _to_text(response.content)
    try:
        data = _parse_json_text(text)
    except (json.JSONDecodeError, ValueError):
        response = model.invoke(
            prompt + strict + "\n(이전 응답이 유효한 JSON이 아니었습니다. 다시 출력하세요.)"
        )
        text = _to_text(response.content)
        data = _parse_json_text(text)
    if not isinstance(data, dict):
        raise ValueError(f"LLM JSON must be dict, got {type(data)}")
    return data


def _mock_json(system: str, user: str, log_raw: str) -> dict:
    s = system.lower()
    src = (log_raw or user).lower()
    is_attack = log_is_attack(src)

    if "classification" in s:
        return {
            "is_attack": is_attack,
            "confidence": 0.85 if is_attack else 0.2,
            "attack_type": "SQL Injection" if is_attack else "",
            "summary": "공격 의심" if is_attack else "정상/저위험",
        }
    if "judge" in s:
        if is_attack:
            return {
                "verdict": "attack",
                "tp_fp": "TP",
                "confidence": 0.78,
                "rationale": "Red Team 근거 우세",
                "final_rationale": (
                    "Red Team은 로그에서 공격 패턴(의심 페이로드·비정상 URI)을 근거로 공격 가능성을 높게 평가했습니다. "
                    "Blue Team은 오탐·정상 트래픽 가능성을 제시했으나, IOC 및 1차 분류 결과와 비교할 때 공격 근거가 더 설득력 있습니다. "
                    "따라서 본 이벤트는 실제 공격(TP)으로 판단합니다."
                ),
            }
        return {
            "verdict": "normal",
            "tp_fp": "FP",
            "confidence": 0.72,
            "rationale": "Blue Team 근거 우세",
            "final_rationale": (
                "Blue Team은 업무 트래픽·오탐 가능성 및 정상 HTTP 패턴을 근거로 정상 가능성을 높게 평가했습니다. "
                "Red Team의 공격 가설은 있으나 로그만으로는 악성 행위가 명확하지 않습니다. "
                "따라서 본 이벤트는 정상/오탐(FP)으로 판단합니다."
            ),
        }
    if "red team" in s:
        return {
            "attack_hypothesis": "공격 시도 가능" if is_attack else "공격 근거 약함",
            "evidence": ["의심 페이로드", "비정상 패턴"] if is_attack else ["명확한 공격 패턴 없음"],
            "confidence": 0.8 if is_attack else 0.3,
        }
    if "blue team" in s:
        return {
            "benign_hypothesis": "정상/오탐 가능" if not is_attack else "오탐 가능성 낮음",
            "evidence": ["업무 트래픽", "차단됨"] if not is_attack else ["공격 패턴 뚜렷"],
            "confidence": 0.7 if not is_attack else 0.25,
        }
    if "mitre" in s:
        return {
            "technique_ids": ["T1190"] if is_attack else [],
            "recommendations": ["IP 차단", "WAF 룰 점검"] if is_attack else ["모니터링 유지"],
            "severity": "high" if is_attack else "low",
        }
    if "incident report" in s:
        return {
            "title": "보안 이벤트 분석 리포트",
            "executive_summary": "공격으로 분류됨" if is_attack else "정상/저위험으로 분류됨",
            "full_report_markdown": f"# Report\n\n{'Attack' if is_attack else 'Normal'}",
        }
    return {}


# ── Nodes ───────────────────────────────────────────────────────────

_model = None


def _llm():
    global _model
    if _model is None:
        _model = get_chat_model()
    return _model


def parse_node(state: SOCState) -> dict:
    parsed = parse_log(state["raw_log"], state.get("log_type", "auto"))
    return {"parsed_log": parsed}


def classify_node(state: SOCState) -> dict:
    p = state["parsed_log"]
    result = ask_json(
        _llm(),
        "Attack Classification Agent. JSON keys: is_attack(bool), confidence(float), attack_type(str), summary(str)",
        f"로그:\n{p.raw[:2500]}",
        log_raw=p.raw,
        schema=ClassificationResult,
    )
    return {"classification": ClassificationResult.model_validate(result)}


def red_team_node(state: SOCState) -> dict:
    p, c = state["parsed_log"], state["classification"]
    result = ask_json(
        _llm(),
        "Red Team Agent. JSON keys: attack_hypothesis(str), evidence(list[str]), confidence(float)",
        f"classification={c.model_dump_json()}\n로그:\n{p.raw[:2500]}",
        log_raw=p.raw,
        schema=RedTeamAnalysis,
    )
    return {"red_team": RedTeamAnalysis.model_validate(result)}


def blue_team_node(state: SOCState) -> dict:
    p, c = state["parsed_log"], state["classification"]
    result = ask_json(
        _llm(),
        "Blue Team Agent. JSON keys: benign_hypothesis(str), evidence(list[str]), confidence(float)",
        f"classification={c.model_dump_json()}\n로그:\n{p.raw[:2500]}",
        log_raw=p.raw,
        schema=BlueTeamAnalysis,
    )
    return {"blue_team": BlueTeamAnalysis.model_validate(result)}


def judge_node(state: SOCState) -> dict:
    p = state["parsed_log"]
    c, r, b = state["classification"], state["red_team"], state["blue_team"]
    result = ask_json(
        _llm(),
        """Judge Agent (SOC Lead). Red Team vs Blue Team 분석을 종합해 최종 판정하세요.

JSON keys:
- verdict: attack | normal | investigate
- tp_fp: TP | FP | 추가조사
- confidence: float 0~1
- rationale: 한 줄 요약
- final_rationale: 최종 판단 근거 (4~6문장, 한국어). 반드시 포함:
  1) Red Team 핵심 근거 요약
  2) Blue Team 핵심 근거 요약
  3) 어느 쪽을 왜 채택했는지
  4) 로그/IOC와의 연결""",
        f"""## 1차 분류
{c.model_dump_json()}

## Red Team
{r.model_dump_json()}

## Blue Team
{b.model_dump_json()}

## IOC
{[i.model_dump() for i in p.iocs]}

## 로그 (발췌)
{p.raw[:2000]}""",
        log_raw=p.raw,
        schema=JudgeVerdict,
    )
    if not result.get("final_rationale"):
        result["final_rationale"] = result.get("rationale", "")
    return {"verdict": JudgeVerdict.model_validate(result)}


def mitre_node(state: SOCState) -> dict:
    p = state["parsed_log"]
    result = ask_json(
        _llm(),
        "MITRE Agent. JSON keys: technique_ids(list[str]), recommendations(list[str]), severity(str)",
        f"verdict={state['verdict'].model_dump_json()}",
        log_raw=p.raw,
        schema=MitreMapping,
    )
    return {"mitre": MitreMapping.model_validate(result)}


def report_node(state: SOCState) -> dict:
    p = state["parsed_log"]
    result = ask_json(
        _llm(),
        "Incident Report Agent. JSON keys: title(str), executive_summary(str), full_report_markdown(str)",
        f"verdict={state['verdict'].model_dump_json()}\nmitre={state['mitre'].model_dump_json()}",
        log_raw=p.raw,
        schema=IncidentReport,
    )
    return {"incident_report": IncidentReport.model_validate(result)}


# ── Graph ───────────────────────────────────────────────────────────

_app = None


def build_app():
    g = StateGraph(SOCState)
    g.add_node("parse", parse_node)
    g.add_node("classify", classify_node)
    g.add_node("red_team", red_team_node)
    g.add_node("blue_team", blue_team_node)
    g.add_node("judge", judge_node)
    g.add_node("mitre", mitre_node)
    g.add_node("report", report_node)

    g.add_edge(START, "parse")
    g.add_edge("parse", "classify")
    g.add_edge("classify", "red_team")
    g.add_edge("classify", "blue_team")
    g.add_edge("red_team", "judge")
    g.add_edge("blue_team", "judge")
    g.add_edge("judge", "mitre")
    g.add_edge("mitre", "report")
    g.add_edge("report", END)
    return g.compile()


def get_app():
    global _app
    if _app is None:
        _app = build_app()
    return _app


def analyze(raw_log: str | dict, log_type: str = "waf") -> dict:
    return get_app().invoke({"raw_log": raw_log, "log_type": log_type})
