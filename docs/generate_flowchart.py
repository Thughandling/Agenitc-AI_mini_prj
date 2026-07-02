#!/usr/bin/env python3
"""AI SecOps LangGraph pipeline flowchart → PNG + PDF."""
from __future__ import annotations

import os
from pathlib import Path

import matplotlib.pyplot as plt
from matplotlib.patches import FancyArrowPatch, FancyBboxPatch
from matplotlib.backends.backend_pdf import PdfPages

OUT_DIR = Path(__file__).resolve().parent
FONT = ["Apple SD Gothic Neo", "AppleGothic", "Malgun Gothic", "NanumGothic", "DejaVu Sans"]
plt.rcParams["font.family"] = FONT
plt.rcParams["axes.unicode_minus"] = False

# colors
C_INPUT = "#E3F2FD"
C_NODE = "#FFF8E1"
C_LLM = "#F3E5F5"
C_STATE = "#E8F5E9"
C_FUNC = "#ECEFF1"
C_EDGE = "#455A64"
C_PARALLEL = "#FF7043"


def box(ax, x, y, w, h, text, fc, ec="#37474F", fs=8, lw=1.2, bold=False):
    p = FancyBboxPatch(
        (x, y), w, h,
        boxstyle="round,pad=0.02,rounding_size=0.08",
        linewidth=lw, edgecolor=ec, facecolor=fc,
    )
    ax.add_patch(p)
    weight = "bold" if bold else "normal"
    ax.text(x + w / 2, y + h / 2, text, ha="center", va="center", fontsize=fs, weight=weight, wrap=True)


def arrow(ax, x1, y1, x2, y2, color=C_EDGE, style="-|>", lw=1.5):
    ax.add_patch(FancyArrowPatch((x1, y1), (x2, y2), arrowstyle=style, color=color, lw=lw, mutation_scale=12))


def draw_page1(ax):
    ax.set_xlim(0, 20)
    ax.set_ylim(0, 28)
    ax.axis("off")
    ax.text(10, 27.2, "AI SecOps Multi-Agent Pipeline — Node / State / Function Flow", ha="center", fontsize=14, weight="bold")
    ax.text(10, 26.5, "LangGraph StateGraph(SOCState)  |  app.invoke({raw_log, log_type})", ha="center", fontsize=9, color="#546E7A")

    # SOCState legend
    box(ax, 0.5, 24.2, 19, 1.8, "", C_STATE)
    ax.text(1, 25.5, "SOCState (공유 상태)", fontsize=9, weight="bold")
    ax.text(1, 24.7,
            "입력: raw_log, log_type  →  중간: parsed_log, classification, red_team, blue_team  →  출력: verdict, mitre, incident_report",
            fontsize=7.5)

    # Entry
    box(ax, 7, 22.5, 6, 0.9, "START\napp.invoke({raw_log, log_type})", C_INPUT, bold=True)
    arrow(ax, 10, 22.5, 10, 21.8)

    nodes = [
        {
            "name": "① parse_node",
            "y": 18.8,
            "read": "raw_log, log_type",
            "func": "parse_log(raw_log, log_type)",
            "ret": '{"parsed_log": ParsedLog}',
            "llm": False,
            "detail": "ParsedLog: log_type, raw, normalized, iocs[]",
        },
        {
            "name": "② classify_node",
            "y": 15.0,
            "read": "parsed_log",
            "func": "ask_json(model, …, schema=ClassificationResult)",
            "ret": '{"classification": ClassificationResult}',
            "llm": True,
            "detail": "is_attack, confidence, attack_type, summary",
        },
    ]

    for n in nodes:
        y = n["y"]
        box(ax, 1, y, 18, 2.6, "", C_NODE)
        ax.text(1.3, y + 2.2, n["name"], fontsize=10, weight="bold")
        ax.text(1.3, y + 1.75, f"📖 State 읽기: {n['read']}", fontsize=7.5, color="#1565C0")
        fc = C_LLM if n["llm"] else C_FUNC
        box(ax, 1.3, y + 0.95, 8.5, 0.65, n["func"], fc, fs=7)
        box(ax, 10.2, y + 0.95, 8.3, 0.65, f"↳ 반환 → State: {n['ret']}", C_STATE, fs=7)
        ax.text(1.3, y + 0.35, f"필드: {n['detail']}", fontsize=7, color="#546E7A")
        if n != nodes[-1]:
            arrow(ax, 10, y, 10, y - 0.5)

    arrow(ax, 10, 15.0, 10, 14.3)
    ax.text(10, 14.0, "병렬 분기 (Parallelization)", ha="center", fontsize=9, color=C_PARALLEL, weight="bold")

    # parallel nodes
    par = [
        ("③ red_team_node", 11.5, "parsed_log, classification",
         "ask_json(…, schema=RedTeamAnalysis)", '{"red_team": RedTeamAnalysis}',
         "attack_hypothesis, evidence[], confidence"),
        ("③ blue_team_node", 8.0, "parsed_log, classification",
         "ask_json(…, schema=BlueTeamAnalysis)", '{"blue_team": BlueTeamAnalysis}',
         "benign_hypothesis, evidence[], confidence"),
    ]
    for name, y, read, func, ret, detail in par:
        box(ax, 0.8 if "red" in name else 10.2, y, 8.8, 2.5, "", C_NODE)
        x0 = 0.8 if "red" in name else 10.2
        ax.text(x0 + 0.3, y + 2.1, name, fontsize=9, weight="bold")
        ax.text(x0 + 0.3, y + 1.7, f"📖 {read}", fontsize=7, color="#1565C0")
        box(ax, x0 + 0.3, y + 0.95, 8.2, 0.55, func, C_LLM, fs=6.5)
        box(ax, x0 + 0.3, y + 0.3, 8.2, 0.55, f"↳ {ret}", C_STATE, fs=6.5)
        ax.text(x0 + 0.3, y + 0.05, detail, fontsize=6.5, color="#546E7A")

    arrow(ax, 5.2, 11.5, 8.5, 10.8)
    arrow(ax, 14.8, 11.5, 11.5, 10.8)
    ax.text(10, 10.5, "합류 (join)", ha="center", fontsize=8, color=C_PARALLEL)

    tail = [
        ("④ judge_node", 7.2, "parsed_log, classification, red_team, blue_team",
         "ask_json(…, schema=JudgeVerdict)", '{"verdict": JudgeVerdict}',
         "verdict, tp_fp, confidence, rationale, final_rationale", True),
        ("⑤ mitre_node", 4.0, "parsed_log, verdict",
         "ask_json(…, schema=MitreMapping)", '{"mitre": MitreMapping}',
         "technique_ids[], recommendations[], severity", True),
        ("⑥ report_node", 0.8, "parsed_log, verdict, mitre",
         "ask_json(…, schema=IncidentReport)", '{"incident_report": IncidentReport}',
         "title, executive_summary, full_report_markdown", True),
    ]
    prev_y = 10.2
    for name, y, read, func, ret, detail, llm in tail:
        arrow(ax, 10, prev_y, 10, y + 2.6)
        box(ax, 1, y, 18, 2.6, "", C_NODE)
        ax.text(1.3, y + 2.2, name, fontsize=10, weight="bold")
        ax.text(1.3, y + 1.75, f"📖 State 읽기: {read}", fontsize=7.5, color="#1565C0")
        box(ax, 1.3, y + 0.95, 8.5, 0.65, func, C_LLM if llm else C_FUNC, fs=7)
        box(ax, 10.2, y + 0.95, 8.3, 0.65, f"↳ 반환 → State: {ret}", C_STATE, fs=7)
        ax.text(1.3, y + 0.35, f"필드: {detail}", fontsize=7, color="#546E7A")
        prev_y = y

    arrow(ax, 10, 0.8, 10, 0.2)
    box(ax, 7.5, -0.5, 5, 0.6, "END → result (전체 SOCState)", C_INPUT, fs=8, bold=True)


def draw_page2(ax):
    ax.set_xlim(0, 20)
    ax.set_ylim(0, 28)
    ax.axis("off")
    ax.text(10, 27.2, "Function Call Detail — parse_log & ask_json 내부 흐름", ha="center", fontsize=14, weight="bold")

    # parse_log
    box(ax, 0.5, 23.5, 19, 3.2, "", C_FUNC)
    ax.text(1, 26.2, "parse_log(raw_log, log_type) → ParsedLog", fontsize=10, weight="bold")
    steps = [
        "1. raw_log가 dict → json.dumps / str → raw 문자열",
        "2. log_type=='auto' → process/command_line 키워드로 edr|waf 자동 판별",
        "3. IP_RE 정규식 → iocs[] (type=ip)",
        "4. uri/url 필드 → iocs[] (type=url)",
        "5. return ParsedLog(log_type, raw, normalized, iocs)",
    ]
    for i, s in enumerate(steps):
        ax.text(1.2, 25.5 - i * 0.45, s, fontsize=7.5)

    arrow(ax, 10, 23.5, 10, 22.8)

    # ask_json
    box(ax, 0.5, 14.5, 19, 8.0, "", C_LLM)
    ax.text(1, 22.0, "ask_json(model, system, user, log_raw, schema) → dict", fontsize=10, weight="bold")
    flow = [
        ("model is None (mock)", "_mock_json(system, user, log_raw)\n  → log_is_attack() 키워드 휴리스틱", 21.0),
        ("schema 있음", "model.with_structured_output(schema).invoke(prompt)\n  → Pydantic.model_dump() → dict", 19.8),
        ("fallback", "model.invoke(prompt + strict JSON 지시)", 18.4),
        ("응답 파싱", "_to_text(response.content)  # Gemini list 대응", 17.2),
        ("JSON decode", "_parse_json_text: json → json5 → json_repair", 16.0),
        ("재시도", "파싱 실패 시 model.invoke() 1회 재요청", 14.9),
    ]
    for title, desc, yy in flow:
        box(ax, 1, yy - 0.35, 3.5, 0.7, title, "#EDE7F6", fs=7, bold=True)
        box(ax, 4.8, yy - 0.35, 14.2, 0.7, desc, "#FAFAFA", fs=7)

    arrow(ax, 10, 14.5, 10, 13.8)

    # get_chat_model
    box(ax, 0.5, 11.5, 19, 2.0, "", C_FUNC)
    ax.text(1, 13.0, "get_chat_model() → ChatModel | None", fontsize=10, weight="bold")
    ax.text(1.2, 12.4, "LLM_PROVIDER=mock → None  |  gemini → init_chat_model(GEMINI, google_genai)  |  openai → init_chat_model(OPENAI)", fontsize=7.5)
    ax.text(1.2, 11.8, "노드에서 model / _llm() 호출 → ask_json에 전달", fontsize=7.5)

    arrow(ax, 10, 11.5, 10, 10.8)

    # state merge
    box(ax, 0.5, 7.5, 19, 3.0, "", C_STATE)
    ax.text(1, 10.0, "LangGraph State 병합 규칙", fontsize=10, weight="bold")
    ax.text(1.2, 9.3, "각 node 함수: state: SOCState 읽기 → dict 반환  →  LangGraph가 키별 merge", fontsize=8)
    ax.text(1.2, 8.7, "예: classify_node returns {classification: …}  →  state['classification'] 갱신", fontsize=8)
    ax.text(1.2, 8.1, "병렬 red_team + blue_team 각각 독립 dict 반환 → judge 진입 전까지 두 필드 모두 채워짐", fontsize=8)
    ax.text(1.2, 7.65, "최종 app.invoke() 반환값 = 모든 필드가 채워진 SOCState dict", fontsize=8)

    # graph edges table
    box(ax, 0.5, 0.5, 19, 6.5, "", "#FAFAFA")
    ax.text(1, 6.5, "Graph Edges (workflow.compile())", fontsize=10, weight="bold")
    edges = [
        "START → parse → classify",
        "classify → red_team  ∥  classify → blue_team  (병렬)",
        "red_team → judge  +  blue_team → judge  (합류)",
        "judge → mitre → report → END",
    ]
    for i, e in enumerate(edges):
        ax.text(1.2, 5.9 - i * 0.55, f"• {e}", fontsize=8)

    ax.text(1, 3.5, "Pydantic Models (Agent 간 데이터 형식)", fontsize=9, weight="bold")
    models = "ParsedLog | ClassificationResult | RedTeamAnalysis | BlueTeamAnalysis | JudgeVerdict | MitreMapping | IncidentReport | IOC"
    ax.text(1.2, 3.0, models, fontsize=7, wrap=True)
    ax.text(1, 2.0, "실행 예: result = app.invoke({'raw_log': WAF_LOG, 'log_type': 'waf'})", fontsize=8, color="#1565C0")
    ax.text(1.2, 1.4, "result['verdict'].final_rationale  |  result['incident_report'].executive_summary", fontsize=7.5)


def main():
    os.environ.setdefault("MPLCONFIGDIR", str(OUT_DIR / ".mpl_cache"))
    (OUT_DIR / ".mpl_cache").mkdir(exist_ok=True)

    png_path = OUT_DIR / "AI_SecOps_Flowchart.png"
    pdf_path = OUT_DIR / "AI_SecOps_Flowchart.pdf"

    fig1 = plt.figure(figsize=(14, 18), dpi=150)
    draw_page1(fig1.add_axes([0, 0, 1, 1]))
    fig1.savefig(png_path, bbox_inches="tight", facecolor="white")
    plt.close(fig1)

    with PdfPages(pdf_path) as pdf:
        for draw in (draw_page1, draw_page2):
            fig = plt.figure(figsize=(14, 18))
            draw(fig.add_axes([0, 0, 1, 1]))
            pdf.savefig(fig, bbox_inches="tight", facecolor="white")
            plt.close(fig)

    # high-res single-page PNG for page2 as supplement
    fig2 = plt.figure(figsize=(14, 18), dpi=150)
    draw_page2(fig2.add_axes([0, 0, 1, 1]))
    fig2.savefig(OUT_DIR / "AI_SecOps_Flowchart_Functions.png", bbox_inches="tight", facecolor="white")
    plt.close(fig2)

    print(f"PNG: {png_path}")
    print(f"PNG: {OUT_DIR / 'AI_SecOps_Flowchart_Functions.png'}")
    print(f"PDF: {pdf_path}")


if __name__ == "__main__":
    main()
