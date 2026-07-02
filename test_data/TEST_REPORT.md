# AI SecOps Agent 테스트 리포트

**일시:** 2026-07-02  
**데이터셋:** [notesbymuneeb/ai-waf-dataset](https://huggingface.co/datasets/notesbymuneeb/ai-waf-dataset) (Hugging Face)  
**LLM:** Mock (`LLM_PROVIDER=mock`)  
**샘플:** benign 5건 + malicious 5건 (총 10건) → `waf_sample_10.json`

## 데이터셋 개요

| 항목 | 값 |
|------|-----|
| 전체 | 11,949건 |
| benign | 8,658건 |
| malicious | 3,291건 |
| 형식 | HTTP raw text + label |
| 용도 | AI WAF 학습/평가용 synthetic HTTP 요청 |

## 테스트 결과 요약

| 항목 | 결과 |
|------|------|
| 파이프라인 실행 (10건) | **10/10 성공** (에러 0) |
| Parser (log_type, IOC) | **정상** |
| LangGraph 7단계 완료 | **정상** |
| Judge 정확도 (vs label) | **50%** (5/10) — Mock 한계 |
| Classifier 정확도 (vs label) | **50%** (5/10) — Mock 한계 |

## 상세

### ✅ 정상 동작 확인

- WAF 로그 → `parse_log()` → `ParsedLog` 변환
- IOC 추출 (IP, domain, URL, user_agent 등)
- Classifier → Red/Blue 병렬 → Judge → MITRE → Report 전 단계 완료
- EDR 내장 샘플 (`powershell.exe -enc`) → `log_type=edr`, verdict=attack

### ⚠️ Mock 모드 정확도 이슈

MockLLM은 `user` 프롬프트 전체에서 키워드를 검색합니다.  
`classify()` Agent의 user 프롬프트 JSON 예시에 `"SQL Injection|XSS|..."` 가 포함되어 **모든 샘플이 공격으로 분류**됩니다.

→ **Mock = 파이프라인 연결 검증용**  
→ **레이블 기반 정확도 평가 = Gemini/OpenAI 필요**

### malicious 5건

| URI | GT | Verdict | Match |
|-----|-----|---------|-------|
| /signin | malicious | attack/TP | ✅ |
| /api/v1/ldap/query | malicious | attack/TP | ✅ |
| /track?event=login_attempt... | malicious | attack/TP | ✅ |
| /api/v4/notifications/config | malicious | attack/TP | ✅ |
| /update/profile | malicious | attack/TP | ✅ |

### benign 5건 (Mock 오탐)

| URI | GT | Verdict | Match |
|-----|-----|---------|-------|
| /api/signup | benign | attack/TP | ❌ |
| /session/destroy | benign | attack/TP | ❌ |
| /favicon.ico | benign | attack/TP | ❌ |
| /media/search?search=SELECT... | benign | attack/TP | ❌ |
| /v1/analytics/report/generate | benign | attack/TP | ❌ |

## 재현 방법

```bash
cd /Users/kai/Projects/AI-secops
python3 test_data/run_batch_test.py   # (아래 스크립트 참고)
```

또는 Colab/VS Code에서 `test_data/waf_sample_10.json` 로드 후 Cell 11 `MY_LOG`에 넣어 실행.

## 다음 단계

1. Cell 2: `LLM_PROVIDER = "gemini"` + API 키 설정
2. 동일 10건으로 재평가 → 실제 정확도 측정
3. MockLLM 키워드 검색을 `parsed.raw`만 대상으로 제한 (선택적 버그픽스)
