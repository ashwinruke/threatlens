"""Run the AI evaluation: write a report for every frozen case and score it.

    python -m scripts.run_eval                    # report writer and judge from your .env
    python -m scripts.run_eval --runs 3           # each case 3 times, to see how much answers vary
    python -m scripts.run_eval --judge none       # rule-based checks only (no judge calls)
    python -m scripts.run_eval --cases ip-mirai,inject-otx
    python -m scripts.run_eval --regrade evals/results/latest.json   # re-score a saved run, no AI calls

The sources are never called: every case is the frozen evidence in evals/cases.json, so the only
thing being tested is the AI and ThreatLens's guardrails around it. It uses the same prompt,
the same parser and the same guardrails as production.

Results go to evals/results/ (full detail), frontend/src/data/evaluation.json (the website's
Evaluation page) and the README (between the eval markers). --no-publish skips the last two.
"""
import argparse
import asyncio
import hashlib
import json
import re
import time
from datetime import datetime, timezone
from pathlib import Path

import httpx2

from app.ai.grounding import Evidence
from app.ai.prompt import SYSTEM_PROMPT, user_message
from app.ai.providers import GeminiProvider, GroqProvider, ProviderError
from app.ai.report import _check, _parse
from app.config import Settings, get_settings
from evals.grading import grade, summarize
from evals.judge import judge_report

BACKEND = Path(__file__).resolve().parent.parent
CASES = BACKEND / "evals" / "cases.json"
RESULTS = BACKEND / "evals" / "results"
SITE_DATA = BACKEND.parent / "frontend" / "src" / "data" / "evaluation.json"
README = BACKEND.parent / "README.md"
PROVIDERS = {"groq": GroqProvider, "gemini": GeminiProvider}


def make_provider(name: str, settings: Settings, model: str | None):
    provider = PROVIDERS[name](settings, model=model or None, timeout=90)
    if not provider.is_configured():
        raise SystemExit(f"{provider.name} isn't configured: add its API key to backend/.env")
    return provider


async def ask(provider, system: str, message: str, client: httpx2.AsyncClient):
    """One call, waiting out free-tier rate limits instead of failing the case."""
    for attempt in range(4):
        try:
            return await provider.complete(system, message, client)
        except ProviderError as exc:
            limited = "rate limit" in str(exc)
            if attempt == 3 or not (limited or exc.retryable):
                raise
            wait = 30 if limited else 5
            print(f"      {provider.name}: {exc}. Waiting {wait} s")
            await asyncio.sleep(wait)
        except (httpx2.TimeoutException, httpx2.RequestError):
            if attempt == 3:
                raise
            await asyncio.sleep(5)


async def run_case(case: dict, run: int, writer, judge, client) -> dict:
    record = {"case": case["id"], "run": run}
    started = time.perf_counter()
    try:
        completion = await ask(writer, SYSTEM_PROMPT, user_message(case["packet"]), client)
    except Exception as exc:
        record.update(error=f"{type(exc).__name__}: {exc}", grade=grade(case, None, None))
        return record
    record.update(ms=round((time.perf_counter() - started) * 1000), text=completion.text,
                  input_tokens=completion.input_tokens, output_tokens=completion.output_tokens)
    record.update(regrade(case, completion.text))
    if judge and record.get("shown"):
        try:
            record["judge"] = await judge_report(judge, case, record["shown"], client)
        except Exception as exc:
            record["judge_error"] = f"{type(exc).__name__}: {exc}"
    return record


def regrade(case: dict, text: str) -> dict:
    """Parse the model's answer, apply production's guardrails, and grade both versions."""
    try:
        draft = _parse(text)
    except Exception as exc:
        return {"parse_error": f"{type(exc).__name__}", "raw": None, "shown": None, "grade": grade(case, None, None)}
    valid_ids = {c["id"] for c in case["citations"]}
    parts, uncited, invented = _check(draft, valid_ids, Evidence(case["packet"]))
    raw = draft.model_dump()
    shown = {k: [i.model_dump() for i in v] if k in ("findings", "affected", "actions") else v for k, v in parts.items()}
    return {"raw": raw, "shown": shown, "removed_uncited": uncited, "removed_invented": invented,
            "grade": grade(case, raw, shown)}


def case_rows(cases: list[dict], records: list[dict]) -> list[dict]:
    """One compact row per case for the website."""
    rows = []
    for case in cases:
        mine = [r for r in records if r["case"] == case["id"]]
        graded = [r["grade"] for r in mine if r["grade"]["json_valid"]]
        examples = []
        for r in mine:
            for s in (r["grade"].get("raw") or {}).get("statements", []):
                if s["status"] in ("invented", "misattributed", "uncited") and len(examples) < 3:
                    examples.append({"text": s["text"][:220], "status": s["status"],
                                     "detail": ", ".join(s.get("invented") or s.get("misattributed") or []),
                                     "removed": s["status"] == "uncited" or any(x.split(":")[0] in
                                                ("cve", "cwe", "attack", "ip", "hash", "version") for x in s.get("invented") or [])})
            for d in (r.get("judge") or {}).get("details", []):
                if d["verdict"] == "unsupported" and len(examples) < 3:
                    examples.append({"text": d["text"][:220], "status": "judge: unsupported", "detail": d["reason"], "removed": False})
        facts_total = sum(g["facts"]["total"] for g in graded)
        judged = [v for r in mine for v in (r.get("judge") or {}).get("verdicts", [])]
        rows.append({
            "id": case["id"], "title": case["title"], "category": case["category"], "level": case["verdict"]["level"],
            "reports": len(mine), "valid": len(graded),
            "fact_recall_pct": round(100 * sum(len(g["facts"]["found"]) for g in graded) / facts_total, 1) if facts_total else None,
            "missed_facts": sorted({m for g in graded for m in g["facts"]["missed"]}),
            "contradictions": sorted({c for g in graded for c in g["contradictions"]}),
            "consistent": all(g["consistent"] for g in graded) if graded else None,
            "statements": sum(g["raw"]["counts"]["total"] for g in graded),
            "grounding": {k: sum(g["raw"]["counts"][k] for g in graded) for k in ("grounded", "misattributed", "invented", "no_specifics", "uncited")},
            "removed": sum(r.get("removed_uncited", 0) + r.get("removed_invented", 0) for r in mine),
            "judge_supported_pct": round(100 * judged.count("supported") / len(judged), 1) if judged else None,
            "injection": ({"resisted": all(g["injection"]["resisted"] for g in graded),
                           "flagged": all(g["injection"]["flagged"] for g in graded)}
                          if graded and "injection" in graded[0] else None),
            "examples": examples,
        })
    return rows


def _fmt(value, suffix="%") -> str:
    return "n/a" if value is None else f"{value:g}{suffix}"


def readme_block(meta: dict, summary: dict) -> str:
    judge = summary.get("judge")
    lines = [
        f"Latest run: {meta['ran_at'][:10]}, report writer **{meta['writer']['model']}**"
        + (f", judge **{meta['judge']['model']}**" if meta.get("judge") else "")
        + f", {meta['cases']} cases × {meta['runs']} run{'s' if meta['runs'] != 1 else ''} ({summary['reports']} reports, {summary['statements']} statements).",
        "",
        "| Measure | Result |",
        "|---|---|",
        f"| Valid report JSON | {_fmt(summary['json_valid_pct'])} |",
        f"| Facts a correct report must mention, found | {_fmt(summary['fact_recall_pct'])} |",
        f"| Specifics (IDs, numbers, versions) found in the cited source | {_fmt(summary['raw']['grounded_pct'])} |",
        f"| Specifics invented (not in the evidence), as written by the model | {_fmt(summary['raw']['invented_pct'])} |",
        f"| Specifics invented, as shown to users after the guardrails | {_fmt(summary['shown']['invented_pct'])} |",
        f"| Real fact, wrong source cited | {_fmt(summary['raw']['misattributed_pct'])} |",
        f"| Statements with no valid citation (removed) | {_fmt(summary['uncited_pct'])} |",
    ]
    if judge:
        lines.append(f"| Statements the judge found supported by their sources | {_fmt(judge['supported_pct'])} (partly {_fmt(judge['partly_pct'])}, unsupported {_fmt(judge['unsupported_pct'])}) |")
    lines += [
        f"| Reports that contradict the evidence | {_fmt(summary['reports_with_contradictions_pct'])} |",
        f"| Reports stating the same risk level as the verdict | {_fmt(summary['verdict_consistency_pct'])} |",
        f"| Prompt-injection attacks resisted | {_fmt(summary['injection']['resisted_pct'])} of {summary['injection']['attacks']} |",
        f"| Attacks the report warned about | {_fmt(summary['injection']['flagged_pct'])} |",
    ]
    return "\n".join(lines)


def publish(meta: dict, summary: dict, rows: list[dict]) -> None:
    SITE_DATA.parent.mkdir(parents=True, exist_ok=True)
    SITE_DATA.write_text(json.dumps({"meta": meta, "summary": summary, "cases": rows}, indent=1, ensure_ascii=False) + "\n",
                         encoding="utf-8")
    if README.exists():
        text = README.read_text(encoding="utf-8")
        block = f"<!-- eval:start -->\n{readme_block(meta, summary)}\n<!-- eval:end -->"
        new = re.sub(r"<!-- eval:start -->.*?<!-- eval:end -->", lambda _: block, text, flags=re.DOTALL)
        README.write_text(new, encoding="utf-8")
    print(f"Updated {SITE_DATA.name} for the website, and the README")


def print_summary(summary: dict) -> None:
    print("\nResults")
    print(f"  valid JSON                 {_fmt(summary['json_valid_pct'])}")
    print(f"  fact recall                {_fmt(summary['fact_recall_pct'])}")
    print(f"  specifics grounded         {_fmt(summary['raw']['grounded_pct'])}  (misattributed {_fmt(summary['raw']['misattributed_pct'])}, invented {_fmt(summary['raw']['invented_pct'])})")
    print(f"  invented after guardrails  {_fmt(summary['shown']['invented_pct'])}")
    print(f"  uncited statements         {_fmt(summary['uncited_pct'])}")
    if summary.get("judge"):
        j = summary["judge"]
        print(f"  judge: supported           {_fmt(j['supported_pct'])}  (partly {_fmt(j['partly_pct'])}, unsupported {_fmt(j['unsupported_pct'])})")
    print(f"  contradictions             {_fmt(summary['reports_with_contradictions_pct'])} of reports")
    print(f"  verdict consistency        {_fmt(summary['verdict_consistency_pct'])}")
    print(f"  injection resisted         {_fmt(summary['injection']['resisted_pct'])} of {summary['injection']['attacks']}  (flagged {_fmt(summary['injection']['flagged_pct'])})")


async def main_async(args) -> None:
    data = json.loads(CASES.read_text(encoding="utf-8"))
    cases = data["cases"]
    if args.cases:
        wanted = set(args.cases.split(","))
        cases = [c for c in cases if c["id"] in wanted]

    if args.regrade:
        saved = json.loads(Path(args.regrade).read_text(encoding="utf-8"))
        by_id = {c["id"]: c for c in cases}
        records = []
        for r in saved["records"]:
            if r["case"] in by_id and r.get("text"):
                records.append({**r, **regrade(by_id[r["case"]], r["text"])})
            elif r["case"] in by_id:
                records.append(r)
        meta = {**saved["meta"], "regraded_at": datetime.now(timezone.utc).isoformat(timespec="seconds")}
    else:
        settings = get_settings()
        order = [p.strip().lower() for p in settings.ai_provider_order.split(",") if p.strip()]
        writer_name = args.writer or next((p for p in order if PROVIDERS[p](settings).is_configured()), None)
        if not writer_name:
            raise SystemExit("No AI provider is configured: add GROQ_API_KEY or GEMINI_API_KEY to backend/.env")
        writer = make_provider(writer_name, settings, args.model)
        judge = None
        if args.judge != "none":
            judge_name = args.judge if args.judge != "auto" else next(
                (p for p in ("gemini", "groq") if p != writer_name and PROVIDERS[p](settings).is_configured()), None)
            if judge_name:
                default_judge_model = settings.agent_groq_model if judge_name == writer_name == "groq" else None
                judge = make_provider(judge_name, settings, args.judge_model or default_judge_model)
            else:
                print("No second AI provider for the judge, so only rule-based checks run (add GEMINI_API_KEY to use one).")
        print(f"Report writer: {writer.name} {writer.model}" + (f"   judge: {judge.name} {judge.model}" if judge else "   judge: none"))
        print(f"{len(cases)} cases × {args.runs} run(s)\n")

        records = []
        async with httpx2.AsyncClient() as client:
            for run in range(1, args.runs + 1):
                for case in cases:
                    record = await run_case(case, run, writer, judge, client)
                    records.append(record)
                    g = record["grade"]
                    status = ("ERROR " + record.get("error", record.get("parse_error", ""))[:60]) if not g["json_valid"] else (
                        f"facts {len(g['facts']['found'])}/{g['facts']['total']}  "
                        f"invented {g['raw']['counts']['invented']}  misattributed {g['raw']['counts']['misattributed']}"
                        + (f"  contradicts: {', '.join(g['contradictions'])}" if g["contradictions"] else "")
                        + (f"  injection {'resisted' if g['injection']['resisted'] else 'OBEYED'}" if "injection" in g else ""))
                    print(f"  run {run}  {case['id']:<22} {status}")
                    await asyncio.sleep(args.pace)
        meta = {"ran_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                "writer": {"provider": writer.name, "model": writer.model},
                "judge": {"provider": judge.name, "model": judge.model} if judge else None,
                "runs": args.runs, "cases": len(cases), "cases_built": data.get("built_at"),
                "prompt": hashlib.sha256(SYSTEM_PROMPT.encode()).hexdigest()[:10],
                "threatlens_version": settings.app_version}

    graded = [r["grade"] for r in records]
    judged = [r["judge"] for r in records if r.get("judge")]
    summary = summarize(graded, judged or None)
    print_summary(summary)

    RESULTS.mkdir(parents=True, exist_ok=True)
    full = {"meta": meta, "summary": summary, "records": records}
    stamp = meta["ran_at"][:19].replace(":", "")
    for path in (RESULTS / f"{stamp}_{re.sub(r'[^A-Za-z0-9.-]+', '-', meta['writer']['model'])}.json", RESULTS / "latest.json"):
        path.write_text(json.dumps(full, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"\nSaved full results to {(RESULTS / 'latest.json').relative_to(BACKEND.parent)}")
    if not args.no_publish and not args.cases:
        publish(meta, summary, case_rows(cases, records))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--writer", choices=list(PROVIDERS), help="report writer (default: the first configured)")
    parser.add_argument("--model", help="report writer model (default: from .env)")
    parser.add_argument("--judge", default="auto", choices=["auto", "none", *PROVIDERS],
                        help="AI judge (default: the other provider, so the writer isn't grading itself)")
    parser.add_argument("--judge-model", help="judge model")
    parser.add_argument("--runs", type=int, default=1, help="times to run each case (default 1)")
    parser.add_argument("--cases", help="comma-separated case ids (results aren't published)")
    parser.add_argument("--pace", type=float, default=3.0, help="seconds between cases, for free-tier rate limits")
    parser.add_argument("--regrade", help="re-score a saved results file without calling any AI")
    parser.add_argument("--no-publish", action="store_true", help="don't update the website data or the README")
    asyncio.run(main_async(parser.parse_args()))


if __name__ == "__main__":
    main()
