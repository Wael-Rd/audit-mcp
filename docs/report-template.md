# One-pass professional report template

The template is supplied by the MCP, so the AI spends its time on assessment prose. `get_report_context` supplies the exact subject, ten sections, compact evidence, ISO links, a writing brief and a strict schema. `render_report` accepts only that schema for commentary.

```json
{
  "title": "Confidentiality, by design.",
  "executive_summary": "A concise, evidence-based assessment with findings and limitations.",
  "context": "Scope, target environment, owner and collection boundary.",
  "priorities": ["Assign an owner and verify treatment of finding C06."],
  "step_notes": [
    {"step": 1, "note": "Risk, observation, treatment and remaining verification for this domain."}
  ]
}
```

Suggested output: a 120–180 word summary, one short context paragraph, up to five priorities and optional 50–80 word notes for each step. Duplicate steps, extra keys and oversized fields are rejected. Evidence status counts cannot be provided through the narrative schema.

The supplied design includes a dark editorial cover, restrained mint palette, responsive navigation, evidence filters/search, ISO chips, a change-comparison table, review callouts and a clean PDF print layout. It is entirely offline. HTML commentary is escaped; only packaged CSS and JavaScript are trusted. The content-security policy hashes those assets and blocks network access.

The HTML and Markdown contain all ten steps. JSON contains the underlying report evidence. The Markdown version supports GitHub review; the HTML version provides the complete visual layout. Use Print / Save PDF in a browser to produce a PDF.

AI narrative remains commentary. It can be inaccurate even when it is safely escaped. The renderer preserves the collected evidence tables, and a system owner should review the narrative before sharing the report.
