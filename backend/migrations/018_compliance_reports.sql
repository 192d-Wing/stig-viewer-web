-- Scheduled fleet-wide compliance reports. One row per generated PDF.
-- The pdf_path is stored relative to the app's data_dir so the row
-- survives data_dir relocations during ops work. summary holds enough
-- metadata to render a list-row without re-parsing the PDF.
CREATE TABLE compliance_reports (
    id           TEXT PRIMARY KEY,
    generated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    -- Window the report covers, in days. The fleet KPIs are point-in-time
    -- but the per-asset trend lines look back this many days.
    range_days   INT NOT NULL,
    summary      JSONB NOT NULL DEFAULT '{}'::jsonb,
    pdf_path     TEXT NOT NULL
);

CREATE INDEX compliance_reports_generated_idx
    ON compliance_reports(generated_at DESC);
