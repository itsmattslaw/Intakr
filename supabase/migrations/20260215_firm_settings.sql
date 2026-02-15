-- =============================================
-- FIRM SETTINGS TABLE — 2026-02-15
-- =============================================
-- Stores firm-wide settings (logo, Slack toggle, etc.)
-- so they persist across sessions and logouts.
-- Shared by all @margolispllc.com users.
--
-- Run this in the Supabase SQL Editor (Dashboard > SQL Editor).
-- =============================================

CREATE TABLE IF NOT EXISTS firm_settings (
  key   TEXT PRIMARY KEY,
  value TEXT NOT NULL,
  updated_by UUID REFERENCES auth.users(id),
  updated_at TIMESTAMPTZ DEFAULT now()
);

ALTER TABLE firm_settings ENABLE ROW LEVEL SECURITY;
ALTER TABLE firm_settings FORCE ROW LEVEL SECURITY;

-- SELECT: any authenticated @margolispllc.com user can read all settings
CREATE POLICY "Org users can read firm settings"
  ON firm_settings FOR SELECT
  USING (
    auth.jwt() ->> 'email' LIKE '%@margolispllc.com'
  );

-- INSERT: any authenticated @margolispllc.com user can create settings
CREATE POLICY "Org users can insert firm settings"
  ON firm_settings FOR INSERT
  WITH CHECK (
    auth.jwt() ->> 'email' LIKE '%@margolispllc.com'
  );

-- UPDATE: any authenticated @margolispllc.com user can update settings
CREATE POLICY "Org users can update firm settings"
  ON firm_settings FOR UPDATE
  USING (
    auth.jwt() ->> 'email' LIKE '%@margolispllc.com'
  );

-- DELETE: any authenticated @margolispllc.com user can delete settings
CREATE POLICY "Org users can delete firm settings"
  ON firm_settings FOR DELETE
  USING (
    auth.jwt() ->> 'email' LIKE '%@margolispllc.com'
  );
