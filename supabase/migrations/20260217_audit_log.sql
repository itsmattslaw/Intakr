-- =============================================
-- AUDIT LOG TABLE — 2026-02-17
-- =============================================
-- Tracks all significant user actions across the system
-- for compliance, accountability, and transparency.
-- Shared read access for all @margolispllc.com users.
--
-- Run this in the Supabase SQL Editor (Dashboard > SQL Editor).
-- =============================================

CREATE TABLE IF NOT EXISTS audit_log (
  id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
  user_id UUID REFERENCES auth.users(id),
  user_email TEXT NOT NULL,
  action TEXT NOT NULL,
  entity_type TEXT,
  entity_id UUID,
  details JSONB,
  created_at TIMESTAMPTZ DEFAULT now()
);

-- Indexes for common queries
CREATE INDEX idx_audit_log_created ON audit_log(created_at DESC);
CREATE INDEX idx_audit_log_user ON audit_log(user_id);
CREATE INDEX idx_audit_log_entity ON audit_log(entity_type, entity_id);
CREATE INDEX idx_audit_log_action ON audit_log(action);

ALTER TABLE audit_log ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_log FORCE ROW LEVEL SECURITY;

-- SELECT: any authenticated @margolispllc.com user can read all audit entries
CREATE POLICY "Org users can read audit log"
  ON audit_log FOR SELECT
  USING (
    auth.jwt() ->> 'email' LIKE '%@margolispllc.com'
  );

-- INSERT: any authenticated @margolispllc.com user can write audit entries
CREATE POLICY "Org users can insert audit log"
  ON audit_log FOR INSERT
  WITH CHECK (
    auth.jwt() ->> 'email' LIKE '%@margolispllc.com'
  );

-- No UPDATE or DELETE — audit log is append-only
