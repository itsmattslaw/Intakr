-- =============================================
-- RLS AUDIT & HARDENING — 2026-02-15
-- =============================================
-- This migration tightens Row Level Security policies on all tables.
-- It adds domain-level restrictions so only @margolispllc.com users
-- can access data, and ensures the approval workflow allows
-- cross-user review while keeping data properly scoped.
--
-- Run this in the Supabase SQL Editor (Dashboard > SQL Editor).
-- =============================================

-- 1. CLIENTS TABLE — tighten all policies with domain check
-- =============================================

-- SELECT: user can see own clients + clients assigned to them, but only if authed under org domain
DROP POLICY IF EXISTS "Users can view own clients" ON clients;
DROP POLICY IF EXISTS "Users can view own or assigned clients" ON clients;
CREATE POLICY "Users can view own or assigned clients"
  ON clients FOR SELECT
  USING (
    auth.jwt() ->> 'email' LIKE '%@margolispllc.com'
    AND (auth.uid() = user_id OR auth.uid() = assigned_to_user_id)
  );

-- INSERT: only the authenticated user can insert, scoped to their user_id
DROP POLICY IF EXISTS "Users can insert own clients" ON clients;
CREATE POLICY "Users can insert own clients"
  ON clients FOR INSERT
  WITH CHECK (
    auth.jwt() ->> 'email' LIKE '%@margolispllc.com'
    AND auth.uid() = user_id
  );

-- UPDATE: user can update own clients + clients assigned to them
DROP POLICY IF EXISTS "Users can update own clients" ON clients;
DROP POLICY IF EXISTS "Users can update own or assigned clients" ON clients;
CREATE POLICY "Users can update own or assigned clients"
  ON clients FOR UPDATE
  USING (
    auth.jwt() ->> 'email' LIKE '%@margolispllc.com'
    AND (auth.uid() = user_id OR auth.uid() = assigned_to_user_id)
  );

-- DELETE: only the owner can delete
DROP POLICY IF EXISTS "Users can delete own clients" ON clients;
CREATE POLICY "Users can delete own clients"
  ON clients FOR DELETE
  USING (
    auth.jwt() ->> 'email' LIKE '%@margolispllc.com'
    AND auth.uid() = user_id
  );


-- 2. ENGAGEMENT_LETTERS TABLE — tighten + enable cross-user review
-- =============================================

-- SELECT: owner OR assigned user (via client) can read letters
DROP POLICY IF EXISTS "Users can view own letters" ON engagement_letters;
DROP POLICY IF EXISTS "Users can view own or assigned letters" ON engagement_letters;
CREATE POLICY "Users can view own or assigned letters"
  ON engagement_letters FOR SELECT
  USING (
    auth.jwt() ->> 'email' LIKE '%@margolispllc.com'
    AND (
      auth.uid() = user_id
      OR EXISTS (
        SELECT 1 FROM clients
        WHERE clients.id = engagement_letters.client_id
        AND (auth.uid() = clients.user_id OR auth.uid() = clients.assigned_to_user_id)
      )
    )
  );

-- INSERT: only the authenticated user, scoped to their user_id
DROP POLICY IF EXISTS "Users can insert own letters" ON engagement_letters;
CREATE POLICY "Users can insert own letters"
  ON engagement_letters FOR INSERT
  WITH CHECK (
    auth.jwt() ->> 'email' LIKE '%@margolispllc.com'
    AND auth.uid() = user_id
  );

-- UPDATE: owner can update own letters; assigned/linked users can update
-- (needed for the approval workflow — reviewers update approval_status)
DROP POLICY IF EXISTS "Users can update own letters" ON engagement_letters;
DROP POLICY IF EXISTS "Users can update own or assigned letters" ON engagement_letters;
CREATE POLICY "Users can update own or assigned letters"
  ON engagement_letters FOR UPDATE
  USING (
    auth.jwt() ->> 'email' LIKE '%@margolispllc.com'
    AND (
      auth.uid() = user_id
      OR EXISTS (
        SELECT 1 FROM clients
        WHERE clients.id = engagement_letters.client_id
        AND (auth.uid() = clients.user_id OR auth.uid() = clients.assigned_to_user_id)
      )
    )
  );

-- DELETE: only the owner can delete letters
DROP POLICY IF EXISTS "Users can delete own letters" ON engagement_letters;
CREATE POLICY "Users can delete own letters"
  ON engagement_letters FOR DELETE
  USING (
    auth.jwt() ->> 'email' LIKE '%@margolispllc.com'
    AND auth.uid() = user_id
  );


-- 3. VERIFY: confirm RLS is enabled on both tables
-- =============================================
ALTER TABLE clients ENABLE ROW LEVEL SECURITY;
ALTER TABLE engagement_letters ENABLE ROW LEVEL SECURITY;

-- Force RLS for table owners too (prevents bypassing via service role in app code)
ALTER TABLE clients FORCE ROW LEVEL SECURITY;
ALTER TABLE engagement_letters FORCE ROW LEVEL SECURITY;
