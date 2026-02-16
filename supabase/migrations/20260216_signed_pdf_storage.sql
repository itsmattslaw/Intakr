-- Add signed PDF storage column to engagement_letters
ALTER TABLE engagement_letters ADD COLUMN IF NOT EXISTS signed_pdf_path TEXT DEFAULT NULL;

-- Create storage bucket for signed engagement letters (private — requires signed URLs)
INSERT INTO storage.buckets (id, name, public)
VALUES ('signed-letters', 'signed-letters', false)
ON CONFLICT (id) DO NOTHING;

-- Storage RLS: allow authenticated @margolispllc.com users to read signed letters
CREATE POLICY "Org users can read signed letters"
  ON storage.objects FOR SELECT
  USING (
    bucket_id = 'signed-letters'
    AND auth.jwt() ->> 'email' LIKE '%@margolispllc.com'
  );

-- Storage RLS: service role (webhook) can insert signed letters
-- (service role bypasses RLS, so this policy is for app-level uploads if needed)
CREATE POLICY "Org users can upload signed letters"
  ON storage.objects FOR INSERT
  WITH CHECK (
    bucket_id = 'signed-letters'
    AND auth.jwt() ->> 'email' LIKE '%@margolispllc.com'
  );
