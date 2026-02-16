-- Add BoldSign e-signature tracking columns to engagement_letters
ALTER TABLE engagement_letters ADD COLUMN IF NOT EXISTS boldsign_document_id TEXT;
ALTER TABLE engagement_letters ADD COLUMN IF NOT EXISTS esign_status TEXT DEFAULT NULL;
-- esign_status values: 'sent', 'viewed', 'signed', 'completed', 'declined', 'expired'

-- Index for webhook lookups by BoldSign document ID
CREATE INDEX IF NOT EXISTS idx_engagement_letters_boldsign_doc_id
  ON engagement_letters (boldsign_document_id)
  WHERE boldsign_document_id IS NOT NULL;
