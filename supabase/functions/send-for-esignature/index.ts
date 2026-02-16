import { serve } from "https://deno.land/std@0.168.0/http/server.ts"
import { createClient } from "https://esm.sh/@supabase/supabase-js@2"

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
}

// Limits
const MAX_BODY_SIZE = 15 * 1024 * 1024
const MAX_MESSAGE_LENGTH = 2000
const MAX_TITLE_LENGTH = 500

function hasCRLF(s: string): boolean {
  return /[\r\n]/.test(s)
}

serve(async (req) => {
  if (req.method === 'OPTIONS') {
    return new Response('ok', { headers: corsHeaders })
  }

  try {
    // Enforce request body size limit
    const contentLength = req.headers.get('content-length')
    if (contentLength && parseInt(contentLength, 10) > MAX_BODY_SIZE) {
      return new Response(JSON.stringify({ error: 'Request too large' }), {
        status: 413,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      })
    }

    // Verify the caller is authenticated
    const authHeader = req.headers.get('Authorization')
    if (!authHeader) {
      return new Response(JSON.stringify({ error: 'Missing authorization' }), {
        status: 401,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      })
    }

    const supabaseUrl = Deno.env.get('SUPABASE_URL')!
    const supabaseAnonKey = Deno.env.get('SUPABASE_ANON_KEY')!
    const supabase = createClient(supabaseUrl, supabaseAnonKey, {
      global: { headers: { Authorization: authHeader } },
    })

    const { data: { user }, error: authError } = await supabase.auth.getUser()
    if (authError || !user) {
      return new Response(JSON.stringify({ error: 'Unauthorized' }), {
        status: 401,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      })
    }

    if (!user.email?.endsWith('@margolispllc.com')) {
      return new Response(JSON.stringify({ error: 'Forbidden' }), {
        status: 403,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      })
    }

    const boldsignApiKey = Deno.env.get('BOLDSIGN_API_KEY')
    if (!boldsignApiKey) {
      return new Response(JSON.stringify({ error: 'BoldSign API key not configured. Set BOLDSIGN_API_KEY in Edge Function secrets.' }), {
        status: 500,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      })
    }

    const body = await req.json()

    // Validate allowed fields
    const allowedKeys = new Set([
      'pdfBase64', 'fileName', 'signerName', 'signerEmail',
      'title', 'message', 'clientId', 'letterId',
      'signaturePageNumber',
    ])
    for (const key of Object.keys(body)) {
      if (!allowedKeys.has(key)) {
        return new Response(JSON.stringify({ error: 'Invalid payload field: ' + key }), {
          status: 400,
          headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        })
      }
    }

    const { pdfBase64, fileName, signerName, signerEmail, title, message, clientId, letterId, signaturePageNumber } = body

    // Validate required fields
    if (!pdfBase64 || !signerName || !signerEmail || !title) {
      return new Response(JSON.stringify({ error: 'Missing required fields: pdfBase64, signerName, signerEmail, title' }), {
        status: 400,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      })
    }

    // Type and sanity checks
    if (typeof pdfBase64 !== 'string' || typeof signerName !== 'string' ||
        typeof signerEmail !== 'string' || typeof title !== 'string') {
      return new Response(JSON.stringify({ error: 'Invalid field types' }), {
        status: 400,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      })
    }

    if (hasCRLF(signerEmail) || hasCRLF(signerName) || hasCRLF(title)) {
      return new Response(JSON.stringify({ error: 'Invalid characters in fields' }), {
        status: 400,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      })
    }

    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/
    if (!emailRegex.test(signerEmail)) {
      return new Response(JSON.stringify({ error: 'Invalid signer email address' }), {
        status: 400,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      })
    }

    if (title.length > MAX_TITLE_LENGTH) {
      return new Response(JSON.stringify({ error: 'Title too long' }), {
        status: 400,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      })
    }

    if (typeof message === 'string' && message.length > MAX_MESSAGE_LENGTH) {
      return new Response(JSON.stringify({ error: 'Message too long' }), {
        status: 400,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      })
    }

    // Decode PDF from base64
    const binaryStr = atob(pdfBase64)
    const pdfBytes = new Uint8Array(binaryStr.length)
    for (let i = 0; i < binaryStr.length; i++) {
      pdfBytes[i] = binaryStr.charCodeAt(i)
    }

    const pdfBlob = new Blob([pdfBytes], { type: 'application/pdf' })
    const safeName = (fileName || 'Engagement_Letter.pdf').replace(/[^a-zA-Z0-9._-]/g, '_').slice(0, 255)

    // The signature page number (1-indexed) — defaults to 2 if not provided
    const sigPage = typeof signaturePageNumber === 'number' && signaturePageNumber > 0
      ? signaturePageNumber
      : 2

    // Build multipart/form-data for BoldSign API
    // Signature field positions on the signature page (coordinates in points for US Letter 612x792)
    // These correspond to the "By: ___", "Name: ___", "Date: ___" lines in the acknowledgment section
    const formData = new FormData()
    formData.append('Files', pdfBlob, safeName)
    formData.append('Title', title)

    if (typeof message === 'string' && message.trim()) {
      formData.append('Message', message.trim())
    }

    // Signer details
    formData.append('Signers[0][Name]', signerName)
    formData.append('Signers[0][EmailAddress]', signerEmail)
    formData.append('Signers[0][SignerType]', 'Signer')

    // Signature field — overlays the "By: _____" line
    formData.append('Signers[0][FormFields][0][Id]', 'clientSignature')
    formData.append('Signers[0][FormFields][0][Name]', 'Client Signature')
    formData.append('Signers[0][FormFields][0][FieldType]', 'Signature')
    formData.append('Signers[0][FormFields][0][PageNumber]', String(sigPage))
    formData.append('Signers[0][FormFields][0][Bounds][X]', '100')
    formData.append('Signers[0][FormFields][0][Bounds][Y]', '265')
    formData.append('Signers[0][FormFields][0][Bounds][Width]', '250')
    formData.append('Signers[0][FormFields][0][Bounds][Height]', '28')
    formData.append('Signers[0][FormFields][0][IsRequired]', 'true')

    // Name text field — overlays the "Name: ___" line
    formData.append('Signers[0][FormFields][1][Id]', 'clientName')
    formData.append('Signers[0][FormFields][1][Name]', 'Client Name')
    formData.append('Signers[0][FormFields][1][FieldType]', 'TextBox')
    formData.append('Signers[0][FormFields][1][PageNumber]', String(sigPage))
    formData.append('Signers[0][FormFields][1][Bounds][X]', '130')
    formData.append('Signers[0][FormFields][1][Bounds][Y]', '290')
    formData.append('Signers[0][FormFields][1][Bounds][Width]', '220')
    formData.append('Signers[0][FormFields][1][Bounds][Height]', '18')
    formData.append('Signers[0][FormFields][1][IsRequired]', 'true')

    // Date field — overlays the "Date: ___" line
    formData.append('Signers[0][FormFields][2][Id]', 'clientDate')
    formData.append('Signers[0][FormFields][2][Name]', 'Date')
    formData.append('Signers[0][FormFields][2][FieldType]', 'DateSigned')
    formData.append('Signers[0][FormFields][2][PageNumber]', String(sigPage))
    formData.append('Signers[0][FormFields][2][Bounds][X]', '116')
    formData.append('Signers[0][FormFields][2][Bounds][Y]', '306')
    formData.append('Signers[0][FormFields][2][Bounds][Width]', '180')
    formData.append('Signers[0][FormFields][2][Bounds][Height]', '18')
    formData.append('Signers[0][FormFields][2][IsRequired]', 'true')

    // Send to BoldSign
    const boldsignRes = await fetch('https://api.boldsign.com/v1/document/send', {
      method: 'POST',
      headers: {
        'X-API-KEY': boldsignApiKey,
      },
      body: formData,
    })

    if (!boldsignRes.ok) {
      const errBody = await boldsignRes.text()
      let detail = errBody
      try { detail = JSON.parse(errBody).message || errBody } catch (_) { /* use raw text */ }
      return new Response(JSON.stringify({ error: 'BoldSign API error', detail }), {
        status: 502,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      })
    }

    const boldsignResult = await boldsignRes.json()
    const documentId = boldsignResult.documentId

    // Update the engagement letter record with the BoldSign document ID
    // Use service role key to bypass RLS
    const serviceRoleKey = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!
    const serviceClient = createClient(supabaseUrl, serviceRoleKey)

    if (letterId && documentId) {
      const { error: letterUpdateError } = await serviceClient.from('engagement_letters')
        .update({ boldsign_document_id: documentId, esign_status: 'sent', approval_status: 'Approved' })
        .eq('id', letterId)

      if (letterUpdateError) {
        console.error('Failed to update engagement letter with BoldSign ID:', letterUpdateError.message)
      }
    }

    // Update client status to "Letter Sent" if clientId provided
    if (clientId) {
      const today = new Date().toISOString().slice(0, 10)
      const { error: clientUpdateError } = await serviceClient.from('clients')
        .update({ status: 'Letter Sent', letter_sent: today })
        .eq('id', clientId)

      if (clientUpdateError) {
        console.error('Failed to update client status:', clientUpdateError.message)
      }
    }

    return new Response(JSON.stringify({ ok: true, documentId }), {
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    })
  } catch (err) {
    return new Response(JSON.stringify({ error: err.message }), {
      status: 500,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    })
  }
})
