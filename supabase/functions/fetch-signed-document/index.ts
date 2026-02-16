import { serve } from "https://deno.land/std@0.168.0/http/server.ts"
import { createClient } from "https://esm.sh/@supabase/supabase-js@2"

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
}

serve(async (req) => {
  if (req.method === 'OPTIONS') {
    return new Response('ok', { headers: corsHeaders })
  }

  try {
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

    const body = await req.json()
    const { letterId } = body

    if (!letterId || typeof letterId !== 'string') {
      return new Response(JSON.stringify({ error: 'Missing letterId' }), {
        status: 400,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      })
    }

    // Use service role key for all DB operations (bypasses RLS)
    const serviceRoleKey = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!
    const serviceClient = createClient(supabaseUrl, serviceRoleKey)

    // Fetch the engagement letter record using service client
    const { data: letter, error: letterError } = await serviceClient
      .from('engagement_letters')
      .select('id, client_id, boldsign_document_id, signed_pdf_path, esign_status')
      .eq('id', letterId)
      .single()

    if (letterError || !letter) {
      return new Response(JSON.stringify({ error: 'Letter not found', detail: letterError?.message }), {
        status: 404,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      })
    }

    // If already stored, return the existing path
    if (letter.signed_pdf_path) {
      return new Response(JSON.stringify({ ok: true, path: letter.signed_pdf_path, alreadyStored: true }), {
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      })
    }

    // Must have a BoldSign document ID
    if (!letter.boldsign_document_id) {
      return new Response(JSON.stringify({
        error: 'No BoldSign document linked to this letter',
        detail: `Letter ${letterId} has esign_status="${letter.esign_status}" but boldsign_document_id is null. The document ID may not have been saved when the letter was sent for e-signature.`,
      }), {
        status: 400,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      })
    }

    // Allow fetch if status is completed, signed, or even sent (to handle webhook status update failures)
    // The BoldSign API will return an error if the document isn't actually signed yet
    const boldsignApiKey = Deno.env.get('BOLDSIGN_API_KEY')
    if (!boldsignApiKey) {
      return new Response(JSON.stringify({ error: 'BoldSign API key not configured' }), {
        status: 500,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      })
    }

    // Download signed PDF from BoldSign
    const downloadUrl = `https://api.boldsign.com/v1/document/download?documentId=${encodeURIComponent(letter.boldsign_document_id)}`
    console.log(`Downloading signed PDF from BoldSign: documentId=${letter.boldsign_document_id}, esign_status=${letter.esign_status}`)

    const dlRes = await fetch(downloadUrl, {
      headers: { 'X-API-KEY': boldsignApiKey },
    })

    if (!dlRes.ok) {
      const errText = await dlRes.text()
      console.error(`BoldSign download failed: status=${dlRes.status}, body=${errText}`)
      return new Response(JSON.stringify({
        error: 'Failed to download from BoldSign',
        detail: errText,
        boldsignStatus: dlRes.status,
        documentId: letter.boldsign_document_id,
        esignStatus: letter.esign_status,
      }), {
        status: 502,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      })
    }

    const contentType = dlRes.headers.get('content-type') || ''
    const pdfBytes = new Uint8Array(await dlRes.arrayBuffer())

    if (pdfBytes.length === 0) {
      return new Response(JSON.stringify({ error: 'BoldSign returned empty response' }), {
        status: 502,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      })
    }

    console.log(`Downloaded ${pdfBytes.length} bytes from BoldSign (content-type: ${contentType})`)

    // Upload to Supabase Storage
    const storagePath = `${letter.client_id}/${letter.id}_signed.pdf`
    const { error: uploadError } = await serviceClient.storage
      .from('signed-letters')
      .upload(storagePath, pdfBytes, {
        contentType: 'application/pdf',
        upsert: true,
      })

    if (uploadError) {
      console.error('Storage upload failed:', uploadError.message)
      return new Response(JSON.stringify({ error: 'Failed to store PDF', detail: uploadError.message }), {
        status: 500,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      })
    }

    // Update the engagement letter record with the storage path and ensure status is correct
    const updateData: Record<string, string> = { signed_pdf_path: storagePath }
    if (letter.esign_status !== 'completed') {
      updateData.esign_status = 'completed'
    }

    const { error: updateError } = await serviceClient.from('engagement_letters')
      .update(updateData)
      .eq('id', letter.id)

    if (updateError) {
      console.error('Letter record update failed:', updateError.message)
    }

    console.log(`Signed PDF stored at: ${storagePath}`)
    return new Response(JSON.stringify({ ok: true, path: storagePath }), {
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    })
  } catch (err) {
    console.error('fetch-signed-document error:', err.message)
    return new Response(JSON.stringify({ error: err.message }), {
      status: 500,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    })
  }
})
