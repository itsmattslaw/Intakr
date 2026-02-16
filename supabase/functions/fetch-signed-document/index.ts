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

    // Fetch the engagement letter record
    const { data: letter, error: letterError } = await supabase
      .from('engagement_letters')
      .select('id, client_id, boldsign_document_id, signed_pdf_path, esign_status')
      .eq('id', letterId)
      .single()

    if (letterError || !letter) {
      return new Response(JSON.stringify({ error: 'Letter not found' }), {
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

    // Must have a BoldSign document ID and completed status
    if (!letter.boldsign_document_id) {
      return new Response(JSON.stringify({ error: 'No BoldSign document linked to this letter' }), {
        status: 400,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      })
    }

    if (letter.esign_status !== 'completed' && letter.esign_status !== 'signed') {
      return new Response(JSON.stringify({ error: 'Document has not been signed yet' }), {
        status: 400,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      })
    }

    const boldsignApiKey = Deno.env.get('BOLDSIGN_API_KEY')
    if (!boldsignApiKey) {
      return new Response(JSON.stringify({ error: 'BoldSign API key not configured' }), {
        status: 500,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      })
    }

    // Download signed PDF from BoldSign
    const dlRes = await fetch(
      `https://api.boldsign.com/v1/document/download?documentId=${encodeURIComponent(letter.boldsign_document_id)}`,
      { headers: { 'X-API-KEY': boldsignApiKey } },
    )

    if (!dlRes.ok) {
      const errText = await dlRes.text()
      return new Response(JSON.stringify({ error: 'Failed to download from BoldSign', detail: errText }), {
        status: 502,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      })
    }

    const pdfBytes = new Uint8Array(await dlRes.arrayBuffer())

    // Upload to Supabase Storage using service role to bypass RLS
    const serviceRoleKey = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!
    const serviceClient = createClient(supabaseUrl, serviceRoleKey)

    const storagePath = `${letter.client_id}/${letter.id}_signed.pdf`
    const { error: uploadError } = await serviceClient.storage
      .from('signed-letters')
      .upload(storagePath, pdfBytes, {
        contentType: 'application/pdf',
        upsert: true,
      })

    if (uploadError) {
      return new Response(JSON.stringify({ error: 'Failed to store PDF', detail: uploadError.message }), {
        status: 500,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      })
    }

    // Update the engagement letter record with the storage path
    await serviceClient.from('engagement_letters')
      .update({ signed_pdf_path: storagePath })
      .eq('id', letter.id)

    return new Response(JSON.stringify({ ok: true, path: storagePath }), {
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    })
  } catch (err) {
    return new Response(JSON.stringify({ error: err.message }), {
      status: 500,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    })
  }
})
