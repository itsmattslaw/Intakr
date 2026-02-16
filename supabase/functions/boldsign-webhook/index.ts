import { serve } from "https://deno.land/std@0.168.0/http/server.ts"
import { createClient } from "https://esm.sh/@supabase/supabase-js@2"

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type, x-boldsign-signature',
}

// BoldSign webhook event types we handle
const HANDLED_EVENTS = new Set([
  'Sent', 'Viewed', 'Signed', 'Completed', 'Declined', 'Expired', 'Revoked',
])

// Map BoldSign event names to our esign_status values
function mapEventToStatus(event: string): string | null {
  switch (event) {
    case 'Sent': return 'sent'
    case 'Viewed': return 'viewed'
    case 'Signed': return 'signed'
    case 'Completed': return 'completed'
    case 'Declined': return 'declined'
    case 'Expired': return 'expired'
    case 'Revoked': return 'revoked'
    default: return null
  }
}

// Verify BoldSign webhook signature using HMAC-SHA256
async function verifyWebhookSignature(body: string, signature: string, secret: string): Promise<boolean> {
  const encoder = new TextEncoder()
  const key = await crypto.subtle.importKey(
    'raw',
    encoder.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  )
  const sig = await crypto.subtle.sign('HMAC', key, encoder.encode(body))
  const computed = btoa(String.fromCharCode(...new Uint8Array(sig)))
  return computed === signature
}

serve(async (req) => {
  if (req.method === 'OPTIONS') {
    return new Response('ok', { headers: corsHeaders })
  }

  // Only accept POST
  if (req.method !== 'POST') {
    return new Response(JSON.stringify({ error: 'Method not allowed' }), {
      status: 405,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    })
  }

  try {
    const rawBody = await req.text()

    // Verify webhook signature if secret is configured
    const webhookSecret = Deno.env.get('BOLDSIGN_WEBHOOK_SECRET')
    if (webhookSecret) {
      const signature = req.headers.get('X-BoldSign-Signature') || ''
      if (!signature) {
        return new Response(JSON.stringify({ error: 'Missing webhook signature' }), {
          status: 401,
          headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        })
      }
      const valid = await verifyWebhookSignature(rawBody, signature, webhookSecret)
      if (!valid) {
        return new Response(JSON.stringify({ error: 'Invalid webhook signature' }), {
          status: 401,
          headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        })
      }
    }

    const payload = JSON.parse(rawBody)
    const eventType = payload.event?.eventType || payload.eventType
    const documentId = payload.event?.document?.documentId || payload.documentId

    if (!eventType || !documentId) {
      // Acknowledge unknown payloads gracefully (BoldSign verification pings)
      return new Response(JSON.stringify({ ok: true, message: 'Acknowledged' }), {
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      })
    }

    if (!HANDLED_EVENTS.has(eventType)) {
      return new Response(JSON.stringify({ ok: true, message: 'Event not handled' }), {
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      })
    }

    const esignStatus = mapEventToStatus(eventType)
    if (!esignStatus) {
      return new Response(JSON.stringify({ ok: true }), {
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      })
    }

    // Use service role key to bypass RLS for webhook updates
    const supabaseUrl = Deno.env.get('SUPABASE_URL')!
    const serviceRoleKey = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!
    const supabase = createClient(supabaseUrl, serviceRoleKey)

    // Find the engagement letter by BoldSign document ID
    const { data: letters, error: findError } = await supabase
      .from('engagement_letters')
      .select('id, client_id, esign_status')
      .eq('boldsign_document_id', documentId)
      .limit(1)

    if (findError || !letters || letters.length === 0) {
      console.warn('No engagement letter found for BoldSign document:', documentId)
      return new Response(JSON.stringify({ ok: true, message: 'Document not found in system' }), {
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      })
    }

    const letter = letters[0]

    // Update esign_status on the engagement letter
    const updateData: Record<string, string> = { esign_status: esignStatus }
    if (eventType === 'Completed') {
      updateData.approval_status = 'Executed'
    }
    const { error: updateError } = await supabase
      .from('engagement_letters')
      .update(updateData)
      .eq('id', letter.id)

    if (updateError) {
      console.error('Failed to update esign_status:', updateError.message)
    }

    // On completion, download signed PDF from BoldSign and store in Supabase Storage
    if (eventType === 'Completed') {
      const boldsignApiKey = Deno.env.get('BOLDSIGN_API_KEY')
      if (boldsignApiKey) {
        try {
          const dlRes = await fetch(
            `https://api.boldsign.com/v1/document/download?documentId=${encodeURIComponent(documentId)}`,
            { headers: { 'X-API-KEY': boldsignApiKey } },
          )
          if (dlRes.ok) {
            const pdfBytes = new Uint8Array(await dlRes.arrayBuffer())
            const storagePath = `${letter.client_id}/${letter.id}_signed.pdf`
            const { error: uploadError } = await supabase.storage
              .from('signed-letters')
              .upload(storagePath, pdfBytes, {
                contentType: 'application/pdf',
                upsert: true,
              })
            if (uploadError) {
              console.error('Failed to upload signed PDF:', uploadError.message)
            } else {
              // Store the path on the engagement letter record
              await supabase.from('engagement_letters')
                .update({ signed_pdf_path: storagePath })
                .eq('id', letter.id)
            }
          } else {
            console.warn('BoldSign download failed:', dlRes.status, await dlRes.text())
          }
        } catch (e) {
          console.warn('Signed PDF download/upload failed:', e.message)
        }
      }
    }

    // On completion, update the client status to "Executed"
    if (eventType === 'Completed' && letter.client_id) {
      const today = new Date().toISOString().slice(0, 10)
      const { error: clientError } = await supabase
        .from('clients')
        .update({ status: 'Executed', letter_executed: today })
        .eq('id', letter.client_id)

      if (clientError) {
        console.error('Failed to update client status:', clientError.message)
      }

      // Notify Slack if webhook URL is configured (best-effort)
      const slackWebhookUrl = Deno.env.get('SLACK_WEBHOOK_URL')
      if (slackWebhookUrl) {
        try {
          // Fetch client name for the notification
          const { data: clientData } = await supabase
            .from('clients')
            .select('entity_name, contact_name, matter_type')
            .eq('id', letter.client_id)
            .limit(1)

          const client = clientData?.[0]
          const clientName = client?.entity_name || client?.contact_name || 'Unknown'
          const matterType = client?.matter_type || ''

          await fetch(slackWebhookUrl, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              text: `Engagement letter signed by ${clientName}`,
              blocks: [
                { type: 'header', text: { type: 'plain_text', text: 'Engagement Letter Signed', emoji: true } },
                { type: 'section', fields: [
                  { type: 'mrkdwn', text: `*Client:*\n${clientName}` },
                  { type: 'mrkdwn', text: `*Matter:*\n${matterType}` },
                ]},
                { type: 'section', fields: [
                  { type: 'mrkdwn', text: `*Status:*\nFully Executed` },
                  { type: 'mrkdwn', text: `*Signed:*\n${today}` },
                ]},
                { type: 'context', elements: [
                  { type: 'mrkdwn', text: 'Signed via BoldSign e-signature' },
                ]},
              ],
            }),
          })
        } catch (e) {
          console.warn('Slack notification failed:', e.message)
        }
      }
    }

    return new Response(JSON.stringify({ ok: true, status: esignStatus }), {
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    })
  } catch (err) {
    console.error('Webhook error:', err.message)
    return new Response(JSON.stringify({ error: err.message }), {
      status: 500,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    })
  }
})
